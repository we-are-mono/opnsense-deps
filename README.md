# Mono Gateway custom components for OPNsense

Out-of-tree kernel modules, userspace daemons, and build tooling for the Mono
Gateway OPNsense image. Contains the DPAA1 fast-path stack (CDX flow offload,
FCI, CMM connection manager, PF notifier, auto-bridge), board-support drivers
(LP5812 LED, EMC2302 fan, INA2xx power, SFP LED, PCF2131 RTC, TMP431 thermal,
CAAM crypto), WiFi support (NXP 88W9098 PCIe driver + DPAA OH port bridge),
FMan toolchain (fmlib, fmc, dpa_app), and helper scripts for kernel image
creation and deployment.

## Repository layout

```
opnsense-deps/
├── drivers/              # out-of-tree kernel modules
│   ├── caam/             # NXP CAAM crypto accelerator (JR + QI)
│   ├── dpaa_wifi/        # WiFi ↔ FMan OH port data plane bridge
│   ├── emc2302/          # SMSC EMC2302 fan controller
│   ├── fand/             # Fan control daemon (userspace)
│   ├── ina2xx/           # TI INA2xx power monitor
│   ├── lp5812/           # TI LP5812 LED controller
│   ├── mwifiex/          # NXP 88W9098 PCIe WiFi driver + firmware
│   ├── pcf2131/          # NXP PCF2131 RTC
│   ├── sfp-led/          # SFP+ link status LED
│   └── tmp431/           # TI TMP431 thermal sensor
├── fastpath/             # DPAA1 fast-path modules + userspace
│   ├── cdx/              # CDX flow offload kernel module
│   ├── fci/              # Fast-path Control Interface module
│   ├── auto_bridge/      # Auto-bridge kernel module
│   ├── pf_notify/        # PF state change notifier module
│   ├── fmlib/            # FMan userspace library
│   ├── fmc/              # FMan Configuration tool
│   ├── dpa_app/          # DPAA application (PCD setup)
│   ├── cmm/              # Connection Manager daemon
│   └── cmmctl/           # CMM control utility
├── config/               # FMC/CDX XML configuration files
├── rc.d/                 # rc.d service scripts and syshook scripts
├── pkg/                  # FreeBSD package metadata
├── _vendor/              # NXP vendor repos (cloned at build time, gitignored)
└── Makefile              # top-level build (modules + userspace + package)
```

## Network interface mapping

The FMan MAC numbering in the device tree does not match the physical port order
on the board. This is a cosmetic mismatch in the PCB routing — it has no effect
on performance or functionality.

| Physical position (left → right) | Interface | Speed |
|----------------------------------|-----------|-------|
| Port 1 | dtsec1 | 1 GbE |
| Port 2 | dtsec2 | 1 GbE |
| Port 3 | dtsec0 | 1 GbE |
| Port 4 | dtsec3 | 10 GbE SFP+ |
| Port 5 | dtsec4 | 10 GbE SFP+ |

## Build instructions

All commands run on the build server (FreeBSD, matching the OPNsense base version).

The build server should run the same FreeBSD version that OPNsense is based on
(e.g., FreeBSD 14.3 for OPNsense 26.1). Mismatched versions can cause ABI
issues in kernel modules. Native aarch64 builds are preferred; cross-compilation
from amd64 also works (see below).

### 1. Prerequisites

**Native aarch64 build server:**

```
sudo pkg install -y git python3
```

**Cross-compilation from amd64:**

```
sudo pkg install -y git aarch64-binutils qemu-user-static python3
```

### 2. Directory layout

The build system uses standard OPNsense paths under `/usr/`. Repositories map
to these paths either by cloning directly or via NFS + nullfs mounts:

| Path | Repository | OPNsense variable |
|------|-----------|-------------------|
| `/usr/src` | [we-are-mono/opnsense-src](https://github.com/we-are-mono/opnsense-src) | `SRCDIR` |
| `/usr/tools` | [opnsense/tools](https://github.com/opnsense/tools) | `TOOLSDIR` |
| `/usr/deps` | [we-are-mono/opnsense-deps](https://github.com/we-are-mono/opnsense-deps) | (this repo) |
| `/usr/core` | [opnsense/core](https://github.com/opnsense/core) | `COREDIR` |

All paths are overridable: `sudo make -C /usr/deps image SRCDIR=/my/src TOOLSDIR=/my/tools`

**Option A — Local development** (clone directly):

```
sudo git clone https://github.com/we-are-mono/opnsense-src.git /usr/src
sudo git clone https://github.com/opnsense/tools.git /usr/tools
sudo git clone https://github.com/we-are-mono/opnsense-deps /usr/deps
sudo cp /usr/deps/config/GATEWAY.conf /usr/tools/device/
```

**Option B — Remote source via NFS** (source tree on another machine):

```
# Enable the NFS client
sudo sysrc nfs_client_enable="YES"
sudo service nfsclient start

# Mount the remote NFS export
# Replace [server] and [nfs-export] with your NFS server and export path.
# The exported directory should contain opnsense-src, opnsense-build,
# opnsense-deps, and opnsense-core as subdirectories.
sudo mkdir -p /mnt/opnsense /usr/tools /usr/core /usr/deps
echo '[server]:[nfs-export] /mnt/opnsense nfs rw,late 0 0' | sudo tee -a /etc/fstab
echo '/mnt/opnsense/opnsense-src /usr/src nullfs rw,late 0 0' | sudo tee -a /etc/fstab
echo '/mnt/opnsense/opnsense-build /usr/tools nullfs rw,late 0 0' | sudo tee -a /etc/fstab
echo '/mnt/opnsense/opnsense-deps /usr/deps nullfs rw,late 0 0' | sudo tee -a /etc/fstab
echo '/mnt/opnsense/opnsense-core /usr/core nullfs rw,late 0 0' | sudo tee -a /etc/fstab
sudo mount -a

sudo cp /usr/deps/config/GATEWAY.conf /usr/tools/device/
```

Using nullfs (rather than symlinks) ensures `pwd` reports `/usr/...` in build
output, keeping kernel version strings and module paths clean.

### 3. Prefetch base and packages

Official OPNsense mirrors only publish amd64 sets. For aarch64, use walker.earth.
Check https://opnsense-update.walker.earth/FreeBSD:14:aarch64/26.1/sets/ for available versions.

```
export VERSION=26.1.1   # use latest available on the mirror

sudo make -C /usr/tools prefetch-base DEVICE=GATEWAY SETTINGS=26.1 TOOLSDIR=/usr/tools MIRRORS=https://opnsense-update.walker.earth VERSION=$VERSION

# The build system expects a -GATEWAY suffix on the base set
cd /usr/local/opnsense/build/26.1/aarch64/sets
sudo mv base-${VERSION}-aarch64.txz base-${VERSION}-aarch64-GATEWAY.txz

sudo make -C /usr/tools prefetch-packages DEVICE=GATEWAY SETTINGS=26.1 TOOLSDIR=/usr/tools MIRRORS=https://opnsense-update.walker.earth VERSION=$VERSION
```

This skips `make base`, `make ports`, `make core`, and `make plugins` (no cross-compilation needed).

The build system's `check_packages()` validates the host `pkg` version against the
ports tree before checking whether the prefetched set already has completion markers.
Create a minimal stub so the version check passes:

```
sudo mkdir -p /usr/ports/ports-mgmt/pkg
echo "PORTVERSION=$(pkg -v)" | sudo tee /usr/ports/ports-mgmt/pkg/Makefile
```

**Important:** Do NOT run `make base` or `make xtools` locally. If an `xtools-*-aarch64.txz`
set exists in the sets directory, remove it before building the image. The xtools overlay/restore
mechanism (`setup_xtools`/`setup_xbase`) is broken for cross-builds and will leave amd64 binaries
in the image.

### 4–7. Build everything (single command)

After completing steps 1–3, a single command builds the kernel, modules, userspace,
package, and assembles the final eMMC image:

```
sudo make -C /usr/deps image
```

The individual steps below are documented for development workflows where you
only need to rebuild part of the stack.

### 4. Build kernel

```
sudo make -C /usr/tools kernel DEVICE=GATEWAY SETTINGS=26.1 TOOLSDIR=/usr/tools
```

On a native aarch64 build server, no cross-compilation flags are needed. On an
amd64 host, the kernel is cross-compiled natively (no QEMU). Package
installation during `make arm` uses QEMU user-static emulation.

**Rebuilding:** The build system caches the kernel set in the sets directory and
skips the build if one already exists. When rebuilding after source changes,
remove the stale set and obj tree first:

```
sudo rm -f /usr/local/opnsense/build/26.1/aarch64/sets/kernel-*-GATEWAY.txz
sudo rm -rf /usr/obj/usr/src/arm64.aarch64/sys/GATEWAY
```

### 5. Install libxml2

Required by opnsense-deps (fmc links against libxml2).

**Native aarch64 build server:**

```
sudo pkg install -y libxml2
```

**Cross-compilation from amd64:**

Fetch the aarch64 package from the FreeBSD pkg mirror and extract its headers
and libraries into the sysroot created by `make kernel`. `make image` does this
automatically; the manual steps below are only needed when building without it.

```
fetch -o /tmp/libxml2.pkg 'https://pkg.FreeBSD.org/FreeBSD:14:aarch64/latest/All/libxml2-2.15.2.pkg'
mkdir -p /tmp/libxml2-extract && cd /tmp/libxml2-extract && tar xf /tmp/libxml2.pkg

SYSROOT=/usr/obj/usr/src/arm64.aarch64/tmp
sudo mkdir -p ${SYSROOT}/usr/local/include ${SYSROOT}/usr/local/lib
sudo cp -r /tmp/libxml2-extract/usr/local/include/libxml2 ${SYSROOT}/usr/local/include/
sudo cp -a /tmp/libxml2-extract/usr/local/lib/libxml2* ${SYSROOT}/usr/local/lib/
```

If the package version has changed, override it in the Makefile:

```
make -C /usr/deps image LIBXML2_PKG=libxml2-2.16.0.pkg
```

### 6. Build custom modules and tools (everything in this repo)

```
sudo make -C /usr/deps -j24 all
```

The first build automatically clones NXP vendor repositories (mwifiex driver
source and imx-firmware) into `_vendor/` at pinned commits. Subsequent builds
reuse the cached clones. To force a fresh clone, remove `_vendor/` and rebuild.

### 7. Assemble eMMC image

```
sudo make -C /usr/tools arm-5G DEVICE=GATEWAY SETTINGS=26.1 TOOLSDIR=/usr/tools
```

Output: `/usr/local/opnsense/build/26.1/aarch64/images/OPNsense-*-arm-aarch64-GATEWAY.img`

Optionally, compress the image for faster transfers:

```
sudo gzip /usr/local/opnsense/build/26.1/aarch64/images/OPNsense-*-GATEWAY.img
```

## Development workflow

### Kernel source

The kernel source (`opnsense-src`) is a fork of OPNsense/FreeBSD at
[we-are-mono/opnsense-src](https://github.com/we-are-mono/opnsense-src),
branched from `stable/26.1`. All Mono Gateway changes live as commits on this
branch.

**Making a change:**

```bash
cd /usr/src

# See Mono Gateway commits on top of upstream
git log --oneline origin/stable/26.1..HEAD

# 1. Edit the file
vim sys/contrib/device-tree/src/arm64/freescale/mono-gateway-dk.dts

# 2. Stage and commit
git add sys/contrib/device-tree/src/arm64/freescale/mono-gateway-dk.dts
git commit -m "dts: add PCIe WiFi reset GPIO"

# 3. Push
git push
```

To rebase on a newer upstream OPNsense release:

```bash
git remote add upstream https://github.com/opnsense/src.git
git fetch upstream
git rebase upstream/stable/26.7   # or whatever the new branch is
git push --force-with-lease
```

### Out-of-tree modules

Drivers in `drivers/` build against kernel headers without modifying the kernel
source. To iterate on one:

```bash
# Rebuild just caam
sudo make -C /usr/deps build-caam

# Or rebuild all modules
sudo make -C /usr/deps -j24 modules
```

Output `.ko` files land in the driver directory and are collected into `dist/`
by `make all`.

## Local / Test Deployment

Flashing writes the image directly to the gateway's eMMC. The gateway must be
booted into Recovery Linux (initramfs) so the eMMC is not in use.

**Warning:** This overwrites the entire eMMC, including any existing OPNsense
installation and its configuration.

### 1. Boot into Recovery Linux

Power on the gateway and let U-Boot autoboot into Recovery Linux (or interrupt
U-Boot and run `run recovery`).

### 2. Configure networking on the gateway

Recovery Linux has no DHCP client. Assign a static IP on the uplink port
(adjust addresses to match your network):

```
ip link set eth3 up
ip addr add 10.0.0.69/24 dev eth3
ip route add default via 10.0.0.1 dev eth3
```

### 3. Serve the image from the build server

On the build server, start an HTTP server in the images directory:

```
cd /usr/local/opnsense/build/26.1/aarch64/images
python3 -m http.server 8000
```

### 4. Flash the eMMC

On the gateway, stream the compressed image directly to the eMMC. This
downloads, decompresses, and writes in a single pipeline — no local storage
needed (works even on devices with limited RAM):

```
curl http://[build-server]:8000/OPNsense-*-GATEWAY.img.gz | gunzip | dd of=/dev/mmcblk0 bs=1M
```

For an uncompressed image (slower transfer, no gunzip needed):

```
curl http://[build-server]:8000/OPNsense-*-GATEWAY.img | dd of=/dev/mmcblk0 bs=1M
```

### 5. Reboot

```
reboot
```

U-Boot will load `kernel.img` and the device tree from the FAT partition and
boot into OPNsense.

## Booting into OPNsense

The board's default boot command loads OpenWRT. To boot OPNsense instead,
interrupt U-Boot's autoboot (press any key during the countdown) and configure
a persistent `opnsense` boot environment:

```
=> setenv opnsense "load mmc 0:1 ${kernel_addr_r} kernel.img; load mmc 0:1 ${fdt_addr_r} dtb/mono-gateway-dk.dtb; booti 0x82000000 - 0x88000000"
=> setenv bootcmd_bak ${bootcmd}
=> setenv bootcmd "run opnsense || run recovery"
=> saveenv
=> reset
```

This saves the original boot command as `bootcmd_bak`, then sets `bootcmd` to
try OPNsense first and fall back to Recovery Linux if the kernel image is missing.
After `saveenv` and `reset`, the board will automatically boot into OPNsense on
every subsequent power-on.

> ## Disclaimer
> Many of the files in this repository, and in the [kernel fork](https://github.com/we-are-mono/opnsense-src), were ported from Linux sources provided by NXP (originally targeting Linux kernel 5.4). Due to the sheer scope of the porting effort, Claude Opus 4.6 was used to assist with the adaptation of this code to FreeBSD. As such, this project should be considered **highly experimental** and is **not fit for production use** until thorough reviews and testing have been performed by the wider community.
