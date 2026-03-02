# Mono Gateway custom components for OPNsense

Out-of-tree kernel modules, userspace daemons, and build tooling for the Mono
Gateway OPNsense image. Contains the DPAA1 fast-path stack (CDX flow offload,
FCI, CMM connection manager, PF notifier, auto-bridge), board-support drivers
(LP5812 LED, EMC2302 fan, INA2xx power, SFP LED, PCF2131 RTC, CAAM crypto),
FMan toolchain (fmlib, fmc, dpa_app), and helper scripts for kernel image
creation and deployment.

## Repository layout

```
opnsense-deps/
├── patches/              # kernel source patches (git format-patch)
│   ├── 0001-arm64-platform-support-for-NXP-LS1046A.patch
│   ├── 0002-ncsw-port-DPAA1-NCSW-layer-to-ARM64.patch
│   ├── 0003-dpaa-drivers-and-board-peripherals-for-LS1046A.patch
│   ├── 0004-net-bridge-and-pf-hooks-for-hardware-flow-offload.patch
│   ├── 0005-dts-add-Mono-Gateway-Development-Kit-device-tree.patch
│   └── 0006-build-GATEWAY-kernel-config-and-DPAA-build-rules.patch
├── drivers/              # out-of-tree kernel modules
│   ├── caam/             # NXP CAAM crypto accelerator (JR + QI)
│   ├── pcf2131/          # NXP PCF2131 RTC
│   ├── emc2302/          # SMSC EMC2302 fan controller
│   ├── ina2xx/           # TI INA2xx power monitor
│   ├── lp5812/           # TI LP5812 LED controller
│   └── sfp-led/          # SFP+ link status LED
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
└── Makefile              # top-level build (modules + userspace + package)
```

## Build instructions

All commands run on the build server (amd64 FreeBSD).

The build server should run the same FreeBSD version that OPNsense is based on (e.g., FreeBSD 14.3
for OPNsense 26.1). Mismatched versions can cause ABI issues in cross-compiled kernel modules.

### 1. Prerequisites

```
sudo pkg install -y git aarch64-binutils qemu-user-static python3
```

### 2. Set up `/build`

All build paths assume the source tree is at `/build`. This directory must contain
`opnsense-build`, `opnsense-src`, and `opnsense-deps`.

**Local development** (source tree lives on the build server):

```
sudo mkdir /build && sudo chown $(whoami) /build
```

**Remote source via NFS** (source tree lives on another machine):

```
# Enable the NFS client
sudo sysrc nfs_client_enable="YES"
sudo service nfsclient start

# Mount the remote share — the NFS export is the directory containing
# opnsense-build, opnsense-src, opnsense-deps, etc.
# Replace [server] with the NFS server's hostname and [nfs-export] with
# the path to the exported directory.
sudo mkdir -p /mnt/opnsense /build
echo '[server]:[nfs-export] /mnt/opnsense nfs rw,late 0 0' | sudo tee -a /etc/fstab
echo '/mnt/opnsense /build nullfs rw,late 0 0' | sudo tee -a /etc/fstab
sudo mount /mnt/opnsense
sudo mount /build
```

Using nullfs (rather than a symlink) ensures `pwd` reports `/build/...` in build
output, keeping kernel version strings and module paths clean.

### 2b. Clone repositories

Both the local and NFS paths need the following repositories in `/build`:

```
cd /build
git clone https://github.com/maurice-w/opnsense-vm-images.git opnsense-build
git clone https://github.com/opnsense/src.git opnsense-src
git clone https://github.com/we-are-mono/opnsense-deps

# Copy the GATEWAY device config into the build system
cp /build/opnsense-deps/config/GATEWAY.conf /build/opnsense-build/device/
```

### 3. Prefetch base and packages

Official OPNsense mirrors only publish amd64 sets. For aarch64, use walker.earth.
Check https://opnsense-update.walker.earth/FreeBSD:14:aarch64/26.1/sets/ for available versions.

```
export VERSION=26.1.1   # use latest available on the mirror

sudo make -C /build/opnsense-build prefetch-base DEVICE=GATEWAY SETTINGS=26.1 TOOLSDIR=/build/opnsense-build SRCDIR=/build/opnsense-src MIRRORS=https://opnsense-update.walker.earth VERSION=$VERSION

# The build system expects a -GATEWAY suffix on the base set
cd /usr/local/opnsense/build/26.1/aarch64/sets
sudo mv base-${VERSION}-aarch64.txz base-${VERSION}-aarch64-GATEWAY.txz

sudo make -C /build/opnsense-build prefetch-packages DEVICE=GATEWAY SETTINGS=26.1 TOOLSDIR=/build/opnsense-build SRCDIR=/build/opnsense-src MIRRORS=https://opnsense-update.walker.earth VERSION=$VERSION
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

### 4. Apply kernel patches

The kernel source is patched from upstream OPNsense (`stable/26.1`) via a series
of format-patch files in `patches/`. Apply them before building:

```
cd /build/opnsense-src
git checkout stable/26.1
git am /build/opnsense-deps/patches/*.patch
```

### 5. Build kernel

```
sudo make -C /build/opnsense-build kernel DEVICE=GATEWAY SETTINGS=26.1 TOOLSDIR=/build/opnsense-build SRCDIR=/build/opnsense-src
```

The OPNsense build system defaults `SRCDIR` to `/usr/src`; since our source tree
is named `opnsense-src`, the explicit `SRCDIR=` is required on all make targets
that touch the kernel source (kernel, arm).

The kernel is cross-compiled natively (no QEMU). Package installation during `make arm` uses QEMU user-static emulation.

**Rebuilding:** The build system caches the kernel set in the sets directory and
skips the build if one already exists. When rebuilding after source changes,
remove the stale set and obj tree first:

```
sudo rm -f /usr/local/opnsense/build/26.1/aarch64/sets/kernel-*-GATEWAY.txz
sudo rm -rf /usr/obj/build/opnsense-src/arm64.aarch64/sys/GATEWAY
```

### 6. Install libxml2 into cross-compilation sysroot

Required by opnsense-deps (fmc links against libxml2). Fetch the aarch64 package
from the FreeBSD pkg mirror and extract its headers and libraries into the
cross-compilation sysroot created by `make kernel`.

```
# Check https://pkg.FreeBSD.org/FreeBSD:14:aarch64/latest/All/ for current version
fetch -o /tmp/libxml2.pkg 'https://pkg.FreeBSD.org/FreeBSD:14:aarch64/latest/All/libxml2-2.15.1_1.pkg'
mkdir -p /tmp/libxml2-extract && cd /tmp/libxml2-extract && tar xf /tmp/libxml2.pkg

SYSROOT=/usr/obj/build/opnsense-src/arm64.aarch64/tmp
sudo mkdir -p ${SYSROOT}/usr/local/include ${SYSROOT}/usr/local/lib
sudo cp -r /tmp/libxml2-extract/usr/local/include/libxml2 ${SYSROOT}/usr/local/include/
sudo cp -a /tmp/libxml2-extract/usr/local/lib/libxml2* ${SYSROOT}/usr/local/lib/
```

### 7. Build custom modules and tools (everything in this repo)

```
make -C /build/opnsense-deps -j24 all
```

### 8. Assemble eMMC image

```
sudo make -C /build/opnsense-build arm-5G DEVICE=GATEWAY SETTINGS=26.1 TOOLSDIR=/build/opnsense-build SRCDIR=/build/opnsense-src
```

Output: `/usr/local/opnsense/build/26.1/aarch64/images/OPNsense-*-arm-aarch64-GATEWAY.img`

Optionally, compress the image for faster transfers:

```
sudo gzip /usr/local/opnsense/build/26.1/aarch64/images/OPNsense-*-GATEWAY.img
```

## Development workflow

### Kernel patches

The kernel source (`opnsense-src`) is maintained on the `mono-gateway` branch,
based on `stable/26.1`. Changes are organized into 6 logical patches:

| # | Patch | Scope |
|---|-------|-------|
| 1 | arm64: platform support | pio.h, machdep.c, systm.h, random.h |
| 2 | ncsw: DPAA1 NCSW ARM64 | NCSW vendor code ARM64 porting |
| 3 | dpaa: drivers + peripherals | BMan/QMan/FMan, dtsec, GPY PHY, INA2xx, GPIO |
| 4 | net: bridge + pf hooks | if_bridge.c, pf.c for hardware offload |
| 5 | dts: board device tree | mono-gateway-dk.dts |
| 6 | build: GATEWAY config | kernel config, DPAA build rules |

Applying the patches with `git am` creates real commits with full history — the
patches *are* the commit history. This means the `--fixup`/`--autosquash`
workflow works identically whether you originally authored the patches or applied
them fresh from the repository.

**Making a change:**

```bash
cd /build/opnsense-src

# See the 6 commits created by git am
git log --oneline stable/26.1..mono-gateway

# 1. Edit the file
vim sys/contrib/device-tree/src/arm64/freescale/mono-gateway-dk.dts

# 2. Stage and create a fixup commit targeting the right patch
git add sys/contrib/device-tree/src/arm64/freescale/mono-gateway-dk.dts
git commit --fixup <hash-of-patch-5>

# 3. Autosquash into the correct patch
git rebase --autosquash stable/26.1

# 4. Regenerate all patches
rm /build/opnsense-deps/patches/*.patch
git format-patch -o /build/opnsense-deps/patches/ stable/26.1..mono-gateway
```

For a change that doesn't fit an existing patch, just add a new commit at the
end of `mono-gateway` — it becomes patch 7.

### Out-of-tree modules

Drivers in `drivers/` build against kernel headers without modifying the kernel
source. To iterate on one:

```bash
# Rebuild just caam
make -C /build/opnsense-deps build-caam

# Or rebuild all modules
make -C /build/opnsense-deps -j24 modules
```

Output `.ko` files land in the driver directory and are collected into `dist/`
by `make dist`.

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
> Many of the files in this repository, including the kernel patches, were ported from Linux sources provided by NXP (originally targeting Linux kernel 5.4). Due to the sheer scope of the porting effort, Claude Opus 4.6 was used to assist with the adaptation of this code to FreeBSD. As such, this project should be considered **highly experimental** and is **not fit for production use** until thorough reviews and testing have been performed by the wider community.
