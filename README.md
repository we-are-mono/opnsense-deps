# Mono Gateway custom components for OPNsense

Out-of-tree kernel modules, userspace daemons, and build tooling for the Mono
Gateway OPNsense image. Contains the DPAA1 fast-path stack (CDX flow offload,
FCI, CMM connection manager, PF notifier, auto-bridge), board-support drivers
(LP5812 LED, EMC2302 fan, INA2xx power, SFP LED), FMan toolchain (fmlib, fmc,
dpa_app), and helper scripts for kernel image creation and deployment.

## Build instructions

All commands run on the build server (amd64 FreeBSD).

The build server should run the same FreeBSD version that OPNsense is based on (e.g., FreeBSD 14.3
for OPNsense 26.1). Mismatched versions can cause ABI issues in cross-compiled kernel modules.

### 1. Prerequisites

```
sudo pkg install -y git aarch64-binutils qemu-user-static
```

### 2. Set up `/build`

All build paths assume the source tree is at `/build`. This directory must contain
`opnsense-build`, `opnsense-src`, and `opnsense-deps`.

**Local development** (source tree lives on the build server):

```
# Clone into /build directly
sudo mkdir /build && sudo chown $(whoami) /build
cd /build
git clone https://github.com/maurice-w/opnsense-vm-images.git opnsense-build
git clone https://github.com/opnsense/src.git opnsense-src
# opnsense-deps is this repository

# Copy the GATEWAY device config into the build system
cp /build/opnsense-deps/config/GATEWAY.conf /build/opnsense-build/device/
```

**Remote source via NFS** (source tree lives on another machine):

```
# Mount the remote share, then expose it at /build via nullfs
echo '/path/to/nfs/mount /mnt/remote nfs rw 0 0' | sudo tee -a /etc/fstab
sudo mount /mnt/remote

sudo mkdir /build
echo '/mnt/remote /build nullfs rw,late 0 0' | sudo tee -a /etc/fstab
sudo mount /build

# Copy the GATEWAY device config into the build system
cp /build/opnsense-deps/config/GATEWAY.conf /build/opnsense-build/device/
```

Using nullfs (rather than a symlink) ensures `pwd` reports `/build/...` in build
output, keeping kernel version strings and module paths clean.

### 3. Prefetch base and packages

Official OPNsense mirrors only publish amd64 sets. For aarch64, use walker.earth.
Check https://opnsense-update.walker.earth/FreeBSD:14:aarch64/26.1/sets/ for available versions.

```
VERSION=26.1.1   # use latest available on the mirror

sudo make -C /build/opnsense-build prefetch-base DEVICE=GATEWAY SETTINGS=26.1 TOOLSDIR=/build/opnsense-build MIRRORS=https://opnsense-update.walker.earth VERSION=$VERSION

# The build system expects a -GATEWAY suffix on the base set
cd /usr/local/opnsense/build/26.1/aarch64/sets
sudo mv base-${VERSION}-aarch64.txz base-${VERSION}-aarch64-GATEWAY.txz

sudo make -C /build/opnsense-build prefetch-packages DEVICE=GATEWAY SETTINGS=26.1 TOOLSDIR=/build/opnsense-build MIRRORS=https://opnsense-update.walker.earth VERSION=$VERSION
```

This skips `make base`, `make ports`, `make core`, and `make plugins` (no cross-compilation needed).

**Important:** Do NOT run `make base` or `make xtools` locally. If an `xtools-*-aarch64.txz`
set exists in the sets directory, remove it before building the image. The xtools overlay/restore
mechanism (`setup_xtools`/`setup_xbase`) is broken for cross-builds and will leave amd64 binaries
in the image.

### 4. Build kernel

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
### 5. Install libxml2 into cross-compilation sysroot

Required by opnsense-deps (fmc links against libxml2).

```
fetch -o /tmp/libxml2.pkg 'https://pkg.FreeBSD.org/FreeBSD:14:aarch64/latest/All/Hashed/libxml2-2.15.1_1~82f6f2bc79.pkg'
mkdir -p /tmp/libxml2-extract && cd /tmp/libxml2-extract && tar xf /tmp/libxml2.pkg

SYSROOT=/usr/obj/build/opnsense-src/arm64.aarch64/tmp
sudo mkdir -p ${SYSROOT}/usr/local/include ${SYSROOT}/usr/local/lib
sudo cp -r /tmp/libxml2-extract/usr/local/include/libxml2 ${SYSROOT}/usr/local/include/
sudo cp -a /tmp/libxml2-extract/usr/local/lib/libxml2* ${SYSROOT}/usr/local/lib/
```

### 6. Build custom modules and tools

```
make -C /build/opnsense-deps -j24 all
```

### 7. Assemble eMMC image

```
sudo make -C /build/opnsense-build arm-5G DEVICE=GATEWAY SETTINGS=26.1 TOOLSDIR=/build/opnsense-build SRCDIR=/build/opnsense-src
```

Output: `/usr/local/opnsense/build/26.1/aarch64/images/OPNsense-*-arm-aarch64-GATEWAY.img`

## Development

The kernel source tree (`opnsense-src`) is patched from upstream OPNsense via
`OPNsense-26.1-aarch64-GATEWAY.patch`. To work on kernel changes:

1. Clone a fresh `opnsense-src` and apply the patch:
   ```
   git clone https://github.com/opnsense/src.git opnsense-src
   cd opnsense-src
   git checkout 2e22159dcc0  # stable/26.1 base commit the patch was generated against
   git apply ../opnsense-deps/OPNsense-26.1-aarch64-GATEWAY.patch
   git checkout -b mono-gateway
   git commit -am "Apply Mono Gateway patch"
   ```

2. Make your changes, build, test, and commit as needed.

3. When done, regenerate the patch. Use `git format-patch` to produce a patch
   with a proper commit header (author, date, subject, diffstat):
   ```
   git format-patch -1 mono-gateway --stdout > ../opnsense-deps/OPNsense-26.1-aarch64-GATEWAY.patch
   ```
   This generates a patch from the single squashed commit on `mono-gateway`.
   If you have multiple commits on top of `stable/26.1`, squash them first:
   ```
   git reset --soft stable/26.1
   git commit -m "Port Mono Gateway (NXP LS1046A) to OPNsense's FreeBSD 14.3"
   git format-patch -1 --stdout > ../opnsense-deps/OPNsense-26.1-aarch64-GATEWAY.patch
   ```

## Local / Test Deployment

Boot the gateway into Recovery Linux. Assign an IP since Recovery Linux has no DHCP (adjust IPs to match your network):

```
ip link set eth3 up
ip addr add 10.0.0.69/24 dev eth3
ip route add default via 10.0.0.1 dev eth3
```

On your build server, serve the image directory over HTTP:

```
python3 -m http.server
```

Then on the gateway, fetch and flash in one go (the image is too large to store locally first):

```
curl http://10.0.0.70:8000/OPNsense-GATEWAY.img | dd of=/dev/mmcblk0 bs=1M
```

Or flash a pre-built image from the mirror (gzip-compressed):

```
curl http://opnsense.mono.si/images/OPNsense-YYYYMMDD-arm-aarch64-GATEWAY.img.gz \
    | gunzip | dd of=/dev/mmcblk0 bs=1M
```

**Warning:** This overwrites the entire eMMC, including any existing OPNsense
installation and its configuration.

## Booting into OPNsense

The board's default boot command loads Recovery Linux. To boot OPNsense instead,
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
> Many of the files in this repository, including the large kernel patch, were ported from Linux sources provided by NXP (originally targeting Linux kernel 5.4). Due to the sheer scope of the porting effort, Claude Opus 4.6 was used to assist with the adaptation of this code to FreeBSD. As such, this project should be considered **highly experimental** and is **not fit for production use** until thorough reviews and testing have been performed by the wider community.