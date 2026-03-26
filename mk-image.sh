#!/bin/sh
#
# mk-image.sh -- Build a ZFS OPNsense ARM image directly
#
# This script replaces arm.sh's UFS image creation with ZFS.
# It sources opnsense-build's common.sh for all setup_* functions,
# so it must be run from ${TOOLSDIR}/build/ with the same arguments
# that the opnsense-build Makefile passes to build scripts.
#
# Usage (invoked by opnsense-deps Makefile):
#   cd ${TOOLSDIR}/build && sh /usr/deps/mk-image.sh [common.sh args] 5G
#
# Copyright 2026 Mono Technologies Inc.
# SPDX-License-Identifier: BSD-2-Clause

set -e

SELF=arm

. ./common.sh

if [ ${PRODUCT_ARCH} != aarch64 ]; then
	echo ">>> Cannot build arm image with arch ${PRODUCT_ARCH}"
	exit 1
fi

check_image ${SELF} ${@}

IMGSIZE="5G"

if [ -n "${1}" ]; then
	IMGSIZE=${1}
fi

ZPOOL=pool0
ARMIMG="${IMAGESDIR}/${PRODUCT_RELEASE}-arm-${PRODUCT_ARCH}${PRODUCT_DEVICE+"-${PRODUCT_DEVICE}"}.img"

sh ./clean.sh ${SELF}

setup_stage ${STAGEDIR}

# ---------------------------------------------------------------
# Check for stale ZFS pool
# ---------------------------------------------------------------
for IMPORT in $(zpool import 2>/dev/null | awk '$1 == "pool:" { print $2 }'); do
	if [ "${IMPORT}" = "${ZPOOL}" ]; then
		echo ">>> ERROR: ZFS pool '${ZPOOL}' already exists" >&2
		exit 1
	fi
done

# ---------------------------------------------------------------
# Create GPT image with FAT boot + ZFS root
# ---------------------------------------------------------------
echo ">>> Creating ZFS image (${IMGSIZE})..."

truncate -s ${IMGSIZE} ${ARMIMG}
DEV=$(mdconfig -a -t vnode -f ${ARMIMG})

gpart create -s GPT ${DEV}
gpart add -t efi -l boot -s ${ARM_FAT_SIZE} ${DEV}
gpart add -t freebsd-zfs -l rootpool ${DEV}
newfs_msdos -L BOOT -F 16 /dev/${DEV}p1

echo ">>> Creating ZFS pool..."

zpool create -o cachefile=none -R ${STAGEDIR} ${ZPOOL} /dev/${DEV}p2

# Dataset layout (matches FreeBSD standard / OPNsense vm.sh)
zfs create -o mountpoint=none ${ZPOOL}/ROOT
zfs create -o mountpoint=/ ${ZPOOL}/ROOT/default
zfs create -o mountpoint=/tmp -o exec=on -o setuid=off ${ZPOOL}/tmp
zfs create -o mountpoint=/usr -o canmount=off ${ZPOOL}/usr
zfs create ${ZPOOL}/usr/home
zfs create -o mountpoint=/var -o canmount=off ${ZPOOL}/var
zfs create -o exec=off -o setuid=off ${ZPOOL}/var/audit
zfs create -o exec=off -o setuid=off ${ZPOOL}/var/crash
zfs create -o exec=off -o setuid=off ${ZPOOL}/var/log
zfs create -o atime=on ${ZPOOL}/var/mail
zfs create -o setuid=off ${ZPOOL}/var/tmp
zpool set bootfs=${ZPOOL}/ROOT/default ${ZPOOL}

# ---------------------------------------------------------------
# Populate rootfs (same sequence as arm.sh)
# ---------------------------------------------------------------
setup_base ${STAGEDIR}
setup_kernel ${STAGEDIR}
setup_xtools ${STAGEDIR}
setup_packages ${STAGEDIR}
setup_extras ${STAGEDIR} ${SELF}
setup_entropy ${STAGEDIR}
setup_xbase ${STAGEDIR}

# ZFS fstab: only the FAT boot partition
cat > ${STAGEDIR}/etc/fstab << EOF
# Device		Mountpoint	FStype	Options		Dump	Pass#
/dev/gpt/boot		/boot/msdos	msdosfs	rw,noatime	0	0
EOF

# ---------------------------------------------------------------
# Populate FAT boot partition
# ---------------------------------------------------------------
mkdir -p ${STAGEDIR}/boot/msdos
mount_msdosfs /dev/${DEV}p1 ${STAGEDIR}/boot/msdos

arm_install_uboot

# EFI boot not used (U-Boot booti), but keep the check for completeness
if [ -n "${PRODUCT_UEFI}" -a -z "${PRODUCT_UEFI%%*"${SELF}"*}" ]; then
	setup_efiboot ${STAGEDIR}/efiboot.img ${STAGEDIR}/boot/loader.efi
	cp -r ${STAGEDIR}/efiboot.img.d/efi ${STAGEDIR}/boot/msdos/efi
fi

# ---------------------------------------------------------------
# Finalize
# ---------------------------------------------------------------
echo -n ">>> Building arm image... "

sync
umount ${STAGEDIR}/boot/msdos
zpool export ${ZPOOL}
mdconfig -d -u ${DEV}

echo "done"

sign_image ${ARMIMG}
