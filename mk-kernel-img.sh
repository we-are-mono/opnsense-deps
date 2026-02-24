#!/bin/sh
#
# mk-kernel-img.sh — Create ARM64 Image for U-Boot booti from FreeBSD kernel
#
# loader.efi does NOT work on LS1046A — U-Boot's SDHCI SDMA engine can't DMA
# above 4GB, and the EFI allocator places loader.efi in high memory. All EFI
# filesystem reads fail silently. We boot the kernel directly via U-Boot booti.
#
# objcopy -O binary strips the ELF headers. The kernel's get_load_phys_addr
# uses adr to compute its physical base relative to KERNBASE. Without the
# ARM64 Image header + 0x7C0 padding, .text doesn't land at offset 0x800
# (matching the ELF layout), causing page table corruption on MMU enable.
#
# Usage: mk-kernel-img.sh [kernel_elf] [output]
#   kernel_elf  defaults to /usr/obj/mnt/vision/freebsd-src/arm64.aarch64/sys/MONO-GATEWAY/kernel.full
#   output      defaults to /mnt/vision/kernel.img

set -e

KERNEL_ELF="${1:-/usr/obj/mnt/vision/freebsd-src/arm64.aarch64/sys/MONO-GATEWAY/kernel.full}"
OUTPUT="${2:-/mnt/vision/kernel.img}"
TMPBIN=$(mktemp /tmp/kernel.bin.XXXXXX)
TMPIMG=$(mktemp /tmp/kernel.img.XXXXXX)

trap 'rm -f "$TMPBIN" "$TMPIMG"' EXIT

if [ ! -f "$KERNEL_ELF" ]; then
    echo "Error: kernel ELF not found: $KERNEL_ELF" >&2
    exit 1
fi

echo "Converting $KERNEL_ELF -> $OUTPUT"
objcopy -O binary "$KERNEL_ELF" "$TMPBIN"

python3 -c "
import struct, sys

raw = open('$TMPBIN', 'rb').read()
hdr = bytearray(64)
struct.pack_into('<I', hdr, 0, 0x14000200)       # code0: b 0x800 (branch to entry)
struct.pack_into('<Q', hdr, 16, len(raw) + 0x800) # image_size
struct.pack_into('<Q', hdr, 24, 0x0a)             # flags: LE, 4K pages, anywhere
struct.pack_into('<I', hdr, 56, 0x644d5241)       # magic: ARMd
open('$TMPIMG', 'wb').write(hdr + b'\x00' * 0x7C0 + raw)
print(f'Created {len(hdr) + 0x7C0 + len(raw)} bytes')
"

cp "$TMPIMG" "$OUTPUT" 2>/dev/null || sudo cp "$TMPIMG" "$OUTPUT"
echo "Done: $OUTPUT"
