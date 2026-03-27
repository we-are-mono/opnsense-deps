#!/usr/bin/env python3
"""
Create a GPT partition table with minimal entries (4) on a block device or file.
Avoids FreeBSD gpart's 128-entry minimum, keeping the table under 2KB so
firmware can be placed at 4KB offset.

Usage: mkgpt.py <device> <boot_size_mb> <disk_size>
  device       - block device or image file (e.g. /dev/md0)
  boot_size_mb - size of EFI/FAT boot partition in MB (e.g. 100)
  disk_size    - total disk size in bytes (from mdconfig or device)

Creates:
  Partition 1: EFI System (FAT) at sector 65536 (32MB), size boot_size_mb
  Partition 2: FreeBSD ZFS filling remainder
"""

import struct
import sys
import uuid
import zlib

SECTOR = 512
NUM_ENTRIES = 4
ENTRY_SIZE = 128

# GPT type GUIDs (little-endian mixed format)
EFI_SYSTEM_GUID = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
FREEBSD_ZFS_GUID = uuid.UUID("516e7cba-6ecf-11d6-8ff8-00022d09712b")

def uuid_to_mixed_endian(u):
    """Convert UUID to GPT's mixed-endian format."""
    b = u.bytes
    return (b[3::-1] + b[5:3:-1] + b[7:5:-1] + b[8:])

def make_protective_mbr(disk_sectors):
    """Create a protective MBR with one 0xEE partition."""
    mbr = bytearray(512)
    # Partition entry 1 at offset 446
    pe = struct.pack("<BBBBBBBBII",
        0x00,       # status (not bootable)
        0x00, 0x02, 0x00,  # CHS first (0/0/2)
        0xEE,       # type (GPT protective)
        0xFF, 0xFF, 0xFF,  # CHS last
        1,          # LBA start
        min(disk_sectors - 1, 0xFFFFFFFF))  # LBA size
    mbr[446:446+16] = pe
    mbr[510] = 0x55
    mbr[511] = 0xAA
    return bytes(mbr)

def make_gpt_entry(type_guid, unique_guid, start_lba, end_lba, name):
    """Create a 128-byte GPT partition entry."""
    entry = bytearray(ENTRY_SIZE)
    entry[0:16] = uuid_to_mixed_endian(type_guid)
    entry[16:32] = uuid_to_mixed_endian(unique_guid)
    struct.pack_into("<QQ", entry, 32, start_lba, end_lba)
    # Name: UTF-16LE, max 36 chars
    name_bytes = name.encode("utf-16-le")[:72]
    entry[56:56+len(name_bytes)] = name_bytes
    return bytes(entry)

def make_gpt_header(disk_sectors, my_lba, alt_lba, first_usable, last_usable,
                    disk_guid, entry_start_lba, entries_crc):
    """Create a 92-byte GPT header (padded to 512 bytes)."""
    hdr = bytearray(SECTOR)
    struct.pack_into("<8sIIIIQQQQ16sQIII", hdr, 0,
        b"EFI PART",   # signature
        0x00010000,     # revision 1.0
        92,             # header size
        0,              # header CRC (filled below)
        0,              # reserved
        my_lba,
        alt_lba,
        first_usable,
        last_usable,
        uuid_to_mixed_endian(disk_guid),
        entry_start_lba,
        NUM_ENTRIES,
        ENTRY_SIZE,
        entries_crc)
    # Compute header CRC over first 92 bytes
    hdr_crc = zlib.crc32(bytes(hdr[:92])) & 0xFFFFFFFF
    struct.pack_into("<I", hdr, 16, hdr_crc)
    return bytes(hdr)

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <device> <boot_size_mb> <disk_size_bytes>")
        sys.exit(1)

    device = sys.argv[1]
    boot_mb = int(sys.argv[2])
    disk_size = int(sys.argv[3])
    disk_sectors = disk_size // SECTOR

    # Entry table size in sectors
    tbl_sectors = (NUM_ENTRIES * ENTRY_SIZE + SECTOR - 1) // SECTOR  # = 1

    # Partition layout
    first_usable = 2 + tbl_sectors  # LBA 3 (after MBR + header + 1 sector entries)
    last_usable = disk_sectors - 2 - tbl_sectors  # leave room for backup

    boot_start = 65536  # 32MB
    boot_sectors = boot_mb * 1024 * 1024 // SECTOR
    boot_end = boot_start + boot_sectors - 1

    zfs_start = boot_end + 1
    zfs_end = last_usable

    disk_guid = uuid.uuid4()

    # Build partition entries
    entries = bytearray(NUM_ENTRIES * ENTRY_SIZE)
    e1 = make_gpt_entry(EFI_SYSTEM_GUID, uuid.uuid4(), boot_start, boot_end, "boot")
    e2 = make_gpt_entry(FREEBSD_ZFS_GUID, uuid.uuid4(), zfs_start, zfs_end, "rootpool")
    entries[0:128] = e1
    entries[128:256] = e2
    entries_crc = zlib.crc32(bytes(entries)) & 0xFFFFFFFF

    # Primary header at LBA 1
    primary = make_gpt_header(disk_sectors, 1, disk_sectors - 1,
                              first_usable, last_usable, disk_guid,
                              2, entries_crc)

    # Backup header at last LBA
    backup = make_gpt_header(disk_sectors, disk_sectors - 1, 1,
                             first_usable, last_usable, disk_guid,
                             disk_sectors - 1 - tbl_sectors, entries_crc)

    # Write to device
    with open(device, "r+b") as f:
        # Protective MBR
        f.seek(0)
        f.write(make_protective_mbr(disk_sectors))
        # Primary header
        f.seek(SECTOR)
        f.write(primary)
        # Primary entries
        f.seek(2 * SECTOR)
        f.write(bytes(entries))
        # Backup entries
        f.seek((disk_sectors - 1 - tbl_sectors) * SECTOR)
        f.write(bytes(entries))
        # Backup header
        f.seek((disk_sectors - 1) * SECTOR)
        f.write(backup)

    print(f"GPT created: {NUM_ENTRIES} entries, boot@{boot_start} ({boot_mb}MB), "
          f"zfs@{zfs_start}-{zfs_end}")

if __name__ == "__main__":
    main()
