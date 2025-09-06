#!/bin/bash
set -e # Exit on error

# Create a 16MB file to be our virtual disk
dd if=/dev/zero of=.build/test_fat32.img bs=1M count=16

# Use fdisk to partition the image
# o: Create a new empty DOS partition table (MBR)
# n: Add a new partition
# p: Primary partition
# 1: Partition number 1
#  : Default first sector (usually 2048)
#  : Default last sector (end of the disk)
# t: Change partition type
# c: Set type to 0x0C, which is "W95 FAT32 (LBA)"
# w: Write changes and exit
printf "o\nn\np\n1\n\n\nt\nc\nw\n" | fdisk .build/test_fat32.img

# Find the partition offset
fdisk -l .build/test_fat32.img

# Use a loopback device to format the partition that we found
START_SECTOR=$(fdisk -l .build/test_fat32.img | grep 'test_fat32.img1' | awk '{print $2}')
OFFSET=$((START_SECTOR * 512))
echo "Partition 1 starts at sector $START_SECTOR, which is offset $OFFSET bytes."

LOOP_DEV=$(sudo losetup --find --show --offset $OFFSET .build/test_fat32.img)
echo "Partition mapped to loop device: $LOOP_DEV"
sudo mkfs.fat -F 32 $LOOP_DEV

# Mount the FAT32 partition and create a file for testing
mkdir -p mnt
sudo mount $LOOP_DEV mnt
sudo sh -c 'echo "Hello from my FAT32 disk!" > mnt/hello.txt'
sudo umount mnt

# Cleanup
sudo losetup --detach $LOOP_DEV
sudo rmdir mnt