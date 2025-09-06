#!/bin/bash

# Exit on error
set -e

# Config
IMAGE_NAME=".build/risk-os.img"
IMAGE_SIZE_MB=64
MOUNT_POINT="mnt_usb"
KERNEL_FILE=".build/bin/riskos"
INITRAMFS_FILE=".build/initramfs.tar"
LIMINE_CONFIG="limine.conf"
LIMINE_SYS_FILE=".build/limine/limine-bios.sys"
LIMINE_INSTALL_CMD=".build/limine/limine"

# Check that the required files exist before we start.
if [ ! -f "$KERNEL_FILE" ]; then
    echo "Error: Kernel file not found at $KERNEL_FILE"
    exit 1
fi
if [ ! -f "$LIMINE_CONFIG" ]; then
    echo "Error: Limine config not found at $LIMINE_CONFIG"
    exit 1
fi
if [ ! -f "$LIMINE_SYS_FILE" ]; then
    echo "Error: limine.sys not found at $LIMINE_SYS_FILE"
    exit 1
fi
if ! command -v $LIMINE_INSTALL_CMD &> /dev/null; then
    echo "Error: The '$LIMINE_INSTALL_CMD' command could not be found."
    echo "Please ensure the Limine binary package is installed and in your system's PATH."
    exit 1
fi

echo ">>> Step 1: Creating blank ${IMAGE_SIZE_MB}MB disk image..."
dd if=/dev/zero of="$IMAGE_NAME" bs=1M count=$IMAGE_SIZE_MB

echo ">>> Step 2: Partitioning the disk image with a bootable MBR partition..."
# o: Create a new empty DOS partition table (MBR)
# n: Add a new partition
# p: Primary partition
# 1: Partition number 1
#  : Default first sector
#  : Default last sector
# a: Mark the first partition as active/bootable
# w: Write changes and exit
printf "o\nn\np\n1\n\n\na\nw\n" | fdisk "$IMAGE_NAME"

echo ">>> Step 3: Installing the Limine bootloader to the MBR..."
$LIMINE_INSTALL_CMD bios-install "$IMAGE_NAME"

echo ">>> Step 4: Formatting the partition as FAT32..."
# Find the start sector of the first partition to calculate the offset
START_SECTOR=$(fdisk -l "$IMAGE_NAME" | grep "${IMAGE_NAME}1" | awk '{if ($2 == "*") {print $3} else {print $2}}')
OFFSET=$((START_SECTOR * 512))

# Use losetup to create a temporary loop device for our partition
LOOP_DEV=$(sudo losetup --find --show --offset $OFFSET "$IMAGE_NAME")
echo "Partition mapped to loop device: $LOOP_DEV"
sudo mkfs.fat -F 32 "$LOOP_DEV"

echo ">>> Step 5: Mounting the filesystem and copying files..."
sudo mkdir -p "$MOUNT_POINT"
sudo mount "$LOOP_DEV" "$MOUNT_POINT"

# Copy the OS files into a /boot directory, which is a standard practice.
sudo mkdir -p "$MOUNT_POINT/boot"
sudo cp "$KERNEL_FILE" "$MOUNT_POINT/boot/riskos"
sudo cp "$INITRAMFS_FILE" "$MOUNT_POINT/boot/initramfs.tar"
sudo cp "$LIMINE_CONFIG" "$MOUNT_POINT/boot/limine.conf" # Rename to .cfg for convention
sudo cp "$LIMINE_SYS_FILE" "$MOUNT_POINT/boot/limine-bios.sys"

# It's good practice to sync to ensure all writes are flushed to the disk image
echo "Syncing filesystem..."
sudo sync

pwd
ls -la mnt_usb

echo ">>> Step 6: Cleaning up..."
sudo umount "$MOUNT_POINT"
sudo losetup --detach "$LOOP_DEV"
sudo rmdir "$MOUNT_POINT"

echo ""
echo "--- Success! ---"
echo "Your bootable disk image '$IMAGE_NAME' has been created."
echo "Run it with the following QEMU command:"
echo ""
echo "qemu-system-x86_64 -m 2G -device usb-ehci,id=ehci -drive if=none,id=usbstick,file=$IMAGE_NAME -device usb-storage,bus=ehci.0,drive=usbstick -serial stdio"
echo ""
