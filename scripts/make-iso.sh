#!/bin/bash
set -e # Exit on error

rm -rf .build/limine

# Download the latest Limine binary release for the 9.x branch.
git clone https://github.com/limine-bootloader/limine.git --branch=v9.x-binary --depth=1 .build/limine

# Build "limine" utility.
make -C .build/limine

# Create a directory which will be our ISO root.
mkdir -p .build/iso_root

# Copy the relevant files over.
mkdir -p .build/iso_root/boot
cp -v .build/bin/riskos .build/iso_root/boot/
cp -v .build/initramfs.tar .build/iso_root/boot/
mkdir -p .build/iso_root/boot/limine
cp -v limine.conf .build/limine/limine-bios.sys .build/limine/limine-bios-cd.bin \
      .build/limine/limine-uefi-cd.bin .build/iso_root/boot/limine/

# Create the EFI boot tree and copy Limine's EFI executables over.
mkdir -p .build/iso_root/EFI/BOOT
cp -v .build/limine/BOOTX64.EFI .build/iso_root/EFI/BOOT/
cp -v .build/limine/BOOTIA32.EFI .build/iso_root/EFI/BOOT/

# Create the bootable ISO.
xorriso -as mkisofs -R -r -J -b boot/limine/limine-bios-cd.bin \
        -no-emul-boot -boot-load-size 4 -boot-info-table -hfsplus \
        -apm-block-size 2048 --efi-boot boot/limine/limine-uefi-cd.bin \
        -efi-boot-part --efi-boot-image --protective-msdos-label \
        .build/iso_root -o .build/risk-os.iso

# Install Limine stage 1 and 2 for legacy BIOS boot.
.build/limine/limine bios-install .build/risk-os.iso