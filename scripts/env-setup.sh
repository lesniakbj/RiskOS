#!/bin/bash
set -e # Exit on error

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

# Update package list and install dependencies
apt-get update
apt-get install -y build-essential wget tar qemu-system-x86 grub-common xorriso

# Run the cross-compiler build script
echo "--- Running cross-compiler build script ---"
bash ../.toolchain/build-cross.sh
