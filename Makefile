# This is the name that our final executable will have.
OUTPUT = riskos

# --- User Controllable Variables ---
# To use a different toolchain, set these variables on the command line.
# Example for LLVM: make CC=clang LD=ld.lld
# Example for a cross-compiler: make TOOLCHAIN_PREFIX=x86_64-elf-
TOOLCHAIN_PREFIX := 
CC := $(TOOLCHAIN_PREFIX)gcc
LD := $(TOOLCHAIN_PREFIX)ld

# C and NASM flags
CFLAGS = -g -O2 -pipe
NASMFLAGS = -g
LDFLAGS = 

# --- Internal Flags (Do not change) ---
CFLAGS += -Wall -Wextra -std=gnu11 -ffreestanding
CFLAGS += -fno-stack-protector -fno-stack-check -fno-lto -fno-PIC
CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -m64 -march=x86-64 -mabi=sysv -mno-80387 -mno-mmx
CFLAGS += -mno-sse -mno-sse2 -mno-red-zone -mcmodel=kernel
CFLAGS += -Wa,--noexecstack

CPPFLAGS += -I include -DLIMINE_API_REVISION=3 -MMD -MP

NASMFLAGS += -f elf64 -F dwarf -Wall

LDFLAGS += -m elf_x86_64 -nostdlib -static
LDFLAGS += -z max-page-size=0x1000 --gc-sections -T linker.lds

# --- User space flags ---
USER_CFLAGS = -g -O2 -pipe -std=gnu11 -fno-stack-protector -fno-stack-check -fno-lto -fPIC -m64 -march=x86-64 -mabi=sysv
USER_LDFLAGS = -nostdlib -static -T src/usr/user.lds

# --- Source Files (Generated automatically) ---
C_SOURCES = $(shell find src -type f -name '*.c' -not -path 'src/usr/*')
S_SOURCES = $(shell find src -type f -name '*.S' -not -path 'src/usr/*')
USER_C_SOURCES = $(shell find src/usr -type f -name '*.c')
USER_LIBC_SOURCES = $(shell find src/libc -type f -name '*.c')
USER_LIBC_S_SOURCES = $(shell find src/libc -type f -name '*.S')

# --- Automatic Variable Generation ---
OBJ_DIR = .build
C_OBJS = $(C_SOURCES:%.c=$(OBJ_DIR)/%.c.o)
S_OBJS = $(S_SOURCES:%.S=$(OBJ_DIR)/%.S.o)
USER_BINS = $(USER_C_SOURCES:src/usr/%.c=$(OBJ_DIR)/usr/%)

OBJS = $(C_OBJS) $(S_OBJS)

# Generate dependency file paths from object paths
DEPS = $(OBJS:.o=.d)

# --- Build Rules ---

.PHONY: all
all: bin/$(OUTPUT) .build/initramfs.tar
	@./scripts/make-iso.sh      # Makes a bootable ISO (CD) for the kernel
	@./scripts/make-img.sh      # Makes a bootable USB for the kernel
	@./scripts/make-fat32.sh    # A FAT32 formatted drive attached to the system

# Main link rule
bin/$(OUTPUT): $(OBJS)
	mkdir -p .build/$(@D)
	$(LD) $(LDFLAGS) $^ -o .build/$@

# Rule for the TAR archive
.build/initramfs.tar: $(USER_BINS)
	cd .build/usr && cp ../../src/usr/user.lds . && tar -cf ../initramfs.tar *

# Include header dependencies (the '-' suppresses errors if files are missing)
-include $(DEPS)

# Pattern rule to build C object files
$(OBJ_DIR)/%.c.o: %.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Pattern rule to build Assembly object files
$(OBJ_DIR)/%.S.o: %.S
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Pattern rule to build user C files
$(OBJ_DIR)/usr/%: src/usr/%.c
	mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) $(CPPFLAGS) $(USER_LIBC_S_SOURCES) $< $(USER_LIBC_SOURCES) -o $@ $(USER_LDFLAGS)

.PHONY: clean qemu

clean:
	rm -rf bin $(OBJ_DIR) .build/usr .build/initramfs.tar

qemu: all
	qemu-system-x86_64 -m 8G \
	-cdrom .build/risk-os.iso -boot d \
	-serial stdio -hda .build/test_fat32.img \
	-d int -D qemu.log

qemu-usb: all
	qemu-system-x86_64 -m 8G \
	-device usb-ehci,id=ehci \
	-drive if=none,id=usbstick,file=.build/risk-os.img \
	-device usb-storage,bus=ehci.0,drive=usbstick \
	-serial stdio -hda .build/test_fat32.img -boot menu=on \
	-d int -D qemu.log