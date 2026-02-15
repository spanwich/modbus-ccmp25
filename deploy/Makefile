# Build seL4 deployment SD card for CCMP25-DVK
# Requires: u-boot-tools (apt install u-boot-tools)

BUILD_DIR  ?= ../../../build-modbus-ccmp25
IMAGE      := $(BUILD_DIR)/images/capdl-loader-image-arm-stm32mp25x
SDCARD_DIR := sdcard

SCRIPTS    := boot.scr install.scr restore.scr

.PHONY: all clean

all: $(addprefix $(SDCARD_DIR)/,$(SCRIPTS)) $(SDCARD_DIR)/sel4.bin
	@echo ""
	@echo "=== SD card contents ready in $(SDCARD_DIR)/ ==="
	@echo "Copy all files to a FAT32-formatted SD card."
	@echo ""
	@echo "To install seL4: interrupt U-Boot, then run:"
	@echo "  fatload mmc 2 0x90000000 install.scr && source 0x90000000"
	@echo ""
	@echo "To restore Linux:"
	@echo "  fatload mmc 2 0x90000000 restore.scr && source 0x90000000"
	@echo ""

$(SDCARD_DIR)/%.scr: %.cmd | $(SDCARD_DIR)
	mkimage -T script -C none -n "$*" -d $< $@

$(SDCARD_DIR)/sel4.bin: $(IMAGE) | $(SDCARD_DIR)
	cp $< $@

$(SDCARD_DIR):
	mkdir -p $@

clean:
	rm -rf $(SDCARD_DIR)
