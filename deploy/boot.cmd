# seL4 boot script for CCMP25-DVK (STM32MP255)
# Loaded by U-Boot from eMMC partition 5 via bootcmd -> loadscript -> source
#
# Image format: uImage (bootm handles load address automatically)
# Note: bootm on ARM64 requires an FDT argument. We pass the board DTB
# (still on eMMC from Linux install) to satisfy U-Boot. seL4's elfloader
# ignores it and uses its own embedded DTB.

echo "seL4 boot - CCMP25-DVK (STM32MP255)"

echo "Loading sel4.bin from mmc 0:5..."
fatload mmc 0:5 0x90000000 sel4.bin
if test $? -ne 0; then
    echo "ERROR: fatload sel4.bin failed"
    echo "Falling back to Linux boot..."
    dboot linux mmc 0:5
fi

echo "Loading DTB (required by bootm)..."
fatload mmc 0:5 0x88000000 ccmp25-dvk.dtb
if test $? -ne 0; then
    echo "WARNING: No DTB found, trying bootm without FDT..."
    bootm 0x90000000
fi

# Disable watchdog before jumping to seL4 (32s IWDG timeout otherwise)
echo "Stopping watchdog..."
wdt stop

echo "Starting seL4 via bootm..."
bootm 0x90000000 - 0x88000000
