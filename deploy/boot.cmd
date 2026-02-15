# seL4 boot script for CCMP25-DVK (STM32MP255)
# Loaded by U-Boot from eMMC partition 5 via bootcmd -> loadscript -> source
#
# Image format: uImage (bootm handles load address automatically)

echo "seL4 boot - CCMP25-DVK (STM32MP255)"
echo "Loading sel4.bin from mmc 0:5..."

fatload mmc 0:5 0x90000000 sel4.bin
if test $? -ne 0; then
    echo "ERROR: fatload sel4.bin failed"
    echo "Falling back to Linux boot..."
    dboot linux mmc 0:5
fi

echo "Starting seL4 via bootm..."
bootm 0x90000000
