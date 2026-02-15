# Install seL4 to eMMC from SD card
# Usage: interrupt U-Boot, run:
#   fatload mmc 2 0x90000000 install.scr && source 0x90000000
#
# This backs up the original boot.scr and installs seL4.

echo ""
echo "=== seL4 Installer for CCMP25-DVK ==="
echo ""

# Step 1: Backup original boot.scr from eMMC
echo "Backing up original boot.scr..."
fatload mmc 0:5 ${loadaddr} boot.scr
if test $? -eq 0; then
    fatwrite mmc 0:5 ${loadaddr} boot.scr.bak ${filesize}
    echo "  Saved as boot.scr.bak on eMMC partition 5"
else
    echo "  WARNING: No boot.scr found on eMMC (skipping backup)"
fi

# Step 2: Copy seL4 image from SD to eMMC
echo "Installing sel4.bin to eMMC partition 5..."
updatefile linux mmc 2 sel4.bin sel4.bin
if test $? -ne 0; then
    echo "ERROR: Failed to copy sel4.bin"
    exit
fi

# Step 3: Copy seL4 boot.scr from SD to eMMC (overwrites Linux boot.scr)
echo "Installing boot.scr to eMMC partition 5..."
updatefile linux mmc 2 boot.scr boot.scr
if test $? -ne 0; then
    echo "ERROR: Failed to copy boot.scr"
    exit
fi

echo ""
echo "=== Installation complete ==="
echo "eMMC partition 5 now contains:"
fatls mmc 0:5
echo ""
echo "Rebooting into seL4..."
reset
