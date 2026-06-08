# Restore Linux boot from backup
# Usage: interrupt U-Boot, run:
#   fatload mmc 2 0x90000000 restore.scr && source 0x90000000

echo ""
echo "=== Restoring Linux boot ==="
echo ""

# Restore boot.scr from backup on eMMC
echo "Restoring boot.scr.bak -> boot.scr..."
fatload mmc 0:5 ${loadaddr} boot.scr.bak
if test $? -eq 0; then
    fatwrite mmc 0:5 ${loadaddr} boot.scr ${filesize}
    echo "  Linux boot.scr restored"
else
    echo "ERROR: boot.scr.bak not found on eMMC"
    echo "Use Digi installer (run install_linux_fw_sd) to fully restore"
    exit
fi

echo ""
echo "Rebooting into Linux..."
reset
