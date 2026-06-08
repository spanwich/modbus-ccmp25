#!/bin/bash
#===============================================================================
# USB-OTG deploy for seL4 on CCMP25-DVK (sel4-multikernel fork)
#
# Writes an seL4 image (as sel4.bin) and boot.scr to eMMC partition 5 via USB
# fastboot, using uuu's built-in `fat_write` script.
#
# Prerequisites:
#   - uuu installed (apt install uuu)
#   - u-boot-tools installed (mkimage)
#   - Board in fastboot mode:
#       1. Connect USB-C OTG cable (separate from the debug-USB console cable)
#       2. Interrupt U-Boot on the serial console (ttyACM1)
#       3. => fastboot 0      (board enumerates as 0483:0afb, in uuu's list)
#
# Usage:
#   ./usb-deploy.sh                          # default: multikernel K0 build
#   ./usb-deploy.sh --image <path-to-image>  # flash a specific image
#   ./usb-deploy.sh <build-dir>              # flash <build-dir>/images/rootserver_hello-*
#   ./usb-deploy.sh --no-scr ...             # skip re-writing boot.scr
#
# Common images in this fork:
#   build-ccwmp25-mk-hello-k0/images/rootserver_hello-image-arm-stm32mp25x  (multikernel)
#   build-ccwmp25-mk-hello-plain/images/rootserver_hello-image-arm-stm32mp25x (single-kernel discriminator)
#===============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# eMMC partition 5 in U-Boot notation
MMC_DEV="mmc"
PART_NUM="0:5"
IMAGE_NAME="rootserver_hello-image-arm-stm32mp25x"

WRITE_SCR=1
IMAGE=""
BUILD_DIR=""

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { printf "${CYAN}%s${NC}\n" "$*"; }
ok()   { printf "${GREEN}%s${NC}\n" "$*"; }
err()  { printf "${RED}%s${NC}\n" "$*" >&2; }

#--- Parse args ---
while [ $# -gt 0 ]; do
    case "$1" in
        --image)  IMAGE="$2"; shift 2 ;;
        --no-scr) WRITE_SCR=0; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *)        BUILD_DIR="$1"; shift ;;
    esac
done

# Resolve the image to flash
if [ -z "${IMAGE}" ]; then
    BUILD_DIR="${BUILD_DIR:-${WORKSPACE}/build-ccwmp25-mk-hello-k0}"
    IMAGE="${BUILD_DIR}/images/${IMAGE_NAME}"
fi

#--- Preflight ---
command -v uuu     &>/dev/null || { err "uuu not found. sudo apt install uuu"; exit 1; }
command -v mkimage &>/dev/null || { err "mkimage not found. sudo apt install u-boot-tools"; exit 1; }
[ -f "${IMAGE}" ] || { err "seL4 image not found: ${IMAGE}"; err "Build first, or pass --image <path>."; exit 1; }

#--- Stage files ---
TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT
cp "${IMAGE}" "${TMPDIR}/sel4.bin"
if [ "${WRITE_SCR}" -eq 1 ]; then
    info "Building boot.scr from boot.cmd..."
    mkimage -T script -C none -n "boot" -d "${SCRIPT_DIR}/boot.cmd" "${TMPDIR}/boot.scr" >/dev/null
fi

info ""
info "============================================"
info "  seL4 USB-OTG Deploy for CCMP25-DVK"
info "============================================"
info "  image : ${IMAGE}"
info "  target: eMMC ${MMC_DEV} ${PART_NUM} (FAT)"
info ""

# Hint if no board is enumerated yet (uuu will still wait/poll)
if [ "$(uuu -lsusb 2>&1 | grep -c 'FB' || true)" -eq 0 ]; then
    info "No board in fastboot mode yet. On U-Boot: => fastboot 0"
    info "Waiting for board (Ctrl+C to cancel)..."
fi

#--- Flash via uuu built-in fat_write: <local-file> <dev> <part> <fat-name> ---
info "Writing sel4.bin -> ${MMC_DEV} ${PART_NUM}..."
uuu -v -b fat_write "${TMPDIR}/sel4.bin" "${MMC_DEV}" "${PART_NUM}" sel4.bin

if [ "${WRITE_SCR}" -eq 1 ]; then
    info "Writing boot.scr -> ${MMC_DEV} ${PART_NUM}..."
    uuu -v -b fat_write "${TMPDIR}/boot.scr" "${MMC_DEV}" "${PART_NUM}" boot.scr
fi

ok ""
ok "Deploy complete. On U-Boot: press Ctrl+C to exit fastboot, then 'reset'."
