#!/bin/bash
#
# Setup script for building the Linux kernel for the STM32MP25x VM guest.
#
# This clones the Digi yocto-linux kernel (v6.6 branch) and provides
# instructions for cross-compiling a minimal kernel for the seL4 VM.
#
# Usage:
#   cd projects/modbus_ccmp25/linux
#   bash setup-kernel.sh
#
# SPDX-License-Identifier: BSD-2-Clause

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_DIR="${SCRIPT_DIR}/yocto-linux"
CROSS_COMPILE="aarch64-linux-gnu-"

echo "=== MODBUS CCMP25 — Linux VM Kernel Setup ==="
echo ""

# Step 1: Clone yocto-linux if not present
if [ ! -d "${KERNEL_DIR}" ]; then
    echo "[1/3] Cloning digidotcom/yocto-linux (v6.6/digi branch, shallow)..."
    echo "      This may take several minutes (~500MB download)."
    git clone --depth 1 -b v6.6/digi \
        https://github.com/digidotcom/yocto-linux.git \
        "${KERNEL_DIR}"
else
    echo "[1/3] yocto-linux already cloned at ${KERNEL_DIR}"
fi

echo ""
echo "[2/3] Kernel source ready. To build:"
echo ""
echo "  cd ${KERNEL_DIR}"
echo "  make ARCH=arm64 CROSS_COMPILE=${CROSS_COMPILE} defconfig"
echo "  # Or use Digi's defconfig if available:"
echo "  # make ARCH=arm64 CROSS_COMPILE=${CROSS_COMPILE} ccmp25_defconfig"
echo ""
echo "  make ARCH=arm64 CROSS_COMPILE=${CROSS_COMPILE} -j\$(nproc) Image"
echo ""
echo "[3/3] After building, copy the kernel image:"
echo ""
echo "  cp ${KERNEL_DIR}/arch/arm64/boot/Image ${SCRIPT_DIR}/linux-Image"
echo ""
echo "=== Also needed: rootfs.cpio.gz ==="
echo ""
echo "Build a minimal BusyBox-based initrd or use Yocto to generate one."
echo "Place the result at: ${SCRIPT_DIR}/rootfs.cpio.gz"
echo ""
echo "Then build the VM-enabled MODBUS CCMP25:"
echo ""
echo "  cd camkes-vm-examples"
echo "  mkdir build-modbus-vm && cd build-modbus-vm"
echo "  cmake -G Ninja -DPLATFORM=stm32mp25x -DSTM32MP25X_VM=ON \\"
echo "    -DCROSS_COMPILER_PREFIX=aarch64-linux-gnu- \\"
echo "    -DCMAKE_TOOLCHAIN_FILE=../kernel/gcc.cmake \\"
echo "    ../projects/modbus_ccmp25"
echo "  ninja"
