#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VENV="$WORKSPACE/sel4-dev-env"

K1_BUILD="$WORKSPACE/build-ccwmp25-mk-hello-k1"
K0_BUILD="$WORKSPACE/build-ccwmp25-mk-hello-k0"
FINAL_IMAGE="$K0_BUILD/images/rootserver_hello-image-arm-stm32mp25x"
ROOTSERVER_BUILD_ID="ccwmp25-mk-secmmu-markers-01"

if [ "${1:-build}" = "clean" ]; then
    rm -rf "$K1_BUILD" "$K0_BUILD"
    echo "Removed $K1_BUILD and $K0_BUILD"
    exit 0
fi

if [ ! -f "$VENV/bin/activate" ]; then
    echo "ERROR: missing venv at $VENV" >&2
    exit 2
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"

COMMON_ARGS=(
    -G Ninja
    -DCMAKE_TOOLCHAIN_FILE="$WORKSPACE/kernel/gcc.cmake"
    -DCROSS_COMPILER_PREFIX=aarch64-linux-gnu-
    -DSEL4_CACHE_DIR="$WORKSPACE/.sel4_cache"
)

configure_kernel() {
    local build_dir="$1"
    local kid="$2"
    local dts="$3"
    shift 3

    mkdir -p "$build_dir"
    (
        cd "$build_dir"
        cmake "${COMMON_ARGS[@]}" \
            -DMK_KERNEL_ID="$kid" \
            -DKernelCustomDTS="$dts" \
            "$@" \
            "$SCRIPT_DIR"
    )
}

verify_prepared_secondary_config() {
    local build_dir="$1"
    local expected="$2"
    local config="$build_dir/kernel/gen_config/kernel/gen_config.h"

    [ -f "$config" ] || { echo "ERROR: missing kernel config: $config" >&2; exit 4; }
    if [ "$expected" = "enabled" ]; then
        grep -q '^#define CONFIG_ARM_PREPARED_SECONDARY_BOOT  1$' "$config" || {
            echo "ERROR: expected CONFIG_ARM_PREPARED_SECONDARY_BOOT=1 in $config" >&2
            exit 4
        }
    else
        if grep -q '^#define CONFIG_ARM_PREPARED_SECONDARY_BOOT  1$' "$config"; then
            echo "ERROR: K0 unexpectedly has CONFIG_ARM_PREPARED_SECONDARY_BOOT=1 in $config" >&2
            exit 4
        fi
    fi
}

verify_rootserver_build_id() {
    local artifact="$1"

    grep -aFq "$ROOTSERVER_BUILD_ID" "$artifact" || {
        echo "ERROR: missing rootserver build id $ROOTSERVER_BUILD_ID in $artifact" >&2
        exit 5
    }
}

echo "==> Configure/build K1 hello rootserver"
configure_kernel "$K1_BUILD" 1 "$SCRIPT_DIR/dts/stm32mp25x-k1.dts" \
    -DKernelArmPreparedSecondaryBoot=ON
( cd "$K1_BUILD" && ninja )
verify_prepared_secondary_config "$K1_BUILD" enabled

K1_KERNEL_ELF="$K1_BUILD/kernel/kernel.elf"
K1_ROOTSERVER="$K1_BUILD/rootserver/rootserver_hello"
K1_DTB="$K1_BUILD/kernel/kernel.dtb"

for artifact in "$K1_KERNEL_ELF" "$K1_ROOTSERVER" "$K1_DTB"; do
    [ -f "$artifact" ] || { echo "ERROR: missing K1 artifact: $artifact" >&2; exit 3; }
done
verify_rootserver_build_id "$K1_ROOTSERVER"

echo "==> Configure/build K0 bundled multikernel image"
configure_kernel "$K0_BUILD" 0 "$SCRIPT_DIR/dts/stm32mp25x-k0.dts" \
    -DCCWMP25HelloMultikernel=ON \
    -DCCWMP25HelloMultikernelCount=2 \
    -DCCWMP25HelloMultikernelDispatch=OFF \
    -DCCWMP25HelloMultikernelDispatchAfterMmu=OFF \
    -DMULTIKERNEL_K1_KERNEL_ELF="$K1_KERNEL_ELF" \
    -DMULTIKERNEL_K1_ROOTSERVER="$K1_ROOTSERVER" \
    -DMULTIKERNEL_K1_DTB="$K1_DTB"
( cd "$K0_BUILD" && ninja )
verify_prepared_secondary_config "$K0_BUILD" disabled
verify_rootserver_build_id "$K0_BUILD/rootserver/rootserver_hello"

echo
echo "Final image: $FINAL_IMAGE"
ls -lh "$FINAL_IMAGE"
