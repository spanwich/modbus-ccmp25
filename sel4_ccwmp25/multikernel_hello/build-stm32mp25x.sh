#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VENV="$WORKSPACE/sel4-dev-env"

K1_BUILD="$WORKSPACE/build-ccwmp25-mk-hello-k1"
K0_BUILD="$WORKSPACE/build-ccwmp25-mk-hello-k0"
FINAL_IMAGE="$K0_BUILD/images/rootserver_hello-image-arm-stm32mp25x"

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
    if [ ! -f "$build_dir/CMakeCache.txt" ]; then
        (
            cd "$build_dir"
            cmake "${COMMON_ARGS[@]}" \
                -DMK_KERNEL_ID="$kid" \
                -DKernelCustomDTS="$dts" \
                "$@" \
                "$SCRIPT_DIR"
        )
    fi
}

echo "==> Configure/build K1 hello rootserver"
configure_kernel "$K1_BUILD" 1 "$SCRIPT_DIR/dts/stm32mp25x-k1.dts"
( cd "$K1_BUILD" && ninja )

K1_KERNEL_ELF="$K1_BUILD/kernel/kernel.elf"
K1_ROOTSERVER="$K1_BUILD/rootserver/rootserver_hello"
K1_DTB="$K1_BUILD/kernel/kernel.dtb"

for artifact in "$K1_KERNEL_ELF" "$K1_ROOTSERVER" "$K1_DTB"; do
    [ -f "$artifact" ] || { echo "ERROR: missing K1 artifact: $artifact" >&2; exit 3; }
done

echo "==> Configure/build K0 bundled multikernel image"
configure_kernel "$K0_BUILD" 0 "$SCRIPT_DIR/dts/stm32mp25x-k0.dts" \
    -DCCWMP25HelloMultikernel=ON \
    -DCCWMP25HelloMultikernelCount=2 \
    -DCCWMP25HelloMultikernelDispatch=ON \
    -DCCWMP25HelloMultikernelDispatchAfterMmu=OFF \
    -DMULTIKERNEL_K1_KERNEL_ELF="$K1_KERNEL_ELF" \
    -DMULTIKERNEL_K1_ROOTSERVER="$K1_ROOTSERVER" \
    -DMULTIKERNEL_K1_DTB="$K1_DTB"
( cd "$K0_BUILD" && ninja )

echo
echo "Final image: $FINAL_IMAGE"
ls -lh "$FINAL_IMAGE"
