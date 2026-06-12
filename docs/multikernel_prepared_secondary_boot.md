# Prepared Secondary Boot Mode

`KernelArmPreparedSecondaryBoot` is a global ARM AArch64 kernel option for asymmetric multikernel bring-up where a secondary kernel image is entered by a handoff provider after the image has already been loaded and made coherent.

## Configuration

- CMake option: `KernelArmPreparedSecondaryBoot`
- Kernel config symbol: `CONFIG_ARM_PREPARED_SECONDARY_BOOT`
- Default: off
- Scope: ARM AArch64 secondary kernel instances only

The option is intentionally not platform-specific. A board project enables it for the prepared secondary kernel build, for example K1, while leaving the primary K0 kernel on the default boot path.

## Contract

When this mode is enabled, the handoff provider owns preparation of all memory the secondary kernel consumes at entry:

- secondary kernel ELF image
- secondary rootserver/user image
- secondary DTB
- boot metadata and entry arguments
- page tables or trampoline metadata used before the kernel establishes its normal state

Those regions must be cleaned by virtual address to the point of coherency before the secondary core enters the kernel. The mode disables ARM set/way data-cache maintenance in the kernel boot path because whole-cache operations can target secure firmware lines on systems with secure SRAM firewalls. Address-scoped cache maintenance remains the preferred preparation mechanism.

## Verification Boundary

This is a boot-mode contract, not a formal verification claim. It changes low-level ARM cache-maintenance behavior and should be treated as outside any existing verified kernel configuration until separately reviewed and verified.

## STM32MP25x Usage

`multikernel_hello/build-stm32mp25x.sh` enables `KernelArmPreparedSecondaryBoot=ON` only for K1. The script checks K1's generated kernel config for `CONFIG_ARM_PREPARED_SECONDARY_BOOT`, checks K0 does not enable it, and verifies the rootserver build marker `ccwmp25-mk-prepared-secondary-01` is present in both rootserver binaries.

Expected proof for this project:

- build-time K1 generated config contains `CONFIG_ARM_PREPARED_SECONDARY_BOOT  1`
- UART reaches `[K1] ROOTSERVER_BUILD: ccwmp25-mk-prepared-secondary-01`

There is intentionally no early kernel UART marker for this mode: before `map_kernel_window()` the secondary kernel may still be running on handoff page tables whose `KDEV_BASE` mapping is not the final seL4 device mapping.
