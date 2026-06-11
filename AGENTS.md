# Repository Guidelines

## Project Structure & Module Organization

This repository is a CAmkES/seL4 MODBUS gateway for `qemu-arm-virt` simulation and Digi CCMP25-DVK (`stm32mp25x`) hardware. Top-level assemblies live in `ics_dual_nic.camkes`, `ics_stm32mp25x.camkes`, and `ics_vm_stm32mp25x.camkes`. Build configuration is in `CMakeLists.txt` and `settings.cmake`.

Component code is under `components/`: `ICS_Inbound/` and `ICS_Outbound/` contain MODBUS validation components, `WatchdogKicker/` handles OP-TEE watchdog servicing, `VirtIO_Net{0,1}_Driver/` are QEMU-only NIC drivers, and shared headers/helpers live in `components/include/` and `components/lib/`. Platform files are in `stm32mp25x/` and `plat_include/stm32mp25x/`. Linux VM inputs are staged from `linux/`. Deployment scripts are in `deploy/`, and design/investigation notes are in `docs/`.

`multikernel_hello/` is a separate minimal STM32MP25x multikernel bring-up app. It bypasses the CAmkES gateway and builds independent per-core seL4 rootservers using its own `CMakeLists.txt`, `settings.cmake`, DTS files, and `rootserver/` sources.

## Build, Test, and Development Commands

Run builds from the parent `camkes-vm-examples` tree, not from this project directory. CAmkES requires two CMake passes with AST generation between them.

```bash
cmake -G Ninja -DPLATFORM=qemu-arm-virt -DCMAKE_TOOLCHAIN_FILE=../kernel/gcc.cmake ../projects/sel4_ccwmp25
bash ast.pickle.cmd && bash camkes-gen.cmake.cmd
cmake -G Ninja -DPLATFORM=qemu-arm-virt -DCMAKE_TOOLCHAIN_FILE=../kernel/gcc.cmake ../projects/sel4_ccwmp25
ninja
./simulate
```

For hardware native builds, use `-DPLATFORM=stm32mp25x -DCROSS_COMPILER_PREFIX=aarch64-linux-gnu-`. For the VM build, add `-DSTM32MP25X_VM=ON` and provide `linux/linux-Image` plus `linux/rootfs.cpio.gz`. Build deployment scripts with `make -C deploy`.

For the multikernel hello bring-up, run `./multikernel_hello/build-stm32mp25x.sh` from this project. The script creates sibling build directories under the workspace, builds K1 first, then bundles K0 with the K1 artifacts. Use `./multikernel_hello/build-stm32mp25x.sh clean` to remove those generated build directories.

## Coding Style & Naming Conventions

Use C99-compatible C and CMake consistent with the existing files. Keep indentation at four spaces in C/CMake blocks, prefer descriptive `snake_case` for functions and variables, and reserve all-caps names for macros and constants. Match existing component names (`ICS_Inbound`, `VirtIO_Net0_Driver`) and keep platform-specific code guarded by platform build branches. Do not introduce unrelated formatting churn in generated EverParse files.

## Testing Guidelines

There is no checked-in unit-test suite. Validate changes by building the smallest relevant target, then run `./simulate` for QEMU-facing changes. Hardware changes require flashing through the `deploy/` SD-card flow and checking UART output. For validator or policy changes, document the MODBUS scenario exercised and include packet/register details in the PR.

## Commit & Pull Request Guidelines

Use concise imperative commit subjects such as `Fix watchdog SMC cadence` or `Add STM32MP25x VM DTS notes`. Keep each commit scoped to one behavior or investigation.

Pull requests should include the target platform, build commands run, test or boot evidence, and links to relevant `docs/` files or issue notes. Include UART logs, QEMU output, or deployment steps when behavior changes. Call out required external artifacts such as `linux/linux-Image` or `rootfs.cpio.gz`.

## Security & Configuration Notes

Treat watchdog, RIFSC, RISAB, PSCI, OP-TEE SMC, MMIO, elfloader, and VM passthrough changes as high risk. Cross-check `docs/optee_smc_interfaces.md`, `docs/rifsc_dwmac_investigation.md`, `docs/alignment_report_20260305.md`, `docs/risab_tfa_sram_investigation.md`, and `docs/risk3_psci_warmboot_mmu_state.md` before editing those paths.
