# MODBUS CCMP25 — ICS Cross-Domain Gateway on Digi CCMP25-DVK

Bidirectional MODBUS validation gateway running as native CAmkES components on seL4, targeting the Digi ConnectCore MP25 Development Kit (STM32MP255, dual Cortex-A35, AArch64).

## Architecture

```
[PLC/SCADA] ←→ ICS_Inbound ←→ ICS_Outbound ←→ [Field Devices]
                     ↕               ↕
              EverParse validators (policy-driven)

WatchdogKicker — pets IWDG1 via SMC to OP-TEE every ~10s
```

- **ICS_Inbound**: Validates external→internal MODBUS traffic (priority 150)
- **ICS_Outbound**: Validates internal→external MODBUS traffic (priority 150)
- **WatchdogKicker**: Prevents 32s IWDG hardware reset (priority 50)

## Key Files

| File | Purpose |
|------|---------|
| `ics_stm32mp25x.camkes` | Native-only CAmkES assembly (no VM) |
| `ics_vm_stm32mp25x.camkes` | VM-enabled assembly (Linux VM + native components) |
| `settings.cmake` | Platform config, KernelAllowSMCCalls |
| `CMakeLists.txt` | Component declarations (native + VM builds) |
| `stm32mp25x/devices.camkes` | VM platform config (RAM, DTB, MMIO) |
| `linux/stm32mp25x-guest.dts` | Minimal guest device tree for VM |
| `plat_include/stm32mp25x/plat/vmlinux.h` | VMM platform config (IRQs, GIC, keep-devices) |
| `components/ICS_Inbound/` | External→internal validator |
| `components/ICS_Outbound/` | Internal→external validator |
| `components/WatchdogKicker/` | IWDG SMC kicker |
| `deploy/` | SD card install/restore scripts |
| `docs/vm-migration-reference.md` | VM migration planning reference |
| `docs/rifsc_dwmac_investigation.md` | RIFSC/DWMAC access analysis (ETH1/ETH2 confirmed NSEC) |
| `docs/build-readiness-analysis.md` | Build resource verification (native + VM) |
| `docs/gap_analysis_20260302.md` | Implementation readiness assessment against target architecture |
| `docs/rcc_clock_investigation.md` | RCC RIFSC analysis (SEC/CID1, clocks OFF at boot) |
| `docs/optee_smc_interfaces.md` | Complete OP-TEE SMC/PTA/SCMI reference for seL4 |
| `docs/elfloader_bss_investigation.md` | AArch64 uImage BSS bug analysis (MASKED verdict) |
| `docs/alignment_report_20260305.md` | Project instructions vs codebase verification |

## Platform Rules

See `../../.claude/ccwmp255-sel4-rules.md` for hard-won platform-specific rules:
- Timer register traps (VCPUFault under hypervisor mode)
- IWDG is RIFSC-protected (no MMIO, must use SMC)
- Elfloader BSS: patched `64/crt0.S` to call `clear_bss()` for uImage (upstream bug fix)
- ZF log level defaults to FATAL-only

## Build

### Native-only (no VM, default)

```bash
cd camkes-vm-examples
rm -rf build-modbus-ccmp25 && mkdir build-modbus-ccmp25 && cd build-modbus-ccmp25
cmake -G Ninja -DPLATFORM=stm32mp25x \
  -DCROSS_COMPILER_PREFIX=aarch64-linux-gnu- \
  -DCMAKE_TOOLCHAIN_FILE=../kernel/gcc.cmake \
  ../projects/modbus_ccmp25
bash ast.pickle.cmd && bash camkes-gen.cmake.cmd
cmake -G Ninja -DPLATFORM=stm32mp25x \
  -DCROSS_COMPILER_PREFIX=aarch64-linux-gnu- \
  -DCMAKE_TOOLCHAIN_FILE=../kernel/gcc.cmake \
  ../projects/modbus_ccmp25
ninja
```

### VM-enabled (Linux VM + native components)

Requires: `linux/linux-Image`, `linux/rootfs.cpio.gz` in project directory.

```bash
cd camkes-vm-examples
rm -rf build-modbus-vm && mkdir build-modbus-vm && cd build-modbus-vm
cmake -G Ninja -DPLATFORM=stm32mp25x -DSTM32MP25X_VM=ON \
  -DCROSS_COMPILER_PREFIX=aarch64-linux-gnu- \
  -DCMAKE_TOOLCHAIN_FILE=../kernel/gcc.cmake \
  ../projects/modbus_ccmp25
bash ast.pickle.cmd && bash camkes-gen.cmake.cmd
cmake -G Ninja -DPLATFORM=stm32mp25x -DSTM32MP25X_VM=ON \
  -DCROSS_COMPILER_PREFIX=aarch64-linux-gnu- \
  -DCMAKE_TOOLCHAIN_FILE=../kernel/gcc.cmake \
  ../projects/modbus_ccmp25
ninja
```

## Deploy

```bash
cd deploy && make                    # Build .scr scripts + copy sel4.bin
cp sdcard/* /mnt/d/STM32/sdcard/     # Copy to SD card

# In U-Boot console:
fatload mmc 2 0x90000000 install.scr && source 0x90000000
# Reboot to boot seL4
```

## Boot Chain

TF-A → OP-TEE (starts IWDG1, 32s timeout) → U-Boot → seL4 (uImage via bootm)
