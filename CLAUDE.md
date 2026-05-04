# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

**Active work (Path B Phase 1):** Boot two independent seL4 kernels pinned per A35 core on STM32MP25x — design phase, no implementation yet. See `docs/path_b_phase1_design.md` and `docs/uart_dataport_design_review.md`. Risks 1 and 3 are closed (`docs/risk1_*.md`, `docs/risk3_*.md`).

## Key Files

| File / Dir | Purpose |
|------|---------|
| `ics_stm32mp25x.camkes` | Native-only assembly for hardware (Phase 1) |
| `ics_vm_stm32mp25x.camkes` | Hardware assembly + Linux VM (Phase 2 target) |
| `ics_dual_nic.camkes` | **QEMU-only** simulation: full dual-NIC gateway with VirtIO + lwIP |
| `settings.cmake` / `CMakeLists.txt` | Three build paths: `qemu-arm-virt`, `stm32mp25x` native, `stm32mp25x` + VM |
| `components/ICS_{Inbound,Outbound}/` | EverParse MODBUS validators |
| `components/WatchdogKicker/` | Pets IWDG1 via OP-TEE SMC (10s cadence, 32s timeout) |
| `components/VirtIO_Net{0,1}_Driver/` | QEMU-only NIC drivers + lwIP (one per side) |
| `stm32mp25x/devices.camkes`, `plat_include/stm32mp25x/plat/vmlinux.h` | VM platform config (DTB, MMIO, IRQs) |
| `linux/stm32mp25x-guest.dts` | Minimal guest DTS for VM build |
| `deploy/` | `make` builds U-Boot `.scr` scripts and stages SD-card layout |
| `docs/` | Investigations & design docs — see "Where to look" below |

## Platform Gotchas

- **IWDG1 is RIFSC-protected.** Direct MMIO writes silently fail; must use OP-TEE SMC (see `WatchdogKicker`). 32s timeout — if anything stalls the kicker for >30s, the board resets.
- **Timer registers trap under hypervisor.** EL2 traps `CNTV_*` access as VCPUFault. Native components don't hit this; the VM build does.
- **Elfloader BSS bug (patched).** `kernel/elfloader-tool/src/arch-arm/64/crt0.S` was patched to call `clear_bss()` for uImage boot — a fix for an upstream AArch64 bug. Don't revert.
- **ZF log defaults to FATAL-only.** If a component is silent, raise `ZF_LOG_LEVEL` rather than assume it's hung.
- **DWMAC / ETH1/ETH2 RIFSC state:** confirmed NSEC and accessible (see `docs/rifsc_dwmac_investigation.md`); RCC clocks are OFF at boot (see `docs/rcc_clock_investigation.md`).

## Build

CAmkES requires two cmake passes with `ast.pickle.cmd` + `camkes-gen.cmake.cmd` between them: the first pass generates those scripts, running them produces the AST, and the second pass picks up the generated targets. This is normal — don't try to collapse it.

No unit-test suite. Validation is by booting the QEMU build (below) or flashing the hardware build to the CCMP25-DVK.

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

### QEMU simulation (dual-NIC, no hardware)

Builds the full validation pipeline against `qemu-arm-virt` for testing without a board.

```bash
cd camkes-vm-examples
rm -rf build-qemu && mkdir build-qemu && cd build-qemu
cmake -G Ninja -DPLATFORM=qemu-arm-virt \
  -DCMAKE_TOOLCHAIN_FILE=../kernel/gcc.cmake \
  ../projects/modbus_ccmp25
bash ast.pickle.cmd && bash camkes-gen.cmake.cmd
cmake -G Ninja -DPLATFORM=qemu-arm-virt \
  -DCMAKE_TOOLCHAIN_FILE=../kernel/gcc.cmake \
  ../projects/modbus_ccmp25
ninja
./simulate    # generated by GenerateSimulateScript()
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

## Slack handoff with Claude.ai web

This project uses Slack channel `#multikernel-amp` to exchange messages between Claude Code (local) and Claude.ai web chat, so the user can hand off context seamlessly across surfaces.

- **Local identity:** post as `Enchanted-donut` (Claude Code's persona in this channel).
- **When to read:** check `#multikernel-amp` at the start of a session to see if the web chat has left context to pick up; check again whenever the user references "what I told the web chat" or similar.
- **When to post:** when the user asks to send something to web chat, or when reaching a checkpoint the web side should know about.

## Where to look in `docs/`

- `path_b_phase1_design.md` + `uart_dataport_design_review.md` — current design line (multikernel-AMP)
- `optee_smc_interfaces.md` — full OP-TEE SMC/PTA/SCMI reference (needed for any SMC work)
- `gap_analysis_20260302.md` + `alignment_report_20260305.md` — readiness audits
- `elfloader_bss_investigation.md` — context for the `crt0.S` patch
- Other files are point-in-time investigations; check git log for currency.
