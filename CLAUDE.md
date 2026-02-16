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
| `ics_stm32mp25x.camkes` | CAmkES assembly (stm32mp25x platform) |
| `settings.cmake` | Platform config, KernelAllowSMCCalls |
| `CMakeLists.txt` | Component declarations |
| `components/ICS_Inbound/` | External→internal validator |
| `components/ICS_Outbound/` | Internal→external validator |
| `components/WatchdogKicker/` | IWDG SMC kicker |
| `deploy/` | SD card install/restore scripts |

## Platform Rules

See `../../.claude/ccwmp255-sel4-rules.md` for hard-won platform-specific rules:
- Timer register traps (VCPUFault under hypervisor mode)
- IWDG is RIFSC-protected (no MMIO, must use SMC)
- Elfloader BSS clearing bug (our fork fixes this)
- ZF log level defaults to FATAL-only

## Build

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
