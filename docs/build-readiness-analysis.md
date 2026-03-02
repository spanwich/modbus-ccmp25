# Build Readiness Analysis — MODBUS CCMP25

Resource verification for native-only and VM-enabled builds on Digi CCMP25-DVK (STM32MP25x).

## Native-Only Build (`-DSTM32MP25X_VM` not set)

### Verdict: BUILD-READY

All resources verified present.

### Component Sources

| File | Path | Status |
|------|------|--------|
| ICS_Inbound.c | `components/ICS_Inbound/` | Present |
| ICS_Outbound.c | `components/ICS_Outbound/` | Present |
| WatchdogKicker.c | `components/WatchdogKicker/` | Present |
| ModbusTCP_v3_Simple.c | `components/include/` | Present |
| ModbusTCP_v3_SimpleWrapper.c | `components/include/` | Present |
| everparse_error_handler.c | `components/lib/` | Present |
| ringbuf.c / ringbuf.h | `components/lib/` | Present |
| All headers | `components/include/` | Present |

### CAmkES Assembly

| File | Status | Details |
|------|--------|---------|
| `ics_stm32mp25x.camkes` | Present | 111 lines; native-only assembly |

### Build Infrastructure

| Resource | Status | Details |
|----------|--------|---------|
| `aarch64-linux-gnu-gcc` | Installed | v13.3.0 |
| seL4 kernel source | Available | Git submodule |
| CAmkES tools | Available | cmake-tool + griddle |
| `kernel/gcc.cmake` | Present | Toolchain file |
| `global-components.cmake` | Present | Referenced in settings.cmake |

### settings.cmake Dependencies

| Dependency | Status |
|-----------|--------|
| `find_package(seL4 REQUIRED)` | Resolvable |
| `find_package(camkes-tool REQUIRED)` | Resolvable |
| `global-components.cmake` | Present |
| elfloader settings | Available |
| `KernelAllowSMCCalls ON` | Configured (line 56) |
| `LibLwip OFF` | Set (line 54) |

### Pre-build Checklist

- [x] All source files exist
- [x] CAmkES assembly file exists
- [x] Cross-compiler available
- [x] seL4 kernel source available
- [x] CAmkES tool infrastructure present
- [x] global-components.cmake accessible
- [x] settings.cmake resolves all dependencies
- [ ] Verify `.sel4_cache` directory exists or will be created
- [ ] Verify U-Boot supports uImage format on CCMP25-DVK
- [ ] Verify OP-TEE firmware supports SMC function `0xbc000000` (IWDG petting)

---

## VM-Enabled Build (`-DSTM32MP25X_VM=ON`)

### Verdict: CMAKE CONFIGURES — NINJA BUILD REQUIRES LINUX IMAGES

### VM Infrastructure (All Present)

| Resource | Status |
|----------|--------|
| `arm_vm_helpers.cmake` | Present |
| `VM_Arm` component directory | Present |
| `VM_Arm/VM.camkes` | Present |
| `configurations/vm.h` | Present |
| `std_connector.camkes` | Present (builtin) |
| `global-connectors.camkes` | Present |
| `vm-connectors.camkes` | Present |
| `dtc` (device tree compiler) | Installed |

### Project-Specific VM Files (All Created)

| Resource | Status | Details |
|----------|--------|---------|
| `ics_vm_stm32mp25x.camkes` | Present | 123 lines; VM assembly with FileServer + vm0 |
| `stm32mp25x/devices.camkes` | Present | 82 lines; 256MB VM RAM at `0x90000000` |
| `linux/stm32mp25x-guest.dts` | Present | 106 lines; Cortex-A35, PSCI, GIC, USART2, DWMAC |
| `plat_include/stm32mp25x/plat/vmlinux.h` | Present | GIC SPI offset 32, passthrough IRQs |
| `linux/setup-kernel.sh` | Present | Clone + build helper for yocto-linux |
| `linux/.gitignore` | Present | Excludes build artifacts |
| `docs/vm-migration-reference.md` | Present | Design reference + gap analysis |

### Linux VM Guest Images (Missing — Expected)

| Resource | Expected Path | Status |
|----------|--------------|--------|
| Linux kernel | `linux/linux-Image` | **MISSING** |
| Root filesystem | `linux/rootfs.cpio.gz` | **MISSING** |

Both checked with `if(EXISTS ...)` in CMakeLists.txt — produces warnings, not fatal errors.

### Platform Module Note

No platform-specific VM init module exists at `VM_Arm/src/modules/plat/stm32mp25x/init.c`. This is non-fatal — `arm_vm_helpers.cmake` checks `if(EXISTS ...)` and falls back to generic initialization.

### Build Phase Predictions

**CMake Configure: WILL SUCCEED**
- All VM infrastructure resolves correctly
- Missing linux images produce warnings only
- Expected warnings:
  ```
  WARNING: Linux kernel image not found at .../linux-Image
  WARNING: Root filesystem not found at .../rootfs.cpio.gz
  ```

**Ninja Build: WILL FAIL (without linux images)**
- DTS→DTB compilation will succeed
- FileServer creation will fail (missing kernel + initrd to embed)
- seL4 image linking will fail

### Steps to Complete VM Build

1. Run `bash linux/setup-kernel.sh` to clone yocto-linux (v6.6/digi branch)
2. Build kernel: `make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- Image`
3. Copy: `cp linux/yocto-linux/arch/arm64/boot/Image linux/linux-Image`
4. Build rootfs: create BusyBox-based initrd at `linux/rootfs.cpio.gz`
5. Re-run cmake + ninja

---

## Remaining Prerequisites (Gap Analysis)

Before the VM build produces a bootable image:

1. **Linux kernel** — build from yocto-linux v6.6/digi branch
2. **Root filesystem** — BusyBox-based initrd
3. **VCPUFault handler** — timer register traps (`cntvct_el0`, `cntfrq_el0`) will crash the VM until the VMM handles VCPUFault
4. **RIFSC verification** — confirm USART2 and DWMAC are accessible when seL4 runs at EL2
