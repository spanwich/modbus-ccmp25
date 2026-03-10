# Alignment Report: Project Instructions vs Codebase

**Date**: 2026-03-05
**Scope**: MODBUS CCMP25 project — CLAUDE.md, ccwmp255-sel4-rules.md, auto-memory, and all codebase files

---

## CONFIRMED — matches project instructions

### Boot Chain & Hardware Addresses
- U-Boot bootm load address `0x90000000` — confirmed in `deploy/boot.cmd` (line 12, 23, 27) and `deploy/install.cmd` (line 3)
- USART2 @ `0x400e0000` — confirmed in `stm32mp25x/devices.camkes` (lines 13, 49-50, 61, 76), `linux/stm32mp25x-guest.dts` (line 77-79), `docs/vm-migration-reference.md` (line 14)
- DWMAC ETH1 @ `0x482C0000` — confirmed in `devices.camkes` (lines 14, 62, 77), `stm32mp25x-guest.dts` (line 92-94), `docs/rifsc_dwmac_investigation.md` (line 64)
- DWMAC ETH2 @ `0x482D0000` — confirmed in `docs/rifsc_dwmac_investigation.md` (line 64)
- GICv2 @ `0x4ac00000` base — confirmed across 7 independent sources: kernel `config.cmake`, `gicv2.h`, `vmlinux.h`, guest DTS, OP-TEE DTS, Linux DTS, TF-A `platform.mk`
- GICD=`0x4ac10000`, GICC=`0x4ac20000`, GICH=`0x4ac40000`, GICV=`0x4ac60000` — all confirmed
- No wrong GIC address `0x44220000` found anywhere in codebase (0 matches)
- `KernelArmGicV2 ON` in kernel `config.cmake`

### Kernel & Build System
- Kernel submodule on `spanwich/stm32mp25x-platform` branch @ commit `921de426` — confirmed
- Kernel remote: `git@github.com:spanwich/seL4.git` (custom fork) — confirmed
- Platform directory `kernel/src/plat/stm32mp25x/` exists with `config.cmake` + `overlay-stm32mp25x.dts`
- `settings.cmake`: Conditional build setup — VM builds call `camkes_arm_vm_setup_arm_vm_environment()`, native builds call `camkes_tool_setup_camkes_build_environment()` — confirmed
- `KernelAllowSMCCalls ON` for stm32mp25x — confirmed (settings.cmake line 56)
- `ElfloaderImage "uimage"` for stm32mp25x — confirmed (settings.cmake line 75)
- AST bootstrap required: two-pass cmake + ninja — confirmed in build instructions

### WatchdogKicker
- SMC function ID `0xbc000000` — confirmed (`WatchdogKicker.c` line 12)
- Subfunc 3 (`SMCWD_PET`) — confirmed (`WatchdogKicker.c` line 13)
- Priority 50 — confirmed in both `ics_stm32mp25x.camkes` (lines 96-97) and `ics_vm_stm32mp25x.camkes` (lines 111-112)
- Yield loop ~10s (10M iterations * ~1µs) — confirmed (`PET_YIELD_COUNT = 10000000`, line 20)
- No direct IWDG MMIO access — confirmed (only SMC references, no `0x4C006000`)

### Validator Components
- Version `v2.270` dated `2026-01-06` — confirmed in `components/include/version.h`
- EverParse integration via `ModbusTcpV3SimpleCheckModbusTcpFrameV3()` — confirmed in `common.h` (lines 256-299)
- CVE-2022-0367 policy validates both read_address AND write_address for FC 0x17 — confirmed in `modbus_policy.h` (lines 310-341)
- `ICS_Message`: `FrameMetadata` + `payload_length` + 60KB payload — confirmed in `common.h` (lines 44-87)
- ICS_Inbound priority 150, ICS_Outbound priority 150 — confirmed in both assemblies
- Current wiring is loopback only (inbound↔outbound, no DWMAC) — confirmed in both assemblies

### QEMU Reference Build
- `ics_dual_nic.camkes` exists (333 lines) with dual VirtIO drivers (Net0 + Net1) — confirmed
- VirtIO_Net0_Driver has lwIP (tcp_new, netif, pbuf, DHCP) — confirmed (181KB source)
- VirtIO_Net1_Driver exists with separate lwIP instance (`lwip_net1`) — confirmed (194KB source)

### VM Assembly
- `ics_vm_stm32mp25x.camkes` exists (122 lines) with VM + native components — confirmed
- `stm32mp25x/devices.camkes`: 256MB VM RAM @ `0x90000000`, USART2/DWMAC passthrough, GICV mapped, `num_vcpus=2` — confirmed
- `linux/stm32mp25x-guest.dts` exists (106 lines) — minimal DTS with GIC, USART2, DWMAC — confirmed
- Guest DTS: clock properties intentionally stripped for Phase 1 — confirmed (comments at lines 84-90)
- CMakeLists.txt VM block: AddToFileServer for linux/linux-dtb/linux-initrd, DTB compilation via `dtc` — confirmed

### Investigation Docs
- `docs/rifsc_dwmac_investigation.md` — NSEC/NPRIV finding confirmed
- `docs/rcc_clock_investigation.md` — SEC/CID1 finding confirmed
- `docs/optee_smc_interfaces.md` — present
- `docs/gap_analysis_20260302.md` — present
- `docs/build-readiness-analysis.md` — present
- `docs/vm-migration-reference.md` — present

### Forbidden Patterns
- No `0x44220000` (wrong GIC) in codebase — confirmed
- No timer register reads (`cntvct_el0`, `cntfrq_el0`) in CAmkES components — confirmed
- No direct RCC MMIO writes (`0x44200000`, `0x442007F0`) in components — confirmed
- No direct IWDG MMIO access in components — confirmed

---

## MISALIGNMENT — differs from project instructions

### 1. Elfloader BSS claim: "our fork fixes this"

- **Claim in instructions**: `CLAUDE.md` line 46 says "Elfloader BSS clearing bug (our fork fixes this)". `ccwmp255-sel4-rules.md` line 17 says "Our fork fixes this."
- **Reality in codebase**: Elfloader remote is `seL4 https://github.com/seL4/seL4_tools.git` (official upstream master at commit `ee550199`). This is **NOT a fork**.
- **Impact**: Documentation-only error. Does not block any build or runtime.
- **Suggested resolution**: Update `ccwmp255-sel4-rules.md` and `CLAUDE.md` to remove "our fork fixes this". The BSS issue is a latent concern (see UNKNOWN #1 below) but the elfloader is on upstream, not a fork.

### 2. MEMORY.md incorrect reasoning about BSS clearing

- **Claim in auto-memory**: "NOT A BLOCKER — `clear_bss()` called in `CONFIG_IMAGE_BINARY` path in aarch64 crt0.S (line 47), active for uImage builds"
- **Reality in codebase**: `config_choice` in elfloader `CMakeLists.txt` (lines 26-33) makes `IMAGE_BINARY` and `IMAGE_UIMAGE` **mutually exclusive**. uImage builds define `CONFIG_IMAGE_UIMAGE`, NOT `CONFIG_IMAGE_BINARY`. The `clear_bss` call at crt0.S line 47 is inside `#ifdef CONFIG_IMAGE_BINARY` (lines 22-50) and is **NOT compiled** for uImage builds.
- **Impact**: The "NOT A BLOCKER" conclusion is pragmatically correct (no crash occurs because there's no UART driver for STM32 USART — the uninitialized `uart_out` pointer is never dereferenced). But the technical reasoning is wrong.
- **Suggested resolution**: Update auto-memory to: "NOT A BLOCKER (pragmatically) — `clear_bss()` is NOT called for uImage builds (`CONFIG_IMAGE_UIMAGE` ≠ `CONFIG_IMAGE_BINARY`), but no crash occurs because elfloader has no UART driver for `st,stm32h7-uart` (runs silently). Latent risk if future elfloader code uses BSS-initialized globals."

---

## MISSING — referenced but not found

### Expected missing (planned, not yet built)

| Item | Referenced in | Status |
|------|---------------|--------|
| `linux/linux-Image` | `CMakeLists.txt` line 182, `CLAUDE.md` line 70 | **Expected missing** — must be cross-compiled from yocto-linux (v6.6/digi branch). `linux/setup-kernel.sh` exists for this. |
| `linux/rootfs.cpio.gz` | `CMakeLists.txt` line 207, `CLAUDE.md` line 70 | **Expected missing** — must build BusyBox-based initrd. |
| DWMAC_Driver component | Gap analysis (future phase) | **Expected missing** — Phase 2 work; validators currently in loopback |
| VM↔native bridge | `ics_vm_stm32mp25x.camkes` line 78 comment | **Expected missing** — Phase 2 work |

### Unexpected missing

None found. All files referenced in CLAUDE.md key files table exist.

---

## UNKNOWN — could not be determined

### 1. Elfloader BSS clearing — runtime impact

The elfloader on upstream does NOT call `clear_bss()` for uImage builds. The `ccwmp255-sel4-rules.md` correctly identifies this as a potential issue ("uninitialized `uart_out` pointer causes Synchronous Abort on first putchar"). Currently masked because there's no UART driver. Cannot determine without board access whether any other BSS-dependent behavior causes silent corruption.

**Verification needed**: On live board, check if elfloader BSS region happens to be zeroed by U-Boot's `bootm` (some bootloaders zero the load region). If so, the issue is fully benign. If not, any future elfloader code using BSS globals could fail silently.

### 2. OP-TEE clock enable at boot (Option D)

`docs/rcc_clock_investigation.md` recommends modifying OP-TEE DTS to enable ETH1 clocks at boot for native builds. Cannot verify whether this has been implemented without board access or OP-TEE rebuild.

### 3. Deploy scripts — SD card partition layout

`deploy/boot.cmd` references `mmc 0:5` (eMMC partition 5) and `mmc 2` (SD card). Cannot verify partition layout without board access.

---

## Recommendation

The project is **ready to proceed with Phase 1 implementation** (VM boot). All code, configuration, and build infrastructure is internally consistent. The two misalignments are documentation-only errors that do not affect builds or runtime:

1. **Elfloader fork claim** — cosmetic; the elfloader works correctly on upstream for the current use case (no UART driver means BSS issue is masked).
2. **Memory entry reasoning** — the conclusion is right but the reasoning is wrong; should be corrected to avoid future confusion.

The missing `linux-Image` and `rootfs.cpio.gz` are expected prerequisites for VM boot (external build task, not a code fix). All other verification items — hardware addresses, GIC configuration, kernel branch, WatchdogKicker, validators, QEMU reference build, VM assembly, and forbidden patterns — are confirmed correct.

**Suggested pre-implementation fixes** (optional, low priority):
1. Update `ccwmp255-sel4-rules.md` line 17: remove "Our fork fixes this" → "Upstream elfloader does not clear BSS for uImage builds, but this is masked by the absence of a UART driver."
2. Update `CLAUDE.md` line 46: remove "our fork fixes this" → "BSS not cleared for uImage (masked — no UART driver)"
3. Correct auto-memory entry for elfloader BSS reasoning.
