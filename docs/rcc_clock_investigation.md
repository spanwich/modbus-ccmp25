# RCC Clock Controller RIFSC Investigation

**Date**: 2026-03-04
**Platform**: Digi CCMP25-DVK (STM32MP255CAL, dual Cortex-A35, AArch64)
**Purpose**: Determine if seL4 at EL2 can directly access RCC to enable DWMAC clocks

## RCC RIFSC Status

### Is RCC at 0x44200000 accessible from non-secure EL2? **NO**

RCC is a **"RIF-aware IP"** — it manages its own access control via an internal RIF
mechanism (not the RIFSC peripheral ID table that controls GMAC MMIO).

**Evidence** — `optee_os/core/arch/arm/dts/ccmp25-dvk-rif.dtsi` lines 665-781:

The `&rcc` node has 114 RIFPROT entries (RIF_RCC_RESOURCE 0-113). **All ETH-relevant
resources are SEC/PRIV/CID1** (locked to OP-TEE):

```
// Lines 776-777 — ETH-related RCC resources
RIFPROT(RIF_RCC_RESOURCE(60), RIF_UNUSED, RIF_UNLOCK, RIF_SEC, RIF_PRIV, RIF_CID1, RIF_SEM_DIS, RIF_CFEN)
RIFPROT(RIF_RCC_RESOURCE(61), RIF_UNUSED, RIF_UNLOCK, RIF_SEC, RIF_PRIV, RIF_CID1, RIF_SEM_DIS, RIF_CFEN)

// Lines 716-779 — ALL resources 0-63 are SEC/CID1 except resource 50 (NSEC)
```

Of all 114 RCC RIF resources, only **5 are NSEC** (resources 50, 72, 86, 102, 110, 111).
Everything else — including all clock gate configuration registers — is **SEC/PRIV/CID1**.

**Named resources** (64-113) — `optee_os/core/drivers/clk/clk-stm32mp25.c` lines 113-159:
- 64: PLL4_TO_8, 65: FCAL, 66: SYSTEM_RESET, 69: OSCILLATORS
- 90-101: GPIOx, 102: RTC_TAMP (NSEC), 110-111: OSPI1/2 (NSEC)

**Resources 0-63**: Correspond to individual peripheral clock configuration registers
(RCC_xxxCFGR). All SEC/CID1 except resource 50.

**Controlling firewall**: RCC internal RIF (not RIFSC, not RISAB).

### Important: RIFSC vs RCC RIF namespace

These are **separate namespaces** — do not confuse them:

| Namespace | ID 60 | ID 61 | Access |
|-----------|-------|-------|--------|
| RIFSC peripheral IDs | ETH1 GMAC (0x482C0000) | ETH2 GMAC (0x482D0000) | **NSEC** |
| RCC RIF resources | Clock config register | Clock config register | **SEC/CID1** |

The DWMAC MMIO is freely accessible (NSEC). The RCC clock gate registers are not (SEC).

## Clock Survival Analysis

### Does U-Boot enable ETH1 clocks before handoff? **NO**

- `u-boot/configs/stm32mp25_defconfig` line 34: `# CONFIG_NET is not set`
- **No clock driver for MP25x exists**: `u-boot/drivers/clk/stm32/` has MP1, MP13, H7, F —
  no `clk-stm32mp25.c`
- U-Boot cannot and does not touch ETH clocks

### Does OP-TEE enable ETH clocks at boot? **NO**

- `optee_os/core/arch/arm/dts/ccmp25-dvk.dts` lines 501-516: `&rcc` node configures PLL
  sources and CPU OPP only — **no ETH clock enablement**
- No ETH1/ETH2 device nodes in OP-TEE DTS (no `status = "okay"`)
- OP-TEE defines the gate registers but does not enable them at boot

### Does elfloader preserve clock state? **YES**

- Searched `tools/seL4/elfloader-tool/src/` — **no references** to RCC, clocks, or 0x44200000
- Elfloader is clock-agnostic; only `psci_system_reset()` touches anything reset-related

### Does seL4 kernel preserve clock state? **YES**

- `kernel/src/plat/stm32mp25x/` contains only `config.cmake` and DTS overlay — **no C code**
- **No platform init code** for STM32MP25x in the seL4 kernel
- No references to RCC anywhere in kernel source

### Clock state summary

| Boot stage | Touches RCC? | ETH1 clocks after |
|-----------|-------------|-------------------|
| TF-A (BL2/BL31) | Sets up PLLs | OFF (gates closed) |
| OP-TEE (BL32) | Configures RCC RIF, PLL sources | OFF (no ETH init) |
| U-Boot (BL33) | No (no clock driver) | OFF |
| seL4 elfloader | No | OFF |
| seL4 kernel | No | **OFF** |

**ETH1/ETH2 clocks will be OFF when seL4 boots.** DWMAC registers at 0x482C0000
will be accessible (NSEC) but return 0x00000000 because the core is not clocked.

## How Linux Handles This

Linux uses the STM32MP25x RCC clock driver (`linux/drivers/clk/stm32/clk-stm32mp25.c`)
which is aware of the `stm32_firewall` framework (`linux/include/bus/stm32_firewall.h`).

The DTS references clocks directly:
```dts
// linux/arch/arm64/boot/dts/st/stm32mp251.dtsi lines 2299-2304
clocks = <&rcc CK_ETH1_MAC>,
         <&rcc CK_ETH1_TX>,
         <&rcc CK_ETH1_RX>,
         <&rcc CK_KER_ETH1PTP>,
         <&rcc CK_ETH1_STP>,
         <&rcc CK_KER_ETH1>;
```

SCMI transport uses OP-TEE as backend:
```dts
// stm32mp251.dtsi line 139
compatible = "linaro,scmi-optee";
```

For SEC-protected clock resources, the Linux firewall framework negotiates access through
OP-TEE. seL4 lacks this framework — it needs a different approach.

## ETH1 Clock Gate Registers

From `optee_os/core/drivers/clk/clk-stm32mp25.c` lines 492-496 and 627-631:

| Gate | Register | Bit | Function |
|------|----------|-----|----------|
| GATE_ETH1MAC | RCC_ETH1CFGR (0x442007F0) | 1 | Core MAC clock |
| GATE_ETH1STP | RCC_ETH1CFGR | 4 | Low-power stop clock |
| GATE_ETH1 | RCC_ETH1CFGR | 5 | Bus (ICN) clock |
| GATE_ETH1TX | RCC_ETH1CFGR | 8 | TX clock |
| GATE_ETH1RX | RCC_ETH1CFGR | 10 | RX clock |

All 5 gates are in a single register: **RCC_ETH1CFGR** at RCC+0x7F0.
Bits to set: `(1<<1) | (1<<4) | (1<<5) | (1<<8) | (1<<10) = 0x532`.

## Runtime Verification Commands

Run these on the live board in Linux to confirm the static analysis:

```bash
# 1. Read RCC base (should succeed — RCC bus access may be open)
devmem2 0x44200000 w

# 2. Read RCC_ETH1CFGR — if non-zero, clocks are enabled by Linux
devmem2 0x442007F0 w
# Expected with Linux ETH driver loaded: 0x00000532 or similar (all gates open)
# Expected with ETH driver NOT loaded: 0x00000000 (gates closed)

# 3. Verify DWMAC responds (proves clocks are on AND MMIO accessible)
devmem2 0x482C0110 w
# Expected: 0x60XX (DWMAC 5.10a version)
# If 0x00000000: clocks are off

# 4. Check Linux clock tree
cat /sys/kernel/debug/clk/clk_summary 2>/dev/null | grep -i eth

# 5. Critical test: write ETH1CFGR directly (tests if RCC RIF blocks NSEC writes)
devmem2 0x442007F0 w 0x00000532
# If succeeds silently: RCC is accessible from NSEC (contradicts static analysis)
# If bus error/hangs: RCC is SEC-protected (confirms static analysis)
```

**After seL4 boots** (before any driver init):
```
# In seL4 serial console, read DWMAC version register
# If returns 0x00000000: clocks are OFF (confirms analysis)
# If returns 0x60XX: clocks somehow survived (unexpected)
```

## Strategy Evaluation

### Option A: Direct RCC access from seL4 — **RULED OUT**

RCC is SEC/PRIV/CID1. seL4 at EL2 (NSEC) cannot write RCC_ETH1CFGR.
devmem2 test from Linux can confirm, but static analysis is conclusive.

### Option B: Rely on U-Boot clock state — **RULED OUT**

U-Boot has CONFIG_NET disabled and no STM32MP25x clock driver.
ETH clocks are never enabled. Nothing to preserve.

### Option C: SMC to OP-TEE for clock management — **VIABLE (native builds)**

**Effort**: Moderate — OP-TEE already has a full RCC clock driver and SCMI server.
**Approach**: Add a Trusted Application or extend existing PTA to accept clock
enable/disable SMC calls for specific clock IDs.

Similar to the existing IWDG watchdog SMC path (already implemented in WatchdogKicker).
The seL4 component would issue:
```c
// SMC to OP-TEE: "enable CK_ETH1_MAC, CK_ETH1_TX, CK_ETH1_RX, etc."
arm_sys_smc(OPTEE_SMC_FAST_CALL, PTA_CLOCK_ENABLE, CK_ETH1_MAC, 0, 0);
```

### Option D: Modify OP-TEE DTS to enable at boot — **RECOMMENDED (fastest path)**

**Effort**: Low — add ETH1/ETH2 clock enable to OP-TEE platform init DTS.
**Approach**: Add `status = "okay"` ETH node or explicit clock-enable in `ccmp25-dvk.dts`
so OP-TEE enables the gate clocks before handing off to U-Boot/seL4.

**Risk**: Low — clocks stay enabled permanently (minor power cost, no security impact
since GMAC MMIO is already NSEC). ETH1/ETH2 RIFSC status is NSEC, so OP-TEE is not
giving away any new access — it's just pre-gating clocks for a peripheral that's
already accessible.

Requires OP-TEE rebuild and re-flash (TF-A/OP-TEE/U-Boot FIP update).

### Option E: Linux VM handles clocks — **BEST for VM builds**

In the VM architecture (`-DSTM32MP25X_VM=ON`), the Linux guest runs OP-TEE's SCMI
client natively. Linux's DWMAC driver requests clocks through the normal
`stm32_firewall` → SCMI → OP-TEE path. No seL4-side changes needed.

The DWMAC_Driver component only needs to wait for Linux to have initialized the clocks
before starting its own MMIO operations (a simple "read GMAC_Version until non-zero" loop).

## Recommended Strategy

| Build type | Strategy | Rationale |
|-----------|----------|-----------|
| **VM build** | Option E (Linux handles it) | Zero additional work; Linux SCMI stack handles clocks |
| **Native build** | Option D (OP-TEE DTS mod) | Lowest effort; one DTS change + FIP rebuild |
| **Long-term** | Option C (SMC clock service) | Proper dynamic clock management from seL4 |

## Is This Still a Blocker?

**YES** — for native builds, ETH clocks cannot be enabled without OP-TEE modification.
**NO** — for VM builds, Linux guest handles clock management transparently.

**Immediate next step**: Modify `ccmp25-dvk.dts` in OP-TEE to enable ETH1 clocks at boot
(Option D), then verify with devmem2 that RCC_ETH1CFGR reads 0x532 after OP-TEE handoff.

## Source Files Referenced

| File | Lines | Content |
|------|-------|---------|
| `optee_os/core/arch/arm/dts/ccmp25-dvk-rif.dtsi` | 665-781 | RCC RIFPROT (all SEC/CID1) |
| `optee_os/core/arch/arm/dts/ccmp25-dvk.dts` | 501-516 | RCC PLL config (no ETH) |
| `optee_os/core/drivers/clk/clk-stm32mp25.c` | 113-159, 627-636 | RIF IDs + gate defs |
| `u-boot/configs/stm32mp25_defconfig` | 34 | `# CONFIG_NET is not set` |
| `linux/arch/arm64/boot/dts/st/stm32mp251.dtsi` | 2285-2315 | ETH1 node + clock refs |
| `linux/drivers/clk/stm32/clk-stm32mp25.c` | 8-9, 48-50, 492-496 | Firewall-aware driver |
| `arm-trusted-firmware/plat/st/stm32mp2/stm32mp2_def.h` | 324 | `RCC_BASE 0x44200000` |
