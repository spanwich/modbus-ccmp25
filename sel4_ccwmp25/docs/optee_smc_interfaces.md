# OP-TEE Callable SMC Interfaces — STM32MP25x (Digi CCMP25-DVK)

**Date**: 2026-03-04
**Platform**: STM32MP255CAL, dual Cortex-A35, AArch64
**OP-TEE source**: `../../ccwmp255/optee_os/`

## 1. Standard SMC Protocol

### 1.1 SMC Encoding (optee_smc.h)

```
Bit 31:    1=Fast Call (non-blocking), 0=Standard Call (blocking)
Bit 30:    1=SMC64 (64-bit), 0=SMC32 (32-bit)
Bits 29-24: Owner (6 bits): 50=TRUSTED_OS (OP-TEE), 2=SiP, 63=OP-TEE API
Bits 15-0:  Function number (16 bits)
```

Source: `optee_os/core/arch/arm/include/sm/optee_smc.h` lines 20-59

### 1.2 Fast SMC Functions (dispatched in entry_fast.c:258-355)

| SMC Value | FUNCID | Name | Description |
|-----------|--------|------|-------------|
| `0xbf00ff00` | 0xFF00 | CALLS_COUNT | Number of supported SMC functions |
| `0xbf00ff01` | 0xFF01 | CALLS_UID | API UUID: `384fb3e0-e7f8-11e3-af63-0002a5d5c51b` |
| `0xbf00ff03` | 0xFF03 | CALLS_REVISION | API revision (2.0) |
| `0xb2000000` | 0x0000 | GET_OS_UUID | OS UUID: `486178e0-e7f8-11e3-bc5e-0002a5d5c51b` |
| `0xb2000001` | 0x0001 | GET_OS_REVISION | OS revision (major.minor + build ID) |
| `0xb2000007` | 7 | GET_SHM_CONFIG | Shared memory configuration |
| `0xb2000008` | 8 | L2CC_MUTEX | L2 cache controller mutex ops |
| `0xb2000009` | 9 | EXCHANGE_CAPABILITIES | Negotiate normal/secure world capabilities |
| `0xb200000a` | 10 | DISABLE_SHM_CACHE | Disable shared memory cache |
| `0xb200000b` | 11 | ENABLE_SHM_CACHE | Enable shared memory cache |
| `0xb200000c` | 12 | BOOT_SECONDARY | Release secondary cores |
| `0xb200000f` | 15 | GET_THREAD_COUNT | Number of OP-TEE threads |
| `0xb200000d` | 13 | VM_CREATED | Inform of VM creation |
| `0xb200000e` | 14 | VM_DESTROYED | Inform of VM destruction |
| `0xb2000010` | 16 | ENABLE_ASYNC_NOTIF | Enable async notifications |
| `0xb2000011` | 17 | GET_ASYNC_NOTIF_VALUE | Get pending async notification |
| `0xb2000035` | 53 | GET_IT_NOTIF_VALUE | Get interrupt notification |
| `0xb2000036` | 54 | SET_IT_NOTIF_MASK | Mask/unmask interrupt notifications |
| **`0xbc000000`** | — | **WDT_SM_HANDLER** | **STM32MP25x watchdog (IWDG)** |

### 1.3 Standard (Yielding) SMC Functions (thread_optee_smc.c:292-310)

| SMC Value | FUNCID | Name | Description |
|-----------|--------|------|-------------|
| `0x32000004` | 0x0004 | CALL_WITH_ARG | Invoke TA/PTA via `optee_msg_arg` in shared mem |
| `0x32000012` | 18 | CALL_WITH_RPC_ARG | Same + RPC argument buffer |
| `0x32000013` | 19 | CALL_WITH_REGD_ARG | Same + registered shared memory |
| `0x32000003` | 3 | RETURN_FROM_RPC | Resume after RPC completion |

### 1.4 Message Commands (within optee_msg_arg.cmd)

Used with CALL_WITH_ARG to invoke services:

| CMD | Value | Purpose |
|-----|-------|---------|
| OPEN_SESSION | 0 | Open session to TA/PTA (by UUID) |
| INVOKE_COMMAND | 1 | Invoke command on open session |
| CLOSE_SESSION | 2 | Close session |
| CANCEL | 3 | Cancel pending command |
| REGISTER_SHM | 4 | Register shared memory |
| UNREGISTER_SHM | 5 | Unregister shared memory |

Source: `optee_os/core/include/optee_msg.h` lines 335-342

## 2. Pseudo Trusted Applications (PTAs)

PTAs are invoked via Standard SMC → OPEN_SESSION (UUID) → INVOKE_COMMAND (cmd_id).

### 2.1 PTA-SCMI (System Control and Management Interface)

**UUID**: `a8cfe406-d4f5-4a2e-9f8d-a25dc754c099`
**Source**: `optee_os/core/pta/scmi.c` (registered line 414)
**Client header**: `optee_os/lib/libutee/include/pta_scmi_client.h`

| CMD ID | Name | Description |
|--------|------|-------------|
| 0x0 | CAPABILITIES | Get channel capabilities |
| 0x1 | PROCESS_SMT_CHANNEL | Process SCMI message in SMT shared buffer |
| 0x2 | PROCESS_SMT_CHANNEL_MESSAGE | Process SCMI in SMT buffer via memref |
| 0x3 | GET_CHANNEL_HANDLE | Get handle for an SCMI channel |
| 0x4 | PROCESS_MSG_CHANNEL | Process SCMI message in MSG buffer |
| 0x800 | OCALL2_SMT_THREAD | Allocate thread for SMT messages |
| 0x801 | OCALL2_MSG_THREAD | Allocate thread for MSG messages |

**This is the entry point for clock management from non-secure world.**

### 2.2 STM32MP BSEC PTA (OTP/Fuse Access)

**UUID**: `94cf71ad-80e6-40b5-a7c6-3dc501eb2803`
**Source**: `optee_os/core/pta/stm32mp/bsec_pta.c` (line 331)
**Client header**: `optee_os/lib/libutee/include/pta_stm32mp_bsec.h`

| CMD ID | Name | Description |
|--------|------|-------------|
| 0x0 | READ_OTP | Read OTP memory (shadow, fuse, or locks) |
| 0x1 | WRITE_OTP | Write OTP memory |
| 0x3 | GET_STATE | Get BSEC security state |

### 2.3 Remote Processor PTA

**UUID**: `54af4a68-19be-40d7-bbe6-8950350a8744`
**Source**: `optee_os/core/pta/stm32mp/remoteproc_pta.c` (line 526)

| CMD ID | Name | Description |
|--------|------|-------------|
| 0x1 | HW_CAPABILITIES | Get firmware loader capabilities |
| 0x2 | FIRMWARE_LOAD | Load firmware |
| 0x3 | LOAD_SEGMENT | Load segment with hash verification |
| 0x5 | FIRMWARE_START | Start remote processor |
| 0x6 | FIRMWARE_STOP | Stop remote processor |
| 0x7 | DA_TO_PA | Device address to physical address |
| 0x8 | VERIFY_DIGEST | Verify firmware digest |
| 0xa | CLEAN | Clean remote processor resources |

### 2.4 Device Enumeration PTA

**UUID**: `7011a688-ddde-4053-a5a9-7b3c4ddf13b8`
**Source**: `optee_os/core/pta/device.c` (line 105)

| CMD ID | Name | Description |
|--------|------|-------------|
| 0x0 | GET_DEVICES | Get device UUIDs (pre-supplicant) |
| 0x1 | GET_DEVICES_SUPP | Get device UUIDs (post-supplicant) |

### 2.5 RNG PTA (Random Number Generator)

**UUID**: `ab7a617c-b8e7-4d8f-8301-d09b61036b64`
**Source**: `optee_os/core/pta/hwrng.c` (line 82)

| CMD ID | Name | Description |
|--------|------|-------------|
| 0x0 | GET_ENTROPY | Get entropy from hardware RNG |
| 0x1 | GET_RNG_INFO | Get RNG information |

### 2.6 RTC PTA (Real Time Clock)

**UUID**: `f389f8c8-845f-496c-8bbe-d64bd24c92fd`
**Source**: `optee_os/core/pta/rtc.c` (line 350)

| CMD ID | Name | Description |
|--------|------|-------------|
| 0x0 | GET_INFO | Get RTC information |
| 0x1 | GET_TIME | Read time |
| 0x2 | SET_TIME | Set time |
| 0x3-0x4 | GET/SET_OFFSET | RTC calibration offset |
| 0x5-0x8 | ALARM ops | Read/set/enable/wait alarm |

### 2.7 Attestation PTA

**UUID**: `39800861-182a-4720-9b67-2bcd622bc0b5`
**Source**: `optee_os/core/pta/attestation.c` (line 800)

| CMD ID | Name | Description |
|--------|------|-------------|
| 0x0 | GET_PUBKEY | Get RSA public key |
| 0x1 | GET_TA_SHDR_DIGEST | Get TA signed header digest |
| 0x2 | HASH_TA_MEMORY | Signed hash of TA memory |
| 0x3 | HASH_TEE_MEMORY | Signed hash of TEE memory |

### 2.8 System PTA

**UUID**: `3a2f8978-5dc0-11e8-9c2d-fa7ae01bbebc`
**Source**: `optee_os/core/pta/system.c` (line 402)

| CMD ID | Name | Description |
|--------|------|-------------|
| 0x0 | ADD_RNG_ENTROPY | Add entropy to RNG pool |
| 0x1 | DERIVE_TA_UNIQUE_KEY | Derive device/TA unique key |
| 0x2 | MAP_ZI | Map zero-initialized memory |
| 0x3 | UNMAP | Unmap memory |

### 2.9 Other PTAs (not STM32-relevant)

| PTA | UUID | Source | Purpose |
|-----|------|--------|---------|
| Stats | `d96a5b40-e2c7-b1af-...` | `pta/stats.c` | Pager/heap/TA statistics |
| Benchmark | `0b9a63b0-b4c6-4c85-...` | `pta/benchmark.c` | Performance benchmarking |
| GProf | `2f6e0d48-c574-426d-...` | `pta/gprof.c` | Profiling data |
| Socket | `3b996a7d-2c2b-4a49-...` | `tee/socket.c` | Network sockets (via supplicant) |
| APDU | `3f3eb880-3639-11ec-...` | `pta/apdu.c` | Smart card communication |
| TUI | `9c199eb0-4d2d-41a5-...` | `pta/tui.c` | Trusted UI |
| SCP03 | `be0e5821-e718-4f77-...` | `pta/scp03.c` | Secure Channel Protocol 3 |
| SecStor TA Mgmt | `6e256cba-fc4d-4941-...` | `pta/secstor_ta_mgmt.c` | TA install from signed binary |

## 3. SCMI Interface

### 3.1 Architecture

```
seL4 / Linux (NSEC)
    │
    ├─ Open session to PTA_SCMI (UUID a8cfe406...)
    ├─ GET_CHANNEL_HANDLE → channel_id
    ├─ PROCESS_SMT_CHANNEL / PROCESS_MSG_CHANNEL
    │     └─ Payload: SCMI protocol message
    │
    └───────── SMC ──────────►  OP-TEE (SEC)
                                   │
                                   ├─ PTA SCMI dispatcher (core/pta/scmi.c)
                                   ├─ SCMI Server (core/lib/scmi-server/)
                                   │    └─ SCP-firmware modules
                                   └─ Platform backend (plat-stm32mp2/scmi_server_scpfw.c)
                                        └─ Clock driver (core/drivers/clk/clk-stm32mp25.c)
                                             └─ RCC register write (MMIO to 0x44200000+offset)
```

### 3.2 Transport

- **Type**: Shared Memory Transport (SMT) with SMC as doorbell
- **Compatible**: `"linaro,scmi-optee"` (Linux DTS stm32mp251.dtsi:139)
- **Shared memory**: Dynamically allocated by OP-TEE at boot (not static DTS address)
- **Channel setup**: Via `PTA_SCMI_CMD_GET_CHANNEL_HANDLE`
- **Source**: `optee_os/core/lib/scmi-server/scmi_server.c` — `smt_phys_to_virt()` maps shmem

### 3.3 Protocols Implemented

Source: `optee_os/core/include/drivers/scmi.h`

| Protocol ID | Name | SCP-firmware module |
|------------|------|---------------------|
| 0x10 | BASE | `scmi/` |
| 0x13 | PERF | `scmi_perf/` |
| **0x14** | **CLOCK** | **`scmi_clock/`** |
| 0x15 | SENSOR | `scmi_sensor/` |
| 0x16 | RESET_DOMAIN | `scmi_reset_domain/` |
| 0x17 | VOLTAGE_DOMAIN | `scmi_voltage_domain/` |

### 3.4 SCMI Clock Protocol (0x14)

**Clock CONFIG_SET message** (enable/disable a clock):

Source: `SCP-firmware/module/scmi_clock/include/internal/scmi_clock.h` lines 204-217

```c
// Agent → Platform (request)
struct scmi_clock_config_set_a2p {
    uint32_t clock_id;      // Clock ID (e.g., CK_BUS_ETH1 = 92)
    uint32_t attributes;    // Bit 0: 1=enable, 0=disable
};

// Platform → Agent (response)
struct scmi_clock_config_set_p2a {
    int32_t status;         // SCMI_SUCCESS = 0
};
```

Handler: `scmi_clock_config_set_handler()` in
`SCP-firmware/module/scmi_clock/src/mod_scmi_clock.c` line 1140

### 3.5 ETH1 Clock IDs

Source: `optee_os/core/include/dt-bindings/clock/stm32mp25-clks.h`

| Clock ID | Define | Register | Gate Bit | Required? |
|----------|--------|----------|----------|-----------|
| 92 | CK_BUS_ETH1 | RCC_ETH1CFGR | 5 | Yes (bus/ICN clock) |
| 316 | CK_KER_ETH1 | RCC_ETH1CFGR | 5 | Yes (kernel clock) |
| 318 | CK_KER_ETH1PTP | RCC_ETH1CFGR | 5 | PTP timestamping |
| 327 | CK_ETH1_RX | RCC_ETH1CFGR | 10 | Yes |
| 328 | CK_ETH1_TX | RCC_ETH1CFGR | 8 | Yes |
| 329 | CK_ETH1_MAC | RCC_ETH1CFGR | 1 | Yes |
| 333 | CK_ETH1_STP | RCC_ETH1CFGR | 4 | Low-power stop |

All gate clocks share a single register: **RCC_ETH1CFGR** at `RCC_BASE + 0x7F0`.
Gate driver: `clk-stm32mp25.c` lines 492-496, 627-631.

### 3.6 SCMI Access from Non-Linux Clients

**SCMI can be called from any non-secure entity**, including seL4. Evidence:

- PTA_SCMI UUID is public, no agent restrictions at PTA layer
- `GET_CHANNEL_HANDLE` returns unique handle per caller
- `scmi_server_scpfw.c` line 230-240: agent discovery from DTS, no Linux-only restriction
- Resource permissions (`BUILD_HAS_MOD_RESOURCE_PERMS`) are optional; if disabled, all
  agents have equal access

**Constraint**: Requires shared memory between seL4 and OP-TEE for SMT headers and
SCMI payloads. This is the complex part — see Section 5 for feasibility analysis.

## 4. WatchdogKicker SMC — Annotated Call Path

### 4.1 seL4 Side

```c
// WatchdogKicker/WatchdogKicker.c
#define SMCWD_FUNC_ID   0xbc000000
#define SMCWD_PET       3

seL4_ARM_SMCContext args = {0};
args.x0 = SMCWD_FUNC_ID;    // SMC function ID
args.x1 = SMCWD_PET;        // Command: pet/refresh
// x2-x7 = 0 (unused)

seL4_CPtr smc_cap = camkes_get_smc_cap(0xbc000000);
seL4_ARM_SMC_Call(smc_cap, &args, &result);
// result.x0 = PSCI_RET_SUCCESS (0) on success
```

CAmkES assembly configures:
```
watchdog_kicker.allowed_smc_functions = [0xbc000000];
```

### 4.2 Full Call Chain

```
seL4 WatchdogKicker (EL0/EL1)
│  seL4_ARM_SMC_Call(smc_cap, args, result)
│    ↓ syscall to seL4 kernel
│
seL4 Kernel (EL2)
│  Validates SMC capability badge = 0xbc000000
│  Loads x0-x7 into CPU registers
│  Executes: smc #0
│    ↓ trap to EL3
│
TF-A Secure Monitor (EL3)
│  runtime_svc_dispatch(): routes 0xbc OEN to OP-TEE
│    ↓ world switch to Secure EL1
│
OP-TEE (S-EL1)
│  __tee_entry_fast()                    — entry_fast.c:258
│    case CFG_WDT_SM_HANDLER_ID:         — entry_fast.c:333
│      tee_entry_watchdog(args)          — entry_fast.c:222
│        __wdt_sm_handler(args)          — watchdog_sm.c:17
│          case SMCWD_PET:               — watchdog_sm.c:66
│            watchdog_ping()             — wdt.h:76
│              wdt_chip->ops->ping()
│                ↓
│
STM32 IWDG Driver (OP-TEE)
│  iwdg_refresh()                        — stm32_iwdg.c:154
│    io_write32(0x4C006000 + 0x00,       — IWDG_KR register
│               0xAAAA)                  — Reload key
│    ↓
│
IWDG1 Hardware (0x4C006000)
   Countdown timer reset — 32s timeout extended
```

### 4.3 SMC Capability in seL4

- Enabled by: `KernelAllowSMCCalls ON` in `settings.cmake`
- CAmkES template: `camkes-tool/camkes/templates/component.common.c` lines 87-103
- `camkes_get_smc_cap(func_id)` returns capability allocated by CAmkES `alloc()`
- Capability type: `seL4_ARMSMC`, badge = SMC function ID
- Kernel validates badge matches `args.x0` before executing `smc #0`

### 4.4 Watchdog SMC Commands (Full Reference)

Source: `optee_os/core/arch/arm/include/sm/watchdog_smc.h`
Handler: `optee_os/core/drivers/wdt/watchdog_sm.c`
Config: `CFG_WDT_SM_HANDLER_ID = 0xbc000000` (plat-stm32mp2/conf.mk)

| CMD (x1) | Name | x2 input | Return (x0) | x1 output |
|----------|------|----------|-------------|-----------|
| 0 | SMCWD_INIT | — | SUCCESS | min_timeout |
| 1 | SMCWD_SET_TIMEOUT | timeout_s | SUCCESS/INVALID | — |
| 2 | SMCWD_ENABLE | 0=stop, 1=start | SUCCESS/FAIL | — |
| **3** | **SMCWD_PET** | — | **SUCCESS/DISABLED** | — |
| 4 | SMCWD_GET_TIMELEFT | — | SUCCESS/NOT_SUPPORTED | time_left |

## 5. Clock Enable Path Options for seL4 DWMAC_Driver

### Option A: SCMI via PTA_SCMI (Standard Path)

```c
// seL4 side — REQUIRES TEE client API implementation
// Step 1: Open session to PTA_SCMI
struct optee_msg_arg msg = {
    .cmd = OPTEE_MSG_CMD_OPEN_SESSION,
    .uuid = {0xa8cfe406, 0xd4f5, 0x4a2e, ...}  // PTA_SCMI UUID
};
smc_call(OPTEE_SMC_CALL_WITH_ARG, &msg);  // Standard SMC

// Step 2: Get SCMI channel handle
msg.cmd = OPTEE_MSG_CMD_INVOKE_COMMAND;
msg.func = PTA_SCMI_CMD_GET_CHANNEL_HANDLE;  // 0x3
smc_call(OPTEE_SMC_CALL_WITH_ARG, &msg);

// Step 3: Enable CK_BUS_ETH1 (clock_id=92)
// Build SMT buffer with SCMI CLOCK CONFIG_SET (protocol=0x14)
struct scmi_clock_config_set_a2p payload = {
    .clock_id = 92,       // CK_BUS_ETH1
    .attributes = 1,      // enable
};
// Write to SMT shared memory, then:
msg.func = PTA_SCMI_CMD_PROCESS_SMT_CHANNEL;  // 0x1
smc_call(OPTEE_SMC_CALL_WITH_ARG, &msg);

// Repeat for clock IDs: 327 (RX), 328 (TX), 329 (MAC), 333 (STP)
```

- **Requires OP-TEE modification**: NO
- **Complexity**: HIGH — needs TEE client API (open session, shared memory, SCMI protocol
  framing, SMT headers). No existing seL4 implementation.
- **Confidence**: Likely works, but substantial engineering effort
- **Shared memory**: Must map OP-TEE's SMT buffer into seL4 component address space

### Option B: Add Clock FAST SMC Handler to OP-TEE (New Service)

```c
// OP-TEE side — new handler in entry_fast.c, modeled on watchdog_sm.c
// New function ID: 0xbd000000 (or configurable via CFG_CLK_SM_HANDLER_ID)
// Commands:
//   SMCCLK_ENABLE  = 0  (x2 = clock_id)
//   SMCCLK_DISABLE = 1  (x2 = clock_id)
//   SMCCLK_STATUS  = 2  (x2 = clock_id, returns enabled/disabled in x1)

// seL4 side — identical pattern to WatchdogKicker
#define SMCCLK_FUNC_ID  0xbd000000
#define SMCCLK_ENABLE   0

seL4_ARM_SMCContext args = {0};
args.x0 = SMCCLK_FUNC_ID;
args.x1 = SMCCLK_ENABLE;
args.x2 = 92;  // CK_BUS_ETH1

seL4_CPtr smc_cap = camkes_get_smc_cap(0xbd000000);
seL4_ARM_SMC_Call(smc_cap, &args, &result);
// Repeat for IDs: 327, 328, 329, 333
```

- **Requires OP-TEE modification**: YES — add ~50 lines to entry_fast.c + new handler file
- **Complexity**: MEDIUM — OP-TEE change is small; seL4 side is trivial (WatchdogKicker pattern)
- **Confidence**: High — proven pattern (WatchdogKicker works this way)
- **OP-TEE files to modify**:
  - `core/arch/arm/plat-stm32mp2/conf.mk` — add `CFG_CLK_SM_HANDLER_ID`
  - `core/arch/arm/tee/entry_fast.c` — add case for new function ID
  - `core/drivers/clk/clk_sm.c` (new) — handler that calls `clk_enable()`

### Option C: Extend Watchdog SMC with Clock Commands

```c
// seL4 side — reuse existing 0xbc000000 handler
// Add new commands alongside SMCWD_PET:
//   SMCWD_CLK_ENABLE  = 5  (x2 = clock_id)
//   SMCWD_CLK_DISABLE = 6  (x2 = clock_id)

seL4_ARM_SMCContext args = {0};
args.x0 = 0xbc000000;    // Existing watchdog function ID
args.x1 = 5;             // New: CLK_ENABLE
args.x2 = 92;            // CK_BUS_ETH1

seL4_ARM_SMC_Call(smc_cap, &args, &result);
```

- **Requires OP-TEE modification**: YES — add ~20 lines to `watchdog_sm.c`
- **Complexity**: LOW — smallest change, no new files
- **Confidence**: High — extends proven working handler
- **Downside**: Semantically mixes clock and watchdog concerns. Workable for development;
  should be refactored to Option B for production.

### Option D: Modify OP-TEE DTS to Enable at Boot

```dts
// In optee_os/core/arch/arm/dts/ccmp25-dvk.dts, add:
&eth1 {
    status = "okay";
};
// Or add explicit clock-enable to OP-TEE platform init code
```

```c
// seL4 side — NO CODE CHANGES
// Clocks are on from boot. DWMAC_Driver just reads GMAC_Version to verify.
uint32_t ver = *(volatile uint32_t *)(dwmac_base + 0x110);
assert(ver != 0);  // Non-zero confirms clocks are on
```

- **Requires OP-TEE modification**: YES — DTS change only (1-3 lines)
- **Complexity**: LOW — no driver code, just DTS + FIP rebuild
- **Confidence**: Uncertain — depends on whether OP-TEE's ETH1 DTS node triggers clock
  enable. OP-TEE's probe function must call `clk_enable()` for the node. Need to verify
  that OP-TEE actually probes non-secure-relevant peripherals.
- **Risk**: OP-TEE may ignore `status = "okay"` for peripherals it doesn't use

### Option E: Linux VM Guest Handles Clocks

```c
// seL4 side (VM build only) — NO CHANGES
// Linux guest boots → DWMAC driver probes → requests clocks via SCMI → OP-TEE enables
// seL4 DWMAC_Driver waits for clocks to be on:
while (*(volatile uint32_t *)(dwmac_base + 0x110) == 0) {
    // Linux hasn't initialized ETH1 yet
    seL4_Yield();
}
// Clocks are now on, proceed with MMIO
```

- **Requires OP-TEE modification**: NO
- **Complexity**: ZERO for seL4
- **Confidence**: High — this is how Linux works today
- **Limitation**: Only works in VM builds (`-DSTM32MP25X_VM=ON`). Native builds need
  another option.

## 6. Recommended Approach for DWMAC Clock Enable

### For VM builds: Option E (Linux handles it)

Zero effort. Linux VM guest's DWMAC driver requests clocks through SCMI automatically.
The seL4 DWMAC_Driver only needs a startup check (read GMAC_Version until non-zero).

### For native builds: Option C (extend watchdog SMC), then refactor to Option B

**Phase 1** — Get it working (Option C):
- Add `SMCWD_CLK_ENABLE = 5` and `SMCWD_CLK_DISABLE = 6` to `watchdog_sm.c`
- Handler calls `clk_enable()` / `clk_disable()` via the existing OP-TEE clock framework
- seL4 side: 5 SMC calls at DWMAC_Driver init (one per gate clock)
- ~20 lines of OP-TEE code + FIP rebuild

**Phase 2** — Clean up (Option B):
- Factor clock SMC into its own handler with dedicated function ID (0xbd000000)
- Proper command structure (ENABLE, DISABLE, STATUS)
- Allow CAmkES to control which clock IDs each component may request

### Why not Option A (SCMI via PTA)?

The PTA invocation path requires implementing the full TEE client API from seL4:
- `optee_msg_arg` shared memory setup
- Session management (open/close)
- SCMI SMT header framing
- Shared memory registration

This is weeks of engineering for the first use. Option C achieves the same result with
~20 lines of OP-TEE code and reuses the proven WatchdogKicker SMC pattern.

### Why not Option D (OP-TEE DTS)?

Uncertain whether OP-TEE probes `eth1` node when it doesn't use the peripheral.
Option C is more reliable and equally low-effort on the OP-TEE side.

## Appendix: Source Files Referenced

| File | Lines | Content |
|------|-------|---------|
| `optee_os/core/arch/arm/include/sm/optee_smc.h` | 20-59, 787-801 | SMC encoding, return codes |
| `optee_os/core/arch/arm/tee/entry_fast.c` | 222-229, 258-355 | Fast SMC dispatcher |
| `optee_os/core/arch/arm/kernel/thread_optee_smc.c` | 292-310 | Standard SMC dispatcher |
| `optee_os/core/arch/arm/include/sm/watchdog_smc.h` | full | WDT SMC protocol |
| `optee_os/core/drivers/wdt/watchdog_sm.c` | 17-88 | WDT SMC handler |
| `optee_os/core/arch/arm/plat-stm32mp2/conf.mk` | — | `CFG_WDT_SM_HANDLER_ID=0xbc000000` |
| `optee_os/core/pta/scmi.c` | 414 | PTA_SCMI registration |
| `optee_os/lib/libutee/include/pta_scmi_client.h` | full | SCMI PTA client interface |
| `optee_os/core/lib/scmi-server/SCP-firmware/module/scmi_clock/` | — | SCMI clock protocol |
| `optee_os/core/drivers/clk/clk-stm32mp25.c` | 492-496, 627-636 | ETH1 gate definitions |
| `optee_os/core/include/dt-bindings/clock/stm32mp25-clks.h` | 115, 327-333 | Clock IDs |
| `optee_os/core/include/optee_msg.h` | 335-342 | Message commands |
| `modbus_ccmp25/components/WatchdogKicker/WatchdogKicker.c` | 33-43 | seL4 SMC call |
| `camkes-tool/camkes/templates/component.common.c` | 87-103 | SMC capability alloc |
