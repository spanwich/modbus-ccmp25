# RISAB / TF-A SRAM firewall panic — investigation

**Status:** open (root master not yet pinned; discriminator experiment pending hardware).
**Date:** 2026-06-08.
**Symptom:** booting the multikernel `rootserver_hello` image on the CCMP25-DVK reaches
user space (`[K0] hello rootserver up`, `[K0] tick 0`) and then OP-TEE **panics** on an
IAC (Illegal Access Controller) exception. OP-TEE panic wedges the SoC → hard boot
blocker.

## The panic, decoded

```
E/TC:1  stm32_iac_itr:192  IAC exceptions [159:128]: 0x1      (latched at "Starting kernel")
E/TC:1  stm32_iac_itr:197  IAC exception ID: 128
E/TC:1  DUMPING DATA FOR risab@420f0000
E/TC:1  Status register (IAESR): 0x11
E/TC:1  Faulty address (IADDR): 0xe002570
E/TC:1  Panic at .../core/drivers/firewall/...
```

Confirmed against OP-TEE source `~/phd/ccwmp255/optee_os` (read-only reference):

| Field | Value | Meaning |
|-------|-------|---------|
| firewall | `risab@420f0000` = **RISAB1** | `stm32mp251.dtsi:2850`, `st,mem-map = <0xa000000 0x20000>` (128 KB SRAM bank) |
| bank owner | `tfa_bl31` @ `0xa000000` | `ccmp25-dvk-rif.dtsi:883` `&risab1 { memory-region = <&tfa_bl31>; }` → **TF-A BL31 runtime SRAM**, secure / CID1 |
| IADDR | `0x0E002570` | same physical SRAM via the CPU `0x0E00_0000` alias; offset `0x2570` into BL31's bank |
| IAC ID | 128 | maps to RISAB1 |
| IAESR | `0x11` | decode below |

**IAESR `0x11` decode** (`stm32_risab.c:151-153`: `cid = v & 0x7`, `priv = v&BIT(4)`,
`sec = v&BIT(5)`, `nrw = v&BIT(7)`):
- `cid = 1`, `priv = 1`, `sec = 0`, `nrw = 0`
- ⇒ a **non-secure, privileged, CID1** access (and `nrw=0`, i.e. a read under ST's bit
  convention — confirm the convention before relying on direction).

**Mechanism:** privileged non-secure code touched a 128 KB SRAM bank RISAB1 reserves for
secure TF-A BL31. RISAB raised an IAC interrupt to the secure world; OP-TEE's IAC handler
is **fail-stop** (`panic()`). The firewall is working *correctly* — this is a real
isolation violation by the normal world, not an OP-TEE bug.

## Ruled out (by evidence)

- **Not the rootserver.** `priv=1` ⇒ EL2/privileged code, not the EL0 rootserver
  (which only does `seL4_DebugPutChar` + a CPU busy-loop). `tick 0` printing before the
  dump is console interleaving; the IAC bit is already latched at "Starting kernel".
- **Not the board DTB.** `deploy/boot.cmd` hands `ccmp25-dvk.dtb` to `bootm` only; the
  elfloader uses its own embedded minimal DTB (serial/GIC/timer). No SRAM node reaches seL4.
- **Not the parked secondary core.** On STM32MP25 (non-MLXBF2),
  `multikernel_dispatch_secondaries()` (`arch-arm/multikernel.c:258-260`) PSCI-CPU_ONs
  core 1 to `multikernel_secondary_park` — a `wfe` loop in DDR — **not** the
  `multikernel_secondary_startup` trampoline (which `multikernel_trampoline.S:55-58` notes
  is MLXBF2-specific). A parked core in DDR makes no SRAM access.
- **Not an explicit SRAM literal.** No `0x0a0x_x000` / `0x0e0x_xxxx` constant appears in
  the disassembled `elfloader` or `kernel.elf`; `multikernel_load_all` loads K1 to DDR
  (`0x98000000`) and keeps its structs in BSS (DDR).
- **Not speculative prefetch.** The elfloader's flat identity map
  (`arch-arm/64/mmu.c:30-35`, `_boot_pud_down`) tags blocks `(0 << 2)` =
  strongly-ordered / Device-nGnRnE, never speculatively accessed. So the SRAM hit is an
  *explicit* access.

## Key complication: the elfloader is silent on this platform

The elfloader is heavily instrumented (`BF2-ELFLOADER[...]`, `multikernel: ...`,
`Enabling hypervisor MMU and paging`, `Jumping to kernel-image entry point`), yet **none**
of those lines appear in the boot log — the first seL4-side output is the kernel's
`[K0] Bootstrapping kernel`. There is no stm32 UART driver under
`tools/seL4/elfloader-tool/src/plat/`, so elfloader `printf` is a no-op here.

Consequence: the planned UART-marker bisect **cannot work**. Phase localization must use
**behavioral discriminators** (rebuild with features removed and observe whether the panic
survives), not elfloader prints.

## Remaining hypotheses (privileged-NS, explicit, ~"Starting kernel")

1. **The multikernel load / PSCI path on core 0** issues something (e.g. a PSCI/SMC, or a
   handoff) that makes OP-TEE service a pending IAC and panic — possibly an IAC latched
   earlier (U-Boot) but only surfaced once seL4 pokes the secure world.
2. **The base elfloader/kernel boot for stm32mp25x** makes a privileged-NS read of the
   SRAM alias (DTB/handoff/early init) independent of multikernel.

## Discriminator experiment

### Round 1 — plain single-kernel (RESULT: PASS, panic gone)

Built `multikernel_hello` with `CCWMP25HelloMultikernel=OFF` (no load, no dispatch, no
PSCI) → `build-ccwmp25-mk-hello-plain`. Flashed via USB-OTG, booted: reaches user space
and `tick` climbs steadily (>11) with **no `E/TC:` IAC/RISAB lines**.

⇒ The stray access is in the **multikernel path** (hypothesis 1), not the base
elfloader/kernel boot. Hypothesis 2 is ruled out.

### Round 2 — load-only (Multikernel=ON, Dispatch=OFF) (RESULT: PASS, panic gone)

`build-ccwmp25-mk-hello-k0-loadonly` loads K1's kernel/rootserver/DTB into DDR but issues
no `psci_cpu_on`. Flashed, booted: `tick` climbs, **no `E/TC:`** even at "Starting kernel".

⇒ Loading K1 is harmless. The fault is **exactly the PSCI CPU_ON dispatch** that wakes
core 1 (`multikernel_dispatch_secondaries()` → `psci_cpu_on(0x1, park, 1)`).

## Root cause (PSCI secondary bring-up, secure-world handoff)

Confirmed facts:
- Core-1 MPIDR `reg=<0x1>` (k0.dts) matches `bf2_mpidr[1]=0x1` — PSCI target correct.
- `multikernel_secondary_park` = `0x84726000` — valid NS-DRAM, a clean `wfe` loop that
  reads nothing. If core 1 reached it, it could not touch SRAM.
- elfloader issues a real `smc #0` (`psci_asm.S`), ABI x1=target,x2=entry,x3=ctx — correct.

TF-A (`~/phd/ccwmp255/arm-trusted-firmware`, read-only) shows:
- `STM32MP_SYSRAM_BASE = 0x0E000000` (`plat/st/stm32mp2/stm32mp2_def.h`); **`bl31_warm_entrypoint`
  and BL31 per-cpu/context data live in this SRAM** (the bank RISAB1 protects).
- Secondary reset vector is held in `CA35SS_SYSCFG_VBAR_CR` (`A35SSC 0x48800000 + 0x2084`),
  set to `stm32_sec_entrypoint = bl31_warm_entrypoint` (`stm32mp2_pm.c`).

The faulting `0x0E002570` is inside that warm-boot/BL31 SRAM. The IAESR says the access is
**non-secure** (sec=0). So **core 1 is running TF-A's warm-boot SRAM code in NON-SECURE
state** instead of being handed to our NS park entry via the secure EL3 monitor. It never
reaches `0x84726000`. This is a secure-world secondary-bring-up handoff problem at the
TF-A/OP-TEE/board level — not fixable from seL4's elfloader.

**NOTE / correction:** an earlier subagent blamed TF-A's `el3_exit` SCR_EL3 ordering — that
is incorrect (EL3 accesses are always Secure regardless of `SCR_EL3.NS`). Do **not** patch
TF-A's generic `el3_exit`.

## Two distinct gaps for real multikernel on 2×A35

1. **CPU_ON handoff:** an NS-initiated PSCI CPU_ON (OP-TEE resident) lands core 1 in BL31
   SRAM as NS → firewall panic. Needs the secure firmware to release core 1 to the NS
   entry properly (or confirmation that the board even supports a 2nd NS A35).
2. **Park vs boot:** even if (1) is fixed, STM32MP25 dispatch only PARKS core 1
   (`multikernel.c:259`, `multikernel_secondary_park`); the real
   `multikernel_secondary_startup` trampoline is `CONFIG_PLAT_MLXBF2`-gated. To actually
   run K1 on core 1, that startup path must be generalized for STM32MP25.

## Linux SMP check (RESULT: dual-core PSCI confirmed, from source)

`~/phd/ccwmp255/linux` DTS: `stm32mp255.dtsi → stm32mp253.dtsi → stm32mp251.dtsi`.
`mp253.dtsi` defines `cpu1: cpu@1` with `enable-method = "psci"`, `power-domains = <&cpu1_pd>`,
`clocks = <&scmi_perf 0>` — **not disabled**; arm-pmu has affinity `<&cpu0>, <&cpu1>`.

⇒ Vendor Linux brings up **both A35 via PSCI**. The firmware supports a 2nd non-secure A35;
OP-TEE permits it. So 2×A35 multikernel is **feasible** — the bug is seL4-specific in how it
drives CPU_ON, not a hardware/firmware wall.

## Working hypothesis & next steps

Core 1 fetches `bl31_warm_entrypoint` (SRAM) as NS ⇒ it isn't entering via the secure EL3
monitor as Linux's secondary does. Salient difference: seL4 fires CPU_ON from the
**elfloader at the very start of boot** (pre-MMU), while Linux does it **late**, after the
secure/SCMI/power-domain state (`cpu1_pd`, `scmi_perf`) is established.

Candidate next steps (seL4-side, cheap → deeper):
1. **Timing probe:** `CCWMP25HelloMultikernelDispatchAfterMmu=ON` (dispatch after K0 MMU
   enable). Cheap reflash; weak signal (still in elfloader, µs apart).
2. **Late dispatch:** issue CPU_ON from a fully-booted K0 (rootserver via `seL4_ARM_SMC`),
   mimicking Linux's late bring-up — closer match, needs a small code path.
3. **Secure prerequisites:** read TF-A `stm32_pwr_domain_on` / SCMI power-domain (`cpu1_pd`)
   to see what secure-side state Linux establishes before CPU_ON that the elfloader skips.

Separately, gap #2 still stands: STM32MP25 dispatch only parks core 1; real K1 boot needs
the `multikernel_secondary_startup` path generalized off `CONFIG_PLAT_MLXBF2`.

## TF-A `stm32_pwr_domain_on` findings (read-only, arm-trusted-firmware)

`plat/st/stm32mp2/stm32mp2_pm.c`:
- `stm32_pwr_domain_on()` (357): for the secondary, the ONLY action is a Power-On Reset of
  core 1 — `mmio_write_32(RCC_BASE + RCC_C1P1RSTCSETR, RCC_C1P1RSTCSETR_C1P1PORRST)`. No
  per-call entry/secure-state setup.
- Reset vector programmed ONCE at BL31 cold boot, `plat_setup_psci_ops()` (1391):
  `CA35SS_SYSCFG_VBAR_CR (A35SSC 0x48800000 + 0x2084) = bl31_warm_entrypoint`. That entry is
  in BL31 SRAM (`STM32MP_SYSRAM_BASE = 0x0E000000`) — i.e. `0x0E00xxxx`, matching the fault.
- `stm32_validate_ns_entrypoint()` (1060): only checks `entrypoint >= STM32MP_DDR_BASE`
  (0x80000000). Our `0x84726000` passes → TF-A accepts the call; it is not rejecting it.

**Key conclusion:** the fault is at `bl31_warm_entrypoint` — TF-A's own SECURE warm-boot
code — which runs *before* core 1 reaches our NS park entry. So core 1 is executing TF-A's
secure warm-boot **in non-secure state**, and the first fetch trips RISAB1. ⇒ our entry
address and elfloader dispatch timing are IRRELEVANT to this fault (kills the early-vs-late
timing hypothesis). The real issue is **core 1 not entering EL3/secure out of PORRST** — an
A35-subsystem secure-reset-state problem one level below the PM code.

### Threads 1 & 2 results

**Alias (thread 2) — disproven as the cause.** `0x0A000000` and `0x0E000000` are the SAME
physical SYSRAM; TF-A and OP-TEE both use the `0x0E` view at runtime
(`STM32MP_SYSRAM_BASE`/`SYSRAM_BASE = 0x0E000000`). RISAB decides allow/deny from the **bus
NS signal, not the address**. So it is not an alias mis-attribution — the access is genuinely
non-secure because **core 1 is genuinely in NS state**. RISAB1's secure-only config for the
BL31 bank is correct; the fix is NOT an OP-TEE RISAB change.

**TF-A (thread 1) — partial.** TF-A only PORRST-resets core 1 and relies on it resetting
into EL3/secure. A subagent concluded TF-A "never establishes the secondary's secure state",
but that would break vendor Linux dual-core too — so *why core 1 is NS specifically in the
seL4 boot context* remains OPEN. (Caveat: the Linux DTS only proves Linux *attempts*
dual-core; not yet proven it succeeds on this board.)

### Discovery: OP-TEE already patched to not panic (not yet flashed)

`~/phd/ccwmp255/optee_os/core/drivers/firewall/stm32_iac.c:209-213` has had `panic()`
replaced with `EMSG("IAC panic suppressed for temporary CPU1 warmboot diagnostics")`. So the
OP-TEE *source* no longer fail-stops on IAC — but the BOARD still runs stock vendor OP-TEE
(`4.0.0-stm32mp-r2`), which panicked in the original log. The no-panic PoC is staged in
source, not deployed. (`CFG_STM32_PANIC_ON_IAC_EVENT ?= y`, conf.mk:315.)

### PoC (no-panic OP-TEE + dispatch-ON multikernel)

Build+flash the patched OP-TEE (user-driven; ~/phd is off-limits to the agent) + the
dispatch-ON image `build-ccwmp25-mk-hello-k0`. Proves:
- ✅ K0 survives instead of the SoC wedging (decouples K0 from the core-1 IAC).
- ⚠️ K1 still won't run — suppressing the panic does NOT make RISAB allow core 1's fetch;
  core 1 stays blocked. Real fix requires resolving why core 1 warm-boots non-secure.

### Real-fix open question
Why does core 1 come out of PORRST non-secure under seL4 but secure under the vendor flow
(Linux SMP works — established from DTS + vendor support, no re-check needed)? Since the
firmware is provably capable, the bug is in seL4's invocation context. Candidate: Linux
does CPU_ON late, as one coordinated kernel, after SCMI/clock/`cpu1_pd` state is set up;
seL4's elfloader fires raw PSCI CPU_ON cold/early.

### Instrumentation: elfloader UART (added, seL4-side, no firmware touch)

Root cause of the silent elfloader: `devices_gen.h` lists serial@400e0000
(`compat "st,stm32h7-uart"`, base 0x400e0000) but NO elfloader driver matched it, so
`uart_set_out()` was never called and every elfloader `printf()` was a no-op — hiding the
whole boot/dispatch trace. Added `tools/seL4/elfloader-tool/src/drivers/uart/stm32-uart.c`
(TX-only, polls `USART_ISR.TXE` @0x1C, writes `USART_TDR` @0x28; U-Boot already configured
the UART). CMake globs `src/drivers/uart/*.c` — reconfigure required (glob is configure-time).
Rebuilt `build-ccwmp25-mk-hello-k0`; `_driver_list_stm32_uart` confirmed linked.

This is fully reflashable (`sel4.bin`), zero firmware/brick risk, and lets us finally see
the **PSCI handshake**:
- `multikernel: PSCI CPU_ON K1 mpidr=1 -> <entry> ctx=1`
- then either `multikernel: K1 dispatched` (PSCI returned SUCCESS → TF-A accepted, core 1
  powered, faults in secure warm-boot as NS ⇒ confirms core-1-secure-state hypothesis), or
  `PSCI CPU_ON K1 failed: <code>` (TF-A rejected — code says why: -2 INVALID_PARAMS,
  -9 INVALID_ADDRESS, -4 ALREADY_ON).
Plus all prior-hidden elfloader prints (BF2-ELFLOADER state, MMU enable, load trace).

### Result (RESULT: PSCI SUCCESS — core-1-secure-state confirmed)

Full trace captured on hardware:
```
multikernel: PSCI CPU_ON K1 mpidr=1 -> 84726000 ctx=1
multikernel: K1 dispatched                 <- psci_cpu_on returned PSCI_E_SUCCESS
Enabling hypervisor MMU and paging
Jumping t E/TC:1  stm32_iac_itr:192 IAC exceptions [159:128]: 0x1   <- async, after SMC
... [K0] hello rootserver up / tick 0 ... then OP-TEE panic (stock build)
```
- `K1 dispatched` ⇒ TF-A **accepted** CPU_ON (entry 0x84726000 + MPIDR 0x1 valid). NOT a
  PSCI rejection.
- The IAC fires asynchronously after the SMC returns ⇒ the fault is **core 1's**, in its
  TF-A warm-boot. Core-1-secure-state hypothesis **confirmed**.
- K0 is healthy (reaches tick 0); the panic is purely OP-TEE fail-stopping on core 1's
  access, not K0 misbehaving.

Note: the elfloader's `BF2-ELFLOADER`/`BF2 bundle` strings are cosmetic labels (BF2-first
development); the substantive secondary-boot code (`multikernel_secondary_startup`, shared
pool) is `#ifdef CONFIG_PLAT_MLXBF2` and compiled OUT — STM32MP25 only ever PARKS core 1.

### SCMI/clock hypothesis — KILLED (checked TF-A)
`stm32_pwr_domain_on()` for the secondary does ONLY the PORRST (`RCC_C1P1RSTCSETR`) — no
`clk_enable`/SCMI/power-domain step before reset. And clocks don't set a CPU's security
state. So there is no clock/SCMI prerequisite we skip. Scratch it.

### EL2 question (CurrentEL=8) — explained, and a config decision
`CurrentEL=8` = EL2. Cause: `multikernel_hello/settings.cmake` force-set
`KernelArmHypervisorSupport ON` (now made overridable via `CCWMP25HelloHypervisor`,
default ON). The `BF2-ELFLOADER[...] CurrentEL=8` lines are the **elfloader's** EL — it
ALWAYS runs at EL2 (U-Boot handoff), independent of the kernel's hyp setting. hyp controls
only the KERNEL's EL (ON→EL2, OFF→EL1 via an EL2→EL1 drop). Almost certainly a red herring
for the fault: PSCI dispatch happens in the elfloader at EL2 *before* any EL drop, so the
secondary bring-up is identical either way.

EL1 experiment built: `build-ccwmp25-mk-hello-k1-el1` + `build-ccwmp25-mk-hello-k0-el1`
(`KernelArmHypervisorSupport=OFF`, dispatch ON). Expect: early elfloader prints still EL=8;
new EL2→EL1 handoff markers (`after-eret-in-leave-hyp`, CurrentEL=4); firewall fault likely
persists (confirming kernel-EL is not the cause). Watch the finicky EL1-handoff path.

### EL1 experiment RESULT (RESULT: fault persists, EL ruled out)
Flashed `build-ccwmp25-mk-hello-k0-el1`: `ARM_HYPERVISOR_SUPPORT=off`, EL2→EL1 handoff
works (`after-eret-in-leave-hyp: CurrentEL=4`, kernel at EL1 = the intended config). Fault
identical (`IADDR 0xe002570`, `IAESR 0x11`, panic). Also: entry changed 84726000→84722000
but fault addr unchanged ⇒ fault is in TF-A/OP-TEE secure bring-up, independent of our NS
entry. EL conclusively ruled out. Left `CCWMP25HelloHypervisor` toggle in settings.cmake
(default ON).

### Extensive OP-TEE secondary-bringup review (verified, with one correction)
- OP-TEE secondary path: `vector_cpu_on_entry → cpu_on_handler → boot_cpu_on_handler →
  init_secondary_helper` (entry_a64.S, boot.c:1246-1267); first line is
  `IMSG("Secondary CPU %zu initializing")`. **Not seen in the log** ⇒ core 1 never reached
  OP-TEE per-core init. Fault is BEFORE OP-TEE, in TF-A warm-boot.
- OP-TEE is in DDR (0x82000000); the faulting bank is exclusively TF-A BL31. `0x0E002570`
  is almost certainly `bl31_warm_entrypoint` itself ⇒ core 1 faults on its FIRST warm-boot
  fetch ⇒ core 1 is non-secure from reset.
- **CORRECTION (quote-checked):** a subagent claimed `RIMUPROT(RIMU_ID(0), RIF_CID1,
  RIF_NSEC,...)` tags the A35 cluster non-secure. WRONG. `RIMU_ID(0)`=200 is a DMA/interconnect
  master; the whole `st,rimu` table is the stock ST default (all 16 masters NSEC/PRIV). The
  A35 CPU is NOT RIMU-governed — CPU bus security = execution state. If RIMU forced the A35
  NS, core 0 couldn't run secure BL31 either. The CID1/NSEC/PRIV bit-match is coincidental.
  RIMU lead is DEAD.
- RISAB1/tfa_bl31 config is correct (secure-only, CID1).

### Conclusion: core 1 resets NON-SECURE; cause is A35SS/RCC reset-security (not in source)
TF-A/OP-TEE only set the reset VECTOR (`CA35SS_SYSCFG_VBAR_CR`) and assume the architectural
EL3/Secure reset; neither writes any per-core "boot secure" config. Why the secondary PORRSTs
non-secure (when core 0 cold-boots secure) is an A35-subsystem / RCC reset-security detail
**not present in the TF-A or OP-TEE source** → needs the STM32MP25 reference manual or
hardware observation. Source analysis is exhausted.

### Reference manual (RM0457) findings — AUTHORITATIVE, and they reframe the bug
RISAB_IAESR layout (RM pp.381-382) exactly matches OP-TEE's decode. `IAESR=0x11` decodes:
- IACID[2:0]=1 (CID1), IAPRIV(b4)=1 (privileged), IASEC(b5)=0 (**non-secure**),
  IANRW(b7)=0 (**data read**).
⇒ The blocked access is a **non-secure, privileged, CID1 DATA READ** of 0x0E002570 — NOT an
instruction fetch.

CA35SS boot (RM §3.4-3.5.3): cores reset via `CA35SS_SYSCFG_VBAR_CR`/`RVBARADDRL` into
**EL3/secure** (RVBAR). `AARCH_MODE_CR`(0x2080)=mode, `VBAR_CR`(0x2084)=reset vector; both
trusted-CID/secure-only. **No per-core "boot non-secure" bit** (TrustZone knobs are M33-only;
`C0/C1_SMP` are read-only coherency-status). So core 1 DOES boot secure.

**Reframe:** the earlier "core 1 boots NS and faults fetching warm-boot code" theory is
REFUTED. Core 1 boots secure-EL3, warm-boots (secure), and is handed to our NS park entry
(a `wfe` loop in DDR that reads nothing). Yet a non-secure DATA READ of BL31's SRAM occurs,
only when core 1 is dispatched. No NS instruction in core 1's path reads 0x0E002570 ⇒ most
likely a HARDWARE side-effect of core 1 joining the SMP coherency domain (snoop/prefetch of
secure BL31 cache lines) or TF-A NS-context handling — not in/ fixable from seL4 source.

### Status: static analysis exhausted (firmware source + RM)
The decode is authoritative; the boot path understood. The remaining unknown — WHICH master
issues the NS data read of 0x0E002570 — needs live observation, not reading.

### Recovery path + OP-TEE flash method (FOUND — brick risk solved)
Vendor DEY installer at `/home/iamfo470/Documents/ccmp25-dvk-webkit-installer` contains stock
TF-A + **OP-TEE FIP** (`fip-ccmp25-dvk-optee-emmc.bin`) + Linux + `install_linux_fw_uuu.sh`.
- Recovery = re-run `install_linux_fw_uuu.sh` (restores everything incl. stock OP-TEE).
- OP-TEE flash method: FIP → GPT partitions `fip-a`/`fip-b` via `uuu fb: flash fip-a <fip.bin>`
  (same uuu tooling as sel4.bin). The patched-OP-TEE FIP replaces `fip-...-optee-emmc.bin`.
(NB: `phd/.../linux/` is the CAmkES VM *guest* kernel, NOT a vendor/recovery image.)

### Vendor Linux cross-check (RESULT: DEFINITIVE — firmware works, seL4 is the bug)
Flashed the Digi DEY installer, booted vendor Linux 6.6.78:
- `nproc` = 2; `CPU1: Booted secondary processor 0x...01`; `SMP: Total of 2 processors
  activated`; `CPU: All CPU(s) started at EL2`. **No `E/TC:`/RISAB fault.**
⇒ The IDENTICAL TF-A+OP-TEE+RISAB firmware brings up core 1 cleanly via PSCI. So the firewall
fault is **100% in how seL4 wakes core 1** — **no OP-TEE patch needed.**

Key clue: Linux brings up CPU1 at t=0.007s, **before** it probes RIFSC (0.169s) or SCMI
(0.268s). So it's NOT SCMI/firewall-driver timing (dead hypothesis). The firewall state is the
OP-TEE-left one in both cases. The real difference is **system state at dispatch**:
- Linux: CPU_ON issued with core 0's **MMU+caches ON**, cluster coherency established.
- seL4: CPU_ON issued from the **early elfloader, caches OFF, before core 0 MMU enable**
  (trace: disable-caches → dispatching → Enabling MMU).

### DispatchAfterMmu=ON test (RESULT: fault persists — cache-state RULED OUT)
`build-ccwmp25-mk-hello-k0-aftermmu`. Same fault (IADDR 0xe002570, IAESR 0x11). Notable:
now `E/TC:0` (was `E/TC:1`) and NO `K1 dispatched` — fault fires DURING the `psci_cpu_on`
SMC, before it returns. ⇒ core 1's warm-boot read fires immediately after PORRST (before the
SMC returns); moving dispatch later only changed which core services the IAC. The access is
robustly tied to PSCI CPU_ON of core 1, independent of seL4-side state.

### seL4-side levers EXHAUSTED (all hardware-tested)
Ruled out: entry address, kernel EL (EL2 vs EL1), dispatch timing (before/after MMU), cache
state. Linux does a structurally identical PSCI CPU_ON on the same firmware → core 1 fine;
seL4 → fault. The differing state precedes any seL4 secondary code (it's in TF-A warm-boot),
so it can't be found by reading seL4. 

### Decision: no-panic OP-TEE (observe, not infer) — now safe
Vendor installer = proven restore path. Staged patch (stm32_iac.c panic→log-continue) already
suffices. Flash patched OP-TEE FIP (fip-a/fip-b via `uuu fb: flash`) + multikernel seL4:
- K0 survives + `[K1]` ticks appear → blocked read was BENIGN, multikernel works (mask the
  IAC); DONE.
- K1 stays dead / IAC repeats → read is consequential; hunt the exact state delta vs Linux
  (read ~/phd/ccwmp255/linux smp/psci path).
Open: how the user rebuilds + packages the OP-TEE FIP (vendor ships prebuilt FIP only).

### Linux source check (RESULT: no code-level delta)
arm64 uses GENERIC PSCI for secondaries (`arch/arm64/kernel/psci.c:41`:
`psci_ops.cpu_on(cpu_logical_map(cpu), __pa_symbol(secondary_entry))`). No STM32-specific
secondary code; nothing STM32 runs before CPU1 (up at t=0.007s, before RIFSC 0.169s / SCMI
0.268s). The `a35ss_syscfg` DT refs are for the M33 boot vector, not the A35. Only diff vs
seL4: context_id (Linux 0, seL4 1) — opaque. ⇒ difference is the **calling context's system
state**: Linux wakes the secondary from a FULLY-BOOTED kernel; seL4 woke it from the minimal
elfloader (the one variable not yet moved).

### Path B test (Path #2): dispatch core 1 from BOOTED K0 (most Linux-like)
Decided to do this BEFORE the no-panic OP-TEE (no-panic tests the read under the OLD elfloader
state, can't predict the new state; and #2 is the likely clean fix — no firmware patch/brick).
Feasible cleanly: rootserver uses `seL4_CapSMC` (slot 15, badge 0 ⇒ any FID;
`kernel/src/arch/arm/object/smc.c:84`) + `seL4_ARM_SMC_Call` to issue PSCI CPU_ON. Implemented
in `multikernel_hello/rootserver/main.c` (`dispatch_core1()`, guarded `#if KERNEL_ID==0`):
PSCI CPU_ON core1 → 0x98000000 after "hello rootserver up". Built into
`build-ccwmp25-mk-hello-k0-loadonly` (elfloader Dispatch=OFF; rootserver does it).
- No `E/TC:` fault + K0 keeps ticking → booted-K0 dispatch avoids the warm-boot fault ⇒ the
  cause was elfloader bring-up state ⇒ clean seL4-side fix; next wire a real K1 trampoline
  (current entry 0x98000000 with garbage args will crash K1 — fine, we only test the firewall).
- Fault at 0x0E002570 → intrinsic to PSCI CPU_ON of core 1 ⇒ fall back to no-panic/mask.
- Fault at a DIFFERENT addr → that's K1's garbage-arg boot, not the warm-boot.

### RESULT (RESOLVED): booted-K0 dispatch works — firewall fault GONE
Hardware: `PSCI CPU_ON returned x0=0 (SUCCESS)`, **no `E/TC:`/RISAB fault**, K0 ticks
steadily (>19). ⇒ Waking core 1 via PSCI CPU_ON from the **fully-booted K0 rootserver**
(seL4_CapSMC) avoids the warm-boot firewall fault. ROOT CAUSE: the early **elfloader's
minimal bring-up state** provoked the non-secure access during TF-A warm-boot; dispatching
from a running OS (like Linux) is clean. **Fix is 100% seL4-side — no OP-TEE/firmware patch.**

The no-panic OP-TEE path is now MOOT (not needed). The OP-TEE source in ~/phd still has the
staged panic→log patch — revert it (restore `panic()`) if that tree is ever rebuilt for prod.

### Remaining work: actually BOOT K1 on core 1 (firewall solved; K1 not yet running)
Current test wakes core 1 to 0x98000000 (K1 kernel _start) with garbage x0-x5 ⇒ K1 crashes
silently (no `[K1]` output) — expected; it only validated the firewall. To boot K1:
1. K1 needs its OWN boot page tables (map 0x8098000000→0x98000000 + identity) in SURVIVING
   memory (K1's region @0x98000000+, outside K0 RAM [0x84000000..0x98000000)).
2. A trampoline (surviving memory) core 1 enters MMU-off: load K1 TTBR0, enable MMU, set
   x0-x5 = K1 init args (user phys start/end, pv_offset, user ventry, dtb, dtb_size), branch
   to K1 virt entry. Generalize `multikernel_secondary_startup` off `CONFIG_PLAT_MLXBF2`.
3. Elfloader `multikernel_load_all` places trampoline + K1 page tables + entry struct in K1's
   region (NOT the elfloader region, which K0 may reuse). `multikernel_entries[1].ttbr0_phys`
   is currently 0 — must be built for K1.
4. Rootserver wakes core 1 to the trampoline's surviving phys addr (instead of 0x98000000).

### Kernel entry contract (head.S:79-135) — why the full trampoline is needed
seL4 `_start` immediately uses high-half virtual addresses (`ldr x4,=kernel_stack_alloc`,
`bl init_kernel`) and only tweaks SCTLR control bits — so K1 must be entered **MMU-ON at its
virtual entry 0x8098000000**, with the high-half mapped. Waking core 1 to 0x98000000 raw
(MMU-off) cannot work; the trampoline must build K1 page tables + enable MMU + set x0-x5 +
branch to the virtual entry.

### Watchdog fix (done): rootserver pets IWDG1
`multikernel_hello/rootserver/main.c` `pet_watchdog()` (OP-TEE SMC 0xbc000000/PET via
`seL4_CapSMC`) called each tick loop ⇒ board no longer resets at 32s. Any core running the
rootserver pets.

### Stage 2a (built): "core1 alive" stub in K1's region
Foundation before the full trampoline + delivers visible [K1] console + watchdog. Elfloader
`multikernel.c` stages a position-independent stub (`mk_core1_stub_start/end`) at
`k_phys_start + 0x400000` (= 0x98400000, surviving). Rootserver wakes core 1 there. Stub runs
NS/MMU-off: prints "[K1] core1 ALIVE via trampoline stub", loops petting IWDG1 (raw smc) +
'.' heartbeat. Image: build-ccwmp25-mk-hello-k0-loadonly. Validates core 1 executes surviving
NS code from K1's region (UART + SMC) with no firewall fault. Next: Stage 2b = build K1 boot
page tables + enable MMU + jump to K1 kernel virt entry (generalize multikernel_secondary_startup).

## Resolution direction (see plan)

- The faulting bank is TF-A's, **never** to be opened to non-secure. Fix = remove the
  stray privileged-NS access (seL4-side, this fork).
- The eventual **kernel ↔ M33 RPMSG** need targets a *different* bank (`cm33_sram1/2` /
  `cm33_retram`, RISAB3/4/5) — prefer a shared DDR carveout (no firewall change); only if
  on-chip SRAM is mandatory, open that specific M33 bank to one kernel's CID in OP-TEE.

## References

- OP-TEE (read-only): `core/arch/arm/dts/{stm32mp251.dtsi,ccmp25-dvk-rif.dtsi,ccmp25-dvk-resmem.dtsi}`,
  `core/drivers/firewall/{stm32_risab.c,stm32_iac.c}`.
- seL4 (editable): `tools/seL4/elfloader-tool/src/arch-arm/{multikernel.c,sys_boot.c}`,
  `tools/seL4/elfloader-tool/src/arch-arm/64/{mmu.c,multikernel_trampoline.S}`,
  `projects/sel4_ccwmp25/multikernel_hello/{settings.cmake,build-stm32mp25x.sh}`.
