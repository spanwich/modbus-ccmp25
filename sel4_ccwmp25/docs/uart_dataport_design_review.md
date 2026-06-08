# UART Dataport Design Review — `seL4-multikernel-amp-chat` Phase 1 Proposal

Investigation of the web-Claude proposal (Slack 2026-05-04 13:26): **core 0
owns UART exclusively, core 1 logs via shared-memory ring buffer dataport**.

The three configuration questions raised: (Q1) Cortex-A35 cache coherency
for shared atomics, (Q2) seL4 device-untyped frame sharing across two
separate kernels, (Q3) RIFSC enforcement on USART2 between two A35 cores.

**Verdict: all three check out. Proposal is technically sound.**

## Q1 — Cortex-A35 cluster cache coherency

**Confirmed: shared cacheable mappings work via implicit inner-shareable
coherency. No non-cacheable workaround needed.**

- `kernel/src/plat/stm32mp25x/config.cmake:36` declares `l2c_nop.c` — no
  external L2 cache controller. Cluster cache coherency is intrinsic to the
  Cortex-A35 cluster fabric (snoop control unit is built-in to the cluster).
- `kernel/libsel4/arch_include/arm/sel4/arch/types.h:29-31` defines
  `seL4_ARM_PageCacheable = 0x01` and `seL4_ARM_Default_VMAttributes = 0x03`
  (PageCacheable | ParityEnabled). Default frame mappings are **cacheable**.
- A35 cluster's coherency fabric handles snoop traffic between cores at L1
  granularity. `_Atomic uint32_t` (LDAR/STLR / LDXR/STXR pairs) on a
  cacheable inner-shareable mapping works correctly across both A35 cores
  without explicit cache maintenance.

**Implication:** The ring buffer design's `_Atomic` head/tail counters work
when both kernels map the shared frame with default attributes
(`seL4_ARM_Default_VMAttributes`). No need to introduce non-cacheable
mappings or explicit `dc cvac` / `dc ivac` cache ops in the ring code.

## Q2 — Cross-kernel device-untyped frame sharing

**Confirmed: each kernel independently creates device untypeds from its own
DTS. Same physical frame in both kernels' DTS → both rootservers get device
caps for it.**

- seL4's boot path (`kernel/src/kernel/boot.c:730` `create_untypeds_for_region`)
  iterates the kernel's view of physical memory regions. Anything NOT
  declared as `/memory` in that kernel's DTS becomes a device untyped exposed
  in `bi_frame->untypedList[]` (line 699).
- Each kernel runs `init_kernel()` independently, processes its own DTS,
  creates its own caps. **There's no cross-kernel coordination at the seL4
  layer** — kernels don't even know about each other.
- For the shared log ring: declare a 4 KiB device-memory region at
  `0xAC000000` in both `kernel_0`'s DTS and `kernel_1`'s DTS. Both
  rootservers will receive a device untyped for that physical address in
  their bootinfo. Each retypes it to a frame and maps it into its own VSpace.

**Implication:** The shared-frame mechanism works without any new kernel
plumbing. It's "do nothing special at the kernel level" — both kernels
naturally produce a cap for any region they're told is device memory.

## Q3 — RIFSC enforcement on USART2

**Confirmed: RIFSC has CID filtering DISABLED for USART2. Both A35 cores can
access it; isolation must come from seL4 capability model (DTS exclusion).**

From `optee_os/core/arch/arm/dts/ccmp25-dvk-rif.dtsi:47`:
```
RIFPROT(STM32MP25_RIFSC_USART2_ID, RIF_UNUSED, RIF_UNLOCK, RIF_NSEC,
        RIF_NPRIV, RIF_UNUSED, RIF_SEM_DIS, RIF_CFDIS)
```
Decoded: non-secure ✓, non-privileged ✓, **CID filtering disabled (`RIF_CFDIS`)**.
USART2 is "open" at the bus controller — any bus master, regardless of CID,
can read/write `0x400e0000`.

Compare with IWDG1 (per project's `rifsc_dwmac_investigation.md`):
`RIF_LOCK, RIF_SEC, RIF_PRIV, RIF_CID1, RIF_CFEN` — locked, secure,
privileged, CID1-only, CID filtering ENABLED. That's how IWDG actually
restricts access; UART has none of that protection.

**Implication:** The web-Claude proposal's reasoning is correct.
RIFSC cannot enforce isolation between two A35 cores both accessing
USART2 — they share the same bus-master CID and CID filtering is off
anyway. The only enforcement available is **the seL4 capability model**:
don't include the UART region in `kernel_1`'s DTS, kernel_1 never sees
a device untyped for it, and kernel_1's rootserver has no cap to map.

This is the canonical seL4 pattern for peripheral ownership. Capability
isolation is necessary and sufficient; RIFSC is at most defense-in-depth
(and on this board, even that's absent for UART).

## Adoption recommendation for Phase 1

The proposal is technically viable and pulls forward useful Phase 2
prerequisites. But it adds a second new mechanism (shared frame mapping +
ring buffer) on top of the already-new mechanism (multikernel boot). If we
do both at once and something fails, we can't distinguish "kernel boot
failed" from "shared mapping failed".

**Suggested split** — preserves the proposal's value, lowers debugging risk:

| Sub-phase | Goal | Mechanisms exercised | UART output |
|---|---|---|---|
| **Phase 1.0 — minimal proof of life** | Both kernels boot and prove they're alive | elfloader N-image + per-kernel DTS + PSCI CPU_ON + per-kernel trampoline | Both kernels write directly. **Accept garbled output.** Distinct prefixes (`[K0]`, `[K1]`) keep messages identifiable even when interleaved at byte level. |
| **Phase 1.1 — clean dataport output** | Validate shared frame + cross-kernel ring | Shared device untyped + dual-mapped frame + lockless ring buffer | Core 0 owns UART; core 1 writes to ring; core 0 polls and drains. |

Phase 1.0 is the "two kernels boot" success criterion. Phase 1.1 is "shared
memory works between two kernels" — exactly the Phase 2 prerequisite the
proposal correctly identifies.

Effort impact: still ~0.5 day for the ring buffer, but as a follow-on
rather than entangled with boot debug. Total Phase 1 (1.0 + 1.1) remains
6-7 days.

**If Phase 1.0 fails**, garbled output still tells us which side(s) booted
— much better signal than silence from one side. **If Phase 1.1 fails**, we
know Phase 1.0 already worked (kernels boot fine), so the failure is
isolated to the shared-frame plumbing.

## Open question for the user

The proposal's `0xAC000000` shared-pool address conflicts mildly with the
Phase 1 design's `[0xAC000000 – 0xBA7FFFFF]` *reserved* shared pool (held
back for Phase 2 expansion). This is fine — we just allocate the first 4 KiB
of that pool now. Or pick a clearer non-overlapping address.

## Status

- Configuration audit: ✅ complete (all three Qs check out)
- Adoption: pending user decision on the Phase 1.0/1.1 split
- Phase 1 design doc §1, §3, §4, §5, §7, §9 will need updates either way
  (per the proposal's "Impact on Phase 1 design doc" list)
