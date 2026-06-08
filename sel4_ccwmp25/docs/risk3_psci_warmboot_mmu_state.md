# Risk 3 Analysis — PSCI Warm-Boot MMU State vs seL4 Kernel Entry Expectations

**Result: REAL but MANAGEABLE. Existing elfloader SMP pattern already solves it; we adapt for multikernel.**

Code-only analysis 2026-05-04. No hardware test required — pure read of seL4
ARM `head.S` + TF-A PSCI exit code.

## The concern (per Slack risk review)

If TF-A's PSCI `CPU_ON` warm boot leaves NS-EL1/2 with MMU off, and seL4's
ARM kernel `_start` assumes MMU is already configured (because the elfloader
normally does that before jumping in), then PSCI'ing CPU1 directly to
`kernel_1`'s `_start` will fault on first instruction with no diagnostic
output ("core 1 never prints anything").

## What seL4's ARM `_start` actually expects

`kernel/src/arch/arm/64/head.S:79-147`:

```asm
BEGIN_FUNC(_start)
    msr daifset, #DAIFSET_MASK         /* mask all interrupts */
    msr spsel, #1
    mrs x4, SCTLR                       /* read SCTLR_EL1 or SCTLR_EL2 */
    ldr x19, =CR_BITS_SET               /* includes BIT(CONTROL_M) — MMU enable */
    ldr x20, =CR_BITS_CLEAR
    orr x4, x4, x19
    bic x4, x4, x20
    msr SCTLR, x4                       /* write SCTLR — enables MMU */
    /* ... stack setup, then call init_kernel(x0..x5) in C */
```

`CR_BITS_SET` (line 50-54) includes:
- `BIT(CONTROL_M)` — MMU enable
- `BIT(CONTROL_I)` — I-cache enable
- `BIT(CONTROL_C)` — D-cache enable

**The SCTLR write at line 94 enables the MMU.** This means seL4 `_start`
expects:
1. **TTBR0/1_EL1 (or TTBR_EL2) is already loaded** with valid page tables.
2. **Those page tables include at least an identity map covering the kernel
   image's physical address range** — otherwise the very next instruction
   fetch (at the kernel's physical PC, now translated through whatever the
   stale TTBR points at) faults.
3. MMU may currently be off; `_start` will turn it on.
4. `x0..x5` contain `init_kernel()` parameters (set by the elfloader normally).

Conclusion: **seL4 `_start` is NOT a self-contained entry point.** It assumes
the elfloader has already prepared page tables and loaded TTBR.

## What TF-A leaves at PSCI CPU_ON exit

`arm-trusted-firmware/lib/psci/psci_common.c:824-881` (`psci_get_ns_ep_info`,
AArch64 path):

```c
sctlr = ((ns_scr_el3 & SCR_HCE_BIT) != 0U) ?
    read_sctlr_el2() : ns_sctlr_el1;
ee = 0;
ep_attr = NON_SECURE | EP_ST_DISABLE;
SET_PARAM_HEAD(ep, PARAM_EP, VERSION_1, ep_attr);

ep->pc = entrypoint;
zeromem(&ep->args, sizeof(ep->args));        /* x0-x7 zeroed */
ep->args.arg0 = context_id;                  /* x0 = context_id */

mode = ((ns_scr_el3 & SCR_HCE_BIT) != 0U) ? MODE_EL2 : MODE_EL1;
ep->spsr = SPSR_64((uint64_t)mode, MODE_SP_ELX, DISABLE_ALL_EXCEPTIONS);
```

When CPU1 enters NS via PSCI warm-boot:
- **PC = user-supplied `entrypoint`**
- **All x0-x7 zeroed except x0 = context_id** (the third arg to PSCI_CPU_ON)
- **SPSR sets EL1 or EL2 with all interrupts masked**
- **MMU/caches inherit current NS SCTLR state** — for a cold-booted CPU this is **OFF**
- **TTBRs are undefined from the NS perspective** (TF-A manages SECURE state only; NS state at entry is "whatever NS left it as", which for a never-before-running secondary CPU is uninitialized)

## The mismatch

| | seL4 `_start` expects | TF-A PSCI exit provides |
|---|---|---|
| MMU state | Either (page tables loaded so MMU enable is safe) | **OFF, no page tables** |
| TTBRs | Loaded with kernel-image identity map | **Undefined / zero** |
| x0..x5 (init_kernel args) | Boot params from elfloader | **Zeroed except x0 = context_id** |
| EL | EL1 or EL2 (matches build config) | EL1 or EL2 (matches build config) ✓ |
| Interrupts | Masked by `_start` first instruction | Masked ✓ |

**Direct PSCI CPU_ON → seL4 `_start` will fault immediately** — the SCTLR
write enables MMU with garbage TTBR and CPU1 dies silently.

## How the existing elfloader solves this for SMP

`tools/seL4/elfloader-tool/src/arch-arm/armv/armv8-a/64/smp.c` shows the
existing SMP boot pattern. The primary CPU:

1. Sets up identity-mapped page tables covering all of DRAM.
2. Computes per-core stacks.
3. PSCI CPU_ON's each secondary, with **`secondary_startup`** (an assembly
   stub in the elfloader, not seL4 `_start`) as the entry pointer.

Each secondary lands at `secondary_startup`, which:

1. Reads its position in `core_stacks[]` to derive its logical ID.
2. Loads TTBR with the page tables CPU0 prepared (shared by all cores).
3. Enables MMU.
4. Sets stack pointer.
5. Sets `tpidr_el1` to the logical core ID.
6. Jumps to seL4's `_start` (with MMU now on and valid TTBR).

For SMP, all cores share the same page tables and jump to the same kernel.

## How we adapt this for multikernel

Each core gets a **DIFFERENT** kernel and a **DIFFERENT** page-table set. The
existing pattern needs only a small change:

**Per-kernel trampoline.** For each kernel_N (N>0), the elfloader:

1. Sets up an identity-mapped page table for kernel_N's physical region
   (`0x98000000–0xA8000000` for kernel_1).
2. Stores the page-table base and kernel_N entry address in a small
   per-CPU descriptor.
3. PSCI CPU_ON's CPU N pointing at `multikernel_secondary_startup_N` (one
   trampoline per kernel, OR one trampoline that picks the kernel based on
   `MPIDR_EL1`).

The trampoline:
1. Loads TTBR with kernel_N's page tables.
2. Enables MMU.
3. Sets up `init_kernel()` args (x0..x5) for kernel_N's user image and DTB.
4. Jumps to kernel_N's `_start` (which is at kernel_N's physical base, NOW
   reachable because identity map covers that region).

This is a **modest extension of the existing elfloader SMP code**, not a
new design. The trampoline assembly is ~30 lines per kernel (or one
parameterized trampoline of similar size).

## Implications for Phase 1 design

The Phase 1 design's §4 (Boot sequence) currently says:

> "PSCI CPU_ON(target=cpu1, entry=0x98000000, ctx=0)"

This is **wrong**. It should be:

> "PSCI CPU_ON(target=cpu1, entry=&multikernel_secondary_startup_kernel_1, ctx=0)"
>
> where `multikernel_secondary_startup_kernel_1` is a small assembly stub in
> the elfloader that loads kernel_1's TTBR, enables MMU, sets init_kernel
> args, then jumps to `0x98000000` (kernel_1's physical entry).

Effort impact on Phase 1: **small** — adapting the existing
`secondary_startup` pattern. ~30 lines of assembly + a per-kernel descriptor
struct. No new mechanism, no new debugging surface beyond standard MMU setup.

## What would NOT have worked

Approaches that would have hit the silent-fault failure mode:

- **PSCI CPU_ON directly to seL4 `_start`**: TTBR garbage, MMU enable faults
- **Loading kernel_1 via the elfloader and just letting CPU1 wake into it
  without a trampoline**: same problem
- **Sharing kernel_0's page tables with kernel_1**: kernel_1's text would be
  in kernel_0's page tables but kernel_1 would still need its own state
  separation; messy

The trampoline approach is clean: each kernel gets its own page tables, the
elfloader sets them up before PSCI'ing the secondary CPU.

## Status

Risk 3: **CLOSED via design refinement.** Phase 1 design doc needs §4
update to reflect the trampoline. No hardware test needed — the analysis is
deterministic from reading the two code paths.
