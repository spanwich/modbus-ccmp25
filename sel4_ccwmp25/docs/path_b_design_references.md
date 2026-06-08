# Path B Design References — Multikernel-AMP for STM32MP25x

Notes from surveying public multikernel/multi-instance work on seL4. Captured
**before** writing our own implementation so the design draws on what's known
without inheriting broken code. Path B = build the multikernel infrastructure
ourselves on vanilla seL4, treating these as design reference only.

## References surveyed

### Kent McLeod / Kry10 (2022 — "Multiprocessing on seL4 with verified kernels")
- **Architecture:** Static partitioned multikernel — N independent unicore
  kernel instances, one per core. Each kernel manages its own memory
  partition. Cross-kernel comms via shared device-untyped frames + IPIs.
- **Build artifacts:** `Kernel.0.elf`, `Capdl.0.img`, `Kernel.1.elf`,
  `Capdl.1.img` → bundled into a single `Elfloader.img`.
- **Boot sequence:** Early bootloaders → elfloader → Kernel.0 init → Capdl.0
  init → System 0; in parallel core-1 elfloader → Kernel.1 init → ... → System
  1.
- **CAmkES extension:** `component Kernel node0;` declarations with
  `node_id`/`memory`/`reserved`/`shared_pool` attributes.
- **Public branch state (audit 2026-05-04):** `kent/multicore3` is effectively
  abandoned for public use. Bugs from the original 2022 multikernel commits
  remain unfixed (`elfloader_common.h:77` references undeclared
  `CONFIG_MAX_NUM_NODES`; `elfloader-tool/CMakeLists.txt:106` `config_set`
  call breaks for non-multikernel apps; `vm_multikernel_minimal` shipped with
  hardcoded `/tmp/tmp.3uICRi1C9y/...` developer path; CI workflows exist but
  none have ever run against `kent/multicore3`).
- **Useful as:** architecture blueprint, CAmkES syntax inspiration, lessons
  on what NOT to do (don't collide macro names between kernel and elfloader
  scopes, don't ship hardcoded paths, ensure the public branch builds from a
  clean checkout).

### Neutrality / Atoll (2025 Summit — "seL4 on Big Iron")
- **Architecture:** Same static multikernel model — per-kernel MMU + page
  tables + private frames, plus shared frames between kernels (slide 15).
- **Target:** x86 datacenter hardware with PCIe + IOMMU + SR-IOV. **Not
  directly applicable to STM32MP25x** (no PCIe, no SR-IOV, no IOMMU on the
  Cortex-A35 cluster — only an SMMU we don't currently use).
- **Code:** Not public. Commercial product.
- **Notable quote:** *"A clever build system makes things harder"* (slide 17)
  — direct critique of kent/Kry10's elaborate cmake/CAmkES tooling. Argues
  for simpler build machinery.
- **Cross-kernel cap transfer:** "Cap transfer is coming..." (slide 20) —
  acknowledged as future work; "duplicating caps is expensive". Implies
  current Atoll deployment also doesn't have arbitrary cap transfer.
- **Useful as:** validation that the static multikernel architecture is the
  agreed direction in the broader seL4 community; warning to keep the build
  system simple.

### Microkit (`seL4/microkit`)
- **Architecture:** Single-kernel, multi-Protection-Domain framework. PDs are
  isolated tasks within ONE seL4 kernel instance. **Not multikernel** —
  doesn't fit our use case directly.
- **IPC vocabulary:** ppcall (synchronous, low→high priority only),
  notifications (asynchronous), shared memory regions from untyped (lock-free
  ring buffers without kernel involvement in the data path).
- **Useful as:** vocabulary and API shape for the user-space layer we'll
  eventually build (Slack Phases 2-4). Microkit's notification + shared-region
  pattern translates directly to cross-kernel signalling once we add the IPI
  cap underneath.

### seL4 RFC 0170 — Multikernel IPI API
- **Status:** Implemented and merged into upstream seL4 master.
- **API:** New cap type — IPI/SGI signal cap. Created from `IRQControl`
  invocation with hardware-specific configuration. Invoked like a notification
  send cap. Receiver gets it as a regular IRQ on a bound notification.
- **GIC support:** GICv2 supports up to 8 cores via the SGI target list
  field; GICv3 supports broader affinity. **STM32MP25x uses GICv2** (verified)
  — 2 cores fits trivially.
- **Useful as:** the actual primitive we use for cross-core signalling. No
  custom kernel work required — just user-space code that creates and
  invokes the IPI cap.

## What this means for our Path B implementation

**Architecture is settled** (consensus across kent + Atoll):
- Static memory partition per kernel via DTS
- Each kernel is unicore-verified; no kernel modifications
- Shared frames + IPI cap for cross-kernel coordination
- User-space orchestration layer ("distributed kernel") on top

**No working public reference exists** for the *implementation* of:
- Elfloader that loads N kernel ELFs into disjoint memory regions
- Per-kernel build orchestration (separate kernel ELFs from one source tree)
- Per-kernel CapDL spec generation
- Cross-kernel CAmkES connectors (Microkit-style PDs/notifications across
  kernels)

These pieces we build ourselves, on vanilla seL4 master.

## Implementation surface for Phase 1 (boot two kernels, print loop)

Minimum viable to get UART output from both A35 cores:

1. **Two parallel kernel builds** — each with its own DTS that declares a
   disjoint `/memory` region. Two `seL4-N.elf` artefacts. *Mechanism:* two
   cmake `ExternalProject_Add` invocations or two separate build directories
   merged into one final image.
2. **Elfloader modified to load both** — pack 2 kernel ELFs + 2 minimal
   rootserver ELFs into the CPIO. On primary CPU: load both at their
   respective physical addresses, jump to kernel_0.
3. **Kernel_0's rootserver issues PSCI `CPU_ON` for CPU1** with
   `kernel_1_entry` as the entry pointer. (Existing seL4 elfloader's
   `psci_cpu_on` infrastructure already does this for SMP; we redirect the
   target.) PSCI `CPU_ON` validation on STM32MP25x TF-A is just `entrypoint
   >= STM32MP_DDR_BASE` (verified earlier — `bl31`/`stm32mp2_pm.c:1060`).
4. **Hand-rolled rootserver per kernel** (~80 lines C) — calls
   `seL4_DebugPutChar()` in a loop with a delay; prints `[K0] WDG kick N` for
   the watchdog-petting kernel and `[K1] tick N` for the other. UART
   contention at byte granularity is acceptable for the PoC (interleaved
   output proves both cores alive).
5. **WatchdogKicker stays on core 0** — kernel_0 keeps petting IWDG1 via SMC
   to OP-TEE every ~10 s (current behaviour, modified to print each kick).

## Out of scope for Phase 1 (deferred to later phases)

- IPI cap usage for cross-kernel signalling (Slack Phase 3)
- Shared-memory dataports between kernels (Slack Phase 2)
- User-space distributed-kernel coordinator (Slack Phase 4)
- CapDL multikernel spec generation (we'll hand-roll rootservers initially)
