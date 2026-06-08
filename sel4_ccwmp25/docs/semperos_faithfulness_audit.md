# SemperOS Faithfulness Audit — Multikernel-AMP SemperKernel layer

**Date:** 2026-05-07
**Scope:** Capability system only (transport/network already known to differ)
**Reference source:** `projects/semperos-sel4-ref/` @ `legacy/hille-baseline` `97f38b9`
**Our implementation:** `projects/vm-examples/apps/Arm/test_two_components/lib/vdtu/` + `components/ComponentC/component_c.c`

The 7-test pass we celebrated proves the cross-kernel transport + tree
revocation infrastructure works. This audit makes explicit what the
infrastructure does **not** yet do that the original SemperOS design
requires for a real distributed-capability OS.

---

## Item 1 — Permission bits on capabilities

### Original SemperOS
- **Storage:** Permissions are **packed into the low bits of `MsgObject::label`** (which `MemCapability` inherits and accesses via `MemCapability::perms()`).
  - `Capability.h:233-244` — `MemObject` constructor does `MsgObject(addr | perms, ...)` and `assert((addr & m3::KIF::Perm::RWX) == 0)` (address page-aligned ⇒ low bits free).
  - `Capability.h:332-340` — `MemCapability::addr() = obj->label & ~RWX`, `perms() = obj->label & RWX`.
- **Bit layout:** `KIF.h:43-49` — `R=1, W=2, X=4, RW=3, RWX=7`. Three bits.
- **Enforcement sites:**
  - **Use → `createmap` syscall** (`SyscallHandler.cc:518`): `if(perms & ~mcapobj->perms()) SYS_ERROR("Invalid permissions")`. The page-table mapping cannot grant rights that the source memory cap doesn't have.
  - **Derivation → `derivemem` syscall** (`SyscallHandler.cc:711`): `perms & srccap->perms()` — child's perms are bitwise-ANDed with parent's. Monotonic restriction baked in (see also Item 10).
  - **Validation:** `SyscallHandler.cc:672, 704` — `(perms & ~RWX)` rejects unknown bits; `perms == 0` rejected for `reqmem`.
- **Activation:** `do_activate` (`SyscallHandler.cc:81-100`) does NOT check perms — perms enforcement happens at *use* time (createmap) and at *derivation* (derivemem). Activation is permission-blind because activation is "wire this cap into EP register so it actually fires"; the cap's perms travel with it.

### Our Implementation
- **Status:** Partial — field exists, NEVER enforced.
- **What we have:** `struct mk_cap.perms` (uint16_t) in `captable.h:33`. `mk_cap_grant` accepts a `perms` argument and writes it into the OFFER message and the local placeholder. `handle_exchange_offer` writes it into the destination cap.
- **What's missing:** No comparison anywhere. A grant with `perms=0xFFFF` (or any value) is accepted unchanged. `mk_cap_grant` does not bitwise-AND with parent's perms during a derived grant. There is no use-time check because we have no `createmap`-equivalent (we don't have seL4 frame mapping in our model — the pool is mapped once at boot and ComponentC reads/writes it directly).

### Gap Assessment
- **Security impact:** **High**. A revoked-but-still-mapped scenario doesn't apply (we don't unmap), but: (a) any grantee can demand RWX on a cap that the donor only has R for, and (b) no mechanism exists to model "read-only delegated capability." This breaks the basic capability invariant.
- **Effort to implement:** ~1 day. Two changes: (1) in `mk_cap_grant` derived path, replace `perms` arg with `perms & parent_cap->perms`; (2) add a `mk_cap_check_perms(cap_id, requested)` helper used at the (currently absent) use-site. The use-site work depends on Items 5/9 (activation + EP state).

---

## Item 2 — Syscall interface

### Original SemperOS
- **Source:** `kernel/SyscallHandler.{h,cc}` (1 277 LOC total).
- **Dispatch:** `SyscallHandler::handle_message` reads a 1-byte `Operation` opcode from the inbound `GateIStream`, indexes into `_callbacks[op]` (member-function-pointer table), and invokes the handler.
- **Operation enum** (`base/KIF.h:55-76`): 18 ops total —
  | # | Op | Purpose |
  |---|---|---|
  | 0 | `PAGEFAULT` | DTU-emitted PF when handler unreachable |
  | 1 | `CREATESRV` | register a named service |
  | 2 | `CREATESESS` | open a session by service name |
  | 3 | `CREATESESSAT` | open at a specific selector |
  | 4 | `CREATEGATE` | create a SEND endpoint cap |
  | 5 | `CREATEVPE` | spawn a VPE |
  | 6 | `CREATEMAP` | install page-table mapping for a memory cap |
  | 7 | `ATTACHRB` | wire a receive buffer to an EP |
  | 8 | `DETACHRB` | tear down a receive buffer |
  | 9 | `EXCHANGE` | direct VPE↔VPE cap transfer |
  | 10 | `VPECTRL` | start/wait/stop a VPE |
  | 11 | `DELEGATE` | send-cap-to-server (via session) |
  | 12 | `OBTAIN` | get-cap-from-server (via session) |
  | 13 | `ACTIVATE` | bind a SEND/MEM cap to a local EP register |
  | 14 | `REQMEM` | allocate from MainMemory and create a MemCap |
  | 15 | `DERIVEMEM` | sub-region MemCap with restricted perms |
  | 16 | `REVOKE` | revoke a capability range |
  | 17 | `EXIT` | terminate VPE |
  | 18 | `NOOP` | benchmarking no-op |
- **Validation pattern:** every handler starts with `vpe->objcaps().get(sel, expected_type)` lookup, returns `INV_ARGS` on mismatch. Cross-kernel ops route through `MHTInstance::keyLocality()` to detect remote authority.

### Our Implementation
- **Status:** **Missing**. There is no syscall layer.
- **What we have:** Direct C function calls — `mk_cap_grant()`, `mk_cap_revoke()`, `mk_kc_ping()` — invoked by ComponentC code that lives in the *same* address space as the KernelcallHandler. There is no privilege boundary between "VPE" and "kernel" at all.
- **What's missing:** Every entry point a real distributed-capability OS would need: `createvpe`, `createsrv`, `createsess`, `createmap`, `attachrb`, `delegate`, `obtain`, `activate`, `vpectrl`, `exit`, `derivemem`, `reqmem`. We only have the equivalent of `EXCHANGE` (`mk_cap_grant`) and `REVOKE`. Of the 18 SemperOS syscalls we cover **2**.

### Gap Assessment
- **Security impact:** **Critical**. Without a syscall boundary, any code in the VPE component can modify the CapTable directly — there's no enforcement at all. The current passing tests are honest only because the test driver is the only client.
- **Effort to implement:** Large — multi-week. Real fix is: split ComponentC into `KernelcallHandler` (runs the dispatch + cap-table) and N `VPE` components, with a CAmkES `seL4RPC` interface for the syscall boundary. Each VPE talks to its kernel via that RPC; the kernel validates and routes to remote kernels via the existing ring protocol. This is a structural change.

---

## Item 3 — VPE-local capability selectors

### Original SemperOS
- **Selector:** `typedef capsel_t` (16-bit; `KIF.h:33` — `INV_SEL = 0xFFFF`).
- **Per-VPE table:** `VPE.h:222-223` — every `VPE` instance owns two `CapTable`s:
  - `_objcaps` (object capabilities — MEM, SEND, RECV, SESSION, SERVICE, VPE)
  - `_mapcaps` (map capabilities — MAP)
- **Lookup:** `vpe->objcaps().get(sel, expected_type)` (`SyscallHandler.cc` everywhere) returns the `Capability *` or null. The `CapTable` is a **Treap** keyed by `capsel_t` (`CapTable.h:149` — `m3::Treap<Capability> _caps`).
- **Cross-VPE access:** is mediated. `exchange` syscall takes `(tcap, own, other, obtain)` where `tcap` is a `VIRTPE` cap held by the caller — i.e. the caller must already possess a capability *naming* the target VPE. There's no global selector space; selectors are local to the holder.
- **Global cap-id:** `mht_key_t` is the *globally unique* identifier (encodes PE | VPE | type | sel — `Capability.h:67`, `CapTable::set` line 114 — `HashUtil::structured_hash(_id, _id, type, i)`). Used by the MHT for cross-kernel routing. The `mht_key_t` is **derived** from the local `(vpe_id, sel)`; it's not a separate handle.

### Our Implementation
- **Status:** **Missing**. We have no selector layer.
- **What we have:** Our `mk_cap_id_t` (also `PE | VPE | type | sel` — `protocol.h:27-38`) is the global key — but it's also the only handle. Every API call (`mk_cap_grant`, `mk_cap_revoke`) takes the global `mk_cap_id_t` directly. There is no per-VPE table — we have ONE flat `g_table[256]` (`captable.c:11`) per kernel.
- **What's missing:** Per-VPE isolation of cap namespaces. Today, our test code can construct `MK_CAP_ID(kid=0, vpe=2, MEM, sel=6)` from thin air and then look it up; a malicious VPE could enumerate every cap on the kernel.

### Gap Assessment
- **Security impact:** **Critical** (in any real system). The CapTable is global; any VPE can read any other VPE's caps by guessing the encoding. With one VPE per kernel (the current test driver), this is invisible — but the moment we have N VPEs per kernel, the gap is exploitable.
- **Effort to implement:** Medium — a few days. Add a `struct vpe { uint16_t vpe_id; struct mk_cap_table caps; ... }` and migrate `mk_captable_*` functions to take a `struct vpe *` first argument. The cap-id ↔ slot mapping stays the same, but lookups are scoped to the calling VPE's table. The hard part is the cross-kernel reverse map: when K1's handler receives an OFFER for `dst_vpe=1`, it has to find K1's local VPE struct for vpe=1; today there's no VPE registry.

---

## Item 4 — Capability types

### Original SemperOS
**Six** capability types (`Capability.h:51-58`):
| Bit | Const | Subclass | What it represents |
|---|---|---|---|
| 0x01 | `SERVICE` | `ServiceCapability` | A registered named service (the holder is the service provider) |
| 0x02 | `SESSION` | `SessionCapability` | An open session on a service (the holder is a client) |
| 0x04 | `MSG` | `MsgCapability` | A SEND endpoint — `(core, vpe, epid, label, credits)` |
| 0x08 | `MEM` | `MemCapability` (extends MsgCapability) | A memory region with perms |
| 0x10 | `MAP` | `MapCapability` | A page-table mapping — `(phys, attr)` |
| 0x20 | `VIRTPE` | `VPECapability` | Reference to a VPE for `vpectrl`/`exchange` targeting |

Each subclass has its own `revoke()` override (`Capability.h:175-177`). Side-objects: `MsgObject`, `MemObject`, `SessionObject` are reference-counted (`m3::RefCounted`) and can outlive their cap. `RECV_EP` is not a separate cap type in SemperOS — receive buffers are managed via `attachrb`/`detachrb` syscalls keyed by `(vpe, ep)` (`SyscallHandler.cc:542-585`), and "ownership" of the receive side is implicit in being the VPE that did `attachrb`.

### Our Implementation
- **Status:** **Partial — 2 of 6.**
- **What we have** (`protocol.h:41-46`):
  | Const | Used? | Notes |
  |---|---|---|
  | `MK_CAP_NONE = 0x0000` | sentinel | for "no parent" |
  | `MK_CAP_MEM = 0x0008` | YES | exercised by Tests 1-6 |
  | `MK_CAP_MSG = 0x0004` | declared | never created in tests |
- **What's missing:** SERVICE, SESSION, MAP, VIRTPE types entirely. Also missing: per-type `revoke()` polymorphism (our `do_revoke_subtree` is type-agnostic; no per-type teardown action like `MemObject::revokeAction()` for freeing memory).

### Gap Assessment
- **Security impact:** **High**, but *currently latent* — we don't have services/sessions/VPEs to protect. Without these types, the "distributed capability system" doesn't actually mediate distributed services; it only mediates memory frames.
- **Effort to implement:** Medium — ~3 days for the 4 missing types + per-type revoke hooks, given Items 2 and 3 land first.

---

## Item 5 — Capability activation

### Original SemperOS
**Two-phase model:**
1. **Phase 1 — Cap exists in CapTable** (after `creategate` / `derivemem` / `reqmem` / `obtain`): `MsgCapability` is in `vpe->objcaps()` but cannot fire messages yet. The field that records this is `MsgCapability::localepid = -1` (`Capability.h:314`).
2. **Phase 2 — Cap activated on a local EP**: `activate(epid, oldcap, newcap)` (`SyscallHandler.cc:998-1068`) calls `do_activate` (`:81-100`) which:
   - `vpe->xchg_ep(epid, oldcapobj, newcapobj)` — issues a DTU `config_send`/`config_mem`/`config_recv` to load the EP register on the target PE
   - `oldcapobj->localepid = -1; newcapobj->localepid = epid` — bookkeeping

Cross-kernel subtlety (`SyscallHandler.cc:1042-1062`): if the receive buffer for `newcapobj` lives on another kernel, the activate **blocks** the calling thread on a `Kernelcalls::recvBufisAttached` round-trip; activation is the moment we discover whether the receiver is ready to accept.

**Deactivation:** `activate(epid, oldcap, INV_SEL)` — passes only `oldcapobj` and clears the EP register.

### Our Implementation
- **Status:** **Missing**. Single-phase.
- **What we have:** `handle_exchange_offer` installs the cap directly into our flat CapTable. No notion of "installed but not yet usable." Use happens via direct memory access on the pool (we are the page-table-less analog because `seL4HardwareMMIO` already mapped the pool at boot).
- **What's missing:** The entire activation phase. If we ever introduce real per-VPE seL4 vspaces and seL4 endpoints, `mk_cap_activate(cap_id, target_ep)` would have to: (a) check perms (Item 1); (b) issue the seL4 cap copy from the kernelcall handler's CSpace into the VPE's CSpace at slot `target_ep`; (c) optionally do the cross-kernel "is the receive buffer attached" round-trip.

### Gap Assessment
- **Security impact:** **Medium** for now. With a single VPE per kernel and a pre-mapped pool, "activated" is a no-op concept. As soon as Item 2 (real syscalls) lands, we need this to control *when* a granted cap becomes usable.
- **Effort to implement:** ~3 days, gated on Item 2 (syscall boundary) — until we have a privilege barrier, there's nothing to "activate against."

---

## Item 6 — Session lifecycle

### Original SemperOS
- **Open:** `SyscallHandler::createsess` (`SyscallHandler.cc:229-376`):
  - VPE supplies `(target_vpe_cap, dst_sel, service_name)`.
  - Kernel looks up the service in `ServiceList` (local) or `RemoteServiceList` (remote).
  - For local: kernel `subscribe`s a callback on `vpe->service_gate()`, forwards the request to the service. Service replies with a `word_t sess` identifier. Kernel creates `SessionCapability` in target VPE's CapTable, **inheriting from the ServiceCapability** so revoking the service revokes all sessions.
  - For remote: round-trip via `Kernelcalls::createSessFwd` → service-side kernel → service → reply.
- **Resources:** `SessionObject` (`Capability.h:246-262`) — `{ servowned, ident, srv, srvID }`. Reference-counted.
- **Close:** `SessionObject::close()` triggered by `SessionCapability::revoke()`. Sends a CLOSE service-call to the service; service can clean up its per-session state.
- **Resource accounting:** `SendQueue::pending()` / `inflight()` for back-pressure on the service.

### Our Implementation
- **Status:** **Missing entirely.**
- **What we have:** Nothing. The architect explicitly said in the 2026-05-05 greenlight message: *"Strip network artifacts — no CryptoTransport, no DTUBridge, no Raft, no session lifecycle."*
- **What's missing:** All of the above. This is intentionally deferred per architect's direction, but the audit requires noting it.

### Gap Assessment
- **Security impact:** **Low** for the QEMU MVP. SemperOS sessions exist primarily so a service can attach per-client state; without sessions you can't have a real service architecture. The architect's plan presumably re-introduces this when an application demo lands.
- **Effort to implement:** Large — a real session lifecycle pulls in all of Items 1, 2, 3, 4, 7. Several weeks of work.

---

## Item 7 — Service directory

### Original SemperOS
- **Local registry:** `kernel/com/Services.h` — `ServiceList` (`:82-126`), a singleton `m3::SList<Service>` capped at `MAX_SERVICES = 32` (`:91`). Lookup by name with linear scan (`find()`).
- **Cross-kernel registry:** `RemoteServiceList` (`:128-177`) — same structure but tracks services on *other* kernels. Populated by `Coordinator::broadcastAnnounceSrv` (`SyscallHandler.cc:185`) when a local `createsrv` succeeds.
- **Service object** (`:34-80`): `{ vpe, sel, name, sgate (SendGate), queue (SendQueue), id (mht_key_t) }`.
- **Registration:** `createsrv` syscall (`SyscallHandler.cc:153-189`) — VPE provides the receive-EP it has already attached, kernel allocates a `Service`, broadcasts the announcement to peers.
- **Discovery:** `createsess` first checks local `ServiceList`, then `RemoteServiceList`, then blocks waiting for the service to register if neither has it (`PEManager::start_pending`).

### Our Implementation
- **Status:** **Missing entirely.**
- **What we have:** Nothing. Same architect's-direction reason as Item 6.
- **What's missing:** Service registration and lookup, name namespace, cross-kernel announcement.

### Gap Assessment
- **Security impact:** **Low** for QEMU MVP — no services to direct.
- **Effort to implement:** Medium-Large — a few weeks combined with Items 2, 4, 6.

---

## Item 8 — RevocationList (concurrent revocation)

### Original SemperOS
- **Source:** `kernel/cap/Revocations.{h,cc}` — `RevocationList` (`:68-164`) is a global open-addressing hash table of in-flight revocations, keyed by `mht_key_t cap_id`.
- **`Revocation` struct** (`:34-66`): `{ capID, parent, origin (root cap), awaitedResp (counter), tid (thread id of the root revoker), subscribers (SList<RevocationSub>) }`.
- **Subscriber pattern** (`Revocations.cc:25-60`):
  - When `revoke_rec` walks a child and finds it's *already mid-revocation* (`RevocationList::find(child_id)` returns non-null), the new revoker **subscribes** rather than duplicating: `childRevoke->subscribe(ongoing); ongoing->awaitedResp++;` (`CapTable.cc:172-179`).
  - When a revocation completes (its own `awaitedResp` hits 0), `notifySubscribers()` is called: each subscriber's `awaitedResp` decrements by 1, propagating cascades. The thread waiting on the *root* (where `tid != -1`) gets woken via `m3::ThreadManager::get().notify(tid)`.
- **Effect:** Two threads revoking overlapping subtrees converge — neither does the same work twice; both block on the same root completion.

### Our Implementation
- **Status:** **Missing.**
- **What we have:** `mk_kc_reply_slot[32]` (`kernelcall.c:48`) — a flat array of pending replies keyed by `req_id`. Sufficient for the *waiter* side (one slot per outstanding REVOKE_BATCH). Not a `Revocation` tracker.
- **What's missing:** No "in-progress revocation" registry. If two ComponentC threads call `mk_cap_revoke(same_cap_id)` simultaneously: both call `do_revoke_subtree` on the same subtree, both DFS-walk the same children, both send REVOKE_BATCHes for the same remote children, the second receives `find(...) < 0` (cap already removed) and returns 0. No crash, but: (a) double work, (b) the second revoker reports `removed=0` even though the first will report `removed=N` — the assertion in Test 2a/2b assumes single-revoker semantics.
- The bigger gap: we do not handle the case where revoke A is waiting on K1's FINISH and revoke B (different cap, same subtree) starts — there's no subscription, so B starts its own round-trip and may finish before A wakes.

### Gap Assessment
- **Security impact:** **Medium**. Concurrent revocation isn't a correctness hazard in our cooperative-thread model (revoke_walk runs to completion before yielding to the next worker). But the *liveness* property "concurrent revokers converge to a single round-trip" is violated, which under load wastes ring traffic and can deadlock if pending-slot capacity is exhausted.
- **Effort to implement:** ~3 days — port `RevocationList` (open-addressing hash, ~100 LOC), add `subscribe`/`notifySubscribers` semantics, integrate into `do_revoke_subtree` (check before sending REVOKE_BATCH; if a previous revocation is in flight for any of the same caps, subscribe instead).

---

## Item 9 — EP state machine

### Original SemperOS / Our Vendored Code
- **Source:** `lib/vdtu/include/multikernel/vdtu_ep_state.h` (vendored verbatim from SemperOS, F* extracted).
- **States** (`:28-31`): `UNCONFIGURED → CONFIGURED → ACTIVE → TERMINATED`. Monotonic forward transitions only; `TERMINATED` is absorbing.
- **Transition function** (`:51-75`): `vdtu_ep_state_transition(state*, next, blocked)` — gates `→ TERMINATED` on `blocked == true`. Verified properties: monotonic, terminated absorbing, only valid forward transitions.

### Original SemperOS Enforcement
- The state machine governs **EP lifecycle** during configuration, send/recv, and revocation. `vdtu_ring_send` at `:59-60` returns `-3` ("terminated") if the producer's view of the EP state is `TERMINATED`. The `blocked` gate represents the cache-ancestry check from the Raft canonical revocation log.

### Our Implementation
- **Status:** **Partial — vendored but barely used.**
- **What we have:** `vdtu_ring_init` (`vdtu_ring.c:30`) sets `ep_state = ACTIVE` directly (no state-machine transition; just a store-relaxed write). `vdtu_ring_send` (`:62`) checks `if(ep_state == TERMINATED) return -3`. The `vdtu_ep_state_transition` function is **never called** in our code — `grep -r vdtu_ep_state_transition lib/ components/` returns zero hits.
- **What's missing:** We never transition any EP through `UNCONFIGURED → CONFIGURED → ACTIVE`. We initialize directly to `ACTIVE`, skipping the cap-config moments where the state machine would be enforced. The verified `blocked` gate (which encodes "this EP's Raft ancestry has been revoked → it is safe to terminate") has no equivalent in our system.

### Gap Assessment
- **Security impact:** **Low** for QEMU MVP. The terminated check protects against use-after-revoke on the data plane; we get that bit. The intermediate states matter when EPs are configured by user-space (creategate → activate flow) and get revoked under concurrent use — none of which we model.
- **Effort to implement:** ~1 day to call `vdtu_ep_state_transition` in `vdtu_ring_init` (UNCONFIGURED→CONFIGURED→ACTIVE) and in revocation paths (ACTIVE→TERMINATED). The `blocked` gate stays vacuously true for now.

---

## Item 10 — Monotonic permission restriction

### Original SemperOS
- **Single explicit site:** `SyscallHandler::derivemem` (`SyscallHandler.cc:711`):
  ```cpp
  perms & srccap->perms()
  ```
  Bitwise-AND of requested perms with parent's perms — child can only have a *subset* of parent's bits. Combined with `(perms & ~RWX)` validation upstream (`:704`), this is the entire monotonic-restriction enforcement.
- **No restriction during pure delegation/exchange:** `do_exchange` (`:732-762`) calls `dsttab.obtain(dstcap, scapobj)` which clones via `MemCapability::clone()` (`Capability.h:343-349`) — a pure copy. The new cap has the same perms as the old. Restriction only happens via `derivemem`, which is a *separate* syscall that produces a sub-region with possibly-tighter perms.
- This is consistent with capability-system theory: delegation preserves rights; *derivation* restricts them. SemperOS conflates them only inside `derivemem`.

### Our Implementation
- **Status:** **Missing.**
- **What we have:** `mk_cap_grant` accepts `perms` as a parameter and writes it through unchanged. There is no parent-cap lookup at grant time; the caller decides.
- **What's missing:** During a derived grant (`parent_cap_id != MK_CAP_NONE`), we do not look up the parent cap's perms and AND with the requested ones. In Test 5, K1's derived grant of C2 from C1 *could* request RWX even if C1 only has R — we'd happily grant it.

### Gap Assessment
- **Security impact:** **High**. This is the canonical monotonicity invariant of capability systems. Every derived/delegated cap MUST have ⊆ parent perms. Our system can amplify rights silently.
- **Effort to implement:** **Trivial — ~30 minutes.** Inside `mk_cap_grant`, when `parent_cap_id != MK_CAP_NONE`, look up the parent (`mk_captable_find`), AND the requested perms with `parent->perms`, and use the result. One file, ~5 lines.

---

## Item 11 — Other features in original SemperOS, missing here

I scanned `kernel/` for every subsystem and listed what we have no analog for. (Scope is limited to the cap system; transport/Raft/network are intentionally excluded per audit instructions.)

| Subsystem | Where | Function | Our impl |
|---|---|---|---|
| **MainMemory allocator** | `mem/MainMemory.{h,cc}` | Tracks free/used DRAM regions per-PE; `reqmem` calls `MainMemory::allocate(size)` to get a fresh region | None — pool is statically allocated at boot |
| **AddrSpace** | `mem/AddrSpace.{h,cc}` | Manages a VPE's virtual address space + page-fault handler EP | None — pool is in ComponentC's CAmkES vspace, no per-VPE vspace |
| **PEManager** | `pes/PEManager.{h,cc}` | Tracks which VPE runs on which PE; `start_pending` resumes VPEs once their service deps land | None — VPE concept absent |
| **RecvBufs** | `com/RecvBufs.{h,cc}` | Per-PE receive-buffer registry; `attachrb`/`detachrb` syscalls; `is_attached`/`subscribe` for remote handshake during `activate` | None |
| **SendQueue** | `kernel/SendQueue.h` | Per-Service back-pressure with credit accounting | None — our control ring uses the vdtu credit field but never enforces |
| **WorkLoop** | `kernel/WorkLoop.{h,cc}` | The main dispatch loop with fault-handler subscription; lets multiple subsystems hook in | We have a single `handler_thread` poll loop (`kernelcall.c:355`) — no event-handler abstraction |
| **Coordinator** | `kernel/Coordinator.{h,cc}` | Multi-kernel membership: `broadcastAnnounceSrv`, `getKPE`, `kid()` lookup | We have MHT init, no `Coordinator` equivalent for membership changes (kernel join/leave) |
| **MHT (DDL)** | `kernel/ddl/MHTInstance.{h,cc}` + `ddl/MHTTypes.h` | Distributed Data Layer — cap-id ↔ `Capability *` global directory across kernels; `responsibleMember`, `keyLocality` | Our `mht.h/.c` only has `{ kid → control_ring_paddr, ep_pool_base, status }` — no directory of *capabilities*; cross-kernel cap routing relies on the `kid` field in `mk_cap_id_t` directly |
| **VPE struct** | `pes/VPE.{h,cc}` | The VPE concept itself (state, exit-cb, name, address space, two CapTables, ServiceList membership, exec) | None — ComponentC IS the only VPE per kernel, statically |
| **Cloning / Clone hierarchy** | `Capability::clone()` virtual | Each cap subclass implements `clone()` for the `obtain()` / `do_exchange` path | Not needed under our model — but means we lack proper subclass dispatch when cap types diverge |
| **Per-type `revoke()` action** | `MsgCapability::revoke()`, `MemCapability::revoke()`, `MemObject::revokeAction()`, `SessionCapability::revoke()`, `ServiceCapability::revoke()` | Each cap type has a teardown path: free DRAM (MemObject), close session, deregister service, etc. | Our `do_revoke_subtree` is type-agnostic — it just removes table entries |
| **CapTable reservations** | `CapTable::reserve(sel)` / `release(sel)` | A 2-phase delegation can reserve the destination slot before the source is decided | None |
| **CapRngDesc** | `base/util/CapRngDesc.h` | Range descriptor `(type, start, count)` lets one syscall touch a contiguous range of selectors | None — our API is per-cap |
| **Exit / cleanup paths** | `VPE::~VPE()`, `CapTable::~CapTable() → revoke_all()`, `RevocationList` stale cleanup (`CapTable.cc:34-48`) | When a VPE dies, all its caps revoke automatically; RevocationList prunes stale entries from killed waiters | None — we never destroy a VPE |
| **Fault handling** | `WorkLoop` fault subscription, `pagefault` syscall | DTU traps deliver to a kernel handler that consults `AddrSpace` for the PF gate | None — relevant only when we have user-space VPEs with their own vspaces |
| **Benchmarking** | `base/benchmark/capbench.h`, `CAP_BENCH_TRACE_*` | Cycle-accurate trace points around every cap op | None — we only have ring-message counters |

### Gap Assessment
- **Security impact:** Spread across **Critical → Low**. The biggest items here that the architect's list didn't explicitly call out:
  - **MHT-as-directory** vs our MHT-as-routing-table. SemperOS uses MHT as a *distributed cap directory* — given any `mht_key_t`, you can find the canonical `Capability *` regardless of which kernel owns it. Our MHT only knows where rings live.
  - **No VPE struct.** This is probably the single largest architectural gap. The architect's greenlight message said "VPE struct must be extensible" — but we never created the VPE struct. ComponentC plays the VPE role implicitly, with a hard-coded mapping `kid → 1 VPE`.
  - **No per-type revoke action.** MemObject's `revokeAction()` would free the underlying DRAM allocation; our flat removal doesn't free anything because nothing was allocated.

---

## Summary table

| Item | Original | Ours | Sec impact | Effort |
|---|---|---|---|---|
| 1. Permissions | Stored, enforced at `createmap`/`derivemem` | Stored, never enforced | **High** | ~1 day |
| 2. Syscall interface | 18 syscalls, RPC over GateIStream | None — direct C calls | **Critical** | Multi-week |
| 3. VPE-local selectors | Per-VPE `_objcaps`/`_mapcaps` Treap | Single global hash | **Critical** | ~3 days |
| 4. Cap types | 6 (SERVICE, SESSION, MSG, MEM, MAP, VIRTPE) | 2 (MEM, MSG declared) | **High** (latent) | ~3 days |
| 5. Activation | 2-phase via `activate` syscall | 1-phase (install on grant) | **Medium** | ~3 days, gated on Item 2 |
| 6. Sessions | `createsess`/SessionObject/close | None (per architect's strip) | **Low** for MVP | Weeks |
| 7. Service dir | `ServiceList`+`RemoteServiceList` | None (per architect's strip) | **Low** for MVP | Weeks |
| 8. RevocationList | In-progress hash + subscribers | Pending-slot only | **Medium** | ~3 days |
| 9. EP state machine | Vendored verbatim | Vendored but never invoked | **Low** | ~1 day |
| 10. Monotonic perms | `perms & parent->perms` in `derivemem` | Pass-through | **High** | ~30 min |
| 11. Other (VPE struct, MHT-as-directory, MainMemory, AddrSpace, RecvBufs, per-type revoke, …) | Full kernel infra | Largely absent | Mixed | Multi-month |

**Highest-ROI fixes** (by sec-impact-per-effort):
1. **Item 10** (monotonic perms) — 30 min for High-impact fix
2. **Item 1** (perm enforcement at use-time, once a use-site exists) — 1 day
3. **Item 9** (call the verified state-machine function we already have) — 1 day
4. **Item 8** (port RevocationList from existing code) — 3 days
5. **Item 3** (per-VPE CapTable scoping) — 3 days, unlocks Items 4/5

**Largest structural gaps** (require architectural decisions, not just code):
- Item 2 (syscall boundary) — needs a CAmkES split or a real VPE/kernel privilege model
- Item 11 → VPE struct as a first-class object — the architect's greenlight message asked for this and it's absent
- Item 11 → MHT-as-directory (vs routing-table-only)
