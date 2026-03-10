# GAP ANALYSIS: seL4 DWMAC → Validator → VirtIO → Linux VM

**Date**: 2026-03-02
**Project**: modbus_ccmp25 / STM32MP255CAL (Digi CCMP25-DVK)

**Target Architecture**:
```
Physical NIC (eth0, DWMAC 5.10a @ 0x482C0000)
     │
     ▼
[seL4 EL2 - CAmkES]
  DWMAC_Driver component          ← NEW: needs full implementation
     │ dataport (ICS_Message)
     ▼
  ICS_Inbound component           ← EXISTS: loopback wiring only
     │ dataport (ICS_Message)
     ▼
  VirtIO_Net_Backend (VM_Arm)     ← EXISTS in VM library; needs VirtQueue wiring
     │ VirtQueue (shared memory + virtual IRQ)
     ▼
[Linux Guest - EL1]
  virtio-net driver (built-in)    ← EXISTS in kernel; needs DTB entry
     │
  eth0 (virtual) → Linux network stack

Outbound (reverse): Linux → VirtIO → ICS_Outbound → DWMAC_Driver → NIC
```

---

## COMPONENT STATUS TABLE

| Component | Status | Location | Blocking Issues |
|-----------|--------|----------|-----------------|
| DWMAC NIC Driver | **MISSING** | N/A | Full driver needed: MMIO init, DMA descriptors, MDIO/PHY, IRQ handler, frame TX/RX |
| ICS_Inbound Validator | **PARTIAL** | `components/ICS_Inbound/` | Works but wired in loopback; needs connection to DWMAC_Driver and VirtIO backend |
| ICS_Outbound Validator | **PARTIAL** | `components/ICS_Outbound/` | Same as ICS_Inbound — loopback only |
| VirtIO-net Backend | **EXISTS (in VM library)** | `projects/vm/components/VM_Arm/src/modules/virtio_net_virtqueue.c` | Emulated inside VM_Arm; needs VirtQueue connections wired in CAmkES assembly |
| Linux VM component | **PARTIAL** | `ics_vm_stm32mp25x.camkes` | VM shell exists; no VirtQueue connections, no VirtIO-net configuration |
| WatchdogKicker | **DONE** | `components/WatchdogKicker/` | Working: SMC to OP-TEE, 10s yield loop, priority 50 |
| Platform init (stm32mp25x) | **MISSING** | N/A | No `modules/plat/stm32mp25x/init.c`; may be optional for basic boot (QEMU works without one) |
| VCPUFault / timer trap handler | **DONE (in VM library)** | `libsel4vm/src/arch/arm/vm.c` | VM library handles VCPUFault via HSR dispatch; sysreg table lacks timer entries but EL1 timer access doesn't trap under hypervisor |
| VGICMaintenance handler | **DONE (in VM library)** | `libsel4vm/src/arch/arm/vm.c` | GICv2 VGIC implementation present |
| GIC platform addresses | **MISSING** | `libsel4vm/src/arch/arm/vgic/gicv2.h` | **BUILD BLOCKER**: `#error "Unsupported platform for GIC"` — no `CONFIG_PLAT_STM32MP25X` entry |
| devices.camkes (stm32mp25x) | **DONE** | `stm32mp25x/devices.camkes` | 256MB VM RAM, USART2/DWMAC passthrough, GICV mapped |
| Guest Linux kernel image | **MISSING** | `linux/linux-Image` | Must build from yocto-linux v6.6/digi branch |
| Guest rootfs / initrd | **MISSING** | `linux/rootfs.cpio.gz` | Must build BusyBox-based initrd |
| Guest DTB (DTS source) | **PARTIAL** | `linux/stm32mp25x-guest.dts` | Present but minimal; clock/DMA properties stripped — DWMAC probe may fail without clocks |
| CAmkES assembly (full arch) | **PARTIAL** | `ics_vm_stm32mp25x.camkes` | VM + native components exist but ICS validators are in loopback — no VirtQueue or DWMAC connections |
| Elfloader BSS fix | **MISSING (in current checkout)** | `tools/seL4/elfloader-tool/src/arch-arm/64/crt0.S` | Upstream elfloader; BSS not cleared for uImage. Fix exists but not in checked-out submodule |
| seL4 kernel platform | **EXISTS (in fork branch)** | `kernel` submodule, branch `spanwich/stm32mp25x-platform` | Platform files exist but kernel HEAD is on `spanwich/master` — must switch branches for stm32mp25x builds |

---

## INTERFACE COMPATIBILITY ISSUES

### DWMAC_Driver → ICS_Inbound

- **Current ICS_Inbound input**: 64KB `seL4SharedData` dataport containing `InboundDataport` struct = `ICS_Message` (metadata + MODBUS TCP payload) + `control_queue`
- **DWMAC_Driver output must produce**: Parsed `ICS_Message` — the driver must extract Ethernet/IP/TCP headers, populate `FrameMetadata`, and place MODBUS TCP payload into `ICS_Message.payload[]`
- **Reference implementation**: `VirtIO_Net0_Driver` in `ics_dual_nic.camkes` does exactly this (lwIP-based TCP server on port 502, extracts MODBUS TCP payload)
- **Compatibility**: The DWMAC_Driver MUST replicate the `VirtIO_Net0_Driver` interface — same dataport layout, same `ICS_Message` format, same notification protocol
- **Key concern**: The DWMAC_Driver needs a full TCP/IP stack (lwIP) to parse TCP connections and extract MODBUS payloads. Raw Ethernet frames cannot be passed directly to ICS_Inbound.

### ICS_Inbound → VirtIO_Backend

- **Current ICS_Inbound output**: 64KB `seL4SharedData` dataport containing `InboundDataport` struct (same `ICS_Message` format)
- **VirtIO_Net_Backend input**: Raw Ethernet frames via VirtQueue shared memory (32KB default)
- **INCOMPATIBLE**: ICS_Inbound outputs pre-parsed `ICS_Message` (MODBUS TCP payload only), but VirtIO-net expects raw Ethernet frames
- **Resolution options**:
  1. **New component**: `VirtIO_Net1_Driver`-equivalent that reassembles raw frames from `ICS_Message` and injects via VirtQueue
  2. **Modified architecture**: Replace VirtIO-net with CrossVM dataport — pass `ICS_Message` directly to Linux via shared memory + custom Linux kernel module
  3. **Bypass validators for VM traffic**: Use VirtIO-net for Linux ↔ physical NIC (raw frames), place validators only on the DWMAC-facing path

### ICS_Outbound → DWMAC_Driver

- **Same as DWMAC_Driver → ICS_Inbound but reversed**: ICS_Outbound produces `OutboundDataport` (validated `ICS_Message`), DWMAC_Driver must reassemble TCP response and transmit
- **Compatible** if DWMAC_Driver implements `VirtIO_Net0_Driver`-equivalent receive path

### VirtIO_Backend → Linux VM

- **Mechanism**: `virtio_net_virtqueue.c` module inside VM_Arm bridges CAmkES VirtQueues to guest VirtIO PCI device
- **VirtQueue shared memory**: 32KB per direction (configurable)
- **Queue length**: 256 entries (configurable)
- **IRQ delivery**: Virtual SPI injected via VGIC; IRQ number from `vmlinux.h` free platform interrupts (currently IRQ 82 / SPI 50 available)
- **Guest DTS**: Needs VirtIO-net node (PCI or MMIO) for Linux to discover the virtual NIC; current guest DTS has physical DWMAC passthrough instead
- **Concern**: If the target architecture uses VirtIO-net to Linux (not DWMAC passthrough), the guest DTS must be changed to include a VirtIO device and remove the physical DWMAC node

### WatchdogKicker → OP-TEE

- **Fully working**: SMC `0xbc000000` with `x1=3` (SMCWD_PET), yield-loop timing, priority 50
- **No compatibility issues**

---

## CRITICAL PATH

Items in dependency order (each blocks everything below it):

1. **seL4 kernel on `stm32mp25x-platform` branch** — blocks: all stm32mp25x builds
   - Currently on `spanwich/master` (7dc04b9a); must switch to `spanwich/stm32mp25x-platform` (921de426)
   - Action: `git -C kernel checkout spanwich/stm32mp25x-platform`

2. **GIC addresses in `gicv2.h`** — blocks: VM component compilation
   - Add `CONFIG_PLAT_STM32MP25X` with `GIC_PADDR = 0x4ac00000` and ZynqMP-style offsets (+0x10000, +0x20000, +0x40000, +0x60000)
   - File: `projects/seL4_projects_libs/libsel4vm/src/arch/arm/vgic/gicv2.h`

3. **Elfloader BSS fix** — blocks: booting on real hardware
   - Upstream `crt0.S` doesn't clear BSS for uImage format
   - Either fork elfloader or patch locally

4. **Linux kernel image** — blocks: VM guest boot
   - Run `bash linux/setup-kernel.sh`, cross-compile, copy to `linux/linux-Image`

5. **Root filesystem** — blocks: VM guest boot
   - Build BusyBox-based initrd, place at `linux/rootfs.cpio.gz`

6. **Architecture decision: raw frames vs ICS_Message** — blocks: component design
   - Must decide whether validators operate on raw Ethernet frames (new design) or keep ICS_Message format (requires TCP/IP stack in DWMAC_Driver)

7. **DWMAC_Driver component** — blocks: physical NIC access
   - Full implementation: MMIO init, clock enable, PHY init (Marvell 88E1512 via MDIO), DMA descriptor rings, IRQ handler, frame TX/RX, lwIP TCP stack

8. **CAmkES assembly wiring** — blocks: end-to-end data flow
   - Wire DWMAC_Driver ↔ ICS_Inbound ↔ VirtIO backend ↔ VM
   - Wire reverse path: VM → ICS_Outbound → DWMAC_Driver

---

## ARCHITECTURAL DECISION REQUIRED

The target architecture has a fundamental interface mismatch. There are **three viable architectures**:

### Option A: Full NIC Driver + lwIP Stack (replicate QEMU model)

```
DWMAC_Driver (new, with lwIP + TCP server/client)
  → ICS_Inbound (existing, ICS_Message format)
    → VirtIO_Net1_Driver-equivalent (new, lwIP → VirtQueue raw frames)
      → VM_Arm virtio_net_virtqueue module (existing)
        → Linux guest virtio-net (existing)
```

- **Pros**: Validators stay unchanged; proven architecture from QEMU build
- **Cons**: Two lwIP instances; complex DWMAC_Driver; multiple frame copies; high effort

### Option B: DWMAC Passthrough to Linux VM (current devices.camkes approach)

```
Linux VM (owns DWMAC via passthrough at 0x482c0000)
  → CrossVM shared memory (raw MODBUS TCP data)
    → ICS_Inbound/Outbound (modified for raw-frame or CrossVM interface)
      → CrossVM shared memory back to Linux
```

- **Pros**: Linux kernel drives DWMAC (mature stmmac driver); simpler NIC bring-up
- **Cons**: Validators need modification; Linux is in the trust path for NIC access; cross-VM IPC overhead; need custom Linux kernel module for CrossVM

### Option C: Thin NIC Driver + Raw Frame Validators (redesign)

```
DWMAC_Driver (new, raw frame TX/RX only, no TCP stack)
  → ICS_Inbound (MODIFIED: raw Ethernet frame inspection, DPI on MODBUS TCP)
    → VM_Arm VirtQueue (raw frames → virtio-net)
      → Linux guest
```

- **Pros**: Minimal driver (no lwIP); single frame format throughout; lowest latency
- **Cons**: Validators must be rewritten for raw frame inspection; EverParse validation on raw bytes is harder; lose TCP connection state tracking

**Current project state implies Option A** (the QEMU build uses this exact model with VirtIO_Net0/Net1 drivers containing lwIP).

---

## ESTIMATED EFFORT TABLE

| Gap Item | Effort | Risk | Notes |
|----------|--------|------|-------|
| Switch kernel to stm32mp25x branch | S (minutes) | LOW | `git checkout spanwich/stm32mp25x-platform` |
| GIC addresses in gicv2.h | S (hours) | LOW | 6-line patch; ZynqMP offset model matches |
| Elfloader BSS fix | S (hours) | LOW | Patch crt0.S or fork elfloader |
| Linux kernel build | M (1-2 days) | MED | Yocto-linux cross-compile; clock tree issues possible |
| Rootfs build | S (hours) | LOW | BusyBox initrd; well-documented process |
| Guest DTS for VirtIO-net | S (hours) | LOW | Add VirtIO MMIO or PCI node; remove DWMAC passthrough if Option A |
| Platform init module | S (hours) | LOW | Optional; may not be needed for basic boot |
| DWMAC_Driver (Option A, with lwIP) | XL (3-4 weeks) | HIGH | Full NIC driver + lwIP integration; DMA, PHY, IRQ, clock management |
| DWMAC_Driver (Option C, raw frames) | L (1-2 weeks) | HIGH | Simpler but still substantial; DMA, PHY, IRQ |
| VirtIO_Net1_Driver equivalent | M (days) | MED | Adapt existing driver for VirtQueue ↔ ICS_Message bridge |
| CAmkES assembly wiring | M (days) | MED | VirtQueue connections, notification routing, memory sizing |
| Validator raw-frame adaptation (Option C) | L (1-2 weeks) | HIGH | Deep redesign of frame processing pipeline |
| DWMAC passthrough + CrossVM (Option B) | M (days) | MED | Simpler NIC path but needs custom Linux module |

S=hours, M=days, L=1-2 weeks, XL=2+ weeks

---

## WHAT IS WORKING NOW

Confirmed on real hardware (Digi CCMP25-DVK):

1. **seL4 boots on STM32MP25x** via U-Boot `bootm` (uImage format)
2. **WatchdogKicker pets IWDG1** via SMC to OP-TEE (prevents 32s hardware reset)
3. **ICS_Inbound + ICS_Outbound** validate MODBUS TCP with EverParse v3 parser (loopback mode)
4. **Deploy scripts** install/restore seL4 on eMMC from SD card
5. **RIFSC firewall** confirmed: ETH1/ETH2 are NSEC/NPRIV — seL4 at EL2 can access DWMAC directly

Confirmed on QEMU (full architecture):

6. **Dual-NIC gateway** with VirtIO_Net0_Driver (external) and VirtIO_Net1_Driver (internal)
7. **Bidirectional MODBUS validation** with EverParse + policy enforcement (CVE-2022-0367)
8. **150 concurrent TCP connections** with session tracking and connection state sharing
9. **Full data path**: SCADA → Net0 → ICS_Inbound → Net1 → PLC and reverse

---

## INVENTORY OF EXISTING REUSABLE COMPONENTS

| Component/File | Reuse Target | Adaptation Needed |
|----------------|-------------|-------------------|
| `VirtIO_Net0_Driver` (QEMU) | DWMAC_Driver frame format | Replace VirtIO MMIO with DWMAC MMIO; keep lwIP + ICS_Message production |
| `VirtIO_Net1_Driver` (QEMU) | VirtIO-net ↔ ICS_Message bridge | Replace VirtIO MMIO with VirtQueue interface; keep lwIP + ICS_Message consumption |
| `virtio_net_virtqueue.c` (VM library) | VM-side VirtIO backend | Wire VirtQueue connections in CAmkES assembly |
| `ICS_Inbound` / `ICS_Outbound` | Direct reuse | No changes needed if upstream/downstream use ICS_Message format |
| `common.h` (ICS_Message, FrameMetadata) | All components | Defines the dataport wire format |
| `modbus_policy.h` | Direct reuse | Runtime-configurable policy engine |
| `EverParse validators` | Direct reuse | Formally verified MODBUS TCP parser |
| `control_queue.h` | Direct reuse | Lock-free SPSC queue for close/error signals |
| `connection_state.h` | Direct reuse | Cross-component connection state sharing |
| `devices.camkes` | VM platform config | Already configured for DWMAC + USART2 passthrough |
| `vmlinux.h` | VMM platform header | Already has DWMAC IRQ passthrough |
| `stm32mp25x-guest.dts` | Guest DTS | Needs VirtIO-net node if not using DWMAC passthrough |
| `deploy/` scripts | Direct reuse | SD card install/restore for eMMC |

---

## RECOMMENDED NEXT ACTIONS (priority order)

1. **Fix build blockers** (S, hours) — Switch kernel to `spanwich/stm32mp25x-platform` branch; add STM32MP25x GIC addresses to `gicv2.h`; apply elfloader BSS fix. These are prerequisite for any VM build.

2. **Make architecture decision** — Choose between Option A (full NIC driver + lwIP, replicate QEMU model), Option B (DWMAC passthrough to Linux), or Option C (thin driver + raw frame validators). This decision shapes all subsequent work.

3. **Build Linux guest images** (M, days) — Clone yocto-linux, cross-compile kernel, build BusyBox rootfs. Required regardless of architecture choice.

4. **Boot Linux VM on STM32MP25x** (M, days) — Verify VM infrastructure works: VM_Arm + FileServer + guest kernel boot. This validates the GIC fix, VGIC, timer handling, and memory layout before adding networking.

5. **Implement DWMAC_Driver** (L-XL, 1-4 weeks) — Start with register verification (devmem2 from Linux for DWMAC version/features), then implement: clock enable → PHY init → DMA setup → simple TX/RX → IRQ → lwIP integration.

6. **Wire VirtIO-net to VM** (M, days) — Add VirtQueue connections between ICS validators and VM_Arm's `virtio_net_virtqueue` module. Update guest DTS with VirtIO-net node.

7. **End-to-end integration test** (M, days) — Full bidirectional path: physical NIC → DWMAC_Driver → ICS_Inbound → VirtIO → Linux VM → VirtIO → ICS_Outbound → DWMAC_Driver → physical NIC.

---

## APPENDIX: Three CAmkES Assemblies Compared

| Feature | `ics_dual_nic.camkes` (QEMU) | `ics_stm32mp25x.camkes` (native) | `ics_vm_stm32mp25x.camkes` (VM) |
|---------|-----|-----|-----|
| Platform | qemu-arm-virt | stm32mp25x | stm32mp25x |
| Components | 6 (2 HW + 2 Net + 2 ICS) | 3 (WDT + 2 ICS) | 5+ (VM + FS + WDT + 2 ICS) |
| Connections | 14 | 4 (loopback) | 5 (loopback + VM DTB) |
| NIC driver | VirtIO_Net0/Net1 (lwIP) | None | None |
| VM guest | No | No | Yes (vm0) |
| DWMAC access | N/A | No | Passthrough to VM |
| VirtIO-net | No | No | Not wired |
| WatchdogKicker | No | Yes (SMC) | Yes (SMC) |
| Data flow | Bidirectional end-to-end | Loopback only | Loopback only |
| lwIP | Yes (2 instances) | No | No |
| EverParse | Yes | Yes | Yes |

## APPENDIX: Source File Inventory

### Source Trees
| Tree | Path | Status |
|------|------|--------|
| TF-A | `/home/iamfo470/phd/ccwmp255/arm-trusted-firmware/` | Present |
| U-Boot | `/home/iamfo470/phd/ccwmp255/u-boot/` | Present |
| Linux | `/home/iamfo470/phd/ccwmp255/linux/` | Present |
| OP-TEE | `/home/iamfo470/phd/ccwmp255/optee_os/` | Present |

### Key Kernel Fork Branches
| Branch | Contents |
|--------|----------|
| `spanwich/master` | Stock upstream seL4 kernel (current HEAD) |
| `spanwich/stm32mp25x-platform` | STM32MP25x platform support (config.cmake + DTS overlay) |
| `spanwich/phd-custom-changes` | Hypervisor memory mapping enhancements |
