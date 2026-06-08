# Risk 1 Validation — `KernelArmRamBase` Parameterizable on STM32MP25x

**Result: CLOSED. Both build-time and runtime confirmed.**

Validated 2026-05-04 on Digi CCMP25-DVK hardware via USB fastboot + minicom.

## Background

The Slack risk review on Phase 1 design (`seL4-multikernel-amp-chat` web session, 2026-05-04) identified as the highest-impact open question: *"`KernelArmRamBase` may not be parameterizable. If the STM32MP25x platform config hardcodes the kernel link address, you cannot build two kernels at different physical bases from the same source tree without patching the kernel — exactly what we're trying to avoid."*

If true, the Phase 1 design needs rethinking (would require maintaining a kernel fork divergence, or both kernels linked at the same VA with elfloader-managed phys-to-virt mappings).

## Test setup

- Edited `kernel/tools/dts/stm32mp25x.dts` `/memory` node:
  - **Baseline**: `memory@84000000 { reg = <0x0 0x84000000 0x0 0x36800000>; };` (870 MB at 0x84000000)
  - **Test**: `memory@98000000 { reg = <0x0 0x98000000 0x0 0x10000000>; };` (256 MB at 0x98000000)
- Built native `sel4_ccwmp25` image with the test DTS (TimeServer-dependent WatchdogKicker stashed for the test).
- Flashed via USB fastboot using `deploy/usb-deploy.sh`. UART monitored via minicom on `/dev/ttyACM1`.

## Build-time evidence

```
$ aarch64-linux-gnu-objdump -h kernel/kernel.elf
Idx Name          Size      VMA               LMA               File off  Algn
  0 .boot         00010000  0000008098000000  0000000098000000  00004000  2**4
  1 .text         00019124  0000008098010000  0000000098010000  00014000  2**7
  6 .boot.bss     000001a8  000000809803b000  000000009803b000  0003f000  2**3

$ aarch64-linux-gnu-readelf -h kernel/kernel.elf | grep Entry
  Entry point address:               0x8098000000
```

All sections shifted by exactly `0x14000000` (= `0x98000000 - 0x84000000`). No source-level patches required — the DTS `/memory` change propagates correctly through the seL4 build's `hardware_gen.py` to the link script.

## Runtime evidence (UART output)

```
Starting kernel ...
I[00000000988e0ee8:00000000986b1d30]
JKLMBootstrapping kernel
available phys memory regions: 1
  [98000000..a8000000)
reserved virt address space regions: 3
  [8098000000..809824e000)
  [809824e000..809824e631)
  [809824f000..8098688000)
Booting all finished, dropped to user space
[RT load_env]
[RT calling main]
main@main.c:2162 Starting CapDL Loader...
... (CapDL + ICS_Inbound + ICS_Outbound all started)
```

The kernel:
- Reported its `available phys memory regions` correctly as `[98000000..a8000000)` (matches the new 256 MB DTS region exactly)
- Mapped its virtual high-half at `0x80_98000000` (matches `0x80_00000000 + new physBase`)
- Completed full init (`Booting all finished, dropped to user space`)
- Successfully started the CapDL Loader and three CAmkES components (ICS_Inbound, ICS_Outbound, WatchdogKicker)

Note: the early addresses in the elfloader debug print (`0x988e0ee8`, `0x986b1d30`) are in the new 0x98… range, confirming the elfloader's relocation logic placed the kernel correctly.

## Implications

1. **Phase 1 elfloader changes can rely on the existing relocation logic.** The elfloader already reads each kernel ELF's link address and copies the ELF to that physical address. We don't need to invent a new relocation mechanism for two-kernel builds.
2. **Two parallel kernel builds (kernel_0 at 0x84000000, kernel_1 at 0x98000000) are mechanically straightforward.** Each build uses a different DTS `/memory` node; the kernel link addresses propagate automatically.
3. **Bonus signal on Risk 2** (kernel touches memory outside its declared `/memory` during init): no observed faults; kernel allocated only from the declared 256 MB region. Strong indication Risk 2 is also low — though the test didn't stress allocate-heavy paths.

## Cleanup

- DTS reverted to baseline (md5 verified)
- Stashed WatchdogKicker.c TimeServer changes restored (user's pending work preserved)
- Test build dir `build-ramtest` removed
