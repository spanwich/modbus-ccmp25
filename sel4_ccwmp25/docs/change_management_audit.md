# Change Management Audit — STM32MP25x Platform Stubs

Date: 2026-03-10

## Summary of All Changes

### New Files (Platform Stubs)

| Repo | File | Type | Risk to other platforms |
|------|------|------|------------------------|
| util_libs | `libplatsupport/plat_include/stm32mp25x/platsupport/plat/clock.h` | New file | LOW — isolated in `stm32mp25x/` |
| util_libs | `libplatsupport/plat_include/stm32mp25x/platsupport/plat/serial.h` | New file | LOW — isolated in `stm32mp25x/` |
| util_libs | `libplatsupport/plat_include/stm32mp25x/platsupport/plat/i2c.h` | New file | LOW — isolated in `stm32mp25x/` |
| util_libs | `libplatsupport/src/plat/stm32mp25x/chardev.c` | New file | LOW — isolated in `stm32mp25x/` |
| global-components | `components/TimeServer/include/plat/stm32mp25x/plat/timers.h` | New file | LOW — isolated in `stm32mp25x/` |
| vm | `components/VM_Arm/plat_include/stm32mp25x/plat/vmlinux.h` | New file | LOW — isolated in `stm32mp25x/` |
| seL4_projects_libs | `libsel4vmmplatsupport/plat_include/stm32mp25x/sel4vmmplatsupport/plat/vpci.h` | New file | LOW — isolated in `stm32mp25x/` |
| seL4_projects_libs | `libsel4vmmplatsupport/plat_include/stm32mp25x/sel4vmmplatsupport/plat/device_map.h` | New file | LOW — isolated in `stm32mp25x/` |
| seL4_projects_libs | `libsel4vmmplatsupport/plat_include/stm32mp25x/sel4vmmplatsupport/plat/devices.h` | New file | LOW — isolated in `stm32mp25x/` |
| seL4_projects_libs | `libsel4vmmplatsupport/plat_include/stm32mp25x/sel4vmmplatsupport/plat/guest_vcpu_util.h` | New file | LOW — isolated in `stm32mp25x/` |

### Modified Files (Project)

| Repo | File | Change | Risk |
|------|------|--------|------|
| modbus_ccmp25 | `settings.cmake` | Added `set(LibUSB OFF)` | N/A — project only |
| modbus_ccmp25 | `stm32mp25x/devices.camkes` | Fixed GICV addr, console, DTB path | N/A — project only |
| modbus_ccmp25 | `linux/stm32mp25x-guest.dts` | Added `aliases { serial0 = &usart2; }` | N/A — project only |
| modbus_ccmp25 | `plat_include/stm32mp25x/plat/vmlinux.h` | Removed `/arm-pmu` from keep_devices | N/A — project only |
| modbus_ccmp25 | `CLAUDE.md` | Updated elfloader BSS line, added doc refs | N/A — project only |

### Untracked Docs (modbus_ccmp25 — project only)

| File | Purpose |
|------|---------|
| `docs/alignment_report_20260305.md` | Instructions vs codebase verification |
| `docs/elfloader_bss_investigation.md` | AArch64 uImage BSS bug analysis |
| `docs/gap_analysis_20260302.md` | Implementation readiness assessment |
| `docs/rifsc_dwmac_investigation.md` | RIFSC/DWMAC access analysis |
| `docs/rifsc_dwmac_evidence/` | Supporting evidence files (4 files) |

### Pre-existing Changes (NOT from this session)

| Repo | File | Notes |
|------|------|-------|
| util_libs | `libethdrivers/src/plat/pc99/intel.c` | 1-line pre-existing change, unrelated |
| global-components | `components/TimeServer/include/plat/bcm2837/` | Pre-existing from BCM2837 project |
| semperos-sel4 | 8 modified files + 1 untracked doc | Separate project, unrelated |
| http_gateway_x86 | 2 untracked docs | Separate project, unrelated |

---

## File Content Assessment

### clock.h (util_libs)
- **Purpose**: Empty clock enum stub — clocks managed via OP-TEE SCMI
- **Quality**: Correct minimal stub, byte-for-byte identical to qemu-arm-virt (modulo copyright)
- **Hardcoded values**: NONE (empty enum, just sentinel values)
- **Suitable for upstream**: YES — follows exact upstream pattern

### serial.h (util_libs)
- **Purpose**: Defines USART2 PADDR, IRQ, and chardev_id enum
- **Quality**: Correct, follows qemu-arm-virt pattern exactly
- **Hardcoded values**: `USART2_PADDR=0x400e0000`, `USART2_IRQ=(115+32)` — both correct per STM32MP25x TRM
- **Suitable for upstream**: YES — standard platform serial header

### i2c.h (util_libs)
- **Purpose**: Empty I2C enum stub (no I2C needed)
- **Quality**: Correct, identical to qemu-arm-virt
- **Hardcoded values**: NONE
- **Suitable for upstream**: YES

### chardev.c (util_libs)
- **Purpose**: Stub `ps_cdev_init()` that returns NULL — no native serial driver
- **Quality**: Correct and intentional. VM uses passthrough; native uses `seL4_DebugPutChar`
- **Hardcoded values**: NONE (returns NULL unconditionally)
- **Suitable for upstream**: YES, with caveat — a real STM32H7 UART driver could be added later. The NULL stub is functionally correct for now and is the minimum required to link.

### timers.h (global-components)
- **Purpose**: CAmkES timer component definition using ARM generic timer
- **Quality**: Correct, byte-for-byte identical to qemu-arm-virt
- **Hardcoded values**: `irq_irq_number=30` — correct for ARMv8 non-secure physical timer PPI 14 (= HW IRQ 30 on GICv2)
- **Suitable for upstream**: YES

### vmlinux.h (vm — VM_Arm)
- **Purpose**: Platform VMM config — passthrough IRQs, GIC path, DTB keep-devices
- **Quality**: Correct, well-documented, follows upstream pattern
- **Hardcoded values**: `GIC_NODE_PATH="/intc@4ac00000"`, `linux_pt_irqs={147,162}`, `free_plat_interrupts={82}`, `plat_keep_devices={"/timer","/psci"}` — all verified correct
- **Suitable for upstream**: YES — standard per-platform vmlinux.h
- **NOTE**: Duplicate of `modbus_ccmp25/plat_include/stm32mp25x/plat/vmlinux.h`. Both are needed: the VM_Arm copy is used by the C compiler (hardcoded include path in `arm_vm_helpers.cmake:98`), while the modbus_ccmp25 copy is used by the CAmkES CPP parser (via `cpp_includes` in `CMakeLists.txt:177`). The files are identical.

### vpci.h (seL4_projects_libs)
- **Purpose**: PCI region definitions — all zeroed because STM32MP25x has no PCIe
- **Quality**: Correct. Defines all required macros. `VmPCISupport` is OFF for this platform
- **Hardcoded values**: All PCI addresses/sizes = 0. `GIC_ADDRESS_CELLS=0x2` (correct for GICv2)
- **Suitable for upstream**: YES

### device_map.h (seL4_projects_libs)
- **Purpose**: Empty stub (same as qemu-arm-virt)
- **Quality**: Correct
- **Hardcoded values**: NONE
- **Suitable for upstream**: YES

### devices.h (seL4_projects_libs)
- **Purpose**: Empty stub (same as qemu-arm-virt)
- **Quality**: Correct
- **Hardcoded values**: NONE
- **Suitable for upstream**: YES

### guest_vcpu_util.h (seL4_projects_libs)
- **Purpose**: Defines `PLAT_CPU_COMPAT` string for DT CPU nodes
- **Quality**: Correct, `"arm,cortex-a35"` matches STM32MP255 (dual Cortex-A35)
- **Hardcoded values**: `"arm,cortex-a35"` — correct
- **Suitable for upstream**: YES
- **Minor note**: Missing `#pragma once`, but this matches the qemu-arm-virt reference. Benign since it only defines a macro.

---

## Repo Strategy

### 1. `projects/util_libs` — 4 new files
- **Remote**: `seL4` → `https://github.com/seL4/util_libs.git`
- **Current state**: Detached HEAD at `1ba6640`
- **Push access**: NO (upstream seL4)
- **Recommended strategy**: **[C] Keep as local patch**
  - These files are in `plat_include/stm32mp25x/` and `src/plat/stm32mp25x/` — standard platform directories
  - Cannot push to upstream seL4 without a PR, and STM32MP25x is not an official seL4 platform
  - Changes are self-contained in `stm32mp25x/` dirs and will not conflict with upstream updates
  - **Risk of loss on `git submodule update`**: YES — detached HEAD, untracked files would survive a `submodule update` but could be lost on a `submodule update --force` or if the worktree is cleaned
  - **Mitigation**: Create a local branch to track these changes, or maintain as a patch set

### 2. `projects/global-components` — 1 new file
- **Remote**: `seL4` → `https://github.com/seL4/global-components.git`
- **Current state**: Detached HEAD at `e4fbff8`
- **Push access**: NO (upstream seL4)
- **Recommended strategy**: **[C] Keep as local patch**
  - Same rationale as util_libs
  - Single file in `plat/stm32mp25x/` — no conflict risk

### 3. `projects/vm` — 1 new file
- **Remote**: `spanwich` → `git@github.com:spanwich/camkes-vm.git`
- **Current state**: Detached HEAD
- **Push access**: YES (personal fork)
- **Recommended strategy**: **[A] Commit to a new branch `stm32mp25x-platform`**
  - Personal fork, full push access
  - vmlinux.h is the critical platform file for VM boot
  - Should be on a named branch for tracking

### 4. `projects/seL4_projects_libs` — 4 new files
- **Remote**: `spanwich` → `git@github.com:spanwich/seL4_projects_libs.git`
- **Current state**: Detached HEAD at `dd48a3d` ("feat(vgic): add STM32MP25x GIC addresses")
- **Push access**: YES (personal fork)
- **Recommended strategy**: **[B] Commit to existing platform branch (at dd48a3d)**
  - Already has one STM32MP25x commit (GICv2 addresses)
  - These 4 files are the next logical addition for VM support
  - Should be committed on top of `dd48a3d`

### 5. `projects/modbus_ccmp25` — 5 modified + 8 untracked
- **Remote**: `spanwich` → `git@github.com:spanwich/modbus-ccmp25.git`
- **Current state**: `master`, 4 commits ahead of `origin/master`
- **Push access**: YES (personal fork)
- **Recommended strategy**: **[B] Commit to master branch, then push**
  - All changes are project-specific (no cross-platform risk)
  - Modified files: bug fixes (GICV addr, console, DTS aliases, LibUSB)
  - Untracked docs: investigation artifacts (should be committed)

---

## Duplicate File: vmlinux.h

Two identical copies exist:
1. `projects/vm/components/VM_Arm/plat_include/stm32mp25x/plat/vmlinux.h`
2. `projects/modbus_ccmp25/plat_include/stm32mp25x/plat/vmlinux.h`

**Why both are needed**:
- Copy 1 (VM_Arm): Used by the C compiler. The `DeclareCAmkESARMVM()` macro in `arm_vm_helpers.cmake:98` hardcodes `VM_Arm/plat_include/${KernelPlatform}` as the include path for the VM component. Cannot be overridden without modifying the upstream cmake.
- Copy 2 (modbus_ccmp25): Used by the CAmkES parser. Passed via `cpp_includes` in `CMakeLists.txt:177` for CAmkES CPP preprocessing.

**Risk**: If one copy is updated and the other is not, inconsistent behavior between CAmkES parsing and C compilation. Both copies must stay in sync.

**Long-term fix**: Modify `arm_vm_helpers.cmake` to accept an additional include path (e.g., via `EXTRA_INCLUDES` passthrough), or upstream the vmlinux.h to the `vm` repo.

---

## Linux Image Build Artifacts

- `linux-Image` (27 MB): **gitignored** via `linux/.gitignore`
- `rootfs.cpio.gz` (1.6 MB): **gitignored** via `linux/.gitignore`
- `linux-dtb`: **gitignored** (compiled at build time from `stm32mp25x-guest.dts`)
- `yocto-linux/`: **gitignored** (kernel source submodule)

**Status**: Correctly handled. Build process is documented in `CLAUDE.md` and `docs/build-readiness-analysis.md`. Kernel was built from Digi `ccmp2_defconfig` (v6.6.78). Rootfs was built from archived BusyBox output.

---

## Risk Assessment

### Changes that could break other platforms: NONE
- All 11 new files are in `stm32mp25x/` platform-specific subdirectories
- No shared code, cmake files, or build system changes reference `stm32mp25x` outside these directories
- The cmake auto-discovery uses `${KernelPlatform}` GLOB patterns, so `stm32mp25x/` files are only included when building for that platform

### Changes that would be lost on submodule update

| Repo | Files at risk | Likelihood | Impact |
|------|---------------|------------|--------|
| util_libs | 4 files (3 headers + chardev.c) | MEDIUM — `git submodule update` preserves untracked, but `--force` or reclone loses them | BUILD FAILURE |
| global-components | 1 file (timers.h) | MEDIUM — same as above | BUILD FAILURE |
| vm | 1 file (vmlinux.h) | LOW — personal fork, will be on named branch | BUILD FAILURE |
| seL4_projects_libs | 4 files | LOW — personal fork, will be committed | BUILD FAILURE |

### Changes that should NOT be in upstream repos: NONE
- All stubs follow the exact upstream per-platform pattern
- All are correct minimal implementations for STM32MP25x
- If STM32MP25x were ever an official seL4 platform, all of these would be upstreamed via PR

---

## Recommended Immediate Actions (before hardware boot)

Priority order:

1. **Commit modbus_ccmp25 changes to `master`** — All 5 modified files and 8 untracked docs are project-specific bug fixes and investigation artifacts. No risk. Push to `origin/master`.

2. **Commit seL4_projects_libs stubs on top of `dd48a3d`** — Personal fork, has push access. Create a named branch from the detached HEAD, commit the 4 new headers, push. This preserves the GICv2 fix + VMM stubs together.

3. **Commit vm vmlinux.h to a branch in personal fork** — Personal fork, has push access. Create `stm32mp25x-platform` branch, commit, push.

4. **Create local branches in util_libs and global-components** — Cannot push to upstream seL4, but creating local branches prevents loss:
   ```bash
   git -C projects/util_libs checkout -b stm32mp25x-platform
   git -C projects/util_libs add libplatsupport/plat_include/stm32mp25x/ libplatsupport/src/plat/stm32mp25x/
   git -C projects/util_libs commit -m "feat: add STM32MP25x platform stubs"

   git -C projects/global-components checkout -b stm32mp25x-platform
   git -C projects/global-components add components/TimeServer/include/plat/stm32mp25x/
   git -C projects/global-components commit -m "feat: add STM32MP25x TimeServer timer stub"
   ```

5. **Update `.gitmodules` or repo manifest** to pin util_libs and global-components to local branches (or document the patch requirement in CLAUDE.md).

## Recommended Long-term Actions (after Phase 2 is working)

1. **Eliminate vmlinux.h duplication** — Fork `camkes-vm` to add `EXTRA_PLAT_INCLUDES` support to `DeclareCAmkESARMVM()`, allowing project-level vmlinux.h to be used by both CAmkES parser and C compiler. Remove the VM_Arm copy.

2. **Fork util_libs and global-components** — Create `spanwich/util_libs` and `spanwich/global-components` forks on GitHub. Push the platform stubs there. Update `.gitmodules` to point to the forks.

3. **Implement STM32H7 UART driver** — Replace the NULL `chardev.c` stub with a real driver for USART2 (st,stm32h7-uart). This enables native component serial output without `seL4_DebugPutChar`, which is important for production deployment.

4. **Consider upstream PRs** — If STM32MP25x gains traction in the seL4 community, submit PRs to `seL4/util_libs`, `seL4/global-components`, and `seL4/seL4_projects_libs` with these platform stubs. The code is clean and follows upstream patterns exactly.

5. **Create a reproducible build script for linux-Image and rootfs.cpio.gz** — Document the exact commands (defconfig, cross-compiler version, BusyBox config) so anyone can recreate the artifacts. Consider adding a `Makefile` target in `linux/`.
