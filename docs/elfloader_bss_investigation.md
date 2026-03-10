# Elfloader BSS Clearing Investigation

**Date**: 2026-03-06
**Platform**: Digi CCMP25-DVK (STM32MP255CAL, dual Cortex-A35, AArch64)
**Purpose**: Determine definitively whether elfloader BSS is zeroed for uImage boots

## Executive Summary

**Verdict: MASKED**

BSS is NOT cleared by anyone for AArch64 uImage boots. The issue is currently
masked by two coincidences: (1) no UART driver exists for `st,stm32h7-uart`, and
(2) elfloader globals are written before read in the single-core boot path.
This is a latent bug that could manifest if the elfloader is modified.

---

## Q1: Does U-Boot bootm zero any memory before handoff?

**NO — U-Boot only copies image data and does cache maintenance.**

### Evidence

U-Boot `bootm` state machine (`/home/iamfo470/phd/ccwmp255/u-boot/boot/bootm.c`
lines 994-1129) progresses through these states:

| State | Function | Memory operations |
|-------|----------|-------------------|
| START | `bootm_start()` (line 259) | `memset(&images, 0, ...)` — clears internal struct only |
| LOADOS | `bootm_load_os()` (line 619) | `image_decomp()` — copies/decompresses image to load addr |
| RAMDISK | `boot_ramdisk_high()` | Relocates ramdisk, no zeroing |
| FDT | `boot_relocate_fdt()` | Relocates device tree, no zeroing |
| OS_PREP | `boot_prep_linux()` (line 218) | Sets up FDT, no zeroing |
| OS_GO | `boot_jump_linux()` (line 311) | `cleanup_before_linux()` → disable caches |

**`cleanup_before_linux()`** (`arch/arm/cpu/armv8/cpu.c` lines 38-73):
```c
int cleanup_before_linux(void)
{
    board_cleanup_before_linux();
    disable_interrupts();
    icache_disable();
    invalidate_icache_all();
    dcache_disable();
    invalidate_dcache_all();
    return 0;
}
```

Only cache/interrupt management. **No RAM zeroing.**

All `memset` calls in bootm files target only U-Boot's own `bootm_headers` and
`bootm_info` structs — never kernel/elfloader memory.

---

## Q2: Does the uImage format carry BSS size information?

**NO — legacy uImage header has no BSS field.**

### Evidence

`/home/iamfo470/phd/ccwmp255/u-boot/include/image.h` — `struct legacy_img_hdr`:

| Field | Purpose |
|-------|---------|
| `ih_magic` | Image magic number |
| `ih_hcrc` | Header CRC |
| `ih_time` | Timestamp |
| `ih_size` | Image data size (text+data only) |
| `ih_load` | Load address |
| `ih_ep` | Entry point |
| `ih_dcrc` | Data CRC |
| `ih_os` | OS type |
| `ih_arch` | Architecture |
| `ih_type` | Image type |
| `ih_comp` | Compression |
| `ih_name` | Image name |

No `ih_bss_size`, no `ih_bss_addr`. U-Boot has no way to know where or how
large the BSS section is.

---

## Q3: Where is elfloader BSS relative to the loaded image data?

**AFTER the loaded image data — U-Boot does not touch it.**

### Evidence

**Linker script** (`tools/seL4/elfloader-tool/src/linker.lds` lines 13-62):
```
SECTIONS {
    . = IMAGE_START_ADDR;
    _text = .;
    .text   { ... }         ← Loaded by U-Boot
    .rodata { ... }         ← Loaded by U-Boot (includes CPIO archive)
    .data   { ... }         ← Loaded by U-Boot
    .bss (NOLOAD) {         ← NOT in binary, NOT loaded
        core_stack_alloc    ← Stack (before _bss, not cleared by clear_bss)
        _bss = .;
        *(.sbss*)
        *(.bss)             ← Global variables that should be zero
        *(.bss.*)
        _bss_end = .;
    }
    _end = .;
}
```

**uImage creation** (`tools/seL4/cmake-tool/helpers/make-uimage` line 120):
```bash
"$OBJCOPY" -O binary "$ELF_FILE" /dev/stdout >> $TEMPFILE
```

`objcopy -O binary` produces a flat binary containing **only loadable sections**
(`.text`, `.rodata`, `.data`). The `.bss` section is `NOBITS`/`NOLOAD` — it has
no file content and is excluded from the binary output.

**Memory layout after U-Boot loads the uImage:**
```
┌──────────────────────────────────────┐
│ .text (code)                         │ ← U-Boot wrote this (image data)
│ .rodata (CPIO archive, ~57 MB)       │ ← U-Boot wrote this
│ .data (initialized globals, ~68 B)   │ ← U-Boot wrote this
├──────────────────────────────────────┤
│ core_stack_alloc (~4 KB/core)        │ ← UNINITIALIZED (not in binary)
│ _bss ... _bss_end (~53 KB)           │ ← UNINITIALIZED (not in binary)
└──────────────────────────────────────┘
```

U-Boot writes only the image data region. BSS memory contains whatever was
in RAM before (U-Boot heap, OP-TEE residue, or random DRAM state).

---

## The AArch64 Bug

### `config_choice` makes IMAGE_BINARY and IMAGE_UIMAGE mutually exclusive

`tools/seL4/elfloader-tool/CMakeLists.txt` lines 26-33:
```cmake
config_choice(
    ElfloaderImage  ELFLOADER_IMAGE  "Boot image type"
    "elf;ElfloaderImageELF;IMAGE_ELF;KernelArchARM OR KernelArchRiscV"
    "binary;ElfloaderImageBinary;IMAGE_BINARY;KernelArchARM OR KernelArchRiscV"
    "efi;ElfloaderImageEFI;IMAGE_EFI;KernelArchARM"
    "uimage;ElfloaderImageUimage;IMAGE_UIMAGE;KernelArchARM OR KernelArchRiscV"
)
```

`config_choice` selects **exactly one** option. When `ElfloaderImage="uimage"`:
- `CONFIG_IMAGE_UIMAGE` is defined
- `CONFIG_IMAGE_BINARY` is **NOT defined**

### AArch64 crt0.S gates `clear_bss` on `CONFIG_IMAGE_BINARY`

`tools/seL4/elfloader-tool/src/arch-arm/64/crt0.S` lines 18-51:
```asm
BEGIN_FUNC(_start)
    adrp    x19, core_stack_alloc
    add     x19, x19, #0xff0
    mov     sp, x19
#ifdef CONFIG_IMAGE_BINARY          ← FALSE for uImage builds
    stp     x0, x1, [sp, #-16]!
    ...
    bl      fixup_image_base
    ...
    bl      clear_bss               ← line 47: NEVER REACHED
    ldp     x0, x1, [sp], #16
#endif                              ← clear_bss skipped entirely
    b       main                    ← jumps to main with dirty BSS
END_FUNC(_start)
```

For uImage builds: `_start` sets up the stack, then **jumps directly to `main`**
without calling `clear_bss` or `fixup_image_base`.

### AArch32 handles this correctly

`tools/seL4/elfloader-tool/src/arch-arm/32/crt0.S` lines 105-113:
```asm
#ifndef CONFIG_IMAGE_EFI
    push    {r0}
    bl      clear_bss              ← Called for ALL image types except EFI
    pop     {r0}
#endif
```

AArch32 calls `clear_bss` for binary, uImage, and ELF — only EFI is excluded
(because EFI firmware handles BSS). **The AArch64 code is inconsistent with
AArch32** — it should also call `clear_bss` for uImage.

---

## Why It Works Today (Masking Analysis)

### Mask 1: No UART driver

`tools/seL4/elfloader-tool/src/drivers/uart/common.c` line 12:
```c
static struct elfloader_device *uart_out = NULL;
```

`uart_out` is a BSS global (initialized to NULL = zero, placed in `.bss` by
compiler). If BSS is uncleared, `uart_out` could be garbage (non-NULL).

The null checks at lines 25 and 33 (`if (uart_out == NULL)`) would fail, and
the dereference at line 28 (`uart_out->region_bases[0]`) or line 42/45
(`dev_get_uart(uart_out)->putc(...)`) would cause a Synchronous Abort.

**But**: There is no `st,stm32h7-uart` UART driver in the elfloader driver list.
The device discovery loop finds no matching driver, so `uart_set_out()` is never
called. If `uart_out` happened to be NULL (luck), `plat_console_putchar()` returns
silently. If `uart_out` is garbage, the first `printf` crashes — but the elfloader
for STM32MP25x may not call `printf` before `main()` reaches the kernel unpacker.

### Mask 2: Globals written before read

Key BSS globals in `arch-arm/sys_boot.c` lines 40-43:
```c
struct image_info kernel_info;    // BSS — populated before use
struct image_info user_info;      // BSS — populated before use
void const *dtb;                  // BSS — set from bootm args
size_t dtb_size;                  // BSS — set from bootm args
```

These are all **written** by `main()` → `load_images()` → `elf_*` functions
before being **read**. Uninitialized values don't matter because they're
overwritten. This is fragile — any code path that reads before writing would fail.

### Mask 3: Single-core boot path

`arch-arm/armv/armv8-a/64/smp.c` line 18:
```c
volatile int core_up[CONFIG_MAX_NUM_NODES];  // BSS array
```

Secondary cores spin-wait on `core_up[cpu_id]`. If BSS is uncleared,
`core_up[i]` could be non-zero, causing premature wake-up. Currently safe
because seL4 uses PSCI for secondary core boot (not the elfloader's SMP path).

---

## BSS Globals at Risk

| Global | File | Lines | Risk |
|--------|------|-------|------|
| `uart_out` (static) | `drivers/uart/common.c` | 12 | **HIGH** — if non-NULL, first putchar crashes |
| `kernel_info` | `arch-arm/sys_boot.c` | 40 | Low — written before read |
| `user_info` | `arch-arm/sys_boot.c` | 41 | Low — written before read |
| `dtb` | `arch-arm/sys_boot.c` | 42 | Low — written before read |
| `dtb_size` | `arch-arm/sys_boot.c` | 43 | Low — written before read |
| `core_up[]` | `armv8-a/64/smp.c` | 18 | Medium — SMP race if non-zero |

---

## The Fix

Add `clear_bss` to the AArch64 uImage path. Model on the AArch32 approach
(call for all image types except EFI).

**Minimal patch** — `tools/seL4/elfloader-tool/src/arch-arm/64/crt0.S`:

```diff
 BEGIN_FUNC(_start)
     adrp    x19, core_stack_alloc
     add     x19, x19, #0xff0
     mov     sp, x19
 #ifdef CONFIG_IMAGE_BINARY
     stp     x0, x1, [sp, #-16]!
     ...
     bl      clear_bss
     ldp     x0, x1, [sp], #16
-#endif
+#else
+#ifndef CONFIG_IMAGE_EFI
+    /* uImage/ELF: BSS not included in binary payload, must be cleared */
+    stp     x0, x1, [sp, #-16]!
+    bl      clear_bss
+    ldp     x0, x1, [sp], #16
+#endif
+#endif
     b       main
 END_FUNC(_start)
```

This adds 4 instructions (stp, bl, ldp + branch label) ≈ 16 bytes. No
functional change for binary or EFI builds. Fixes uImage and ELF builds.

**Alternative (simpler, matches AArch32 pattern)**: Always call `clear_bss`
unless EFI, and keep `fixup_image_base` gated on `CONFIG_IMAGE_BINARY`:

```diff
 BEGIN_FUNC(_start)
     adrp    x19, core_stack_alloc
     add     x19, x19, #0xff0
     mov     sp, x19
+    stp     x0, x1, [sp, #-16]!
 #ifdef CONFIG_IMAGE_BINARY
-    stp     x0, x1, [sp, #-16]!
     ldr     x0, =IMAGE_START_ADDR
     ...
     bl      fixup_image_base
     ...
-    bl      clear_bss
-    ldp     x0, x1, [sp], #16
 #endif
+#ifndef CONFIG_IMAGE_EFI
+    bl      clear_bss
+#endif
+    ldp     x0, x1, [sp], #16
     b       main
 END_FUNC(_start)
```

---

## Runtime Verification (Board Test)

If the board is connected, this provides a definitive runtime answer:

```bash
# In U-Boot console, before bootm:
# 1. Load uImage but don't boot
fatload mmc 2 0x90000000 sel4.bin

# 2. Find BSS region from elfloader map (need a build first)
#    Typical: _bss = load_addr + image_size (rounded up to page)

# 3. Read memory at BSS region
md.l <bss_addr> 16
# If all zeros: BSS region happens to be clean (coincidence, not guarantee)
# If non-zero: BSS is dirty (confirms the bug is real)

# 4. Boot and observe
bootm 0x90000000
# If boots successfully: BSS values happened to be benign
# If Synchronous Abort: uart_out was garbage
```

---

## Documentation Updates Required

### 1. `ccwmp255-sel4-rules.md` line 17
**Current**: "Our fork fixes this."
**Corrected**: "Upstream elfloader does NOT clear BSS for uImage builds on AArch64.
This is a known upstream bug (AArch32 handles it correctly). Currently masked
because the elfloader has no UART driver for STM32 USART and key globals are
written before read. A 4-instruction patch to `64/crt0.S` fixes this."

### 2. `CLAUDE.md` line 46
**Current**: "Elfloader BSS clearing bug (our fork fixes this)"
**Corrected**: "Elfloader BSS not cleared for AArch64 uImage (upstream bug, masked by absent UART driver)"

### 3. Auto-memory `MEMORY.md`
**Current**: "NOT A BLOCKER — `clear_bss()` called in `CONFIG_IMAGE_BINARY` path
in aarch64 crt0.S (line 47), active for uImage builds"
**Corrected**: "LATENT BUG — `clear_bss()` is NOT called for uImage builds
(`CONFIG_IMAGE_UIMAGE` ≠ `CONFIG_IMAGE_BINARY`, mutually exclusive via
`config_choice`). Currently masked: no UART driver + globals written before read.
Fix: add `bl clear_bss` to AArch64 crt0.S uImage path (~4 instructions)."

---

## Source Files Referenced

| File | Lines | Content |
|------|-------|---------|
| `tools/seL4/elfloader-tool/src/arch-arm/64/crt0.S` | 9-51 | AArch64 startup, `clear_bss` gated on `CONFIG_IMAGE_BINARY` |
| `tools/seL4/elfloader-tool/src/arch-arm/32/crt0.S` | 105-113 | AArch32 startup, `clear_bss` for all except EFI |
| `tools/seL4/elfloader-tool/src/linker.lds` | 49-61 | BSS section (NOLOAD), `_bss`/`_bss_end` symbols |
| `tools/seL4/elfloader-tool/src/common.c` | 54-68 | `clear_bss()` implementation |
| `tools/seL4/elfloader-tool/src/drivers/uart/common.c` | 12-48 | `uart_out` BSS global, null checks |
| `tools/seL4/elfloader-tool/src/arch-arm/sys_boot.c` | 40-43 | BSS globals: `kernel_info`, `user_info`, `dtb` |
| `tools/seL4/elfloader-tool/src/arch-arm/armv/armv8-a/64/smp.c` | 18 | `core_up[]` BSS array |
| `tools/seL4/elfloader-tool/CMakeLists.txt` | 26-33 | `config_choice`: IMAGE_BINARY ≠ IMAGE_UIMAGE |
| `tools/seL4/cmake-tool/helpers/make-uimage` | 120 | `objcopy -O binary` strips BSS |
| `u-boot/boot/bootm.c` | 259, 619, 994-1129 | bootm state machine (no RAM zeroing) |
| `u-boot/arch/arm/lib/bootm.c` | 311-350 | `boot_jump_linux()` AArch64 |
| `u-boot/arch/arm/cpu/armv8/cpu.c` | 38-73 | `cleanup_before_linux()` (cache only) |
| `u-boot/include/image.h` | 322-335 | Legacy uImage header (no BSS size field) |
