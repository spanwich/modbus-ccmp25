# MODBUS CCMP25 — Current Design & vm_minimal Reference

Reference document for planning Linux VM guest migration on CCMP25-DVK.

---

## 1. Current MODBUS CCMP25 Design

### 1.1 Hardware Target

- **Board**: Digi ConnectCore MP25 Development Kit (CCMP25-DVK)
- **SoC**: STM32MP255, dual Cortex-A35, AArch64
- **NIC**: Synopsys DWMAC 5.10a Gigabit Ethernet (`st,stm32mp25-dwmac`, `snps,dwmac-5.10a`)
- **UART**: USART2 @ `0x400e0000`, 115200 baud, `/dev/ttyACM1`
- **Boot chain**: TF-A (BL2) → OP-TEE (BL32, starts IWDG1 32s timeout) → U-Boot (BL33) → seL4 (uImage via bootm)

### 1.2 Architecture (Software-Only, No VM Guest)

```
[PLC/SCADA] ←→ ICS_Inbound ←→ ICS_Outbound ←→ [Field Devices]
                     ↕               ↕
              EverParse + Policy  EverParse (no policy)

WatchdogKicker — pets IWDG1 via SMC to OP-TEE every ~10s
```

All three are **native CAmkES components** (no Linux VM, no VirtIO):

| Component | Role | Priority |
|-----------|------|----------|
| **ICS_Inbound** | Validates external→internal MODBUS traffic | 150 |
| **ICS_Outbound** | Validates internal→external MODBUS traffic | 150 |
| **WatchdogKicker** | Pets IWDG1 via OP-TEE SMC (function `0xbc000000`, subfunc 3) | 50 |

### 1.3 Validation Pipeline (Two-Stage)

1. **Stage 1 — EverParse (formally verified)**: MBAP header, protocol ID (`0x0000`), length (2–254), function codes (1–127), trailing byte detection (prevents CVE-2019-14462)
2. **Stage 2 — Policy enforcement**: Runtime address-range validation per function code. Mitigates **CVE-2022-0367** (validates both read and write addresses in FC 0x17)

### 1.4 Key Files

```
modbus_ccmp25/
├── CLAUDE.md
├── CMakeLists.txt                      # Build config (qemu-arm-virt & stm32mp25x)
├── settings.cmake                      # Platform settings, KernelArmHypervisorSupport ON
├── ics_stm32mp25x.camkes              # Hardware assembly (loopback, no NIC yet)
├── ics_dual_nic.camkes                # QEMU dual-NIC assembly (VirtIO + lwIP)
├── components/
│   ├── ICS_Inbound/ICS_Inbound.c      # External→internal validator
│   ├── ICS_Outbound/ICS_Outbound.c    # Internal→external validator
│   ├── WatchdogKicker/WatchdogKicker.c # IWDG SMC kicker
│   ├── VirtIO_Net0_Driver/             # External NIC driver (QEMU only)
│   ├── VirtIO_Net1_Driver/             # Internal NIC driver (QEMU only)
│   ├── lib/
│   │   ├── ringbuf.h/c                # Lock-free SPSC ring buffer
│   │   └── everparse_error_handler.c
│   └── include/
│       ├── common.h                    # FrameMetadata, ICS_Message (~60KB), dataports
│       ├── control_queue.h             # SPSC close/error notification queue (128 slots)
│       ├── connection_state.h          # Per-connection tracking (256 entries)
│       ├── modbus_policy.h             # CVE-2022-0367 mitigation, address range checks
│       ├── debug_levels.h              # 5-level debug (NONE/ERROR/WARN/INFO/DEBUG)
│       ├── version.h                   # v2.270 (2026-01-06)
│       ├── ModbusTCP_v3_Simple.h/c     # EverParse-generated parser
│       └── ModbusTCP_v3_SimpleWrapper.h/c
└── deploy/
    ├── Makefile                         # Builds .scr U-Boot scripts
    ├── install.cmd                      # Install seL4 to eMMC
    ├── boot.cmd                         # Boot seL4 (bootm 0x90000000)
    └── restore.cmd                      # Restore Linux boot
```

### 1.5 CAmkES Assembly — `ics_stm32mp25x.camkes`

Current hardware assembly is **loopback only** (Phase 1 — boot validation):

```camkes
import <std_connector.camkes>;
import <global-connectors.camkes>;

assembly {
    composition {
        component WatchdogKicker watchdog_kicker;
        component ICS_Inbound    ics_inbound;
        component ICS_Outbound   ics_outbound;

        /* Loopback: inbound↔outbound via shared dataport */
        connection seL4SharedData inbound_to_outbound(...);
        connection seL4SharedData outbound_to_inbound(...);
        connection seL4Notification notify_inbound(...);
        connection seL4Notification notify_outbound(...);
    }
    configuration {
        watchdog_kicker._priority  = 50;
        ics_inbound._priority      = 150;
        ics_outbound._priority     = 150;
        watchdog_kicker.smc_cap    = 1;   /* OP-TEE SMC capability */
    }
}
```

### 1.6 settings.cmake (Key Settings)

```cmake
set(KernelArch arm CACHE STRING "" FORCE)
set(KernelArmHypervisorSupport ON CACHE BOOL "" FORCE)   # EL2 hypervisor mode
set(KernelAllowSMCCalls ON CACHE BOOL "" FORCE)           # OP-TEE SMC for IWDG
set(CAmkESCPP ON CACHE BOOL "" FORCE)
set(CapDLLoaderMaxObjects 90000 CACHE STRING "" FORCE)
```

### 1.7 Platform Constraints (from ccwmp255-sel4-rules.md)

- **Timer traps**: `mrs cntvct_el0` and `mrs cntfrq_el0` cause VCPUFault (label 7) under hypervisor mode. CAmkES fault handler does NOT handle VCPUFault/VGICMaintenance/VPPIEvent
- **IWDG is RIFSC-protected**: No direct MMIO access, must use SMC via OP-TEE
- **Elfloader BSS bug**: Custom fork fixes BSS clearing issue
- **No UART driver in elfloader**: Silent gap between U-Boot handoff and seL4 kernel output
- **DWMAC NIC**: Likely RIFSC-controlled too — may need SMC or passthrough to VM

### 1.8 Data Structures

```c
/* ~50 bytes — packet metadata extracted by network driver */
typedef struct {
    uint8_t  dst_mac[6], src_mac[6];
    uint16_t ethertype, vlan_id;
    uint8_t  ip_protocol;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint16_t payload_offset, payload_length;
    uint8_t  is_ip, is_tcp, is_udp, is_arp;
} FrameMetadata;

/* ~60KB — full message passed between components */
typedef struct {
    FrameMetadata metadata;
    uint16_t      payload_length;
    uint8_t       payload[60000];
} ICS_Message;

/* Shared dataport layout (Net0 → Inbound → Net1) */
typedef struct {
    ICS_Message request_msg;
    ControlQueue close_queue;   /* 128-slot SPSC for TCP close events */
} InboundDataport;
```

---

## 2. vm_minimal — seL4 Hypervisor VM Configuration Reference

**Location**: `projects/vm-examples/apps/Arm/vm_minimal/`

### 2.1 How It Works (Overview)

```
seL4 kernel (EL2) ──────────────────────────────────
  │
  ├── FileServer component     ← serves kernel/DTB/initrd from CPIO archive
  │
  └── VM component (vm0)       ← VMM: creates vCPUs, loads Linux, handles faults
        │
        └── Linux guest (EL1)  ← boots from loaded kernel + DTB + initrd
              └── /dev/...     ← devices from DTB passthrough or VirtIO
```

### 2.2 CAmkES Assembly — `vm_minimal.camkes`

```camkes
#include <configurations/vm.h>

import <std_connector.camkes>;
import <global-connectors.camkes>;
import <vm-connectors.camkes>;
import <VM_Arm/VM.camkes>;
import <devices.camkes>;

assembly {
    composition {
        VM_GENERAL_COMPOSITION_DEF()
        VM_COMPOSITION_DEF(0)
        connection seL4VMDTBPassthrough vm_dtb(from vm0.dtb_self, to vm0.dtb);
    }
    configuration {
        VM_GENERAL_CONFIGURATION_DEF()
        VM_CONFIGURATION_DEF(0)

        vm0.num_extra_frame_caps = 0;
        vm0.extra_frame_map_address = 0;
        vm0.cnode_size_bits = 23;
        vm0.simple_untyped24_pool = 12;
    }
}
```

### 2.3 VM Component Interfaces (from `VM_INIT_DEF()`)

```camkes
component VM {
    /* Core */
    control;
    uses FileServerInterface fs;
    provides VMDTBPassthrough dtb;
    maybe uses VMDTBPassthrough dtb_self;
    emits HaveNotification notification_ready_connector;
    consumes HaveNotification notification_ready;

    /* Optional — activated by build flags */
    maybe uses VirtQueueDev recv;
    maybe uses VirtQueueDrv send;
    maybe uses Batch batch;
    maybe uses PutChar guest_putchar;
    maybe uses GetChar serial_getchar;

    /* Attributes set per-platform in devices.camkes */
    attribute { ... } linux_address_config;
    attribute { ... } linux_image_config;
}
```

### 2.4 Platform Configuration — `devices.camkes` (per-platform)

Each platform provides memory layout, DTB nodes, and MMIO mappings.

**Example: qemu-arm-virt:**

```camkes
#include <configurations/vm.h>

#define VM_RAM_BASE    0x40000000
#define VM_RAM_SIZE    0x20000000   /* 512 MB */
#define VM_DTB_ADDR    0x4F000000
#define VM_INITRD_ADDR 0x4D700000

assembly {
    composition {}
    configuration {
        vm0.linux_address_config = {
            "linux_ram_base"       : "0x40000000",
            "linux_ram_paddr_base" : "0x40000000",
            "linux_ram_size"       : "0x20000000",
            "linux_ram_offset"     : "0",
            "dtb_addr"             : "0x4F000000",
            "initrd_max_size"      : "0x1900000",
            "initrd_addr"          : "0x4D700000"
        };

        vm0.linux_image_config = {
            "linux_bootcmdline" : "",
            "linux_stdout"      : "/pl011@9000000",
        };

        vm0.num_vcpus = 2;

        vm0.dtb = dtb([
            {"path": "/pl011@9000000"},
        ]);

        vm0.untyped_mmios = [
            "0x8040000:12",       /* GIC virtual CPU interface */
            "0x40000000:29",      /* VM RAM region */
        ];
    }
}
```

**Example: TX2 (with multiple passthrough devices):**

```camkes
vm0.linux_image_config = {
    "linux_bootcmdline" : "console=ttyS0,115200n1 earlycon=uart8250,mmio32,0x03100000",
    "linux_stdout"      : "/serial@3100000",
};
vm0.num_vcpus = 4;

vm0.dtb = dtb([
    {"path": "/serial@3100000"},
    {"path": "/serial@3110000"},
    {"path": "/serial@3130000"},
]);
```

### 2.5 CMakeLists.txt — Build System Integration

```cmake
# 1. Platform-specific settings
if("${KernelARMPlatform}" STREQUAL "qemu-arm-virt")
    set(QEMU_MEMORY "2048")
    set(KernelArmCPU cortex-a53 CACHE STRING "" FORCE)
    set(VmInitRdFile ON CACHE BOOL "" FORCE)
    set(cpp_includes "${CAMKES_ARM_LINUX_DIR}/qemu-arm-virt/devices.camkes")
endif()

# 2. Register Linux kernel image with FileServer
AddToFileServer("linux" "${CAMKES_VM_IMAGES_DIR}/${KernelARMPlatform}/linux")

# 3. Register device tree (compile from .dts or use pre-built)
AddToFileServer("linux-dtb" "${path_to_dtb}")

# 4. Register initrd/rootfs (optional)
AddToFileServer("linux-initrd" "${rootfs_file}")

# 5. Build the FileServer CPIO archive
DefineCAmkESVMFileServer()

# 6. Declare VM component (links libsel4vm, libsel4vmmplatsupport, libvirtio)
DeclareCAmkESARMVM(vm_minimal_init)

# 7. Declare CAmkES root server
DeclareCAmkESRootserver(vm_minimal.camkes
    CPP_FLAGS ${cpp_flags}
    CPP_INCLUDES ${cpp_includes}
)
```

### 2.6 Key CMake Helper Functions

| Function | File | Purpose |
|----------|------|---------|
| `AddToFileServer(name, path)` | `camkes_vm_helpers.cmake` | Stages file into CPIO archive |
| `DefineCAmkESVMFileServer()` | `camkes_vm_helpers.cmake` | Builds CPIO from staged files |
| `DeclareCAmkESARMVM(init)` | `arm_vm_helpers.cmake` | Declares VM component with all VM libraries + optional VirtIO modules |
| `UpdateDtbFromInitrd(dtb, initrd, addr, ...)` | `arm_vm_helpers.cmake` | Patches DTB with initrd load address |
| `DeclareCAmkESRootserver(camkes_file, ...)` | CAmkES build system | Compiles the CAmkES assembly |

### 2.7 VM Runtime Boot Sequence

```
1. seL4 kernel starts → spawns CapDL loader → creates all components
2. FileServer starts → serves CPIO archive contents via RPC
3. VM component starts (main.c):
   a. Calls FileServer to fetch "linux" → loads at linux_ram_base
   b. Calls FileServer to fetch "linux-dtb" → loads at dtb_addr
   c. Calls FileServer to fetch "linux-initrd" → loads at initrd_addr
   d. Manipulates DTB:
      - Adds /memory node (ram_base, ram_size)
      - Adds /chosen node (bootargs, stdout-path, initrd location)
      - Merges passthrough device nodes from vm0.dtb config
   e. Initializes VMM modules (loaded from ELF section "_vmm_module"):
      - init_ram: registers VM RAM with sel4vm
      - Platform init: installs passthrough/virtual devices
      - VirtIO modules (if enabled): virtio_net, virtio_console
   f. Creates vCPUs, sets entry point → boots Linux kernel
4. Linux kernel starts at EL1 → probes DTB → mounts initrd
```

### 2.8 VirtIO Networking (Optional)

Enabled via build flags in `settings.cmake`:

```cmake
set(VmVirtioNetVirtqueue ON CACHE BOOL "" FORCE)
set(VmVirtioNetArping ON CACHE BOOL "" FORCE)
set(VmPCISupport ON CACHE BOOL "" FORCE)
```

### 2.9 Device Passthrough vs VirtIO

| Approach | Mechanism | Pros | Cons |
|----------|-----------|------|------|
| **Passthrough** | Map MMIO + IRQ directly into VM via `untyped_mmios` + `dtb` entries | Uses existing Linux driver, no new code | Less isolation, device exclusively owned by VM |
| **VirtIO** | Paravirtualized via virtqueue shared memory | Full isolation, device shared between components | Needs seL4-native device driver + VirtIO guest driver |

### 2.10 Required Imports & Connectors

```camkes
/* Standard */
import <std_connector.camkes>;
import <global-connectors.camkes>;

/* VM-specific */
import <vm-connectors.camkes>;
import <VM_Arm/VM.camkes>;
import <devices.camkes>;
```

### 2.11 Pre-built VM Images

Standard location: `${CAMKES_VM_IMAGES_DIR}/${KernelARMPlatform}/`

Platforms with pre-built images: exynos5422, tx1, tx2, qemu-arm-virt, odroidc2, zynqmp.
**STM32MP25x has NO pre-built images** — kernel + rootfs must be built from yocto-linux.

---

## 3. Gap Analysis: What STM32MP25x Needs for VM Support

| Requirement | Status | Notes |
|-------------|--------|-------|
| Hypervisor mode (EL2) | **Done** | `KernelArmHypervisorSupport ON` in settings.cmake |
| Cortex-A35 vCPU support | **Done** | ARMv8-A virtualization extensions present |
| `devices.camkes` for stm32mp25x | **Missing** | Must define RAM layout, DTB nodes, MMIO regions |
| Linux kernel image | **Missing** | Must build from `digidotcom/yocto-linux` |
| Root filesystem (initrd) | **Missing** | Minimal rootfs (BusyBox or Yocto-based) |
| Device tree for guest | **Missing** | Subset of stm32mp25x DTB for hypervisor mode |
| VCPUFault handler | **Missing** | Timer register traps (`cntvct_el0`, `cntfrq_el0`) crash the VM |
| VGICMaintenance handler | **Missing** | GIC virtualization faults unhandled |
| DWMAC NIC access | **Undecided** | Passthrough (simpler) vs VirtIO (more isolation) |
| RIFSC constraints | **Unknown** | NIC MMIO may be RIFSC-protected like IWDG |
| Platform init module | **Missing** | `modules/plat/stm32mp25x/init.c` needed |

---

## 4. Key File Paths Reference

```
# Current project
projects/modbus_ccmp25/settings.cmake
projects/modbus_ccmp25/ics_stm32mp25x.camkes
projects/modbus_ccmp25/CMakeLists.txt
projects/modbus_ccmp25/components/

# VM infrastructure
projects/vm/components/VM_Arm/VM.camkes
projects/vm/components/VM_Arm/configurations/vm.h
projects/vm/components/VM_Arm/src/main.c
projects/vm/components/VM_Arm/src/fdt_manipulation.c
projects/vm/components/VM_Arm/src/modules/init_ram.c
projects/vm/arm_vm_helpers.cmake
projects/vm/camkes_vm_helpers.cmake

# VM examples
projects/vm-examples/apps/Arm/vm_minimal/
projects/vm-examples/apps/Arm/vm_virtio_net/
projects/vm-examples/apps/Arm/vm_multi/
projects/vm-examples/apps/Arm/vm_freertos_net/

# Platform rules
.claude/ccwmp255-sel4-rules.md

# Digi kernel sources
../../ccwmp255/linux/arch/arm64/boot/dts/st/stm32mp251.dtsi   (DWMAC @ line 2286)
../../ccwmp255/u-boot/arch/arm/dts/stm32mp251.dtsi
```
