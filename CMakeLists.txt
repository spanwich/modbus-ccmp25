#
# Copyright 2025, PhD Research Project
#
# SPDX-License-Identifier: BSD-2-Clause
#
# MODBUS Bidirectional Cross-Domain Gateway
# Multi-platform: qemu-arm-virt (VirtIO) + stm32mp25x (CCMP25-DVK)
#

cmake_minimum_required(VERSION 3.8.2)

project(modbus-ccmp25 C)

include(settings.cmake)

set(projects_dir "${CMAKE_CURRENT_LIST_DIR}/..")

# ================================================================
# Platform: qemu-arm-virt — full VirtIO dual-NIC build
# ================================================================
if("${KernelARMPlatform}" STREQUAL "qemu-arm-virt")

    include(${CAMKES_ARM_VM_HELPERS_PATH})
    set(cpp_includes "${CAMKES_VM_DIR}/components/VM_Arm")
    set(cpp_flags "-DKERNELARMPLATFORM_QEMU-ARM-VIRT")

    include(simulation)
    GenerateSimulateScript()

    AddCamkesCPPFlag(cpp_flags CONFIG_VARS VmEmmc2NoDMA)
    DefineCAmkESVMFileServer()

    CAmkESAddImportPath(${KernelARMPlatform})
    CAmkESAddImportPath(components/VirtIO_Net0_Driver)
    CAmkESAddImportPath(components/VirtIO_Net1_Driver)

    # lwIP setup
    find_file(LWIP_PATH lwip PATHS ${projects_dir} CMAKE_FIND_ROOT_PATH_BOTH)
    if("${LWIP_PATH}" STREQUAL "LWIP_PATH-NOTFOUND")
        message(FATAL_ERROR "Failed to find lwIP")
    endif()
    include(${projects_dir}/util_libs/liblwip/lwip_helpers.cmake)

    # lwIP for Net0 (SCADA-facing)
    AddLWIPConfiguration(${CMAKE_CURRENT_LIST_DIR}/components/VirtIO_Net0_Driver)

    # lwIP for Net1 (PLC-facing) — separate instance
    add_library(liblwip_config_net1 INTERFACE)
    target_include_directories(liblwip_config_net1 INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/components/VirtIO_Net1_Driver)

    file(GLOB lwip_sources_net1
        ${LWIP_PATH}/src/*/*.c
        ${LWIP_PATH}/src/core/ipv4/*.c
    )
    add_library(lwip_net1 STATIC EXCLUDE_FROM_ALL ${lwip_sources_net1})
    target_include_directories(lwip_net1 PUBLIC
        ${LWIP_PATH}/src/include
        ${projects_dir}/util_libs/liblwip/include
        ${projects_dir}/util_libs/liblwip/include/lwip
    )
    target_link_libraries(lwip_net1 muslc liblwip_config_net1)
    target_compile_definitions(lwip_net1 PRIVATE LWIP_NET1_INSTANCE=1)

    # VirtIO_Net0_Driver (External Network)
    DeclareCAmkESComponent(
        VirtIO_Net0_Driver
        SOURCES
            components/VirtIO_Net0_Driver/virtio_net0_driver.c
        INCLUDES
            components/VirtIO_Net0_Driver
            components/include
            ${LWIP_PATH}/src/include
            ${projects_dir}/util_libs/liblwip/include
        LIBS
            sel4_autoconf
            utils
            lwip
    )

    # VirtIO_Net1_Driver (Internal Network)
    DeclareCAmkESComponent(
        VirtIO_Net1_Driver
        SOURCES
            components/VirtIO_Net1_Driver/virtio_net1_driver.c
        INCLUDES
            components/VirtIO_Net1_Driver
            components/include
            ${LWIP_PATH}/src/include
            ${projects_dir}/util_libs/liblwip/include
        LIBS
            sel4_autoconf
            utils
            lwip_net1
    )

    # ICS_Inbound (External → Internal validation)
    DeclareCAmkESComponent(
        ICS_Inbound
        SOURCES
            components/ICS_Inbound/ICS_Inbound.c
            components/include/ModbusTCP_v3_Simple.c
            components/include/ModbusTCP_v3_SimpleWrapper.c
            components/lib/everparse_error_handler.c
        INCLUDES
            components/include
    )

    # ICS_Outbound (Internal → External validation)
    DeclareCAmkESComponent(
        ICS_Outbound
        SOURCES
            components/ICS_Outbound/ICS_Outbound.c
            components/include/ModbusTCP_v3_Simple.c
            components/include/ModbusTCP_v3_SimpleWrapper.c
            components/lib/everparse_error_handler.c
        INCLUDES
            components/include
    )

    DeclareCAmkESRootserver(
        ics_dual_nic.camkes
        CPP_FLAGS ${cpp_flags}
        CPP_INCLUDES ${cpp_includes}
    )

# ================================================================
# Platform: stm32mp25x — native-only (no VM, no VirtIO, no lwIP)
# Build with: -DSTM32MP25X_VM=OFF (default)
# ================================================================
elseif("${KernelARMPlatform}" STREQUAL "stm32mp25x" AND NOT STM32MP25X_VM)

    # ICS_Inbound (validation component — no hardware deps)
    DeclareCAmkESComponent(
        ICS_Inbound
        SOURCES
            components/ICS_Inbound/ICS_Inbound.c
            components/include/ModbusTCP_v3_Simple.c
            components/include/ModbusTCP_v3_SimpleWrapper.c
            components/lib/everparse_error_handler.c
        INCLUDES
            components/include
    )

    # ICS_Outbound (validation component — no hardware deps)
    DeclareCAmkESComponent(
        ICS_Outbound
        SOURCES
            components/ICS_Outbound/ICS_Outbound.c
            components/include/ModbusTCP_v3_Simple.c
            components/include/ModbusTCP_v3_SimpleWrapper.c
            components/lib/everparse_error_handler.c
        INCLUDES
            components/include
    )

    # WatchdogKicker (pets IWDG1 via OP-TEE SMC)
    DeclareCAmkESComponent(
        WatchdogKicker
        SOURCES
            components/WatchdogKicker/WatchdogKicker.c
    )

    DeclareCAmkESRootserver(ics_stm32mp25x.camkes)

# ================================================================
# Platform: stm32mp25x + VM — Linux VM guest + native components
# Build with: -DSTM32MP25X_VM=ON
# ================================================================
elseif("${KernelARMPlatform}" STREQUAL "stm32mp25x" AND STM32MP25X_VM)

    include(${CAMKES_ARM_VM_HELPERS_PATH})
    set(cpp_includes "${CAMKES_VM_DIR}/components/VM_Arm")
    set(cpp_flags "-DKERNELARMPLATFORM_STM32MP25X")

    # Platform include for vmlinux.h (GIC path, passthrough IRQs, keep-devices)
    list(APPEND cpp_includes "${CMAKE_CURRENT_LIST_DIR}/plat_include/stm32mp25x")

    # Linux kernel image for VM guest
    # Expected at: linux/linux-Image (built from yocto-linux)
    set(linux_dir "${CMAKE_CURRENT_LIST_DIR}/linux")
    if(EXISTS "${linux_dir}/linux-Image")
        AddToFileServer("linux" "${linux_dir}/linux-Image")
    else()
        message(WARNING "Linux kernel image not found at ${linux_dir}/linux-Image. "
                        "Build from yocto-linux (v6.6/digi branch) and place here.")
    endif()

    # Guest device tree (compile from .dts)
    set(guest_dts "${CMAKE_CURRENT_LIST_DIR}/linux/stm32mp25x-guest.dts")
    if(EXISTS "${guest_dts}")
        add_custom_command(
            OUTPUT linux/linux-dtb
            COMMAND
                dtc -I dts -O dtb -o linux/linux-dtb ${guest_dts}
            VERBATIM
            DEPENDS ${guest_dts}
        )
        add_custom_target(set_dtb DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/linux/linux-dtb")
        AddToFileServer("linux-dtb" "${CMAKE_CURRENT_BINARY_DIR}/linux/linux-dtb"
            DEPENDS set_dtb)
    else()
        message(WARNING "Guest DTS not found at ${guest_dts}")
    endif()

    # Root filesystem (initrd)
    if(EXISTS "${linux_dir}/rootfs.cpio.gz")
        AddToFileServer("linux-initrd" "${linux_dir}/rootfs.cpio.gz")
    else()
        message(WARNING "Root filesystem not found at ${linux_dir}/rootfs.cpio.gz. "
                        "Build a minimal initrd (BusyBox-based) and place here.")
    endif()

    AddCamkesCPPFlag(cpp_flags CONFIG_VARS VmEmmc2NoDMA)
    DefineCAmkESVMFileServer()

    CAmkESAddImportPath(${KernelARMPlatform})

    # ICS_Inbound (validation component)
    DeclareCAmkESComponent(
        ICS_Inbound
        SOURCES
            components/ICS_Inbound/ICS_Inbound.c
            components/include/ModbusTCP_v3_Simple.c
            components/include/ModbusTCP_v3_SimpleWrapper.c
            components/lib/everparse_error_handler.c
        INCLUDES
            components/include
    )

    # ICS_Outbound (validation component)
    DeclareCAmkESComponent(
        ICS_Outbound
        SOURCES
            components/ICS_Outbound/ICS_Outbound.c
            components/include/ModbusTCP_v3_Simple.c
            components/include/ModbusTCP_v3_SimpleWrapper.c
            components/lib/everparse_error_handler.c
        INCLUDES
            components/include
    )

    # WatchdogKicker (pets IWDG1 via OP-TEE SMC)
    DeclareCAmkESComponent(
        WatchdogKicker
        SOURCES
            components/WatchdogKicker/WatchdogKicker.c
    )

    DeclareCAmkESRootserver(
        ics_vm_stm32mp25x.camkes
        CPP_FLAGS ${cpp_flags}
        CPP_INCLUDES ${cpp_includes}
    )

endif()

GenerateCAmkESRootserver()
