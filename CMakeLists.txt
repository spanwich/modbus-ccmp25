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
# Platform: stm32mp25x — software-only (no VirtIO, no lwIP)
# ================================================================
elseif("${KernelARMPlatform}" STREQUAL "stm32mp25x")

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

    # WatchdogKicker (IWDG service — stm32mp25x only)
    DeclareCAmkESComponent(
        WatchdogKicker
        SOURCES
            components/WatchdogKicker/WatchdogKicker.c
        INCLUDES
            components/include
    )

    DeclareCAmkESRootserver(ics_stm32mp25x.camkes)

endif()

GenerateCAmkESRootserver()
