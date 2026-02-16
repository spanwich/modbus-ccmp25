#
# Copyright 2025, PhD Research Project
#
# SPDX-License-Identifier: BSD-2-Clause
#
# MODBUS Bidirectional Cross-Domain Gateway
# Multi-platform: qemu-arm-virt (QEMU VirtIO) + stm32mp25x (Digi CCMP25-DVK)
#

cmake_minimum_required(VERSION 3.7.2)

set(project_dir "${CMAKE_CURRENT_LIST_DIR}/../")
file(GLOB project_modules ${project_dir}/*)
list(
    APPEND
        CMAKE_MODULE_PATH
        ${project_dir}/../kernel
        ${project_dir}/../tools/seL4/cmake-tool/helpers/
        ${project_dir}/../tools/seL4/elfloader-tool/
        ${project_modules}
)

set(SEL4_CONFIG_DEFAULT_ADVANCED ON)
set(CAMKES_CONFIG_DEFAULT_ADVANCED ON)
mark_as_advanced(CMAKE_INSTALL_PREFIX)

include(application_settings)

# ================================================================
# Platform-specific configuration
# ================================================================
set(supported_platforms "qemu-arm-virt;stm32mp25x")
if(NOT "${PLATFORM}" IN_LIST supported_platforms)
    message(FATAL_ERROR "modbus_ccmp25 supports: ${supported_platforms}. Got: ${PLATFORM}")
endif()

if("${PLATFORM}" STREQUAL "qemu-arm-virt")
    # QEMU: 32-bit ARM for VirtIO MMIO compatibility
    set(KernelArch "arm" CACHE STRING "" FORCE)
    set(KernelSel4Arch "aarch32" CACHE STRING "" FORCE)
    set(AARCH64 OFF CACHE BOOL "" FORCE)
    set(KernelArmHypervisorSupport ON CACHE BOOL "" FORCE)
    set(VirtioNetSupport ON CACHE BOOL "" FORCE)
    set(SIMULATION ON CACHE BOOL "Generate QEMU simulation script" FORCE)
    set(LibLwip ON CACHE BOOL "" FORCE)
elseif("${PLATFORM}" STREQUAL "stm32mp25x")
    # Digi CCMP25-DVK: Cortex-A35 AArch64, no VirtIO
    set(KernelArch "arm" CACHE STRING "" FORCE)
    set(KernelSel4Arch "aarch64" CACHE STRING "" FORCE)
    set(AARCH64 ON CACHE BOOL "" FORCE)
    set(KernelArmHypervisorSupport ON CACHE BOOL "" FORCE)
    set(VirtioNetSupport OFF CACHE BOOL "" FORCE)
    set(SIMULATION OFF CACHE BOOL "" FORCE)
    # Phase 1: no network — lwIP disabled
    set(LibLwip OFF CACHE BOOL "" FORCE)
    # SMC calls for IWDG watchdog petting via OP-TEE
    set(KernelAllowSMCCalls ON CACHE BOOL "" FORCE)
endif()

set(KernelRootCNodeSizeBits 18 CACHE STRING "" FORCE)
set(CapDLLoaderMaxObjects 90000 CACHE STRING "" FORCE)
set(CAmkESCPP ON CACHE BOOL "" FORCE)

correct_platform_strings()

find_package(seL4 REQUIRED)
sel4_configure_platform_settings()

ApplyData61ElfLoaderSettings(${KernelARMPlatform} ${KernelSel4Arch})

# Override elfloader image format for stm32mp25x:
# bootm reads load/entry from uImage header (no hardcoded addresses)
if("${PLATFORM}" STREQUAL "stm32mp25x")
    set(ElfloaderImage "uimage" CACHE STRING "" FORCE)
endif()

if(NOT DEFINED RELEASE)
    set(RELEASE OFF)
endif()
ApplyCommonReleaseVerificationSettings(${RELEASE} FALSE)

# Kernel debug output — essential for board bring-up
set(KernelPrinting ON CACHE BOOL "" FORCE)
set(KernelDebugBuild ON CACHE BOOL "" FORCE)

find_package(camkes-tool REQUIRED)
camkes_tool_setup_camkes_build_environment()

find_file(GLOBAL_COMPONENTS_PATH global-components.cmake
    PATHS ${project_dir}/global-components/
    CMAKE_FIND_ROOT_PATH_BOTH)
mark_as_advanced(FORCE GLOBAL_COMPONENTS_PATH)
if("${GLOBAL_COMPONENTS_PATH}" STREQUAL "GLOBAL_COMPONENTS_PATH-NOTFOUND")
    message(FATAL_ERROR "Failed to find global-components.cmake")
endif()
include(${GLOBAL_COMPONENTS_PATH})
