#
# STM32MP25x multikernel hello-world settings.
#

cmake_minimum_required(VERSION 3.7.2)

set(project_dir "${CMAKE_CURRENT_LIST_DIR}/../../")
file(GLOB project_modules ${project_dir}/*)
list(
    APPEND
        CMAKE_MODULE_PATH
        ${project_dir}/../kernel
        ${project_dir}/../tools/seL4/cmake-tool/
        ${project_dir}/../tools/seL4/cmake-tool/helpers/
        ${project_dir}/../tools/seL4/elfloader-tool/
        ${project_modules}
)

set(SEL4_CONFIG_DEFAULT_ADVANCED ON)
mark_as_advanced(CMAKE_INSTALL_PREFIX)

include(application_settings)

set(PLATFORM "stm32mp25x" CACHE STRING "" FORCE)
set(KernelArch "arm" CACHE STRING "" FORCE)
set(KernelSel4Arch "aarch64" CACHE STRING "" FORCE)
set(AARCH64 ON CACHE BOOL "" FORCE)
set(CCWMP25HelloHypervisor ON CACHE BOOL "Build the hello kernels as EL2 hypervisors (OFF = plain EL1 kernels)")
set(KernelArmHypervisorSupport ${CCWMP25HelloHypervisor} CACHE BOOL "" FORCE)
set(KernelAllowSMCCalls ON CACHE BOOL "" FORCE)

# Each seL4 instance is a verified unicore kernel. The elfloader wakes CPU1.
set(KernelMaxNumNodes 1 CACHE STRING "" FORCE)
set(KernelNumDomains 1 CACHE STRING "" FORCE)
set(KernelEnableSMPSupport OFF CACHE BOOL "" FORCE)

set(KernelPrinting ON CACHE BOOL "" FORCE)
set(KernelDebugBuild ON CACHE BOOL "" FORCE)
set(KernelRootCNodeSizeBits 12 CACHE STRING "" FORCE)
set(SIMULATION OFF CACHE BOOL "" FORCE)
set(LibUSB OFF CACHE BOOL "" FORCE)
set(CCWMP25HelloMultikernel OFF CACHE BOOL "Bundle independent per-core CCMP25 hello kernels")
set(CCWMP25HelloMultikernelDispatch OFF CACHE BOOL "Dispatch CCMP25 hello secondary kernels from elfloader")
set(CCWMP25HelloMultikernelDispatchAfterMmu OFF CACHE BOOL "Dispatch CCMP25 hello secondaries after K0 MMU enable")
set(CCWMP25HelloMultikernelCount 1 CACHE STRING "Number of CCMP25 hello kernels in the bundle")

correct_platform_strings()

find_package(seL4 REQUIRED)
sel4_configure_platform_settings()

ApplyData61ElfLoaderSettings(${KernelARMPlatform} ${KernelSel4Arch})
set(ElfloaderImage "uimage" CACHE STRING "" FORCE)

if(CCWMP25HelloMultikernel)
    set(ElfloaderMultikernel ON CACHE BOOL "" FORCE)
    set(MULTIKERNEL_COUNT "${CCWMP25HelloMultikernelCount}" CACHE STRING "" FORCE)
    if(CCWMP25HelloMultikernelDispatch)
        set(MULTIKERNEL_DISPATCH_SECONDARIES ON CACHE BOOL "" FORCE)
    else()
        set(MULTIKERNEL_DISPATCH_SECONDARIES OFF CACHE BOOL "" FORCE)
    endif()
    if(CCWMP25HelloMultikernelDispatchAfterMmu)
        set(MULTIKERNEL_DISPATCH_AFTER_MMU ON CACHE BOOL "" FORCE)
    else()
        set(MULTIKERNEL_DISPATCH_AFTER_MMU OFF CACHE BOOL "" FORCE)
    endif()
endif()

if(NOT DEFINED RELEASE)
    set(RELEASE OFF)
endif()
ApplyCommonReleaseVerificationSettings(${RELEASE} FALSE)
