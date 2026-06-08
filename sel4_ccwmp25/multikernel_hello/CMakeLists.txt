#
# Minimal STM32MP25x multikernel hello-world rootserver.
#
# This intentionally bypasses the CAmkES ICS gateway. It is only for proving
# that two independent unicore seL4 kernels can be packaged and booted.
#

cmake_minimum_required(VERSION 3.8.2)

project(ccwmp25_multikernel_hello C ASM)

include(settings.cmake)
include(base)

musllibc_setup_build_environment_with_sel4runtime()

find_package(util_libs REQUIRED)
find_package(seL4_libs REQUIRED)
util_libs_import_libraries()
sel4_libs_import_libraries()

if(NOT DEFINED MK_KERNEL_ID)
    set(MK_KERNEL_ID 0 CACHE STRING "Kernel ID printed by the hello rootserver")
endif()

add_subdirectory(rootserver)

include(rootserver)
DeclareRootserver(rootserver_hello)
