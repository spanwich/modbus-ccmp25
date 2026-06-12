add_executable(rootserver_hello EXCLUDE_FROM_ALL main.c)
target_compile_definitions(rootserver_hello PRIVATE
    KERNEL_ID=${MK_KERNEL_ID}
    ROOTSERVER_BUILD_ID="ccwmp25-mk-trace-e100k-s0-01"
)
target_link_libraries(
    rootserver_hello
    PRIVATE
        sel4
        sel4runtime
        sel4muslcsys
)

target_link_options(rootserver_hello PRIVATE "-Wl,--section-start=.mk_trace=0x41f000")
