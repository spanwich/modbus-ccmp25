add_executable(rootserver_hello EXCLUDE_FROM_ALL main.c)
target_compile_definitions(rootserver_hello PRIVATE
    KERNEL_ID=${MK_KERNEL_ID}
    ROOTSERVER_BUILD_ID="ccwmp25-mk-k1-no-global-icache-01"
)
target_link_libraries(
    rootserver_hello
    PRIVATE
        sel4
        sel4runtime
        sel4muslcsys
)
