
include_directories(${REACTOS_SOURCE_DIR}/sdk/include/reactos/idl ${CMAKE_CURRENT_BINARY_DIR})
add_rpc_files(client ${REACTOS_SOURCE_DIR}/sdk/include/reactos/idl/seclogon.idl)

add_executable(uacprobe uacprobe.c ${CMAKE_CURRENT_BINARY_DIR}/seclogon_c.c)
target_link_libraries(uacprobe ${PSEH_LIB})
set_module_type(uacprobe win32cui UNICODE)
add_importlibs(uacprobe advapi32 user32 rpcrt4 msvcrt kernel32 ntdll)
add_rostests_file(TARGET uacprobe SUBDIR suppl)
