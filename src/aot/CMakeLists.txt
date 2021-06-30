add_library(aot aot.cpp)
target_include_directories(aot PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_include_directories(aot PUBLIC ${CMAKE_BINARY_DIR})
target_compile_definitions(aot PRIVATE ${BPFTRACE_FLAGS})

# TODO(dxu): remove LLVM requirement
find_package(LLVM REQUIRED CONFIG)

add_executable(bpftrace-aotrt aot_main.cpp)
target_link_libraries(bpftrace-aotrt aot runtime arch ast_defs LLVMSupport)
install(TARGETS bpftrace-aotrt DESTINATION ${CMAKE_INSTALL_BINDIR})
