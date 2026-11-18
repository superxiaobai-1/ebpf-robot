cmake_minimum_required(VERSION 3.16)
project(rocket_ebpf_cpp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)
find_program(CLANG_EXECUTABLE NAMES clang-18 clang-17 clang-16 clang-15 clang-14 clang REQUIRED)

execute_process(
    COMMAND ${CMAKE_C_COMPILER} -print-multiarch
    OUTPUT_VARIABLE MULTIARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE)

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" SYSTEM_PROCESSOR_LOWER)
if(SYSTEM_PROCESSOR_LOWER MATCHES "^(aarch64|arm64)$")
    set(BPF_TARGET_ARCH arm64)
    set(ORIN_DEFINE -DROCKET_ORIN_R36_RT=1)
elseif(SYSTEM_PROCESSOR_LOWER MATCHES "^(x86_64|amd64)$")
    set(BPF_TARGET_ARCH x86)
    set(ORIN_DEFINE)
else()
    message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(BPF_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/rocket_ebpf.bpf.c)
set(BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/rocket_ebpf.bpf.o)
set(BPF_SYSTEM_INCLUDE)
if(MULTIARCH AND EXISTS "/usr/include/${MULTIARCH}")
    list(APPEND BPF_SYSTEM_INCLUDE -I/usr/include/${MULTIARCH})
endif()

add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND ${CLANG_EXECUTABLE} -g -O2 -target bpf
            -D__TARGET_ARCH_${BPF_TARGET_ARCH}
            ${ORIN_DEFINE}
            -I${CMAKE_CURRENT_SOURCE_DIR}/include
            ${BPF_SYSTEM_INCLUDE}
            -c ${BPF_SOURCE} -o ${BPF_OBJECT}
    DEPENDS ${BPF_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/include/rocket_ebpf.h
    VERBATIM)
add_custom_target(rocket_ebpf_bpf ALL DEPENDS ${BPF_OBJECT})

add_executable(rocket-ebpf-cpp src/main.cpp)
add_dependencies(rocket-ebpf-cpp rocket_ebpf_bpf)
target_include_directories(rocket-ebpf-cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(rocket-ebpf-cpp PRIVATE PkgConfig::LIBBPF PkgConfig::LIBELF)
target_compile_options(rocket-ebpf-cpp PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS rocket-ebpf-cpp RUNTIME DESTINATION bin)
install(FILES ${BPF_OBJECT} DESTINATION bin)
