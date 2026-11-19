cmake_minimum_required(VERSION 3.16)
project(rocket_ebpf_cpp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(ROCKET_SINGLE_FILE
       "Embed the BPF object and statically link the libbpf/libelf compression stack"
       OFF)

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

set(ROCKET_USER_SOURCES src/main.cpp)
if(ROCKET_SINGLE_FILE)
    # Turn the BPF ELF into a native relocatable object.  GNU ld exposes the
    # bytes through _binary_rocket_ebpf_bpf_o_{start,end}; main.cpp then feeds
    # those bytes directly to bpf_object__open_mem().  The .bpf.o remains only
    # an intermediate build artifact and is not needed at runtime.
    set(BPF_EMBED_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/rocket_ebpf_embed.o)
    add_custom_command(
        OUTPUT ${BPF_EMBED_OBJECT}
        COMMAND ${CMAKE_LINKER} -r -b binary
                rocket_ebpf.bpf.o -o ${BPF_EMBED_OBJECT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${BPF_OBJECT}
        VERBATIM)
    set_source_files_properties(${BPF_EMBED_OBJECT}
                                PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE)
    list(APPEND ROCKET_USER_SOURCES ${BPF_EMBED_OBJECT})
endif()

add_executable(rocket-ebpf-cpp ${ROCKET_USER_SOURCES})
add_dependencies(rocket-ebpf-cpp rocket_ebpf_bpf)
target_include_directories(
    rocket-ebpf-cpp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBELF_INCLUDE_DIRS})
target_compile_options(rocket-ebpf-cpp PRIVATE -Wall -Wextra -Wpedantic)

if(ROCKET_SINGLE_FILE)
    target_compile_definitions(rocket-ebpf-cpp PRIVATE ROCKET_EMBEDDED_BPF=1)

    # pkg-config knows the compression libraries required by the particular
    # libelf/libbpf build on this system.  Put only that dependency closure in
    # a static link region; C++ runtime and glibc stay dynamic.
    execute_process(
        COMMAND ${PKG_CONFIG_EXECUTABLE} --libs --static libbpf libelf
        OUTPUT_VARIABLE ROCKET_STATIC_LIB_FLAGS_RAW
        OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY)
    separate_arguments(ROCKET_STATIC_LIB_FLAGS NATIVE_COMMAND
                       "${ROCKET_STATIC_LIB_FLAGS_RAW}")
    list(FILTER ROCKET_STATIC_LIB_FLAGS EXCLUDE REGEX "^-pthread$")

    find_package(Threads REQUIRED)
    target_link_libraries(
        rocket-ebpf-cpp PRIVATE
        -Wl,-Bstatic
        ${ROCKET_STATIC_LIB_FLAGS}
        -Wl,-Bdynamic
        Threads::Threads
        ${CMAKE_DL_LIBS})
    # Binary input objects do not carry a GNU-stack note.  Explicitly keep the
    # final process stack non-executable.
    target_link_options(rocket-ebpf-cpp PRIVATE -Wl,-z,noexecstack)
else()
    target_link_libraries(rocket-ebpf-cpp PRIVATE
                          PkgConfig::LIBBPF PkgConfig::LIBELF)
endif()

install(TARGETS rocket-ebpf-cpp RUNTIME DESTINATION bin)
if(NOT ROCKET_SINGLE_FILE)
    install(FILES ${BPF_OBJECT} DESTINATION bin)
endif()
