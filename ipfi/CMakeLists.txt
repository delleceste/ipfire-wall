cmake_minimum_required(VERSION 3.16)
project(ipfire C)

# Include directories
include_directories(
    src/includes
    .
    g_getcharlib
    ..
)

# Generate build.h during configuration
string(TIMESTAMP BUILD_DATE "%a %b %d %H:%M:%S %Y")
# We approximate uname -sro
set(BUILD_SYS "${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION} ${CMAKE_SYSTEM_PROCESSOR}")

# Only write if different to trigger rebuild on change? 
# Or just write on configure.
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/src/includes/build.h
    "/* Compilation system and compilation date.\n"
    " * Written by CMake */\n"
    "#define _BUILD_DATE \"${BUILD_DATE}\"\n"
    "#define _BUILD_SYS \"${BUILD_SYS}\"\n\n"
)

# Shared Library Target
add_library(ipfire_common SHARED
    src/common.c
    src/libnetl.c
    src/languages.c
    src/utils.c
    src/filter.c
    src/init_confdir.c
    src/proc.c
    src/rule_cache.c
)

# Executable Target
add_executable(ipfire
    src/interface.c
    src/interface_functions.c
    src/ipfire_userspace.c
    src/mailer.c
    src/print_utils.c
    src/resolver.c
    src/semafori.c
    g_getcharlib/g_getcharlib.c
)

target_link_libraries(ipfire PRIVATE ipfire_common)

# Install
install(TARGETS ipfire DESTINATION bin)
install(TARGETS ipfire_common DESTINATION lib)
install(FILES rc.ipfire DESTINATION sbin)
