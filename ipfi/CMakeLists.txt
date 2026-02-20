cmake_minimum_required(VERSION 3.16)
project(ipfire C)

include(GNUInstallDirs)

# Include directories
include_directories(
    src/includes
    .
    g_getcharlib
    ..
)

# Generate build.h during configuration
string(TIMESTAMP BUILD_DATE "%a %b %d %H:%M:%S %Y")
set(BUILD_SYS "${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_VERSION} ${CMAKE_SYSTEM_PROCESSOR}")

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

# Define paths for the code to use
# These will be passed as absolute paths based on CMAKE_INSTALL_PREFIX
target_compile_definitions(ipfire_common PUBLIC 
    SHARE_CFGDIR="${CMAKE_INSTALL_FULL_DATADIR}/ipfire"
    ROOT_CFGDIR="${CMAKE_INSTALL_FULL_SYSCONFDIR}/ipfire"
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
install(TARGETS ipfire DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS ipfire_common DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ipfire.service DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/systemd/system)

# Install shared assets and default configs
install(DIRECTORY IPFIRE/languages DESTINATION ${CMAKE_INSTALL_DATADIR}/ipfire)
install(FILES IPFIRE/firehelp DESTINATION ${CMAKE_INSTALL_DATADIR}/ipfire)
install(FILES IPFIRE/allowed.base DESTINATION ${CMAKE_INSTALL_DATADIR}/ipfire)
install(FILES IPFIRE/allowed.base.README DESTINATION ${CMAKE_INSTALL_DATADIR}/ipfire)
install(FILES IPFIRE/blacklist.example DESTINATION ${CMAKE_INSTALL_DATADIR}/ipfire)
install(FILES IPFIRE/translation DESTINATION ${CMAKE_INSTALL_DATADIR}/ipfire)
install(FILES IPFIRE/options DESTINATION ${CMAKE_INSTALL_DATADIR}/ipfire)
install(FILES IPFIRE/allowed.base.it DESTINATION ${CMAKE_INSTALL_DATADIR}/ipfire)
install(FILES IPFIRE/options.it DESTINATION ${CMAKE_INSTALL_DATADIR}/ipfire)
install(FILES IPFIRE/blacksites DESTINATION ${CMAKE_INSTALL_DATADIR}/ipfire)

# Documentation
install(DIRECTORY ../doc DESTINATION ${CMAKE_INSTALL_DOCDIR}/ipfire)
