cmake_minimum_required(VERSION 2.8.12)

project(libnetconf2 C)

# include custom Modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMakeModules/")

include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(UseCompat)
include(ABICheck)
include(SourceFormat)
include(GenDoc)
include(GenCoverage)

if(POLICY CMP0075)
    cmake_policy(SET CMP0075 NEW)
endif()

set(LIBNETCONF2_DESCRIPTION "NETCONF server and client library in C.")

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

# osx specific
set(CMAKE_MACOSX_RPATH TRUE)

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()
# see https://github.com/CESNET/libyang/pull/1692 for why CMAKE_C_FLAGS_<type> are not used directly
# normalize build type string
string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE_UPPER)
if ("${BUILD_TYPE_UPPER}" STREQUAL "RELEASE")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build Type" FORCE)
    set(CMAKE_C_FLAGS "-DNDEBUG -O2 ${CMAKE_C_FLAGS}")
elseif("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build Type" FORCE)
    set(CMAKE_C_FLAGS "-g -O0 ${CMAKE_C_FLAGS}")
elseif("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBINFO")
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build Type" FORCE)
elseif("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBUG")
    set(CMAKE_BUILD_TYPE "RelWithDebug" CACHE STRING "Build Type" FORCE)
elseif("${BUILD_TYPE_UPPER}" STREQUAL "ABICHECK")
    set(CMAKE_BUILD_TYPE "ABICheck" CACHE STRING "Build Type" FORCE)
    set(CMAKE_C_FLAGS  "-g -Og ${CMAKE_C_FLAGS}")
elseif("${BUILD_TYPE_UPPER}" STREQUAL "DOCONLY")
    set(CMAKE_BUILD_TYPE "DocOnly" CACHE STRING "Build Type" FORCE)
endif()

# Version of the project
# Generic version of not only the library. Major version is reserved for really big changes of the project,
# minor version changes with added functionality (new tool, functionality of the tool or library, ...) and
# micro version is changed with a set of small changes or bugfixes anywhere in the project.
set(LIBNETCONF2_MAJOR_VERSION 2)
set(LIBNETCONF2_MINOR_VERSION 1)
set(LIBNETCONF2_MICRO_VERSION 26)
set(LIBNETCONF2_VERSION ${LIBNETCONF2_MAJOR_VERSION}.${LIBNETCONF2_MINOR_VERSION}.${LIBNETCONF2_MICRO_VERSION})

# Version of the library
# Major version is changed with every backward non-compatible API/ABI change in libyang, minor version changes
# with backward compatible change and micro version is connected with any internal change of the library.
set(LIBNETCONF2_MAJOR_SOVERSION 3)
set(LIBNETCONF2_MINOR_SOVERSION 5)
set(LIBNETCONF2_MICRO_SOVERSION 3)
set(LIBNETCONF2_SOVERSION_FULL ${LIBNETCONF2_MAJOR_SOVERSION}.${LIBNETCONF2_MINOR_SOVERSION}.${LIBNETCONF2_MICRO_SOVERSION})
set(LIBNETCONF2_SOVERSION ${LIBNETCONF2_MAJOR_SOVERSION})

# Version of libyang library that this project depends on
set(LIBYANG_DEP_VERSION 2.1.19)
set(LIBYANG_DEP_SOVERSION 2.28.0)
set(LIBYANG_DEP_SOVERSION_MAJOR 2)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden -std=gnu99")

#
# options
#
if(("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG") OR ("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBINFO"))
    option(ENABLE_TESTS "Build tests" ON)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" ON)
else()
    option(ENABLE_TESTS "Build tests" OFF)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" OFF)
endif()
option(ENABLE_EXAMPLES "Build examples" ON)
option(ENABLE_COVERAGE "Build code coverage report from tests" OFF)
option(ENABLE_SSH "Enable NETCONF over SSH support (via libssh)" ON)
option(ENABLE_TLS "Enable NETCONF over TLS support (via OpenSSL)" ON)
option(ENABLE_DNSSEC "Enable support for SSHFP retrieval using DNSSEC for SSH (requires OpenSSL and libval)" OFF)
set(READ_INACTIVE_TIMEOUT 20 CACHE STRING "Maximum number of seconds waiting for new data once some data have arrived")
set(READ_ACTIVE_TIMEOUT 300 CACHE STRING "Maximum number of seconds for receiving a full message")
set(MAX_PSPOLL_THREAD_COUNT 6 CACHE STRING "Maximum number of threads that could simultaneously access a ps_poll structure")
set(TIMEOUT_STEP 100 CACHE STRING "Number of microseconds tasks are repeated until timeout elapses")
set(YANG_MODULE_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/yang/modules/libnetconf2" CACHE STRING "Directory where to copy the YANG modules to")
set(CLIENT_SEARCH_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/yang/modules" CACHE STRING "Default NC client YANG module search directory")
set(CALL_HOME_BACKOFF_WAIT 2 CACHE STRING "Number of seconds to wait between Call Home connection attempts")

#
# sources
#
set(libsrc
    src/io.c
    src/log.c
    src/messages_client.c
    src/messages_server.c
    src/session.c
    src/session_client.c
    src/session_server.c)

if(ENABLE_SSH)
    list(APPEND libsrc
        src/session_client_ssh.c
        src/session_server_ssh.c)
    set(SSH_MACRO "#ifndef NC_ENABLED_SSH\n#define NC_ENABLED_SSH\n#endif")
endif()

if(ENABLE_TLS)
    list(APPEND libsrc
        src/session_client_tls.c
        src/session_server_tls.c)
    set(TLS_MACRO "#ifndef NC_ENABLED_TLS\n#define NC_ENABLED_TLS\n#endif")
endif()

set(headers
    src/log.h
    src/netconf.h
    src/session.h
    src/messages_client.h
    src/messages_server.h
    src/session_client.h
    src/session_client_ch.h
    src/session_server.h
    src/session_server_ch.h)

# files to generate doxygen from
set(doxy_files
    src/libnetconf.h
    src/log.h
    src/netconf.h
    src/session.h
    src/messages_client.h
    src/messages_server.h
    src/session_client.h
    src/session_client_ch.h
    src/session_server.h
    src/session_server_ch.h)

# source files to be covered by the 'format' target
set(format_sources
    compat/*.c
    compat/*.h*
    examples/*.c
    examples/*.h*
    src/*.c
    src/*.h
    tests/*.c
    tests/client/*.c
    tests/pam/*.c)

#
# checks
#
if(ENABLE_DNSSEC AND NOT ENABLE_SSH)
    message(WARNING "DNSSEC SSHFP retrieval cannot be used without SSH support.")
    set(ENABLE_DNSSEC OFF)
endif()

if(ENABLE_VALGRIND_TESTS)
    find_program(VALGRIND_FOUND valgrind)
    if(NOT VALGRIND_FOUND)
        message(WARNING "valgrind executable not found! Disabling memory leaks tests.")
        set(ENABLE_VALGRIND_TESTS OFF)
    else()
        set(ENABLE_TESTS ON)
    endif()
endif()

if(ENABLE_TESTS)
    find_package(CMocka 1.0.1)
    if(NOT CMOCKA_FOUND)
        message(STATUS "Disabling tests because of missing CMocka")
        set(ENABLE_TESTS OFF)
    endif()
endif()

if(ENABLE_COVERAGE)
    gen_coverage_enable(${ENABLE_TESTS})
endif()

if ("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
    source_format_enable(0.75)
endif()

if("${BUILD_TYPE_UPPER}" STREQUAL "DOCONLY")
    gen_doc("${doxy_files}" ${LIBNETCONF2_VERSION} ${LIBNETCONF2_DESCRIPTION} "")
    return()
endif()

#
# targets
#

# use compat
use_compat()

# netconf2 target
add_library(netconf2 SHARED ${libsrc} ${compatsrc})
set_target_properties(netconf2 PROPERTIES VERSION ${LIBNETCONF2_SOVERSION_FULL} SOVERSION ${LIBNETCONF2_SOVERSION})

# include repository files with highest priority
include_directories(${PROJECT_BINARY_DIR}/src)

# dependencies - pthread
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(netconf2 ${CMAKE_THREAD_LIBS_INIT})

# check availability for some pthread functions
set(CMAKE_REQUIRED_LIBRARIES pthread)
check_function_exists(pthread_rwlockattr_setkind_np HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)

# dependencies - openssl
if(ENABLE_TLS OR ENABLE_DNSSEC OR ENABLE_SSH)
    find_package(OpenSSL REQUIRED)
    if(ENABLE_TLS)
        message(STATUS "OpenSSL found, required for TLS")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNC_ENABLED_TLS")
    endif()
    if(OPENSSL_VERSION VERSION_LESS 1.1.1)
        message(WARNING "OpenSSL version ${OPENSSL_VERSION} is no longer maintained, consider an update.")
    endif()

    target_link_libraries(netconf2 ${OPENSSL_LIBRARIES})
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

# dependencies - libssh
if(ENABLE_SSH)
    find_package(LibSSH 0.7.1 REQUIRED)
    if(LIBSSH_VERSION VERSION_EQUAL 0.9.3 OR LIBSSH_VERSION VERSION_EQUAL 0.9.4)
        message(FATAL_ERROR "LibSSH ${LIBSSH_VERSION} includes regression bugs and libnetconf2 will NOT work properly, try to use another version")
    endif()

    target_link_libraries(netconf2 ${LIBSSH_LIBRARIES})
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBSSH_LIBRARIES})
    include_directories(${LIBSSH_INCLUDE_DIRS})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNC_ENABLED_SSH")

    # crypt
    if(${CMAKE_SYSTEM_NAME} MATCHES "QNX")
        target_link_libraries(netconf2 -llogin)
        list(APPEND CMAKE_REQUIRED_LIBRARIES login)
    elseif(NOT APPLE)
        target_link_libraries(netconf2 -lcrypt)
        list(APPEND CMAKE_REQUIRED_LIBRARIES crypt)
    endif()

    # libpam
    find_package(LibPAM)
    if(LibPAM_FOUND)
        set(HAVE_LIBPAM TRUE)

        # enable PAM test if a PAM header file contains a declaration of a function pam_start_confdir
        if (LIBPAM_HAVE_CONFDIR)
            message(STATUS "LibPAM found, version >= 1.4, enabled PAM tests")
        else()
            message(STATUS "LibPAM found, version < 1.4, disabled PAM tests")
        endif()

        target_link_libraries(netconf2 ${LIBPAM_LIBRARIES})
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBPAM_LIBRARIES})
        include_directories(${LIBPAM_INCLUDE_DIRS})
    else()
        message(WARNING "LibPAM not found, PAM-based keyboard-interactive SSH server authentication method is disabled")
    endif()
endif()

# dependencies - libval
if(ENABLE_DNSSEC)
    find_package(LibVAL REQUIRED)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_DNSSEC")
    target_link_libraries(netconf2 ${LIBVAL_LIBRARIES})
    include_directories(${LIBVAL_INCLUDE_DIRS})
endif()

# dependencies - libyang
find_package(LibYANG ${LIBYANG_DEP_SOVERSION} REQUIRED)
target_link_libraries(netconf2 ${LIBYANG_LIBRARIES})
include_directories(${LIBYANG_INCLUDE_DIRS})

# header file compatibility - shadow.h and crypt.h
check_include_file("shadow.h" HAVE_SHADOW)
check_include_file("crypt.h" HAVE_CRYPT)

# function compatibility - getpeereid on QNX
if(${CMAKE_SYSTEM_NAME} MATCHES "QNX")
    target_link_libraries(netconf2 -lsocket)
    list(APPEND CMAKE_REQUIRED_LIBRARIES socket)
    list(REMOVE_ITEM CMAKE_REQUIRED_LIBRARIES pthread)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_QNX_SOURCE)
    check_symbol_exists(getpeereid "sys/types.h;unistd.h" HAVE_GETPEEREID)
    list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D_QNX_SOURCE)
endif()

# generate files
configure_file("${PROJECT_SOURCE_DIR}/src/config.h.in" "${PROJECT_BINARY_DIR}/src/config.h" ESCAPE_QUOTES @ONLY)
configure_file(nc_client.h.in nc_client.h)
configure_file(nc_server.h.in nc_server.h)
configure_file(nc_version.h.in nc_version.h)

# install YANG modules
install(DIRECTORY "${PROJECT_SOURCE_DIR}/modules/" DESTINATION ${YANG_MODULE_DIR} FILES_MATCHING PATTERN "*.yang")

# install library
install(TARGETS netconf2 DESTINATION ${CMAKE_INSTALL_LIBDIR})

# install headers
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nc_client.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nc_server.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nc_version.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${headers} ${PROJECT_BINARY_DIR}/src/config.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libnetconf2)

# install pkg-config file
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    configure_file("libnetconf2.pc.in" "libnetconf2.pc" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libnetconf2.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
    # check that pkg-config includes the used path
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --variable pc_path pkg-config RESULT_VARIABLE RETURN OUTPUT_VARIABLE PC_PATH ERROR_QUIET)
    if(RETURN EQUAL 0)
        string(REGEX MATCH "${CMAKE_INSTALL_LIBDIR}/pkgconfig" SUBSTR "${PC_PATH}")
        string(LENGTH "${SUBSTR}" SUBSTR_LEN)
        if(SUBSTR_LEN EQUAL 0)
            message(WARNING "pkg-config will not detect the new package after installation, adjust PKG_CONFIG_PATH using \"export PKG_CONFIG_PATH=\${PKG_CONFIG_PATH}:${CMAKE_INSTALL_LIBDIR}/pkgconfig\".")
        endif()
    endif()
endif()

# examples
if(ENABLE_EXAMPLES)
    if(NOT ENABLE_SSH)
        message(WARNING "Examples will not be compiled because SSH is disabled.")
    else()
        add_subdirectory(examples)
    endif()
endif()

# tests
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# create coverage target for generating coverage reports
gen_coverage("test_.*" "test_.*_valgrind")

# generate doxygen documentation for libnetconf2 API
gen_doc("${doxy_files}" ${LIBNETCONF2_VERSION} ${LIBNETCONF2_DESCRIPTION} "")

# generate API/ABI report
if ("${BUILD_TYPE_UPPER}" STREQUAL "ABICHECK")
    lib_abi_check(netconf2 "${headers}" ${LIBNETCONF2_SOVERSION_FULL} ffb35e9e5b58d0bffb15c0c2efc46a888d4c10b1)
endif()

# source files to be covered by the 'format' target and a test with 'format-check' target
source_format(${format_sources})

# clean cmake cache
add_custom_target(cleancache
                  COMMAND make clean
                  COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
                  COMMAND rm -rf Makefile Doxyfile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# uninstall
add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake")
