cmake_minimum_required(VERSION 3.5...3.28.1)

project(libnetconf2 C)

# include custom Modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules/")

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

#
# variables
#

set(LIBNETCONF2_DESCRIPTION "NETCONF server and client library in C.")

# osx specific
set(CMAKE_MACOSX_RPATH TRUE)

# Version of the project
# Generic version of not only the library. Major version is reserved for really big changes of the project,
# minor version changes with added functionality (new tool, functionality of the tool or library, ...) and
# micro version is changed with a set of small changes or bugfixes anywhere in the project.
set(LIBNETCONF2_MAJOR_VERSION 3)
set(LIBNETCONF2_MINOR_VERSION 3)
set(LIBNETCONF2_MICRO_VERSION 3)
set(LIBNETCONF2_VERSION ${LIBNETCONF2_MAJOR_VERSION}.${LIBNETCONF2_MINOR_VERSION}.${LIBNETCONF2_MICRO_VERSION})

# Version of the library
# Major version is changed with every backward non-compatible API/ABI change in libyang, minor version changes
# with backward compatible change and micro version is connected with any internal change of the library.
set(LIBNETCONF2_MAJOR_SOVERSION 4)
set(LIBNETCONF2_MINOR_SOVERSION 3)
set(LIBNETCONF2_MICRO_SOVERSION 4)
set(LIBNETCONF2_SOVERSION_FULL ${LIBNETCONF2_MAJOR_SOVERSION}.${LIBNETCONF2_MINOR_SOVERSION}.${LIBNETCONF2_MICRO_SOVERSION})
set(LIBNETCONF2_SOVERSION ${LIBNETCONF2_MAJOR_SOVERSION})

# Version of libyang library that this project depends on
set(LIBYANG_DEP_VERSION 2.0.0)
set(LIBYANG_DEP_SOVERSION 3.0.0)
set(LIBYANG_DEP_SOVERSION_MAJOR 3)

# global C flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden -std=c99")

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
option(ENABLE_SSH_TLS "Enable NETCONF over SSH and TLS support (via libssh and OpenSSL)" ON)
option(ENABLE_DNSSEC "Enable support for SSHFP retrieval using DNSSEC for SSH (requires OpenSSL and libval)" OFF)
option(ENABLE_COMMON_TARGETS "Define common custom target names such as 'doc' or 'uninstall', may cause conflicts when using add_subdirectory() to build this project" ON)
option(BUILD_SHARED_LIBS "By default, shared libs are enabled. Turn off for a static build." ON)
set(READ_INACTIVE_TIMEOUT 20 CACHE STRING "Maximum number of seconds waiting for new data once some data have arrived")
set(READ_ACTIVE_TIMEOUT 300 CACHE STRING "Maximum number of seconds for receiving a full message")
set(MAX_PSPOLL_THREAD_COUNT 6 CACHE STRING "Maximum number of threads that could simultaneously access a ps_poll structure")
set(TIMEOUT_STEP 100 CACHE STRING "Number of microseconds tasks are repeated until timeout elapses")
set(YANG_MODULE_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/yang/modules/libnetconf2" CACHE STRING "Directory where to copy the YANG modules to")
set(CLIENT_SEARCH_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/yang/modules" CACHE STRING "Default NC client YANG module search directory")

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
    src/session_server.c
    src/server_config.c
    src/server_config_util.c)

if(ENABLE_SSH_TLS)
    list(APPEND libsrc
        src/session_client_ssh.c
        src/session_server_ssh.c
        src/server_config_util_ssh.c
        src/session_client_tls.c
        src/session_server_tls.c
        src/server_config_util_tls.c
        src/server_config_ks.c
        src/server_config_ts.c)
    set(SSH_TLS_MACRO "#ifndef NC_ENABLED_SSH_TLS\n#define NC_ENABLED_SSH_TLS\n#endif")
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
    src/session_server_ch.h
    src/server_config.h)

# files to generate doxygen from
set(doxy_files
    doc/libnetconf.doc
    src/log.h
    src/netconf.h
    src/session.h
    src/messages_client.h
    src/messages_server.h
    src/session_client.h
    src/session_client_ch.h
    src/session_server.h
    src/session_server_ch.h
    src/server_config.h)

# source files to be covered by the 'format' target
set(format_sources
    compat/*.c
    compat/*.h*
    examples/*.c
    examples/*.h*
    src/*.c
    src/*.h
    tests/*.c)

#
# checks
#
if(ENABLE_DNSSEC AND NOT ENABLE_SSH_TLS)
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
    source_format_enable(0.77)
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

# netconf2 sourceless target - need it for linking libs, but the required sources will be added later
add_library(netconf2)

# set the shared library version
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

# header file compatibility
check_include_file("shadow.h" HAVE_SHADOW)
check_include_file("termios.h" HAVE_TERMIOS)

if(ENABLE_SSH_TLS)
    # dependencies - mbedTLS (higher preference) or OpenSSL
    find_package(MbedTLS 3.5.0)
    if (MBEDTLS_FOUND)
        # dependencies - mbedtls
        set(HAVE_MBEDTLS TRUE)
        list(APPEND libsrc src/session_mbedtls.c)
        include_directories(${MBEDTLS_INCLUDE_DIRS})
        target_link_libraries(netconf2 ${MBEDTLS_LIBRARIES})
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${MBEDTLS_LIBRARIES})
    else()
        # dependencies - openssl
        find_package(OpenSSL 3.0.0 REQUIRED)
        list(APPEND libsrc src/session_openssl.c)
        include_directories(${OPENSSL_INCLUDE_DIR})
        target_link_libraries(netconf2 ${OPENSSL_LIBRARIES})
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
    endif()

    # dependencies - libssh
    find_package(LibSSH 0.9.5 REQUIRED)
    target_link_libraries(netconf2 ${LIBSSH_LIBRARIES})
    list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBSSH_LIBRARIES})
    include_directories(${LIBSSH_INCLUDE_DIRS})

    # dependencies - libcurl
    find_package(CURL 7.30.0 REQUIRED)
    if(TARGET CURL::libcurl)
        target_link_libraries(netconf2 CURL::libcurl)
    else()
        target_link_libraries(netconf2 ${CURL_LIBRARIES})
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${CURL_LIBRARY})
        include_directories(${CURL_INCLUDE_DIRS})
    endif()

    # crypt (if not found, assume no library needs to be linked)
    if(${CMAKE_SYSTEM_NAME} MATCHES "QNX")
        set(LIBCRYPT login)
    else()
        set(LIBCRYPT crypt)
    endif()
    check_library_exists(${LIBCRYPT} crypt "" HAVE_CRYPT)
    if(HAVE_CRYPT)
        target_link_libraries(netconf2 ${LIBCRYPT})
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBCRYPT})
    endif()

    # libpam
    find_package(LibPAM)
    if(LibPAM_FOUND)
        set(HAVE_LIBPAM TRUE)

        target_link_libraries(netconf2 ${LIBPAM_LIBRARIES})
        list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBPAM_LIBRARIES})
        include_directories(${LIBPAM_INCLUDE_DIRS})

        message(STATUS "SSH Keyboard Interactive system method: Linux PAM")
    elseif(HAVE_SHADOW)
        message(STATUS "SSH Keyboard Interactive system method: local users")
    else()
        message(WARNING "SSH Keyboard Interactive system method: disabled")
    endif()

    # set compiler flag
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNC_ENABLED_SSH_TLS")
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

# function compatibility - getpeereid on QNX
if(${CMAKE_SYSTEM_NAME} MATCHES "QNX")
    target_link_libraries(netconf2 -lsocket)
    list(APPEND CMAKE_REQUIRED_LIBRARIES socket)
    list(REMOVE_ITEM CMAKE_REQUIRED_LIBRARIES pthread)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_QNX_SOURCE)
    check_symbol_exists(getpeereid "sys/types.h;unistd.h" HAVE_GETPEEREID)
    list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D_QNX_SOURCE)
endif()

# set sources
target_sources(netconf2 PRIVATE ${libsrc} ${compatsrc})

# generate config file
configure_file("${PROJECT_SOURCE_DIR}/src/config.h.in" "${PROJECT_BINARY_DIR}/src/config.h" ESCAPE_QUOTES @ONLY)

# generate and copy public header files
configure_file("${PROJECT_SOURCE_DIR}/nc_client.h.in" "${PROJECT_BINARY_DIR}/include/nc_client.h")
configure_file("${PROJECT_SOURCE_DIR}/nc_server.h.in" "${PROJECT_BINARY_DIR}/include/nc_server.h")
configure_file("${PROJECT_SOURCE_DIR}/nc_version.h.in" "${PROJECT_BINARY_DIR}/include/nc_version.h")
file(COPY ${headers} DESTINATION "${PROJECT_BINARY_DIR}/include/libnetconf2")

# install YANG modules
install(DIRECTORY "${PROJECT_SOURCE_DIR}/modules/" DESTINATION ${YANG_MODULE_DIR} FILES_MATCHING PATTERN "*.yang")

# install library
install(TARGETS netconf2 DESTINATION ${CMAKE_INSTALL_LIBDIR})

# install headers
install(FILES ${PROJECT_BINARY_DIR}/include/nc_client.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${PROJECT_BINARY_DIR}/include/nc_server.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${PROJECT_BINARY_DIR}/include/nc_version.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY ${PROJECT_BINARY_DIR}/include/libnetconf2 DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# install pkg-config file
find_package(PkgConfig)
if(PKG_CONFIG_FOUND)
    configure_file("libnetconf2.pc.in" "libnetconf2.pc" @ONLY)
    install(FILES "${PROJECT_BINARY_DIR}/libnetconf2.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
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
    if(NOT ENABLE_SSH_TLS)
        message(WARNING "Examples will not be compiled because SSH and TLS are disabled.")
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
if(ENABLE_COMMON_TARGETS)
    gen_doc("${doxy_files}" ${LIBNETCONF2_VERSION} ${LIBNETCONF2_DESCRIPTION} "")
endif()

# generate API/ABI report
if ("${BUILD_TYPE_UPPER}" STREQUAL "ABICHECK")
    lib_abi_check(netconf2 "${headers}" ${LIBNETCONF2_SOVERSION_FULL} 15fbc59efa5e6f1f7bea19ab561d03f8852caabb)
endif()

# source files to be covered by the 'format' target and a test with 'format-check' target
source_format(${format_sources})

# clean cmake cache
if(ENABLE_COMMON_TARGETS)
    add_custom_target(cleancache
            COMMAND make clean
            COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
            COMMAND rm -rf Makefile Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()

# uninstall
if(ENABLE_COMMON_TARGETS)
    add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake")
endif()
