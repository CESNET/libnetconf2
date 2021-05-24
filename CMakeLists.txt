cmake_minimum_required(VERSION 2.8.12)

project(libnetconf2 C)
set(LIBNETCONF2_DESC "NETCONF library in C providing API for both clients and servers.")

# include custom Modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMakeModules/")

include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(UseCompat)
include(Doc)

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
# normalize build type string
string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE_UPPER)
if ("${BUILD_TYPE_UPPER}" STREQUAL "RELEASE")
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build Type" FORCE)
elseif ("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build Type" FORCE)
elseif ("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBINFO")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build Type" FORCE)
elseif ("${BUILD_TYPE_UPPER}" STREQUAL "RELWITHDEBUG")
  set(CMAKE_BUILD_TYPE "RelWithDebug" CACHE STRING "Build Type" FORCE)
elseif ("${BUILD_TYPE_UPPER}" STREQUAL "DOCONLY")
  set(CMAKE_BUILD_TYPE "DocOnly" CACHE STRING "Build Type" FORCE)
endif()

add_compile_options(-Wall -Wextra -fvisibility=hidden -std=gnu99)
set(CMAKE_C_FLAGS_PACKAGE "-g -O2 -DNDEBUG")

# Version of the project
# Generic version of not only the library. Major version is reserved for really big changes of the project,
# minor version changes with added functionality (new tool, functionality of the tool or library, ...) and
# micro version is changed with a set of small changes or bugfixes anywhere in the project.
set(LIBNETCONF2_MAJOR_VERSION 1)
set(LIBNETCONF2_MINOR_VERSION 1)
set(LIBNETCONF2_MICRO_VERSION 45)
set(LIBNETCONF2_VERSION ${LIBNETCONF2_MAJOR_VERSION}.${LIBNETCONF2_MINOR_VERSION}.${LIBNETCONF2_MICRO_VERSION})

# Version of the library
# Major version is changed with every backward non-compatible API/ABI change in libyang, minor version changes
# with backward compatible change and micro version is connected with any internal change of the library.
set(LIBNETCONF2_MAJOR_SOVERSION 1)
set(LIBNETCONF2_MINOR_SOVERSION 3)
set(LIBNETCONF2_MICRO_SOVERSION 24)
set(LIBNETCONF2_SOVERSION_FULL ${LIBNETCONF2_MAJOR_SOVERSION}.${LIBNETCONF2_MINOR_SOVERSION}.${LIBNETCONF2_MICRO_SOVERSION})
set(LIBNETCONF2_SOVERSION ${LIBNETCONF2_MAJOR_SOVERSION})

# libyang SO version required
set(LIBYANG_DEP_SOVERSION_MAJOR 2)

# build options
option(ENABLE_SSH "Enable NETCONF over SSH support (via libssh)" ON)
option(ENABLE_TLS "Enable NETCONF over TLS support (via OpenSSL)" ON)
option(ENABLE_DNSSEC "Enable support for SSHFP retrieval using DNSSEC for SSH (requires OpenSSL and libval)" OFF)
set(READ_INACTIVE_TIMEOUT 20 CACHE STRING "Maximum number of seconds waiting for new data once some data have arrived")
set(READ_ACTIVE_TIMEOUT 300 CACHE STRING "Maximum number of seconds for receiving a full message")
set(MAX_PSPOLL_THREAD_COUNT 6 CACHE STRING "Maximum number of threads that could simultaneously access a ps_poll structure")
set(TIMEOUT_STEP 100 CACHE STRING "Number of microseconds tasks are repeated until timeout elapses")
set(YANG_MODULE_DIR "${CMAKE_INSTALL_PREFIX}/share/yang/modules" CACHE STRING "Directory with common YANG modules")

if(ENABLE_DNSSEC AND NOT ENABLE_SSH)
    message(WARNING "DNSSEC SSHFP retrieval cannot be used without SSH support.")
    set(ENABLE_DNSSEC OFF)
endif()

include_directories(${PROJECT_BINARY_DIR}/src)

# source files
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
    ${PROJECT_BINARY_DIR}/src/config.h
    src/log.h
    src/netconf.h
    src/session.h
    src/messages_client.h
    src/messages_server.h
    src/session_client.h
    src/session_client_ch.h
    src/session_server.h
    src/session_server_ch.h)

if("${BUILD_TYPE_UPPER}" STREQUAL "DOCONLY")
    libnetconf_doc()
    return()
endif()

# use compat
use_compat()

# netconf2 target
add_library(netconf2 SHARED ${libsrc} ${compatsrc})
set_target_properties(netconf2 PROPERTIES VERSION ${LIBNETCONF2_SOVERSION_FULL} SOVERSION ${LIBNETCONF2_SOVERSION})

if((CMAKE_BUILD_TYPE STREQUAL Debug) OR (CMAKE_BUILD_TYPE STREQUAL Package))
    option(ENABLE_BUILD_TESTS "Build tests" ON)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" ON)
else()
    option(ENABLE_BUILD_TESTS "Build tests" OFF)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" OFF)
endif()
option(ENABLE_COVERAGE "Build code coverage report from tests" OFF)

if(ENABLE_COVERAGE)
    find_program(PATH_GCOV NAMES gcov)
    if(NOT PATH_GCOV)
        message(WARNING "'gcov' executable not found! Disabling building code coverage report.")
        set(ENABLE_COVERAGE OFF)
    endif()

    find_program(PATH_LCOV NAMES lcov)
    if(NOT PATH_LCOV)
        message(WARNING "'lcov' executable not found! Disabling building code coverage report.")
        set(ENABLE_COVERAGE OFF)
    endif()

    find_program(PATH_GENHTML NAMES genhtml)
    if(NOT PATH_GENHTML)
        message(WARNING "'genhtml' executable not found! Disabling building code coverage report.")
        set(ENABLE_COVERAGE OFF)
    endif()

    if(NOT CMAKE_COMPILER_IS_GNUCC)
        message(WARNING "Compiler is not gcc! Coverage may break the tests!")
    endif()

    if(ENABLE_COVERAGE)
        set(CMAKE_C_FLAGS_COVERAGE "${CMAKE_C_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    endif()
endif()

# dependencies - pthread
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(netconf2 ${CMAKE_THREAD_LIBS_INIT})

# check availability for some pthread functions
set(CMAKE_REQUIRED_LIBRARIES pthread)
check_include_file(stdatomic.h HAVE_STDATOMIC)
check_function_exists(pthread_rwlockattr_setkind_np HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)

# dependencies - openssl
if(ENABLE_TLS OR ENABLE_DNSSEC OR ENABLE_SSH)
    find_package(OpenSSL REQUIRED)
    if(ENABLE_TLS)
        message(STATUS "OPENSSL found, required for TLS")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_COVERAGE} -DNC_ENABLED_TLS")
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
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_COVERAGE} -DNC_ENABLED_SSH")

    # crypt
    if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "QNX")
        target_link_libraries(netconf2 -lcrypt)
        list(APPEND CMAKE_REQUIRED_LIBRARIES crypt)
    else()
        target_link_libraries(netconf2 -llogin)
        list(APPEND CMAKE_REQUIRED_LIBRARIES login)
    endif()
endif()

# dependencies - libval
if(ENABLE_DNSSEC)
    find_package(LibVAL REQUIRED)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_COVERAGE} -DENABLE_DNSSEC")
    target_link_libraries(netconf2 ${LIBVAL_LIBRARIES})
    include_directories(${LIBVAL_INCLUDE_DIRS})
endif()

# dependencies - libyang
find_package(LibYANG ${LIBYANG_DEP_SOVERSION_MAJOR} REQUIRED)
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

# generate doxygen documentation for libnetconf2 API
libnetconf_doc()

# install library
install(TARGETS netconf2 DESTINATION ${CMAKE_INSTALL_LIBDIR})

# install headers
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nc_client.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nc_server.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${headers} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libnetconf2)

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

if(ENABLE_VALGRIND_TESTS)
    set(ENABLE_BUILD_TESTS ON)
endif()

if(ENABLE_BUILD_TESTS)
    find_package(CMocka 1.0.0)
    if(CMOCKA_FOUND)
        enable_testing()
        add_subdirectory(tests)
    endif()
endif()

configure_file("${PROJECT_SOURCE_DIR}/src/config.h.in" "${PROJECT_BINARY_DIR}/src/config.h" ESCAPE_QUOTES @ONLY)
configure_file(nc_client.h.in nc_client.h)
configure_file(nc_server.h.in nc_server.h)

# clean cmake cache
add_custom_target(cleancache
                  COMMAND make clean
                  COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
                  COMMAND rm -rf Makefile Doxyfile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# uninstall
add_custom_target(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake")
