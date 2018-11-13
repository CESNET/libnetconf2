cmake_minimum_required(VERSION 2.6)
project(libnetconf2 C)
include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckIncludeFile)

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

set(LIBNETCONF2_DESCRIPTION "NETCONF server and client library in C.")

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

# osx specific
set(CMAKE_MACOSX_RPATH TRUE)

set(INCLUDE_INSTALL_SUBDIR ${CMAKE_INSTALL_INCLUDEDIR}/libnetconf2)
set(DATA_INSTALL_DIR ${CMAKE_INSTALL_DATADIR}/libnetconf2)

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden -std=gnu11")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_PACKAGE "-g -O2 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

# set version
set(LIBNETCONF2_MAJOR_VERSION 0)
set(LIBNETCONF2_MINOR_VERSION 12)
set(LIBNETCONF2_MICRO_VERSION 31)
set(LIBNETCONF2_VERSION ${LIBNETCONF2_MAJOR_VERSION}.${LIBNETCONF2_MINOR_VERSION}.${LIBNETCONF2_MICRO_VERSION})
set(LIBNETCONF2_SOVERSION ${LIBNETCONF2_MAJOR_VERSION}.${LIBNETCONF2_MINOR_VERSION})

# build options
option(ENABLE_SSH "Enable NETCONF over SSH support (via libssh)" ON)
option(ENABLE_TLS "Enable NETCONF over TLS support (via OpenSSL)" ON)
option(ENABLE_DNSSEC "Enable support for SSHFP retrieval using DNSSEC for SSH (requires OpenSSL and libval)" OFF)
option(ENABLE_PYTHON "Include bindings for Python 3" OFF)
set(READ_INACTIVE_TIMEOUT 20 CACHE STRING "Maximum number of seconds waiting for new data once some data have arrived")
set(READ_ACTIVE_TIMEOUT 300 CACHE STRING "Maximum number of seconds for receiving a full message")
set(MAX_PSPOLL_THREAD_COUNT 6 CACHE STRING "Maximum number of threads that could simultaneously access a ps_poll structure")
set(SCHEMAS_DIR "${CMAKE_INSTALL_PREFIX}/${DATA_INSTALL_DIR}" CACHE STRING "Directory with internal lnc2 schemas")

if(ENABLE_DNSSEC AND NOT ENABLE_SSH)
    message(WARNING "DNSSEC SSHFP retrieval cannot be used without SSH support.")
    set(ENABLE_DNSSEC OFF)
endif()

# package options
find_program (DEB_BUILDER NAMES debuild)
find_program (RPM_BUILDER NAMES rpmbuild)

if (NOT DEFINED ENV{TRAVIS_BRANCH})
    execute_process(COMMAND "git" "rev-parse" "--abbrev-ref" "HEAD"
                    OUTPUT_VARIABLE GIT_BRANCH
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET
                   )
    if (NOT GIT_BRANCH)
        set(ENV{TRAVIS_BRANCH} "master")
    else()
        if (GIT_BRANCH MATCHES "master|devel")
            set(ENV{TRAVIS_BRANCH} ${GIT_BRANCH})
        else()
            set(ENV{TRAVIS_BRANCH} "master")
        endif()
    endif()
    set(GIT_BRANCH $ENV{TRAVIS_BRANCH})
endif()

if ($ENV{TRAVIS_BRANCH} STREQUAL "master")
    set(PACKAGE_NAME "libnetconf2")
    set(BRANCH "master")
    set(BUILD_TYPE "Package")
    set(CONFLICT_PACKAGE_NAME "libnetconf2-experimental")
    set(COMPAT_PACKAGES "")
else ()
    set(PACKAGE_NAME "libnetconf2-experimental")
    set(BRANCH "devel")
    set(BUILD_TYPE "debug")
    set(CONFLICT_PACKAGE_NAME "libnetconf2")
    set(COMPAT_PACKAGES "-experimental")
endif()
# change version in config files
configure_file(${PROJECT_SOURCE_DIR}/packages/libnetconf2.spec.in ${PROJECT_BINARY_DIR}/build-packages/libnetconf2.spec)
configure_file(${PROJECT_SOURCE_DIR}/packages/libnetconf2.dsc.in ${PROJECT_BINARY_DIR}/build-packages/libnetconf2.dsc)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.control.in ${PROJECT_BINARY_DIR}/build-packages/debian.control @ONLY)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.rules.in ${PROJECT_BINARY_DIR}/build-packages/debian.rules)

if (NOT DEB_BUILDER)
    message(WARNING "Missing tools (devscripts, debhelper package) for building deb package.\nYou won't be able to generate deb package from source code.\nCompiling libnetconf2 should still works fine.")
else ()
    # target for local build deb package
    add_custom_target(build-deb
                      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
                      COMMAND build-packages/local-deb.sh
    )
    configure_file(${PROJECT_SOURCE_DIR}/packages/local-deb.sh.in ${PROJECT_BINARY_DIR}/build-packages/local-deb.sh @ONLY)
endif()

if (NOT RPM_BUILDER)
    message(WARNING "Missing tools (rpm package) for building rpm package. \nYou won't be able to generate rpm package from source code.\nCompiling libnetconf2 should still works fine.")
else ()
    # target for local build rpm package
    string(REPLACE ${PROJECT_SOURCE_DIR} "." EXCLUDE_BUILD_DIR ${PROJECT_BINARY_DIR})
    add_custom_target(build-rpm
                      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
                      COMMAND build-packages/local-rpm.sh
    )
    configure_file(${PROJECT_SOURCE_DIR}/packages/local-rpm.sh.in ${PROJECT_BINARY_DIR}/build-packages/local-rpm.sh @ONLY)
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
    src/session_server.c
    src/time.c)

if(ENABLE_SSH)
    set(libsrc ${libsrc}
        src/session_client_ssh.c
        src/session_server_ssh.c)
    set(SSH_MACRO "#ifndef NC_ENABLED_SSH\n#define NC_ENABLED_SSH\n#endif")
endif()

if(ENABLE_TLS)
    set(libsrc ${libsrc}
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

# libnetconf2 target
add_library(netconf2 SHARED ${libsrc})
set_target_properties(netconf2 PROPERTIES VERSION ${LIBNETCONF2_VERSION} SOVERSION ${LIBNETCONF2_SOVERSION})

if((CMAKE_BUILD_TYPE STREQUAL debug) OR (CMAKE_BUILD_TYPE STREQUAL Package))
    option(ENABLE_BUILD_TESTS "Build tests" ON)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" ON)
else()
    option(ENABLE_BUILD_TESTS "Build tests" OFF)
    option(ENABLE_VALGRIND_TESTS "Build tests with valgrind" OFF)
endif()

# dependencies - pthread
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads REQUIRED)
target_link_libraries(netconf2 ${CMAKE_THREAD_LIBS_INIT})

# check availability for some pthread functions
set(CMAKE_REQUIRED_LIBRARIES pthread)
check_include_file(stdatomic.h HAVE_STDATOMIC)
check_function_exists(pthread_mutex_timedlock HAVE_PTHREAD_MUTEX_TIMEDLOCK)

# dependencies - openssl
if(ENABLE_TLS OR ENABLE_DNSSEC OR ENABLE_SSH)
    find_package(OpenSSL REQUIRED)
    if (ENABLE_TLS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNC_ENABLED_TLS")
    endif()
    target_link_libraries(netconf2 ${OPENSSL_LIBRARIES})
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

# dependencies - libssh
if(ENABLE_SSH)
    find_package(LibSSH 0.7.0 REQUIRED)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNC_ENABLED_SSH")
    if(LibSSH_VERSION VERSION_LESS 0.8.0)
        target_link_libraries(netconf2 "-L${LIBSSH_LIBRARY_DIR}" -lssh -lssh_threads -lcrypt)
    else()
        target_link_libraries(netconf2 "-L${LIBSSH_LIBRARY_DIR}" -lssh -lcrypt)
    endif()
    include_directories(${LIBSSH_INCLUDE_DIRS})
endif()

# dependencies - libval
if (ENABLE_DNSSEC)
    find_package(LibVAL REQUIRED)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_DNSSEC")
    target_link_libraries(netconf2 ${LIBVAL_LIBRARIES})
    include_directories(${LIBVAL_INCLUDE_DIRS})
endif()

# dependencies - libyang
find_package(LibYANG REQUIRED)
target_link_libraries(netconf2 ${LIBYANG_LIBRARIES})
include_directories(${LIBYANG_INCLUDE_DIRS})

# generate doxygen documentation for libnetconf2 API
find_package(Doxygen)
if(DOXYGEN_FOUND)
    set(DOXYGEN_SKIP_DOT TRUE)
    add_custom_target(doc
            COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    configure_file(Doxyfile.in Doxyfile)
endif()

# Python bindings
if(ENABLE_PYTHON)
    add_subdirectory(python)
endif(ENABLE_PYTHON)

# install library
install(TARGETS netconf2 DESTINATION ${CMAKE_INSTALL_LIBDIR})

# install headers
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nc_client.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nc_server.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES ${headers} DESTINATION ${INCLUDE_INSTALL_SUBDIR})

# install schemas
install(
    CODE "file(GLOB yin_schemas \"${CMAKE_SOURCE_DIR}/schemas/*.yin\")"
    CODE "file(INSTALL \${yin_schemas} DESTINATION ${CMAKE_INSTALL_PREFIX}/${DATA_INSTALL_DIR})"
)

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
    endif(CMOCKA_FOUND)
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
