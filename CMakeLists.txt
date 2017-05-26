cmake_minimum_required(VERSION 2.6)
project(libnetconf2 C)
include(GNUInstallDirs)
include (CheckFunctionExists)

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

set(LIBNETCONF2_DESCRIPTION "NETCONF server and client library in C.")

# check the supported platform
if(NOT UNIX)
    message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

set(INCLUDE_INSTALL_SUBDIR ${CMAKE_INSTALL_INCLUDEDIR}/libnetconf2)
set(DATA_INSTALL_DIR ${CMAKE_INSTALL_DATADIR}/libnetconf2)

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE debug)
endif()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

# set version
set(LIBNETCONF2_MAJOR_VERSION 0)
set(LIBNETCONF2_MINOR_VERSION 8)
set(LIBNETCONF2_MICRO_VERSION 62)
set(LIBNETCONF2_VERSION ${LIBNETCONF2_MAJOR_VERSION}.${LIBNETCONF2_MINOR_VERSION}.${LIBNETCONF2_MICRO_VERSION})
set(LIBNETCONF2_SOVERSION ${LIBNETCONF2_MAJOR_VERSION}.${LIBNETCONF2_MINOR_VERSION})

# build options
option(ENABLE_SSH "Enable NETCONF over SSH support (via libssh)" ON)
option(ENABLE_TLS "Enable NETCONF over TLS support (via OpenSSL)" ON)
option(ENABLE_DNSSEC "Enable support for SSHFP retrieval using DNSSEC for SSH (requires OpenSSL and libval)" OFF)
set(READ_INACTIVE_TIMEOUT 20 CACHE STRING "Maximum number of seconds waiting for new data once some data have arrived")
set(READ_ACTIVE_TIMEOUT 300 CACHE STRING "Maximum number of seconds for receiving a full message")
set(MAX_PSPOLL_THREAD_COUNT 6 CACHE STRING "Maximum number of threads that could simultaneously access a ps_poll structure")

if(ENABLE_DNSSEC AND NOT ENABLE_SSH)
    message(WARNING "DNSSEC SSHFP retrieval cannot be used without SSH support.")
    set(ENABLE_DNSSEC OFF)
endif()

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

if(CMAKE_BUILD_TYPE STREQUAL debug)
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
check_function_exists(pthread_spin_lock HAVE_SPINLOCK)
check_function_exists(pthread_mutex_timedlock HAVE_PTHREAD_MUTEX_TIMEDLOCK)

# dependencies - libssh
if(ENABLE_SSH)
    find_package(LibSSH 0.6.4 REQUIRED)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNC_ENABLED_SSH ${LIBSSH_DEFINITIONS}")
    target_link_libraries(netconf2 ${LIBSSH_LIBRARIES} -L${SSH_LIBRARY} -lssh_threads -lcrypt)
    include_directories(${LIBSSH_INCLUDE_DIRS})
endif()

# dependencies - openssl
if(ENABLE_TLS OR ENABLE_DNSSEC)
    find_package(OpenSSL REQUIRED)
    if (ENABLE_TLS)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNC_ENABLED_TLS")
    endif()
    target_link_libraries(netconf2 ${OPENSSL_LIBRARIES})
    include_directories(${OPENSSL_INCLUDE_DIR})
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

configure_file("${PROJECT_SOURCE_DIR}/src/config.h.in" "${PROJECT_SOURCE_DIR}/src/config.h" ESCAPE_QUOTES @ONLY)
configure_file(nc_client.h.in nc_client.h)
configure_file(nc_server.h.in nc_server.h)

# clean cmake cache
add_custom_target(cleancache
                  COMMAND make clean
                  COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
                  COMMAND rm -rf Makefile Doxyfile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
