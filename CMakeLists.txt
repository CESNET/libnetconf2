cmake_minimum_required(VERSION 2.8)

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

project(libnetconf2 C)

# check the supported platform
if(NOT UNIX)
	message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE debug)
endif()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

# set version
set(LIBNETCONF2_MAJOR_VERSION 0)
set(LIBNETCONF2_MINOR_VERSION 1)
set(LIBNETCONF2_MICRO_VERSION 5)
set(LIBNETCONF2_VERSION ${LIBNETCONF2_MAJOR_VERSION}.${LIBNETCONF2_MINOR_VERSION}.${LIBNETCONF2_MICRO_VERSION})
set(LIBNETCONF2_SOVERSION ${LIBNETCONF2_MAJOR_VERSION}.${LIBNETCONF2_MINOR_VERSION})

# build options
option(ENABLE_SSH "Enable NETCONF over SSH support (via libssh)" ON)
option(ENABLE_TLS "Enable NETCONF over TLS support (via OpenSSL)" OFF)

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
	set(SSH_MACRO "#ifndef ENABLE_SSH\n#define ENABLE_SSH\n#endif")
endif()

if(ENABLE_TLS)
	set(libsrc ${libsrc}
		src/session_client_tls.c
		src/session_server_tls.c)
	set(TLS_MACRO "#ifndef ENABLE_TLS\n#define ENABLE_TLS\n#endif")
endif()

set(headers
	src/log.h
	src/netconf.h
	src/session.h
	src/messages_client.h
	src/messages_server.h
	src/session_client.h
    src/session_server.h)

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

# dependencies - libssh
if(ENABLE_SSH)
	find_package(LibSSH 0.6.4 REQUIRED)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_SSH ${LIBSSH_DEFINITIONS}")
	target_link_libraries(netconf2 ${LIBSSH_LIBRARIES} -lssh_threads -lcrypt)
	include_directories(${LIBSSH_INCLUDE_DIRS})
endif()

# dependencies - openssl
if(ENABLE_TLS)
	find_package(OpenSSL REQUIRED)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DENABLE_TLS")
	target_link_libraries(netconf2 ${OPENSSL_LIBRARIES})
	include_directories(${OPENSSL_INCLUDE_DIR})
endif()

# dependencies - libyang
find_package(LibYANG REQUIRED)
target_link_libraries(netconf2 ${LIBYANG_LIBRARIES})
include_directories(${LIBYANG_INCLUDE_DIRS})

if(NOT LIB_INSTALL_DIR)
	set(LIB_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/lib)
endif()

if(NOT INCLUDE_INSTALL_DIR)
	set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/include)
endif()
set(INCLUDE_INSTALL_SUBDIR ${INCLUDE_INSTALL_DIR}/libnetconf2)

if(NOT DATA_INSTALL_DIR)
	set(DATA_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/share/libnetconf2)
endif()

# install library
install(TARGETS netconf2 DESTINATION ${LIB_INSTALL_DIR})

# install headers
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nc_client.h DESTINATION ${INCLUDE_INSTALL_DIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nc_server.h DESTINATION ${INCLUDE_INSTALL_DIR})
#install(FILES ${CMAKE_CURRENT_BINARY_DIR}/nc_transapi.h DESTINATION ${INCLUDE_INSTALL_DIR})
install(FILES ${headers} DESTINATION ${INCLUDE_INSTALL_SUBDIR})

# install schemas
install(
	CODE "file(GLOB yin_schemas \"${CMAKE_SOURCE_DIR}/schemas/*.yin\")"
	CODE "file(INSTALL \${yin_schemas} DESTINATION ${DATA_INSTALL_DIR})"
)

if(ENABLE_VALGRIND_TESTS)
	set(ENABLE_BUILD_TESTS ON)
endif()

if(ENABLE_BUILD_TESTS)
	enable_testing()
	add_subdirectory(tests)
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
