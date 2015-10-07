cmake_minimum_required(VERSION 2.8)
project(libnetconf2 C)

# set version
set(LIBNETCONF2_MAJOR_VERSION 0)
set(LIBNETCONF2_MINOR_VERSION 0)
set(LIBNETCONF2_MICRO_VERSION 0)
set(LIBNETCONF2_VERSION ${LIBNETCONF2_MAJOR_VERSION}.${LIBNETCONF2_MINOR_VERSION}.${LIBNETCONF2_MICRO_VERSION})
set(LIBNETCONF2_SOVERSION ${LIBNETCONF2_MAJOR_VERSION}.${LIBNETCONF2_MINOR_VERSION})

# check the supported platform
if(NOT UNIX)
	message(FATAL_ERROR "Only *nix like systems are supported.")
endif()

if(NOT LIB_INSTALL_DIR)
	set(LIB_INSTALL_DIR lib)
endif()

if(NOT INCLUDE_INSTALL_DIR)
	set(INCLUDE_INSTALL_DIR include)
endif()
set(INCLUDE_INSTALL_SUBDIR ${INCLUDE_INSTALL_DIR}/libnetconf2)

# set default build type if not specified by user
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE debug)
endif()

set(CMAKE_C_FLAGS         "${CMAKE_C_FLAGS} -Wall -Wextra -fvisibility=hidden")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0")

set(libsrc
	src/io.c
	src/log.c
	src/session.c
	src/time.c)

set(headers
	src/log.h)

add_library(netconf2 SHARED ${libsrc})
set_target_properties(netconf2 PROPERTIES VERSION ${LIBNETCONF2_VERSION} SOVERSION ${LIBNETCONF2_SOVERSION})
set(LIBS ${LIBS} netconf2)

# install library
install(TARGETS netconf2 DESTINATION ${LIB_INSTALL_DIR})

# install headers
install(FILES ${CMAKE_SOURCE_DIR}/nc_client.h DESTINATION ${INCLUDE_INSTALL_DIR})
install(FILES ${CMAKE_SOURCE_DIR}/nc_server.h DESTINATION ${INCLUDE_INSTALL_DIR})
install(FILES ${CMAKE_SOURCE_DIR}/nc_transapi.h DESTINATION ${INCLUDE_INSTALL_DIR})
install(FILES ${headers} DESTINATION ${INCLUDE_INSTALL_SUBDIR})

# clean cmake cache
add_custom_target(cleancache
                  COMMAND make clean
                  COMMAND find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
                  COMMAND rm -rf Makefile Doxyfile
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
