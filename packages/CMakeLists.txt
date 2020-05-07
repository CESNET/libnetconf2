set(PACKAGE "libnetconf2")
set(PACKAGE_BRIEF "libnetconf2 library")
set(PACKAGE_DESC ${LIBNETCONF2_DESC})
set(PACKAGE_DBG_DESC "libnetconf2 library debug symbols.")
set(PACKAGE_DEV_BRIEF "Headers of libnetconf2 library")
set(PACKAGE_DEV_DESC "libnetconf2 library headers for C.")

set(GITHUB_URL "https://github.com/cesnet/libnetconf2")

find_program(DEB_BUILDER NAMES debuild)
find_program(RPM_BUILDER NAMES rpmbuild)

# setup package build
configure_file(${PROJECT_SOURCE_DIR}/packages/${PACKAGE}.spec.in ${PROJECT_BINARY_DIR}/build-packages/${PACKAGE}.spec)
configure_file(${PROJECT_SOURCE_DIR}/packages/${PACKAGE}.dsc.in ${PROJECT_BINARY_DIR}/build-packages/${PACKAGE}.dsc)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.control.in ${PROJECT_BINARY_DIR}/build-packages/debian.control @ONLY)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.rules.in ${PROJECT_BINARY_DIR}/build-packages/debian.rules)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.compat
               ${PROJECT_BINARY_DIR}/build-packages/debian.compat COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.copyright
               ${PROJECT_BINARY_DIR}/build-packages/debian.copyright COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/packages/${PACKAGE}.rpmlintrc
               ${PROJECT_BINARY_DIR}/build-packages/${PACKAGE}.rpmlintrc COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.${PACKAGE}.install
               ${PROJECT_BINARY_DIR}/build-packages/debian.${PACKAGE}.install COPYONLY)
configure_file(${PROJECT_SOURCE_DIR}/packages/debian.${PACKAGE}-dev.install
               ${PROJECT_BINARY_DIR}/build-packages/debian.${PACKAGE}-dev.install COPYONLY)

if(NOT DEB_BUILDER)
    message(STATUS "Missing tools (devscripts, debhelper package) for building DEB package.")
else()
    # target for local build deb package
    message(STATUS "To build local DEB package, use \"build-deb\" target.")
    add_custom_target(build-deb
                      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
                      COMMAND build-packages/local-deb.sh
    )
    configure_file(${PROJECT_SOURCE_DIR}/packages/local-deb.sh.in ${PROJECT_BINARY_DIR}/build-packages/local-deb.sh @ONLY)
endif()

if(NOT RPM_BUILDER)
    message(STATUS "Missing tools (rpm package) for building RPM package.")
else()
    # target for local build rpm package
    message(STATUS "To build local RPM package, use \"build-rpm\" target.")
    string(REPLACE ${PROJECT_SOURCE_DIR} "." EXCLUDE_BUILD_DIR ${PROJECT_BINARY_DIR})
    add_custom_target(build-rpm
                      WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
                      COMMAND build-packages/local-rpm.sh
    )
    configure_file(${PROJECT_SOURCE_DIR}/packages/local-rpm.sh.in ${PROJECT_BINARY_DIR}/build-packages/local-rpm.sh @ONLY)
endif()
