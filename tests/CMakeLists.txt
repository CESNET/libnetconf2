# headers test for including compat.h
add_test(NAME headers
    COMMAND ${CMAKE_SOURCE_DIR}/compat/check_includes.sh ${CMAKE_SOURCE_DIR}/src/)

# format
if(${SOURCE_FORMAT_ENABLED})
    add_test(NAME format WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND cmake --build ${CMAKE_BINARY_DIR} --target format-check)
endif()

foreach(src IN LISTS libsrc)
    list(APPEND test_srcs "../${src}")
endforeach()
add_library(testobj OBJECT ${test_srcs} ${compatsrc})

set(NEXT_TEST_PORT 10005)

function(libnetconf2_test)
    cmake_parse_arguments(TEST "" "NAME;PORT_COUNT" "WRAP_FUNCS" ${ARGN})

    add_executable(${TEST_NAME} $<TARGET_OBJECTS:testobj> ${TEST_NAME}.c)
    target_link_libraries(${TEST_NAME} ${CMOCKA_LIBRARIES} ${LIBYANG_LIBRARIES} netconf2)
    target_include_directories(${TEST_NAME} PRIVATE ${CMOCKA_INCLUDE_DIR})
    if(TEST_WRAP_FUNCS)
        set(wrap_link_flags "-Wl")
        foreach(mock_func IN LISTS TEST_WRAP_FUNCS)
            set(wrap_link_flags "${wrap_link_flags},--wrap=${mock_func}")
        endforeach()
        set_target_properties(${TEST_NAME} PROPERTIES LINK_FLAGS "${wrap_link_flags}")
    endif()
    target_compile_definitions(${TEST_NAME} PRIVATE "TEST_PORT=${NEXT_TEST_PORT}" "TEST_PORT_STR=\"${NEXT_TEST_PORT}\"")
    if(NOT TEST_PORT_COUNT)
        set(TEST_PORT_COUNT 1)
    endif()
    SET(PORT_INDEX 2)
    while(PORT_INDEX LESS_EQUAL TEST_PORT_COUNT)
        math(EXPR ANOTHER_PORT "${NEXT_TEST_PORT} + ${PORT_INDEX} - 1")
        target_compile_definitions(${TEST_NAME} PRIVATE "TEST_PORT_${PORT_INDEX}=${ANOTHER_PORT}" "TEST_PORT_${PORT_INDEX}_STR=\"${ANOTHER_PORT}\"")
        math(EXPR PORT_INDEX "${PORT_INDEX} + 1")
    endwhile()
    math(EXPR NEXT_TEST_PORT "${NEXT_TEST_PORT} + ${TEST_PORT_COUNT}")
    set(NEXT_TEST_PORT ${NEXT_TEST_PORT} PARENT_SCOPE)
    add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${TEST_NAME}>)

    if(ENABLE_VALGRIND_TESTS)
        add_test(${TEST_NAME}_valgrind valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1
            --suppressions=${PROJECT_SOURCE_DIR}/tests/library_valgrind.supp ${CMAKE_BINARY_DIR}/tests/${TEST_NAME})
    endif()
endfunction()

# all the tests that don't require SSH and TLS
libnetconf2_test(NAME test_unix_socket)
libnetconf2_test(NAME test_client_thread)
libnetconf2_test(NAME test_fd_comm)
libnetconf2_test(NAME test_init_destroy_client)
libnetconf2_test(NAME test_init_destroy_server)
libnetconf2_test(NAME test_io)
libnetconf2_test(NAME test_thread_messages)
libnetconf2_test(NAME test_client_messages)

# tests depending on SSH/TLS
if(ENABLE_SSH_TLS)
    libnetconf2_test(NAME test_auth)
    libnetconf2_test(NAME test_two_channels)
    libnetconf2_test(NAME test_ks_ts)
    libnetconf2_test(NAME test_ec)
    libnetconf2_test(NAME test_ed25519)
    libnetconf2_test(NAME test_replace)
    libnetconf2_test(NAME test_endpt_share_clients PORT_COUNT 4)
    libnetconf2_test(NAME test_tls)
    libnetconf2_test(NAME test_ch PORT_COUNT 2)
    libnetconf2_test(NAME test_runtime_changes PORT_COUNT 2)
    libnetconf2_test(NAME test_authkeys)
    if (LIBPAM_HAVE_CONFDIR)
        libnetconf2_test(NAME test_pam WRAP_FUNCS pam_start)
    endif()
endif()


include_directories(${CMAKE_SOURCE_DIR}/src ${PROJECT_BINARY_DIR})
configure_file("${PROJECT_SOURCE_DIR}/tests/config.h.in" "${PROJECT_BINARY_DIR}/tests/config.h" ESCAPE_QUOTES @ONLY)

# compile PAM test module
add_library(pam_netconf SHARED ${CMAKE_SOURCE_DIR}/tests/pam/pam_netconf.c)
set_target_properties(pam_netconf PROPERTIES PREFIX "")
target_link_libraries(pam_netconf ${LIBPAM_LIBRARIES})

# generate PAM configuration file
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/netconf.conf
    "#%PAM-1.4\n"
    "auth required ${CMAKE_CURRENT_BINARY_DIR}/pam_netconf.so\n"
    "account required ${CMAKE_CURRENT_BINARY_DIR}/pam_netconf.so\n"
    "password required ${CMAKE_CURRENT_BINARY_DIR}/pam_netconf.so\n"
)
