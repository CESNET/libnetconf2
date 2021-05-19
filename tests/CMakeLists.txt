# list of all the tests in each directory
set(tests test_io test_fd_comm test_init_destroy_client test_init_destroy_server test_client_thread)
set(client_tests test_client test_client_messages)

# add -Wl,--wrap flags
set(test test_client_ssh)
set(${test}_mock_funcs connect ssh_connect ssh_userauth_none ssh_userauth_kbdint ssh_is_connected
    ssh_channel_open_session ssh_channel_request_subsystem ssh_channel_is_close ssh_channel_write
    ssh_channel_poll_timeout ssh_userauth_password nc_handshake_io nc_ctx_check_and_fill
    ssh_userauth_try_publickey ssh_userauth_publickey nc_sock_listen_inet nc_sock_accept_binds nc_accept_callhome_ssh_sock)
set(${test}_wrap_link_flags "-Wl")
foreach(mock_func IN LISTS ${test}_mock_funcs)
    set(${test}_wrap_link_flags "${${test}_wrap_link_flags},--wrap=${mock_func}")
endforeach()

set(test test_client_tls)
set(${test}_mock_funcs connect SSL_connect nc_send_hello_io nc_handshake_io nc_ctx_check_and_fill)
set(${test}_wrap_link_flags "-Wl")
foreach(mock_func IN LISTS ${test}_mock_funcs)
    set(${test}_wrap_link_flags "${${test}_wrap_link_flags},--wrap=${mock_func}")
endforeach()

#append tests depending on SSH/TLS
if(ENABLE_SSH OR ENABLE_TLS)
    list(APPEND tests test_server_thread)
    if(ENABLE_SSH)
        list(APPEND client_tests test_client_ssh)
    endif()

    if(ENABLE_TLS)
        list(APPEND client_tests test_client_tls)
    endif()
endif()

foreach(src IN LISTS libsrc)
    list(APPEND test_srcs "../${src}")
endforeach()
add_library(testobj OBJECT ${test_srcs})

foreach(test_name IN LISTS tests)
    add_executable(${test_name} $<TARGET_OBJECTS:testobj> ${test_name}.c)
    target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} ${LIBYANG_LIBRARIES} netconf2)
    target_include_directories(${test_name} PRIVATE ${CMOCKA_INCLUDE_DIR})
    set_target_properties(${test_name} PROPERTIES LINK_FLAGS "${${test_name}_wrap_link_flags}")
    add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}>)
endforeach()

foreach(test_name IN LISTS client_tests)
    add_executable(${test_name} $<TARGET_OBJECTS:testobj> ./client/${test_name}.c)
    target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} ${LIBYANG_LIBRARIES} netconf2)
    target_include_directories(${test_name} PRIVATE ${CMOCKA_INCLUDE_DIR})
    set_target_properties(${test_name} PROPERTIES LINK_FLAGS "${${test_name}_wrap_link_flags}")
    add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}>)
endforeach()

if(ENABLE_VALGRIND_TESTS)
    find_program(valgrind_FOUND valgrind)
    if(valgrind_FOUND)
        foreach(test_name IN LISTS tests)
            add_test(${test_name}_valgrind valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1
                --suppressions=${PROJECT_SOURCE_DIR}/tests/ld.supp ${CMAKE_BINARY_DIR}/tests/${test_name})
        endforeach()

        foreach(test_name IN LISTS client_tests)
            add_test(${test_name}_valgrind valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1
                --suppressions=${PROJECT_SOURCE_DIR}/tests/ld.supp ${CMAKE_BINARY_DIR}/tests/${test_name})
        endforeach()
    else()
        message("-- valgrind executable not found! Disabling memory leaks tests")
    endif()
endif()

if(ENABLE_COVERAGE)
    # Destination
    set(COVERAGE_DIR        "${CMAKE_BINARY_DIR}/tests/code_coverage/")
    set(COVERAGE_FILE_RAW   "${CMAKE_BINARY_DIR}/tests/coverage_raw.info")
    set(COVERAGE_FILE_CLEAN "${CMAKE_BINARY_DIR}/tests/coverage_clean.info")

    # Add coverage target
    add_custom_target(coverage
        COMMENT "Generating code coverage..."
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
        # Cleanup code counters
        COMMAND "${PATH_LCOV}" --directory . --zerocounters --quiet

        # Run tests
        COMMAND "${CMAKE_CTEST_COMMAND}" --quiet

        # Capture the counters
        COMMAND "${PATH_LCOV}"
            --directory .
            --rc lcov_branch_coverage=1
            --rc 'lcov_excl_line=assert'
            --capture --quiet
            --output-file "${COVERAGE_FILE_RAW}"
        # Remove coverage of tests, system headers, etc.
        COMMAND "${PATH_LCOV}"
            --remove "${COVERAGE_FILE_RAW}" '${CMAKE_SOURCE_DIR}/tests/*'
            --rc lcov_branch_coverage=1
            --quiet --output-file "${COVERAGE_FILE_CLEAN}"
        # Generate HTML report
        COMMAND "${PATH_GENHTML}"
            --branch-coverage --function-coverage --quiet --title "libnetconf2"
            --legend --show-details --output-directory "${COVERAGE_DIR}"
            "${COVERAGE_FILE_CLEAN}"
        # Delete the counters
        COMMAND "${CMAKE_COMMAND}" -E remove
            ${COVERAGE_FILE_RAW} ${COVERAGE_FILE_CLEAN}
        )

    add_custom_command(TARGET coverage POST_BUILD
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
        COMMENT "To see the code coverage report, open ${COVERAGE_DIR}index.html"
        COMMAND ;
        )
endif()

include_directories(${CMAKE_SOURCE_DIR}/src ${PROJECT_BINARY_DIR})
configure_file("${PROJECT_SOURCE_DIR}/tests/config.h.in" "${PROJECT_BINARY_DIR}/tests/config.h" ESCAPE_QUOTES @ONLY)
