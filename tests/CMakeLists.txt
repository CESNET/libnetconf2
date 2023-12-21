# headers test for including compat.h
add_test(NAME headers
    COMMAND ${CMAKE_SOURCE_DIR}/compat/check_includes.sh ${CMAKE_SOURCE_DIR}/src/)

# format
if(${SOURCE_FORMAT_ENABLED})
    add_test(NAME format WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND cmake --build ${CMAKE_BINARY_DIR} --target format-check)
endif()

# list of all the tests that don't require SSH and TLS
set(tests test_unix_socket test_client_thread test_fd_comm test_init_destroy_client test_init_destroy_server
        test_io test_thread_messages test_client_messages)

#append tests depending on SSH/TLS
if(ENABLE_SSH_TLS)
    list(APPEND tests test_auth test_two_channels test_ks_ts test_ec
        test_ed25519 test_replace test_endpt_share_clients test_tls test_crl test_ch
        test_runtime_changes test_client_ssh test_client_tls test_authkeys)

    if (LIBPAM_HAVE_CONFDIR)
        list(APPEND tests test_pam)
    endif()
endif()

foreach(src IN LISTS libsrc)
    list(APPEND test_srcs "../${src}")
endforeach()
add_library(testobj OBJECT ${test_srcs} ${compatsrc})

# set the mocked functions for the tests
set(mock_tests test_client_ssh test_client_tls test_pam)
set(test_client_ssh_mock_funcs connect ssh_connect ssh_userauth_none ssh_userauth_kbdint ssh_is_connected
    ssh_channel_open_session ssh_channel_request_subsystem ssh_channel_is_close ssh_channel_write
    ssh_channel_poll_timeout ssh_userauth_password nc_handshake_io nc_ctx_check_and_fill
    ssh_userauth_try_publickey ssh_userauth_publickey nc_sock_listen_inet nc_sock_accept_binds nc_accept_callhome_ssh_sock)
set(test_client_tls_mock_funcs connect SSL_connect nc_send_hello_io nc_handshake_io nc_ctx_check_and_fill)
set(test_pam_mock_funcs pam_start)

# add -Wl,--wrap flags to tests that require it
set(moc_funcs test_client_ssh_mock_funcs test_client_tls_mock_funcs test_pam_mock_funcs)
foreach(mock_test IN LISTS mock_tests)
    set(${mock_test}_wrap_link_flags "-Wl")
    foreach(mock_func IN LISTS ${mock_test}_mock_funcs)
        set(${mock_test}_wrap_link_flags "${${mock_test}_wrap_link_flags},--wrap=${mock_func}")
    endforeach()
endforeach()

foreach(test_name IN LISTS tests)
    add_executable(${test_name} $<TARGET_OBJECTS:testobj> ${test_name}.c)
    target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} ${LIBYANG_LIBRARIES} netconf2)
    target_include_directories(${test_name} PRIVATE ${CMOCKA_INCLUDE_DIR})
    set_target_properties(${test_name} PROPERTIES LINK_FLAGS "${${test_name}_wrap_link_flags}")
    add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}>)
endforeach()

if(ENABLE_VALGRIND_TESTS)
    foreach(test_name IN LISTS tests)
        add_test(${test_name}_valgrind valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1
            --suppressions=${PROJECT_SOURCE_DIR}/tests/library_valgrind.supp ${CMAKE_BINARY_DIR}/tests/${test_name})
    endforeach()
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
