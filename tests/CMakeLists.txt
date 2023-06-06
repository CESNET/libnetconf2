# headers test for including compat.h
add_test(NAME headers
    COMMAND ${CMAKE_SOURCE_DIR}/compat/check_includes.sh ${CMAKE_SOURCE_DIR}/src/)

# format
if(${SOURCE_FORMAT_ENABLED})
    add_test(NAME format WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND cmake --build ${CMAKE_BINARY_DIR} --target format-check)
endif()

# list of all the tests that don't require SSH and TLS
set(tests test_unix_socket)

# only enable PAM tests if the version of PAM is greater than 1.4
if(LIBPAM_HAVE_CONFDIR)
    list(APPEND tests test_auth)
endif()

# set(client_tests test_client test_client_messages)

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
if(ENABLE_SSH_TLS)
    list(APPEND tests test_two_channels test_keystore test_config_new test_truststore test_ec test_ed25519 test_replace test_endpt_share_clients test_tls)
endif()

foreach(src IN LISTS libsrc)
    list(APPEND test_srcs "../${src}")
endforeach()
add_library(testobj OBJECT ${test_srcs} ${compatsrc})

foreach(test_name IN LISTS tests)
    add_executable(${test_name} $<TARGET_OBJECTS:testobj> ${test_name}.c)
    target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} ${LIBYANG_LIBRARIES} netconf2)
    target_include_directories(${test_name} PRIVATE ${CMOCKA_INCLUDE_DIR})
    set_target_properties(${test_name} PROPERTIES LINK_FLAGS "${${test_name}_wrap_link_flags}")
    add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}>)
endforeach()

# foreach(test_name IN LISTS client_tests)
#     add_executable(${test_name} $<TARGET_OBJECTS:testobj> ./client/${test_name}.c)
#     target_link_libraries(${test_name} ${CMOCKA_LIBRARIES} ${LIBYANG_LIBRARIES} netconf2)
#     target_include_directories(${test_name} PRIVATE ${CMOCKA_INCLUDE_DIR})
#     set_target_properties(${test_name} PROPERTIES LINK_FLAGS "${${test_name}_wrap_link_flags}")
#     add_test(NAME ${test_name} COMMAND $<TARGET_FILE:${test_name}>)
# endforeach()

if(ENABLE_VALGRIND_TESTS)
    foreach(test_name IN LISTS tests)
        add_test(${test_name}_valgrind valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1
            --suppressions=${PROJECT_SOURCE_DIR}/tests/library_valgrind.supp ${CMAKE_BINARY_DIR}/tests/${test_name})
    endforeach()

    # foreach(test_name IN LISTS client_tests)
    #     add_test(${test_name}_valgrind valgrind --leak-check=full --show-leak-kinds=all --error-exitcode=1
    #         --suppressions=${PROJECT_SOURCE_DIR}/tests/library_valgrind.supp ${CMAKE_BINARY_DIR}/tests/${test_name})
    # endforeach()
endif()

include_directories(${CMAKE_SOURCE_DIR}/src ${PROJECT_BINARY_DIR})
configure_file("${PROJECT_SOURCE_DIR}/tests/config.h.in" "${PROJECT_BINARY_DIR}/tests/config.h" ESCAPE_QUOTES @ONLY)

if(LIBPAM_HAVE_CONFDIR)

    #compile PAM test module
    add_library(pam_netconf SHARED ${CMAKE_SOURCE_DIR}/tests/pam/pam_netconf.c)
    set_target_properties(pam_netconf PROPERTIES PREFIX "")
    target_link_libraries(pam_netconf ${LIBPAM_LIBRARIES})

    #generate PAM configuration file
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/netconf.conf
        "#%PAM-1.4\n"
        "auth required ${CMAKE_CURRENT_BINARY_DIR}/pam_netconf.so\n"
        "account required ${CMAKE_CURRENT_BINARY_DIR}/pam_netconf.so\n"
        "password required ${CMAKE_CURRENT_BINARY_DIR}/pam_netconf.so\n"
    )

endif()
