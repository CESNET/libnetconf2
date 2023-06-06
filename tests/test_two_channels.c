/**
 * @file test_pam.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 Linux PAM keyboard-interactive authentication test
 *
 * @copyright
 * Copyright (c) 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include "tests/config.h"

#define NC_ACCEPT_TIMEOUT 2000
#define NC_PS_POLL_TIMEOUT 2000
#define BACKOFF_TIMEOUT_USECS 100

struct ly_ctx *ctx;
int flag = 0;

const char *data =
        "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\" xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
        "    <listen yang:operation=\"create\">\n"
        "        <idle-timeout>10</idle-timeout>\n"
        "        <endpoint>\n"
        "            <name>default-ssh</name>\n"
        "            <ssh>\n"
        "                <tcp-server-parameters>\n"
        "                    <local-address>127.0.0.1</local-address>\n"
        "                    <local-port>10005</local-port>\n"
        "                </tcp-server-parameters>\n"
        "                <ssh-server-parameters>\n"
        "                    <server-identity>\n"
        "                        <host-key>\n"
        "                            <name>key</name>\n"
        "                            <public-key>\n"
        "                                <local-definition>\n"
        "                                    <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>\n"
        "                                    <public-key>MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6ojtjfDmvyQP1ZkIwBpr97eKDuebvpoglRHRdvVuTpf/gU1VArAQmwGh05i6lm8TkVl1noMlIxLJDcWslaeVn6KyvsX0HhsQtXwqPqwka5UCv6alwf/ivAvcNpcX1j0t/uIGCI4dSiKnzQCyf0FTirzQkjrDZUd3meDhNQTruCalGV4gfNWIq3e1oGuwAn1tLlu9oTrE4HzMpgbNEU6wNmsSqpwGxUhYLoSaM7b0dLmqP+ZczSS0Uac0PFNkehGQ2CYIT80f580o4XGtoLCUUGkp6YCTL4Z2CeBEaJABWjDIDH+dKYIUBqUpz4Th12gXAP+h+3qI6+9eppeHrfrzARDsfLjwUNxQJse1QSArjAytf0FKtGHrORc7W0TiCFvR0zaoUNLTKk7enTiRQ9rfWZOAu44fUvPCaXDE6zXXeaVgoKCo4VHlho36erUcjlEBM+jk28IykbZGtBb6igKvYa1tPSgeYm/zJoFVjQcnr14uci/ft1+Na+hOIEoEEiKxcAPk2b2vBKNlRIW7WLJ3u7ZiuQEJTNm6+3cE4+lfwaBCBqBToE+dpzvoUXoMyFFReUFd1O5axu4fXgt00jMaOQxmE0v9OmR/pL/PWIflVF4Zz5yVONYaDVc7l+veY0oEZruEPJ0hlEgxuCzLrcMhjufl2qE2Q7fQIaav/1NqBVkCAwEAAQ==</public-key>\n"
        "                                    <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>\n"
        "                                    <cleartext-private-key>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</cleartext-private-key>\n"
        "                                </local-definition>\n"
        "                            </public-key>\n"
        "                        </host-key>\n"
        "                    </server-identity>\n"
        "                    <client-authentication>\n"
        "                        <users>\n"
        "                            <user>\n"
        "                                <name>test1</name>\n"
        "                                <public-keys>\n"
        "                                    <local-definition>\n"
        "                                        <public-key>\n"
        "                                            <name>client</name>\n"
        "                                            <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>\n"
        "                                            <public-key>AAAAB3NzaC1yc2EAAAADAQABAAABAQDPavVALiM7QwTIUAndO8E9GOkSDQWjuEwkzbJ3kOBPa7kkq71UOZFeecDjFb9eipkljfFys/JYHGQaYVF8/svT0KV5h7HlutRdF6yvqSEbjpbTORb27pdHX3iFEyDCwCIoq9vMeX+wyXnteyn01GpIL0ig0WAnvkqX/SPjuplX5ZItUSr0MhXM7fNSX50BD6G8IO0/djUcdMUcjTjGv73SxB9ZzLvxnhXuUJbzEJJJLj6qajyEIVaJSa73vA33JCD8qzarrsuITojVLPDFmeHwSAoB5dP86yop6e6ypuXzKxxef6yNXcE8oTj8UFYBIXsgIP2nBvWk41EaK0Vk3YFl</public-key>\n"
        "                                        </public-key>\n"
        "                                    </local-definition>\n"
        "                                </public-keys>\n"
        "                            </user>\n"
        "                            <user>\n"
        "                                <name>test2</name>\n"
        "                                <public-keys>\n"
        "                                    <local-definition>\n"
        "                                        <public-key>\n"
        "                                            <name>client</name>\n"
        "                                            <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>\n"
        "                                            <public-key>AAAAB3NzaC1yc2EAAAADAQABAAABAQDPavVALiM7QwTIUAndO8E9GOkSDQWjuEwkzbJ3kOBPa7kkq71UOZFeecDjFb9eipkljfFys/JYHGQaYVF8/svT0KV5h7HlutRdF6yvqSEbjpbTORb27pdHX3iFEyDCwCIoq9vMeX+wyXnteyn01GpIL0ig0WAnvkqX/SPjuplX5ZItUSr0MhXM7fNSX50BD6G8IO0/djUcdMUcjTjGv73SxB9ZzLvxnhXuUJbzEJJJLj6qajyEIVaJSa73vA33JCD8qzarrsuITojVLPDFmeHwSAoB5dP86yop6e6ypuXzKxxef6yNXcE8oTj8UFYBIXsgIP2nBvWk41EaK0Vk3YFl</public-key>\n"
        "                                        </public-key>\n"
        "                                    </local-definition>\n"
        "                                </public-keys>\n"
        "                            </user>\n"
        "                        </users>\n"
        "                    </client-authentication>\n"
        "                    <transport-params>\n"
        "                        <host-key>\n"
        "                            <host-key-alg xmlns:sshpka=\"urn:ietf:params:xml:ns:yang:iana-ssh-public-key-algs\">sshpka:rsa-sha2-512</host-key-alg>\n"
        "                        </host-key>\n"
        "                        <key-exchange>\n"
        "                            <key-exchange-alg xmlns:sshkea=\"urn:ietf:params:xml:ns:yang:iana-ssh-key-exchange-algs\">sshkea:curve25519-sha256</key-exchange-alg>\n"
        "                        </key-exchange>\n"
        "                        <encryption>\n"
        "                            <encryption-alg xmlns:sshea=\"urn:ietf:params:xml:ns:yang:iana-ssh-encryption-algs\">sshea:aes256-ctr</encryption-alg>\n"
        "                        </encryption>\n"
        "                        <mac>\n"
        "                            <mac-alg xmlns:sshma=\"urn:ietf:params:xml:ns:yang:iana-ssh-mac-algs\">sshma:hmac-sha2-512</mac-alg>\n"
        "                        </mac>\n"
        "                    </transport-params>\n"
        "                </ssh-server-parameters>\n"
        "            </ssh>\n"
        "        </endpoint>\n"
        "    </listen>\n"
        "</netconf-server>\n";

static void *
server_thread(void *arg)
{
    int ret, del_session_count = 0, sleep_count = 0;
    NC_MSG_TYPE msgtype;
    struct nc_session *session, *new_session;
    struct nc_pollsession *ps;

    (void) arg;

    ps = nc_ps_new();
    assert_non_null(ps);

    while (del_session_count < 2) {
        msgtype = nc_accept(0, ctx, &session);

        if (msgtype == NC_MSG_HELLO) {
            ret = nc_ps_add_session(ps, session);
            assert_int_equal(ret, 0);
        }

        ret = nc_ps_poll(ps, 0, &new_session);

        if (ret & NC_PSPOLL_SESSION_TERM) {
            nc_ps_del_session(ps, new_session);
            nc_session_free(new_session, NULL);
            del_session_count++;
        } else if (ret & NC_PSPOLL_SSH_CHANNEL) {
            msgtype = nc_session_accept_ssh_channel(session, &new_session);
            if (msgtype == NC_MSG_HELLO) {
                ret = nc_ps_add_session(ps, new_session);
                assert_int_equal(ret, 0);
            }
        } else if (ret & NC_PS_POLL_TIMEOUT) {
            usleep(BACKOFF_TIMEOUT_USECS);
            sleep_count++;
            assert_int_not_equal(sleep_count, 50000);
        }
    }

    nc_ps_free(ps);
    return NULL;
}

static void *
client_thread(void *arg)
{
    (void) arg;
    int ret;
    struct nc_session *session_cl1, *session_cl2;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, 1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, -1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, -1);

    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/key_rsa.pub", TESTS_DIR "/data/key_rsa");
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username("test1");
    assert_int_equal(ret, 0);

    session_cl1 = nc_connect_ssh("127.0.0.1", 10005, NULL);
    assert_non_null(session_cl1);

    ret = nc_client_ssh_set_username("test2");
    assert_int_equal(ret, 0);

    session_cl2 = nc_connect_ssh_channel(session_cl1, NULL);
    assert_non_null(session_cl2);

    nc_client_destroy();
    nc_session_free(session_cl1, NULL);
    nc_session_free(session_cl2, NULL);
    return NULL;
}

static void
test_nc_two_channels(void **state)
{
    int ret, i;
    pthread_t tids[2];

    (void) state;

    ret = pthread_create(&tids[0], NULL, client_thread, NULL);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, server_thread, NULL);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static int
setup_f(void **state)
{
    int ret;
    struct lyd_node *tree;

    (void) state;

    nc_verbosity(NC_VERB_VERBOSE);

    ret = ly_ctx_new(MODULES_DIR, 0, &ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_init_ctx(&ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_config_load_modules(&ctx);
    assert_int_equal(ret, 0);

    ret = lyd_parse_data_mem(ctx, data, LYD_XML, LYD_PARSE_NO_STATE | LYD_PARSE_STRICT, LYD_VALIDATE_NO_STATE, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    ret = nc_server_init();
    assert_int_equal(ret, 0);

    lyd_free_all(tree);

    return 0;
}

static int
teardown_f(void **state)
{
    (void) state;

    nc_server_destroy();
    ly_ctx_destroy(ctx);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_two_channels, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
