/**
 * @file test_ec.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 EC hostkey test
 *
 * @copyright
 * Copyright (c) 2023 CESNET, z.s.p.o.
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

#include <cmocka.h>

#include "tests/config.h"

#define NC_ACCEPT_TIMEOUT 2000
#define NC_PS_POLL_TIMEOUT 2000

struct ly_ctx *ctx;

struct test_state {
    pthread_barrier_t barrier;
};

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
        "                                    <public-key>MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEje+TM7/KHx8zJ4HtVcehRNg6ZXLjeWpXWI7m2x9EeKBX+TgYElq0mIESw88s1HnPrT5AdaWeZymD+MSxd4dzwA==</public-key>\n"
        "                                    <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ec-private-key-format</private-key-format>\n"
        "                                    <cleartext-private-key>MHcCAQEEIGAq2oW59feizNqqUDqDyuLLQ7f1Y1WQHo5KGVuFhwQ/oAoGCCqGSM49AwEHoUQDQgAEje+TM7/KHx8zJ4HtVcehRNg6ZXLjeWpXWI7m2x9EeKBX+TgYElq0mIESw88s1HnPrT5AdaWeZymD+MSxd4dzwA==</cleartext-private-key>\n"
        "                                </local-definition>\n"
        "                            </public-key>\n"
        "                        </host-key>\n"
        "                    </server-identity>\n"
        "                    <client-authentication>\n"
        "                        <users>\n"
        "                            <user>\n"
        "                                <name>test_ec</name>\n"
        "                                <public-keys>\n"
        "                                    <local-definition>\n"
        "                                        <public-key>\n"
        "                                            <name>test</name>\n"
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
        "                            <host-key-alg xmlns:sshpka=\"urn:ietf:params:xml:ns:yang:iana-ssh-public-key-algs\">sshpka:ecdsa-sha2-nistp256</host-key-alg>\n"
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
    int ret;
    NC_MSG_TYPE msgtype;
    struct nc_session *session;
    struct nc_pollsession *ps;
    struct test_state *state = arg;

    (void) arg;

    ps = nc_ps_new();
    assert_non_null(ps);

    /* accept a session and add it to the poll session structure */
    pthread_barrier_wait(&state->barrier);
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, ctx, &session);
    assert_int_equal(msgtype, NC_MSG_HELLO);

    ret = nc_ps_add_session(ps, session);
    assert_int_equal(ret, 0);

    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
        assert_int_equal(ret & NC_PSPOLL_RPC, NC_PSPOLL_RPC);
    } while (!(ret & NC_PSPOLL_SESSION_TERM));

    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);
    nc_thread_destroy();
    return NULL;
}

static int
ssh_hostkey_check_clb(const char *hostname, ssh_session session, void *priv)
{
    (void)hostname;
    (void)session;
    (void)priv;
    /* skip the knownhost check */

    return 0;
}

static void *
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct test_state *state = arg;

    /* set directory where to search for modules */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set ssh username */
    ret = nc_client_ssh_set_username("test_ec");
    assert_int_equal(ret, 0);

    /* add client's key pair */
    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/key_rsa.pub", TESTS_DIR "/data/key_rsa");
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&state->barrier);
    /* connect */
    session = nc_connect_ssh("127.0.0.1", 10005, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    nc_thread_destroy();
    return NULL;
}

static void
test_nc_ec(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
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
    struct test_state *test_state;

    nc_verbosity(NC_VERB_VERBOSE);

    /* init barrier */
    test_state = malloc(sizeof *test_state);
    assert_non_null(test_state);

    ret = pthread_barrier_init(&test_state->barrier, NULL, 2);
    assert_int_equal(ret, 0);

    *state = test_state;

    /* create new context */
    ret = ly_ctx_new(MODULES_DIR, 0, &ctx);
    assert_int_equal(ret, 0);

    /* load default modules into context */
    ret = nc_server_init_ctx(&ctx);
    assert_int_equal(ret, 0);

    /* load ietf-netconf-server module and it's imports into context */
    ret = nc_server_config_load_modules(&ctx);
    assert_int_equal(ret, 0);

    /* parse yang data */
    ret = lyd_parse_data_mem(ctx, data, LYD_XML, LYD_PARSE_NO_STATE | LYD_PARSE_STRICT, LYD_VALIDATE_NO_STATE, &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup(tree);
    assert_int_equal(ret, 0);

    /* initialize client */
    nc_client_init();

    /* initialize server */
    ret = nc_server_init();
    assert_int_equal(ret, 0);

    /* skip the knownhost check */
    nc_client_ssh_set_auth_hostkey_check_clb(ssh_hostkey_check_clb, NULL);

    lyd_free_all(tree);

    return 0;
}

static int
teardown_f(void **state)
{
    int ret = 0;
    struct test_state *test_state;

    assert_non_null(state);
    test_state = *state;

    ret = pthread_barrier_destroy(&test_state->barrier);
    assert_int_equal(ret, 0);

    free(*state);
    nc_client_destroy();
    nc_server_destroy();
    ly_ctx_destroy(ctx);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_ec, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
