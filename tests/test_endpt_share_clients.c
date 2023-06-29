/**
 * @file test_endpt_share_clients.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 Sharing clients between endpoints test
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

static void *
server_thread(void *arg)
{
    int ret;
    NC_MSG_TYPE msgtype;
    struct nc_session *session;
    struct nc_pollsession *ps;
    struct test_state *state = arg;

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
    return NULL;
}

static void *
client_thread_ssh(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct test_state *state = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    /* set directory where to search for modules */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set ssh username */
    ret = nc_client_ssh_set_username("client");
    assert_int_equal(ret, 0);

    /* add client's key pair */
    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/key_rsa.pub", TESTS_DIR "/data/key_rsa");
    assert_int_equal(ret, 0);

    /* wait for the server to reach polling */
    pthread_barrier_wait(&state->barrier);

    /* connect */
    session = nc_connect_ssh("127.0.0.1", 10005, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
nc_test_endpt_share_clients_ssh(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void *
client_thread_tls(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct test_state *state = arg;

    /* set directory where to search for modules */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set client cert */
    ret = nc_client_tls_set_cert_key_paths(TESTS_DIR "/data/client.crt", TESTS_DIR "/data/client.key");
    assert_int_equal(ret, 0);

    /* set client ca */
    ret = nc_client_tls_set_trusted_ca_paths(NULL, TESTS_DIR "/data");
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&state->barrier);
    session = nc_connect_tls("127.0.0.1", 10008, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
nc_test_endpt_share_clients_tls(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread_tls, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static int
setup_ssh(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
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

    /* create the first SSH endpoint with a client reference to the second endpoint */
    ret = nc_server_config_new_ssh_hostkey(ctx, "SSH_endpt_1", "hostkey", TESTS_DIR "/data/key_rsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_address_port(ctx, "SSH_endpt_1", NC_TI_LIBSSH, "127.0.0.1", 10005, &tree);
    assert_int_equal(ret, 0);

    ret = nc_config_new_ssh_endpoint_client_reference(ctx, "SSH_endpt_1", "SSH_endpt_2", &tree);
    assert_int_equal(ret, 0);

    /* create the second SSH endpoint with a single client */
    ret = nc_server_config_new_ssh_hostkey(ctx, "SSH_endpt_2", "hostkey", TESTS_DIR "/data/key_rsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_address_port(ctx, "SSH_endpt_2", NC_TI_LIBSSH, "127.0.0.1", 10006, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_ssh_client_auth_pubkey(ctx, "SSH_endpt_2", "client", "pubkey", TESTS_DIR "/data/key_rsa.pub", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the yang data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* initialize the server */
    ret = nc_server_init();
    assert_int_equal(ret, 0);

    lyd_free_all(tree);

    return 0;
}

static int
setup_tls(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
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

    /* create the first TLS endpoint with a single end entity client cert and a CTN entry */
    ret = nc_server_config_new_tls_server_certificate(ctx, "TLS_endpt_1", NULL,
            TESTS_DIR "/data/server.key", TESTS_DIR "/data/server.crt", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_address_port(ctx, "TLS_endpt_1", NC_TI_OPENSSL, "127.0.0.1", 10007, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_tls_client_certificate(ctx, "TLS_endpt_1", "cert_client", TESTS_DIR "/data/client.crt", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_tls_client_ca(ctx, "TLS_endpt_1", "cert_ca", TESTS_DIR "/data/serverca.pem", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_tls_ctn(ctx, "TLS_endpt_1", 1,
            "04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D",
            NC_TLS_CTN_SPECIFIED, "client", &tree);
    assert_int_equal(ret, 0);

    /* create the second TLS endpoint with a reference to the first endpoint */
    ret = nc_server_config_new_tls_server_certificate(ctx, "TLS_endpt_2", NULL,
            TESTS_DIR "/data/server.key", TESTS_DIR "/data/server.crt", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_address_port(ctx, "TLS_endpt_2", NC_TI_OPENSSL, "127.0.0.1", 10008, &tree);
    assert_int_equal(ret, 0);

    ret = nc_config_new_tls_endpoint_client_reference(ctx, "TLS_endpt_2", "TLS_endpt_1", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the yang data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* initialize the server */
    ret = nc_server_init();
    assert_int_equal(ret, 0);

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
        cmocka_unit_test_setup_teardown(nc_test_endpt_share_clients_ssh, setup_ssh, teardown_f),
        cmocka_unit_test_setup_teardown(nc_test_endpt_share_clients_tls, setup_tls, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
