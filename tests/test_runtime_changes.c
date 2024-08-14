/**
 * @file test_runtime_changes.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 Runtime changes test.
 *
 * @copyright
 * Copyright (c) 2023 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "ln2_test.h"

struct test_state {
    pthread_barrier_t start_barrier;
    pthread_barrier_t end_barrier;
    struct lyd_node *tree;
};

typedef enum {
    NC_TEST_EXPECT_FAIL,
    NC_TEST_EXPECT_OK
} NC_TEST_EXPECT;

typedef enum {
    NC_TEST_STATE_END,
    NC_TEST_STATE_RUN
} NC_TEST_STATE;

struct ly_ctx *ctx;
int test_running;
int expect_ok;

int TEST_PORT = 10050, TEST_PORT_2 = 10051;
const char *TEST_PORT_STR = "10050", *TEST_PORT_2_STR = "10051";

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

    /* just to wait for when new data is configured */
    pthread_barrier_wait(&state->end_barrier);

    while (1) {
        /* config ready, wait for client/server to be ready */
        pthread_barrier_wait(&state->start_barrier);
        msgtype = nc_accept(NC_ACCEPT_TIMEOUT, ctx, &session);

        if (expect_ok) {
            assert_int_equal(msgtype, NC_MSG_HELLO);
            ret = nc_ps_add_session(ps, session);
            assert_int_equal(ret, 0);

            do {
                ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
                assert_int_equal(ret & NC_PSPOLL_RPC, NC_PSPOLL_RPC);
            } while (!(ret & NC_PSPOLL_SESSION_TERM));
            nc_ps_clear(ps, 1, NULL);
        } else {
            assert_int_equal(msgtype, NC_MSG_ERROR);
        }

        if (!test_running) {
            break;
        }

        /* wait for next config */
        pthread_barrier_wait(&state->end_barrier);
    }

    nc_ps_free(ps);
    return NULL;
}

static void *
client_thread_tls(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct test_state *state = arg;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set client cert */
    ret = nc_client_tls_set_cert_key_paths(TESTS_DIR "/data/client.crt", TESTS_DIR "/data/client.key");
    assert_int_equal(ret, 0);

    /* set client ca */
    ret = nc_client_tls_set_trusted_ca_paths(NULL, TESTS_DIR "/data");
    assert_int_equal(ret, 0);

    /* just to wait for when new data is configured */
    pthread_barrier_wait(&state->end_barrier);

    while (1) {
        /* config ready, wait for client/server to be ready */
        pthread_barrier_wait(&state->start_barrier);
        session = nc_connect_tls("127.0.0.1", TEST_PORT, NULL);
        if (expect_ok) {
            assert_non_null(session);
            nc_session_free(session, NULL);
        } else {
            assert_null(session);
        }

        if (!test_running) {
            break;
        }

        /* wait for next config */
        pthread_barrier_wait(&state->end_barrier);
    }

    return NULL;
}

static void *
client_thread_ssh(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct test_state *state = arg;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    /* set ssh username */
    ret = nc_client_ssh_set_username("client");
    assert_int_equal(ret, 0);

    /* add client's key pair */
    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/id_ed25519.pub", TESTS_DIR "/data/id_ed25519");
    assert_int_equal(ret, 0);

    /* just to wait for when new data is configured */
    pthread_barrier_wait(&state->end_barrier);

    while (1) {
        /* config ready, wait for client/server to be ready */
        pthread_barrier_wait(&state->start_barrier);
        session = nc_connect_ssh("127.0.0.1", TEST_PORT_2, NULL);
        if (expect_ok) {
            assert_non_null(session);
            nc_session_free(session, NULL);
        } else {
            assert_null(session);
        }

        if (!test_running) {
            break;
        }

        /* wait for next config */
        pthread_barrier_wait(&state->end_barrier);
    }

    return NULL;
}

static inline void
configure(struct test_state *state, NC_TEST_EXPECT ok_or_fail, NC_TEST_STATE run_or_end)
{
    int ret = 0;

    /* lidl synchronization */
    pthread_barrier_wait(&state->end_barrier);

    /* apply new config */
    ret = nc_server_config_setup_data(state->tree);
    assert_int_equal(ret, 0);

    /* set test params */
    expect_ok = ok_or_fail;
    test_running = run_or_end;

    /* it just works */
    pthread_barrier_wait(&state->start_barrier);
}

static void
init_test_create_threads_tls(pthread_t tids[2], void **state)
{
    int ret;

    /* so threads dont quit immediately */
    test_running = NC_TEST_STATE_RUN;
    ret = pthread_create(&tids[0], NULL, client_thread_tls, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
    assert_int_equal(ret, 0);
}

static void
init_test_create_threads_ssh(pthread_t tids[2], void **state)
{
    int ret;

    /* so threads dont quit immediately */
    test_running = NC_TEST_STATE_RUN;
    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
    assert_int_equal(ret, 0);
}

static void
test_nc_change_tls_srv_crt(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *test_state;

    assert_non_null(state);
    test_state = *state;
    init_test_create_threads_tls(tids, state);

    ret = nc_server_config_add_tls_server_cert(ctx, "endpt_tls", TESTS_DIR "/data/client.key", NULL, TESTS_DIR "/data/client.crt", &test_state->tree);
    assert_int_equal(ret, 0);
    configure(test_state, NC_TEST_EXPECT_FAIL, NC_TEST_STATE_RUN);

    ret = nc_server_config_add_tls_server_cert(ctx, "endpt_tls", TESTS_DIR "/data/server.key", NULL, TESTS_DIR "/data/server.crt", &test_state->tree);
    assert_int_equal(ret, 0);
    configure(test_state, NC_TEST_EXPECT_OK, NC_TEST_STATE_END);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_change_tls_client_crt(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *test_state;

    assert_non_null(state);
    test_state = *state;
    init_test_create_threads_tls(tids, state);

    ret = nc_server_config_add_tls_client_cert(ctx, "endpt_tls", "client_cert", TESTS_DIR "/data/server.crt", &test_state->tree);
    assert_int_equal(ret, 0);
    configure(test_state, NC_TEST_EXPECT_FAIL, NC_TEST_STATE_RUN);

    ret = nc_server_config_add_tls_client_cert(ctx, "endpt_tls", "client_cert", TESTS_DIR "/data/client.crt", &test_state->tree);
    assert_int_equal(ret, 0);
    configure(test_state, NC_TEST_EXPECT_OK, NC_TEST_STATE_END);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_change_tls_ctn(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *test_state;

    assert_non_null(state);
    test_state = *state;
    init_test_create_threads_tls(tids, state);

    ret = nc_server_config_add_tls_ctn(ctx, "endpt_tls", 1,
            "FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF",
            NC_TLS_CTN_SPECIFIED, "invalid-fingerprint", &test_state->tree);
    assert_int_equal(ret, 0);
    configure(test_state, NC_TEST_EXPECT_FAIL, NC_TEST_STATE_RUN);

    ret = nc_server_config_add_tls_ctn(ctx, "endpt_tls", 1,
            "04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D",
            NC_TLS_CTN_SPECIFIED, "client", &test_state->tree);
    assert_int_equal(ret, 0);
    configure(test_state, NC_TEST_EXPECT_OK, NC_TEST_STATE_END);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_change_ssh_hostkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *test_state;

    assert_non_null(state);
    test_state = *state;
    init_test_create_threads_ssh(tids, state);

    ret = nc_server_config_add_ssh_hostkey(ctx, "endpt_ssh", "hostkey", TESTS_DIR "/data/server.key", NULL, &test_state->tree);
    assert_int_equal(ret, 0);
    configure(test_state, NC_TEST_EXPECT_OK, NC_TEST_STATE_RUN);

    ret = nc_server_config_add_keystore_asym_key(ctx, NC_TI_SSH, "keystore_hostkey", TESTS_DIR "/data/key_rsa", TESTS_DIR "/data/key_rsa.pub", &test_state->tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ssh_keystore_ref(ctx, "endpt_ssh", "hostkey", "keystore_hostkey", &test_state->tree);
    assert_int_equal(ret, 0);
    configure(test_state, NC_TEST_EXPECT_OK, NC_TEST_STATE_END);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_change_ssh_usr_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *test_state;

    assert_non_null(state);
    test_state = *state;
    init_test_create_threads_ssh(tids, state);

    ret = nc_server_config_add_ssh_user_pubkey(ctx, "endpt_ssh", "client", "pubkey", TESTS_DIR "/data/id_ecdsa521.pub", &test_state->tree);
    assert_int_equal(ret, 0);
    configure(test_state, NC_TEST_EXPECT_FAIL, NC_TEST_STATE_RUN);

    ret = nc_server_config_add_ssh_user_pubkey(ctx, "endpt_ssh", "client", "pubkey", TESTS_DIR "/data/id_ed25519.pub", &test_state->tree);
    assert_int_equal(ret, 0);
    configure(test_state, NC_TEST_EXPECT_OK, NC_TEST_STATE_END);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static int
setup_f(void **state)
{
    int ret;
    struct test_state *test_state;

    nc_verbosity(NC_VERB_VERBOSE);

    test_state = malloc(sizeof *test_state);
    assert_non_null(test_state);

    /* init barriers */
    ret = pthread_barrier_init(&test_state->start_barrier, NULL, 3);
    assert_int_equal(ret, 0);
    ret = pthread_barrier_init(&test_state->end_barrier, NULL, 3);
    assert_int_equal(ret, 0);

    test_state->tree = NULL;
    *state = test_state;

    ret = ly_ctx_new(MODULES_DIR, 0, &ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_init_ctx(&ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_config_load_modules(&ctx);
    assert_int_equal(ret, 0);

    /* create new address and port data */
    ret = nc_server_config_add_address_port(ctx, "endpt_tls", NC_TI_TLS, "127.0.0.1", TEST_PORT, &test_state->tree);
    assert_int_equal(ret, 0);

    /* create new server certificate data */
    ret = nc_server_config_add_tls_server_cert(ctx, "endpt_tls", TESTS_DIR "/data/server.key", NULL, TESTS_DIR "/data/server.crt", &test_state->tree);
    assert_int_equal(ret, 0);

    /* create new end entity client cert data */
    ret = nc_server_config_add_tls_client_cert(ctx, "endpt_tls", "client_cert", TESTS_DIR "/data/client.crt", &test_state->tree);
    assert_int_equal(ret, 0);

    /* create new cert-to-name */
    ret = nc_server_config_add_tls_ctn(ctx, "endpt_tls", 1,
            "04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D",
            NC_TLS_CTN_SPECIFIED, "client", &test_state->tree);
    assert_int_equal(ret, 0);

    /* create new address and port data */
    ret = nc_server_config_add_address_port(ctx, "endpt_ssh", NC_TI_SSH, "127.0.0.1", TEST_PORT_2, &test_state->tree);
    assert_int_equal(ret, 0);

    /* create new hostkey data */
    ret = nc_server_config_add_ssh_hostkey(ctx, "endpt_ssh", "hostkey", TESTS_DIR "/data/server.key", NULL, &test_state->tree);
    assert_int_equal(ret, 0);

    /* create new ssh user pubkey data */
    ret = nc_server_config_add_ssh_user_pubkey(ctx, "endpt_ssh", "client", "pubkey", TESTS_DIR "/data/id_ed25519.pub", &test_state->tree);
    assert_int_equal(ret, 0);

    ret = nc_server_init();
    assert_int_equal(ret, 0);

    /* initialize client */
    ret = nc_client_init();
    assert_int_equal(ret, 0);

    return 0;
}

static int
teardown_f(void **state)
{
    int ret = 0;
    struct test_state *test_state;

    assert_non_null(state);
    test_state = *state;

    ret = pthread_barrier_destroy(&test_state->start_barrier);
    assert_int_equal(ret, 0);
    ret = pthread_barrier_destroy(&test_state->end_barrier);
    assert_int_equal(ret, 0);

    lyd_free_all(test_state->tree);
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
        cmocka_unit_test_setup_teardown(test_nc_change_tls_srv_crt, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_change_tls_client_crt, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_change_tls_ctn, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_change_ssh_hostkey, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_change_ssh_usr_pubkey, setup_f, teardown_f),
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(2, &TEST_PORT, &TEST_PORT_STR, &TEST_PORT_2, &TEST_PORT_2_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
