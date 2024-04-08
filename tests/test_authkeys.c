/**
 * @file test_authkeys.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 SSH authentication using mocked system authorized_keys
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
    const char *pubkey_path;
    const char *privkey_path;
    int expect_ok;
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

    /* only continue if we expect to authenticate successfully */
    if (state->expect_ok) {
        assert_int_equal(msgtype, NC_MSG_HELLO);
    } else {
        assert_int_equal(msgtype, NC_MSG_ERROR);
        nc_ps_free(ps);
        return NULL;
    }

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
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct test_state *state = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    /* set directory where to search for modules */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* add client's key pair */
    ret = nc_client_ssh_add_keypair(state->pubkey_path, state->privkey_path);
    assert_int_equal(ret, 0);

    /* set ssh username */
    ret = nc_client_ssh_set_username("test");
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&state->barrier);
    /* connect */
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    if (state->expect_ok) {
        assert_non_null(session);
    } else {
        assert_null(session);
    }

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_authkey_ok(void **arg)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *state;

    assert_non_null(arg);

    state = *(struct test_state **)arg;

    /* set the path to the test's authorized_keys file */
    ret = nc_server_ssh_set_authkey_path_format(TESTS_DIR "/data/authorized_keys");
    assert_int_equal(ret, 0);

    /* set pubkey and privkey path, the pubkey matches the one in authorized keys */
    state->pubkey_path = TESTS_DIR "/data/id_ed25519.pub";
    state->privkey_path = TESTS_DIR "/data/id_ed25519";

    /* expect ok result */
    state->expect_ok = 1;

    /* client */
    ret = pthread_create(&tids[0], NULL, client_thread, state);
    assert_int_equal(ret, 0);

    /* server */
    ret = pthread_create(&tids[1], NULL, server_thread, state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_authkey_bad_key(void **arg)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *state;

    assert_non_null(arg);

    state = *(struct test_state **)arg;

    /* set the path to the test's authorized_keys file */
    ret = nc_server_ssh_set_authkey_path_format(TESTS_DIR "/data/authorized_keys");
    assert_int_equal(ret, 0);

    /* set pubkey and privkey path, the pubkey doesn't match the one in authorized keys */
    state->pubkey_path = TESTS_DIR "/data/id_ecdsa521.pub";
    state->privkey_path = TESTS_DIR "/data/id_ecdsa521";

    /* expect fail */
    state->expect_ok = 0;

    /* client */
    ret = pthread_create(&tids[0], NULL, client_thread, state);
    assert_int_equal(ret, 0);

    /* server */
    ret = pthread_create(&tids[1], NULL, server_thread, state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_authkey_bad_path(void **arg)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *state;

    assert_non_null(arg);

    state = *(struct test_state **)arg;

    /* set the path to the test's authorized_keys file */
    ret = nc_server_ssh_set_authkey_path_format(TESTS_DIR "/some/bad/path");
    assert_int_equal(ret, 0);

    /* set pubkey and privkey path, the pubkey doesn't match the one in authorized keys */
    state->pubkey_path = TESTS_DIR "/data/id_ed25519.pub";
    state->privkey_path = TESTS_DIR "/data/id_ed25519";

    /* expect fail */
    state->expect_ok = 0;

    /* client */
    ret = pthread_create(&tids[0], NULL, client_thread, state);
    assert_int_equal(ret, 0);

    /* server */
    ret = pthread_create(&tids[1], NULL, server_thread, state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static int
setup_f(void **state)
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

    ret = nc_server_config_add_ssh_hostkey(ctx, "endpt", "hostkey", TESTS_DIR "/data/server.key", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_address_port(ctx, "endpt", NC_TI_LIBSSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_authkey(ctx, "endpt", "test", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* initialize server */
    ret = nc_server_init();
    assert_int_equal(ret, 0);

    /* initialize client */
    ret = nc_client_init();
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
        cmocka_unit_test_setup_teardown(test_nc_authkey_ok, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_authkey_bad_key, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_authkey_bad_path, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
