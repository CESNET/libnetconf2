/**
 * @file test_keystore.c
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

#include <pthread.h>
#include <setjmp.h>
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

static char *
auth_password(const char *username, const char *hostname, void *priv)
{
    (void) username;
    (void) hostname;
    (void) priv;

    /* set the reply to password authentication */
    return strdup("testpassword123");
}

static void *
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct test_state *state = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username("client");
    assert_int_equal(ret, 0);

    nc_client_ssh_set_auth_password_clb(auth_password, NULL);

    pthread_barrier_wait(&state->barrier);
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_config_new(void **state)
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
    struct lyd_node *tree = NULL;
    struct test_state *test_state;

    nc_verbosity(NC_VERB_VERBOSE);

    /* init barrier */
    test_state = malloc(sizeof *test_state);
    assert_non_null(test_state);

    ret = pthread_barrier_init(&test_state->barrier, NULL, 2);
    assert_int_equal(ret, 0);

    *state = test_state;

    /* new context */
    ret = ly_ctx_new(MODULES_DIR, 0, &ctx);
    assert_int_equal(ret, 0);

    /* initialize the context by loading default modules */
    ret = nc_server_init_ctx(&ctx);
    assert_int_equal(ret, 0);

    /* load ietf-netconf-server module and it's imports */
    ret = nc_server_config_load_modules(&ctx);
    assert_int_equal(ret, 0);

    /* create new hostkey data */
    ret = nc_server_config_add_ssh_hostkey(ctx, "endpt", "hostkey", TESTS_DIR "/data/server.key", NULL, &tree);
    assert_int_equal(ret, 0);

    /* create new address and port data */
    ret = nc_server_config_add_address_port(ctx, "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    /* create the host-key algorithms data */
    ret = nc_server_config_add_ssh_host_key_algs(ctx, "endpt", &tree, 1, "rsa-sha2-512");
    assert_int_equal(ret, 0);

    /* create the client authentication data, password only */
    ret = nc_server_config_add_ssh_user_password(ctx, "endpt", "client", "testpassword123", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

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
        cmocka_unit_test_setup_teardown(test_nc_config_new, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
