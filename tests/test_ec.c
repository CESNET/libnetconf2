/**
 * @file test_ec.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 EC keys authentication test
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
    const char *client_username;
    const char *client_privkey;
    const char *client_pubkey;
};

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

    /* set ssh username */
    ret = nc_client_ssh_set_username(state->client_username);
    assert_int_equal(ret, 0);

    /* add client's key pair */
    ret = nc_client_ssh_add_keypair(state->client_pubkey, state->client_privkey);
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&state->barrier);
    /* connect */
    session = nc_connect_ssh("127.0.0.1", 10009, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_ec256(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *client;

    /* set specific data for the client */
    assert_non_null(state);
    client = *state;

    /* client */
    client->client_username = "test_ec256";
    client->client_pubkey = TESTS_DIR "/data/id_ecdsa256.pub";
    client->client_privkey = TESTS_DIR "/data/id_ecdsa256";
    ret = pthread_create(&tids[0], NULL, client_thread, client);
    assert_int_equal(ret, 0);

    /* server */
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_ec384(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *client;

    /* set specific data for the client */
    assert_non_null(state);
    client = *state;

    /* client */
    client->client_username = "test_ec384";
    client->client_pubkey = TESTS_DIR "/data/id_ecdsa384.pub";
    client->client_privkey = TESTS_DIR "/data/id_ecdsa384";
    ret = pthread_create(&tids[0], NULL, client_thread, client);
    assert_int_equal(ret, 0);

    /* server */
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_ec521(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *client;

    /* set specific data for the client */
    assert_non_null(state);
    client = *state;

    /* client */
    client->client_username = "test_ec521";
    client->client_pubkey = TESTS_DIR "/data/id_ecdsa521.pub";
    client->client_privkey = TESTS_DIR "/data/id_ecdsa521";
    ret = pthread_create(&tids[0], NULL, client_thread, client);
    assert_int_equal(ret, 0);

    /* server */
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

    /* create new context */
    ret = ly_ctx_new(MODULES_DIR, 0, &ctx);
    assert_int_equal(ret, 0);

    /* load default modules into context */
    ret = nc_server_init_ctx(&ctx);
    assert_int_equal(ret, 0);

    /* load ietf-netconf-server module and it's imports into context */
    ret = nc_server_config_load_modules(&ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_ssh_hostkey(ctx, "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_address_port(ctx, "endpt", NC_TI_LIBSSH, "127.0.0.1", "10009", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_ssh_client_auth_pubkey(ctx, "endpt", "test_ec256", "pubkey", TESTS_DIR "/data/id_ecdsa256.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_ssh_client_auth_pubkey(ctx, "endpt", "test_ec384", "pubkey", TESTS_DIR "/data/id_ecdsa384.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_ssh_client_auth_pubkey(ctx, "endpt", "test_ec521", "pubkey", TESTS_DIR "/data/id_ecdsa521.pub", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    /* initialize server */
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
        cmocka_unit_test_setup_teardown(test_nc_ec256, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_ec384, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_ec521, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
