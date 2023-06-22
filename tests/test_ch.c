/**
 * @file test_ch.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 Call-home test
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

#define NC_PS_POLL_TIMEOUT 2000

#define NC_ACCEPT_TIMEOUT 2000

struct ly_ctx *ctx;

struct test_state {
    pthread_barrier_t barrier;
};

/* acquire ctx cb for dispatch */
const struct ly_ctx *
ch_session_acquire_ctx_cb(void *cb_data)
{
    (void) cb_data;
    return ctx;
}

/* release ctx cb for dispatch */
void
ch_session_release_ctx_cb(void *cb_data)
{
    (void) cb_data;
    return;
}

/* new session cb for dispatch */
int
ch_new_session_cb(const char *client_name, struct nc_session *new_session, void *user_data)
{
    int ret = 0;
    struct nc_pollsession *ps = (struct nc_pollsession *)user_data;

    (void) client_name;

    ret = nc_ps_add_session(ps, new_session);
    assert_int_equal(ret, 0);
    return 0;
}

static void *
server_thread(void *arg)
{
    int ret;
    struct test_state *state = arg;
    struct nc_pollsession *ps;
    struct lyd_node *tree = NULL;

    (void) arg;

    /* prepare data for deleting the call-home client */
    ret = nc_server_config_new_del_ch_client(ctx, "ch", &tree);
    assert_int_equal(ret, 0);

    /* new poll session */
    ps = nc_ps_new();
    assert_non_null(ps);

    pthread_barrier_wait(&state->barrier);
    /* create the call-home client thread */
    ret = nc_connect_ch_client_dispatch("ch", ch_session_acquire_ctx_cb,
            ch_session_release_ctx_cb, NULL, ch_new_session_cb, ps);
    assert_int_equal(ret, 0);

    /* poll */
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
        if (ret & (NC_PSPOLL_TIMEOUT | NC_PSPOLL_NOSESSIONS)) {
            usleep(500);
        }
    } while (!(ret & NC_PSPOLL_SESSION_TERM));

    /* delete the call-home client, the thread should end */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    lyd_free_tree(tree);
    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);
    nc_server_destroy();
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
    ret = nc_client_ssh_ch_set_username("test_ch");
    assert_int_equal(ret, 0);

    /* add client's key pair */
    ret = nc_client_ssh_ch_add_keypair(TESTS_DIR "/data/id_ed25519.pub", TESTS_DIR "/data/id_ed25519");
    assert_int_equal(ret, 0);

    /* add call-home bind */
    ret = nc_client_ssh_ch_add_bind_listen("127.0.0.1", 10009);
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&state->barrier);
    /* connect */
    ret = nc_accept_callhome(NC_ACCEPT_TIMEOUT, NULL, &session);
    assert_int_equal(ret, 1);

    ret = nc_client_ssh_ch_del_bind("127.0.0.1", 10009);
    assert_int_equal(ret, 0);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_ch(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    /* client */
    ret = pthread_create(&tids[0], NULL, client_thread, *state);
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

    ret = nc_server_config_new_ch_address_port(ctx, "ch", "endpt", NC_TI_LIBSSH, "127.0.0.1", "10009", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_ssh_ch_hostkey(ctx, "ch", "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_new_ssh_ch_client_auth_pubkey(ctx, "ch", "endpt", "test_ch", "pubkey", TESTS_DIR "/data/id_ed25519.pub", &tree);
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
    ly_ctx_destroy(ctx);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_ch, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
