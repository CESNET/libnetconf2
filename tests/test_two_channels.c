/**
 * @file test_two_channels.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 Openning a new session on an established SSH channel test.
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
#include <unistd.h>

#include <cmocka.h>

#include "ln2_test.h"
#include "tests/config.h"

#define NC_ACCEPT_TIMEOUT 2000
#define NC_PS_POLL_TIMEOUT 2000
#define BACKOFF_TIMEOUT_USECS 100

struct ly_ctx *ctx;

int TEST_PORT = 10050;
const char *TEST_PORT_STR = "10050";

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
        msgtype = nc_accept(0, ctx, &new_session);

        if (msgtype == NC_MSG_HELLO) {
            ret = nc_ps_add_session(ps, new_session);
            assert_int_equal(ret, 0);
        }

        ret = nc_ps_poll(ps, 0, &session);

        if (ret & NC_PSPOLL_SESSION_TERM) {
            nc_ps_del_session(ps, session);
            nc_session_free(session, NULL);
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

    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/id_ed25519.pub", TESTS_DIR "/data/id_ed25519");
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username("client_1");
    assert_int_equal(ret, 0);

    session_cl1 = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session_cl1);

    ret = nc_client_ssh_set_username("client_2");
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_del_keypair(0);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/id_ecdsa521.pub", TESTS_DIR "/data/id_ecdsa521");
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
    struct lyd_node *tree = NULL;

    (void) state;

    nc_verbosity(NC_VERB_VERBOSE);

    ret = ly_ctx_new(MODULES_DIR, 0, &ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_init_ctx(&ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_config_load_modules(&ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_address_port(ctx, "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_hostkey(ctx, "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(ctx, "endpt", "client_1", "pubkey", TESTS_DIR "/data/id_ed25519.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(ctx, "endpt", "client_2", "pubkey", TESTS_DIR "/data/id_ecdsa521.pub", &tree);
    assert_int_equal(ret, 0);

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

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
