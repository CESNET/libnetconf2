/**
 * @file test_client_monitoring.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 client monitoring thread test
 *
 * @copyright
 * Copyright (c) 2024 CESNET, z.s.p.o.
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

#include "ln2_test.h"
#include "session_p.h"

#include <libssh/libssh.h>

int TEST_PORT = 10050;
const char *TEST_PORT_STR = "10050";

void
monitoring_clb(struct nc_session *sess, void *user_data)
{
    pthread_barrier_t *barrier = user_data;

    /* signal the main thread that the monitoring callback was called */
    pthread_barrier_wait(barrier);
    printf("Session with ID %d disconnected by the server.\n", nc_session_get_id(sess));
}

static void *
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;
    pthread_barrier_t monitoring_barrier;

    /* initialize the barrier */
    ret = pthread_barrier_init(&monitoring_barrier, NULL, 2);
    assert_int_equal(ret, 0);

    /* start the monitoring thread */
    ret = nc_client_monitoring_thread_start(monitoring_clb, &monitoring_barrier, NULL);
    assert_int_equal(ret, 0);

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    /* set the search path for the schemas */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set the client's username */
    ret = nc_client_ssh_set_username("test_client_monitoring");
    assert_int_equal(ret, 0);

    /* add the client's key pair */
    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/key_rsa.pub", TESTS_DIR "/data/key_rsa");
    assert_int_equal(ret, 0);

    /* wait for the server to be ready and connect */
    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);

    /* wait for the monitoring thread callback to be called */
    pthread_barrier_wait(&monitoring_barrier);

    /* stop the monitoring thread */
    nc_client_monitoring_thread_stop();

    pthread_barrier_destroy(&monitoring_barrier);
    return NULL;
}

void *
server_thread(void *arg)
{
    int ret;
    NC_MSG_TYPE msgtype;
    struct nc_session *session = NULL;
    struct nc_pollsession *ps = NULL;
    struct ln2_test_ctx *test_ctx = arg;
    int fd;
    struct linger ling = {1, 0};

    ps = nc_ps_new();
    assert_non_null(ps);

    /* wait for the client to be ready to connect */
    pthread_barrier_wait(&test_ctx->barrier);

    /* accept a session and add it to the poll session structure */
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, test_ctx->ctx, &session);
    assert_int_equal(msgtype, NC_MSG_HELLO);

    /* get the session's fd */
    fd = ssh_get_fd(session->ti.libssh.session);
    assert_int_not_equal(fd, -1);

    /* set the socket to close immediately */
    ret = setsockopt(fd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
    assert_int_equal(ret, 0);

    /* add the session to the poll session */
    ret = nc_ps_add_session(ps, session);
    assert_int_equal(ret, 0);

    /* poll until the client stops sending messages */
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
    } while ((ret & NC_PSPOLL_RPC));

    /* free the session (it will close the socket -> client needs to detect this) */
    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);
    return NULL;
}

static void
test_nc_client_monitoring(void **state)
{
    int ret, i;
    pthread_t tids[2];

    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static int
setup(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx;

    /* global setup */
    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    *state = test_ctx;

    /* add endpoint */
    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    /* add hostkey */
    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &tree);
    assert_int_equal(ret, 0);

    /* add the test client */
    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_client_monitoring", "pubkey", TESTS_DIR "/data/key_rsa.pub", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    lyd_free_all(tree);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_client_monitoring, setup, ln2_glob_test_teardown)
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
