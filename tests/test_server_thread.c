/**
 * @file test_server_thread.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 parallel server accept thread test.
 *
 * @copyright
 * Copyright (c) 2026 CESNET, z.s.p.o.
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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cmocka.h>

#include "ln2_test.h"

#define PARALLEL_SERVER_THREADS 4
#define PARALLEL_CLIENT_THREADS 4
#define NOCLIENT_ATTEMPTS 8
#define NONBLOCK_BACKOFF_USECS 1000
#define SHORT_ACCEPT_TIMEOUT 400

int TEST_PORT = 10050;
const char *TEST_PORT_STR = "10050";

struct accept_state {
    pthread_barrier_t start_barrier;
    pthread_mutex_t lock;
    int accept_timeout;
    int client_count;
    int accepted_count;
    int timeout_count;
    struct ln2_test_ctx *test_ctx;
};

struct no_client_state {
    pthread_barrier_t start_barrier;
    int accept_timeout;
    struct ln2_test_ctx *test_ctx;
};

static void *
server_thread_accept_all(void *arg)
{
    int done;
    NC_MSG_TYPE msgtype;
    struct nc_session *session = NULL;
    struct accept_state *state = arg;

    /* wait until all server and client threads are ready to start the test */
    pthread_barrier_wait(&state->start_barrier);

    while (1) {
        pthread_mutex_lock(&state->lock);
        done = state->accepted_count >= state->client_count;
        pthread_mutex_unlock(&state->lock);
        if (done) {
            break;
        }

        msgtype = nc_accept(state->accept_timeout, state->test_ctx->ctx, &session);
        if (msgtype == NC_MSG_HELLO) {
            assert_non_null(session);
            nc_session_free(session, NULL);

            pthread_mutex_lock(&state->lock);
            ++state->accepted_count;
            pthread_mutex_unlock(&state->lock);
        } else if (msgtype == NC_MSG_WOULDBLOCK) {
            assert_null(session);

            pthread_mutex_lock(&state->lock);
            ++state->timeout_count;
            pthread_mutex_unlock(&state->lock);

            usleep(NONBLOCK_BACKOFF_USECS);
        } else {
            fail_msg("Unexpected nc_accept return code %d", msgtype);
        }
    }

    return NULL;
}

static void *
client_thread_connect(void *arg)
{
    int ret = 0;
    struct nc_session *session = NULL;
    struct accept_state *state = arg;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username("parallel_client");
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/id_ed25519.pub", TESTS_DIR "/data/id_ed25519");
    assert_int_equal(ret, 0);

    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    /* wait until the server threads are ready to accept connections */
    pthread_barrier_wait(&state->start_barrier);

    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);
    nc_session_free(session, NULL);

    return NULL;
}

static void *
server_thread_timeout_only(void *arg)
{
    int i;
    NC_MSG_TYPE msgtype;
    struct nc_session *session = NULL;
    struct no_client_state *state = arg;

    /* wait until all server threads are ready to start the test */
    pthread_barrier_wait(&state->start_barrier);

    for (i = 0; i < NOCLIENT_ATTEMPTS; ++i) {
        msgtype = nc_accept(state->accept_timeout, state->test_ctx->ctx, &session);
        assert_int_equal(msgtype, NC_MSG_WOULDBLOCK);
        assert_null(session);

        usleep(NONBLOCK_BACKOFF_USECS);
    }

    return NULL;
}

static void
run_parallel_accept(void **state, int accept_timeout)
{
    int i, ret;
    pthread_t server_tids[PARALLEL_SERVER_THREADS];
    pthread_t client_tids[PARALLEL_CLIENT_THREADS];
    struct ln2_test_ctx *test_ctx = *state;
    struct accept_state accept_state;

    accept_state.accept_timeout = accept_timeout;
    accept_state.client_count = PARALLEL_CLIENT_THREADS;
    accept_state.accepted_count = 0;
    accept_state.timeout_count = 0;
    accept_state.test_ctx = test_ctx;

    /* sync all threads to start at the same time */
    ret = pthread_barrier_init(&accept_state.start_barrier, NULL,
            PARALLEL_SERVER_THREADS + PARALLEL_CLIENT_THREADS + 1);
    assert_int_equal(ret, 0);
    ret = pthread_mutex_init(&accept_state.lock, NULL);
    assert_int_equal(ret, 0);

    /* start server threads */
    for (i = 0; i < PARALLEL_SERVER_THREADS; ++i) {
        ret = pthread_create(&server_tids[i], NULL, server_thread_accept_all, &accept_state);
        assert_int_equal(ret, 0);
    }

    /* start client threads */
    for (i = 0; i < PARALLEL_CLIENT_THREADS; ++i) {
        ret = pthread_create(&client_tids[i], NULL, client_thread_connect, &accept_state);
        assert_int_equal(ret, 0);
    }

    /* wait until all threads are ready to start the test */
    pthread_barrier_wait(&accept_state.start_barrier);

    for (i = 0; i < PARALLEL_CLIENT_THREADS; ++i) {
        pthread_join(client_tids[i], NULL);
    }
    for (i = 0; i < PARALLEL_SERVER_THREADS; ++i) {
        pthread_join(server_tids[i], NULL);
    }

    /* all clients should have been accepted */
    assert_int_equal(accept_state.accepted_count, PARALLEL_CLIENT_THREADS);

    pthread_mutex_destroy(&accept_state.lock);
    pthread_barrier_destroy(&accept_state.start_barrier);
}

static void
run_timeout_only(void **state, int accept_timeout)
{
    int i, ret;
    pthread_t server_tids[PARALLEL_SERVER_THREADS];
    struct ln2_test_ctx *test_ctx = *state;
    struct no_client_state no_client_state;

    no_client_state.accept_timeout = accept_timeout;
    no_client_state.test_ctx = test_ctx;

    /* sync all threads to start at the same time */
    ret = pthread_barrier_init(&no_client_state.start_barrier, NULL, PARALLEL_SERVER_THREADS + 1);
    assert_int_equal(ret, 0);

    /* start server threads, no client threads will be started, so all threads should only experience timeouts */
    for (i = 0; i < PARALLEL_SERVER_THREADS; ++i) {
        ret = pthread_create(&server_tids[i], NULL, server_thread_timeout_only, &no_client_state);
        assert_int_equal(ret, 0);
    }

    /* wait until all threads are ready to start the test */
    pthread_barrier_wait(&no_client_state.start_barrier);

    for (i = 0; i < PARALLEL_SERVER_THREADS; ++i) {
        pthread_join(server_tids[i], NULL);
    }

    pthread_barrier_destroy(&no_client_state.start_barrier);
}

static void
test_parallel_accept_nonblocking(void **state)
{
    run_parallel_accept(state, 0);
}

static void
test_parallel_accept_timed(void **state)
{
    run_parallel_accept(state, NC_ACCEPT_TIMEOUT);
}

static void
test_parallel_accept_timeout_only_nonblocking(void **state)
{
    run_timeout_only(state, 0);
}

static void
test_parallel_accept_timeout_only_timed(void **state)
{
    run_timeout_only(state, SHORT_ACCEPT_TIMEOUT);
}

static int
setup_ssh(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    *state = test_ctx;

    /* setup server with single SSH endpoint and one user with public key authentication */
    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "parallel_client", "pubkey",
            TESTS_DIR "/data/id_ed25519.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    lyd_free_all(tree);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_parallel_accept_nonblocking, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_parallel_accept_timed, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_parallel_accept_timeout_only_nonblocking, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_parallel_accept_timeout_only_timed, setup_ssh, ln2_glob_test_teardown),
    };

    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
