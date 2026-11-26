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

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>

#include "ln2_test.h"

/* how long to wait for the monitoring callback */
#define TEST_CLB_TIMEOUT_S 5

/* the session passed to the monitoring callback, guarded by clb_lock */
static pthread_mutex_t clb_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t clb_cond = PTHREAD_COND_INITIALIZER;
static struct nc_session *clb_session;

/**
 * @brief Monitoring callback, remembers the disconnected session.
 */
static void
test_monitoring_clb(struct nc_session *session, void *UNUSED(user_data))
{
    pthread_mutex_lock(&clb_lock);
    clb_session = session;
    pthread_cond_signal(&clb_cond);
    pthread_mutex_unlock(&clb_lock);
}

static void
test_nc_client_monitoring(void **state)
{
    struct ln2_test_ctx *test_ctx = *state;
    struct nc_session *server, *client, *sess;
    struct timespec ts;
    int fds[2], r = 0;

    /* the monitoring thread watches only the sessions created after it started */
    assert_int_equal(nc_client_monitoring_thread_start(test_monitoring_clb, NULL, NULL), 0);
    ln2_glob_test_fd_sessions(test_ctx->ctx, 1, &server, &client, fds);

    /* the server end disappears */
    close(fds[0]);

    /* wait for the callback */
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += TEST_CLB_TIMEOUT_S;
    pthread_mutex_lock(&clb_lock);
    while (!clb_session && !r) {
        r = pthread_cond_timedwait(&clb_cond, &clb_lock, &ts);
    }
    sess = clb_session;
    pthread_mutex_unlock(&clb_lock);

    assert_ptr_equal(sess, client);
    assert_int_equal(nc_session_get_status(client), NC_STATUS_INVALID);
    assert_int_equal(nc_session_get_term_reason(client), NC_SESSION_TERM_DROPPED);

    nc_client_monitoring_thread_stop();
    nc_session_free(client, NULL);
    nc_session_free(server, NULL);
    close(fds[1]);
}

static int
setup_glob(void **state)
{
    return ln2_glob_test_setup((struct ln2_test_ctx **)state);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_nc_client_monitoring),
    };

    return cmocka_run_group_tests(tests, setup_glob, ln2_glob_test_teardown);
}
