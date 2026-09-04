/**
 * @file test_ps_poll.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 tests - pollsession queue fairness
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

#include <inttypes.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include <session_p.h>

#include "ln2_test.h"

/* long enough that a poll thread holding its turn for the whole timeout is unmistakable */
#define TEST_POLL_TIMEOUT 1000

/* more threads than the queue was sized for, it has to grow */
#define TEST_POLLER_COUNT (NC_PS_QUEUE_SIZE + 4)

/* a high priority operation must get the turn within one session scan of the polling thread,
 * not within one or more poll timeouts */
#define TEST_ADD_LIMIT 250

struct test_state {
    struct nc_pollsession *ps;
    pthread_t tids[TEST_POLLER_COUNT];
    uint16_t poller_count;
    ATOMIC_T stop;
};

/* socketpair peer ends of the created sessions, kept open so that the sessions are not
 * reported as hung up, closed together with their session */
static struct {
    struct nc_session *sess;
    int fd;
} test_peers[8];

/**
 * @brief Remember the socketpair peer end of a session.
 *
 * @param[in] sess Session the peer end belongs to.
 * @param[in] fd Peer end of the session socketpair.
 * @return 0 on success, -1 on error.
 */
static int
test_peer_store(struct nc_session *sess, int fd)
{
    uint32_t i;

    for (i = 0; i < sizeof test_peers / sizeof *test_peers; ++i) {
        if (!test_peers[i].sess) {
            test_peers[i].sess = sess;
            test_peers[i].fd = fd;
            return 0;
        }
    }

    return -1;
}

/**
 * @brief Close the socketpair peer end of a session.
 *
 * @param[in] sess Session being freed.
 */
static void
test_peer_close(struct nc_session *sess)
{
    uint32_t i;

    for (i = 0; i < sizeof test_peers / sizeof *test_peers; ++i) {
        if (test_peers[i].sess == sess) {
            close(test_peers[i].fd);
            test_peers[i].sess = NULL;
            test_peers[i].fd = -1;
            return;
        }
    }

    fail_msg("Session %" PRIu32 " has no stored socketpair peer end.", sess->id);
}

/**
 * @brief Create a bare server session on a socketpair, without any transport handshake.
 *
 * @param[in] id Session ID to use.
 * @return Created session, NULL on error.
 */
static struct nc_session *
test_new_session(uint32_t id)
{
    struct nc_session *sess;
    struct timespec ts;
    int sock[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock)) {
        return NULL;
    }

    sess = calloc(1, sizeof *sess);
    if (!sess) {
        close(sock[0]);
        close(sock[1]);
        return NULL;
    }

    sess->side = NC_SERVER;
    pthread_mutex_init(&sess->opts.server.ntf_status_lock, NULL);
    pthread_mutex_init(&sess->opts.server.rpc_lock, NULL);
    pthread_cond_init(&sess->opts.server.rpc_cond, NULL);
    nc_timeouttime_get(&ts, 0);
    sess->opts.server.last_rpc = ts.tv_sec;

    sess->io_lock = malloc(sizeof *sess->io_lock);
    if (!sess->io_lock) {
        free(sess);
        close(sock[0]);
        close(sock[1]);
        return NULL;
    }
    pthread_mutex_init(sess->io_lock, NULL);

    NC_SESSION_STATUS_SET(sess, NC_STATUS_RUNNING);
    sess->id = id;
    sess->ti_type = NC_TI_FD;
    sess->ti.fd.in = sock[0];
    sess->ti.fd.out = sock[0];

    /* remember the socketpair peer end so that it can be closed with the session */
    if (test_peer_store(sess, sock[1])) {
        pthread_mutex_destroy(&sess->opts.server.ntf_status_lock);
        pthread_mutex_destroy(&sess->opts.server.rpc_lock);
        pthread_cond_destroy(&sess->opts.server.rpc_cond);
        pthread_mutex_destroy(sess->io_lock);
        free(sess->io_lock);
        free(sess);
        close(sock[0]);
        close(sock[1]);
        return NULL;
    }

    return sess;
}

static void
test_free_session(struct nc_session *sess)
{
    close(sess->ti.fd.in);
    test_peer_close(sess);
    pthread_mutex_destroy(&sess->opts.server.ntf_status_lock);
    pthread_mutex_destroy(&sess->opts.server.rpc_lock);
    pthread_cond_destroy(&sess->opts.server.rpc_cond);
    pthread_mutex_destroy(sess->io_lock);
    free(sess->io_lock);
    free(sess);
}

/**
 * @brief Poll the pollsession in a loop, like a server worker thread does.
 *
 * @param[in] arg Test state.
 * @return NULL.
 */
static void *
test_poller_thread(void *arg)
{
    struct test_state *st = arg;

    while (!ATOMIC_LOAD_RELAXED(st->stop)) {
        nc_ps_poll(st->ps, TEST_POLL_TIMEOUT, NULL);
    }

    return NULL;
}

static int
setup_f(void **state)
{
    struct test_state *st;
    struct nc_session *sess;
    uint16_t i;

    st = calloc(1, sizeof *st);
    if (!st) {
        SETUP_FAIL_LOG;
        return 1;
    }
    ATOMIC_STORE_RELAXED(st->stop, 0);

    st->ps = nc_ps_new();
    if (!st->ps) {
        SETUP_FAIL_LOG;
        return 1;
    }

    /* an already established, idle session, otherwise the pollers would just return no-sessions */
    sess = test_new_session(1);
    if (!sess) {
        SETUP_FAIL_LOG;
        return 1;
    }
    if (nc_ps_add_session(st->ps, sess)) {
        SETUP_FAIL_LOG;
        return 1;
    }

    /* start the pollers and let them settle into the poll loop */
    for (i = 0; i < TEST_POLLER_COUNT; ++i) {
        if (pthread_create(&st->tids[i], NULL, test_poller_thread, st)) {
            SETUP_FAIL_LOG;
            return 1;
        }
        ++st->poller_count;
    }
    usleep(200000);

    *state = st;
    return 0;
}

static int
teardown_f(void **state)
{
    struct test_state *st = *state;
    struct nc_session *sess;
    uint16_t i;

    ATOMIC_STORE_RELAXED(st->stop, 1);

    /* remove the sessions first, the pollers then return right away instead of each waiting
     * for its turn and timing out in it */
    while (nc_ps_session_count(st->ps)) {
        sess = nc_ps_get_session(st->ps, 0);
        nc_ps_del_session(st->ps, sess);
        test_free_session(sess);
    }

    for (i = 0; i < st->poller_count; ++i) {
        pthread_join(st->tids[i], NULL);
    }

    nc_ps_free(st->ps);
    free(st);

    return 0;
}

/**
 * @brief Adding a session must not wait for the poll threads to time out.
 *
 * Session addition used to queue up behind all the poll threads in the same FIFO queue, so a
 * newly established session waited poller_count * TEST_POLL_TIMEOUT before it was polled for
 * the first time. It now queues up in front of them and the polling thread hands the turn over.
 * Also verifies that the queue grows past NC_PS_QUEUE_SIZE instead of dropping the session.
 */
static void
test_add_session_not_blocked(void **state)
{
    struct test_state *st = *state;
    struct nc_session *sess;
    struct timespec ts_start;
    int32_t elapsed;

    sess = test_new_session(2);
    assert_non_null(sess);

    nc_timeouttime_get(&ts_start, 0);
    assert_int_equal(nc_ps_add_session(st->ps, sess), 0);
    elapsed = -nc_timeouttime_cur_diff(&ts_start);

    assert_int_equal(nc_ps_session_count(st->ps), 2);
    assert_true(elapsed < TEST_ADD_LIMIT);
}

/**
 * @brief Removing a session must not be blocked by the idle poll threads either.
 */
static void
test_del_session_not_blocked(void **state)
{
    struct test_state *st = *state;
    struct nc_session *sess;
    struct timespec ts_start;
    int32_t elapsed;

    sess = nc_ps_get_session(st->ps, 0);
    assert_non_null(sess);

    nc_timeouttime_get(&ts_start, 0);
    assert_int_equal(nc_ps_del_session(st->ps, sess), 0);
    elapsed = -nc_timeouttime_cur_diff(&ts_start);

    assert_int_equal(nc_ps_session_count(st->ps), 0);
    test_free_session(sess);
    assert_true(elapsed < TEST_ADD_LIMIT);
}

/**
 * @brief The session idle timeout must be evaluated against the current time.
 *
 * It used to be checked against the nc_ps_poll() deadline instead, so a poll timeout longer
 * than the remaining idle time terminated a perfectly active session right away. With an
 * infinite timeout that timespec was not even initialized.
 */
static void
test_idle_timeout(void **state)
{
    struct nc_pollsession *ps;
    struct nc_session *sess;
    struct timespec ts, ts_start;
    int ret;
    int32_t elapsed;

    (void)state;

    ps = nc_ps_new();
    assert_non_null(ps);

    sess = test_new_session(1);
    assert_non_null(sess);
    assert_int_equal(nc_ps_add_session(ps, sess), 0);

    /* the session was active just now, so with an idle timeout of 2s it must survive for 2s,
     * even though the poll deadline is further away than that */
    ATOMIC_STORE_RELAXED(server_opts.idle_timeout, 2);

    nc_timeouttime_get(&ts_start, 0);
    ret = nc_ps_poll(ps, 2500, NULL);
    elapsed = -nc_timeouttime_cur_diff(&ts_start);

    assert_int_equal(ret, NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR);
    assert_int_equal(NC_SESSION_STATUS_GET(sess), NC_STATUS_INVALID);
    assert_int_equal(NC_SESSION_TERM_REASON_GET(sess), NC_SESSION_TERM_TIMEOUT);
    assert_true(elapsed >= 1000);

    assert_int_equal(nc_ps_del_session(ps, sess), 0);
    test_free_session(sess);

    /* a session that really has been idle for too long is terminated right away */
    sess = test_new_session(2);
    assert_non_null(sess);
    nc_timeouttime_get(&ts, 0);
    sess->opts.server.last_rpc = ts.tv_sec - 3;
    assert_int_equal(nc_ps_add_session(ps, sess), 0);

    nc_timeouttime_get(&ts_start, 0);
    ret = nc_ps_poll(ps, 2500, NULL);
    elapsed = -nc_timeouttime_cur_diff(&ts_start);

    assert_int_equal(ret, NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR);
    assert_int_equal(NC_SESSION_STATUS_GET(sess), NC_STATUS_INVALID);
    assert_int_equal(NC_SESSION_TERM_REASON_GET(sess), NC_SESSION_TERM_TIMEOUT);
    assert_true(elapsed < 500);

    ATOMIC_STORE_RELAXED(server_opts.idle_timeout, 0);

    assert_int_equal(nc_ps_del_session(ps, sess), 0);
    test_free_session(sess);
    nc_ps_free(ps);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_add_session_not_blocked, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_del_session_not_blocked, setup_f, teardown_f),
        cmocka_unit_test(test_idle_timeout),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
