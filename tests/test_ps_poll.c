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
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "compat.h"
#include "ln2_test.h"

/* long enough that a poll thread holding its turn for the whole timeout is unmistakable */
#define TEST_POLL_TIMEOUT 1000

/* more threads than the initial size of the pollsession queue (NC_PS_QUEUE_INIT_SIZE, 6), it has to grow */
#define TEST_POLLER_COUNT 10

/* a high priority operation must get the turn within one session scan of the polling thread,
 * not within one or more poll timeouts */
#define TEST_ADD_LIMIT 250

/* idle timeout of the sessions in seconds */
#define TEST_IDLE_TIMEOUT_S 2

/* poll timeout longer than the idle timeout */
#define TEST_IDLE_POLL_TIMEOUT_MS (TEST_IDLE_TIMEOUT_S * 1000 + 500)

struct test_state {
    struct nc_pollsession *ps;
    pthread_t tids[TEST_POLLER_COUNT];
    uint16_t poller_count;
    ATOMIC_T stop;
};

/* context shared by all the tests */
static struct ln2_test_ctx *test_ctx;

/* socketpair ends of the created sessions, the peer ends are kept open so that the sessions are
 * not reported as hung up, closed together with their session */
static struct {
    struct nc_session *sess;
    int fds[2];
} test_socks[8];

/**
 * @brief Create a server session on a socketpair.
 *
 * @return Created session, NULL on error.
 */
static struct nc_session *
test_new_session(void)
{
    uint32_t i;

    for (i = 0; i < sizeof test_socks / sizeof *test_socks; ++i) {
        if (!test_socks[i].sess) {
            break;
        }
    }
    if (i == sizeof test_socks / sizeof *test_socks) {
        return NULL;
    }

    ln2_glob_test_fd_sessions(test_ctx->ctx, 1, &test_socks[i].sess, NULL, test_socks[i].fds);
    return test_socks[i].sess;
}

/**
 * @brief Free a session created by ::test_new_session() and close its socketpair.
 *
 * @param[in] sess Session to free.
 */
static void
test_free_session(struct nc_session *sess)
{
    uint32_t i;

    for (i = 0; i < sizeof test_socks / sizeof *test_socks; ++i) {
        if (test_socks[i].sess == sess) {
            nc_session_free(sess, NULL);
            close(test_socks[i].fds[0]);
            close(test_socks[i].fds[1]);
            test_socks[i].sess = NULL;
            return;
        }
    }

    fail_msg("Session %" PRIu32 " was not created by the test.", nc_session_get_id(sess));
}

/**
 * @brief Set the server idle timeout.
 *
 * @param[in] idle_timeout Idle timeout in seconds, 0 for none.
 */
static void
test_set_idle_timeout(uint16_t idle_timeout)
{
    struct lyd_node *tree = NULL;
    char buf[8];

    sprintf(buf, "%" PRIu16, idle_timeout);
    assert_int_equal(lyd_new_path(NULL, test_ctx->ctx, "/ietf-netconf-server:netconf-server/listen/idle-timeout", buf,
            0, &tree), LY_SUCCESS);
    assert_int_equal(nc_server_config_setup_data(tree), 0);
    lyd_free_all(tree);
}

/**
 * @brief Get the milliseconds elapsed since a time.
 *
 * @param[in] ts_start Monotonic time to measure from.
 * @return Elapsed milliseconds.
 */
static int32_t
test_elapsed(const struct timespec *ts_start)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec - ts_start->tv_sec) * 1000 + (ts.tv_nsec - ts_start->tv_nsec) / 1000000;
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
    sess = test_new_session();
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
 * Also verifies that the queue grows past its initial size instead of dropping the session.
 */
static void
test_add_session_not_blocked(void **state)
{
    struct test_state *st = *state;
    struct nc_session *sess;
    struct timespec ts_start;
    int32_t elapsed;

    sess = test_new_session();
    assert_non_null(sess);

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    assert_int_equal(nc_ps_add_session(st->ps, sess), 0);
    elapsed = test_elapsed(&ts_start);

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

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    assert_int_equal(nc_ps_del_session(st->ps, sess), 0);
    elapsed = test_elapsed(&ts_start);

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
    struct nc_session *sess, *term_sess;
    struct timespec ts_start;
    int ret;
    int32_t elapsed;

    (void)state;

    ps = nc_ps_new();
    assert_non_null(ps);
    test_set_idle_timeout(TEST_IDLE_TIMEOUT_S);

    /* the session was active just now, so it must survive for the idle timeout, even though the
     * poll deadline is further away than that */
    sess = test_new_session();
    assert_non_null(sess);
    assert_int_equal(nc_ps_add_session(ps, sess), 0);

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    ret = nc_ps_poll(ps, TEST_IDLE_POLL_TIMEOUT_MS, &term_sess);
    elapsed = test_elapsed(&ts_start);

    assert_int_equal(ret, NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR);
    assert_int_equal(nc_session_get_status(sess), NC_STATUS_INVALID);
    assert_int_equal(nc_session_get_term_reason(sess), NC_SESSION_TERM_TIMEOUT);
    /* the idle time is counted in whole seconds */
    assert_true(elapsed >= (TEST_IDLE_TIMEOUT_S - 1) * 1000);

    /* the session was handed over to us, it is no longer in ps */
    assert_ptr_equal(term_sess, sess);
    assert_int_equal(nc_ps_session_count(ps), 0);
    assert_int_equal(nc_ps_del_session(ps, sess), -1);
    test_free_session(sess);

    /* a session that really has been idle for too long is terminated right away */
    sess = test_new_session();
    assert_non_null(sess);
    sleep(TEST_IDLE_TIMEOUT_S);
    assert_int_equal(nc_ps_add_session(ps, sess), 0);

    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    ret = nc_ps_poll(ps, TEST_IDLE_POLL_TIMEOUT_MS, &term_sess);
    elapsed = test_elapsed(&ts_start);

    assert_int_equal(ret, NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR);
    assert_int_equal(nc_session_get_status(sess), NC_STATUS_INVALID);
    assert_int_equal(nc_session_get_term_reason(sess), NC_SESSION_TERM_TIMEOUT);
    assert_true(elapsed < 500);

    test_set_idle_timeout(0);

    assert_ptr_equal(term_sess, sess);
    assert_int_equal(nc_ps_session_count(ps), 0);
    test_free_session(sess);
    nc_ps_free(ps);
}

/**
 * @brief Terminating the last session in the array must not corrupt the round-robin index.
 *
 * ::nc_ps_poll() reports a terminated session and removes it from the pollsession in one step,
 * so the index it was found on no longer exists. Remembering it as the last event index made
 * the next poll start one past the end of the session array.
 */
static void
test_term_last_session(void **state)
{
    struct nc_pollsession *ps;
    struct nc_session *sess[3], *term_sess;
    uint16_t i;
    int ret;

    (void)state;

    ps = nc_ps_new();
    assert_non_null(ps);
    test_set_idle_timeout(TEST_IDLE_TIMEOUT_S);

    /* the last session in the array has been idle for too long, the other two are fine */
    sess[2] = test_new_session();
    assert_non_null(sess[2]);
    sleep(TEST_IDLE_TIMEOUT_S);
    for (i = 0; i < 2; ++i) {
        sess[i] = test_new_session();
        assert_non_null(sess[i]);
    }
    for (i = 0; i < 3; ++i) {
        assert_int_equal(nc_ps_add_session(ps, sess[i]), 0);
    }

    /* the last session is terminated, removed and handed over */
    ret = nc_ps_poll(ps, 0, &term_sess);
    assert_int_equal(ret, NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR);
    assert_ptr_equal(term_sess, sess[2]);
    assert_int_equal(nc_ps_session_count(ps), 2);
    test_free_session(sess[2]);

    /* the next poll must stay inside the session array */
    ret = nc_ps_poll(ps, 0, &term_sess);
    assert_int_equal(ret, NC_PSPOLL_TIMEOUT);
    assert_int_equal(nc_ps_session_count(ps), 2);

    test_set_idle_timeout(0);

    for (i = 0; i < 2; ++i) {
        assert_int_equal(nc_ps_del_session(ps, sess[i]), 0);
        test_free_session(sess[i]);
    }
    nc_ps_free(ps);
}

static int
setup_glob(void **state)
{
    (void)state;

    return ln2_glob_test_setup(&test_ctx);
}

static int
teardown_glob(void **state)
{
    (void)state;

    return ln2_glob_test_teardown((void **)&test_ctx);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_add_session_not_blocked, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_del_session_not_blocked, setup_f, teardown_f),
        cmocka_unit_test(test_idle_timeout),
        cmocka_unit_test(test_term_last_session),
    };

    return cmocka_run_group_tests(tests, setup_glob, teardown_glob);
}
