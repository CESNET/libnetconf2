/**
 * @file ln2_test.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief base header for libnetconf2 testing
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

#ifndef _LN2_TEST_H_
#define _LN2_TEST_H_

#include <pthread.h>
#include <stdarg.h>

#include "tests/config.h"

/* timeout of accepting a new session */
#define NC_ACCEPT_TIMEOUT_MS 4000

/* timeout of a single poll of the sessions */
#define NC_PS_POLL_TIMEOUT_MS 2000

/* timeout of sending or receiving a single message */
#define NC_MSG_TIMEOUT_MS 1000

#define SETUP_FAIL_LOG \
    fprintf(stderr, "Setup fail in %s:%d.\n", __FILE__, __LINE__)

/**
 * @brief Test context used for sharing data between the test and the server/client threads.
 */
struct ln2_test_ctx {
    pthread_barrier_t barrier;      /**< Barrier for synchronizing the client and the server. */
    struct ly_ctx *ctx;             /**< libyang context. */
    void *test_data;                /**< Arbitrary test data. */
    void (*free_test_data)(void *); /**< Callback for freeing the test data. */
};

/**
 * @brief Try to obtain ports from the TEST_PORT_X environment variables.
 *
 * @param[in] port_count Number of ports needed by the test.
 * @param[in] ... @p port_count number of (int *, const char **) pairs, which will be filled with the port numbers.
 * @return 0 on success, 1 on error.
 */
int ln2_glob_test_get_ports(int port_count, ...);

/**
 * @brief Default server thread for the tests.
 *
 * @param[in] arg Test context.
 * @return NULL.
 */
void *ln2_glob_test_server_thread(void *arg);

/**
 * @brief Default server thread for the tests, expecting the client connection to fail.
 *
 * @param[in] arg Test context.
 * @return NULL.
 */
void *ln2_glob_test_server_thread_fail(void *arg);

/**
 * @brief Default setup of the test context (init server, client, libyang context and a barrier).
 *
 * @param[out] test_ctx Test context.
 * @return 0 on success, non-zero on error.
 */
int ln2_glob_test_setup(struct ln2_test_ctx **test_ctx);

/**
 * @brief Default teardown of the test context (destroy server, client, test data, libyang context and a barrier).
 *
 * @param[in] state Test context.
 * @return 0.
 */
int ln2_glob_test_teardown(void **state);

/**
 * @brief Default callback for freeing test data.
 *
 * @param[in] test_data Test data.
 */
void ln2_glob_test_free_test_data(void *test_data);

/**
 * @brief Create NETCONF sessions on both ends of a new socketpair.
 *
 * Each session makes its handshake with a fake peer on a separate socketpair, which chooses the NETCONF
 * version, and is then switched to its end of the shared socketpair. Disables the client context autofill,
 * the fake server provides no YANG modules.
 *
 * @param[in] ctx libyang context of the sessions.
 * @param[in] version NETCONF version, 0 for 1.0, 1 for 1.1, as returned by ::nc_session_get_version().
 * @param[out] server Created server session.
 * @param[out] client Created client session, NULL if not needed.
 * @param[out] fds Socketpair, the server end first, the caller closes both after freeing the sessions.
 */
void ln2_glob_test_fd_sessions(struct ly_ctx *ctx, int version, struct nc_session **server, struct nc_session **client,
        int fds[2]);

#endif
