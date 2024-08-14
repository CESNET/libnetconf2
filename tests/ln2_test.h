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

#define NC_ACCEPT_TIMEOUT 2000
#define NC_PS_POLL_TIMEOUT 2000

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
void * ln2_glob_test_server_thread(void *arg);

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

#endif
