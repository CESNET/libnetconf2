/**
 * @file test_unix_socket.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 UNIX socket test
 *
 * @copyright
 * Copyright (c) 2022 - 2024 CESNET, z.s.p.o.
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

static void *
client_thread(void *arg)
{
    int ret = 0;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_unix("/tmp/nc2_test_unix_sock", NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_connect_unix_socket(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
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
    struct ln2_test_ctx *test_ctx;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    *state = test_ctx;

    /* create the UNIX socket */
    ret = nc_server_add_endpt_unix_socket_listen("unix", "/tmp/nc2_test_unix_sock", 0700, -1, -1);
    assert_int_equal(ret, 0);

    lyd_free_all(tree);
    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_connect_unix_socket, setup_f, ln2_glob_test_teardown),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
