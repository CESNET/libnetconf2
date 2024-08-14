/**
 * @file test_replace.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 Non-diff YANG data configuration test
 *
 * @copyright
 * Copyright (c) 2023 - 2024 CESNET, z.s.p.o.
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

int TEST_PORT = 10050;
const char *TEST_PORT_STR = "10050";

static void *
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    /* set directory where to search for modules */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set ssh username */
    ret = nc_client_ssh_set_username("new_client");
    assert_int_equal(ret, 0);

    /* add client's key pair */
    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/key_rsa.pub", TESTS_DIR "/data/key_rsa");
    assert_int_equal(ret, 0);

    /* wait for the server to reach polling */
    pthread_barrier_wait(&test_ctx->barrier);

    /* connect */
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
nc_test_replace(void **state)
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
    struct lyd_node *old_tree = NULL, *new_tree = NULL;
    struct ln2_test_ctx *test_ctx;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    *state = test_ctx;

    ret = nc_server_config_add_address_port(test_ctx->ctx, "old", NC_TI_SSH, "127.0.0.1", TEST_PORT, &old_tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "old", "old_key", TESTS_DIR "/data/key_rsa", NULL, &old_tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_password(test_ctx->ctx, "old", "old_client", "passwd", &old_tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the yang data, treat them as if every node had replace operation */
    ret = nc_server_config_setup_data(old_tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_address_port(test_ctx->ctx, "new", NC_TI_SSH, "127.0.0.1", TEST_PORT, &new_tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "new", "new_key", TESTS_DIR "/data/key_rsa", NULL, &new_tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "new", "new_client", "pubkey", TESTS_DIR "/data/key_rsa.pub", &new_tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the yang data, meaning
     * everything configured will be deleted and only the new data applied
     */
    ret = nc_server_config_setup_data(new_tree);
    assert_int_equal(ret, 0);

    lyd_free_all(old_tree);
    lyd_free_all(new_tree);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(nc_test_replace, setup_f, ln2_glob_test_teardown),
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
