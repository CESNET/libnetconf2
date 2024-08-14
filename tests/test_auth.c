/**
 * @file test_auth.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 SSH authentication methods test
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

static char *
auth_password(const char *username, const char *hostname, void *priv)
{
    (void) hostname;
    (void) priv;

    /* set the reply to password authentication */
    if (!strcmp(username, "test_pw")) {
        return strdup("testpw");
    } else {
        return NULL;
    }
}

static void *
client_thread_password(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username("test_pw");
    assert_int_equal(ret, 0);

    nc_client_ssh_set_auth_password_clb(auth_password, NULL);

    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, -1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, 1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, -1);

    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_auth_password(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread_password, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void *
client_thread_pubkey(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username("test_pk");
    assert_int_equal(ret, 0);

    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, 1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, -1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, -1);

    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/key_rsa.pub", TESTS_DIR "/data/key_rsa");
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_auth_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread_pubkey, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void *
client_thread_none(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username("test_none");
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_auth_none(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread_none, *state);
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

    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_pk", "pubkey", TESTS_DIR "/data/key_rsa.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_password(test_ctx->ctx, "endpt", "test_pw", "testpw", &tree);
    assert_int_equal(ret, 0);

    ret = lyd_new_path(tree, test_ctx->ctx, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='endpt']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='test_none']/none", NULL, 0, NULL);
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
        cmocka_unit_test_setup_teardown(test_nc_auth_pubkey, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_auth_password, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_auth_none, setup_f, ln2_glob_test_teardown)
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
