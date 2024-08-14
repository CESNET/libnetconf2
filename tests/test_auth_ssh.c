/**
 * @file test_auth_ssh.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 SSH authentication test
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

struct test_auth_ssh_data {
    const char *username;
    const char *pubkey_path;
    const char *privkey_path;
};

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
client_thread_ssh(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;
    struct test_auth_ssh_data *test_data = test_ctx->test_data;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username(test_data->username);
    assert_int_equal(ret, 0);

    if (test_data->pubkey_path) {
        ret = nc_client_ssh_add_keypair(test_data->pubkey_path, test_data->privkey_path);
        assert_int_equal(ret, 0);
    } else {
        nc_client_ssh_set_auth_password_clb(auth_password, NULL);
    }

    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_auth_ssh_password(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_auth_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_pw";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_auth_ssh_none(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_auth_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_none";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_auth_ssh_rsa_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_auth_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_pk";
    test_data->pubkey_path = TESTS_DIR "/data/key_rsa.pub";
    test_data->privkey_path = TESTS_DIR "/data/key_rsa";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_auth_ssh_ec256_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_auth_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_ec256";
    test_data->pubkey_path = TESTS_DIR "/data/id_ecdsa256.pub";
    test_data->privkey_path = TESTS_DIR "/data/id_ecdsa256";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_auth_ssh_ec384_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_auth_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_ec384";
    test_data->pubkey_path = TESTS_DIR "/data/id_ecdsa384.pub";
    test_data->privkey_path = TESTS_DIR "/data/id_ecdsa384";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_auth_ssh_ec521_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_auth_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_ec521";
    test_data->pubkey_path = TESTS_DIR "/data/id_ecdsa521.pub";
    test_data->privkey_path = TESTS_DIR "/data/id_ecdsa521";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_auth_ssh_ed25519_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_auth_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_ed25519";
    test_data->pubkey_path = TESTS_DIR "/data/id_ed25519.pub";
    test_data->privkey_path = TESTS_DIR "/data/id_ed25519";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static int
setup_ssh(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx;
    struct test_auth_ssh_data *test_data;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    test_data = calloc(1, sizeof *test_data);
    assert_non_null(test_data);

    test_ctx->test_data = test_data;
    test_ctx->free_test_data = ln2_glob_test_free_test_data;
    *state = test_ctx;

    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_pk", "pubkey", TESTS_DIR "/data/key_rsa.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_ec256", "pubkey", TESTS_DIR "/data/id_ecdsa256.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_ec384", "pubkey", TESTS_DIR "/data/id_ecdsa384.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_ec521", "pubkey", TESTS_DIR "/data/id_ecdsa521.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_ed25519", "pubkey", TESTS_DIR "/data/id_ed25519.pub", &tree);
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
        cmocka_unit_test_setup_teardown(test_nc_auth_ssh_password, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_auth_ssh_none, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_auth_ssh_rsa_pubkey, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_auth_ssh_ec256_pubkey, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_auth_ssh_ec384_pubkey, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_auth_ssh_ec521_pubkey, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_auth_ssh_ed25519_pubkey, setup_ssh, ln2_glob_test_teardown)
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
