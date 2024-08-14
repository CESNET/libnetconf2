/**
 * @file test_endpt_share_clients.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 Sharing clients between endpoints test
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

int TEST_PORT = 10050, TEST_PORT_2 = 10051, TEST_PORT_3 = 10052, TEST_PORT_4 = 10053;
const char *TEST_PORT_STR = "10050", *TEST_PORT_2_STR = "10051", *TEST_PORT_3_STR = "10052", *TEST_PORT_4_STR = "10053";

static void *
client_thread_ssh(void *arg)
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
    ret = nc_client_ssh_set_username("client");
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
nc_test_endpt_share_clients_ssh(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void *
client_thread_tls(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* set directory where to search for modules */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set client cert */
    ret = nc_client_tls_set_cert_key_paths(TESTS_DIR "/data/client.crt", TESTS_DIR "/data/client.key");
    assert_int_equal(ret, 0);

    /* set client ca */
    ret = nc_client_tls_set_trusted_ca_paths(NULL, TESTS_DIR "/data");
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_tls("127.0.0.1", TEST_PORT_4, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
nc_test_endpt_share_clients_tls(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread_tls, *state);
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

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    *state = test_ctx;

    /* create the first SSH endpoint with a client reference to the second endpoint */
    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "SSH_endpt_1", "hostkey", TESTS_DIR "/data/key_rsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_address_port(test_ctx->ctx, "SSH_endpt_1", NC_TI_SSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_endpoint_client_ref(test_ctx->ctx, "SSH_endpt_1", "SSH_endpt_2", &tree);
    assert_int_equal(ret, 0);

    /* create the second SSH endpoint with a single client */
    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "SSH_endpt_2", "hostkey", TESTS_DIR "/data/key_rsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_address_port(test_ctx->ctx, "SSH_endpt_2", NC_TI_SSH, "127.0.0.1", TEST_PORT_2, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "SSH_endpt_2", "client", "pubkey", TESTS_DIR "/data/key_rsa.pub", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the yang data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    lyd_free_all(tree);

    return 0;
}

static int
setup_tls(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    *state = test_ctx;

    /* create the first TLS endpoint with a single end entity client cert and a CTN entry */
    ret = nc_server_config_add_tls_server_cert(test_ctx->ctx, "TLS_endpt_1", TESTS_DIR "/data/server.key", NULL, TESTS_DIR "/data/server.crt", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_address_port(test_ctx->ctx, "TLS_endpt_1", NC_TI_TLS, "127.0.0.1", TEST_PORT_3, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_tls_client_cert(test_ctx->ctx, "TLS_endpt_1", "cert_client", TESTS_DIR "/data/client.crt", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_tls_ca_cert(test_ctx->ctx, "TLS_endpt_1", "cert_ca", TESTS_DIR "/data/serverca.pem", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_tls_ctn(test_ctx->ctx, "TLS_endpt_1", 1,
            "04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D",
            NC_TLS_CTN_SPECIFIED, "client", &tree);
    assert_int_equal(ret, 0);

    /* create the second TLS endpoint with a reference to the first endpoint */
    ret = nc_server_config_add_tls_server_cert(test_ctx->ctx, "TLS_endpt_2",
            TESTS_DIR "/data/server.key", NULL, TESTS_DIR "/data/server.crt", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_address_port(test_ctx->ctx, "TLS_endpt_2", NC_TI_TLS, "127.0.0.1", TEST_PORT_4, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_tls_endpoint_client_ref(test_ctx->ctx, "TLS_endpt_2", "TLS_endpt_1", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the yang data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    lyd_free_all(tree);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(nc_test_endpt_share_clients_ssh, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(nc_test_endpt_share_clients_tls, setup_tls, ln2_glob_test_teardown),
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(4, &TEST_PORT, &TEST_PORT_STR, &TEST_PORT_2, &TEST_PORT_2_STR,
            &TEST_PORT_3, &TEST_PORT_3_STR, &TEST_PORT_4, &TEST_PORT_4_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
