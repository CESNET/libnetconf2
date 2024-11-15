/**
 * @file test_tls.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 TLS authentication test
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

#include <pthread.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "ln2_test.h"

#define KEYLOG_FILENAME "ln2_test_tls_keylog.txt"

int TEST_PORT = 10050;
const char *TEST_PORT_STR = "10050";

static void *
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set client cert */
    ret = nc_client_tls_set_cert_key_paths(TESTS_DIR "/data/client.crt", TESTS_DIR "/data/client.key");
    assert_int_equal(ret, 0);

    /* set client ca */
    ret = nc_client_tls_set_trusted_ca_paths(NULL, TESTS_DIR "/data");
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_tls("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_tls(void **state)
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

static void
test_nc_tls_ec_key(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx;

    assert_non_null(state);
    test_ctx = *state;

    ret = nc_server_config_add_tls_server_cert(test_ctx->ctx, "endpt", TESTS_DIR "/data/ec_server.key",
            NULL, TESTS_DIR "/data/ec_server.crt", (struct lyd_node **)&test_ctx->test_data);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(test_ctx->test_data);
    assert_int_equal(ret, 0);

    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
check_keylog_file(const char *filename)
{
    char buf[256];
    FILE *f;
    int cli_random, cli_hs, cli_traffic, srv_hs, srv_traffic;

    cli_random = cli_hs = cli_traffic = srv_hs = srv_traffic = 0;

    f = fopen(filename, "r");
    assert_non_null(f);

    while (fgets(buf, sizeof(buf), f)) {
        if (!strncmp(buf, "CLIENT_RANDOM", 13)) {
            cli_random++;
        } else if (!strncmp(buf, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", 31)) {
            cli_hs++;
        } else if (!strncmp(buf, "CLIENT_TRAFFIC_SECRET_0", 23)) {
            cli_traffic++;
        } else if (!strncmp(buf, "SERVER_HANDSHAKE_TRAFFIC_SECRET", 31)) {
            srv_hs++;
        } else if (!strncmp(buf, "SERVER_TRAFFIC_SECRET_0", 23)) {
            srv_traffic++;
        }
    }

    fclose(f);

    if (cli_random) {
        /* tls 1.2 */
        assert_int_equal(cli_random, 1);
        assert_int_equal(cli_hs + cli_traffic + srv_hs + srv_traffic, 0);
    } else {
        /* tls 1.3 */
        assert_int_equal(cli_hs + cli_traffic + srv_hs + srv_traffic, 4);
    }
}

static void
test_nc_tls_keylog(void **state)
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

    check_keylog_file(KEYLOG_FILENAME);
}

static void
test_nc_tls_free_test_data(void *test_data)
{
    lyd_free_all(test_data);
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

    /* create new address and port data */
    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_TLS, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    /* create new server certificate data */
    ret = nc_server_config_add_tls_server_cert(test_ctx->ctx, "endpt", TESTS_DIR "/data/server.key", NULL, TESTS_DIR "/data/server.crt", &tree);
    assert_int_equal(ret, 0);

    /* create new end entity client cert data */
    ret = nc_server_config_add_tls_client_cert(test_ctx->ctx, "endpt", "client_cert", TESTS_DIR "/data/client.crt", &tree);
    assert_int_equal(ret, 0);

    /* create new client ca data */
    ret = nc_server_config_add_tls_ca_cert(test_ctx->ctx, "endpt", "client_ca", TESTS_DIR "/data/serverca.pem", &tree);
    assert_int_equal(ret, 0);

    /* create new cert-to-name */
    ret = nc_server_config_add_tls_ctn(test_ctx->ctx, "endpt", 1,
            "04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D",
            NC_TLS_CTN_SPECIFIED, "client", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    test_ctx->test_data = tree;
    test_ctx->free_test_data = test_nc_tls_free_test_data;

    return 0;
}

static int
keylog_setup_f(void **state)
{
    unlink(KEYLOG_FILENAME);
    setenv("SSLKEYLOGFILE", KEYLOG_FILENAME, 1);

    return setup_f(state);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_tls, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_tls_ec_key, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_tls_keylog, keylog_setup_f, ln2_glob_test_teardown)
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
