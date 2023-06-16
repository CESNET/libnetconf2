/**
 * @file test_crl.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 TLS CRL test
 *
 * @copyright
 * Copyright (c) 2023 CESNET, z.s.p.o.
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

#include "tests/config.h"

#define NC_ACCEPT_TIMEOUT 2000
#define NC_PS_POLL_TIMEOUT 2000

struct ly_ctx *ctx;

struct test_state {
    pthread_barrier_t barrier;
};

char buffer[512];
char expected[512];

static void
test_msg_callback(const struct nc_session *session, NC_VERB_LEVEL level, const char *msg)
{
    (void) level;
    (void) session;

    if (strstr(msg, expected)) {
        strcpy(buffer, msg);
    }

    printf("%s\n", msg);
}

static void *
server_thread(void *arg)
{
    NC_MSG_TYPE msgtype;
    struct nc_session *session;
    struct test_state *state = arg;

    /* set print clb so we get access to messages */
    nc_set_print_clb_session(test_msg_callback);
    buffer[0] = '\0';
    strcpy(expected, "revoked per CRL");

    /* accept a session and add it to the poll session structure */
    pthread_barrier_wait(&state->barrier);
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, ctx, &session);
    assert_int_equal(msgtype, NC_MSG_ERROR);

    assert_int_not_equal(strlen(buffer), 0);

    nc_session_free(session, NULL);
    return NULL;
}

static void *
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct test_state *state = arg;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set client cert */
    ret = nc_client_tls_set_cert_key_paths(TESTS_DIR "/data/client.crt", TESTS_DIR "/data/client.key");
    assert_int_equal(ret, 0);

    /* set client ca */
    ret = nc_client_tls_set_trusted_ca_paths(NULL, TESTS_DIR "/data");
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&state->barrier);
    session = nc_connect_tls("127.0.0.1", 10005, NULL);

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
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
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
    struct test_state *test_state;

    nc_verbosity(NC_VERB_VERBOSE);

    /* init barrier */
    test_state = malloc(sizeof *test_state);
    assert_non_null(test_state);

    ret = pthread_barrier_init(&test_state->barrier, NULL, 2);
    assert_int_equal(ret, 0);

    *state = test_state;

    ret = ly_ctx_new(MODULES_DIR, 0, &ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_init_ctx(&ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_config_load_modules(&ctx);
    assert_int_equal(ret, 0);

    /* create new address and port data */
    ret = nc_server_config_new_address_port(ctx, "endpt", NC_TI_OPENSSL, "127.0.0.1", "10005", &tree);
    assert_int_equal(ret, 0);

    /* create new server certificate data */
    ret = nc_server_config_new_tls_server_certificate(ctx, "endpt", NULL, TESTS_DIR "/data/server.key", TESTS_DIR "/data/server.crt", &tree);
    assert_int_equal(ret, 0);

    /* create new end entity client cert data */
    ret = nc_server_config_new_tls_client_certificate(ctx, "endpt", "client_cert", TESTS_DIR "/data/client.crt", &tree);
    assert_int_equal(ret, 0);

    /* create new client ca data */
    ret = nc_server_config_new_tls_client_ca(ctx, "endpt", "client_ca", TESTS_DIR "/data/serverca.pem", &tree);
    assert_int_equal(ret, 0);

    /* create new cert-to-name */
    ret = nc_server_config_new_tls_ctn(ctx, "endpt", 1,
            "04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D",
            NC_TLS_CTN_SPECIFIED, "client", &tree);
    assert_int_equal(ret, 0);

    /* limit TLS version to 1.3 */
    ret = nc_server_config_new_tls_version(ctx, "endpt", NC_TLS_VERSION_13, &tree);
    assert_int_equal(ret, 0);

    /* set the TLS cipher */
    ret = nc_server_config_new_tls_ciphers(ctx, "endpt", &tree, 3, "tls-aes-128-ccm-sha256", "tls-aes-128-gcm-sha256", "tls-chacha20-poly1305-sha256");
    assert_int_equal(ret, 0);

    /* set this node, but it should be deleted by the next call, bcs only one choice node can be present */
    ret = nc_server_config_new_tls_crl_url(ctx, "endpt", "abc", &tree);
    assert_int_equal(ret, 0);

    /* set path to a CRL file */
    ret = nc_server_config_new_tls_crl_path(ctx, "endpt", TESTS_DIR "/data/crl.pem", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    ret = nc_server_init();
    assert_int_equal(ret, 0);

    lyd_free_all(tree);

    return 0;
}

static int
teardown_f(void **state)
{
    int ret = 0;
    struct test_state *test_state;

    assert_non_null(state);
    test_state = *state;

    ret = pthread_barrier_destroy(&test_state->barrier);
    assert_int_equal(ret, 0);

    free(*state);
    nc_client_destroy();
    nc_server_destroy();
    ly_ctx_destroy(ctx);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_tls, setup_f, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
