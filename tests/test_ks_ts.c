/**
 * @file test_ks_ts.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 Keystore and trustore usage test.
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

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
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

static void *
server_thread(void *arg)
{
    int ret;
    NC_MSG_TYPE msgtype;
    struct nc_session *session;
    struct nc_pollsession *ps;
    struct test_state *state = arg;

    ps = nc_ps_new();
    assert_non_null(ps);

    /* accept a session and add it to the poll session structure */
    pthread_barrier_wait(&state->barrier);
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, ctx, &session);
    assert_int_equal(msgtype, NC_MSG_HELLO);

    ret = nc_ps_add_session(ps, session);
    assert_int_equal(ret, 0);

    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
        assert_int_equal(ret & NC_PSPOLL_RPC, NC_PSPOLL_RPC);
    } while (!(ret & NC_PSPOLL_SESSION_TERM));

    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);
    return NULL;
}

static void *
client_thread_ssh(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct test_state *state = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username("client");
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/id_ed25519.pub", TESTS_DIR "/data/id_ed25519");
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&state->barrier);
    session = nc_connect_ssh("127.0.0.1", 10005, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_ks_ts_ssh(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
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

    ret = nc_server_config_add_address_port(ctx, "endpt", NC_TI_LIBSSH, "127.0.0.1", 10005, &tree);
    assert_int_equal(ret, 0);

    ret = lyd_new_path(tree, ctx, "/ietf-netconf-server:netconf-server/listen/"
            "endpoint[name='endpt']/ssh/ssh-server-parameters/server-identity/host-key[name='hostkey']/public-key/"
            "keystore-reference", "test_keystore", 0, NULL);
    assert_int_equal(ret, 0);

    ret = lyd_new_path(tree, ctx, "/ietf-netconf-server:netconf-server/listen/"
            "endpoint[name='endpt']/ssh/ssh-server-parameters/client-authentication/users/user[name='client']/public-keys/"
            "truststore-reference", "test_truststore", 0, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_keystore_asym_key(ctx, NC_TI_LIBSSH, "test_keystore", TESTS_DIR "/data/key_rsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_truststore_pubkey(ctx, NC_TI_LIBSSH, "test_truststore", "pubkey", TESTS_DIR "/data/id_ed25519.pub", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    ret = nc_server_init();
    assert_int_equal(ret, 0);

    /* initialize client */
    ret = nc_client_init();
    assert_int_equal(ret, 0);

    lyd_free_all(tree);

    return 0;
}

static void *
client_thread_tls(void *arg)
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
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_ks_ts_tls(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread_tls, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static int
setup_tls(void **state)
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

    /* new ctx */
    ret = ly_ctx_new(MODULES_DIR, 0, &ctx);
    assert_int_equal(ret, 0);

    /* init ctx */
    ret = nc_server_init_ctx(&ctx);
    assert_int_equal(ret, 0);

    /* load ietf netconf server module and its requisities */
    ret = nc_server_config_load_modules(&ctx);
    assert_int_equal(ret, 0);

    /* new tls bind */
    ret = nc_server_config_add_address_port(ctx, "endpt", NC_TI_OPENSSL, "127.0.0.1", 10005, &tree);
    assert_int_equal(ret, 0);

    /* new keystore asym key pair */
    ret = nc_server_config_add_keystore_asym_key(ctx, NC_TI_OPENSSL, "server_key", TESTS_DIR "/data/server.key", NULL, &tree);
    assert_int_equal(ret, 0);

    /* new keystore cert belonging to the key pair */
    ret = nc_server_config_add_keystore_cert(ctx, "server_key", "server_cert", TESTS_DIR "/data/server.crt", &tree);
    assert_int_equal(ret, 0);

    /* new truststore client cert */
    ret = nc_server_config_add_truststore_cert(ctx, "ee_cert_bag", "ee_cert", TESTS_DIR "/data/client.crt", &tree);
    assert_int_equal(ret, 0);

    /* new truststore client CA cert */
    ret = nc_server_config_add_truststore_cert(ctx, "ca_cert_bag", "ca_cert", TESTS_DIR "/data/serverca.pem", &tree);
    assert_int_equal(ret, 0);

    /* new keystore ref for the TLS server cert */
    ret = lyd_new_path(tree, ctx, "/ietf-netconf-server:netconf-server/listen/endpoint[name='endpt']/"
            "tls/tls-server-parameters/server-identity/certificate/keystore-reference/asymmetric-key", "server_key", 0, NULL);
    assert_int_equal(ret, 0);
    ret = lyd_new_path(tree, ctx, "/ietf-netconf-server:netconf-server/listen/endpoint[name='endpt']/"
            "tls/tls-server-parameters/server-identity/certificate/keystore-reference/certificate", "server_cert", 0, NULL);
    assert_int_equal(ret, 0);

    /* new truststore ref for the client cert */
    ret = lyd_new_path(tree, ctx, "/ietf-netconf-server:netconf-server/listen/endpoint[name='endpt']/tls/"
            "tls-server-parameters/client-authentication/ee-certs/truststore-reference", "ee_cert_bag", 0, NULL);
    assert_int_equal(ret, 0);

    /* new truststore ref for the client CA cert */
    ret = lyd_new_path(tree, ctx, "/ietf-netconf-server:netconf-server/listen/endpoint[name='endpt']/tls/"
            "tls-server-parameters/client-authentication/ca-certs/truststore-reference", "ca_cert_bag", 0, NULL);
    assert_int_equal(ret, 0);

    /* new cert-to-name */
    ret = nc_server_config_add_tls_ctn(ctx, "endpt", 1,
            "04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D",
            NC_TLS_CTN_SPECIFIED, "client", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    ret = nc_server_init();
    assert_int_equal(ret, 0);

    /* initialize client */
    ret = nc_client_init();
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
        cmocka_unit_test_setup_teardown(test_nc_ks_ts_ssh, setup_ssh, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_ks_ts_tls, setup_tls, teardown_f),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
