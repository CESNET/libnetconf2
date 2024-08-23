/**
 * @file test_ch.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 Call-home test
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

struct test_ch_data {
    struct lyd_node *tree;
};

char buffer[512];
char expected[512];

int TEST_PORT = 10050, TEST_PORT_2 = 10051;
const char *TEST_PORT_STR = "10050", *TEST_PORT_2_STR = "10051";

static void
test_msg_callback(const struct nc_session *session, NC_VERB_LEVEL level, const char *msg)
{
    (void) level;
    (void) session;

    if (strstr(msg, expected)) {
        strncpy(buffer, msg, 511);
    }

    printf("%s\n", msg);
}

/* acquire ctx cb for dispatch */
const struct ly_ctx *
ch_session_acquire_ctx_cb(void *cb_data)
{
    return ((struct ln2_test_ctx *)cb_data)->ctx;
}

/* release ctx cb for dispatch */
void
ch_session_release_ctx_cb(void *cb_data)
{
    (void) cb_data;
    return;
}

/* new session cb for dispatch */
int
ch_new_session_cb(const char *client_name, struct nc_session *new_session, void *user_data)
{
    int ret = 0;
    struct nc_pollsession *ps = (struct nc_pollsession *)user_data;

    (void) client_name;

    ret = nc_ps_add_session(ps, new_session);
    assert_int_equal(ret, 0);
    return 0;
}

static void *
server_thread_ssh(void *arg)
{
    int ret;
    struct nc_pollsession *ps;
    struct ln2_test_ctx *test_ctx = arg;
    struct test_ch_data *test_data = test_ctx->test_data;

    /* set print clb so we get access to messages */
    nc_set_print_clb_session(test_msg_callback);
    buffer[0] = '\0';
    strcpy(expected, "reconnecting in");

    /* prepare data for deleting the call-home client */
    ret = nc_server_config_del_ch_client("ch_ssh", &test_data->tree);
    assert_int_equal(ret, 0);

    /* new poll session */
    ps = nc_ps_new();
    assert_non_null(ps);

    pthread_barrier_wait(&test_ctx->barrier);
    /* create the call-home client thread */
    ret = nc_connect_ch_client_dispatch("ch_ssh", ch_session_acquire_ctx_cb,
            ch_session_release_ctx_cb, test_ctx, ch_new_session_cb, ps);
    assert_int_equal(ret, 0);

    /* poll */
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
        if (ret & (NC_PSPOLL_TIMEOUT | NC_PSPOLL_NOSESSIONS)) {
            usleep(500);
        }
    } while (!strlen(buffer));

    /* delete the call-home client, the thread should end */
    ret = nc_server_config_setup_data(test_data->tree);
    assert_int_equal(ret, 0);

    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);

    return NULL;
}

static void *
client_thread_ssh(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_ch_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    /* set directory where to search for modules */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set ssh username */
    ret = nc_client_ssh_ch_set_username("test_ch_ssh");
    assert_int_equal(ret, 0);

    /* add client's key pair */
    ret = nc_client_ssh_ch_add_keypair(TESTS_DIR "/data/id_ed25519.pub", TESTS_DIR "/data/id_ed25519");
    assert_int_equal(ret, 0);

    /* add call-home bind */
    ret = nc_client_ssh_ch_add_bind_listen("127.0.0.1", TEST_PORT);
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&test_ctx->barrier);
    /* connect */
    ret = nc_accept_callhome(NC_ACCEPT_TIMEOUT, NULL, &session);
    assert_int_equal(ret, 1);

    ret = nc_client_ssh_ch_del_bind("127.0.0.1", TEST_PORT);
    assert_int_equal(ret, 0);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_ch_free_test_data(void *test_data)
{
    struct test_ch_data *test_ch_data;

    test_ch_data = test_data;
    lyd_free_tree(test_ch_data->tree);
    free(test_ch_data);
}

static int
setup_ssh(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx;
    struct test_ch_data *test_data;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    test_data = calloc(1, sizeof *test_data);
    assert_non_null(test_data);

    test_ctx->test_data = test_data;
    test_ctx->free_test_data = test_nc_ch_free_test_data;
    *state = test_ctx;

    /* set call-home address and port */
    ret = nc_server_config_add_ch_address_port(test_ctx->ctx, "ch_ssh", "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT_STR, &tree);
    assert_int_equal(ret, 0);

    /* set connection type to persistent */
    ret = nc_server_config_add_ch_persistent(test_ctx->ctx, "ch_ssh", &tree);
    assert_int_equal(ret, 0);

    /* set the period of the periodic connection type, this should remove the persistent connection type */
    ret = nc_server_config_add_ch_period(test_ctx->ctx, "ch_ssh", 3, &tree);
    assert_int_equal(ret, 0);

    /* set call-home server hostkey */
    ret = nc_server_config_add_ch_ssh_hostkey(test_ctx->ctx, "ch_ssh", "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &tree);
    assert_int_equal(ret, 0);

    /* set call-home client's pubkey */
    ret = nc_server_config_add_ch_ssh_user_pubkey(test_ctx->ctx, "ch_ssh", "endpt", "test_ch_ssh", "pubkey", TESTS_DIR "/data/id_ed25519.pub", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    test_data->tree = tree;
    return 0;
}

static void
test_nc_ch_ssh(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    /* client */
    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);

    /* server */
    ret = pthread_create(&tids[1], NULL, server_thread_ssh, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void *
server_thread_tls(void *arg)
{
    int ret;
    struct nc_pollsession *ps;
    struct ln2_test_ctx *test_ctx = arg;
    struct test_ch_data *test_data = test_ctx->test_data;

    /* prepare data for deleting the call-home client */
    ret = nc_server_config_del_ch_client("ch_tls", &test_data->tree);
    assert_int_equal(ret, 0);

    /* new poll session */
    ps = nc_ps_new();
    assert_non_null(ps);

    pthread_barrier_wait(&test_ctx->barrier);
    /* create the call-home client thread */
    ret = nc_connect_ch_client_dispatch("ch_tls", ch_session_acquire_ctx_cb,
            ch_session_release_ctx_cb, test_ctx, ch_new_session_cb, ps);
    assert_int_equal(ret, 0);

    /* poll */
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
        if (ret & (NC_PSPOLL_TIMEOUT | NC_PSPOLL_NOSESSIONS)) {
            usleep(500);
        }
    } while (!(ret & NC_PSPOLL_SESSION_TERM));

    /* delete the call-home client, the thread should end */
    ret = nc_server_config_setup_data(test_data->tree);
    assert_int_equal(ret, 0);

    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);
    return NULL;
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

    /* add client's cert */
    ret = nc_client_tls_ch_set_cert_key_paths(TESTS_DIR "/data/client.crt", TESTS_DIR "/data/client.key");
    assert_int_equal(ret, 0);

    /* set client ca */
    ret = nc_client_tls_ch_set_trusted_ca_paths(TESTS_DIR "/data/serverca.pem", NULL);
    assert_int_equal(ret, 0);

    /* add call-home bind */
    ret = nc_client_tls_ch_add_bind_listen("127.0.0.1", TEST_PORT_2);
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&test_ctx->barrier);
    /* connect */
    ret = nc_accept_callhome(NC_ACCEPT_TIMEOUT, NULL, &session);
    assert_int_equal(ret, 1);

    ret = nc_client_tls_ch_del_bind("127.0.0.1", TEST_PORT_2);
    assert_int_equal(ret, 0);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_ch_tls(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    /* client */
    ret = pthread_create(&tids[0], NULL, client_thread_tls, *state);
    assert_int_equal(ret, 0);

    /* server */
    ret = pthread_create(&tids[1], NULL, server_thread_tls, *state);
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
    struct ln2_test_ctx *test_ctx;
    struct test_ch_data *test_data;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    test_data = calloc(1, sizeof *test_data);
    assert_non_null(test_data);

    test_ctx->test_data = test_data;
    test_ctx->free_test_data = test_nc_ch_free_test_data;
    *state = test_ctx;

    /* set call-home address and port */
    ret = nc_server_config_add_ch_address_port(test_ctx->ctx, "ch_tls", "endpt", NC_TI_TLS, "127.0.0.1", TEST_PORT_2_STR, &tree);
    assert_int_equal(ret, 0);

    /* set call-home server certificate */
    ret = nc_server_config_add_ch_tls_server_cert(test_ctx->ctx, "ch_tls", "endpt", TESTS_DIR "/data/server.key", NULL, TESTS_DIR "/data/server.crt", &tree);
    assert_int_equal(ret, 0);

    /* set call-home client end entity certificate */
    ret = nc_server_config_add_ch_tls_client_cert(test_ctx->ctx, "ch_tls", "endpt", "ee-cert", TESTS_DIR "/data/client.crt", &tree);
    assert_int_equal(ret, 0);

    /* set call-home client certificate authority certificate */
    ret = nc_server_config_add_ch_tls_ca_cert(test_ctx->ctx, "ch_tls", "endpt", "ca-cert", TESTS_DIR "/data/serverca.pem", &tree);
    assert_int_equal(ret, 0);

    /* set call-home CTN */
    ret = nc_server_config_add_ch_tls_ctn(test_ctx->ctx, "ch_tls", "endpt", 1,
            "04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D",
            NC_TLS_CTN_SPECIFIED, "ch_client_tls", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    test_data->tree = tree;
    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_ch_ssh, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_ch_tls, setup_tls, ln2_glob_test_teardown),
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(2, &TEST_PORT, &TEST_PORT_STR, &TEST_PORT_2, &TEST_PORT_2_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
