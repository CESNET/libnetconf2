/**
 * @file test_ch.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 Call-home test
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

#include "ln2_test.h"
#include "tests/config.h"

#define NC_PS_POLL_TIMEOUT 2000

#define NC_ACCEPT_TIMEOUT 2000

struct ly_ctx *ctx;

struct test_state {
    pthread_barrier_t barrier;
    struct lyd_node *ssh_tree;
    struct lyd_node *tls_tree;
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
    (void) cb_data;
    return ctx;
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
    struct test_state *state = arg;
    struct nc_pollsession *ps;

    /* set print clb so we get access to messages */
    nc_set_print_clb_session(test_msg_callback);
    buffer[0] = '\0';
    strcpy(expected, "reconnecting in");

    /* prepare data for deleting the call-home client */
    ret = nc_server_config_del_ch_client("ch_ssh", &state->ssh_tree);
    assert_int_equal(ret, 0);

    /* new poll session */
    ps = nc_ps_new();
    assert_non_null(ps);

    pthread_barrier_wait(&state->barrier);
    /* create the call-home client thread */
    ret = nc_connect_ch_client_dispatch("ch_ssh", ch_session_acquire_ctx_cb,
            ch_session_release_ctx_cb, NULL, ch_new_session_cb, ps);
    assert_int_equal(ret, 0);

    /* poll */
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
        if (ret & (NC_PSPOLL_TIMEOUT | NC_PSPOLL_NOSESSIONS)) {
            usleep(500);
        }
    } while (!strlen(buffer));

    /* delete the call-home client, the thread should end */
    ret = nc_server_config_setup_data(state->ssh_tree);
    assert_int_equal(ret, 0);

    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);
    nc_server_destroy();
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

    pthread_barrier_wait(&state->barrier);
    /* connect */
    ret = nc_accept_callhome(NC_ACCEPT_TIMEOUT, NULL, &session);
    assert_int_equal(ret, 1);

    ret = nc_client_ssh_ch_del_bind("127.0.0.1", TEST_PORT);
    assert_int_equal(ret, 0);

    nc_session_free(session, NULL);
    return NULL;
}

static int
setup_ssh(void **state)
{
    int ret;
    struct test_state *test_state;

    nc_verbosity(NC_VERB_VERBOSE);

    /* init barrier */
    test_state = malloc(sizeof *test_state);
    assert_non_null(test_state);

    ret = pthread_barrier_init(&test_state->barrier, NULL, 2);
    assert_int_equal(ret, 0);

    test_state->ssh_tree = NULL;
    *state = test_state;

    /* create new context */
    ret = ly_ctx_new(MODULES_DIR, 0, &ctx);
    assert_int_equal(ret, 0);

    /* load default modules into context */
    ret = nc_server_init_ctx(&ctx);
    assert_int_equal(ret, 0);

    /* load ietf-netconf-server module and it's imports into context */
    ret = nc_server_config_load_modules(&ctx);
    assert_int_equal(ret, 0);

    /* set call-home address and port */
    ret = nc_server_config_add_ch_address_port(ctx, "ch_ssh", "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT_STR, &test_state->ssh_tree);
    assert_int_equal(ret, 0);

    /* set connection type to persistent */
    ret = nc_server_config_add_ch_persistent(ctx, "ch_ssh", &test_state->ssh_tree);
    assert_int_equal(ret, 0);

    /* set the period of the periodic connection type, this should remove the persistent connection type */
    ret = nc_server_config_add_ch_period(ctx, "ch_ssh", 3, &test_state->ssh_tree);
    assert_int_equal(ret, 0);

    /* set call-home server hostkey */
    ret = nc_server_config_add_ch_ssh_hostkey(ctx, "ch_ssh", "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &test_state->ssh_tree);
    assert_int_equal(ret, 0);

    /* set call-home client's pubkey */
    ret = nc_server_config_add_ch_ssh_user_pubkey(ctx, "ch_ssh", "endpt", "test_ch_ssh", "pubkey", TESTS_DIR "/data/id_ed25519.pub", &test_state->ssh_tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(test_state->ssh_tree);
    assert_int_equal(ret, 0);

    /* initialize server */
    ret = nc_server_init();
    assert_int_equal(ret, 0);

    /* initialize client */
    ret = nc_client_init();
    assert_int_equal(ret, 0);

    return 0;
}

static int
teardown_ssh(void **state)
{
    int ret = 0;
    struct test_state *test_state;

    assert_non_null(state);
    test_state = *state;

    ret = pthread_barrier_destroy(&test_state->barrier);
    assert_int_equal(ret, 0);

    lyd_free_tree(test_state->ssh_tree);

    free(*state);
    nc_client_destroy();
    ly_ctx_destroy(ctx);

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
    struct test_state *state = arg;
    struct nc_pollsession *ps;

    /* prepare data for deleting the call-home client */
    ret = nc_server_config_del_ch_client("ch_tls", &state->tls_tree);
    assert_int_equal(ret, 0);

    /* new poll session */
    ps = nc_ps_new();
    assert_non_null(ps);

    pthread_barrier_wait(&state->barrier);
    /* create the call-home client thread */
    ret = nc_connect_ch_client_dispatch("ch_tls", ch_session_acquire_ctx_cb,
            ch_session_release_ctx_cb, NULL, ch_new_session_cb, ps);
    assert_int_equal(ret, 0);

    /* poll */
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
        if (ret & (NC_PSPOLL_TIMEOUT | NC_PSPOLL_NOSESSIONS)) {
            usleep(500);
        }
    } while (!(ret & NC_PSPOLL_SESSION_TERM));

    /* delete the call-home client, the thread should end */
    ret = nc_server_config_setup_data(state->tls_tree);
    assert_int_equal(ret, 0);

    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);
    nc_server_destroy();
    return NULL;
}

static void *
client_thread_tls(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct test_state *state = arg;

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

    pthread_barrier_wait(&state->barrier);
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
    struct test_state *test_state;

    nc_verbosity(NC_VERB_VERBOSE);

    /* init barrier */
    test_state = malloc(sizeof *test_state);
    assert_non_null(test_state);

    ret = pthread_barrier_init(&test_state->barrier, NULL, 2);
    assert_int_equal(ret, 0);

    test_state->tls_tree = NULL;
    *state = test_state;

    /* create new context */
    ret = ly_ctx_new(MODULES_DIR, 0, &ctx);
    assert_int_equal(ret, 0);

    /* load default modules into context */
    ret = nc_server_init_ctx(&ctx);
    assert_int_equal(ret, 0);

    /* load ietf-netconf-server module and it's imports into context */
    ret = nc_server_config_load_modules(&ctx);
    assert_int_equal(ret, 0);

    /* set call-home address and port */
    ret = nc_server_config_add_ch_address_port(ctx, "ch_tls", "endpt", NC_TI_TLS, "127.0.0.1", TEST_PORT_2_STR, &test_state->tls_tree);
    assert_int_equal(ret, 0);

    /* set call-home server certificate */
    ret = nc_server_config_add_ch_tls_server_cert(ctx, "ch_tls", "endpt", TESTS_DIR "/data/server.key", NULL, TESTS_DIR "/data/server.crt", &test_state->tls_tree);
    assert_int_equal(ret, 0);

    /* set call-home client end entity certificate */
    ret = nc_server_config_add_ch_tls_client_cert(ctx, "ch_tls", "endpt", "ee-cert", TESTS_DIR "/data/client.crt", &test_state->tls_tree);
    assert_int_equal(ret, 0);

    /* set call-home client certificate authority certificate */
    ret = nc_server_config_add_ch_tls_ca_cert(ctx, "ch_tls", "endpt", "ca-cert", TESTS_DIR "/data/serverca.pem", &test_state->tls_tree);
    assert_int_equal(ret, 0);

    /* set call-home CTN */
    ret = nc_server_config_add_ch_tls_ctn(ctx, "ch_tls", "endpt", 1,
            "04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D",
            NC_TLS_CTN_SPECIFIED, "ch_client_tls", &test_state->tls_tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(test_state->tls_tree);
    assert_int_equal(ret, 0);

    /* initialize server */
    ret = nc_server_init();
    assert_int_equal(ret, 0);

    /* initialize client */
    ret = nc_client_init();
    assert_int_equal(ret, 0);

    return 0;
}

static int
teardown_tls(void **state)
{
    int ret = 0;
    struct test_state *test_state;

    assert_non_null(state);
    test_state = *state;

    ret = pthread_barrier_destroy(&test_state->barrier);
    assert_int_equal(ret, 0);

    lyd_free_tree(test_state->tls_tree);

    free(*state);
    nc_client_destroy();
    ly_ctx_destroy(ctx);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_ch_ssh, setup_ssh, teardown_ssh),
        cmocka_unit_test_setup_teardown(test_nc_ch_tls, setup_tls, teardown_tls),
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(2, &TEST_PORT, &TEST_PORT_STR, &TEST_PORT_2, &TEST_PORT_2_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
