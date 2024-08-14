/**
 * \file test_fd_comm.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 tests - file descriptor basic RPC communication
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include <messages_p.h>
#include <session_p.h>

#include "ln2_test.h"

struct nc_session *server_session;
struct nc_session *client_session;
struct ly_ctx *ctx;
pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_barrier_t barrier;
int glob_state;

struct nc_server_reply *
my_get_rpc_clb(struct lyd_node *rpc, struct nc_session *session)
{
    assert_string_equal(rpc->schema->name, "get");
    assert_ptr_equal(session, server_session);

    return nc_server_reply_ok();
}

struct nc_server_reply *
my_getconfig_rpc_clb(struct lyd_node *rpc, struct nc_session *session)
{
    struct lyd_node *data;

    assert_string_equal(rpc->schema->name, "get-config");
    assert_ptr_equal(session, server_session);

    lyd_new_path(NULL, session->ctx, "/ietf-netconf:get-config/data", NULL, LYD_NEW_VAL_OUTPUT, &data);
    assert_non_null(data);

    return nc_server_reply_data(data, NC_WD_EXPLICIT, NC_PARAMTYPE_FREE);
}

struct nc_server_reply *
my_commit_rpc_clb(struct lyd_node *rpc, struct nc_session *session)
{
    assert_string_equal(rpc->schema->name, "commit");
    assert_ptr_equal(session, server_session);

    /* update state */
    pthread_mutex_lock(&state_lock);
    glob_state = 1;

    /* wait until the client receives the notification */
    while (glob_state != 3) {
        pthread_mutex_unlock(&state_lock);
        usleep(100000);
        pthread_mutex_lock(&state_lock);
    }
    pthread_mutex_unlock(&state_lock);

    return nc_server_reply_ok();
}

static struct nc_session *
test_new_session(NC_SIDE side)
{
    struct nc_session *sess;
    struct timespec ts;

    sess = calloc(1, sizeof *sess);
    if (!sess) {
        return NULL;
    }

    sess->side = side;

    if (side == NC_SERVER) {
        pthread_mutex_init(&sess->opts.server.ntf_status_lock, NULL);
        pthread_mutex_init(&sess->opts.server.rpc_lock, NULL);
        pthread_cond_init(&sess->opts.server.rpc_cond, NULL);
        sess->opts.server.rpc_inuse = 0;

        nc_timeouttime_get(&ts, 0);
        sess->opts.server.last_rpc = ts.tv_sec;
    }

    sess->io_lock = malloc(sizeof *sess->io_lock);
    if (!sess->io_lock) {
        goto error;
    }
    pthread_mutex_init(sess->io_lock, NULL);

    return sess;

error:
    free(sess);
    return NULL;
}

static int
setup_sessions(void **state)
{
    (void)state;
    int sock[2];

    /* create communication channel */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sock);

    /* create server session */
    server_session = test_new_session(NC_SERVER);
    server_session->status = NC_STATUS_RUNNING;
    server_session->id = 1;
    server_session->ti_type = NC_TI_FD;
    server_session->ti.fd.in = sock[0];
    server_session->ti.fd.out = sock[0];
    server_session->ctx = ctx;
    server_session->flags = NC_SESSION_SHAREDCTX;

    /* create client session */
    client_session = test_new_session(NC_CLIENT);
    client_session->status = NC_STATUS_RUNNING;
    client_session->id = 1;
    client_session->ti_type = NC_TI_FD;
    client_session->ti.fd.in = sock[1];
    client_session->ti.fd.out = sock[1];
    client_session->ctx = ctx;
    client_session->flags = NC_SESSION_SHAREDCTX;
    client_session->opts.client.msgid = 50;

    return 0;
}

static int
teardown_sessions(void **state)
{
    (void)state;

    close(server_session->ti.fd.in);
    server_session->ti.fd.in = -1;
    nc_session_free(server_session, NULL);

    close(client_session->ti.fd.in);
    client_session->ti.fd.in = -1;
    nc_session_free(client_session, NULL);

    return 0;
}

static void
test_send_recv_ok(void)
{
    int ret;
    uint64_t msgid;
    NC_MSG_TYPE msgtype;
    struct nc_rpc *rpc;
    struct lyd_node *envp, *op;
    struct nc_pollsession *ps;

    /* client RPC */
    rpc = nc_rpc_get(NULL, 0, 0);
    assert_non_null(rpc);

    msgtype = nc_send_rpc(client_session, rpc, 0, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* server RPC, send reply */
    ps = nc_ps_new();
    assert_non_null(ps);
    nc_ps_add_session(ps, server_session);

    ret = nc_ps_poll(ps, 0, NULL);
    assert_int_equal(ret, NC_PSPOLL_RPC);

    /* server finished */
    nc_ps_free(ps);

    /* client reply */
    msgtype = nc_recv_reply(client_session, rpc, msgid, 0, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);

    nc_rpc_free(rpc);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");
    lyd_free_tree(envp);
}

static void
test_send_recv_ok_10(void **state)
{
    (void)state;

    server_session->version = NC_VERSION_10;
    client_session->version = NC_VERSION_10;

    test_send_recv_ok();
}

static void
test_send_recv_ok_11(void **state)
{
    (void)state;

    server_session->version = NC_VERSION_11;
    client_session->version = NC_VERSION_11;

    test_send_recv_ok();
}

static void
test_send_recv_error(void)
{
    int ret;
    uint64_t msgid;
    NC_MSG_TYPE msgtype;
    struct nc_rpc *rpc;
    struct lyd_node *envp, *op, *node;
    struct nc_pollsession *ps;

    /* client RPC */
    rpc = nc_rpc_kill(1);
    assert_non_null(rpc);

    msgtype = nc_send_rpc(client_session, rpc, 0, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* server RPC, send reply */
    ps = nc_ps_new();
    assert_non_null(ps);
    nc_ps_add_session(ps, server_session);

    ret = nc_ps_poll(ps, 0, NULL);
    assert_int_equal(ret, NC_PSPOLL_RPC | NC_PSPOLL_REPLY_ERROR);

    /* server finished */
    nc_ps_free(ps);

    /* client reply */
    msgtype = nc_recv_reply(client_session, rpc, msgid, 0, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);

    nc_rpc_free(rpc);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "rpc-error");
    lyd_find_sibling_opaq_next(lyd_child(lyd_child(envp)), "error-tag", &node);
    assert_non_null(node);
    assert_string_equal(((struct lyd_node_opaq *)node)->value, "operation-not-supported");
    lyd_free_tree(envp);
    assert_null(op);
}

static void
test_send_recv_error_10(void **state)
{
    (void)state;

    server_session->version = NC_VERSION_10;
    client_session->version = NC_VERSION_10;

    test_send_recv_error();
}

static void
test_send_recv_error_11(void **state)
{
    (void)state;

    server_session->version = NC_VERSION_11;
    client_session->version = NC_VERSION_11;

    test_send_recv_error();
}

static void
test_send_recv_data(void)
{
    int ret;
    uint64_t msgid;
    NC_MSG_TYPE msgtype;
    struct nc_rpc *rpc;
    struct lyd_node *envp, *op;
    struct nc_pollsession *ps;

    /* client RPC */
    rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, NULL, 0, 0);
    assert_non_null(rpc);

    msgtype = nc_send_rpc(client_session, rpc, 0, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* server RPC, send reply */
    ps = nc_ps_new();
    assert_non_null(ps);
    nc_ps_add_session(ps, server_session);

    ret = nc_ps_poll(ps, 0, NULL);
    assert_int_equal(ret, NC_PSPOLL_RPC);

    /* server finished */
    nc_ps_free(ps);

    /* client reply */
    msgtype = nc_recv_reply(client_session, rpc, msgid, 0, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);

    nc_rpc_free(rpc);
    assert_non_null(envp);
    lyd_free_tree(envp);
    assert_non_null(op);
    lyd_free_tree(op);
}

static void
test_send_recv_data_10(void **state)
{
    (void)state;

    server_session->version = NC_VERSION_10;
    client_session->version = NC_VERSION_10;

    test_send_recv_data();
}

static void
test_send_recv_data_11(void **state)
{
    (void)state;

    server_session->version = NC_VERSION_11;
    client_session->version = NC_VERSION_11;

    test_send_recv_data();
}

static void *
server_send_notif_thread(void *arg)
{
    NC_MSG_TYPE msg_type;
    struct lyd_node *notif_tree;
    struct nc_server_notif *notif;
    struct timespec ts;
    char *buf;

    (void)arg;

    /* wait for the RPC callback to be called */
    pthread_mutex_lock(&state_lock);
    while (glob_state != 1) {
        pthread_mutex_unlock(&state_lock);
        usleep(1000);
        pthread_mutex_lock(&state_lock);
    }

    /* create notif */
    lyd_new_path(NULL, ctx, "/nc-notifications:notificationComplete", NULL, 0, &notif_tree);
    assert_non_null(notif_tree);
    clock_gettime(CLOCK_REALTIME, &ts);
    ly_time_ts2str(&ts, &buf);
    notif = nc_server_notif_new(notif_tree, buf, NC_PARAMTYPE_FREE);
    assert_non_null(notif);

    /* send notif */
    nc_session_inc_notif_status(server_session);
    msg_type = nc_server_notif_send(server_session, notif, 100);
    nc_server_notif_free(notif);
    assert_int_equal(msg_type, NC_MSG_NOTIF);

    /* update state */
    glob_state = 2;
    pthread_barrier_wait(&barrier);
    pthread_mutex_unlock(&state_lock);

    return NULL;
}

static void *
thread_recv_notif(void *arg)
{
    struct nc_session *session = (struct nc_session *)arg;
    struct lyd_node *envp;
    struct lyd_node *op;
    NC_MSG_TYPE msgtype;

    pthread_barrier_wait(&barrier);
    msgtype = nc_recv_notif(session, 1000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_NOTIF);
    assert_string_equal(op->schema->name, "notificationComplete");

    lyd_free_tree(envp);
    lyd_free_tree(op);

    pthread_mutex_lock(&state_lock);
    glob_state = 3;
    pthread_mutex_unlock(&state_lock);

    return (void *)0;
}

static void
test_send_recv_notif(void)
{
    int ret;
    pthread_t tid[2];
    uint64_t msgid;
    NC_MSG_TYPE msgtype;
    struct nc_rpc *rpc;
    struct lyd_node *envp, *op;
    struct nc_pollsession *ps;

    /* client RPC */
    rpc = nc_rpc_commit(0, 0, NULL, NULL, 0);
    assert_non_null(rpc);

    msgtype = nc_send_rpc(client_session, rpc, 0, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* client subscription */
    pthread_create(&tid[0], NULL, thread_recv_notif, client_session);

    /* create server */
    ps = nc_ps_new();
    assert_non_null(ps);
    nc_ps_add_session(ps, server_session);

    /* server will send a notification */
    pthread_mutex_lock(&state_lock);
    glob_state = 0;
    pthread_mutex_unlock(&state_lock);
    ret = pthread_create(&tid[1], NULL, server_send_notif_thread, NULL);
    assert_int_equal(ret, 0);

    /* server blocked on RPC */
    ret = nc_ps_poll(ps, 0, NULL);
    assert_int_equal(ret, NC_PSPOLL_RPC);

    /* RPC, notification finished fine */
    pthread_mutex_lock(&state_lock);
    assert_int_equal(glob_state, 3);
    pthread_mutex_unlock(&state_lock);

    /* server finished */
    ret = 0;
    ret |= pthread_join(tid[0], NULL);
    ret |= pthread_join(tid[1], NULL);
    assert_int_equal(ret, 0);
    nc_ps_free(ps);

    /* client reply */
    msgtype = nc_recv_reply(client_session, rpc, msgid, 0, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    nc_rpc_free(rpc);

    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");
    lyd_free_tree(envp);
    assert_null(op);
}

static void
test_send_recv_notif_10(void **state)
{
    (void)state;

    server_session->version = NC_VERSION_10;
    client_session->version = NC_VERSION_10;

    test_send_recv_notif();
}

static void
test_send_recv_notif_11(void **state)
{
    (void)state;

    server_session->version = NC_VERSION_11;
    client_session->version = NC_VERSION_11;

    test_send_recv_notif();
}

static void
test_send_recv_malformed_10(void **state)
{
    int ret;
    struct nc_pollsession *ps;
    struct nc_rpc *rpc;
    struct lyd_node *envp, *op, *node;
    NC_MSG_TYPE msgtype;
    const char *msg;

    (void)state;

    server_session->version = NC_VERSION_10;
    client_session->version = NC_VERSION_10;

    /* write malformed message */
    msg =
            "<nc:rpc xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "  <nc:commit/>"
            "</nc:rpc>"
            "]]>]]>";
    assert_int_equal(write(client_session->ti.fd.out, msg, strlen(msg)), strlen(msg));
    rpc = nc_rpc_commit(0, 0, NULL, NULL, 0);
    assert_non_null(rpc);

    /* server RPC, send reply */
    ps = nc_ps_new();
    assert_non_null(ps);
    nc_ps_add_session(ps, server_session);

    ret = nc_ps_poll(ps, 0, NULL);
    assert_int_equal(ret, NC_PSPOLL_BAD_RPC | NC_PSPOLL_REPLY_ERROR);

    /* server finished */
    nc_ps_free(ps);

    /* client reply */
    msgtype = nc_recv_reply(client_session, rpc, 0, 0, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY_ERR_MSGID);

    nc_rpc_free(rpc);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "rpc-error");
    lyd_find_sibling_opaq_next(lyd_child(lyd_child(envp)), "error-tag", &node);
    assert_non_null(node);
    assert_string_equal(((struct lyd_node_opaq *)node)->value, "missing-attribute");
    lyd_free_tree(envp);
    assert_null(op);
}

int
main(void)
{
    int ret;
    const struct lys_module *module;
    struct lysc_node *node;
    const char *nc_features[] = {"candidate", NULL};

    pthread_barrier_init(&barrier, NULL, 2);

    /* create ctx */
    ly_ctx_new(TESTS_DIR "/data/modules", 0, &ctx);
    assert_non_null(ctx);

    /* load modules */
    module = ly_ctx_load_module(ctx, "ietf-netconf-acm", NULL, NULL);
    assert_non_null(module);

    module = ly_ctx_load_module(ctx, "ietf-netconf", NULL, nc_features);
    assert_non_null(module);

    module = ly_ctx_load_module(ctx, "nc-notifications", NULL, NULL);
    assert_non_null(module);

    /* set RPC callbacks */
    node = (struct lysc_node *)lys_find_path(module->ctx, NULL, "/ietf-netconf:get", 0);
    assert_non_null(node);
    node->priv = my_get_rpc_clb;

    node = (struct lysc_node *)lys_find_path(module->ctx, NULL, "/ietf-netconf:get-config", 0);
    assert_non_null(node);
    node->priv = my_getconfig_rpc_clb;

    node = (struct lysc_node *)lys_find_path(module->ctx, NULL, "/ietf-netconf:commit", 0);
    assert_non_null(node);
    node->priv = my_commit_rpc_clb;

    nc_server_init();

    const struct CMUnitTest comm[] = {
        cmocka_unit_test_setup_teardown(test_send_recv_ok_10, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_error_10, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_data_10, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_notif_10, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_malformed_10, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_ok_11, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_error_11, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_data_11, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_notif_11, setup_sessions, teardown_sessions),
    };

    ret = cmocka_run_group_tests(comm, NULL, NULL);

    nc_server_destroy();
    ly_ctx_destroy(ctx);
    pthread_barrier_destroy(&barrier);

    return ret;
}
