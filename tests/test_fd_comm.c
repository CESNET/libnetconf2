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

struct state {
    struct nc_session *server_session;
    struct nc_session *client_session;
    struct ly_ctx *ctx;
    pthread_mutex_t state_lock;
    pthread_barrier_t barrier;
    int glob_state;
};

static struct nc_server_reply *
my_get_rpc_clb(struct lyd_node *rpc, struct nc_session *UNUSED(session))
{
    assert_string_equal(rpc->schema->name, "get");

    return nc_server_reply_ok();
}

static struct nc_server_reply *
my_getconfig_rpc_clb(struct lyd_node *rpc, struct nc_session *session)
{
    struct lyd_node *data;

    assert_string_equal(rpc->schema->name, "get-config");

    lyd_new_path(NULL, session->ctx, "/ietf-netconf:get-config/data", NULL, LYD_NEW_VAL_OUTPUT, &data);
    assert_non_null(data);

    return nc_server_reply_data(data, NC_WD_EXPLICIT, NC_PARAMTYPE_FREE);
}

static struct nc_server_reply *
my_commit_rpc_clb(struct lyd_node *rpc, struct nc_session *session)
{
    struct state *st = nc_session_get_data(session);

    assert_string_equal(rpc->schema->name, "commit");
    assert_ptr_equal(session, st->server_session);

    /* update state */
    pthread_mutex_lock(&st->state_lock);
    st->glob_state = 1;

    /* wait until the client receives the notification */
    while (st->glob_state != 3) {
        pthread_mutex_unlock(&st->state_lock);
        usleep(100000);
        pthread_mutex_lock(&st->state_lock);
    }
    pthread_mutex_unlock(&st->state_lock);

    return nc_server_reply_ok();
}

static int
setup_f(void **state)
{
    struct state *st;
    const struct lys_module *module;
    struct lysc_node *node;
    const char *nc_features[] = {"candidate", NULL};

    st = calloc(1, sizeof *st);
    if (!st) {
        return 1;
    }

    pthread_mutex_init(&st->state_lock, NULL);
    pthread_barrier_init(&st->barrier, NULL, 2);

    /* create ctx */
    ly_ctx_new(ly_yang_module_dir(), 0, &st->ctx);
    assert_non_null(st->ctx);
    ly_ctx_set_searchdir(st->ctx, TESTS_DIR "/data/modules");

    /* load modules */
    module = ly_ctx_load_module(st->ctx, "ietf-netconf-acm", NULL, NULL);
    assert_non_null(module);

    module = ly_ctx_load_module(st->ctx, "ietf-netconf", NULL, nc_features);
    assert_non_null(module);

    module = ly_ctx_load_module(st->ctx, "nc-notifications", NULL, NULL);
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

    *state = st;
    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = *state;

    nc_server_destroy();
    ly_ctx_destroy(st->ctx);
    pthread_mutex_destroy(&st->state_lock);
    pthread_barrier_destroy(&st->barrier);
    free(st);

    return 0;
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

    sess->io_rd_lock = malloc(sizeof *sess->io_rd_lock);
    sess->io_wr_lock = malloc(sizeof *sess->io_wr_lock);
    if (!sess->io_rd_lock || !sess->io_wr_lock) {
        goto error;
    }
    pthread_mutex_init(sess->io_rd_lock, NULL);
    pthread_mutex_init(sess->io_wr_lock, NULL);

    return sess;

error:
    free(sess);
    return NULL;
}

static int
setup_sessions(void **state)
{
    struct state *st = *state;
    int sock[2];

    /* create communication channel */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sock);

    /* create server session */
    st->server_session = test_new_session(NC_SERVER);
    NC_SESSION_STATUS_SET(st->server_session, NC_STATUS_RUNNING);
    st->server_session->id = 1;
    st->server_session->ti_type = NC_TI_FD;
    st->server_session->ti.fd.in = sock[0];
    st->server_session->ti.fd.out = sock[0];
    st->server_session->ctx = st->ctx;
    st->server_session->flags = NC_SESSION_SHAREDCTX;

    nc_session_set_data(st->server_session, st);

    /* create client session */
    st->client_session = test_new_session(NC_CLIENT);
    NC_SESSION_STATUS_SET(st->client_session, NC_STATUS_RUNNING);
    st->client_session->id = 1;
    st->client_session->ti_type = NC_TI_FD;
    st->client_session->ti.fd.in = sock[1];
    st->client_session->ti.fd.out = sock[1];
    st->client_session->ctx = st->ctx;
    st->client_session->flags = NC_SESSION_SHAREDCTX;
    st->client_session->opts.client.msgid = 50;

    return 0;
}

static int
teardown_sessions(void **state)
{
    struct state *st = *state;

    close(st->server_session->ti.fd.in);
    st->server_session->ti.fd.in = -1;
    nc_session_free(st->server_session, NULL);

    close(st->client_session->ti.fd.in);
    st->client_session->ti.fd.in = -1;
    nc_session_free(st->client_session, NULL);

    return 0;
}

static void
test_send_recv_ok(struct state *st)
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

    msgtype = nc_send_rpc(st->client_session, rpc, 0, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* server RPC, send reply */
    ps = nc_ps_new();
    assert_non_null(ps);
    nc_ps_add_session(ps, st->server_session);

    ret = nc_ps_poll(ps, 0, NULL);
    assert_int_equal(ret, NC_PSPOLL_RPC);

    /* server finished */
    nc_ps_free(ps);

    /* client reply */
    msgtype = nc_recv_reply(st->client_session, rpc, msgid, 0, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);

    nc_rpc_free(rpc);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");
    lyd_free_tree(envp);
}

static void
test_send_recv_ok_10(void **state)
{
    struct state *st = *state;

    st->server_session->version = NC_PROT_VERSION_10;
    st->client_session->version = NC_PROT_VERSION_10;

    test_send_recv_ok(st);
}

static void
test_send_recv_ok_11(void **state)
{
    struct state *st = *state;

    st->server_session->version = NC_PROT_VERSION_11;
    st->client_session->version = NC_PROT_VERSION_11;

    test_send_recv_ok(st);
}

static void
test_send_recv_error(struct state *st)
{
    int ret;
    uint64_t msgid;
    NC_MSG_TYPE msgtype;
    struct nc_rpc *rpc;
    struct lyd_node *envp, *op, *node;
    const struct lysc_node *schema;
    struct nc_pollsession *ps;

    /* client RPC */
    rpc = nc_rpc_kill(1);
    assert_non_null(rpc);

    msgtype = nc_send_rpc(st->client_session, rpc, 0, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* server RPC, send reply */
    ps = nc_ps_new();
    assert_non_null(ps);
    nc_ps_add_session(ps, st->server_session);

    ret = nc_ps_poll(ps, 0, NULL);
    assert_int_equal(ret, NC_PSPOLL_RPC | NC_PSPOLL_REPLY_ERROR);

    /* server finished */
    nc_ps_free(ps);

    /* client reply */
    msgtype = nc_recv_reply(st->client_session, rpc, msgid, 0, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);

    nc_rpc_free(rpc);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "rpc-error");
    schema = lys_find_path(LYD_CTX(envp), NULL, "/ietf-netconf:rpc-error/error-tag", 0);
    lyd_find_sibling_val(lyd_child(lyd_child(envp)), schema, NULL, 0, &node);
    assert_non_null(node);
    assert_string_equal(lyd_get_value(node), "operation-not-supported");
    lyd_free_tree(envp);
    assert_null(op);
}

static void
test_send_recv_error_10(void **state)
{
    struct state *st = *state;

    st->server_session->version = NC_PROT_VERSION_10;
    st->client_session->version = NC_PROT_VERSION_10;

    test_send_recv_error(st);
}

static void
test_send_recv_error_11(void **state)
{
    struct state *st = *state;

    st->server_session->version = NC_PROT_VERSION_11;
    st->client_session->version = NC_PROT_VERSION_11;

    test_send_recv_error(st);
}

static void
test_send_recv_data(struct state *st)
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

    msgtype = nc_send_rpc(st->client_session, rpc, 0, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* server RPC, send reply */
    ps = nc_ps_new();
    assert_non_null(ps);
    nc_ps_add_session(ps, st->server_session);

    ret = nc_ps_poll(ps, 0, NULL);
    assert_int_equal(ret, NC_PSPOLL_RPC);

    /* server finished */
    nc_ps_free(ps);

    /* client reply */
    msgtype = nc_recv_reply(st->client_session, rpc, msgid, 0, &envp, &op);
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
    struct state *st = *state;

    st->server_session->version = NC_PROT_VERSION_10;
    st->client_session->version = NC_PROT_VERSION_10;

    test_send_recv_data(st);
}

static void
test_send_recv_data_11(void **state)
{
    struct state *st = *state;

    st->server_session->version = NC_PROT_VERSION_11;
    st->client_session->version = NC_PROT_VERSION_11;

    test_send_recv_data(st);
}

static void *
server_send_notif_thread(void *arg)
{
    struct state *st = arg;
    NC_MSG_TYPE msg_type;
    struct lyd_node *notif_tree;
    struct nc_server_notif *notif;
    struct timespec ts;
    char *buf;

    /* wait for the RPC callback to be called */
    pthread_mutex_lock(&st->state_lock);
    while (st->glob_state != 1) {
        pthread_mutex_unlock(&st->state_lock);
        usleep(1000);
        pthread_mutex_lock(&st->state_lock);
    }

    /* create notif */
    lyd_new_path(NULL, st->ctx, "/nc-notifications:notificationComplete", NULL, 0, &notif_tree);
    assert_non_null(notif_tree);
    clock_gettime(CLOCK_REALTIME, &ts);
    ly_time_ts2str(&ts, &buf);
    notif = nc_server_notif_new(notif_tree, buf, NC_PARAMTYPE_FREE);
    assert_non_null(notif);

    /* send notif */
    nc_session_inc_notif_status(st->server_session);
    msg_type = nc_server_notif_send(st->server_session, notif, 100);
    nc_server_notif_free(notif);
    assert_int_equal(msg_type, NC_MSG_NOTIF);

    /* update state */
    st->glob_state = 2;
    pthread_barrier_wait(&st->barrier);
    pthread_mutex_unlock(&st->state_lock);

    return NULL;
}

static void *
thread_recv_notif(void *arg)
{
    struct state *st = arg;
    struct lyd_node *envp;
    struct lyd_node *op;
    NC_MSG_TYPE msgtype;

    pthread_barrier_wait(&st->barrier);
    msgtype = nc_recv_notif(st->client_session, 1000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_NOTIF);
    assert_string_equal(op->schema->name, "notificationComplete");

    lyd_free_tree(envp);
    lyd_free_tree(op);

    pthread_mutex_lock(&st->state_lock);
    st->glob_state = 3;
    pthread_mutex_unlock(&st->state_lock);

    return NULL;
}

static void
test_send_recv_notif(struct state *st)
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

    msgtype = nc_send_rpc(st->client_session, rpc, 0, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* client subscription */
    pthread_create(&tid[0], NULL, thread_recv_notif, st);

    /* create server */
    ps = nc_ps_new();
    assert_non_null(ps);
    nc_ps_add_session(ps, st->server_session);

    /* server will send a notification */
    pthread_mutex_lock(&st->state_lock);
    st->glob_state = 0;
    pthread_mutex_unlock(&st->state_lock);
    ret = pthread_create(&tid[1], NULL, server_send_notif_thread, st);
    assert_int_equal(ret, 0);

    /* server blocked on RPC */
    ret = nc_ps_poll(ps, 0, NULL);
    assert_int_equal(ret, NC_PSPOLL_RPC);

    /* RPC, notification finished fine */
    pthread_mutex_lock(&st->state_lock);
    assert_int_equal(st->glob_state, 3);
    pthread_mutex_unlock(&st->state_lock);

    /* server finished */
    ret = 0;
    ret |= pthread_join(tid[0], NULL);
    ret |= pthread_join(tid[1], NULL);
    assert_int_equal(ret, 0);
    nc_ps_free(ps);

    /* client reply */
    msgtype = nc_recv_reply(st->client_session, rpc, msgid, 0, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    nc_rpc_free(rpc);

    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");
    lyd_free_tree(envp);
    assert_null(op);
}

static void
test_send_recv_notif_10(void **state)
{
    struct state *st = *state;

    st->server_session->version = NC_PROT_VERSION_10;
    st->client_session->version = NC_PROT_VERSION_10;

    test_send_recv_notif(st);
}

static void
test_send_recv_notif_11(void **state)
{
    struct state *st = *state;

    st->server_session->version = NC_PROT_VERSION_11;
    st->client_session->version = NC_PROT_VERSION_11;

    test_send_recv_notif(st);
}

static void
test_send_recv_malformed_10(void **state)
{
    struct state *st = *state;
    int ret;
    struct nc_pollsession *ps;
    struct nc_rpc *rpc;
    struct lyd_node *envp, *op, *node;
    const struct lysc_node *schema;
    NC_MSG_TYPE msgtype;
    const char *msg;

    st->server_session->version = NC_PROT_VERSION_10;
    st->client_session->version = NC_PROT_VERSION_10;

    /* write malformed message */
    msg =
            "<nc:rpc xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "  <nc:commit/>"
            "</nc:rpc>"
            "]]>]]>";
    assert_int_equal(write(st->client_session->ti.fd.out, msg, strlen(msg)), strlen(msg));
    rpc = nc_rpc_commit(0, 0, NULL, NULL, 0);
    assert_non_null(rpc);

    /* server RPC, send reply */
    ps = nc_ps_new();
    assert_non_null(ps);
    nc_ps_add_session(ps, st->server_session);

    ret = nc_ps_poll(ps, 0, NULL);
    assert_int_equal(ret, NC_PSPOLL_BAD_RPC | NC_PSPOLL_REPLY_ERROR);

    /* server finished */
    nc_ps_free(ps);

    /* client reply */
    msgtype = nc_recv_reply(st->client_session, rpc, 0, 0, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY_ERR_MSGID);

    nc_rpc_free(rpc);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "rpc-error");
    schema = lys_find_path(LYD_CTX(envp), NULL, "/ietf-netconf:rpc-error/error-tag", 0);
    lyd_find_sibling_val(lyd_child(lyd_child(envp)), schema, NULL, 0, &node);
    assert_non_null(node);
    assert_string_equal(lyd_get_value(node), "missing-attribute");
    lyd_free_tree(envp);
    assert_null(op);
}

int
main(void)
{
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

    return cmocka_run_group_tests(comm, setup_f, teardown_f);
}
