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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include <session_client.h>
#include <session_server.h>
#include <session_p.h>
#include <messages_p.h>
#include "tests/config.h"

struct nc_session *server_session;
struct nc_session *client_session;
struct ly_ctx *ctx;
volatile int glob_state;

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

    data = lyd_new_path(NULL, session->ctx, "/ietf-netconf:get-config/data", NULL, LYD_ANYDATA_CONSTSTRING,
                        LYD_PATH_OPT_OUTPUT);
    assert_non_null(data);

    return nc_server_reply_data(data, NC_WD_EXPLICIT, NC_PARAMTYPE_FREE);
}

struct nc_server_reply *
my_commit_rpc_clb(struct lyd_node *rpc, struct nc_session *session)
{
    assert_string_equal(rpc->schema->name, "commit");
    assert_ptr_equal(session, server_session);

    /* update state */
    glob_state = 1;

    /* wait until the client receives the notification */
    while (glob_state != 3) {
        usleep(100000);
    }

    return nc_server_reply_ok();
}

static struct nc_session *
test_new_session(NC_SIDE side)
{
    struct nc_session *sess;

    sess = calloc(1, sizeof *sess);
    if (!sess) {
        return NULL;
    }

    sess->side = side;

    if (side == NC_SERVER) {
        sess->opts.server.rpc_lock = malloc(sizeof *sess->opts.server.rpc_lock);
        sess->opts.server.rpc_cond = malloc(sizeof *sess->opts.server.rpc_cond);
        sess->opts.server.rpc_inuse = malloc(sizeof *sess->opts.server.rpc_inuse);
        if (!sess->opts.server.rpc_lock || !sess->opts.server.rpc_cond || !sess->opts.server.rpc_inuse) {
            goto error;
        }
        pthread_mutex_init(sess->opts.server.rpc_lock, NULL);
        pthread_cond_init(sess->opts.server.rpc_cond, NULL);
        *sess->opts.server.rpc_inuse = 0;
    }

    sess->io_lock = malloc(sizeof *sess->io_lock);
    if (!sess->io_lock) {
        goto error;
    }
    pthread_mutex_init(sess->io_lock, NULL);

    return sess;

error:
    if (side == NC_SERVER) {
        free(sess->opts.server.rpc_lock);
        free(sess->opts.server.rpc_cond);
        free((int *)sess->opts.server.rpc_inuse);
    }
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
    nc_session_free(server_session, NULL);

    close(client_session->ti.fd.in);
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
    struct nc_reply *reply;
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
    msgtype = nc_recv_reply(client_session, rpc, msgid, 0, 0, &reply);
    assert_int_equal(msgtype, NC_MSG_REPLY);

    nc_rpc_free(rpc);
    assert_int_equal(reply->type, NC_RPL_OK);
    nc_reply_free(reply);
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
    struct nc_reply *reply;
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
    msgtype = nc_recv_reply(client_session, rpc, msgid, 0, 0, &reply);
    assert_int_equal(msgtype, NC_MSG_REPLY);

    nc_rpc_free(rpc);
    assert_int_equal(reply->type, NC_RPL_ERROR);
    assert_string_equal(((struct nc_reply_error *)reply)->err->tag, "operation-not-supported");
    nc_reply_free(reply);
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
    struct nc_reply *reply;
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
    msgtype = nc_recv_reply(client_session, rpc, msgid, 0, 0, &reply);
    assert_int_equal(msgtype, NC_MSG_REPLY);

    nc_rpc_free(rpc);
    assert_int_equal(reply->type, NC_RPL_DATA);
    nc_reply_free(reply);
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

static void
test_notif_clb(struct nc_session *session, const struct nc_notif *notif)
{
    assert_ptr_equal(session, client_session);
    assert_string_equal(notif->tree->schema->name, "notificationComplete");

    /* client notification received, update state */
    while (glob_state != 2) {
        usleep(1000);
    }
    glob_state = 3;
}

static void *
server_send_notif_thread(void *arg)
{
    NC_MSG_TYPE msg_type;
    struct lyd_node *notif_tree;
    struct nc_server_notif *notif;
    char *buf;
    (void)arg;

    /* wait for the RPC callback to be called */
    while (glob_state != 1) {
        usleep(1000);
    }

    /* create notif */
    notif_tree = lyd_new_path(NULL, ctx, "/nc-notifications:notificationComplete", NULL, 0, 0);
    assert_non_null(notif_tree);
    buf = malloc(64);
    assert_non_null(buf);
    notif = nc_server_notif_new(notif_tree, nc_time2datetime(time(NULL), NULL, buf), NC_PARAMTYPE_FREE);
    assert_non_null(notif);

    /* send notif */
    nc_session_set_notif_status(server_session, 1);
    msg_type = nc_server_notif_send(server_session, notif, 100);
    nc_server_notif_free(notif);
    assert_int_equal(msg_type, NC_MSG_NOTIF);

    /* update state */
    glob_state = 2;

    return NULL;
}

static void
test_send_recv_notif(void)
{
    int ret;
    pthread_t tid;
    uint64_t msgid;
    NC_MSG_TYPE msgtype;
    struct nc_rpc *rpc;
    struct nc_reply *reply;
    struct nc_pollsession *ps;

    /* client RPC */
    rpc = nc_rpc_commit(0, 0, NULL, NULL, 0);
    assert_non_null(rpc);

    msgtype = nc_send_rpc(client_session, rpc, 0, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* client subscription */
    ret = nc_recv_notif_dispatch(client_session, test_notif_clb);
    assert_int_equal(ret, 0);

    /* create server */
    ps = nc_ps_new();
    assert_non_null(ps);
    nc_ps_add_session(ps, server_session);

    /* server will send a notification */
    glob_state = 0;
    ret = pthread_create(&tid, NULL, server_send_notif_thread, NULL);
    assert_int_equal(ret, 0);

    /* server blocked on RPC */
    ret = nc_ps_poll(ps, 0, NULL);
    assert_int_equal(ret, NC_PSPOLL_RPC);

    /* RPC, notification finished fine */
    assert_int_equal(glob_state, 3);

    /* server finished */
    ret = pthread_join(tid, NULL);
    assert_int_equal(ret, 0);
    nc_ps_free(ps);

    /* client reply */
    msgtype = nc_recv_reply(client_session, rpc, msgid, 0, 0, &reply);
    assert_int_equal(msgtype, NC_MSG_REPLY);

    nc_rpc_free(rpc);
    assert_int_equal(reply->type, NC_RPL_OK);
    nc_reply_free(reply);
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

int
main(void)
{
    int ret;
    const struct lys_module *module;
    const struct lys_node *node;

    /* create ctx */
    ctx = ly_ctx_new(TESTS_DIR"../schemas", 0);
    assert_non_null(ctx);

    /* load modules */
    module = ly_ctx_load_module(ctx, "ietf-netconf-acm", NULL);
    assert_non_null(module);

    module = ly_ctx_load_module(ctx, "ietf-netconf", NULL);
    assert_non_null(module);
    ret = lys_features_enable(module, "candidate");
    assert_int_equal(ret, 0);

    module = ly_ctx_load_module(ctx, "nc-notifications", NULL);
    assert_non_null(module);

    /* set RPC callbacks */
    node = ly_ctx_get_node(module->ctx, NULL, "/ietf-netconf:get", 0);
    assert_non_null(node);
    lys_set_private(node, my_get_rpc_clb);

    node = ly_ctx_get_node(module->ctx, NULL, "/ietf-netconf:get-config", 0);
    assert_non_null(node);
    lys_set_private(node, my_getconfig_rpc_clb);

    node = ly_ctx_get_node(module->ctx, NULL, "/ietf-netconf:commit", 0);
    assert_non_null(node);
    lys_set_private(node, my_commit_rpc_clb);

    nc_server_init(ctx);

    const struct CMUnitTest comm[] = {
        cmocka_unit_test_setup_teardown(test_send_recv_ok_10, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_error_10, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_data_10, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_notif_10, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_ok_11, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_error_11, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_data_11, setup_sessions, teardown_sessions),
        cmocka_unit_test_setup_teardown(test_send_recv_notif_11, setup_sessions, teardown_sessions),
    };

    ret = cmocka_run_group_tests(comm, NULL, NULL);

    nc_server_destroy();
    ly_ctx_destroy(ctx, NULL);

    return ret;
}
