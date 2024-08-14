/**
 * \file test_thread_messages
 * \author Tadeas Vintrlik <xvint04@stud.fit.vutbr.cz>
 * \brief libnetconf2 tests - thread-safety for receiving messages
 *
 * Copyright 2021 Deutsche Telekom AG.
 * Copyright 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "ln2_test.h"

/* sec */
#define CLIENT_SSH_AUTH_TIMEOUT 10

#define nc_assert(cond) if (!(cond)) { fprintf(stderr, "assert failed (%s:%d)\n", __FILE__, __LINE__); exit(1); }

#if _POSIX_BARRIERS >= 200112L
pthread_barrier_t barrier;
pthread_barrier_t barrier_msg;
#endif

typedef struct arg {
    int in;
    int out;
    struct ly_ctx *ctx;
} arg_t;

struct nc_server_reply *
rpc_clb(struct lyd_node *rpc, struct nc_session *session)
{
    (void)rpc; (void)session;
    return nc_server_reply_ok();
}

static void *
server_thread(void *arg)
{
    struct nc_session *sess;
    struct nc_server_notif *notif;
    struct lyd_node *ntf;
    struct ly_in *in;
    struct nc_pollsession *ps;
    arg_t args = *(arg_t *)arg;
    char *eventtime;
    struct timespec ts;
    const char *data;
    int poll;

    nc_assert(!nc_server_init());
    nc_assert(nc_accept_inout(args.in, args.out, "test", args.ctx, &sess) == NC_MSG_HELLO);
    nc_session_inc_notif_status(sess);
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";

    nc_assert(ly_in_new_memory(data, &in) == LY_SUCCESS);
    nc_assert(lyd_parse_op(args.ctx, NULL, in, LYD_XML, LYD_TYPE_NOTIF_YANG, &ntf, NULL) == LY_SUCCESS);
    ly_in_free(in, 0);

    nc_assert(clock_gettime(CLOCK_REALTIME, &ts) != -1);
    nc_assert(ly_time_ts2str(&ts, &eventtime) == LY_SUCCESS);
    notif = nc_server_notif_new(ntf, eventtime, NC_PARAMTYPE_FREE);

    ps = nc_ps_new();
    nc_assert(ps);
    nc_ps_add_session(ps, sess);

    /* get for ietf-yang-library data; delete-config in test */
    poll = nc_ps_poll(ps, 1000, &sess);
    nc_assert(poll == NC_PSPOLL_RPC);
    poll = nc_ps_poll(ps, 1000, &sess);
    nc_assert(poll == NC_PSPOLL_RPC);

    nc_server_notif_send(sess, notif, 1000);

    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);

    /* Waiting for end of test */
    pthread_barrier_wait(&barrier);

    nc_server_notif_free(notif);
    return arg;
}

static void *
notif_thread(void *arg)
{
    struct nc_session *sess = (struct nc_session *)arg;
    struct lyd_node *envp;
    struct lyd_node *op;
    NC_MSG_TYPE msgtype;

    /* Sync threads for receiving message to increase chance of datarace */
    pthread_barrier_wait(&barrier_msg);
    do {
        msgtype = nc_recv_notif(sess, 1000, &envp, &op);
    } while (msgtype == NC_MSG_REPLY);
    nc_assert(msgtype == NC_MSG_NOTIF);
    lyd_free_tree(envp);
    lyd_free_tree(op);
    return arg;
}

int
main(void)
{
    int pipes[4];
    struct nc_session *sess;
    struct lyd_node *op, *envp;
    struct ly_ctx *server_ctx, *client_ctx;
    struct nc_rpc *rpc;
    uint64_t msgid;
    NC_MSG_TYPE msgtype;
    const char *features[] = {"startup", NULL};
    arg_t thread_arg;
    pthread_t t[2];

    pthread_barrier_init(&barrier, NULL, 2);
    pthread_barrier_init(&barrier_msg, NULL, 2);

    /* Create a two pipes */
    nc_assert(pipe(pipes) != -1);
    nc_assert(pipe(pipes + 2) != -1);
    thread_arg.in = pipes[0];
    thread_arg.out = pipes[3];

    /* Create both contexts */
    nc_assert(ly_ctx_new(TESTS_DIR "/data/modules", 0, &server_ctx) == LY_SUCCESS);
    nc_assert(ly_ctx_load_module(server_ctx, "ietf-netconf", NULL, features));
    nc_assert(ly_ctx_load_module(server_ctx, "notif1", NULL, NULL));
    thread_arg.ctx = server_ctx;
    nc_set_global_rpc_clb(rpc_clb);

    nc_assert(ly_ctx_new(TESTS_DIR "/data/modules", 0, &client_ctx) == LY_SUCCESS);
    nc_assert(ly_ctx_load_module(client_ctx, "ietf-netconf", NULL, features));
    nc_assert(ly_ctx_load_module(client_ctx, "notif1", NULL, NULL));

    /* Start server thread */
    pthread_create(&t[0], NULL, server_thread, &thread_arg);
    nc_client_init();

    /* Listen for notifications */
    sess = nc_connect_inout(pipes[2], pipes[1], client_ctx);
    nc_assert(sess);
    pthread_create(&t[1], NULL, notif_thread, sess);

    /* Send rpc */
    rpc = nc_rpc_delete(NC_DATASTORE_STARTUP, NULL, NC_PARAMTYPE_CONST);
    nc_assert(nc_send_rpc(sess, rpc, 1000, &msgid) == NC_MSG_RPC);

    /* Sync threads for receiving message to increase chance of datarace */
    pthread_barrier_wait(&barrier_msg);
    do {
        msgtype = nc_recv_reply(sess, rpc, msgid, 1000, &envp, &op);
    } while (msgtype == NC_MSG_NOTIF);
    nc_assert(msgtype == NC_MSG_REPLY);
    nc_rpc_free(rpc);
    lyd_free_tree(envp);

    /* Waiting of end of test */
    pthread_barrier_wait(&barrier);
    pthread_join(t[0], NULL);
    pthread_join(t[1], NULL);

    /* Cleanup */
    nc_session_free(sess, NULL);
    ly_ctx_destroy(server_ctx);
    ly_ctx_destroy(client_ctx);
    for (uint8_t i = 0; i < 4; i++) {
        close(pipes[i]);
    }
    return 0;
}
