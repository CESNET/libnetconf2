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
    struct lyd_node *e;

    (void)session;

    if (!strcmp(LYD_NAME(rpc), "get") || !strcmp(LYD_NAME(rpc), "delete-config")) {
        return nc_server_reply_ok();
    } else if (!strcmp(LYD_NAME(rpc), "commit")) {
        e = nc_err(LYD_CTX(rpc), NC_ERR_RES_DENIED, NC_ERR_TYPE_APP);
        nc_err_set_path(e, "/module-a:top/name");
        return nc_server_reply_err(e);
    } else {
        nc_assert(0);
    }

    return NULL;
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
    nc_assert(lyd_parse_op(args.ctx, NULL, in, LYD_XML, LYD_TYPE_NOTIF_YANG, LYD_PARSE_STRICT, &ntf, NULL) == LY_SUCCESS);
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

    /* commit in test */
    poll = nc_ps_poll(ps, 1000, &sess);
    nc_assert(poll == (NC_PSPOLL_RPC | NC_PSPOLL_REPLY_ERROR));

    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);

    /* waiting for end of test */
    pthread_barrier_wait(&barrier);

    nc_server_notif_free(notif);
    return arg;
}

static struct ly_ctx *
create_test_ctx(const char *features[])
{
    struct ly_ctx *ctx;

    nc_assert(ly_ctx_new(ly_yang_module_dir(), 0, &ctx) == LY_SUCCESS);
    nc_assert(ly_ctx_set_searchdir(ctx, TESTS_DIR "/data/modules") == LY_SUCCESS);
    nc_assert(ly_ctx_load_module(ctx, "ietf-netconf", NULL, features));
    nc_assert(ly_ctx_load_module(ctx, "notif1", NULL, NULL));
    nc_assert(ly_ctx_load_module(ctx, "module-a", NULL, NULL));
    nc_assert(ly_ctx_load_module(ctx, "ietf-yp-notification", NULL, NULL));
    return ctx;
}

static struct lyd_node *
build_envelope_notif(struct ly_ctx *ctx, const char *data)
{
    struct lyd_node *ntf;
    struct ly_in *in;

    /* create a notification tree */
    nc_assert(ly_in_new_memory(data, &in) == LY_SUCCESS);
    nc_assert(lyd_parse_op(ctx, NULL, in, LYD_XML, LYD_TYPE_NOTIF_YANG, LYD_PARSE_STRICT, &ntf, NULL) == LY_SUCCESS);
    ly_in_free(in, 0);

    /* wrap it in an ietf-yp-notification envelope (takes ownership of ntf) */
    return ln2_build_yp_envelope(ctx, ntf);
}

static void *
server_envelope_notif_thread(void *arg)
{
    struct nc_session *sess;
    struct nc_server_notif *notif;
    struct lyd_node *env;
    struct nc_pollsession *ps;
    arg_t args = *(arg_t *)arg;
    int poll;
    NC_MSG_TYPE msg_type;
    const char *data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Envelope</first>\n"
            "</n1>\n";

    nc_assert(!nc_server_init());
    nc_assert(nc_accept_inout(args.in, args.out, "test", args.ctx, &sess) == NC_MSG_HELLO);
    nc_session_inc_notif_status(sess);

    /* build and send an envelope notification */
    env = build_envelope_notif(args.ctx, data);
    notif = nc_server_notif_new2(env, NC_NOTIF_TYPE_ENVELOPE, NULL, NC_PARAMTYPE_FREE);
    nc_assert(notif);

    ps = nc_ps_new();
    nc_assert(ps);
    nc_ps_add_session(ps, sess);

    /* poll for the get (yang-library) RPC and the delete-config RPC */
    poll = nc_ps_poll(ps, 5000, &sess);
    nc_assert(poll == NC_PSPOLL_RPC);
    poll = nc_ps_poll(ps, 5000, &sess);
    nc_assert(poll == NC_PSPOLL_RPC);

    /* send envelope notification */
    msg_type = nc_server_notif_send(sess, notif, 1000);
    nc_assert(msg_type == NC_MSG_NOTIF);

    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);

    /* waiting for end of test */
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

    /* sync threads for receiving message to increase chance of datarace */
    pthread_barrier_wait(&barrier_msg);
    do {
        msgtype = nc_recv_notif(sess, 1000, &envp, &op);
    } while (msgtype == NC_MSG_REPLY);
    nc_assert(msgtype == NC_MSG_NOTIF);
    lyd_free_tree(envp);
    lyd_free_tree(op);
    return arg;
}

static void
test_setup_env(const char *features[], arg_t *thread_arg, int pipes[4],
        struct ly_ctx **server_ctx, struct ly_ctx **client_ctx)
{
    nc_assert(pipe(pipes) != -1);
    nc_assert(pipe(pipes + 2) != -1);
    thread_arg->in = pipes[0];
    thread_arg->out = pipes[3];
    *server_ctx = create_test_ctx(features);
    thread_arg->ctx = *server_ctx;
    *client_ctx = create_test_ctx(features);
}

static void
test_teardown_env(struct ly_ctx *server_ctx, struct ly_ctx *client_ctx, int pipes[4])
{
    ly_ctx_destroy(server_ctx);
    ly_ctx_destroy(client_ctx);
    for (uint8_t i = 0; i < 4; i++) {
        close(pipes[i]);
    }
}

static void
run_legacy_notif_test(const char *features[], arg_t *thread_arg, int pipes[4], pthread_t t[2])
{
    struct nc_session *sess;
    struct lyd_node *op, *envp;
    struct ly_ctx *server_ctx, *client_ctx;
    struct nc_rpc *rpc;
    uint64_t msgid;
    NC_MSG_TYPE msgtype;
    char *str;

    test_setup_env(features, thread_arg, pipes, &server_ctx, &client_ctx);

    /* start server thread */
    pthread_create(&t[0], NULL, server_thread, thread_arg);

    /* listen for notifications */
    sess = nc_connect_inout(pipes[2], pipes[1], client_ctx);
    nc_assert(sess);
    pthread_create(&t[1], NULL, notif_thread, sess);

    /* send delete-config rpc */
    rpc = nc_rpc_delete(NC_DATASTORE_STARTUP, NULL, NC_PARAMTYPE_CONST);
    nc_assert(nc_send_rpc(sess, rpc, 1000, &msgid) == NC_MSG_RPC);

    /* sync threads for receiving message to increase chance of datarace */
    pthread_barrier_wait(&barrier_msg);
    do {
        msgtype = nc_recv_reply(sess, rpc, msgid, 1000, &envp, &op);
    } while (msgtype == NC_MSG_NOTIF);
    nc_assert(msgtype == NC_MSG_REPLY);
    nc_rpc_free(rpc);
    lyd_free_tree(envp);

    /* send commit rpc */
    rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    nc_assert(nc_send_rpc(sess, rpc, 1000, &msgid) == NC_MSG_RPC);
    do {
        msgtype = nc_recv_reply(sess, rpc, msgid, 1000, &envp, &op);
    } while (msgtype == NC_MSG_NOTIF);
    nc_assert(msgtype == NC_MSG_REPLY);
    nc_rpc_free(rpc);

    lyd_print_mem(&str, envp, LYD_XML, LYD_PRINT_SHRINK);
    nc_assert(!strcmp(str,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"3\"><rpc-error>"
            "<error-type>application</error-type>"
            "<error-tag>resource-denied</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-path xmlns:a=\"urn:jmu:params:xml:ns:yang:module-a\">/a:top/a:name</error-path>"
            "<error-message xml:lang=\"en\">Request could not be completed because of insufficient resources.</error-message>"
            "</rpc-error></rpc-reply>"));
    free(str);
    lyd_free_tree(envp);

    /* waiting for end of test */
    pthread_barrier_wait(&barrier);
    pthread_join(t[0], NULL);
    pthread_join(t[1], NULL);

    /* cleanup */
    nc_session_free(sess, NULL);
    test_teardown_env(server_ctx, client_ctx, pipes);
}

static void
run_envelope_notif_test(const char *features[], arg_t *thread_arg, int pipes[4], pthread_t t[2])
{
    struct nc_session *sess;
    struct lyd_node *op, *envp;
    struct ly_ctx *server_ctx, *client_ctx;
    struct nc_rpc *rpc;
    uint64_t msgid;
    NC_MSG_TYPE msgtype;

    test_setup_env(features, thread_arg, pipes, &server_ctx, &client_ctx);

    /* start server thread */
    pthread_create(&t[0], NULL, server_envelope_notif_thread, thread_arg);

    /* connect client */
    sess = nc_connect_inout(pipes[2], pipes[1], client_ctx);
    nc_assert(sess);

    /* send delete-config rpc */
    rpc = nc_rpc_delete(NC_DATASTORE_STARTUP, NULL, NC_PARAMTYPE_CONST);
    nc_assert(nc_send_rpc(sess, rpc, 5000, &msgid) == NC_MSG_RPC);

    /* receive reply (may get yang-library get reply first with wrong msgid) */
    do {
        msgtype = nc_recv_reply(sess, rpc, msgid, 5000, &envp, &op);
        if ((msgtype == NC_MSG_NOTIF) || (msgtype == NC_MSG_REPLY_ERR_MSGID)) {
            lyd_free_tree(envp);
            envp = NULL;
            lyd_free_tree(op);
            op = NULL;
        }
    } while ((msgtype == NC_MSG_NOTIF) || (msgtype == NC_MSG_REPLY_ERR_MSGID));
    nc_assert(msgtype == NC_MSG_REPLY);
    nc_rpc_free(rpc);
    lyd_free_tree(envp);

    /* receive the envelope notification */
    do {
        msgtype = nc_recv_notif(sess, 5000, &envp, &op);
    } while (msgtype == NC_MSG_REPLY);
    nc_assert(msgtype == NC_MSG_NOTIF);

    /* verify envelope format */
    nc_assert(envp != NULL);
    nc_assert(!strcmp(LYD_NAME(envp), "envelope"));
    nc_assert(op != NULL);
    nc_assert(!strcmp(op->schema->name, "n1"));

    lyd_free_tree(envp);
    lyd_free_tree(op);

    /* waiting for end of test */
    pthread_barrier_wait(&barrier);
    pthread_join(t[0], NULL);

    /* cleanup */
    nc_session_free(sess, NULL);
    test_teardown_env(server_ctx, client_ctx, pipes);
}

int
main(void)
{
    int pipes[4];
    const char *features[] = {"startup", "candidate", NULL};
    arg_t thread_arg;
    pthread_t t[2];

    pthread_barrier_init(&barrier, NULL, 2);
    pthread_barrier_init(&barrier_msg, NULL, 2);
    nc_set_global_rpc_clb(rpc_clb);
    nc_client_init();

    /* Test 1: Legacy notification */
    run_legacy_notif_test(features, &thread_arg, pipes, t);

    /* Test 2: Envelope notification */
    run_envelope_notif_test(features, &thread_arg, pipes, t);

    pthread_barrier_destroy(&barrier);
    pthread_barrier_destroy(&barrier_msg);

    return 0;
}
