/**
 * @file ln2_test.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief base source for libnetconf2 testing
 *
 * @copyright
 * Copyright (c) 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <assert.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cmocka.h>

#include "ln2_test.h"

int
ln2_glob_test_get_ports(int port_count, ...)
{
    va_list ap;
    int i, ret = 0, *port_ptr;
    const char **port_str_ptr, *env;
    char *env_name = NULL;

    va_start(ap, port_count);

    for (i = 0; i < port_count; i++) {
        port_ptr = va_arg(ap, int *);
        port_str_ptr = va_arg(ap, const char **);

        if (asprintf(&env_name, "TEST_PORT_%d", i) == -1) {
            ret = 1;
            goto cleanup;
        }

        /* try to get the env variable, which is set by CTest */
        env = getenv(env_name);
        free(env_name);
        if (!env) {
            /* the default value will be used instead */
            continue;
        }

        *port_ptr = atoi(env);
        *port_str_ptr = env;
    }

cleanup:
    va_end(ap);
    return ret;
}

void *
ln2_glob_test_server_thread(void *arg)
{
    int ret;
    NC_MSG_TYPE msgtype;
    struct nc_session *session = NULL;
    struct nc_pollsession *ps = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    ps = nc_ps_new();
    assert(ps);

    /* wait for the client to be ready to connect */
    pthread_barrier_wait(&test_ctx->barrier);

    /* accept a session and add it to the poll session structure */
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, test_ctx->ctx, &session);
    if (msgtype != NC_MSG_HELLO) {
        SETUP_FAIL_LOG;
        nc_ps_free(ps);
        return NULL;
    }

    ret = nc_ps_add_session(ps, session);
    assert(!ret);

    /* poll until the session is terminated by the client */
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, &session);
        assert(ret & NC_PSPOLL_RPC);
    } while (!(ret & NC_PSPOLL_SESSION_TERM));

    /* the terminated session was removed from ps and we own it now */
    nc_session_free(session, NULL);
    nc_ps_free(ps);
    return NULL;
}

void *
ln2_glob_test_server_thread_fail(void *arg)
{
    NC_MSG_TYPE msgtype;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* wait for the client to be ready to connect */
    pthread_barrier_wait(&test_ctx->barrier);

    /* try to accept a session, but we expect it to fail */
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, test_ctx->ctx, &session);
    assert(msgtype == NC_MSG_ERROR);
    (void)msgtype;
    assert(!session);

    return NULL;
}

int
ln2_glob_test_setup(struct ln2_test_ctx **test_ctx)
{
    int ret;

    *test_ctx = calloc(1, sizeof **test_ctx);
    if (!*test_ctx) {
        SETUP_FAIL_LOG;
        ret = 1;
        goto cleanup;
    }

    /* set verbosity */
    nc_verbosity(NC_VERB_VERBOSE);
    ly_log_level(LY_LLWRN);

    /* initialize server */
    ret = nc_server_init();
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }

    /* initialize client */
    ret = nc_client_init();
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }

    /* init barrier */
    ret = pthread_barrier_init(&(*test_ctx)->barrier, NULL, 2);
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }

    /* create libyang context */
    ret = ly_ctx_new(ly_yang_module_dir(), 0, &(*test_ctx)->ctx);
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }
    ly_ctx_set_searchdir((*test_ctx)->ctx, MODULES_DIR);

    /* load default yang modules */
    ret = nc_server_init_ctx(&(*test_ctx)->ctx);
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }
    ret = nc_server_config_load_modules(&(*test_ctx)->ctx);
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }

cleanup:
    return ret;
}

int
ln2_glob_test_teardown(void **state)
{
    struct ln2_test_ctx *test_ctx = *state;

    nc_client_destroy();
    nc_server_destroy();

    if (test_ctx->free_test_data) {
        test_ctx->free_test_data(test_ctx->test_data);
    }

    pthread_barrier_destroy(&test_ctx->barrier);
    ly_ctx_destroy(test_ctx->ctx);
    free(test_ctx);

    return 0;
}

void
ln2_glob_test_free_test_data(void *test_data)
{
    free(test_data);
}

/**
 * @brief Write a \<hello\> message advertising a single NETCONF base version.
 *
 * @param[in] fd File descriptor to write to.
 * @param[in] version NETCONF version, 0 for 1.0, 1 for 1.1.
 * @param[in] server Whether it is a server \<hello\>, with a session ID.
 * @return 0 on success, -1 on error.
 */
static int
ln2_test_write_hello(int fd, int version, int server)
{
    char *hello;
    int len, rc = 0;

    len = asprintf(&hello, "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><capabilities>"
            "<capability>urn:ietf:params:netconf:base:1.%d</capability></capabilities>%s</hello>]]>]]>",
            version, server ? "<session-id>1</session-id>" : "");
    if (len == -1) {
        return -1;
    }

    if (write(fd, hello, len) != len) {
        rc = -1;
    }
    free(hello);
    return rc;
}

void
ln2_glob_test_fd_sessions(struct ly_ctx *ctx, int version, struct nc_session **server, struct nc_session **client,
        int fds[2])
{
    int link[2], peer[2];

    /* the sessions communicate over this socketpair */
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, link), 0);
    fds[0] = link[0];
    fds[1] = link[1];

    if (client) {
        /* handshake with a fake server on its own socketpair, which also gets the client hello */
        assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, peer), 0);
        assert_int_equal(ln2_test_write_hello(peer[0], version, 1), 0);

        /* the fake server provides no YANG modules, the client uses the context as it is */
        nc_client_set_new_session_context_autofill(0);
        *client = nc_connect_inout(peer[1], peer[1], ctx);
        assert_non_null(*client);
        assert_int_equal(nc_session_get_version(*client), version);

        /* switch the client to its end of the link */
        assert_int_not_equal(dup2(link[1], peer[1]), -1);
        close(peer[0]);
        close(link[1]);
        fds[1] = peer[1];
    }

    /* the same for the server with a fake client */
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, peer), 0);
    assert_int_equal(ln2_test_write_hello(peer[1], version, 0), 0);
    assert_int_equal(nc_accept_inout(peer[0], peer[0], "test", ctx, server), NC_MSG_HELLO);
    assert_int_equal(nc_session_get_version(*server), version);
    assert_int_not_equal(dup2(link[0], peer[0]), -1);
    close(peer[1]);
    close(link[0]);
    fds[0] = peer[0];
}
