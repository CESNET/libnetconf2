/**
 * \file test_io.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 tests - input/output functions
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

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "ln2_test.h"

struct wr {
    struct ln2_test_ctx *test_ctx;
    struct nc_session *server;
    struct nc_session *client;
    int fds[2];
    struct nc_rpc *rpc;
};

/**
 * @brief Create the sessions and the RPC to write.
 *
 * @param[in] state Test state.
 * @param[in] version NETCONF version, 0 for 1.0, 1 for 1.1.
 * @return 0 on success, non-zero on error.
 */
static int
setup_write(void **state, int version)
{
    struct wr *w;

    w = calloc(1, sizeof *w);
    if (!w) {
        return 1;
    }
    *state = w;

    if (ln2_glob_test_setup(&w->test_ctx)) {
        return 1;
    }

    ln2_glob_test_fd_sessions(w->test_ctx->ctx, version, &w->server, &w->client, w->fds);

    /* get rpc to write */
    w->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    if (!w->rpc) {
        return 1;
    }

    return 0;
}

static int
setup_write_10(void **state)
{
    return setup_write(state, 0);
}

static int
setup_write_11(void **state)
{
    return setup_write(state, 1);
}

static int
teardown_write(void **state)
{
    struct wr *w = *state;

    nc_rpc_free(w->rpc);

    /* close the socketpair first so that the client does not wait for a <close-session> reply */
    close(w->fds[0]);
    close(w->fds[1]);
    nc_session_free(w->server, NULL);
    nc_session_free(w->client, NULL);

    ln2_glob_test_teardown((void **)&w->test_ctx);
    free(w);
    *state = NULL;

    return 0;
}

static void
test_write_rpc(void **state)
{
    struct wr *w = *state;
    uint64_t msgid;
    NC_MSG_TYPE type;

    do {
        type = nc_send_rpc(w->client, w->rpc, NC_MSG_TIMEOUT_MS, &msgid);
    } while (type == NC_MSG_WOULDBLOCK);

    assert_int_equal(type, NC_MSG_RPC);

    assert_int_equal(write(w->fds[1], "\n", 1), 1);
}

static void
test_write_rpc_bad(void **state)
{
    struct wr *w = *state;
    uint64_t msgid;
    NC_MSG_TYPE type;

    /* only a client can send an RPC */
    do {
        type = nc_send_rpc(w->server, w->rpc, NC_MSG_TIMEOUT_MS, &msgid);
    } while (type == NC_MSG_WOULDBLOCK);

    assert_int_equal(type, NC_MSG_ERROR);
}

int
main(void)
{
    const struct CMUnitTest io[] = {
        {"test_write_rpc_10", test_write_rpc, setup_write_10, teardown_write, NULL},
        {"test_write_rpc_10_bad", test_write_rpc_bad, setup_write_10, teardown_write, NULL},
        {"test_write_rpc_11", test_write_rpc, setup_write_11, teardown_write, NULL},
        {"test_write_rpc_11_bad", test_write_rpc_bad, setup_write_11, teardown_write, NULL},
    };

    return cmocka_run_group_tests(io, NULL, NULL);
}
