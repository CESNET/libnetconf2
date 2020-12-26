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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include <messages_p.h>
#include <session_p.h>
#include <session_client.h>
#include "tests/config.h"

struct wr {
    struct nc_session *session;
    struct nc_rpc *rpc;
};

static int
setup_write(void **state)
{
    (void) state; /* unused */
    int fd, pipes[2];
    struct wr *w;

    w = malloc(sizeof *w);
    w->session = calloc(1, sizeof *w->session);
    w->session->ctx = ly_ctx_new(TESTS_DIR"/data/modules", 0);

    /* ietf-netconf */
    fd = open(TESTS_DIR"/data/modules/ietf-netconf.yin", O_RDONLY);
    if (fd == -1) {
        free(w);
        return -1;
    }

    lys_parse_fd(w->session->ctx, fd, LYS_IN_YIN);
    close(fd);

    pipe(pipes);

    w->session->status = NC_STATUS_RUNNING;
    w->session->version = NC_VERSION_10;
    w->session->opts.client.msgid = 999;
    w->session->ti_type = NC_TI_FD;
    w->session->io_lock = malloc(sizeof *w->session->io_lock);
    pthread_mutex_init(w->session->io_lock, NULL);
    w->session->ti.fd.in = pipes[0];
    w->session->ti.fd.out = pipes[1];

    /* get rpc to write */
    w->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    assert_non_null(w->rpc);

    *state = w;

    return 0;
}

static int
teardown_write(void **state)
{
    struct wr *w = (struct wr *)*state;

    nc_rpc_free(w->rpc);
    close(w->session->ti.fd.in);
    w->session->ti.fd.in = -1;
    close(w->session->ti.fd.out);
    w->session->ti.fd.out = -1;
    nc_session_free(w->session, NULL);
    free(w);
    *state = NULL;

    return 0;
}

static void
test_write_rpc(void **state)
{
    struct wr *w = (struct wr *)*state;
    uint64_t msgid;
    NC_MSG_TYPE type;

    w->session->side = NC_CLIENT;

    do {
        type = nc_send_rpc(w->session, w->rpc, 1000, &msgid);
    } while(type == NC_MSG_WOULDBLOCK);

    assert_int_equal(type, NC_MSG_RPC);

    write(w->session->ti.fd.out, "\n", 1);
}

static void
test_write_rpc_10(void **state)
{
    struct wr *w = (struct wr *)*state;

    w->session->version = NC_VERSION_10;

    return test_write_rpc(state);
}

static void
test_write_rpc_11(void **state)
{
    struct wr *w = (struct wr *)*state;

    w->session->version = NC_VERSION_11;

    return test_write_rpc(state);
}

static void
test_write_rpc_bad(void **state)
{
    struct wr *w = (struct wr *)*state;
    uint64_t msgid;
    NC_MSG_TYPE type;

    w->session->side = NC_SERVER;
    w->session->opts.server.rpc_lock = malloc(sizeof *w->session->opts.server.rpc_lock);
    pthread_mutex_init(w->session->opts.server.rpc_lock, NULL);
    w->session->opts.server.rpc_cond = malloc(sizeof *w->session->opts.server.rpc_cond);
    pthread_cond_init(w->session->opts.server.rpc_cond, NULL);
    w->session->opts.server.rpc_inuse = malloc(sizeof *w->session->opts.server.rpc_inuse);
    *w->session->opts.server.rpc_inuse = 0;

    do {
        type = nc_send_rpc(w->session, w->rpc, 1000, &msgid);
    } while(type == NC_MSG_WOULDBLOCK);

    assert_int_equal(type, NC_MSG_ERROR);
}

static void
test_write_rpc_10_bad(void **state)
{
    struct wr *w = (struct wr *)*state;

    w->session->version = NC_VERSION_10;

    return test_write_rpc_bad(state);
}

static void
test_write_rpc_11_bad(void **state)
{
    struct wr *w = (struct wr *)*state;

    w->session->version = NC_VERSION_11;

    return test_write_rpc_bad(state);
}

static void
test_nc_send_rpc_bad(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;

    // session is NULL
    ret_a = nc_send_rpc(NULL, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    // rpc is NULL
    ret_a = nc_send_rpc(w->session,NULL, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    // msgid is NULL
    ret_a = nc_send_rpc(w->session, w->rpc, 0, NULL);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_act_generic(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_act_generic_xml("xml", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_ACT_GENERIC);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_validate(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_validate(NC_DATASTORE_RUNNING, "url", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_VALIDATE);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_cancel(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_cancel("persist-id", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_CANCEL);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_discard(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_discard();
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_DISCARD);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_commit(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_commit(1, 100, "persist", "persist-id", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_COMMIT);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_get(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;
    const struct lys_module *module;

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_get("filter", NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GET);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_get("<filter>", NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GET);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    /* load ietf-netconf-with-defaults */
    module = ly_ctx_load_module(w->session->ctx, "ietf-netconf-with-defaults", NULL);
    assert_non_null(module);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_get("filter", NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GET);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_get("filter", NC_WD_ALL_TAG, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GET);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_get("filter", NC_WD_TRIM, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GET);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_get("filter", NC_WD_EXPLICIT, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GET);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_get("filter", 7, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GET);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_unlock(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_UNLOCK);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_delete(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_delete(NC_DATASTORE_RUNNING, "target-url", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_DELETE);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_copy(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_copy(NC_DATASTORE_CANDIDATE, "target-url", NC_DATASTORE_CANDIDATE, "src-url",
                         NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_COPY);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_copy(NC_DATASTORE_CANDIDATE, NULL, NC_DATASTORE_CANDIDATE, "src-url",
                         NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_COPY);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_copy_bad(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;
    const struct lys_module *module;
    int ret;

    module = ly_ctx_load_module(w->session->ctx, "ietf-netconf", NULL);
    assert_non_null(module);
    ret = lys_features_enable(module, "candidate");
    assert_int_equal(ret, 0);

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_copy(NC_DATASTORE_CANDIDATE, NULL, NC_DATASTORE_CANDIDATE, "candidate",
                         NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_COPY);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_copy(NC_DATASTORE_CANDIDATE, NULL, NC_DATASTORE_CANDIDATE, NULL,
                         NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_COPY);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    module = ly_ctx_load_module(w->session->ctx, "ietf-netconf-with-defaults", NULL);
    assert_non_null(module);

    /* free the previous w->rpc, wd_mode is NC_WD_ALL */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_copy(NC_DATASTORE_CANDIDATE, NULL, NC_DATASTORE_CANDIDATE, NULL,
                         NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_COPY);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc, wd_mode is NC_WD_ALL_TAG */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_copy(NC_DATASTORE_CANDIDATE, NULL, NC_DATASTORE_CANDIDATE, NULL,
                         NC_WD_ALL_TAG, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_COPY);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc, wd_mode is NC_WD_ALL_TRIM */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_copy(NC_DATASTORE_CANDIDATE, NULL, NC_DATASTORE_CANDIDATE, NULL,
                         NC_WD_TRIM, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_COPY);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc, wd_mode is NC_WD_EXPLICIT */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_copy(NC_DATASTORE_CANDIDATE, NULL, NC_DATASTORE_CANDIDATE, NULL,
                         NC_WD_EXPLICIT, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_COPY);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

}

static void
test_nc_send_rpc_edit(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;
    const struct lys_module *module;
    int ret;

    w->session->side = NC_CLIENT;

    /* load the ietf-netconf module*/
    module = ly_ctx_load_module(w->session->ctx, "ietf-netconf", NULL);
    assert_non_null(module);
    ret = lys_features_enable(module, "candidate");
    assert_int_equal(ret, 0);
    ret = lys_features_enable(module, "validate");
    assert_int_equal(ret, 0);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_edit(NC_DATASTORE_CANDIDATE, NC_RPC_EDIT_DFLTOP_REPLACE, NC_RPC_EDIT_TESTOPT_TESTSET,
                         NC_RPC_EDIT_ERROPT_STOP, "candidate", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_EDIT);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_edit(NC_DATASTORE_CANDIDATE, NC_RPC_EDIT_DFLTOP_REPLACE, NC_RPC_EDIT_TESTOPT_TESTSET,
                         NC_RPC_EDIT_ERROPT_STOP, "<candidate>", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_EDIT);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_edit_bad(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;
    const struct lys_module *module;
    int ret;

    w->session->side = NC_CLIENT;

    /* load the ietf-netconf module*/
    module = ly_ctx_load_module(w->session->ctx, "ietf-netconf", NULL);
    assert_non_null(module);
    ret = lys_features_enable(module, "candidate");
    assert_int_equal(ret, 0);

    /* free the previous w->rpc, target is bad */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_edit(NC_DATASTORE_RUNNING, NC_RPC_EDIT_DFLTOP_REPLACE, NC_RPC_EDIT_TESTOPT_TESTSET,
                         NC_RPC_EDIT_ERROPT_STOP, "running", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_EDIT);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc, test-opt is bad */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_edit(NC_DATASTORE_CANDIDATE, NC_RPC_EDIT_DFLTOP_REPLACE, NC_RPC_EDIT_TESTOPT_TESTSET,
                         NC_RPC_EDIT_ERROPT_STOP, "candidate", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_EDIT);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_getconfig(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;
    const struct lys_module *module;

    w->session->side = NC_CLIENT;

    /* load the ietf-netconf-with-defaults module */
    module = ly_ctx_load_module(w->session->ctx, "ietf-netconf-with-defaults", NULL);
    assert_non_null(module);

    /* free the previous w->rpc, wd_mode is NC_WD_ALL */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, "filter-string", NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GETCONFIG);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc, wd_mode is NC_WD_ALL_TAG */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, "<filter-string>", NC_WD_ALL_TAG, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GETCONFIG);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc, wd_mode is NC_WD_TRIM */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, "filter-string", NC_WD_TRIM, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GETCONFIG);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc, wd_mode is NC_WD_EXPLICIT */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, "filter-string", NC_WD_EXPLICIT, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GETCONFIG);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_not_equal(ret_a, NC_MSG_ERROR);

}

static void
test_nc_send_rpc_getconfig_bad(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, "filter-string", NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GETCONFIG);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    ly_ctx_destroy(w->session->ctx, NULL);
    w->session->ctx = NULL;
    w->rpc = nc_rpc_getconfig(NC_DATASTORE_CANDIDATE, "filter-string", NC_WD_UNKNOWN, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GETCONFIG);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_getschema(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;
    const struct lys_module *module;

    w->session->side = NC_CLIENT;

    /* load the ietf-netconf-monitoring module */
    module = ly_ctx_load_module(w->session->ctx, "ietf-netconf-monitoring", NULL);
    assert_non_null(module);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_getschema("id", "version", "format", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GETSCHEMA);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    ly_ctx_destroy(w->session->ctx, NULL);
    w->session->ctx = NULL;
    w->rpc = nc_rpc_getschema("id", "version", "format", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GETSCHEMA);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_subscribe(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;
    const struct lys_module *module;

    w->session->side = NC_CLIENT;

    /* load the notification module */
    module = ly_ctx_load_module(w->session->ctx, "notifications", NULL);
    assert_non_null(module);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_subscribe("stream-name", "filter", "start-time",
                              "stop-time", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_SUBSCRIBE);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    ly_ctx_destroy(w->session->ctx, NULL);
    w->session->ctx = NULL;
    w->rpc = nc_rpc_subscribe("stream-name", "filter", "start-time",
                              "stop-time", NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_SUBSCRIBE);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_editdata(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;
    const struct lys_module *module;

    w->session->side = NC_CLIENT;

    /* load the ietf-netconf-nmda module */
    module = ly_ctx_load_module(w->session->ctx, "ietf-netconf-nmda", NULL);
    assert_non_null(module);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_editdata("datastore", NC_RPC_EDIT_DFLTOP_REPLACE, "edit-content",
                              NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_EDITDATA);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);

}

static void
test_nc_send_rpc_getdata(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;
    char *origin_filter = "origin_filter";

    w->session->side = NC_CLIENT;

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    ly_ctx_destroy(w->session->ctx, NULL);
    w->session->ctx = NULL;
    w->rpc = nc_rpc_getdata("datastore", "filter", "config_filter", &origin_filter,
                            1, 1, 2, 1, NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GETDATA);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_getdata_bad(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;
    const struct lys_module *module;
    char *origin_filter = "origin_filter";

    w->session->side = NC_CLIENT;

    /* load the ietf-netconf-nmda module */
    module = ly_ctx_load_module(w->session->ctx, "ietf-netconf-nmda", NULL);
    assert_non_null(module);

    /* free the previous w->rpc */
    nc_rpc_free(w->rpc);
    w->rpc = nc_rpc_getdata("datastore", "filter", "config_filter", &origin_filter,
                            1, 1, 2, 1, NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(w->rpc);
    assert_int_equal(nc_rpc_get_type(w->rpc), NC_RPC_GETDATA);

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_send_rpc_unknown(void **state)
{
    struct wr *w = (struct wr *)*state;
    NC_MSG_TYPE ret_a;
    uint64_t msgid;

    w->session->side = NC_CLIENT;
    w->rpc->type = NC_RPC_UNKNOWN;

    /* send rpc command */
    ret_a = nc_send_rpc(w->session, w->rpc, 0, &msgid);
    assert_int_equal(ret_a, NC_MSG_ERROR);
}

static void
test_nc_client_session_set_not_strict(void **state)
{
    struct wr *w = (struct wr *)*state;

    w->session->side = NC_SERVER;
    nc_client_session_set_not_strict(w->session);

    w->session->side = NC_CLIENT;
    nc_client_session_set_not_strict(w->session);
    assert_true(w->session->flags & NC_SESSION_CLIENT_NOT_STRICT);
}

int main(void)
{
    const struct CMUnitTest io[] = {
        cmocka_unit_test_setup_teardown(test_write_rpc_10, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_write_rpc_10_bad, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_write_rpc_11, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_write_rpc_11_bad, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_bad, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_act_generic, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_validate, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_cancel, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_discard, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_commit, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_get, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_unlock, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_delete, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_copy, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_copy_bad, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_edit, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_edit_bad, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_getconfig, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_getconfig_bad, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_getschema, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_subscribe, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_editdata, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_getdata, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_getdata_bad, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_send_rpc_unknown, setup_write, teardown_write),
        cmocka_unit_test_setup_teardown(test_nc_client_session_set_not_strict, setup_write, teardown_write)};

    return cmocka_run_group_tests(io, NULL, NULL);
}
