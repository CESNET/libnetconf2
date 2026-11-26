/**
 * @file test_client_messages.c
 * @author David Sedlák <xsedla1d@stud.fit.vutbr.cz>
 * @brief client messages test
 *
 * Copyright (c) 2018 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "ln2_test.h"

/* subtree content used in the filters and edits */
#define TEST_SUBTREE "<top xmlns=\"urn:test\"><leaf>val</leaf></top>"

/* URLs in the RPCs, the server never accesses them */
#define TEST_URL "file:/nonexistent.xml"
#define TEST_SRC_URL "file:/nonexistent-src.xml"

/* XPath used in the filters and how the server prints it */
#define TEST_XPATH "/ietf-netconf-server:netconf-server"
#define TEST_XPATH_NS "xmlns:ncs=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\""
#define TEST_XPATH_PRINTED "/ncs:netconf-server"

/* opening tag of with-defaults */
#define TEST_WD "<with-defaults xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\">"

struct test_state {
    struct nc_session *server;
    struct nc_session *client;
    int fds[2];
    struct nc_pollsession *ps;
};

/* context shared by all the tests */
static struct ln2_test_ctx *test_ctx;

/* the last RPC received by the server */
static struct lyd_node *recv_rpc;

/**
 * @brief Global RPC callback, remembers the received RPC.
 */
static struct nc_server_reply *
test_rpc_clb(struct lyd_node *rpc, struct nc_session *UNUSED(session))
{
    lyd_free_tree(recv_rpc);
    recv_rpc = NULL;
    if (lyd_dup_single(rpc, NULL, LYD_DUP_RECURSIVE, &recv_rpc)) {
        return NULL;
    }

    return nc_server_reply_ok();
}

/**
 * @brief Send an RPC and check the RPC received by the server.
 *
 * @param[in] st Test state.
 * @param[in] rpc RPC to send, it is freed.
 * @param[in] expected Expected XML of the received RPC.
 */
static void
test_send_rpc(struct test_state *st, struct nc_rpc *rpc, const char *expected)
{
    uint64_t msgid;
    struct lyd_node *envp, *op;
    char *xml;

    assert_non_null(rpc);
    assert_int_equal(nc_send_rpc(st->client, rpc, NC_MSG_TIMEOUT_MS, &msgid), NC_MSG_RPC);

    /* the server receives the RPC and replies */
    assert_int_equal(nc_ps_poll(st->ps, NC_PS_POLL_TIMEOUT_MS, NULL), NC_PSPOLL_RPC);
    assert_int_equal(nc_recv_reply(st->client, rpc, msgid, NC_MSG_TIMEOUT_MS, &envp, &op), NC_MSG_REPLY);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");
    lyd_free_tree(envp);
    nc_rpc_free(rpc);

    /* compare the received RPC */
    assert_non_null(recv_rpc);
    assert_int_equal(lyd_print_mem(&xml, recv_rpc, LYD_XML, LYD_PRINT_SHRINK), LY_SUCCESS);
    assert_string_equal(xml, expected);
    free(xml);
    lyd_free_tree(recv_rpc);
    recv_rpc = NULL;
}

static void
test_nc_rpc_act_generic_xml(void **state)
{
    struct test_state *st = *state;
    const char *xml = "<lock xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><running/></target></lock>";

    test_send_rpc(st, nc_rpc_act_generic_xml(xml, NC_PARAMTYPE_CONST), xml);
    test_send_rpc(st, nc_rpc_act_generic_xml(strdup(xml), NC_PARAMTYPE_FREE), xml);
    test_send_rpc(st, nc_rpc_act_generic_xml(xml, NC_PARAMTYPE_DUP_AND_FREE), xml);
}

static void
test_nc_rpc_act_generic(void **state)
{
    struct test_state *st = *state;
    const char *xml = "<lock xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><candidate/></target></lock>";
    struct lyd_node *data;

    assert_int_equal(lyd_new_path(NULL, test_ctx->ctx, "/ietf-netconf:lock/target/candidate", NULL, 0, &data),
            LY_SUCCESS);

    test_send_rpc(st, nc_rpc_act_generic(data, NC_PARAMTYPE_CONST), xml);
    test_send_rpc(st, nc_rpc_act_generic(data, NC_PARAMTYPE_DUP_AND_FREE), xml);
    test_send_rpc(st, nc_rpc_act_generic(data, NC_PARAMTYPE_FREE), xml);
}

static void
test_nc_rpc_getconfig(void **state)
{
    struct test_state *st = *state;

    /* subtree filter */
    test_send_rpc(st, nc_rpc_getconfig(NC_DATASTORE_CANDIDATE, TEST_SUBTREE, NC_WD_UNKNOWN, NC_PARAMTYPE_CONST),
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><source><candidate/></source>"
            "<filter type=\"subtree\">" TEST_SUBTREE "</filter></get-config>");

    /* XPath filter */
    test_send_rpc(st, nc_rpc_getconfig(NC_DATASTORE_RUNNING, strdup(TEST_XPATH), NC_WD_EXPLICIT,
            NC_PARAMTYPE_FREE),
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><source><running/></source>"
            "<filter type=\"xpath\" " TEST_XPATH_NS " select=\"" TEST_XPATH_PRINTED "\"/>"
            TEST_WD "explicit</with-defaults>"
            "</get-config>");

    /* no filter */
    test_send_rpc(st, nc_rpc_getconfig(NC_DATASTORE_STARTUP, NULL, NC_WD_ALL, NC_PARAMTYPE_DUP_AND_FREE),
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><source><startup/></source>"
            TEST_WD "report-all</with-defaults>"
            "</get-config>");
}

static void
test_nc_rpc_edit(void **state)
{
    struct test_state *st = *state;

    /* config */
    test_send_rpc(st, nc_rpc_edit(NC_DATASTORE_RUNNING, NC_RPC_EDIT_DFLTOP_REPLACE, NC_RPC_EDIT_TESTOPT_TESTSET,
            NC_RPC_EDIT_ERROPT_ROLLBACK, TEST_SUBTREE, NC_PARAMTYPE_CONST),
            "<edit-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><running/></target>"
            "<default-operation>replace</default-operation><test-option>test-then-set</test-option>"
            "<error-option>rollback-on-error</error-option><config>" TEST_SUBTREE "</config></edit-config>");

    /* URL */
    test_send_rpc(st, nc_rpc_edit(NC_DATASTORE_CANDIDATE, NC_RPC_EDIT_DFLTOP_MERGE, NC_RPC_EDIT_TESTOPT_SET,
            NC_RPC_EDIT_ERROPT_STOP, strdup(TEST_URL), NC_PARAMTYPE_FREE),
            "<edit-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><candidate/></target>"
            "<default-operation>merge</default-operation><test-option>set</test-option>"
            "<error-option>stop-on-error</error-option><url>" TEST_URL "</url></edit-config>");

    /* no options */
    test_send_rpc(st, nc_rpc_edit(NC_DATASTORE_CANDIDATE, NC_RPC_EDIT_DFLTOP_UNKNOWN, NC_RPC_EDIT_TESTOPT_UNKNOWN,
            NC_RPC_EDIT_ERROPT_UNKNOWN, TEST_SUBTREE, NC_PARAMTYPE_DUP_AND_FREE),
            "<edit-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><candidate/></target>"
            "<config>" TEST_SUBTREE "</config></edit-config>");
}

static void
test_nc_rpc_copy(void **state)
{
    struct test_state *st = *state;

    /* datastores */
    test_send_rpc(st, nc_rpc_copy(NC_DATASTORE_STARTUP, NULL, NC_DATASTORE_RUNNING, NULL, NC_WD_TRIM,
            NC_PARAMTYPE_CONST),
            "<copy-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><startup/></target>"
            "<source><running/></source>"
            TEST_WD "trim</with-defaults>"
            "</copy-config>");

    /* URLs */
    test_send_rpc(st, nc_rpc_copy(NC_DATASTORE_URL, strdup(TEST_URL), NC_DATASTORE_URL,
            strdup(TEST_SRC_URL), NC_WD_UNKNOWN, NC_PARAMTYPE_FREE),
            "<copy-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<target><url>" TEST_URL "</url></target><source><url>" TEST_SRC_URL "</url></source>"
            "</copy-config>");

    /* config */
    test_send_rpc(st, nc_rpc_copy(NC_DATASTORE_CANDIDATE, NULL, NC_DATASTORE_CONFIG, TEST_SUBTREE, NC_WD_UNKNOWN,
            NC_PARAMTYPE_DUP_AND_FREE),
            "<copy-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><candidate/></target>"
            "<source><config>" TEST_SUBTREE "</config></source></copy-config>");
}

static void
test_nc_rpc_delete(void **state)
{
    struct test_state *st = *state;

    test_send_rpc(st, nc_rpc_delete(NC_DATASTORE_STARTUP, NULL, NC_PARAMTYPE_CONST),
            "<delete-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><startup/></target>"
            "</delete-config>");
    test_send_rpc(st, nc_rpc_delete(NC_DATASTORE_URL, strdup(TEST_URL), NC_PARAMTYPE_FREE),
            "<delete-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<target><url>" TEST_URL "</url></target></delete-config>");
    test_send_rpc(st, nc_rpc_delete(NC_DATASTORE_URL, TEST_URL, NC_PARAMTYPE_DUP_AND_FREE),
            "<delete-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<target><url>" TEST_URL "</url></target></delete-config>");
}

static void
test_nc_rpc_lock(void **state)
{
    struct test_state *st = *state;

    test_send_rpc(st, nc_rpc_lock(NC_DATASTORE_RUNNING),
            "<lock xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><running/></target></lock>");
    test_send_rpc(st, nc_rpc_unlock(NC_DATASTORE_CANDIDATE),
            "<unlock xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><target><candidate/></target></unlock>");
}

static void
test_nc_rpc_get(void **state)
{
    struct test_state *st = *state;

    /* subtree filter */
    test_send_rpc(st, nc_rpc_get(TEST_SUBTREE, NC_WD_ALL_TAG, NC_PARAMTYPE_CONST),
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><filter type=\"subtree\">" TEST_SUBTREE "</filter>"
            TEST_WD "report-all-tagged</with-defaults></get>");

    /* XPath filter */
    test_send_rpc(st, nc_rpc_get(strdup(TEST_XPATH), NC_WD_UNKNOWN, NC_PARAMTYPE_FREE),
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<filter type=\"xpath\" " TEST_XPATH_NS " select=\"" TEST_XPATH_PRINTED "\"/>"
            "</get>");

    /* no filter */
    test_send_rpc(st, nc_rpc_get(NULL, NC_WD_UNKNOWN, NC_PARAMTYPE_DUP_AND_FREE),
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>");
}

static void
test_nc_rpc_kill(void **state)
{
    struct test_state *st = *state;

    test_send_rpc(st, nc_rpc_kill(10),
            "<kill-session xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><session-id>10</session-id>"
            "</kill-session>");
}

static void
test_nc_rpc_commit(void **state)
{
    struct test_state *st = *state;

    /* confirmed */
    test_send_rpc(st, nc_rpc_commit(1, 100, "persist", NULL, NC_PARAMTYPE_CONST),
            "<commit xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><confirmed/>"
            "<confirm-timeout>100</confirm-timeout><persist>persist</persist></commit>");

    /* confirming */
    test_send_rpc(st, nc_rpc_commit(0, 0, NULL, strdup("persist"), NC_PARAMTYPE_FREE),
            "<commit xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><persist-id>persist</persist-id></commit>");

    /* plain */
    test_send_rpc(st, nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_DUP_AND_FREE),
            "<commit xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>");
}

static void
test_nc_rpc_discard(void **state)
{
    struct test_state *st = *state;

    test_send_rpc(st, nc_rpc_discard(), "<discard-changes xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>");
}

static void
test_nc_rpc_cancel(void **state)
{
    struct test_state *st = *state;

    test_send_rpc(st, nc_rpc_cancel("persist", NC_PARAMTYPE_CONST),
            "<cancel-commit xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><persist-id>persist</persist-id>"
            "</cancel-commit>");
    test_send_rpc(st, nc_rpc_cancel(strdup("persist"), NC_PARAMTYPE_FREE),
            "<cancel-commit xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><persist-id>persist</persist-id>"
            "</cancel-commit>");
    test_send_rpc(st, nc_rpc_cancel(NULL, NC_PARAMTYPE_DUP_AND_FREE),
            "<cancel-commit xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>");
}

static void
test_nc_rpc_validate(void **state)
{
    struct test_state *st = *state;

    test_send_rpc(st, nc_rpc_validate(NC_DATASTORE_CANDIDATE, NULL, NC_PARAMTYPE_CONST),
            "<validate xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><source><candidate/></source></validate>");
    test_send_rpc(st, nc_rpc_validate(NC_DATASTORE_URL, strdup(TEST_URL), NC_PARAMTYPE_FREE),
            "<validate xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<source><url>" TEST_URL "</url></source></validate>");
    test_send_rpc(st, nc_rpc_validate(NC_DATASTORE_CONFIG, TEST_SUBTREE, NC_PARAMTYPE_DUP_AND_FREE),
            "<validate xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<source><config>" TEST_SUBTREE "</config></source></validate>");
}

static void
test_nc_rpc_getschema(void **state)
{
    struct test_state *st = *state;

    test_send_rpc(st, nc_rpc_getschema("ietf-netconf", "2013-09-29", "yang", NC_PARAMTYPE_CONST),
            "<get-schema xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">"
            "<identifier>ietf-netconf</identifier><version>2013-09-29</version><format>yang</format></get-schema>");
    test_send_rpc(st, nc_rpc_getschema(strdup("ietf-netconf"), NULL, strdup("yin"), NC_PARAMTYPE_FREE),
            "<get-schema xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">"
            "<identifier>ietf-netconf</identifier><format>yin</format></get-schema>");
    test_send_rpc(st, nc_rpc_getschema("ietf-netconf", NULL, NULL, NC_PARAMTYPE_DUP_AND_FREE),
            "<get-schema xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">"
            "<identifier>ietf-netconf</identifier></get-schema>");
}

static void
test_nc_rpc_subscribe(void **state)
{
    struct test_state *st = *state;

    /* subtree filter and times */
    test_send_rpc(st, nc_rpc_subscribe("stream", TEST_SUBTREE, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z",
            NC_PARAMTYPE_CONST),
            "<create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><stream>stream</stream>"
            "<filter type=\"subtree\">" TEST_SUBTREE "</filter><startTime>2026-01-01T00:00:00Z</startTime>"
            "<stopTime>2026-01-02T00:00:00Z</stopTime></create-subscription>");

    /* XPath filter */
    test_send_rpc(st, nc_rpc_subscribe(strdup("stream"), strdup(TEST_XPATH), NULL, NULL, NC_PARAMTYPE_FREE),
            "<create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><stream>stream</stream>"
            "<filter type=\"xpath\" " TEST_XPATH_NS " select=\"" TEST_XPATH_PRINTED "\"/>"
            "</create-subscription>");

    /* defaults */
    test_send_rpc(st, nc_rpc_subscribe(NULL, NULL, NULL, NULL, NC_PARAMTYPE_DUP_AND_FREE),
            "<create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\"/>");
}

static void
test_nc_rpc_getdata(void **state)
{
    struct test_state *st = *state;
    char *origin_filter = (char *)"ietf-origin:intended";
    char **origin_filters;

    /* XPath filter, origin */
    test_send_rpc(st, nc_rpc_getdata("ietf-datastores:operational", TEST_XPATH, "true", &origin_filter,
            1, 0, 3, 1, NC_WD_EXPLICIT, NC_PARAMTYPE_CONST),
            "<get-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">"
            "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>"
            "<xpath-filter " TEST_XPATH_NS ">" TEST_XPATH_PRINTED "</xpath-filter>"
            "<config-filter>true</config-filter>"
            "<origin-filter xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\">or:intended</origin-filter>"
            "<max-depth>3</max-depth><with-origin/><with-defaults>explicit</with-defaults></get-data>");

    /* subtree filter, negated origin */
    origin_filters = malloc(sizeof *origin_filters);
    assert_non_null(origin_filters);
    origin_filters[0] = strdup(origin_filter);
    test_send_rpc(st, nc_rpc_getdata(strdup("ietf-datastores:operational"), strdup(TEST_SUBTREE), NULL,
            origin_filters, 1, 1, 0, 0, NC_WD_UNKNOWN, NC_PARAMTYPE_FREE),
            "<get-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">"
            "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>"
            "<subtree-filter>" TEST_SUBTREE "</subtree-filter>"
            "<negated-origin-filter xmlns:or=\"urn:ietf:params:xml:ns:yang:ietf-origin\">or:intended"
            "</negated-origin-filter></get-data>");

    /* no filter */
    test_send_rpc(st, nc_rpc_getdata("ietf-datastores:running", NULL, "false", NULL, 0, 0, 0, 0, NC_WD_UNKNOWN,
            NC_PARAMTYPE_DUP_AND_FREE),
            "<get-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">"
            "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
            "<config-filter>false</config-filter></get-data>");
}

static void
test_nc_rpc_editdata(void **state)
{
    struct test_state *st = *state;

    test_send_rpc(st, nc_rpc_editdata("ietf-datastores:candidate", NC_RPC_EDIT_DFLTOP_MERGE, TEST_SUBTREE,
            NC_PARAMTYPE_CONST),
            "<edit-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">"
            "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:candidate</datastore>"
            "<default-operation>merge</default-operation><config>" TEST_SUBTREE "</config></edit-data>");
    test_send_rpc(st, nc_rpc_editdata(strdup("ietf-datastores:running"), NC_RPC_EDIT_DFLTOP_UNKNOWN,
            strdup(TEST_URL), NC_PARAMTYPE_FREE),
            "<edit-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">"
            "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
            "<url>" TEST_URL "</url></edit-data>");
    test_send_rpc(st, nc_rpc_editdata("ietf-datastores:running", NC_RPC_EDIT_DFLTOP_REPLACE, TEST_SUBTREE,
            NC_PARAMTYPE_DUP_AND_FREE),
            "<edit-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">"
            "<datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
            "<default-operation>replace</default-operation><config>" TEST_SUBTREE "</config></edit-data>");
}

static int
setup_f(void **state)
{
    struct test_state *st;

    st = calloc(1, sizeof *st);
    if (!st) {
        SETUP_FAIL_LOG;
        return 1;
    }
    *state = st;

    ln2_glob_test_fd_sessions(test_ctx->ctx, 1, &st->server, &st->client, st->fds);

    st->ps = nc_ps_new();
    if (!st->ps || nc_ps_add_session(st->ps, st->server)) {
        SETUP_FAIL_LOG;
        return 1;
    }

    return 0;
}

static int
teardown_f(void **state)
{
    struct test_state *st = *state;

    nc_ps_free(st->ps);

    /* close the socketpair first so that the client does not wait for a <close-session> reply */
    close(st->fds[0]);
    close(st->fds[1]);
    nc_session_free(st->server, NULL);
    nc_session_free(st->client, NULL);
    free(st);

    return 0;
}

static int
setup_glob(void **state)
{
    const char *nmda_features[] = {"origin", "with-defaults", NULL};

    (void)state;

    if (ln2_glob_test_setup(&test_ctx)) {
        return 1;
    }

    /* modules of all the RPCs */
    ly_ctx_set_searchdir(test_ctx->ctx, TESTS_DIR "/data/modules");
    if (!ly_ctx_load_module(test_ctx->ctx, "ietf-netconf-with-defaults", NULL, NULL) ||
            !ly_ctx_load_module(test_ctx->ctx, "notifications", NULL, NULL) ||
            !ly_ctx_load_module(test_ctx->ctx, "ietf-origin", NULL, NULL) ||
            !ly_ctx_load_module(test_ctx->ctx, "ietf-netconf-nmda", NULL, nmda_features)) {
        SETUP_FAIL_LOG;
        return 1;
    }

    /* the server only remembers the RPCs */
    nc_set_global_rpc_clb(test_rpc_clb);

    return 0;
}

static int
teardown_glob(void **state)
{
    (void)state;

    nc_set_global_rpc_clb(NULL);
    return ln2_glob_test_teardown((void **)&test_ctx);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_rpc_act_generic_xml, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_act_generic, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_getconfig, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_edit, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_copy, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_delete, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_lock, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_get, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_kill, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_commit, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_discard, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_cancel, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_validate, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_getschema, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_subscribe, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_getdata, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_editdata, setup_f, teardown_f),
    };

    return cmocka_run_group_tests(tests, setup_glob, teardown_glob);
}
