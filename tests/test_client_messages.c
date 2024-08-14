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

#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cmocka.h>
#include <messages_p.h>

#include "ln2_test.h"

static int
setup_f(void **state)
{
    (void)state;

    nc_verbosity(NC_VERB_VERBOSE);

    return 0;
}

static int
teardown_f(void **state)
{
    (void)state;

    return 0;
}

static void
test_nc_rpc_act_generic_xml(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;
    struct nc_rpc_act_generic *generic_rpc = NULL;

    /* create generic rpc with NC_PARAMTYPE_CONST */
    rpc = nc_rpc_act_generic_xml("xml", NC_PARAMTYPE_CONST);
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_ACT_GENERIC);
    generic_rpc = (struct nc_rpc_act_generic *)rpc;
    assert_int_equal(generic_rpc->type, NC_RPC_ACT_GENERIC);
    assert_int_equal(generic_rpc->has_data, 0);
    assert_string_equal(generic_rpc->content.xml_str, "xml");
    nc_rpc_free(rpc);

    /* create generic rpc with NC_PARAMTYPE_FREE */
    char *str = strdup("str");

    rpc = nc_rpc_act_generic_xml(str, NC_PARAMTYPE_FREE);
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_ACT_GENERIC);
    generic_rpc = (struct nc_rpc_act_generic *)rpc;
    assert_int_equal(generic_rpc->type, NC_RPC_ACT_GENERIC);
    assert_int_equal(generic_rpc->has_data, 0);
    assert_string_equal(generic_rpc->content.xml_str, str);
    nc_rpc_free(rpc);

    /* create generic rpc with NC_PARAMTYPE_DUP_AND_FREE */
    rpc = nc_rpc_act_generic_xml("xml", NC_PARAMTYPE_DUP_AND_FREE);
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_ACT_GENERIC);
    generic_rpc = (struct nc_rpc_act_generic *)rpc;
    assert_int_equal(generic_rpc->type, NC_RPC_ACT_GENERIC);
    assert_int_equal(generic_rpc->has_data, 0);
    assert_string_equal(generic_rpc->content.xml_str, "xml");
    nc_rpc_free(rpc);
}

static void
test_nc_rpc_act_generic(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;
    struct nc_rpc_act_generic *generic_rpc = NULL;
    struct lyd_node node;

    node.next = NULL;
    node.prev = &node;

    rpc = nc_rpc_act_generic(&node, NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_ACT_GENERIC);
    generic_rpc = (struct nc_rpc_act_generic *)rpc;
    assert_int_equal(generic_rpc->type, NC_RPC_ACT_GENERIC);
    assert_int_equal(generic_rpc->has_data, 1);
    assert_ptr_equal(generic_rpc->content.data, &node);
    nc_rpc_free(rpc);
}

/* function to check if values of getconfig rpc are set correctly */
void
check_getconfig(struct nc_rpc *rpc, enum NC_DATASTORE_TYPE source, char *filter, NC_WD_MODE wd_mode)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_GETCONFIG);
    struct nc_rpc_getconfig *getconfig_rpc = (struct nc_rpc_getconfig *)rpc;

    assert_int_equal(getconfig_rpc->type, NC_RPC_GETCONFIG);
    assert_int_equal(getconfig_rpc->source, source);
    assert_string_equal(getconfig_rpc->filter, filter);
    assert_int_equal(getconfig_rpc->wd_mode, wd_mode);
}

static void
test_nc_rpc_getconfig(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create getconfig rpc with NC_PARAMTYPE_CONST */
    rpc = nc_rpc_getconfig(NC_DATASTORE_CANDIDATE, "filter-string", NC_WD_UNKNOWN, NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_getconfig(rpc, NC_DATASTORE_CANDIDATE, "filter-string", NC_WD_UNKNOWN);
    nc_rpc_free(rpc);

    /* create getconfig rpc with NC_PARAMTYPE_FREE */
    char *filter = strdup("string");

    rpc = nc_rpc_getconfig(NC_DATASTORE_CONFIG, filter, NC_WD_EXPLICIT, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_getconfig(rpc, NC_DATASTORE_CONFIG, filter, NC_WD_EXPLICIT);
    nc_rpc_free(rpc);

    /* create getconfig rpc with NC_PARAMTYPE_DUP_AND_FREE */
    rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, "filter", NC_WD_ALL, NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_getconfig(rpc, NC_DATASTORE_RUNNING, "filter", NC_WD_ALL);
    nc_rpc_free(rpc);
}

/* function to check if values of edit rpc are set correctly */
void
check_edit(struct nc_rpc *rpc, NC_DATASTORE target, NC_RPC_EDIT_DFLTOP default_op, NC_RPC_EDIT_TESTOPT test_opt,
        NC_RPC_EDIT_ERROPT error_opt, const char *edit_content)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_EDIT);
    struct nc_rpc_edit *edit_rpc = (struct nc_rpc_edit *)rpc;

    assert_int_equal(edit_rpc->type, NC_RPC_EDIT);
    assert_int_equal(edit_rpc->target, target);
    assert_int_equal(edit_rpc->default_op, default_op);
    assert_int_equal(edit_rpc->test_opt, test_opt);
    assert_int_equal(edit_rpc->error_opt, error_opt);
    assert_string_equal(edit_rpc->edit_cont, edit_content);
}

static void
test_nc_rpc_edit(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create edit rpc with NC_PARAMTYPE_CONST */
    rpc = nc_rpc_edit(NC_DATASTORE_RUNNING, NC_RPC_EDIT_DFLTOP_REPLACE, NC_RPC_EDIT_TESTOPT_TESTSET,
            NC_RPC_EDIT_ERROPT_STOP, "url", NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_edit(rpc, NC_DATASTORE_RUNNING, NC_RPC_EDIT_DFLTOP_REPLACE,
            NC_RPC_EDIT_TESTOPT_TESTSET, NC_RPC_EDIT_ERROPT_STOP, "url");
    nc_rpc_free(rpc);

    /* create edit rpc with NC_PARAMTYPE_FREE */
    char *str = strdup("string");

    rpc = nc_rpc_edit(NC_DATASTORE_CANDIDATE, NC_RPC_EDIT_DFLTOP_MERGE, NC_RPC_EDIT_TESTOPT_SET,
            NC_RPC_EDIT_ERROPT_ROLLBACK, str, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_edit(rpc, NC_DATASTORE_CANDIDATE, NC_RPC_EDIT_DFLTOP_MERGE,
            NC_RPC_EDIT_TESTOPT_SET, NC_RPC_EDIT_ERROPT_ROLLBACK, str);
    nc_rpc_free(rpc);

    /* create edit rpc with NC_PARAMTYPE_DUP_AND_FREE */
    rpc = nc_rpc_edit(NC_DATASTORE_CONFIG, NC_RPC_EDIT_DFLTOP_NONE, NC_RPC_EDIT_TESTOPT_TEST,
            NC_RPC_EDIT_ERROPT_CONTINUE, "url1", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_edit(rpc, NC_DATASTORE_CONFIG, NC_RPC_EDIT_DFLTOP_NONE,
            NC_RPC_EDIT_TESTOPT_TEST, NC_RPC_EDIT_ERROPT_CONTINUE, "url1");
    nc_rpc_free(rpc);
}

/* function to check if values of copy rpc are set correctly */
void
check_copy(struct nc_rpc *rpc, NC_DATASTORE target, const char *url_trg, NC_DATASTORE source,
        const char *url_or_config_src, NC_WD_MODE wd_mode)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_COPY);
    struct nc_rpc_copy *copy_rpc = (struct nc_rpc_copy *)rpc;

    assert_int_equal(copy_rpc->type, NC_RPC_COPY);
    assert_int_equal(copy_rpc->target, target);
    assert_string_equal(copy_rpc->url_trg, url_trg);
    assert_int_equal(copy_rpc->source, source);
    assert_string_equal(copy_rpc->url_config_src, url_or_config_src);
    assert_int_equal(copy_rpc->wd_mode, wd_mode);
}

static void
test_nc_rpc_copy(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create copy rpc with NC_PARAMTYPE_CONST */
    rpc = nc_rpc_copy(NC_DATASTORE_RUNNING, "target-url", NC_DATASTORE_RUNNING, "src-url",
            NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_copy(rpc, NC_DATASTORE_RUNNING, "target-url", NC_DATASTORE_RUNNING, "src-url", NC_WD_ALL);
    nc_rpc_free(rpc);

    /* create copy rpc with NC_PARAMTYPE_FREE */
    char *target = strdup("target");
    char *src = strdup("src");

    rpc = nc_rpc_copy(NC_DATASTORE_STARTUP, target, NC_DATASTORE_RUNNING, src,
            NC_WD_ALL_TAG, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_copy(rpc, NC_DATASTORE_STARTUP, target, NC_DATASTORE_RUNNING, src, NC_WD_ALL_TAG);
    nc_rpc_free(rpc);

    /* create copy rpc with NC_PARAMTYPE_DUP_AND_FREE */
    rpc = nc_rpc_copy(NC_DATASTORE_STARTUP, "url", NC_DATASTORE_CANDIDATE, "url",
            NC_WD_TRIM, NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_copy(rpc, NC_DATASTORE_STARTUP, "url", NC_DATASTORE_CANDIDATE, "url", NC_WD_TRIM);
    nc_rpc_free(rpc);
}

/* function to check if values of delete rpc are set correctly */
void
check_delete(struct nc_rpc *rpc, NC_DATASTORE target, const char *url)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_DELETE);
    struct nc_rpc_delete *delete_rpc = (struct nc_rpc_delete *)rpc;

    assert_int_equal(delete_rpc->type, NC_RPC_DELETE);
    assert_int_equal(delete_rpc->target, target);
    assert_string_equal(delete_rpc->url, url);
}

static void
test_nc_rpc_delete(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create delete rpc with NC_PARAMTYPE_CONST */
    rpc = nc_rpc_delete(NC_DATASTORE_RUNNING, "target-url", NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_delete(rpc, NC_DATASTORE_RUNNING, "target-url");
    nc_rpc_free(rpc);

    /* create delete rpc with NC_PARAMTYPE_FREE */
    char *url = strdup("url");

    rpc = nc_rpc_delete(NC_DATASTORE_CANDIDATE, url, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_delete(rpc, NC_DATASTORE_CANDIDATE, url);
    nc_rpc_free(rpc);

    /* create delete rpc with NC_PARAMTYPE_DUP_AND_FREE */
    rpc = nc_rpc_delete(NC_DATASTORE_CONFIG, "target", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_delete(rpc, NC_DATASTORE_CONFIG, "target");
    nc_rpc_free(rpc);
}

static void
test_nc_rpc_lock(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;
    struct nc_rpc_lock *lock_rpc = NULL;

    rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    assert_non_null(rpc);
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_LOCK);

    lock_rpc = (struct nc_rpc_lock *)rpc;
    assert_int_equal(lock_rpc->type, NC_RPC_LOCK);
    assert_int_equal(lock_rpc->target, NC_DATASTORE_RUNNING);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_unlock(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;
    struct nc_rpc_lock *unlock_rpc = NULL;

    rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    assert_non_null(rpc);
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_UNLOCK);

    unlock_rpc = (struct nc_rpc_lock *)rpc;
    assert_int_equal(unlock_rpc->type, NC_RPC_UNLOCK);
    assert_int_equal(unlock_rpc->target, NC_DATASTORE_RUNNING);
    nc_rpc_free(rpc);
}

/* function to check if values of get rpc are set correctly */
void
check_get_rpc(struct nc_rpc *rpc, const char *filter, NC_WD_MODE wd_mode)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_GET);
    struct nc_rpc_get *get_rpc = (struct nc_rpc_get *)rpc;

    assert_int_equal(get_rpc->type, NC_RPC_GET);
    assert_string_equal(get_rpc->filter, filter);
    assert_int_equal(get_rpc->wd_mode, wd_mode);
}

static void
test_nc_rpc_get(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create get rpc with NC_PARAMTYPE_CONST */
    rpc = nc_rpc_get("filter", NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_get_rpc(rpc, "filter", NC_WD_ALL);
    nc_rpc_free(rpc);

    /* create get rpc with NC_PARAMTYPE_FREE */
    char *str = strdup("string");

    rpc = nc_rpc_get(str, NC_WD_EXPLICIT, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_get_rpc(rpc, str, NC_WD_EXPLICIT);
    nc_rpc_free(rpc);

    /* create get rpc with NC_PARAMTYPE_DUP_AND_FREE */
    rpc = nc_rpc_get("filter-string", NC_WD_UNKNOWN, NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_get_rpc(rpc, "filter-string", NC_WD_UNKNOWN);
    nc_rpc_free(rpc);
}

static void
test_nc_rpc_kill(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;
    struct nc_rpc_kill *kill_rpc = NULL;

    rpc = nc_rpc_kill(10);
    assert_non_null(rpc);
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_KILL);

    kill_rpc = (struct nc_rpc_kill *)rpc;
    assert_int_equal(kill_rpc->type, NC_RPC_KILL);
    assert_int_equal(kill_rpc->sid, 10);

    nc_rpc_free(rpc);
}

/* function to check if values of commit rpc are set correctly */
void
check_commit_rpc(struct nc_rpc *rpc, int confirmed, uint32_t confirm_timeout, const char *persist, const char *persist_id)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_COMMIT);
    struct nc_rpc_commit *commit_rpc = (struct nc_rpc_commit *)rpc;

    assert_int_equal(commit_rpc->type, NC_RPC_COMMIT);
    assert_int_equal(commit_rpc->confirmed, confirmed);
    assert_int_equal(commit_rpc->confirm_timeout, confirm_timeout);
    assert_string_equal(commit_rpc->persist, persist);
    assert_string_equal(commit_rpc->persist_id, persist_id);
}

static void
test_nc_rpc_commit(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create commit rpc with NC_PARAMTYPE_CONST*/
    rpc = nc_rpc_commit(1, 100, "persist", "persist-id", NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_commit_rpc(rpc, 1, 100, "persist", "persist-id");
    nc_rpc_free(rpc);

    /* create commit rpc with NC_PARAMTYPE_FREE*/
    char *str1 = strdup("str1");
    char *str2 = strdup("str2");

    rpc = nc_rpc_commit(2, 5, str1, str2, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_commit_rpc(rpc, 2, 5, str1, str2);
    nc_rpc_free(rpc);

    /* create commit rpc with NC_PARAMTYPE_DUP_AND_FREE*/
    rpc = nc_rpc_commit(10, 200, "persistent", "persistent-id", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_commit_rpc(rpc, 10, 200, "persistent", "persistent-id");
    nc_rpc_free(rpc);
}

static void
test_nc_rpc_discard(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_discard();
    assert_non_null(rpc);
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_DISCARD);

    nc_rpc_free(rpc);
}

/* function to check if values of cancel rpc are set correctly */
void
check_cancel_rpc(struct nc_rpc *rpc, const char *persist_id)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_CANCEL);
    struct nc_rpc_cancel *cancel_rpc = (struct nc_rpc_cancel *)rpc;

    assert_int_equal(cancel_rpc->type, NC_RPC_CANCEL);
    assert_string_equal(cancel_rpc->persist_id, persist_id);
}

static void
test_nc_rpc_cancel(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create cancel rpc with NC_PARAMTYPE_CONST*/
    rpc = nc_rpc_cancel("persist-id", NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_cancel_rpc(rpc, "persist-id");
    nc_rpc_free(rpc);

    /* create cancel rpc with NC_PARAMTYPE_FREE*/
    char *str = strdup("string");

    rpc = nc_rpc_cancel(str, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_cancel_rpc(rpc, str);
    nc_rpc_free(rpc);

    /* create cancel rpc with NC_PARAMTYPE_DUP_AND_FREE*/
    rpc = nc_rpc_cancel("id", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_cancel_rpc(rpc, "id");
    nc_rpc_free(rpc);
}

/* function to check if values of validate rpc are set correctly */
void
check_validate_rpc(struct nc_rpc *rpc, NC_DATASTORE source, const char *url_or_config)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_VALIDATE);
    struct nc_rpc_validate *validate_rpc = (struct nc_rpc_validate *)rpc;

    assert_int_equal(validate_rpc->type, NC_RPC_VALIDATE);
    assert_int_equal(validate_rpc->source, source);
    assert_string_equal(validate_rpc->url_config_src, url_or_config);
}

static void
test_nc_rpc_validate(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create validate rpc with NC_PARAMTYPE_CONST */
    rpc = nc_rpc_validate(NC_DATASTORE_RUNNING, "url", NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_validate_rpc(rpc, NC_DATASTORE_RUNNING, "url");
    nc_rpc_free(rpc);

    /* create validate rpc with NC_PARAMTYPE_FREE */
    char *str = strdup("string");

    rpc = nc_rpc_validate(NC_DATASTORE_CANDIDATE, str, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_validate_rpc(rpc, NC_DATASTORE_CANDIDATE, str);
    nc_rpc_free(rpc);

    /* create validate rpc with NC_PARAMTYPE_DUP_AND_FREE */
    rpc = nc_rpc_validate(NC_DATASTORE_CONFIG, "url1", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_validate_rpc(rpc, NC_DATASTORE_CONFIG, "url1");
    nc_rpc_free(rpc);
}

/* function to check if values of getschema rpc are set correctly */
void
check_getschema_rpc(struct nc_rpc *rpc, const char *identifier, const char *version, const char *format)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_GETSCHEMA);
    struct nc_rpc_getschema *getchema_rpc = (struct nc_rpc_getschema *)rpc;

    assert_int_equal(getchema_rpc->type, NC_RPC_GETSCHEMA);
    assert_string_equal(getchema_rpc->identifier, identifier);
    assert_string_equal(getchema_rpc->version, version);
    assert_string_equal(getchema_rpc->format, format);
}

static void
test_nc_rpc_getschema(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create getchema with NC_PARAMTYPE_CONST*/
    rpc = nc_rpc_getschema("id", "version", "format", NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_getschema_rpc(rpc, "id", "version", "format");
    nc_rpc_free(rpc);

    /* create getchema with NC_PARAMTYPE_FREE*/
    char *str1 = strdup("str1");
    char *str2 = strdup("str2");
    char *str3 = strdup("str3");

    rpc = nc_rpc_getschema(str1, str2, str3, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_getschema_rpc(rpc, str1, str2, str3);
    nc_rpc_free(rpc);

    /* create getchema with NC_PARAMTYPE_DUP_AND_FREE*/
    rpc = nc_rpc_getschema("id1", "version1", "format1", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_getschema_rpc(rpc, "id1", "version1", "format1");
    nc_rpc_free(rpc);
}

/* function to check if values of subscribe rpc are set correctly */
void
check_subscribe_rpc(struct nc_rpc *rpc, const char *stream_name, const char *filter,
        const char *start_time, const char *stop_time)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_SUBSCRIBE);
    struct nc_rpc_subscribe *subscribe_rpc = (struct nc_rpc_subscribe *)rpc;

    assert_int_equal(subscribe_rpc->type, NC_RPC_SUBSCRIBE);
    assert_string_equal(subscribe_rpc->stream, stream_name);
    assert_string_equal(subscribe_rpc->filter, filter);
    assert_string_equal(subscribe_rpc->start, start_time);
    assert_string_equal(subscribe_rpc->stop, stop_time);
}

static void
test_nc_rpc_subscribe(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create subscribe rpc with NC_PARAMTYPE_CONST*/
    rpc = nc_rpc_subscribe("stream-name", "filter", "start-time", "stop-time", NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_subscribe_rpc(rpc, "stream-name", "filter", "start-time", "stop-time");
    nc_rpc_free(rpc);

    /* create subscribe rpc with NC_PARAMTYPE_FREE*/
    char *str1 = strdup("str1");
    char *str2 = strdup("str2");
    char *str3 = strdup("str3");
    char *str4 = strdup("str4");

    rpc = nc_rpc_subscribe(str1, str2, str3, str4, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_subscribe_rpc(rpc, str1, str2, str3, str4);
    nc_rpc_free(rpc);

    /* create subscribe rpc with NC_PARAMTYPE_DUP_AND_FREE*/
    rpc = nc_rpc_subscribe("name", "filter-str", "start", "stop", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_subscribe_rpc(rpc, "name", "filter-str", "start", "stop");
    nc_rpc_free(rpc);
}

/* function to check if values of getdata rpc are set correctly */
void
check_getdata(struct nc_rpc *rpc, char *datastore, const char *filter, const char *config_filter,
        char **origin_filter, int origin_filter_count, int negated_origin_filter, uint16_t max_depth,
        int with_origin, NC_WD_MODE wd_mode)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_GETDATA);
    struct nc_rpc_getdata *rpc_getdata = (struct nc_rpc_getdata *)rpc;

    assert_int_equal(rpc_getdata->type, NC_RPC_GETDATA);
    assert_string_equal(rpc_getdata->datastore, datastore);
    assert_string_equal(rpc_getdata->filter, filter);
    assert_string_equal(rpc_getdata->config_filter, config_filter);
    assert_string_equal(*rpc_getdata->origin_filter, *origin_filter);
    assert_int_equal(rpc_getdata->origin_filter_count, origin_filter_count);
    assert_int_equal(rpc_getdata->negated_origin_filter, negated_origin_filter);
    assert_int_equal(rpc_getdata->max_depth, max_depth);
    assert_int_equal(rpc_getdata->with_origin, with_origin);
    assert_int_equal(rpc_getdata->wd_mode, wd_mode);
}

static void
test_nc_rpc_getdata(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create getdata rpc with NC_PARAMTYPE_CONST */
    char *origin_filters = "origin_filter";

    rpc = nc_rpc_getdata("candidate", "filter", "true", &origin_filters, 1, 1, 3, 1, NC_WD_UNKNOWN, NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_getdata(rpc, "candidate", "filter", "true", &origin_filters, 1, 1, 3, 1, NC_WD_UNKNOWN);
    nc_rpc_free(rpc);

    /* create getdata rpc with NC_PARAMTYPE_FREE */
    char *datastore = strdup("running");
    char *filter = strdup("filter");
    char *config_filter = strdup("true");
    char buf[20] = {0};
    char **origin_filter;
    int origin_filter_count = 2;

    origin_filter = calloc(origin_filter_count, sizeof *origin_filter);
    assert_non_null(origin_filter);
    for (int i = 0; i < origin_filter_count; i++) {
        snprintf(buf, sizeof(buf) - 1, "origin_filter%d", i + 1);
        origin_filter[i] = strdup(buf);
    }

    rpc = nc_rpc_getdata(datastore, filter, config_filter, origin_filter, origin_filter_count, 2, 3, 1, NC_WD_EXPLICIT, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_getdata(rpc, datastore, filter, config_filter, origin_filter, origin_filter_count, 2, 3, 1, NC_WD_EXPLICIT);
    nc_rpc_free(rpc);

    /* create getdata rpc with NC_PARAMTYPE_DUP_AND_FREE */
    char *origin_filter1 = "origin_filter1";

    rpc = nc_rpc_getdata("startup", "filter1", "false", &origin_filter1, 1, 0, 3, 1, NC_WD_ALL, NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_getdata(rpc, "startup", "filter1", "false", &origin_filter1, 1, 0, 3, 1, NC_WD_ALL);
    nc_rpc_free(rpc);
}

/* function to check if values of editdata rpc are set correctly */
void
check_editdata(struct nc_rpc *rpc, char *datastore, NC_RPC_EDIT_DFLTOP default_op, const char *edit_content)
{
    assert_int_equal(nc_rpc_get_type(rpc), NC_RPC_EDITDATA);
    struct nc_rpc_editdata *rpc_editdata = (struct nc_rpc_editdata *)rpc;

    assert_int_equal(rpc_editdata->type, NC_RPC_EDITDATA);
    assert_string_equal(rpc_editdata->datastore, datastore);
    assert_int_equal(rpc_editdata->default_op, default_op);
    assert_string_equal(rpc_editdata->edit_cont, edit_content);
}

static void
test_nc_rpc_editdata(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    /* create editdata rpc with NC_PARAMTYPE_CONST */
    rpc = nc_rpc_editdata("candidate", NC_RPC_EDIT_DFLTOP_UNKNOWN, "edit", NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    check_editdata(rpc, "candidate", NC_RPC_EDIT_DFLTOP_UNKNOWN, "edit");
    nc_rpc_free(rpc);

    /* create editdata rpc with NC_PARAMTYPE_FREE */
    char *datastore = strdup("running");
    char *edit_cont = strdup("edit_data");

    rpc = nc_rpc_editdata(datastore, NC_RPC_EDIT_DFLTOP_MERGE, edit_cont, NC_PARAMTYPE_FREE);
    assert_non_null(rpc);
    check_editdata(rpc, datastore, NC_RPC_EDIT_DFLTOP_MERGE, edit_cont);
    nc_rpc_free(rpc);

    /* create editdata rpc with NC_PARAMTYPE_DUP_AND_FREE */
    rpc = nc_rpc_editdata("startup", NC_RPC_EDIT_DFLTOP_REPLACE, "edit_cont", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    check_editdata(rpc, "startup", NC_RPC_EDIT_DFLTOP_REPLACE, "edit_cont");
    nc_rpc_free(rpc);
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
        cmocka_unit_test_setup_teardown(test_nc_rpc_unlock, setup_f, teardown_f),
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
