/**
 * @file messages_server.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 - server NETCONF messages functions
 *
 * @copyright
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE /* pthread_rwlock_t, strdup */

#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "messages_p.h"
#include "messages_server.h"
#include "netconf.h"

extern struct nc_server_opts server_opts;

API struct nc_server_reply *
nc_server_reply_ok(void)
{
    struct nc_server_reply *ret;

    ret = malloc(sizeof *ret);
    NC_CHECK_ERRMEM_RET(!ret, NULL);

    ret->type = NC_RPL_OK;
    return ret;
}

API struct nc_server_reply *
nc_server_reply_data(struct lyd_node *data, NC_WD_MODE wd, NC_PARAMTYPE paramtype)
{
    struct nc_server_reply_data *ret;

    NC_CHECK_ARG_RET(NULL, data, NULL);

    if (!(data->schema->nodetype & (LYS_RPC | LYS_ACTION))) {
        ERR(NULL, "nc_server_reply_data bad data");
        return NULL;
    }

    ret = malloc(sizeof *ret);
    NC_CHECK_ERRMEM_RET(!ret, NULL);

    ret->type = NC_RPL_DATA;
    ret->wd = wd;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        if (lyd_dup_single(data, NULL, LYD_DUP_RECURSIVE, &ret->data)) {
            free(ret);
            return NULL;
        }
    } else {
        ret->data = data;
    }
    if (paramtype != NC_PARAMTYPE_CONST) {
        ret->free = 1;
    } else {
        ret->free = 0;
    }
    return (struct nc_server_reply *)ret;
}

API struct nc_server_reply *
nc_server_reply_err(struct lyd_node *err)
{
    struct nc_server_reply_error *ret;

    NC_CHECK_ARG_RET(NULL, err, NULL);

    ret = malloc(sizeof *ret);
    NC_CHECK_ERRMEM_RET(!ret, NULL);

    ret->type = NC_RPL_ERROR;
    ret->err = err;
    return (struct nc_server_reply *)ret;
}

API int
nc_server_reply_add_err(struct nc_server_reply *reply, struct lyd_node *err)
{
    struct nc_server_reply_error *err_rpl;

    NC_CHECK_ARG_RET(NULL, reply, err, -1);

    if (reply->type != NC_RPL_ERROR) {
        ERR(NULL, "nc_server_reply_add_err() bad reply type");
        return -1;
    }

    err_rpl = (struct nc_server_reply_error *)reply;
    lyd_insert_sibling(err_rpl->err, err, &err_rpl->err);
    return 0;
}

API const struct lyd_node *
nc_server_reply_get_last_err(const struct nc_server_reply *reply)
{
    struct nc_server_reply_error *err_rpl;

    NC_CHECK_ARG_RET(NULL, reply, NULL);

    if (reply->type != NC_RPL_ERROR) {
        ERR(NULL, "nc_server_reply_get_last_err() bad reply type");
        return NULL;
    }

    err_rpl = (struct nc_server_reply_error *)reply;
    if (!err_rpl->err) {
        return NULL;
    }
    return err_rpl->err->prev;
}

static const char *
nc_err_tag2str(NC_ERR tag)
{
    switch (tag) {
    case NC_ERR_IN_USE:
        return "in-use";
    case NC_ERR_INVALID_VALUE:
        return "invalid-value";
    case NC_ERR_ACCESS_DENIED:
        return "access-denied";
    case NC_ERR_ROLLBACK_FAILED:
        return "rollback-failed";
    case NC_ERR_OP_NOT_SUPPORTED:
        return "operation-not-supported";
    case NC_ERR_TOO_BIG:
        return "too-big";
    case NC_ERR_RES_DENIED:
        return "resource-denied";
    case NC_ERR_MISSING_ATTR:
        return "missing-attribute";
    case NC_ERR_BAD_ATTR:
        return "bad-attribute";
    case NC_ERR_UNKNOWN_ATTR:
        return "unknown-attribute";
    case NC_ERR_MISSING_ELEM:
        return "missing-element";
    case NC_ERR_BAD_ELEM:
        return "bad-element";
    case NC_ERR_UNKNOWN_ELEM:
        return "unknown-element";
    case NC_ERR_UNKNOWN_NS:
        return "unknown-namespace";
    case NC_ERR_LOCK_DENIED:
        return "lock-denied";
    case NC_ERR_DATA_EXISTS:
        return "data-exists";
    case NC_ERR_DATA_MISSING:
        return "data-missing";
    case NC_ERR_OP_FAILED:
        return "operation-failed";
    case NC_ERR_MALFORMED_MSG:
        return "malformed-message";
    default:
        break;
    }

    return NULL;
}

static NC_ERR
nc_err_str2tag(const char *str)
{
    if (!strcmp(str, "in-use")) {
        return NC_ERR_IN_USE;
    } else if (!strcmp(str, "invalid-value")) {
        return NC_ERR_INVALID_VALUE;
    } else if (!strcmp(str, "access-denied")) {
        return NC_ERR_ACCESS_DENIED;
    } else if (!strcmp(str, "rollback-failed")) {
        return NC_ERR_ROLLBACK_FAILED;
    } else if (!strcmp(str, "operation-not-supported")) {
        return NC_ERR_OP_NOT_SUPPORTED;
    } else if (!strcmp(str, "too-big")) {
        return NC_ERR_TOO_BIG;
    } else if (!strcmp(str, "resource-denied")) {
        return NC_ERR_RES_DENIED;
    } else if (!strcmp(str, "missing-attribute")) {
        return NC_ERR_MISSING_ATTR;
    } else if (!strcmp(str, "bad-attribute")) {
        return NC_ERR_BAD_ATTR;
    } else if (!strcmp(str, "unknown-attribute")) {
        return NC_ERR_UNKNOWN_ATTR;
    } else if (!strcmp(str, "missing-element")) {
        return NC_ERR_MISSING_ELEM;
    } else if (!strcmp(str, "bad-element")) {
        return NC_ERR_BAD_ELEM;
    } else if (!strcmp(str, "unknown-element")) {
        return NC_ERR_UNKNOWN_ELEM;
    } else if (!strcmp(str, "unknown-namespace")) {
        return NC_ERR_UNKNOWN_NS;
    } else if (!strcmp(str, "lock-denied")) {
        return NC_ERR_LOCK_DENIED;
    } else if (!strcmp(str, "data-exists")) {
        return NC_ERR_DATA_EXISTS;
    } else if (!strcmp(str, "data-missing")) {
        return NC_ERR_DATA_MISSING;
    } else if (!strcmp(str, "operation-failed")) {
        return NC_ERR_OP_FAILED;
    } else if (!strcmp(str, "malformed-message")) {
        return NC_ERR_MALFORMED_MSG;
    }

    return 0;
}

static const char *
nc_err_type2str(NC_ERR_TYPE type)
{
    switch (type) {
    case NC_ERR_TYPE_TRAN:
        return "transport";
    case NC_ERR_TYPE_RPC:
        return "rpc";
    case NC_ERR_TYPE_PROT:
        return "protocol";
    case NC_ERR_TYPE_APP:
        return "application";
    default:
        break;
    }

    return NULL;
}

static NC_ERR_TYPE
nc_err_str2type(const char *str)
{
    if (!strcmp(str, "transport")) {
        return NC_ERR_TYPE_TRAN;
    } else if (!strcmp(str, "rpc")) {
        return NC_ERR_TYPE_RPC;
    } else if (!strcmp(str, "protocol")) {
        return NC_ERR_TYPE_PROT;
    } else if (!strcmp(str, "application")) {
        return NC_ERR_TYPE_APP;
    }

    return 0;
}

API struct lyd_node *
nc_err(const struct ly_ctx *ctx, NC_ERR tag, ...)
{
    va_list ap;
    struct lyd_node *err = NULL;
    NC_ERR_TYPE type;
    const char *arg1, *arg2;
    uint32_t sid;

    NC_CHECK_ARG_RET(NULL, tag, NULL);

    /* rpc-error */
    if (lyd_new_opaq2(NULL, ctx, "rpc-error", NULL, NULL, NC_NS_BASE, &err)) {
        return NULL;
    }

    va_start(ap, tag);

    /* error-type */
    switch (tag) {
    case NC_ERR_IN_USE:
    case NC_ERR_INVALID_VALUE:
    case NC_ERR_ACCESS_DENIED:
    case NC_ERR_ROLLBACK_FAILED:
    case NC_ERR_OP_NOT_SUPPORTED:
        type = (NC_ERR_TYPE)va_arg(ap, int); /* NC_ERR_TYPE enum is automatically promoted to int */
        if ((type != NC_ERR_TYPE_PROT) && (type != NC_ERR_TYPE_APP)) {
            ERRARG(NULL, "type");
            goto fail;
        }
        break;
    case NC_ERR_TOO_BIG:
    case NC_ERR_RES_DENIED:
        type = (NC_ERR_TYPE)va_arg(ap, int);
        break;
    case NC_ERR_MISSING_ATTR:
    case NC_ERR_BAD_ATTR:
    case NC_ERR_UNKNOWN_ATTR:
        type = (NC_ERR_TYPE)va_arg(ap, int);
        if (type == NC_ERR_TYPE_TRAN) {
            ERRARG(NULL, "type");
            goto fail;
        }
        break;
    case NC_ERR_MISSING_ELEM:
    case NC_ERR_BAD_ELEM:
    case NC_ERR_UNKNOWN_ELEM:
        type = (NC_ERR_TYPE)va_arg(ap, int);
        if ((type != NC_ERR_TYPE_PROT) && (type != NC_ERR_TYPE_APP)) {
            ERRARG(NULL, "type");
            goto fail;
        }
        break;
    case NC_ERR_UNKNOWN_NS:
        type = (NC_ERR_TYPE)va_arg(ap, int);
        if ((type != NC_ERR_TYPE_PROT) && (type != NC_ERR_TYPE_APP)) {
            ERRARG(NULL, "type");
            goto fail;
        }
        break;
    case NC_ERR_LOCK_DENIED:
        type = NC_ERR_TYPE_PROT;
        break;
    case NC_ERR_DATA_EXISTS:
    case NC_ERR_DATA_MISSING:
        type = NC_ERR_TYPE_APP;
        break;
    case NC_ERR_OP_FAILED:
        type = (NC_ERR_TYPE)va_arg(ap, int);
        if (type == NC_ERR_TYPE_TRAN) {
            ERRARG(NULL, "type");
            goto fail;
        }
        break;
    case NC_ERR_MALFORMED_MSG:
        type = NC_ERR_TYPE_RPC;
        break;
    default:
        ERRARG(NULL, "tag");
        goto fail;
    }
    if (lyd_new_opaq2(err, NULL, "error-type", nc_err_type2str(type), NULL, NC_NS_BASE, NULL)) {
        goto fail;
    }

    /* error-tag */
    if (lyd_new_opaq2(err, NULL, "error-tag", nc_err_tag2str(tag), NULL, NC_NS_BASE, NULL)) {
        goto fail;
    }

    /* error-severity */
    if (lyd_new_opaq2(err, NULL, "error-severity", "error", NULL, NC_NS_BASE, NULL)) {
        goto fail;
    }

    /* error-message */
    switch (tag) {
    case NC_ERR_IN_USE:
        nc_err_set_msg(err, "The request requires a resource that already is in use.", "en");
        break;
    case NC_ERR_INVALID_VALUE:
        nc_err_set_msg(err, "The request specifies an unacceptable value for one or more parameters.", "en");
        break;
    case NC_ERR_TOO_BIG:
        nc_err_set_msg(err, "The request or response (that would be generated) is too large for the implementation to handle.", "en");
        break;
    case NC_ERR_MISSING_ATTR:
        nc_err_set_msg(err, "An expected attribute is missing.", "en");
        break;
    case NC_ERR_BAD_ATTR:
        nc_err_set_msg(err, "An attribute value is not correct.", "en");
        break;
    case NC_ERR_UNKNOWN_ATTR:
        nc_err_set_msg(err, "An unexpected attribute is present.", "en");
        break;
    case NC_ERR_MISSING_ELEM:
        nc_err_set_msg(err, "An expected element is missing.", "en");
        break;
    case NC_ERR_BAD_ELEM:
        nc_err_set_msg(err, "An element value is not correct.", "en");
        break;
    case NC_ERR_UNKNOWN_ELEM:
        nc_err_set_msg(err, "An unexpected element is present.", "en");
        break;
    case NC_ERR_UNKNOWN_NS:
        nc_err_set_msg(err, "An unexpected namespace is present.", "en");
        break;
    case NC_ERR_ACCESS_DENIED:
        nc_err_set_msg(err, "Access to the requested protocol operation or data model is denied because authorization failed.", "en");
        break;
    case NC_ERR_LOCK_DENIED:
        nc_err_set_msg(err, "Access to the requested lock is denied because the lock is currently held by another entity.", "en");
        break;
    case NC_ERR_RES_DENIED:
        nc_err_set_msg(err, "Request could not be completed because of insufficient resources.", "en");
        break;
    case NC_ERR_ROLLBACK_FAILED:
        nc_err_set_msg(err, "Request to roll back some configuration change was not completed for some reason.", "en");
        break;
    case NC_ERR_DATA_EXISTS:
        nc_err_set_msg(err, "Request could not be completed because the relevant data model content already exists.", "en");
        break;
    case NC_ERR_DATA_MISSING:
        nc_err_set_msg(err, "Request could not be completed because the relevant data model content does not exist.", "en");
        break;
    case NC_ERR_OP_NOT_SUPPORTED:
        nc_err_set_msg(err, "Request could not be completed because the requested operation is not supported by this implementation.", "en");
        break;
    case NC_ERR_OP_FAILED:
        nc_err_set_msg(err, "Request could not be completed because the requested operation failed for a non-specific reason.", "en");
        break;
    case NC_ERR_MALFORMED_MSG:
        nc_err_set_msg(err, "A message could not be handled because it failed to be parsed correctly.", "en");
        break;
    default:
        ERRARG(NULL, "tag");
        goto fail;
    }

    /* error-info */
    switch (tag) {
    case NC_ERR_IN_USE:
    case NC_ERR_INVALID_VALUE:
    case NC_ERR_ACCESS_DENIED:
    case NC_ERR_ROLLBACK_FAILED:
    case NC_ERR_OP_NOT_SUPPORTED:
    case NC_ERR_TOO_BIG:
    case NC_ERR_RES_DENIED:
    case NC_ERR_DATA_EXISTS:
    case NC_ERR_DATA_MISSING:
    case NC_ERR_OP_FAILED:
    case NC_ERR_MALFORMED_MSG:
        break;
    case NC_ERR_MISSING_ATTR:
    case NC_ERR_BAD_ATTR:
    case NC_ERR_UNKNOWN_ATTR:
        arg1 = va_arg(ap, const char *);
        arg2 = va_arg(ap, const char *);

        nc_err_add_bad_attr(err, arg1);
        nc_err_add_bad_elem(err, arg2);
        break;
    case NC_ERR_MISSING_ELEM:
    case NC_ERR_BAD_ELEM:
    case NC_ERR_UNKNOWN_ELEM:
        arg1 = va_arg(ap, const char *);

        nc_err_add_bad_elem(err, arg1);
        break;
    case NC_ERR_UNKNOWN_NS:
        arg1 = va_arg(ap, const char *);
        arg2 = va_arg(ap, const char *);

        nc_err_add_bad_elem(err, arg1);
        nc_err_add_bad_ns(err, arg2);
        break;
    case NC_ERR_LOCK_DENIED:
        sid = va_arg(ap, uint32_t);

        nc_err_set_sid(err, sid);
        break;
    default:
        ERRARG(NULL, "tag");
        goto fail;
    }

    va_end(ap);
    return err;

fail:
    va_end(ap);
    lyd_free_siblings(err);
    return NULL;
}

API NC_ERR_TYPE
nc_err_get_type(const struct lyd_node *err)
{
    struct lyd_node *match;

    NC_CHECK_ARG_RET(NULL, err, 0);

    lyd_find_sibling_opaq_next(lyd_child(err), "error-type", &match);
    if (match) {
        return nc_err_str2type(((struct lyd_node_opaq *)match)->value);
    }

    return 0;
}

API NC_ERR
nc_err_get_tag(const struct lyd_node *err)
{
    struct lyd_node *match;

    NC_CHECK_ARG_RET(NULL, err, 0);

    lyd_find_sibling_opaq_next(lyd_child(err), "error-tag", &match);
    if (match) {
        return nc_err_str2tag(((struct lyd_node_opaq *)match)->value);
    }

    return 0;
}

API int
nc_err_set_app_tag(struct lyd_node *err, const char *error_app_tag)
{
    struct lyd_node *match;

    NC_CHECK_ARG_RET(NULL, err, error_app_tag, -1);

    /* remove previous node */
    lyd_find_sibling_opaq_next(lyd_child(err), "error-app-tag", &match);
    if (match) {
        lyd_free_tree(match);
    }

    if (lyd_new_opaq2(err, NULL, "error-app-tag", error_app_tag, NULL, NC_NS_BASE, NULL)) {
        return -1;
    }

    return 0;
}

API const char *
nc_err_get_app_tag(const struct lyd_node *err)
{
    struct lyd_node *match;

    NC_CHECK_ARG_RET(NULL, err, NULL);

    lyd_find_sibling_opaq_next(lyd_child(err), "error-app-tag", &match);
    if (match) {
        return ((struct lyd_node_opaq *)match)->value;
    }

    return NULL;
}

API int
nc_err_set_path(struct lyd_node *err, const char *error_path)
{
    struct lyd_node *match;

    NC_CHECK_ARG_RET(NULL, err, error_path, -1);

    /* remove previous node */
    lyd_find_sibling_opaq_next(lyd_child(err), "error-path", &match);
    if (match) {
        lyd_free_tree(match);
    }

    if (lyd_new_opaq2(err, NULL, "error-path", error_path, NULL, NC_NS_BASE, NULL)) {
        return -1;
    }

    return 0;
}

API const char *
nc_err_get_path(const struct lyd_node *err)
{
    struct lyd_node *match;

    NC_CHECK_ARG_RET(NULL, err, NULL);

    lyd_find_sibling_opaq_next(lyd_child(err), "error-path", &match);
    if (match) {
        return ((struct lyd_node_opaq *)match)->value;
    }

    return NULL;
}

API int
nc_err_set_msg(struct lyd_node *err, const char *error_message, const char *lang)
{
    struct lyd_node *match;
    struct lyd_attr *attr;

    NC_CHECK_ARG_RET(NULL, err, error_message, -1);

    lyd_find_sibling_opaq_next(lyd_child(err), "error-message", &match);
    if (match) {
        /* Change the value of error-message and keep order of elements to comply with appendix-B in RFC 6241. */
        lydict_remove(LYD_CTX(err), ((struct lyd_node_opaq *)match)->value);
        lydict_insert(LYD_CTX(err), error_message, 0, &(((struct lyd_node_opaq *)match)->value));
        return 0;
    }
    if (lyd_new_opaq2(err, NULL, "error-message", error_message, NULL, NC_NS_BASE, &match)) {
        return -1;
    }
    if (lang && lyd_new_attr(match, NULL, "xml:lang", lang, &attr)) {
        lyd_free_tree(match);
        return -1;
    }

    return 0;
}

API const char *
nc_err_get_msg(const struct lyd_node *err)
{
    struct lyd_node *match;

    NC_CHECK_ARG_RET(NULL, err, NULL);

    lyd_find_sibling_opaq_next(lyd_child(err), "error-message", &match);
    if (match) {
        return ((struct lyd_node_opaq *)match)->value;
    }

    return NULL;
}

API int
nc_err_set_sid(struct lyd_node *err, uint32_t session_id)
{
    struct lyd_node *match, *info;
    char buf[22];

    NC_CHECK_ARG_RET(NULL, err, -1);

    /* find error-info */
    lyd_find_sibling_opaq_next(lyd_child(err), "error-info", &info);
    if (!info && lyd_new_opaq2(err, NULL, "error-info", NULL, NULL, NC_NS_BASE, &info)) {
        return -1;
    }

    /* remove previous node */
    lyd_find_sibling_opaq_next(lyd_child(info), "session-id", &match);
    if (match) {
        lyd_free_tree(match);
    }

    sprintf(buf, "%" PRIu32, session_id);
    if (lyd_new_opaq2(info, NULL, "session-id", buf, NULL, NC_NS_BASE, NULL)) {
        return -1;
    }

    return 0;
}

API int
nc_err_add_bad_attr(struct lyd_node *err, const char *attr_name)
{
    struct lyd_node *info;

    NC_CHECK_ARG_RET(NULL, err, attr_name, -1);

    /* find error-info */
    lyd_find_sibling_opaq_next(lyd_child(err), "error-info", &info);
    if (!info && lyd_new_opaq2(err, NULL, "error-info", NULL, NULL, NC_NS_BASE, &info)) {
        return -1;
    }

    if (lyd_new_opaq2(info, NULL, "bad-attribute", attr_name, NULL, NC_NS_BASE, NULL)) {
        return -1;
    }

    return 0;
}

API int
nc_err_add_bad_elem(struct lyd_node *err, const char *elem_name)
{
    struct lyd_node *info;

    NC_CHECK_ARG_RET(NULL, err, elem_name, -1);

    /* find error-info */
    lyd_find_sibling_opaq_next(lyd_child(err), "error-info", &info);
    if (!info && lyd_new_opaq2(err, NULL, "error-info", NULL, NULL, NC_NS_BASE, &info)) {
        return -1;
    }

    if (lyd_new_opaq2(info, NULL, "bad-element", elem_name, NULL, NC_NS_BASE, NULL)) {
        return -1;
    }

    return 0;
}

API int
nc_err_add_bad_ns(struct lyd_node *err, const char *ns_name)
{
    struct lyd_node *info;

    NC_CHECK_ARG_RET(NULL, err, ns_name, -1);

    /* find error-info */
    lyd_find_sibling_opaq_next(lyd_child(err), "error-info", &info);
    if (!info && lyd_new_opaq2(err, NULL, "error-info", NULL, NULL, NC_NS_BASE, &info)) {
        return -1;
    }

    if (lyd_new_opaq2(info, NULL, "bad-namespace", ns_name, NULL, NC_NS_BASE, NULL)) {
        return -1;
    }

    return 0;
}

API int
nc_err_add_info_other(struct lyd_node *err, struct lyd_node *other)
{
    struct lyd_node *info;

    NC_CHECK_ARG_RET(NULL, err, other, -1);

    /* find error-info */
    lyd_find_sibling_opaq_next(lyd_child(err), "error-info", &info);
    if (!info && lyd_new_opaq2(err, NULL, "error-info", NULL, NULL, NC_NS_BASE, &info)) {
        return -1;
    }

    lyd_insert_child(info, other);

    return 0;
}

void
nc_server_rpc_free(struct nc_server_rpc *rpc)
{
    if (!rpc) {
        return;
    }

    lyd_free_tree(rpc->envp);

    /* may be action */
    lyd_free_all(rpc->rpc);

    free(rpc);
}

API void
nc_server_reply_free(struct nc_server_reply *reply)
{
    struct nc_server_reply_data *data_rpl;
    struct nc_server_reply_error *error_rpl;

    if (!reply) {
        return;
    }

    switch (reply->type) {
    case NC_RPL_DATA:
        data_rpl = (struct nc_server_reply_data *)reply;
        if (data_rpl->free) {
            lyd_free_siblings(data_rpl->data);
        }
        break;
    case NC_RPL_OK:
        /* nothing to free */
        break;
    case NC_RPL_ERROR:
        error_rpl = (struct nc_server_reply_error *)reply;
        lyd_free_siblings(error_rpl->err);
        break;
    default:
        break;
    }
    free(reply);
}

API struct nc_server_notif *
nc_server_notif_new(struct lyd_node *event, char *eventtime, NC_PARAMTYPE paramtype)
{
    struct nc_server_notif *ntf;
    struct lyd_node *elem;
    int found;

    NC_CHECK_ARG_RET(NULL, event, eventtime, NULL);

    /* check that there is a notification */
    found = 0;
    LYD_TREE_DFS_BEGIN(event, elem) {
        if (elem->schema->nodetype == LYS_NOTIF) {
            found = 1;
            break;
        }
        LYD_TREE_DFS_END(event, elem);
    }
    if (!found) {
        ERRARG(NULL, "event");
        return NULL;
    }

    ntf = malloc(sizeof *ntf);
    NC_CHECK_ERRMEM_RET(!ntf, NULL);

    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        ntf->eventtime = strdup(eventtime);
        if (lyd_dup_single(event, NULL, LYD_DUP_RECURSIVE, &ntf->ntf)) {
            free(ntf);
            return NULL;
        }
    } else {
        ntf->eventtime = eventtime;
        ntf->ntf = event;
    }
    ntf->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return ntf;
}

API void
nc_server_notif_free(struct nc_server_notif *notif)
{
    if (!notif) {
        return;
    }

    if (notif->free) {
        lyd_free_tree(notif->ntf);
        free(notif->eventtime);
    }
    free(notif);
}

API const char *
nc_server_notif_get_time(const struct nc_server_notif *notif)
{
    NC_CHECK_ARG_RET(NULL, notif, NULL);

    return notif->eventtime;
}
