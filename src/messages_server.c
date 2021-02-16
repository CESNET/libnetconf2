/**
 * \file messages_server.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 - server NETCONF messages functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "libnetconf.h"
#include "session_server.h"

extern struct nc_server_opts server_opts;

API struct nc_server_reply *
nc_server_reply_ok(void)
{
    struct nc_server_reply *ret;

    ret = malloc(sizeof *ret);
    if (!ret) {
        ERRMEM;
        return NULL;
    }

    ret->type = NC_RPL_OK;
    return ret;
}

API struct nc_server_reply *
nc_server_reply_data(struct lyd_node *data, NC_WD_MODE wd, NC_PARAMTYPE paramtype)
{
    struct nc_server_reply_data *ret;

    if (!data) {
        ERRARG("data");
        return NULL;
    }

    ret = malloc(sizeof *ret);
    if (!ret) {
        ERRMEM;
        return NULL;
    }

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

    if (!err) {
        ERRARG("err");
        return NULL;
    }

    ret = malloc(sizeof *ret);
    if (!ret) {
        ERRMEM;
        return NULL;
    }

    ret->type = NC_RPL_ERROR;
    ret->err = err;
    return (struct nc_server_reply *)ret;
}

API int
nc_server_reply_add_err(struct nc_server_reply *reply, struct lyd_node *err)
{
    struct nc_server_reply_error *err_rpl;

    if (!reply || (reply->type != NC_RPL_ERROR)) {
        ERRARG("reply");
        return -1;
    } else if (!err) {
        ERRARG("err");
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

    if (!reply || (reply->type != NC_RPL_ERROR)) {
        ERRARG("reply");
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

    if (!tag) {
        ERRARG("tag");
        return NULL;
    }

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
            ERRARG("type");
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
            ERRARG("type");
            goto fail;
        }
        break;
    case NC_ERR_MISSING_ELEM:
    case NC_ERR_BAD_ELEM:
    case NC_ERR_UNKNOWN_ELEM:
        type = (NC_ERR_TYPE)va_arg(ap, int);
        if ((type != NC_ERR_TYPE_PROT) && (type != NC_ERR_TYPE_APP)) {
            ERRARG("type");
            goto fail;
        }
        break;
    case NC_ERR_UNKNOWN_NS:
        type = (NC_ERR_TYPE)va_arg(ap, int);
        if ((type != NC_ERR_TYPE_PROT) && (type != NC_ERR_TYPE_APP)) {
            ERRARG("type");
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
            ERRARG("type");
            goto fail;
        }
        break;
    case NC_ERR_MALFORMED_MSG:
        type = NC_ERR_TYPE_RPC;
        break;
    default:
        ERRARG("tag");
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
        ERRARG("tag");
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
        ERRARG("tag");
        goto fail;
    }

    va_end(ap);
    return err;

fail:
    va_end(ap);
    lyd_free_siblings(err);
    return NULL;
}

API struct lyd_node *
nc_err_libyang(struct ly_ctx *ctx)
{
    struct lyd_node *e, *other;
    const char *str, *stri, *strj, *strk, *strl, *uniqi, *uniqj;
    char *attr, *path;
    int len;

    if (!ly_errcode(ctx)) {
        /* LY_SUCCESS */
        return NULL;
    } else if ((ly_errcode(ctx) == LY_EVALID) && (ly_vecode(ctx) == LYVE_DATA)) {
        /* RFC 7950 section 15 errors */
        if (!strncmp(ly_errmsg(ctx), "Unique data", 11)) {
            e = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_app_tag(e, "data-not-unique");
            nc_err_set_path(e, ly_errpath(ctx));

            /* parse the message and get all the information we need */
            str = ly_errmsg(ctx);
            uniqi = strchr(str, '"');
            uniqi++;
            uniqj = strchr(uniqi, '"');

            stri = strchr(uniqj + 1, '"');
            stri++;
            strj = strchr(stri, '"');

            strk = strchr(strj + 1, '"');
            ++strk;
            strl = strchr(strk, '"');

            /* maximum length is the whole unique string with the longer list instance identifier */
            len = (uniqj - uniqi) + (strj - stri > strl - strk ? strj - stri : strl - strk);
            path = malloc(len + 1);
            if (!path) {
                ERRMEM;
                return e;
            }

            /* create non-unique elements, one in 1st list, one in 2nd list, for each unique list */
            while (1) {
                uniqj = strpbrk(uniqi, " \"");

                sprintf(path, "%.*s/%.*s", (int)(strj - stri), stri, (int)(uniqj - uniqi), uniqi);
                if (lyd_new_opaq2(NULL, ctx, "non-unique", path, NULL, "urn:ietf:params:xml:ns:yang:1", &other)) {
                    free(path);
                    return e;
                }
                nc_err_add_info_other(e, other);

                sprintf(path, "%.*s/%.*s", (int)(strl - strk), strk, (int)(uniqj - uniqi), uniqi);
                if (lyd_new_opaq2(NULL, ctx, "non-unique", path, NULL, "urn:ietf:params:xml:ns:yang:1", &other)) {
                    free(path);
                    return e;
                }
                nc_err_add_info_other(e, other);

                if (uniqj[0] == '"') {
                    break;
                }
                uniqi = uniqj + 1;
            }
            free(path);
        } else if (!strncmp(ly_errmsg(ctx), "Too many", 8)) {
            e = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_app_tag(e, "too-many-elements");
            nc_err_set_path(e, ly_errpath(ctx));
        } else if (!strncmp(ly_errmsg(ctx), "Too few", 7)) {
            e = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_app_tag(e, "too-few-elements");
            nc_err_set_path(e, ly_errpath(ctx));
        } else if (!strncmp(ly_errmsg(ctx), "Must condition", 14)) {
            e = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            if (ly_errapptag(ctx)) {
                nc_err_set_app_tag(e, ly_errapptag(ctx));
            } else {
                nc_err_set_app_tag(e, "must-violation");
            }
            nc_err_set_path(e, ly_errpath(ctx));
        } else if (!strncmp(ly_errmsg(ctx), "Invalid leafref", 15) ||
                !strncmp(ly_errmsg(ctx), "Invalid instance-identifier", 27)) {
            e = nc_err(ctx, NC_ERR_DATA_MISSING);
            nc_err_set_app_tag(e, "instance-required");
            nc_err_set_path(e, ly_errpath(ctx));
        } else if (!strncmp(ly_errmsg(ctx), "Mandatory choice", 16)) {
            e = nc_err(ctx, NC_ERR_DATA_MISSING);
            nc_err_set_app_tag(e, "missing-choice");
            nc_err_set_path(e, ly_errpath(ctx));

            str = ly_errmsg(ctx);
            stri = strchr(str, '"');
            stri++;
            strj = strchr(stri, '"');
            path = strndup(stri, strj - stri);

            if (lyd_new_opaq2(NULL, ctx, "missing-choice", path, NULL, "urn:ietf:params:xml:ns:yang:1", &other)) {
                free(path);
                return e;
            }
            nc_err_add_info_other(e, other);
            free(path);
        } else if (!strncmp(ly_errmsg(ctx), "Unexpected data", 15)) {
            str = ly_errpath(ctx);
            if (!str || !strcmp(str, "/")) {
                e = nc_err(ctx, NC_ERR_OP_NOT_SUPPORTED, NC_ERR_TYPE_APP);
                /* keep default message */
                return e;
            } else {
                e = nc_err(ctx, NC_ERR_UNKNOWN_ELEM, NC_ERR_TYPE_PROT, ly_errpath(ctx));
            }
        } else if (!strncmp(ly_errmsg(ctx), "Mandatory node", 14)) {
            e = nc_err(ctx, NC_ERR_MISSING_ELEM, NC_ERR_TYPE_PROT, ly_errpath(ctx));
        } else if (!strncmp(ly_errmsg(ctx), "Duplicate instance", 18) || !strncmp(ly_errmsg(ctx), "Data for both cases", 19)) {
            e = nc_err(ctx, NC_ERR_BAD_ELEM, NC_ERR_TYPE_PROT, ly_errpath(ctx));
        /*case LYVE_INATTR:
        case LYVE_MISSATTR:
        case LYVE_INMETA:
            str = ly_errmsg(ctx);
            stri = strchr(str, '"');
            stri++;
            if (!strncmp(stri, "<none>:", 7)) {
                stri += 7;
            }
            strj = strchr(stri, '"');
            strj--;
            attr = strndup(stri, (strj - stri) + 1);
            if (ly_vecode(ctx) == LYVE_INATTR) {
                e = nc_err(ctx, NC_ERR_UNKNOWN_ATTR, NC_ERR_TYPE_PROT, attr, ly_errpath(ctx));
            } else if (ly_vecode(ctx) == LYVE_MISSATTR) {
                e = nc_err(ctx, NC_ERR_MISSING_ATTR, NC_ERR_TYPE_PROT, attr, ly_errpath(ctx));
            } else { * LYVE_INMETA *
                e = nc_err(ctx, NC_ERR_BAD_ATTR, NC_ERR_TYPE_PROT, attr, ly_errpath(ctx));
            }
            free(attr);
            break;*/
        } else if (!strncmp(ly_errmsg(ctx), "When condition", 14) || !strncmp(ly_errmsg(ctx), "Unsatisfied pattern", 19) ||
                !strncmp(ly_errmsg(ctx), "Unsatisfied length", 18) || !strncmp(ly_errmsg(ctx), "Unsatisfied range", 17)) {
            e = nc_err(ctx, NC_ERR_INVALID_VALUE, NC_ERR_TYPE_PROT);
            /* length, range, pattern can have a specific error-app-tag */
            if (ly_errapptag(ctx)) {
                nc_err_set_app_tag(e, ly_errapptag(ctx));
            }
            nc_err_set_path(e, ly_errpath(ctx));
        } else {
            e = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        }
    } else {
        /* non-validation (internal) error */
        e = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
    }
    nc_err_set_msg(e, ly_errmsg(ctx), "en");
    return e;
}

API NC_ERR_TYPE
nc_err_get_type(const struct lyd_node *err)
{
    struct lyd_node *match;

    if (!err) {
        ERRARG("err");
        return 0;
    }

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

    if (!err) {
        ERRARG("err");
        return 0;
    }

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

    if (!err) {
        ERRARG("err");
        return -1;
    } else if (!error_app_tag) {
        ERRARG("error_app_tag");
        return -1;
    }

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

    if (!err) {
        ERRARG("err");
        return NULL;
    }

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

    if (!err) {
        ERRARG("err");
        return -1;
    } else if (!error_path) {
        ERRARG("error_path");
        return -1;
    }

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

    if (!err) {
        ERRARG("err");
        return 0;
    }

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

    if (!err) {
        ERRARG("err");
        return -1;
    } else if (!error_message) {
        ERRARG("error_message");
        return -1;
    }

    /* remove previous message */
    lyd_find_sibling_opaq_next(lyd_child(err), "error-message", &match);
    if (match) {
        lyd_free_tree(match);
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

    if (!err) {
        ERRARG("err");
        return NULL;
    }

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

    if (!err) {
        ERRARG("err");
        return -1;
    }

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

    if (!err) {
        ERRARG("err");
        return -1;
    } else if (!attr_name) {
        ERRARG("attr_name");
        return -1;
    }

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

    if (!err) {
        ERRARG("err");
        return -1;
    } else if (!elem_name) {
        ERRARG("elem_name");
        return -1;
    }

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

    if (!err) {
        ERRARG("err");
        return -1;
    } else if (!ns_name) {
        ERRARG("ns_name");
        return -1;
    }

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

    if (!err) {
        ERRARG("err");
        return -1;
    } else if (!other) {
        ERRARG("other");
        return -1;
    }

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
    lyd_free_tree(rpc->rpc);

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

    if (!event) {
        ERRARG("event");
        return NULL;
    } else if (!eventtime) {
        ERRARG("eventtime");
        return NULL;
    }

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
        ERRARG("event");
        return NULL;
    }

    ntf = malloc(sizeof *ntf);
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
    if (!notif) {
        ERRARG("notif");
        return NULL;
    }

    return notif->eventtime;
}
