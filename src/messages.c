/**
 * \file messages.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 - NETCONF messages functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <libyang/libyang.h>

#include "libnetconf.h"
#include "messages_p.h"

const char *rpcedit_dfltop2str[] = {NULL, "merge", "replace", "none"};
const char *rpcedit_testopt2str[] = {NULL, "test-then-set", "set", "test-only"};
const char *rpcedit_erropt2str[] = {NULL, "stop-on-error", "continue-on-error", "rollback-on-error"};

API NC_RPC_TYPE
nc_rpc_get_type(const struct nc_rpc *rpc)
{
    return rpc->type;
}

API struct nc_rpc *
nc_rpc_generic(const struct lyd_node *data, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_generic *rpc;

    if (data->next || (data->prev != data)) {
        ERR("Generic RPC must have a single root node.");
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_GENERIC;
    rpc->has_data = 1;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->content.data = lyd_dup(data, 1);
    } else {
        rpc->content.data = (struct lyd_node *)data;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_generic_xml(const char *xml_str, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_generic *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_GENERIC;
    rpc->has_data = 0;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->content.xml_str = strdup(xml_str);
    } else {
        rpc->content.xml_str = (char *)xml_str;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_getconfig(NC_DATASTORE source, const char *filter, NC_WD_MODE wd_mode, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_getconfig *rpc;

    if (filter && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR("Filter must either be an XML subtree or an XPath expression.");
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_GETCONFIG;
    rpc->source = source;
    if (filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->filter = strdup(filter);
    } else {
        rpc->filter = (char *)filter;
    }
    rpc->wd_mode = wd_mode;
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_edit(NC_DATASTORE target, NC_RPC_EDIT_DFLTOP default_op, NC_RPC_EDIT_TESTOPT test_opt,
            NC_RPC_EDIT_ERROPT error_opt, const char *edit_content, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_edit *rpc;

    if ((edit_content[0] != '<') && !isalpha(edit_content[0])) {
        ERR("<edit-config> content must either be a URL or a config (XML).");
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_EDIT;
    rpc->target = target;
    rpc->default_op = default_op;
    rpc->test_opt = test_opt;
    rpc->error_opt = error_opt;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->edit_cont = strdup(edit_content);
    } else {
        rpc->edit_cont = (char *)edit_content;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_copy(NC_DATASTORE target, const char *url_trg, NC_DATASTORE source, const char *url_or_config_src,
            NC_WD_MODE wd_mode, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_copy *rpc;

    if (url_or_config_src && (url_or_config_src[0] != '<') && !isalpha(url_or_config_src[0])) {
        ERR("<copy-config> source is neither a URL nor a config (XML).");
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_COPY;
    rpc->target = target;
    if (url_trg && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->url_trg = strdup(url_trg);
    } else {
        rpc->url_trg = (char *)url_trg;
    }
    rpc->source = source;
    if (url_or_config_src && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->url_config_src = strdup(url_or_config_src);
    } else {
        rpc->url_config_src = (char *)url_or_config_src;
    }
    rpc->wd_mode = wd_mode;
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_delete(NC_DATASTORE target, const char *url, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_delete *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_DELETE;
    rpc->target = target;
    if (url && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->url = strdup(url);
    } else {
        rpc->url = (char *)url;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_lock(NC_DATASTORE target)
{
    struct nc_rpc_lock *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_LOCK;
    rpc->target = target;

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_unlock(NC_DATASTORE target)
{
    struct nc_rpc_lock *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_UNLOCK;
    rpc->target = target;

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_get(const char *filter, NC_WD_MODE wd_mode, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_get *rpc;

    if (filter && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR("Filter must either be an XML subtree or an XPath expression.");
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_GET;
    if (filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->filter = strdup(filter);
    } else {
        rpc->filter = (char *)filter;
    }
    rpc->wd_mode = wd_mode;
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_kill(uint32_t session_id)
{
    struct nc_rpc_kill *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_KILL;
    rpc->sid = session_id;

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_commit(int confirmed, uint32_t confirm_timeout, const char *persist, const char *persist_id,
              NC_PARAMTYPE paramtype)
{
    struct nc_rpc_commit *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_COMMIT;
    rpc->confirmed = confirmed;
    rpc->confirm_timeout = confirm_timeout;
    if (persist && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->persist = strdup(persist);
    } else {
        rpc->persist = (char *)persist;
    }
    if (persist_id && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->persist_id = strdup(persist_id);
    } else {
        rpc->persist_id = (char *)persist_id;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_discard(void)
{
    struct nc_rpc *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_DISCARD;

    return rpc;
}

API struct nc_rpc *
nc_rpc_cancel(const char *persist_id, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_cancel *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_CANCEL;
    if (persist_id && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->persist_id = strdup(persist_id);
    } else {
        rpc->persist_id = (char *)persist_id;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_validate(NC_DATASTORE source, const char *url_or_config, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_validate *rpc;

    if (url_or_config && (url_or_config[0] != '<') && !isalpha(url_or_config[0])) {
        ERR("<validate> source is neither a URL nor a config (XML).");
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_VALIDATE;
    rpc->source = source;
    if (url_or_config && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->url_config_src = strdup(url_or_config);
    } else {
        rpc->url_config_src = (char *)url_or_config;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_getschema(const char *identifier, const char *version, const char *format, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_getschema *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_GETSCHEMA;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->identifier = strdup(identifier);
    } else {
        rpc->identifier = (char *)identifier;
    }
    if (version && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->version = strdup(version);
    } else {
        rpc->version = (char *)version;
    }
    if (format && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->format = strdup(format);
    } else {
        rpc->format = (char *)format;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_subscribe(const char *stream_name, const char *filter, const char *start_time, const char *stop_time,
                 NC_PARAMTYPE paramtype)
{
    struct nc_rpc_subscribe *rpc;

    if (filter && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR("Filter must either be an XML subtree or an XPath expression.");
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_SUBSCRIBE;
    if (stream_name && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->stream = strdup(stream_name);
    } else {
        rpc->stream = (char *)stream_name;
    }
    if (filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->filter = strdup(filter);
    } else {
        rpc->filter = (char *)filter;
    }
    if (start_time && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->start = strdup(start_time);
    } else {
        rpc->start = (char *)start_time;
    }
    if (stop_time && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->stop = strdup(stop_time);
    } else {
        rpc->stop = (char *)stop_time;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

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
nc_server_reply_data(struct lyd_node *data, NC_PARAMTYPE paramtype)
{
    struct nc_server_reply_data *ret;

    if (!data) {
        ERRARG;
        return NULL;
    }

    ret = malloc(sizeof *ret);
    if (!ret) {
        ERRMEM;
        return NULL;
    }

    ret->type = NC_RPL_DATA;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        ret->data = lyd_dup(data, 1);
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
nc_server_reply_err(struct ly_ctx *ctx, struct nc_server_error *err)
{
    struct nc_server_reply_error *ret;

    if (!ctx || !err) {
        ERRARG;
        return NULL;
    }

    ret = malloc(sizeof *ret);
    if (!ret) {
        ERRMEM;
        return NULL;
    }

    ret->type = NC_RPL_ERROR;
    ret->ctx = ctx;
    ret->err = malloc(sizeof *ret->err);
    ret->err[0] = err;
    ret->count = 1;
    return (struct nc_server_reply *)ret;
}

API int
nc_server_reply_add_err(struct nc_server_reply *reply, struct nc_server_error *err)
{
    struct nc_server_reply_error *err_rpl;

    if (!reply || (reply->type != NC_RPL_ERROR) || !err) {
        ERRARG;
        return -1;
    }

    err_rpl = (struct nc_server_reply_error *)reply;
    ++err_rpl->count;
    err_rpl->err = realloc(err_rpl->err, err_rpl->count * sizeof *err_rpl->err);
    err_rpl->err[err_rpl->count - 1] = err;
    return 0;
}

API struct nc_server_error *
nc_err(struct ly_ctx *ctx, NC_ERR tag, NC_ERR_TYPE type, ...)
{
    va_list ap;
    struct nc_server_error *ret;
    const char *arg1, *arg2;
    uint32_t sid;

    if (!ctx || !tag) {
        ERRARG;
        return NULL;
    }

    ret = calloc(1, sizeof *ret);
    if (!ret) {
        ERRMEM;
        return NULL;
    }

    va_start(ap, type);

    switch (tag) {
    case NC_ERR_IN_USE:
    case NC_ERR_INVALID_VALUE:
    case NC_ERR_ACCESS_DENIED:
    case NC_ERR_ROLLBACK_FAILED:
    case NC_ERR_OP_NOT_SUPPORTED:
        if ((type != NC_ERR_TYPE_PROT) && (type == NC_ERR_TYPE_APP)) {
            goto fail;
        }
        break;

    case NC_ERR_TOO_BIG:
    case NC_ERR_RES_DENIED:
        /* nothing to check */
        break;

    case NC_ERR_MISSING_ATTR:
    case NC_ERR_BAD_ATTR:
    case NC_ERR_UNKNOWN_ATTR:
        if (type == NC_ERR_TYPE_TRAN) {
            goto fail;
        }
        arg1 = va_arg(ap, const char *);
        arg2 = va_arg(ap, const char *);

        nc_err_add_bad_attr(ctx, ret, arg1);
        nc_err_add_bad_elem(ctx, ret, arg2);
        break;

    case NC_ERR_MISSING_ELEM:
    case NC_ERR_BAD_ELEM:
    case NC_ERR_UNKNOWN_ELEM:
        if ((type != NC_ERR_TYPE_PROT) && (type != NC_ERR_TYPE_APP)) {
            goto fail;
        }
        arg1 = va_arg(ap, const char *);
        nc_err_add_bad_elem(ctx, ret, arg1);
        break;

    case NC_ERR_UNKNOWN_NS:
        if ((type != NC_ERR_TYPE_PROT) && (type != NC_ERR_TYPE_APP)) {
            goto fail;
        }
        arg1 = va_arg(ap, const char *);
        arg2 = va_arg(ap, const char *);

        nc_err_add_bad_elem(ctx, ret, arg1);
        nc_err_add_bad_ns(ctx, ret, arg2);
        break;

    case NC_ERR_LOCK_DENIED:
        if (type != NC_ERR_TYPE_PROT) {
            goto fail;
        }
        sid = va_arg(ap, uint32_t);

        nc_err_set_sid(ret, sid);
        break;

    case NC_ERR_DATA_EXISTS:
    case NC_ERR_DATA_MISSING:
        if (type != NC_ERR_TYPE_APP) {
            goto fail;
        }
        break;

    case NC_ERR_OP_FAILED:
        if (type == NC_ERR_TYPE_TRAN) {
            goto fail;
        }
        break;

    case NC_ERR_MALFORMED_MSG:
        if (type != NC_ERR_TYPE_RPC) {
            goto fail;
        }
        break;
    default:
        goto fail;
    }

    switch (tag) {
    case NC_ERR_IN_USE:
        nc_err_set_msg(ctx, ret, "The request requires a resource that already is in use.", "en");
        break;
    case NC_ERR_INVALID_VALUE:
        nc_err_set_msg(ctx, ret, "The request specifies an unacceptable value for one or more parameters.", "en");
        break;
    case NC_ERR_TOO_BIG:
        nc_err_set_msg(ctx, ret, "The request or response (that would be generated) is too large for the implementation to handle.", "en");
        break;
    case NC_ERR_MISSING_ATTR:
        nc_err_set_msg(ctx, ret, "An expected attribute is missing.", "en");
        break;
    case NC_ERR_BAD_ATTR:
        nc_err_set_msg(ctx, ret, "An attribute value is not correct.", "en");
        break;
    case NC_ERR_UNKNOWN_ATTR:
        nc_err_set_msg(ctx, ret, "An unexpected attribute is present.", "en");
        break;
    case NC_ERR_MISSING_ELEM:
        nc_err_set_msg(ctx, ret, "An expected element is missing.", "en");
        break;
    case NC_ERR_BAD_ELEM:
        nc_err_set_msg(ctx, ret, "An element value is not correct.", "en");
        break;
    case NC_ERR_UNKNOWN_ELEM:
        nc_err_set_msg(ctx, ret, "An unexpected element is present.", "en");
        break;
    case NC_ERR_UNKNOWN_NS:
        nc_err_set_msg(ctx, ret, "An unexpected namespace is present.", "en");
        break;
    case NC_ERR_ACCESS_DENIED:
        nc_err_set_msg(ctx, ret, "Access to the requested protocol operation or data model is denied because authorization failed.", "en");
        break;
    case NC_ERR_LOCK_DENIED:
        nc_err_set_msg(ctx, ret, "Access to the requested lock is denied because the lock is currently held by another entity.", "en");
        break;
    case NC_ERR_RES_DENIED:
        nc_err_set_msg(ctx, ret, "Request could not be completed because of insufficient resources.", "en");
        break;
    case NC_ERR_ROLLBACK_FAILED:
        nc_err_set_msg(ctx, ret, "Request to roll back some configuration change was not completed for some reason.", "en");
        break;
    case NC_ERR_DATA_EXISTS:
        nc_err_set_msg(ctx, ret, "Request could not be completed because the relevant data model content already exists.", "en");
        break;
    case NC_ERR_DATA_MISSING:
        nc_err_set_msg(ctx, ret, "Request could not be completed because the relevant data model content does not exist.", "en");
        break;
    case NC_ERR_OP_NOT_SUPPORTED:
        nc_err_set_msg(ctx, ret, "Request could not be completed because the requested operation is not supported by this implementation.", "en");
        break;
    case NC_ERR_OP_FAILED:
        nc_err_set_msg(ctx, ret, "Request could not be completed because the requested operation failed for a non-specific reason.", "en");
        break;
    case NC_ERR_MALFORMED_MSG:
        nc_err_set_msg(ctx, ret, "A message could not be handled because it failed to be parsed correctly.", "en");
        break;
    default:
        goto fail;
    }

    va_end(ap);

    ret->type = type;
    ret->tag = tag;
    return ret;

fail:
    ERRARG;
    free(ret);
    return NULL;
}

API int
nc_err_set_app_tag(struct ly_ctx *ctx, struct nc_server_error *err, const char *error_app_tag)
{
    if (!ctx || !err || !error_app_tag) {
        ERRARG;
        return -1;
    }

    if (err->apptag) {
        lydict_remove(ctx, err->apptag);
    }
    err->apptag = lydict_insert(ctx, error_app_tag, 0);
    return 0;
}

API int
nc_err_set_path(struct ly_ctx *ctx, struct nc_server_error *err, const char *error_path)
{
    if (!ctx || !err || !error_path) {
        ERRARG;
        return -1;
    }

    if (err->path) {
        lydict_remove(ctx, err->path);
    }
    err->path = lydict_insert(ctx, error_path, 0);
    return 0;
}

API int
nc_err_set_msg(struct ly_ctx *ctx, struct nc_server_error *err, const char *error_message, const char *lang)
{
    if (!ctx || !err || !error_message) {
        ERRARG;
        return -1;
    }

    if (err->message) {
        lydict_remove(ctx, err->apptag);
    }
    err->message = lydict_insert(ctx, error_message, 0);

    if (err->message_lang) {
        lydict_remove(ctx, err->message_lang);
    }
    if (lang) {
        err->message_lang = lydict_insert(ctx, lang, 0);
    } else {
        lang = NULL;
    }
    return 0;
}

API int
nc_err_set_sid(struct nc_server_error *err, uint32_t session_id)
{
    if (!err) {
        ERRARG;
        return -1;
    }

    err->sid = session_id;
    return 0;
}

API int
nc_err_add_bad_attr(struct ly_ctx *ctx, struct nc_server_error *err, const char *attr_name)
{
    if (!ctx || !err || !attr_name) {
        ERRARG;
        return -1;
    }

    ++err->attr_count;
    err->attr = realloc(err->attr, err->attr_count * sizeof *err->attr);
    err->attr[err->attr_count - 1] = lydict_insert(ctx, attr_name, 0);
    return 0;
}

API int
nc_err_add_bad_elem(struct ly_ctx *ctx, struct nc_server_error *err, const char *elem_name)
{
    if (!ctx || !err || !elem_name) {
        ERRARG;
        return -1;
    }

    ++err->elem_count;
    err->elem = realloc(err->elem, err->elem_count * sizeof *err->elem);
    err->elem[err->elem_count - 1] = lydict_insert(ctx, elem_name, 0);
    return 0;
}

API int
nc_err_add_bad_ns(struct ly_ctx *ctx, struct nc_server_error *err, const char *ns_name)
{
    if (!ctx || !err || !ns_name) {
        ERRARG;
        return -1;
    }

    ++err->ns_count;
    err->ns = realloc(err->ns, err->ns_count * sizeof *err->ns);
    err->ns[err->ns_count - 1] = lydict_insert(ctx, ns_name, 0);
    return 0;
}

API int
nc_err_add_info_other(struct nc_server_error *err, struct lyxml_elem *other)
{
    if (!err || !other) {
        ERRARG;
        return -1;
    }

    ++err->other_count;
    err->other = realloc(err->other, err->other_count * sizeof *err->other);
    err->other[err->other_count - 1] = other;
    return 0;
}

void
nc_server_rpc_free(struct nc_server_rpc *rpc)
{
    lyxml_free(rpc->tree->schema->module->ctx, rpc->root);
    lyd_free(rpc->tree);
    free(rpc);
}

API void
nc_server_reply_free(struct nc_server_reply *reply)
{
    uint32_t i;
    struct nc_server_reply_data *data_rpl;
    struct nc_server_reply_error *error_rpl;

    if (!reply) {
        return;
    }

    switch (reply->type) {
    case NC_RPL_DATA:
        data_rpl = (struct nc_server_reply_data *)reply;
        if (data_rpl->free) {
            lyd_free_withsiblings(data_rpl->data);
        }
        break;
    case NC_RPL_OK:
        /* nothing to free */
        break;
    case NC_RPL_ERROR:
        error_rpl = (struct nc_server_reply_error *)reply;
        for (i = 0; i < error_rpl->count; ++i) {
            nc_err_free(error_rpl->ctx, error_rpl->err[i]);
        }
        free(error_rpl->err);
        break;
    default:
        break;
    }
    free(reply);
}

API void
nc_err_free(struct ly_ctx *ctx, struct nc_server_error *err)
{
    uint32_t i;

    if (!err) {
        ERRARG;
        return;
    }

    lydict_remove(ctx, err->apptag);
    lydict_remove(ctx, err->path);
    lydict_remove(ctx, err->message);
    lydict_remove(ctx, err->message_lang);
    for (i = 0; i < err->attr_count; ++i) {
        lydict_remove(ctx, err->attr[i]);
    }
    free(err->attr);
    for (i = 0; i < err->elem_count; ++i) {
        lydict_remove(ctx, err->elem[i]);
    }
    free(err->elem);
    for (i = 0; i < err->ns_count; ++i) {
        lydict_remove(ctx, err->ns[i]);
    }
    free(err->ns);
    for (i = 0; i < err->other_count; ++i) {
        lyxml_free(ctx, err->other[i]);
    }
    free(err->other);
    free(err);
}

API void
nc_rpc_free(struct nc_rpc *rpc)
{
    struct nc_rpc_generic *rpc_generic;
    struct nc_rpc_getconfig *rpc_getconfig;
    struct nc_rpc_edit *rpc_edit;
    struct nc_rpc_copy *rpc_copy;
    struct nc_rpc_delete *rpc_delete;
    struct nc_rpc_get *rpc_get;
    struct nc_rpc_commit *rpc_commit;
    struct nc_rpc_cancel *rpc_cancel;
    struct nc_rpc_validate *rpc_validate;
    struct nc_rpc_getschema *rpc_getschema;
    struct nc_rpc_subscribe *rpc_subscribe;

    if (!rpc) {
        return;
    }

    switch (rpc->type) {
    case NC_RPC_GENERIC:
        rpc_generic = (struct nc_rpc_generic *)rpc;
        if (rpc_generic->free) {
            if (rpc_generic->has_data) {
                lyd_free(rpc_generic->content.data);
            } else {
                free(rpc_generic->content.xml_str);
            }
        }
        break;
    case NC_RPC_GETCONFIG:
        rpc_getconfig = (struct nc_rpc_getconfig *)rpc;
        if (rpc_getconfig->free) {
            free(rpc_getconfig->filter);
        }
        break;
    case NC_RPC_EDIT:
        rpc_edit = (struct nc_rpc_edit *)rpc;
        if (rpc_edit->free) {
            free(rpc_edit->edit_cont);
        }
        break;
    case NC_RPC_COPY:
        rpc_copy = (struct nc_rpc_copy *)rpc;
        if (rpc_copy->free) {
            free(rpc_copy->url_config_src);
        }
        break;
    case NC_RPC_DELETE:
        rpc_delete = (struct nc_rpc_delete *)rpc;
        if (rpc_delete->free) {
            free(rpc_delete->url);
        }
        break;
    case NC_RPC_GET:
        rpc_get = (struct nc_rpc_get *)rpc;
        if (rpc_get->free) {
            free(rpc_get->filter);
        }
        break;
    case NC_RPC_COMMIT:
        rpc_commit = (struct nc_rpc_commit *)rpc;
        if (rpc_commit->free) {
            free(rpc_commit->persist);
            free(rpc_commit->persist_id);
        }
        break;
    case NC_RPC_CANCEL:
        rpc_cancel = (struct nc_rpc_cancel *)rpc;
        if (rpc_cancel->free) {
            free(rpc_cancel->persist_id);
        }
        break;
    case NC_RPC_VALIDATE:
        rpc_validate = (struct nc_rpc_validate *)rpc;
        if (rpc_validate->free) {
            free(rpc_validate->url_config_src);
        }
        break;
    case NC_RPC_GETSCHEMA:
        rpc_getschema = (struct nc_rpc_getschema *)rpc;
        if (rpc_getschema->free) {
            free(rpc_getschema->identifier);
            free(rpc_getschema->version);
            free(rpc_getschema->format);
        }
        break;
    case NC_RPC_SUBSCRIBE:
        rpc_subscribe = (struct nc_rpc_subscribe *)rpc;
        if (rpc_subscribe->free) {
            free(rpc_subscribe->stream);
            free(rpc_subscribe->filter);
            free(rpc_subscribe->start);
            free(rpc_subscribe->stop);
        }
        break;
    case NC_RPC_KILL:
    case NC_RPC_DISCARD:
    case NC_RPC_LOCK:
    case NC_RPC_UNLOCK:
        /* nothing special needed */
        break;
    }

    free(rpc);
}

API void
nc_reply_free(struct nc_reply *reply)
{
    struct nc_reply_error *error;
    struct nc_reply_data *data;
    uint32_t i, j;

    if (!reply) {
        return;
    }

    switch (reply->type) {
    case NC_RPL_DATA:
        data = (struct nc_reply_data *)reply;
        lyd_free_withsiblings(data->data);
        break;

    case NC_RPL_OK:
        /* nothing to free */
        break;

    case NC_RPL_ERROR:
        error = (struct nc_reply_error *)reply;
        for (i = 0; i < error->count; ++i) {
            lydict_remove(error->ctx, error->err[i].type);
            lydict_remove(error->ctx, error->err[i].tag);
            lydict_remove(error->ctx, error->err[i].severity);
            lydict_remove(error->ctx, error->err[i].apptag);
            lydict_remove(error->ctx, error->err[i].path);
            lydict_remove(error->ctx, error->err[i].message);
            lydict_remove(error->ctx, error->err[i].message_lang);
            lydict_remove(error->ctx, error->err[i].sid);
            for (j = 0; j < error->err[i].attr_count; ++j) {
                lydict_remove(error->ctx, error->err[i].attr[j]);
            }
            free(error->err[i].attr);
            for (j = 0; j < error->err[i].elem_count; ++j) {
                lydict_remove(error->ctx, error->err[i].elem[j]);
            }
            free(error->err[i].elem);
            for (j = 0; j < error->err[i].ns_count; ++j) {
                lydict_remove(error->ctx, error->err[i].ns[j]);
            }
            free(error->err[i].ns);
            for (j = 0; j < error->err[i].other_count; ++j) {
                lyxml_free(error->ctx, error->err[i].other[j]);
            }
            free(error->err[i].other);
        }
        free(error->err);
        break;

    case NC_RPL_NOTIF:
        nc_notif_free((struct nc_notif *)reply);
        break;
    }

    free(reply);
}

API void
nc_notif_free(struct nc_notif *notif)
{
    if (!notif) {
        return;
    }

    lydict_remove(notif->tree->schema->module->ctx, notif->datetime);
    lyd_free(notif->tree);
    free(notif);
}
