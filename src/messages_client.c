/**
 * \file messages.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 - NETCONF messages functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <libyang/libyang.h>

#include "libnetconf.h"

const char *rpcedit_dfltop2str[] = {NULL, "merge", "replace", "none"};
const char *rpcedit_testopt2str[] = {NULL, "test-then-set", "set", "test-only"};
const char *rpcedit_erropt2str[] = {NULL, "stop-on-error", "continue-on-error", "rollback-on-error"};

API NC_RPC_TYPE
nc_rpc_get_type(const struct nc_rpc *rpc)
{
    if (!rpc) {
        ERRARG("rpc");
        return 0;
    }

    return rpc->type;
}

API struct nc_rpc *
nc_rpc_act_generic(const struct lyd_node *data, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_act_generic *rpc;

    if (!data || data->next || (data->prev != data)) {
        ERRARG("data");
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_ACT_GENERIC;
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
nc_rpc_act_generic_xml(const char *xml_str, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_act_generic *rpc;

    if (!xml_str) {
        ERRARG("xml_str");
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_ACT_GENERIC;
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

    if (!source) {
        ERRARG("source");
        return NULL;
    }

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR("Filter is neither an XML subtree nor an XPath expression (invalid first char '%c').", filter[0]);
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

    if (!target) {
        ERRARG("target");
        return NULL;
    } else if (!edit_content) {
        ERRARG("edit_content");
        return NULL;
    }

    if (edit_content[0] && (edit_content[0] != '<') && !isalpha(edit_content[0])) {
        ERR("<edit-config> content is neither a URL nor an XML config (invalid first char '%c').", edit_content[0]);
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

    if (!target) {
        ERRARG("target");
        return NULL;
    } else if (!source) {
        ERRARG("source");
        return NULL;
    }

    if (url_or_config_src && url_or_config_src[0] && (url_or_config_src[0] != '<') && !isalpha(url_or_config_src[0])) {
        ERR("<copy-config> source is neither a URL nor an XML config (invalid first char '%c').", url_or_config_src[0]);
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

    if (!target) {
        ERRARG("target");
        return NULL;
    }

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

    if (!target) {
        ERRARG("target");
        return NULL;
    }

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

    if (!target) {
        ERRARG("target");
        return NULL;
    }

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

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR("Filter is neither an XML subtree nor an XPath expression (invalid first char '%c').", filter[0]);
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

    if (!session_id) {
        ERRARG("session_id");
        return NULL;
    }

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

    if (!source) {
        ERRARG("source");
        return NULL;
    }

    if (url_or_config && url_or_config[0] && (url_or_config[0] != '<') && !isalpha(url_or_config[0])) {
        ERR("<validate> source is neither a URL nor an XML config (invalid first char '%c').", url_or_config[0]);
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

    if (!identifier) {
        ERRARG("identifier");
        return NULL;
    }

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

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR("Filter is neither an XML subtree nor an XPath expression (invalid first char '%c').", filter[0]);
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

API void
nc_rpc_free(struct nc_rpc *rpc)
{
    struct nc_rpc_act_generic *rpc_generic;
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
    case NC_RPC_ACT_GENERIC:
        rpc_generic = (struct nc_rpc_act_generic *)rpc;
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
            free(rpc_copy->url_trg);
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
    default:
        /* nothing special needed */
        break;
    }

    free(rpc);
}

API void
nc_client_err_clean(struct nc_err *err, struct ly_ctx *ctx)
{
    int i;

    assert(ctx);

    if (!err) {
        return;
    }

    lydict_remove(ctx, err->type);
    lydict_remove(ctx, err->tag);
    lydict_remove(ctx, err->severity);
    lydict_remove(ctx, err->apptag);
    lydict_remove(ctx, err->path);
    lydict_remove(ctx, err->message);
    lydict_remove(ctx, err->message_lang);
    lydict_remove(ctx, err->sid);
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
}

API void
nc_reply_free(struct nc_reply *reply)
{
    struct nc_client_reply_error *error;
    struct nc_reply_data *data;
    uint32_t i;

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
        error = (struct nc_client_reply_error *)reply;
        for (i = 0; i < error->count; ++i) {
            nc_client_err_clean(&error->err[i], error->ctx);
        }
        free(error->err);
        break;

    case NC_RPL_NOTIF:
        nc_notif_free((struct nc_notif *)reply);
        return;
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
