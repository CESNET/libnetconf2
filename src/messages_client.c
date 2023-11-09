/**
 * @file messages.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief libnetconf2 - NETCONF messages functions
 *
 * @copyright
 * Copyright (c) 2015 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE /* pthread_rwlock_t, strdup */

#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "messages_client.h"
#include "messages_p.h"
#include "netconf.h"

const char *rpcedit_dfltop2str[] = {NULL, "merge", "replace", "none"};
const char *rpcedit_testopt2str[] = {NULL, "test-then-set", "set", "test-only"};
const char *rpcedit_erropt2str[] = {NULL, "stop-on-error", "continue-on-error", "rollback-on-error"};

API NC_RPC_TYPE
nc_rpc_get_type(const struct nc_rpc *rpc)
{
    NC_CHECK_ARG_RET(NULL, rpc, 0);

    return rpc->type;
}

API struct nc_rpc *
nc_rpc_act_generic(const struct lyd_node *data, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_act_generic *rpc;

    NC_CHECK_ARG_RET(NULL, data, NULL);
    if (data->next || (data->prev != data)) {
        ERR(NULL, "nc_rpc_act_generic missing data");
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_ACT_GENERIC;
    rpc->has_data = 1;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        if (lyd_dup_single(data, NULL, LYD_DUP_RECURSIVE, &rpc->content.data)) {
            free(rpc);
            return NULL;
        }
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

    NC_CHECK_ARG_RET(NULL, xml_str, NULL);

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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

    NC_CHECK_ARG_RET(NULL, source, NULL);

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR(NULL, "Filter is neither an XML subtree nor an XPath expression (invalid first char '%c').", filter[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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

    NC_CHECK_ARG_RET(NULL, target, edit_content, NULL);

    if (edit_content[0] && (edit_content[0] != '<') && !isalpha(edit_content[0])) {
        ERR(NULL, "<edit-config> content is neither a URL nor an XML config (invalid first char '%c').", edit_content[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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

    NC_CHECK_ARG_RET(NULL, target, source, NULL);

    if (url_or_config_src && url_or_config_src[0] && (url_or_config_src[0] != '<') && !isalpha(url_or_config_src[0])) {
        ERR(NULL, "<copy-config> source is neither a URL nor an XML config (invalid first char '%c').", url_or_config_src[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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

    NC_CHECK_ARG_RET(NULL, target, NULL);

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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

    NC_CHECK_ARG_RET(NULL, target, NULL);

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_LOCK;
    rpc->target = target;

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_unlock(NC_DATASTORE target)
{
    struct nc_rpc_lock *rpc;

    NC_CHECK_ARG_RET(NULL, target, NULL);

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_UNLOCK;
    rpc->target = target;

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_get(const char *filter, NC_WD_MODE wd_mode, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_get *rpc;

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR(NULL, "Filter is neither an XML subtree nor an XPath expression (invalid first char '%c').", filter[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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

    NC_CHECK_ARG_RET(NULL, session_id, NULL);

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_DISCARD;

    return rpc;
}

API struct nc_rpc *
nc_rpc_cancel(const char *persist_id, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_cancel *rpc;

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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

    NC_CHECK_ARG_RET(NULL, source, NULL);

    if (url_or_config && url_or_config[0] && (url_or_config[0] != '<') && !isalpha(url_or_config[0])) {
        ERR(NULL, "<validate> source is neither a URL nor an XML config (invalid first char '%c').", url_or_config[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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

    NC_CHECK_ARG_RET(NULL, identifier, NULL);

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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
        ERR(NULL, "Filter is neither an XML subtree nor an XPath expression (invalid first char '%c').", filter[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

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

API struct nc_rpc *
nc_rpc_getdata(const char *datastore, const char *filter, const char *config_filter, char **origin_filter,
        int origin_filter_count, int negated_origin_filter, uint16_t max_depth, int with_origin, NC_WD_MODE wd_mode,
        NC_PARAMTYPE paramtype)
{
    struct nc_rpc_getdata *rpc = NULL;
    int i;

    NC_CHECK_ARG_RET(NULL, datastore, NULL);

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR(NULL, "Filter is neither an XML subtree nor an XPath expression (invalid first char '%c').", filter[0]);
        return NULL;
    }

    rpc = calloc(1, sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    rpc->type = NC_RPC_GETDATA;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->datastore = strdup(datastore);
    } else {
        rpc->datastore = (char *)datastore;
    }
    if (filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->filter = strdup(filter);
    } else {
        rpc->filter = (char *)filter;
    }
    if (config_filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->config_filter = strdup(config_filter);
    } else {
        rpc->config_filter = (char *)config_filter;
    }
    if (origin_filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->origin_filter = malloc(origin_filter_count * sizeof *rpc->origin_filter);
        NC_CHECK_ERRMEM_GOTO(!rpc->origin_filter, , error);
        for (i = 0; i < origin_filter_count; ++i) {
            rpc->origin_filter[i] = strdup(origin_filter[i]);
            NC_CHECK_ERRMEM_GOTO(!rpc->origin_filter[i], , error);
            ++rpc->origin_filter_count;
        }
    } else {
        rpc->origin_filter = origin_filter;
        rpc->origin_filter_count = origin_filter_count;
    }
    rpc->negated_origin_filter = negated_origin_filter;
    rpc->max_depth = max_depth;
    rpc->with_origin = with_origin;
    rpc->wd_mode = wd_mode;

    return (struct nc_rpc *)rpc;

error:
    nc_rpc_free((struct nc_rpc *)rpc);
    return NULL;
}

API struct nc_rpc *
nc_rpc_editdata(const char *datastore, NC_RPC_EDIT_DFLTOP default_op, const char *edit_content, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_editdata *rpc;

    NC_CHECK_ARG_RET(NULL, datastore, edit_content, NULL);

    if (edit_content[0] && (edit_content[0] != '<') && !isalpha(edit_content[0])) {
        ERR(NULL, "<edit-data> content is neither a URL nor an XML config (invalid first char '%c').", edit_content[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_EDITDATA;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->datastore = strdup(datastore);
    } else {
        rpc->datastore = (char *)datastore;
    }
    rpc->default_op = default_op;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->edit_cont = strdup(edit_content);
    } else {
        rpc->edit_cont = (char *)edit_content;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_establishsub(const char *filter, const char *stream_name, const char *start_time,
        const char *stop_time, const char *encoding, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_establishsub *rpc;

    NC_CHECK_ARG_RET(NULL, stream_name, NULL);

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR(NULL, "Filter is not an XML subtree, an XPath expression, not a filter reference (invalid first char '%c').",
                filter[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_ESTABLISHSUB;
    if (filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->filter = strdup(filter);
    } else {
        rpc->filter = (char *)filter;
    }
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->stream = strdup(stream_name);
    } else {
        rpc->stream = (char *)stream_name;
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
    if (encoding && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->encoding = strdup(encoding);
    } else {
        rpc->encoding = (char *)encoding;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_modifysub(uint32_t id, const char *filter, const char *stop_time, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_modifysub *rpc;

    NC_CHECK_ARG_RET(NULL, id, NULL);

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR(NULL, "Filter is not an XML subtree, an XPath expression, not a filter reference (invalid first char '%c').",
                filter[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_MODIFYSUB;
    rpc->id = id;
    if (filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->filter = strdup(filter);
    } else {
        rpc->filter = (char *)filter;
    }
    if (stop_time && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->stop = strdup(stop_time);
    } else {
        rpc->stop = (char *)stop_time;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_deletesub(uint32_t id)
{
    struct nc_rpc_deletesub *rpc;

    NC_CHECK_ARG_RET(NULL, id, NULL);

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_DELETESUB;
    rpc->id = id;

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_killsub(uint32_t id)
{
    struct nc_rpc_killsub *rpc;

    NC_CHECK_ARG_RET(NULL, id, NULL);

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_KILLSUB;
    rpc->id = id;

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_establishpush_periodic(const char *datastore, const char *filter, const char *stop_time, const char *encoding,
        uint32_t period, const char *anchor_time, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_establishpush *rpc;

    NC_CHECK_ARG_RET(NULL, datastore, period, NULL);

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR(NULL, "Filter is not an XML subtree, an XPath expression, not a filter reference (invalid first char '%c').",
                filter[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_ESTABLISHPUSH;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->datastore = strdup(datastore);
    } else {
        rpc->datastore = (char *)datastore;
    }
    if (filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->filter = strdup(filter);
    } else {
        rpc->filter = (char *)filter;
    }
    if (stop_time && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->stop = strdup(stop_time);
    } else {
        rpc->stop = (char *)stop_time;
    }
    if (encoding && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->encoding = strdup(encoding);
    } else {
        rpc->encoding = (char *)encoding;
    }
    rpc->periodic = 1;
    rpc->period = period;
    if (anchor_time && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->anchor_time = strdup(anchor_time);
    } else {
        rpc->anchor_time = (char *)anchor_time;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_establishpush_onchange(const char *datastore, const char *filter, const char *stop_time, const char *encoding,
        uint32_t dampening_period, int sync_on_start, const char **excluded_change, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_establishpush *rpc;
    uint32_t i;
    void *tmp;

    NC_CHECK_ARG_RET(NULL, datastore, NULL);

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR(NULL, "Filter is not an XML subtree, an XPath expression, not a filter reference (invalid first char '%c').",
                filter[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_ESTABLISHPUSH;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->datastore = strdup(datastore);
    } else {
        rpc->datastore = (char *)datastore;
    }
    if (filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->filter = strdup(filter);
    } else {
        rpc->filter = (char *)filter;
    }
    if (stop_time && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->stop = strdup(stop_time);
    } else {
        rpc->stop = (char *)stop_time;
    }
    if (encoding && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->encoding = strdup(encoding);
    } else {
        rpc->encoding = (char *)encoding;
    }
    rpc->periodic = 0;
    rpc->dampening_period = dampening_period;
    rpc->sync_on_start = sync_on_start;
    if (excluded_change && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->excluded_change = NULL;
        for (i = 0; excluded_change[i]; ++i) {
            tmp = realloc(rpc->excluded_change, (i + 2) * sizeof *rpc->excluded_change);
            if (!tmp) {
                /* in case we fail to alloc, just free all the excluded changes, but return the rpc anyways */
                ERRMEM;
                free(rpc->excluded_change);
                rpc->excluded_change = NULL;
                break;
            }
            rpc->excluded_change = tmp;
            rpc->excluded_change[i] = strdup(excluded_change[i]);
            rpc->excluded_change[i + 1] = NULL;
        }
    } else {
        rpc->excluded_change = (char **)excluded_change;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_modifypush_periodic(uint32_t id, const char *datastore, const char *filter, const char *stop_time, uint32_t period,
        const char *anchor_time, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_modifypush *rpc;

    NC_CHECK_ARG_RET(NULL, id, datastore, NULL);

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR(NULL, "Filter is not an XML subtree, an XPath expression, not a filter reference (invalid first char '%c').",
                filter[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_MODIFYPUSH;
    rpc->id = id;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->datastore = strdup(datastore);
    } else {
        rpc->datastore = (char *)datastore;
    }
    if (filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->filter = strdup(filter);
    } else {
        rpc->filter = (char *)filter;
    }
    if (stop_time && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->stop = strdup(stop_time);
    } else {
        rpc->stop = (char *)stop_time;
    }
    rpc->periodic = 1;
    rpc->period = period;
    if (anchor_time && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->anchor_time = strdup(anchor_time);
    } else {
        rpc->anchor_time = (char *)anchor_time;
    }
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_modifypush_onchange(uint32_t id, const char *datastore, const char *filter, const char *stop_time,
        uint32_t dampening_period, NC_PARAMTYPE paramtype)
{
    struct nc_rpc_modifypush *rpc;

    NC_CHECK_ARG_RET(NULL, id, datastore, NULL);

    if (filter && filter[0] && (filter[0] != '<') && (filter[0] != '/') && !isalpha(filter[0])) {
        ERR(NULL, "Filter is not an XML subtree, an XPath expression, not a filter reference (invalid first char '%c').",
                filter[0]);
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_MODIFYPUSH;
    rpc->id = id;
    if (paramtype == NC_PARAMTYPE_DUP_AND_FREE) {
        rpc->datastore = strdup(datastore);
    } else {
        rpc->datastore = (char *)datastore;
    }
    if (filter && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->filter = strdup(filter);
    } else {
        rpc->filter = (char *)filter;
    }
    if (stop_time && (paramtype == NC_PARAMTYPE_DUP_AND_FREE)) {
        rpc->stop = strdup(stop_time);
    } else {
        rpc->stop = (char *)stop_time;
    }
    rpc->periodic = 0;
    rpc->dampening_period = dampening_period;
    rpc->free = (paramtype == NC_PARAMTYPE_CONST ? 0 : 1);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_resyncsub(uint32_t id)
{
    struct nc_rpc_resyncsub *rpc;

    NC_CHECK_ARG_RET(NULL, id, NULL);

    rpc = malloc(sizeof *rpc);
    NC_CHECK_ERRMEM_RET(!rpc, NULL);

    rpc->type = NC_RPC_RESYNCSUB;
    rpc->id = id;

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
    struct nc_rpc_getdata *rpc_getdata;
    struct nc_rpc_editdata *rpc_editdata;
    struct nc_rpc_establishsub *rpc_establishsub;
    struct nc_rpc_modifysub *rpc_modifysub;
    struct nc_rpc_establishpush *rpc_establishpush;
    struct nc_rpc_modifypush *rpc_modifypush;
    int i;

    if (!rpc) {
        return;
    }

    switch (rpc->type) {
    case NC_RPC_ACT_GENERIC:
        rpc_generic = (struct nc_rpc_act_generic *)rpc;
        if (rpc_generic->free) {
            if (rpc_generic->has_data) {
                lyd_free_tree(rpc_generic->content.data);
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
    case NC_RPC_GETDATA:
        rpc_getdata = (struct nc_rpc_getdata *)rpc;
        if (rpc_getdata->free) {
            free(rpc_getdata->datastore);
            free(rpc_getdata->filter);
            free(rpc_getdata->config_filter);
            for (i = 0; i < rpc_getdata->origin_filter_count; ++i) {
                free(rpc_getdata->origin_filter[i]);
            }
            free(rpc_getdata->origin_filter);
        }
        break;
    case NC_RPC_EDITDATA:
        rpc_editdata = (struct nc_rpc_editdata *)rpc;
        if (rpc_editdata->free) {
            free(rpc_editdata->datastore);
            free(rpc_editdata->edit_cont);
        }
        break;
    case NC_RPC_ESTABLISHSUB:
        rpc_establishsub = (struct nc_rpc_establishsub *)rpc;
        if (rpc_establishsub->free) {
            free(rpc_establishsub->filter);
            free(rpc_establishsub->stream);
            free(rpc_establishsub->start);
            free(rpc_establishsub->stop);
            free(rpc_establishsub->encoding);
        }
        break;
    case NC_RPC_MODIFYSUB:
        rpc_modifysub = (struct nc_rpc_modifysub *)rpc;
        if (rpc_modifysub->free) {
            free(rpc_modifysub->filter);
            free(rpc_modifysub->stop);
        }
        break;
    case NC_RPC_ESTABLISHPUSH:
        rpc_establishpush = (struct nc_rpc_establishpush *)rpc;
        if (rpc_establishpush->free) {
            free(rpc_establishpush->datastore);
            free(rpc_establishpush->filter);
            free(rpc_establishpush->stop);
            free(rpc_establishpush->encoding);
            if (rpc_establishpush->periodic) {
                free(rpc_establishpush->anchor_time);
            } else {
                if (rpc_establishpush->excluded_change) {
                    for (i = 0; rpc_establishpush->excluded_change[i]; ++i) {
                        free(rpc_establishpush->excluded_change[i]);
                    }
                    free(rpc_establishpush->excluded_change);
                }
            }
        }
        break;
    case NC_RPC_MODIFYPUSH:
        rpc_modifypush = (struct nc_rpc_modifypush *)rpc;
        if (rpc_modifypush->free) {
            free(rpc_modifypush->datastore);
            free(rpc_modifypush->filter);
            free(rpc_modifypush->stop);
            if (rpc_modifypush->periodic) {
                free(rpc_modifypush->anchor_time);
            }
        }
        break;
    case NC_RPC_UNKNOWN:
    case NC_RPC_LOCK:
    case NC_RPC_UNLOCK:
    case NC_RPC_KILL:
    case NC_RPC_DISCARD:
    case NC_RPC_DELETESUB:
    case NC_RPC_KILLSUB:
    case NC_RPC_RESYNCSUB:
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
    lyd_free_siblings(err->other);
    free(err->other);
}
