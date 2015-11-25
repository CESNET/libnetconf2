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

#include <libyang/libyang.h>

#include "libnetconf.h"
#include "messages_p.h"

const char *rpcedit_dfltop2str[] = {NULL, "merge", "replace", "none"};
const char *rpcedit_testopt2str[] = {NULL, "test-then-set", "set", "test-only"};
const char *rpcedit_erropt2str[] = {NULL, "stop-on-error", "continue-on-error", "rollback-on-error"};

API struct nc_filter *
nc_filter_new(NC_FILTER type, char *data, int constdata)
{
    struct nc_filter *filter;

    if (!data) {
        data = "";
        constdata = 1;
    }

    filter = malloc(sizeof *filter);
    if (!filter) {
        ERRMEM;
        return NULL;
    }

    filter->type = type;
    filter->refs = 1;
    if (constdata) {
        filter->data = strdup(data);
    } else {
        filter->data = data;
    }

    return filter;
}

API void
nc_filter_free(struct nc_filter *filter)
{
    if (!filter) {
        return;
    }

    filter->refs--;

    if (!filter->refs) {
        free(filter->data);
        free(filter);
    }
}

API struct nc_rpc *
nc_rpc_generic(struct lyd_node *data)
{
    struct nc_rpc_generic *rpc;

    if (data->prev != data) {
        ERR("Generic RPC must have a single root node.");
        return NULL;
    }

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_GENERIC;
    rpc->data = data;

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_generic_xml(const char *xml_str)
{
    struct nc_rpc_generic_xml *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_GENERIC_XML;
    rpc->xml_str = strdup(xml_str);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_getconfig(NC_DATASTORE source, struct nc_filter *filter)
{
    struct nc_rpc_getconfig *rpc;

    rpc = calloc(1, sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_GETCONFIG;
    rpc->source = source;
    if (filter) {
        filter->refs++;
        rpc->filter = filter;
    }

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_edit(NC_DATASTORE target, NC_RPC_EDIT_DFLTOP default_op, NC_RPC_EDIT_TESTOPT test_opt,
            NC_RPC_EDIT_ERROPT error_opt, const char *edit_content)
{
    struct nc_rpc_edit *rpc;

    if ((edit_content[0] != '<') && !isalpha(edit_content[0])) {
        ERR("<edit-config> content must either be a URL or a config (XML).");
        return NULL;
    }

    rpc = calloc(1, sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_EDIT;
    rpc->target = target;
    rpc->default_op = default_op;
    rpc->test_opt = test_opt;
    rpc->error_opt = error_opt;
    rpc->edit_cont = strdup(edit_content);

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_copy(NC_DATASTORE target, const char *url_trg, NC_DATASTORE source, const char *url_or_config_src)
{
    struct nc_rpc_copy *rpc;

    if (url_or_config_src && (url_or_config_src[0] != '<') && !isalpha(url_or_config_src[0])) {
        ERR("<copy-config> source is neither a URL nor a config (XML).");
        return NULL;
    }

    rpc = calloc(1, sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_COPY;
    rpc->target = target;
    if (url_trg) {
        rpc->url_trg = strdup(url_trg);
    } else {
        rpc->url_trg = NULL;
    }
    rpc->source = source;
    if (url_or_config_src) {
        rpc->url_config_src = strdup(url_or_config_src);
    } else {
        rpc->url_config_src = NULL;
    }

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_delete(NC_DATASTORE target, char *url)
{
    struct nc_rpc_delete *rpc;

    rpc = calloc(1, sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_DELETE;
    rpc->target = target;
    if (url) {
        rpc->url = strdup(url);
    } else {
        rpc->url = NULL;
    }

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
nc_rpc_get(struct nc_filter *filter)
{
    struct nc_rpc_get *rpc;

    rpc = calloc(1, sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_GET;
    if (filter) {
        filter->refs++;
        rpc->filter = filter;
    }

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
nc_rpc_commit(int confirmed, uint32_t confirm_timeout, const char *persist, const char *persist_id)
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
    if (persist) {
        rpc->persist = strdup(persist);
    } else {
        rpc->persist = NULL;
    }
    if (persist_id) {
        rpc->persist_id = strdup(persist_id);
    } else {
        rpc->persist_id = NULL;
    }

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
nc_rpc_cancel(const char *persist_id)
{
    struct nc_rpc_cancel *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_CANCEL;
    if (persist_id) {
        rpc->persist_id = strdup(persist_id);
    } else {
        rpc->persist_id = NULL;
    }

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_validate(NC_DATASTORE source, const char *url_or_config)
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
    if (url_or_config) {
        rpc->url_config_src = strdup(url_or_config);
    } else {
        rpc->url_config_src = NULL;
    }

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_getschema(const char *identifier, const char *version, const char *format)
{
    struct nc_rpc_getschema *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_GETSCHEMA;
    rpc->identifier = strdup(identifier);
    if (version) {
        rpc->version = strdup(version);
    } else {
        rpc->version = NULL;
    }
    if (format) {
        rpc->format = strdup(format);
    } else {
        rpc->format = NULL;
    }

    return (struct nc_rpc *)rpc;
}

API struct nc_rpc *
nc_rpc_subscribe(const char *stream_name, struct nc_filter *filter, const char *start_time, const char *stop_time)
{
    struct nc_rpc_subscribe *rpc;

    rpc = malloc(sizeof *rpc);
    if (!rpc) {
        ERRMEM;
        return NULL;
    }

    rpc->type = NC_RPC_SUBSCRIBE;
    if (stream_name) {
        rpc->stream = strdup(stream_name);
    } else {
        rpc->stream = NULL;
    }
    if (filter) {
        filter->refs++;
        rpc->filter = filter;
    } else {
        filter = NULL;
    }
    if (start_time) {
        rpc->start = strdup(start_time);
    } else {
        rpc->start = NULL;
    }
    if (stop_time) {
        rpc->stop = strdup(stop_time);
    } else {
        rpc->stop = NULL;
    }

    return (struct nc_rpc *)rpc;
}

API void
nc_rpc_free(struct nc_rpc *rpc)
{
    struct nc_rpc_server *rpc_server;
    struct nc_rpc_generic *rpc_generic;
    struct nc_rpc_generic_xml *rpc_generic_xml;
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

    switch(rpc->type) {
    case NC_RPC_SERVER:
        rpc_server = (struct nc_rpc_server *)rpc;
        lyxml_free_elem(rpc_server->tree->schema->module->ctx, rpc_server->root);
        lyd_free(rpc_server->tree);
        break;
    case NC_RPC_GENERIC:
        rpc_generic = (struct nc_rpc_generic *)rpc;
        lyd_free(rpc_generic->data);
        break;
    case NC_RPC_GENERIC_XML:
        rpc_generic_xml = (struct nc_rpc_generic_xml *)rpc;
        free(rpc_generic_xml->xml_str);
        break;
    case NC_RPC_GETCONFIG:
        rpc_getconfig = (struct nc_rpc_getconfig *)rpc;
        nc_filter_free(rpc_getconfig->filter);
        break;
    case NC_RPC_EDIT:
        rpc_edit = (struct nc_rpc_edit *)rpc;
        free(rpc_edit->edit_cont);
        break;
    case NC_RPC_COPY:
        rpc_copy = (struct nc_rpc_copy *)rpc;
        free(rpc_copy->url_config_src);
        break;
    case NC_RPC_DELETE:
        rpc_delete = (struct nc_rpc_delete *)rpc;
        free(rpc_delete->url);
        break;
    case NC_RPC_GET:
        rpc_get = (struct nc_rpc_get *)rpc;
        nc_filter_free(rpc_get->filter);
        break;
    case NC_RPC_COMMIT:
        rpc_commit = (struct nc_rpc_commit *)rpc;
        free(rpc_commit->persist);
        free(rpc_commit->persist_id);
        break;
    case NC_RPC_CANCEL:
        rpc_cancel = (struct nc_rpc_cancel *)rpc;
        free(rpc_cancel->persist_id);
        break;
    case NC_RPC_VALIDATE:
        rpc_validate = (struct nc_rpc_validate *)rpc;
        free(rpc_validate->url_config_src);
        break;
    case NC_RPC_GETSCHEMA:
        rpc_getschema = (struct nc_rpc_getschema *)rpc;
        free(rpc_getschema->identifier);
        free(rpc_getschema->version);
        free(rpc_getschema->format);
        break;
    case NC_RPC_SUBSCRIBE:
        rpc_subscribe = (struct nc_rpc_subscribe *)rpc;
        free(rpc_subscribe->stream);
        nc_filter_free(rpc_subscribe->filter);
        free(rpc_subscribe->start);
        free(rpc_subscribe->stop);
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
    struct nc_reply_ok *ok;
    struct nc_reply_data *data;
    struct lyd_node *node;

    if (!reply) {
        return;
    }

    switch(reply->type) {
    case NC_REPLY_DATA:
        data = (struct nc_reply_data *)reply;
        lyxml_free_elem(data->data->schema->module->ctx, data->root);
        for (node = data->data; data->data; node = data->data) {
            data->data = node->next;
            lyd_free(node);
        }
        break;
    case NC_REPLY_OK:
        ok = (struct nc_reply_ok *)reply;
        lyxml_free_elem(ok->ctx, ok->root);
        break;
    case NC_REPLY_ERROR:
        error = (struct nc_reply_error *)reply;
        (void)error;
        /* TODO */
        break;
    case NC_REPLY_NOTIF:
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

    lyxml_free_elem(notif->tree->schema->module->ctx, notif->root);
    lyd_free(notif->tree);
    free(notif);
}
