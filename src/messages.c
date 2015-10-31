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

#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "libnetconf.h"
#include "messages_p.h"

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

API void
nc_rpc_free(struct nc_rpc *rpc)
{
    struct nc_rpc_server *rpc_server;
    struct nc_rpc_getconfig *rpc_getconfig;

    if (!rpc) {
        return;
    }

    switch(rpc->type) {
    case NC_RPC_SERVER:
        rpc_server = (struct nc_rpc_server *)rpc;
        lyxml_free_elem(rpc_server->ctx, rpc_server->root);
        lyd_free(rpc_server->tree);
        break;
    case NC_RPC_GETCONFIG:
        rpc_getconfig = (struct nc_rpc_getconfig *)rpc;
        nc_filter_free(rpc_getconfig->filter);
        break;
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
    if (!reply) {
        return;
    }

    lyxml_free_elem(reply->ctx, reply->root);
    lyd_free(reply->tree);
    free(reply);
}
API void
nc_notif_free(struct nc_notif *notif)
{
    if (!notif) {
        return;
    }

    lyxml_free_elem(notif->ctx, notif->root);
    lyd_free(notif->tree);
    free(notif);
}
