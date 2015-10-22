/**
 * \file messages_p.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2's private functions and structures of NETCONF messages.
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

#ifndef NC_MESSAGES_P_H_
#define NC_MESSAGES_P_H_

#include <libyang/libyang.h>

#include "messages.h"

typedef enum {
    NC_RPC_SERVER,    /**< server-side RPC object, see #nc_rpc_server. All other values define client-side RPC object. */
    NC_RPC_GETCONFIG, /**< \<get-config\> RPC, see #nc_rpc_getconfig. */
    NC_RPC_EDIT,      /**< \<edit-config\> RPC, see #nc_rpc_edit. */
    NC_RPC_COPY,      /**< \<copy-config\> RPC, see #nc_rpc_copy. */
    NC_RPC_DELETE,    /**< \<delete-config\> RPC, see #nc_rpc_delete. */
    NC_RPC_LOCK,      /**< \<lock\> RPC, see #nc_rpc_lock. */
    NC_RPC_UNLOCK,    /**< \<unlock\> RPC, see #nc_rpc_lock. */
    NC_RPC_GET,       /**< \<get\> RPC, see #nc_rpc_get. */
    /* NC_RPC_CLOSE is not defined since sending \<close-session\> is done by nc_session_free() */
    NC_RPC_KILL,      /**< \<kill-session\> RPC, see #nc_rpc_kill. */
    NC_RPC_GENERIC    /**< user-defined generic RPC */
} NC_RPC_TYPE;

struct nc_filter {
    NC_FILTER type;   /**< filter type */
    int refs;         /**< number of references */
    char *data;       /**< filter data according to type */
};

struct nc_rpc {
    NC_RPC_TYPE type;
};

struct nc_rpc_server {
    NC_RPC_TYPE type;        /**< NC_RPC_SERVER */
    struct ly_ctx *ctx;      /**< context of the received RPC data */
    struct lyxml_elem *root; /**< RPC element of the received XML message */
    struct lyd_node *tree;   /**< libyang data tree of the message (NETCONF operation) */
};

struct nc_rpc_getconfig {
    NC_RPC_TYPE type;        /**< NC_RPC_GETCONFIG */
    NC_DATASTORE source;     /**< NETCONF datastore being queried */
    struct nc_filter *filter;/**< data filter */
};

struct nc_rpc_lock {
    NC_RPC_TYPE type;        /**< NC_RPC_LOCK or NC_RPC_UNLOCK */
    NC_DATASTORE target;
};

struct nc_reply {
    struct ly_ctx *ctx;
    struct lyxml_elem *root;
    struct lyd_node *tree;  /**< libyang data tree of the message */
};

struct nc_notif {
    struct ly_ctx *ctx;
    struct lyxml_elem *root;
    struct lyd_node *tree;  /**< libyang data tree of the message */
};

#endif /* NC_MESSAGES_P_H_ */
