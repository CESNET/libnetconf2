/**
 * \file messages_p.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2's private functions and structures of NETCONF messages.
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_MESSAGES_P_H_
#define NC_MESSAGES_P_H_

#include <libyang/libyang.h>

#include "messages_server.h"
#include "messages_client.h"

extern const char *rpcedit_dfltop2str[];
extern const char *rpcedit_testopt2str[];
extern const char *rpcedit_erropt2str[];

struct nc_server_error {
    NC_ERR_TYPE type;
    NC_ERR tag;
    //NC_ERR_SEV severity;
    const char *apptag;
    const char *path;
    const char *message;
    const char *message_lang;

    /* <error-info> */
    int64_t sid;    /* -1 for not set */
    const char **attr;
    uint16_t attr_count;
    const char **elem;
    uint16_t elem_count;
    const char **ns;
    uint16_t ns_count;
    struct lyxml_elem **other;
    uint16_t other_count;
};

struct nc_server_reply {
    NC_RPL type;
};

struct nc_server_reply_data {
    NC_RPL type;
    struct lyd_node *data;
    char free;
    NC_WD_MODE wd;
};

struct nc_server_reply_error {
    NC_RPL type;
    struct ly_ctx *ctx;
    struct nc_server_error **err;
    uint32_t count;
};

struct nc_server_rpc {
    struct lyxml_elem *root; /**< RPC element of the received XML message */
    struct lyd_node *tree;   /**< libyang data tree of the message (NETCONF operation) */
};

struct nc_server_notif {
    char *eventtime;        /**< eventTime of the notification */
    struct lyd_node *tree;  /**< libyang data tree of the message */
    int free;
};

struct nc_client_reply_error {
    NC_RPL type;
    struct nc_err *err;
    uint32_t count;
    struct ly_ctx *ctx;
};

struct nc_rpc {
    NC_RPC_TYPE type;
};

struct nc_rpc_act_generic {
    NC_RPC_TYPE type;       /**< NC_RPC_ACT_GENERIC */
    int has_data;           /**< 1 for content.data, 0 for content.xml_str */
    union {
        struct lyd_node *data;  /**< parsed RPC data */
        char *xml_str;          /**< raw XML string */
    } content;
    char free;
};

struct nc_rpc_getconfig {
    NC_RPC_TYPE type;        /**< NC_RPC_GETCONFIG */
    NC_DATASTORE source;     /**< NETCONF datastore being queried */
    char *filter;            /**< either XML subtree (starts with '<') or an XPath (starts with '/' or an alpha) */
    NC_WD_MODE wd_mode;
    char free;
};

struct nc_rpc_edit {
    NC_RPC_TYPE type;        /**< NC_RPC_EDIT */
    NC_DATASTORE target;
    NC_RPC_EDIT_DFLTOP default_op;
    NC_RPC_EDIT_TESTOPT test_opt;
    NC_RPC_EDIT_ERROPT error_opt;
    char *edit_cont;         /**< either URL (starts with aplha) or config (starts with '<') */
    char free;
};

struct nc_rpc_copy {
    NC_RPC_TYPE type;        /**< NC_RPC_COPY */
    NC_DATASTORE target;
    char *url_trg;
    NC_DATASTORE source;
    char *url_config_src;    /**< either URL (starts with aplha) or config (starts with '<') */
    NC_WD_MODE wd_mode;
    char free;
};

struct nc_rpc_delete {
    NC_RPC_TYPE type;        /**< NC_RPC_DELETE */
    NC_DATASTORE target;
    char *url;
    char free;
};

struct nc_rpc_lock {
    NC_RPC_TYPE type;        /**< NC_RPC_LOCK or NC_RPC_UNLOCK */
    NC_DATASTORE target;
};

struct nc_rpc_get {
    NC_RPC_TYPE type;        /**< NC_RPC_GET */
    char *filter;            /**< either XML subtree (starts with '<') or an XPath (starts with '/' or an alpha) */
    NC_WD_MODE wd_mode;
    char free;
};

struct nc_rpc_kill {
    NC_RPC_TYPE type;        /**< NC_RPC_KILL */
    uint32_t sid;
};

struct nc_rpc_commit {
    NC_RPC_TYPE type;        /**< NC_RPC_COMMIT */
    int confirmed;
    uint32_t confirm_timeout;
    char *persist;
    char *persist_id;
    char free;
};

struct nc_rpc_cancel {
    NC_RPC_TYPE type;        /**< NC_RPC_CANCEL */
    char *persist_id;
    char free;
};

struct nc_rpc_validate {
    NC_RPC_TYPE type;        /**< NC_RPC_VALIDATE */
    NC_DATASTORE source;
    char *url_config_src;    /**< either URL (starts with alpha) or config (starts with '<') */
    char free;
};

struct nc_rpc_getschema {
    NC_RPC_TYPE type;        /**< NC_RPC_GETSCHEMA */
    char *identifier;        /**< requested model identifier */
    char *version;           /**< either YANG version (1.0/1.1) or revision date */
    char *format;            /**< model format */
    char free;
};

struct nc_rpc_subscribe {
    NC_RPC_TYPE type;        /**< NC_RPC_SUBSCRIBE */
    char *stream;            /**< stream name */
    char *filter;            /**< either XML subtree (starts with '<') or an XPath (starts with '/' or an alpha) */
    char *start;
    char *stop;
    char free;
};

void nc_server_rpc_free(struct nc_server_rpc *rpc, struct ly_ctx *ctx);

void nc_client_err_clean(struct nc_err *err, struct ly_ctx *ctx);

#endif /* NC_MESSAGES_P_H_ */
