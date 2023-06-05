/**
 * @file messages_p.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief libnetconf2's private functions and structures of NETCONF messages.
 *
 * @copyright
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_MESSAGES_P_H_
#define NC_MESSAGES_P_H_

#include <stdint.h>

#include <libyang/libyang.h>

#include "messages_client.h"
#include "messages_server.h"
#include "netconf.h"

extern const char *rpcedit_dfltop2str[];
extern const char *rpcedit_testopt2str[];
extern const char *rpcedit_erropt2str[];

struct nc_server_reply {
    NC_RPL type;
};

struct nc_server_reply_data {
    NC_RPL type;
    struct lyd_node *data;
    int free;
    NC_WD_MODE wd;
};

struct nc_server_reply_error {
    NC_RPL type;
    struct lyd_node *err;
};

struct nc_server_rpc {
    struct lyd_node *envp;   /**< NETCONF-specific RPC envelopes */
    struct lyd_node *rpc;    /**< RPC data tree */
};

struct nc_server_notif {
    char *eventtime;        /**< eventTime of the notification */
    struct lyd_node *ntf;   /**< notification data tree of the message */
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

struct nc_rpc_getdata {
    NC_RPC_TYPE type;        /**< NC_RPC_GETDATA */
    char *datastore;         /**< target datastore identity */
    char *filter;            /**< either XML subtree (starts with '<') or an XPath (starts with '/' or an alpha) */
    char *config_filter;     /**< config filter ("true"/"false") */
    char **origin_filter;    /**< origin filters */
    int origin_filter_count; /**< origin filter count */
    int negated_origin_filter; /**< whether origin filter is negated or not */
    int max_depth;           /**< max depth of returned subtrees, 0 for unlimited */
    int with_origin;         /**< whether to return origin of data */
    NC_WD_MODE wd_mode;
    char free;
};

struct nc_rpc_editdata {
    NC_RPC_TYPE type;        /**< NC_RPC_EDITDATA */
    char *datastore;         /**< target datastore identity */
    NC_RPC_EDIT_DFLTOP default_op;
    char *edit_cont;         /**< either URL (starts with aplha) or config (starts with '<') */
    char free;
};

struct nc_rpc_establishsub {
    NC_RPC_TYPE type;        /**< NC_RPC_ESTABLISHSUB */
    char *filter;            /**< XML subtree (starts with '<'), an XPath (starts with '/'), or reference (start with alpha) */
    char *stream;            /**< stream name */
    char *start;
    char *stop;
    char *encoding;
    char free;
};

struct nc_rpc_modifysub {
    NC_RPC_TYPE type;        /**< NC_RPC_MODIFYSUB */
    uint32_t id;
    char *filter;            /**< XML subtree (starts with '<'), an XPath (starts with '/'), or reference (start with alpha) */
    char *stop;
    char free;
};

struct nc_rpc_deletesub {
    NC_RPC_TYPE type;        /**< NC_RPC_DELETESUB */
    uint32_t id;
};

struct nc_rpc_killsub {
    NC_RPC_TYPE type;        /**< NC_RPC_KILLSUB */
    uint32_t id;
};

struct nc_rpc_establishpush {
    NC_RPC_TYPE type;        /**< NC_RPC_ESTABLISHPUSH */
    char *datastore;
    char *filter;            /**< XML subtree (starts with '<'), an XPath (starts with '/'), or reference (start with alpha) */
    char *stop;
    char *encoding;
    int periodic;

    union {
        struct {
            uint32_t period;
            char *anchor_time;
        };
        struct {
            uint32_t dampening_period;
            int sync_on_start;
            char **excluded_change;
        };
    };
    char free;
};

struct nc_rpc_modifypush {
    NC_RPC_TYPE type;        /**< NC_RPC_MODIFYPUSH */
    uint32_t id;
    char *datastore;
    char *filter;            /**< XML subtree (starts with '<'), an XPath (starts with '/'), or reference (start with alpha) */
    char *stop;
    int periodic;

    union {
        struct {
            uint32_t period;
            char *anchor_time;
        };
        uint32_t dampening_period;
    };
    char free;
};

struct nc_rpc_resyncsub {
    NC_RPC_TYPE type;        /**< NC_RPC_RESYNCSUB */
    uint32_t id;
};

void nc_server_rpc_free(struct nc_server_rpc *rpc);

void nc_client_err_clean(struct nc_err *err, struct ly_ctx *ctx);

#endif /* NC_MESSAGES_P_H_ */
