/**
 * \file messages_server.h
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2's functions and structures of server NETCONF messages.
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

#ifndef NC_MESSAGES_SERVER_H_
#define NC_MESSAGES_SERVER_H_

#include <stdint.h>

#include "netconf.h"

typedef enum NC_ERROR {
    NC_ERR_UNKNOWN = 0,
    NC_ERR_IN_USE,
    NC_ERR_INVALID_VALUE,
    NC_ERR_TOO_BIG,
    NC_ERR_MISSING_ATTR,
    NC_ERR_BAD_ATTR,
    NC_ERR_UNKNOWN_ATTR,
    NC_ERR_MISSING_ELEM,
    NC_ERR_BAD_ELEM,
    NC_ERR_UNKNOWN_ELEM,
    NC_ERR_UNKNOWN_NS,
    NC_ERR_ACCESS_DENIED,
    NC_ERR_LOCK_DENIED,
    NC_ERR_RES_DENIED,
    NC_ERR_ROLLBACK_FAILED,
    NC_ERR_DATA_EXISTS,
    NC_ERR_DATA_MISSING,
    NC_ERR_OP_NOT_SUPPORTED,
    NC_ERR_OP_FAILED,
    NC_ERR_MALFORMED_MSG
} NC_ERR;

typedef enum NC_ERROR_TYPE {
    NC_ERR_TYPE_UNKNOWN = 0,
    NC_ERR_TYPE_TRAN,
    NC_ERR_TYPE_RPC,
    NC_ERR_TYPE_PROT,
    NC_ERR_TYPE_APP
} NC_ERR_TYPE;

/**
 * @brief NETCONF server RPC reply object
 */
struct nc_server_reply;

struct nc_server_error;

struct nc_server_reply *nc_server_reply_ok(void);

struct nc_server_reply *nc_server_reply_data(struct lyd_node *data, NC_PARAMTYPE paramtype);

struct nc_server_reply *nc_server_reply_err(struct ly_ctx *ctx, struct nc_server_error *err);

int nc_server_reply_add_err(struct nc_server_reply *reply, struct nc_server_error *err);

struct nc_server_error *nc_err(struct ly_ctx *ctx, NC_ERR tag, ...);

int nc_err_set_app_tag(struct ly_ctx *ctx, struct nc_server_error *err, const char *error_app_tag);

int nc_err_set_path(struct ly_ctx *ctx, struct nc_server_error *err, const char *error_path);

int nc_err_set_msg(struct ly_ctx *ctx, struct nc_server_error *err, const char *error_message, const char *lang);

int nc_err_set_sid(struct nc_server_error *err, uint32_t session_id);

int nc_err_add_bad_attr(struct ly_ctx *ctx, struct nc_server_error *err, const char *attr_name);

int nc_err_add_bad_elem(struct ly_ctx *ctx, struct nc_server_error *err, const char *elem_name);

int nc_err_add_bad_ns(struct ly_ctx *ctx, struct nc_server_error *err, const char *ns_name);

int nc_err_add_info_other(struct nc_server_error *err, struct lyxml_elem *other);

void nc_server_reply_free(struct nc_server_reply *reply);

void nc_err_free(struct ly_ctx *ctx, struct nc_server_error *err);

#endif /* NC_MESSAGES_SERVER_H_ */
