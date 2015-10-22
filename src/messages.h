/**
 * \file messages.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2's public functions and structures of NETCONF messages.
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

#ifndef NC_MESSAGES_H_
#define NC_MESSAGES_H_

typedef enum {
    NC_FILTER_SUBTREE,
    NC_FILTER_XPATH
} NC_FILTER;

struct nc_filter;

/**
 * @brief Create NETCONF filter for \<get\> or \<get-config\> RPCs.
 *
 * The returned object can be used repeatedly. Caller is supposed to free it using nc_filter_free().
 *
 * @param[in] type Filter type of the \p data. #NC_FILTER_SUBTREE and #NC_FILTER_XPATH are supported.
 *                 Note that #NC_FILTER_XPATH is accepted only on sessions supporting the :xpath capability.
 * @param[in] data Content of the filter. Serialized XML data in case of #NC_FILTER_SUBTREE and XPath query
 *                 in case of #NC_FILTER_XPATH (use YANG schema names as namespace prefixes).
 * @param[in] constdata Flag for handling \p data. If set, the \p data is handled as const char* and the string
 *                 is duplicated for internal use. If not set, \p data is not duplicated but caller is supposed
 *                 to forget about the provided string.
 * @return Created filter structure to be used in nc_rpc_getconfig() and nc_rpc_get(). NULL in case of failure.
 */
struct nc_filter *nc_filter_new(NC_FILTER type, char *data, int constdata);

/**
 * @brief Free the NETCONF filter object.
 *
 * @param[in] filter Object to free.
 */
void nc_filter_free(struct nc_filter *filter);

/**
 * @brief NETCONF RPC object
 */
struct nc_rpc;
struct nc_rpc_server;

/**
 * @brief NETCONF RPC reply object
 */
struct nc_reply;

/**
 * @brief NETCONF Notification object
 */
struct nc_notif;

/**
 * @brief Create NETCONF RPC \<get-config\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] source Source datastore being queried.
 * @param[in] filter Optional filter data, see nc_filter_new().
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_getconfig(NC_DATASTORE source, struct nc_filter *filter);

/**
 * @brief Create NETCONF RPC \<lock\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] target Target datastore of the operation.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_lock(NC_DATASTORE target);

/**
 * @brief Create NETCONF RPC \<unlock\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] target Target datastore of the operation.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_unlock(NC_DATASTORE target);

/**
 * @brief Free the NETCONF RPC object.
 * @param[in] rpc Object to free.
 */
void nc_rpc_free(struct nc_rpc *rpc);

/**
 * @brief Free the NETCONF RPC reply object.
 * @param[in] rpc Object to free.
 */
void nc_reply_free(struct nc_reply *reply);

/**
 * @brief Free the NETCONF Notification object.
 * @param[in] rpc Object to free.
 */
void nc_notif_free(struct nc_notif *notif);

#endif /* NC_MESSAGES_H_ */
