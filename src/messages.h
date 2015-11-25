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
    NC_RPC_EDIT_DFLTOP_UNKNOWN = 0,
    NC_RPC_EDIT_DFLTOP_MERGE,
    NC_RPC_EDIT_DFLTOP_REPLACE,
    NC_RPC_EDIT_DFLTOP_NONE
} NC_RPC_EDIT_DFLTOP;

typedef enum {
    NC_RPC_EDIT_TESTOPT_UNKOWN = 0,
    NC_RPC_EDIT_TESTOPT_TESTSET,
    NC_RPC_EDIT_TESTOPT_SET,
    NC_RPC_EDIT_TESTOPT_TEST
} NC_RPC_EDIT_TESTOPT;

typedef enum {
    NC_RPC_EDIT_ERROPT_UNKNOWN = 0,
    NC_RPC_EDIT_ERROPT_STOP,
    NC_RPC_EDIT_ERROPT_CONTINUE,
    NC_RPC_EDIR_ERROPT_ROLLBACK
} NC_RPC_EDIT_ERROPT;

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
 * @brief Create a generic NETCONF RPC
 *
 * Note that created object can be sent via any NETCONF session that shares the context
 * of the \p data.
 *
 * @param[in] data NETCONF RPC data. Their ownership is passed to the RPC (they are freed with it).
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_generic(struct lyd_node *data);

/**
 * @brief Create a generic NETCONF RPC from an XML string
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] data NETCONF RPC data. Their ownership is passed to the RPC (they are freed with it).
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_generic_xml(const char *xml_str);

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
 * @brief Create NETCONF RPC \<edit-config\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] target Target datastore being edited.
 * @param[in] default_op Optional default operation.
 * @param[in] test_opt Optional test option.
 * @param[in] error_opt Optional error option.
 * @param[in] edit_content Config or URL where the config to perform is to be found.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_edit(NC_DATASTORE target, NC_RPC_EDIT_DFLTOP default_op, NC_RPC_EDIT_TESTOPT test_opt,
                           NC_RPC_EDIT_ERROPT error_opt, const char *edit_content);

/**
 * @brief Create NETCONF RPC \<copy-config\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] target Target datastore.
 * @param[in] url_trg Used instead \p target if the target is an URL.
 * @param[in] source Source datastore.
 * @param[in] url_or_config_src Used instead \p source if the source is an URL or a config.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_copy(NC_DATASTORE target, const char *url_trg, NC_DATASTORE source, const char *url_or_config_src);

/**
 * @brief Create NETCONF RPC \<delete-config\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] target Target datastore to delete.
 * @param[in] url Used instead \p target if the target is an URL.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_delete(NC_DATASTORE target, char *url);

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
 * @brief Create NETCONF RPC \<get\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] filter Optional filter data, see nc_filter_new().
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_get(struct nc_filter *filter);

/**
 * @brief Create NETCONF RPC \<kill-session\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] session_id Session ID of the session to kill.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_kill(uint32_t session_id);

/**
 * @brief Create NETCONF RPC \<commit\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] confirmed Whether the commit is to be confirmed.
 * @param[in] confirm_timeout Optional confirm timeout.
 * @param[in] persist Optional identification string of a new persistent confirmed commit.
 * @param[in] persist_id Optional identification string of a persistent confirmed commit to be commited.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_commit(int confirmed, uint32_t confirm_timeout, const char *persist, const char *persist_id);

/**
 * @brief Create NETCONF RPC \<discard-changes\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_discard(void);

/**
 * @brief Create NETCONF RPC \<cancel-commit\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] persist_id Optional identification string of a persistent confirmed commit.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_cancel(const char *persist_id);

/**
 * @brief Create NETCONF RPC \<validate\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] source Source datastore being validated.
 * @param[in] url_or_config Usedn instead \p source if the source is an URL or a config.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_validate(NC_DATASTORE source, const char *url_or_config);

/**
 * @brief Create NETCONF RPC \<get-schema\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] identifier Requested model identifier.
 * @param[in] version Optional model version, either YANG version (1.0/1.1) or revision date.
 * @param[in] format Optional format of the model (default is YANG).
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_getschema(const char *identifier, const char *version, const char *format);

/**
 * @brief Create NETCONF RPC \<create-subscription\>
 *
 * Note that functions to create any RPC object do not check validity of the provided
 * parameters. It is checked later while sending the RPC via a specific NETCONF session
 * (nc_send_rpc()) since the NETCONF capabilities of the session are needed for such a
 * check. Created object can be sent via any NETCONF session which supports all the
 * needed NETCONF capabilities for the RPC.
 *
 * @param[in] stream_name Optional name of a NETCONF stream to subscribe to.
 * @param[in] filter Optional filter data, see nc_filter_new().
 * @param[in] start_time Optional YANG datetime identifying the start of the subscription.
 * @param[in] stop_time Optional YANG datetime identifying the end of the subscription.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_subscribe(const char *stream_name, struct nc_filter *filter, const char *start_time,
								const char *stop_time);

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
