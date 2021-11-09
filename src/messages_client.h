/**
 * @file messages_client.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2's public functions and structures of NETCONF client messages.
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

#ifndef NC_MESSAGES_CLIENT_H_
#define NC_MESSAGES_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "netconf.h"

/**
 * @defgroup client_msg Client Messages
 * @ingroup client
 *
 * @brief Functions to create NETCONF RPCs (or actions) and process replies received from the server.
 * @{
 */

/**
 * @brief Enumeration of RPC types
 *
 * Note that NC_RPC_CLOSE is not defined since sending \<close-session\> is done implicitly by nc_session_free()
 */
typedef enum {
    NC_RPC_UNKNOWN = 0, /**< invalid RPC. */
    NC_RPC_ACT_GENERIC, /**< user-defined generic RPC/action. */

    /* ietf-netconf */
    NC_RPC_GETCONFIG,   /**< \<get-config\> RPC. */
    NC_RPC_EDIT,        /**< \<edit-config\> RPC. */
    NC_RPC_COPY,        /**< \<copy-config\> RPC. */
    NC_RPC_DELETE,      /**< \<delete-config\> RPC. */
    NC_RPC_LOCK,        /**< \<lock\> RPC. */
    NC_RPC_UNLOCK,      /**< \<unlock\> RPC. */
    NC_RPC_GET,         /**< \<get\> RPC. */
    NC_RPC_KILL,        /**< \<kill-session\> RPC. */
    NC_RPC_COMMIT,      /**< \<commit\> RPC. */
    NC_RPC_DISCARD,     /**< \<discard-changes\> RPC. */
    NC_RPC_CANCEL,      /**< \<cancel-commit\> RPC. */
    NC_RPC_VALIDATE,    /**< \<validate\> RPC. */

    /* ietf-netconf-monitoring */
    NC_RPC_GETSCHEMA,   /**< \<get-schema\> RPC. */

    /* notifications */
    NC_RPC_SUBSCRIBE,   /**< \<create-subscription\> RPC. */

    /* ietf-netconf-nmda */
    NC_RPC_GETDATA,     /**< \<get-data\> RPC. */
    NC_RPC_EDITDATA,    /**< \<edit-data\> RPC. */

    /* ietf-subscribed-notifications */
    NC_RPC_ESTABLISHSUB,    /**< \<establish-subscription\> RPC. */
    NC_RPC_MODIFYSUB,       /**< \<modify-subscription\> RPC. */
    NC_RPC_DELETESUB,       /**< \<delete-subscription\> RPC. */
    NC_RPC_KILLSUB,         /**< \<kill-subscription\> RPC. */

    /* ietf-yang-push */
    NC_RPC_ESTABLISHPUSH,   /**< \<establish-subscription\> RPC with augments. */
    NC_RPC_MODIFYPUSH,      /**< \<modify-subscription\> RPC with augments. */
    NC_RPC_RESYNCSUB        /**< \<resync-subscription\> RPC. */
} NC_RPC_TYPE;

/**
 * @brief Enumeration of \<edit-config\> default operation
 */
typedef enum {
    NC_RPC_EDIT_DFLTOP_UNKNOWN = 0, /**< unknown default operation */
    NC_RPC_EDIT_DFLTOP_MERGE,       /**< default operation merge */
    NC_RPC_EDIT_DFLTOP_REPLACE,     /**< default operation replace */
    NC_RPC_EDIT_DFLTOP_NONE         /**< default operation none */
} NC_RPC_EDIT_DFLTOP;

/**
 * @brief Enumeration of \<edit-config\> test option
 */
typedef enum {
    NC_RPC_EDIT_TESTOPT_UNKNOWN = 0, /**< unknown test option */
    NC_RPC_EDIT_TESTOPT_TESTSET,     /**< test-then-set option */
    NC_RPC_EDIT_TESTOPT_SET,         /**< set option */
    NC_RPC_EDIT_TESTOPT_TEST         /**< test-only option */
} NC_RPC_EDIT_TESTOPT;

/**
 * @brief Enumeration of \<edit-config\> error option
 */
typedef enum {
    NC_RPC_EDIT_ERROPT_UNKNOWN = 0, /**< unknown error option */
    NC_RPC_EDIT_ERROPT_STOP,        /**< stop-on-error option */
    NC_RPC_EDIT_ERROPT_CONTINUE,    /**< continue-on-error option */
    NC_RPC_EDIT_ERROPT_ROLLBACK     /**< rollback-on-error option */
} NC_RPC_EDIT_ERROPT;

/**
 * @brief NETCONF error structure representation
 */
struct nc_err {
    /** @brief \<error-type\>, error layer where the error occurred. */
    const char *type;
    /** @brief \<error-tag\>. */
    const char *tag;
    /** @brief \<error-severity\>. */
    const char *severity;
    /** @brief \<error-app-tag\>, the data-model-specific or implementation-specific error condition, if one exists. */
    const char *apptag;
    /** @brief \<error-path\>, XPATH expression identifying the element with the error. */
    const char *path;
    /** @brief \<error-message\>, Human-readable description of the error. */
    const char *message;
    /** @brief xml:lang attribute of the error-message. */
    const char *message_lang;

    /* <error-info> */

    /** @brief \<session-id\>, session ID of the session holding the requested lock. Part of \<error-info\>. */
    const char *sid;
    /** @brief \<bad-attr\>, array of the names of the data-model-specific XML attributes that caused the error. Part of \<error-info\>. */
    const char **attr;
    /** @brief \<bad-element\>, array of the names of the data-model-specific XML element that caused the error. Part of \<error-info\>. */
    const char **elem;
    /** @brief \<bad-namespace\>, array of the unexpected XML namespaces that caused the error. Part of \<error-info\>. */
    const char **ns;
    /** @brief List of the remaining non-standard opaque nodes. */
    struct lyd_node *other;

    /** @brief Number of items in the attr array */
    uint16_t attr_count;
    /** @brief Number of items in the elem array */
    uint16_t elem_count;
    /** @brief Number of items in the ns array */
    uint16_t ns_count;
    /** @brief Number of items in the other array */
    uint16_t other_count;
};

/**
 * @struct nc_rpc
 * @brief NETCONF client RPC object
 *
 * Note that any stored parameters are not checked for validity because it is performed later,
 * while sending the RPC via a specific NETCONF session (::nc_send_rpc()) since the NETCONF
 * capabilities of the session are needed for such a check. An RPC object can be sent via any
 * NETCONF session which supports all the needed NETCONF capabilities for the RPC.
 */
struct nc_rpc;

/**
 * @brief Get the type of the RPC
 *
 * @param[in] rpc RPC to check the type of.
 * @return Type of @p rpc.
 */
NC_RPC_TYPE nc_rpc_get_type(const struct nc_rpc *rpc);

/**
 * @brief Create a generic NETCONF RPC or action
 *
 * Note that created object can be sent via any NETCONF session that shares the context
 * of the @p data.
 *
 * @note In case of action, the \<action\> element is added automatically and should not be in @p data.
 *
 * @param[in] data NETCONF RPC data as a data tree.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_act_generic(const struct lyd_node *data, NC_PARAMTYPE paramtype);

/**
 * @brief Create a generic NETCONF RPC or action from an XML string
 *
 * For details, see ::nc_rpc.
 *
 * @note In case of action, the \<action\> element is added automatically and should not be in @p xml_str.
 *
 * @param[in] xml_str NETCONF RPC data as an XML string.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_act_generic_xml(const char *xml_str, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<get-config\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] source Source datastore being queried.
 * @param[in] filter Optional filter data, an XML subtree or XPath expression (with JSON prefixes).
 * @param[in] wd_mode Optional with-defaults capability mode.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_getconfig(NC_DATASTORE source, const char *filter, NC_WD_MODE wd_mode,
        NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<edit-config\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] target Target datastore being edited.
 * @param[in] default_op Optional default operation.
 * @param[in] test_opt Optional test option.
 * @param[in] error_opt Optional error option.
 * @param[in] edit_content Config or URL where the config to perform is to be found.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_edit(NC_DATASTORE target, NC_RPC_EDIT_DFLTOP default_op, NC_RPC_EDIT_TESTOPT test_opt,
        NC_RPC_EDIT_ERROPT error_opt, const char *edit_content, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<copy-config\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] target Target datastore.
 * @param[in] url_trg Used instead @p target if the target is an URL.
 * @param[in] source Source datastore.
 * @param[in] url_or_config_src Used instead @p source if the source is an URL or a config.
 * @param[in] wd_mode Optional with-defaults capability mode.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_copy(NC_DATASTORE target, const char *url_trg, NC_DATASTORE source,
        const char *url_or_config_src, NC_WD_MODE wd_mode, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<delete-config\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] target Target datastore to delete.
 * @param[in] url Used instead @p target if the target is an URL.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_delete(NC_DATASTORE target, const char *url, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<lock\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] target Target datastore of the operation.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_lock(NC_DATASTORE target);

/**
 * @brief Create NETCONF RPC \<unlock\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] target Target datastore of the operation.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_unlock(NC_DATASTORE target);

/**
 * @brief Create NETCONF RPC \<get\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] filter Optional filter data, an XML subtree or XPath expression (with JSON prefixes).
 * @param[in] wd_mode Optional with-defaults capability mode.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_get(const char *filter, NC_WD_MODE wd_mode, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<kill-session\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] session_id Session ID of the session to kill.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_kill(uint32_t session_id);

/**
 * @brief Create NETCONF RPC \<commit\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] confirmed Whether the commit is to be confirmed.
 * @param[in] confirm_timeout Optional confirm timeout.
 * @param[in] persist Optional identification string of a new persistent confirmed commit.
 * @param[in] persist_id Optional identification string of a persistent confirmed commit to be commited.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_commit(int confirmed, uint32_t confirm_timeout, const char *persist, const char *persist_id,
        NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<discard-changes\>
 *
 * For details, see ::nc_rpc.
 *
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_discard(void);

/**
 * @brief Create NETCONF RPC \<cancel-commit\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] persist_id Optional identification string of a persistent confirmed commit.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_cancel(const char *persist_id, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<validate\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] source Source datastore being validated.
 * @param[in] url_or_config Used instead @p source if the source is an URL or a config.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_validate(NC_DATASTORE source, const char *url_or_config, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<get-schema\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] identifier Requested model identifier.
 * @param[in] version Optional model version, either YANG version (1.0/1.1) or revision date.
 * @param[in] format Optional format of the model (default is YANG).
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_getschema(const char *identifier, const char *version, const char *format, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<create-subscription\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] stream_name Optional name of a NETCONF stream to subscribe to.
 * @param[in] filter Optional filter data, an XML subtree or XPath expression (with JSON prefixes).
 * @param[in] start_time Optional YANG datetime identifying the start of the subscription.
 * @param[in] stop_time Optional YANG datetime identifying the end of the subscription.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_subscribe(const char *stream_name, const char *filter, const char *start_time,
        const char *stop_time, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<get-data\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] datastore Source datastore, foreign identity so a module name prefix is required.
 * @param[in] filter Optional filter data, an XML subtree or XPath expression (with JSON prefixes).
 * @param[in] config_filter Optional config filter, "true" for config-only data, "false" for state-only data.
 * @param[in] origin_filter Optional origin filter array, selects only nodes of this or derived origin.
 * @param[in] origin_filter_count Count of filters is @p origin_filter.
 * @param[in] neg_origin_filter Whether origin filters are negated or not.
 * @param[in] max_depth Maximum depth of returned subtrees, 0 for unlimited.
 * @param[in] with_origin Whether return data origin.
 * @param[in] wd_mode Optional with-defaults capability mode.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_getdata(const char *datastore, const char *filter, const char *config_filter, char **origin_filter,
        int origin_filter_count, int neg_origin_filter, uint16_t max_depth, int with_origin, NC_WD_MODE wd_mode,
        NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<get-data\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] datastore Source datastore, foreign identity so a module name prefix is required.
 * @param[in] default_op Optional default operation.
 * @param[in] edit_content Config or URL where the config to perform is to be found.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_editdata(const char *datastore, NC_RPC_EDIT_DFLTOP default_op, const char *edit_content,
        NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<establish-subscription\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] filter Optional filter data, an XML subtree, XPath expression (with JSON prefixes),
 * or filter reference, selected based on the first character.
 * @param[in] stream_name Name of a NETCONF stream to subscribe to.
 * @param[in] start_time Optional YANG datetime identifying the start of the subscription.
 * @param[in] stop_time Optional YANG datetime identifying the end of the subscription.
 * @param[in] encoding Optional specific encoding to use.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_establishsub(const char *filter, const char *stream_name, const char *start_time,
        const char *stop_time, const char *encoding, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<modify-subscription\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] id Subscription ID to modify.
 * @param[in] filter Optional new filter data, an XML subtree, XPath expression (with JSON prefixes),
 * or filter reference, selected based on the first character.
 * @param[in] stop_time Optional new YANG datetime identifying the end of the subscription.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_modifysub(uint32_t id, const char *filter, const char *stop_time, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<delete-subscription\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] id Subscription ID to delete.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_deletesub(uint32_t id);

/**
 * @brief Create NETCONF RPC \<kill-subscription\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] id Subscription ID to kill.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_killsub(uint32_t id);

/**
 * @brief Create NETCONF RPC \<establish-subscription\> with augments from ietf-yang-push for a periodic subscription
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] datastore Source datastore, foreign identity so a module name prefix is required.
 * @param[in] filter Optional filter data, an XML subtree, XPath expression (with JSON prefixes),
 * or filter reference, selected based on the first character.
 * @param[in] stop_time Optional YANG datetime identifying the end of the subscription.
 * @param[in] encoding Optional specific encoding to use.
 * @param[in] period Subscription period in centiseconds (0.01s).
 * @param[in] anchor_time Optional anchor datetime for the period.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_establishpush_periodic(const char *datastore, const char *filter, const char *stop_time,
        const char *encoding, uint32_t period, const char *anchor_time, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<establish-subscription\> with augments from ietf-yang-push for an on-change subscription
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] datastore Source datastore, foreign identity so a module name prefix is required.
 * @param[in] filter Optional filter data, an XML subtree, XPath expression (with JSON prefixes),
 * or filter reference, selected based on the first character.
 * @param[in] stop_time Optional YANG datetime identifying the end of the subscription.
 * @param[in] encoding Optional specific encoding to use.
 * @param[in] dampening_period Optional dampening period of the notifications.
 * @param[in] sync_on_start Whether to send a full push-update notification on subscription start.
 * @param[in] excluded_change Optional NULL-terminated array of excluded changes.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_establishpush_onchange(const char *datastore, const char *filter, const char *stop_time,
        const char *encoding, uint32_t dampening_period, int sync_on_start, const char **excluded_change,
        NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<modify-subscription\> with augments from ietf-yang-push for a periodic subscription
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] id Subscription ID to modify.
 * @param[in] datastore Source datastore, foreign identity so a module name prefix is required.
 * @param[in] filter Optional filter data, an XML subtree, XPath expression (with JSON prefixes),
 * or filter reference, selected based on the first character.
 * @param[in] stop_time Optional YANG datetime identifying the end of the subscription.
 * @param[in] period Subscription period in centiseconds (0.01s).
 * @param[in] anchor_time Optional anchor datetime for the period.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_modifypush_periodic(uint32_t id, const char *datastore, const char *filter, const char *stop_time,
        uint32_t period, const char *anchor_time, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<modify-subscription\> with augments from ietf-yang-push for an on-change subscription
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] id Subscription ID to modify.
 * @param[in] datastore Source datastore, foreign identity so a module name prefix is required.
 * @param[in] filter Optional filter data, an XML subtree, XPath expression (with JSON prefixes),
 * or filter reference, selected based on the first character.
 * @param[in] stop_time Optional YANG datetime identifying the end of the subscription.
 * @param[in] dampening_period Optional dampening period of the notifications.
 * @param[in] paramtype How to further manage data parameters.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_modifypush_onchange(uint32_t id, const char *datastore, const char *filter, const char *stop_time,
        uint32_t dampening_period, NC_PARAMTYPE paramtype);

/**
 * @brief Create NETCONF RPC \<resync-subscription\>
 *
 * For details, see ::nc_rpc.
 *
 * @param[in] id Subscription ID to resync.
 * @return Created RPC object to send via a NETCONF session or NULL in case of (memory allocation) error.
 */
struct nc_rpc *nc_rpc_resyncsub(uint32_t id);

/**
 * @brief Free the NETCONF RPC object.
 *
 * @param[in] rpc Object to free.
 */
void nc_rpc_free(struct nc_rpc *rpc);

/** @} Client Messages */

#ifdef __cplusplus
}
#endif

#endif /* NC_MESSAGES_CLIENT_H_ */
