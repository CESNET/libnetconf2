/**
 * @file netconf.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief libnetconf2's general public functions and structures definitions.
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

#ifndef NC_NETCONF_H_
#define NC_NETCONF_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup misc
 * @{
 */

/** @brief Base NETCONF namespace */
#define NC_NS_BASE  "urn:ietf:params:xml:ns:netconf:base:1.0"
/** @brief Notifications namespace */
#define NC_NS_NOTIF "urn:ietf:params:xml:ns:netconf:notification:1.0"

/** @brief Default NETCONF over SSH port */
#define NC_PORT_SSH 830
/** @brief Default NETCONF over SSH Call Home port */
#define NC_PORT_CH_SSH 4334

/** @brief Default NETCONF over TLS port */
#define NC_PORT_TLS 6513
/** @brief Default NETCONF over TLS Call Home port */
#define NC_PORT_CH_TLS 4335

/**
 * @brief Set RPC callback to a schema node.
 *
 * @param[in] node const struct lysc_node *node
 * @param[in] cb nc_rpc_clb cb
 */
#define nc_set_rpc_callback(node, cb) (node->priv = cb)

/**
 * @brief Enumeration of reasons of the NETCONF session termination as defined in RFC 6470.
 */
typedef enum NC_SESSION_TERM_REASON {
    NC_SESSION_TERM_ERR = -1,     /**< error return code for function getting the session termination reason */
    NC_SESSION_TERM_NONE = 0,     /**< session still running */
    NC_SESSION_TERM_CLOSED,       /**< closed by client in a normal fashion */
    NC_SESSION_TERM_KILLED,       /**< session was terminated by \<kill-session\> operation */
    NC_SESSION_TERM_DROPPED,      /**< transport layer connection was unexpectedly closed */
    NC_SESSION_TERM_TIMEOUT,      /**< terminated because of inactivity */
    NC_SESSION_TERM_BADHELLO,     /**< \<hello\> message was invalid */
    NC_SESSION_TERM_OTHER         /**< terminated for some other reason */
} NC_SESSION_TERM_REASON;

/**
 * @brief Enumeration of NETCONF message types.
 */
typedef enum NC_MSG_TYPE {
    NC_MSG_ERROR,           /**< error return value */
    NC_MSG_WOULDBLOCK,      /**< timeout return value */
    NC_MSG_NONE,            /**< no message at input or message was processed internally */
    NC_MSG_HELLO,           /**< \<hello\> message */
    NC_MSG_BAD_HELLO,       /**< \<hello\> message parsing failed */
    NC_MSG_RPC,             /**< \<rpc\> message */
    NC_MSG_REPLY,           /**< \<rpc-reply\> message */
    NC_MSG_REPLY_ERR_MSGID, /**< \<rpc-reply\> message with missing or wrong message-id attribute value */
    NC_MSG_NOTIF            /**< \<notification\> message */
} NC_MSG_TYPE;

/**
 * @brief Messages of NETCONF message type enum.
 */
extern const char *nc_msgtype2str[];

/**
 * @brief Enumeration of the supported types of datastores defined by NETCONF
 */
typedef enum NC_DATASTORE_TYPE {
    NC_DATASTORE_ERROR = 0, /**< error state of functions returning the datastore type */
    NC_DATASTORE_CONFIG,    /**< value describing that the datastore is set as config */
    NC_DATASTORE_URL,       /**< value describing that the datastore data should be given from the URL */
    NC_DATASTORE_RUNNING,   /**< base NETCONF's datastore containing the current device configuration */
    NC_DATASTORE_STARTUP,   /**< separated startup datastore as defined in Distinct Startup Capability */
    NC_DATASTORE_CANDIDATE  /**< separated working datastore as defined in Candidate Configuration Capability */
} NC_DATASTORE;

/**
 * @brief Enumeration of NETCONF with-defaults capability modes.
 */
typedef enum NC_WITHDEFAULTS_MODE {
    NC_WD_UNKNOWN = 0,    /**< invalid mode */
    NC_WD_ALL,            /**< report-all mode */
    NC_WD_ALL_TAG,        /**< report-all-tagged mode */
    NC_WD_TRIM,           /**< trim mode */
    NC_WD_EXPLICIT        /**< explicit mode */
} NC_WD_MODE;

/**
 * @brief Enumeration of NETCONF (both server and client) rpc-reply types.
 */
typedef enum NC_REPLY {
    NC_RPL_OK,    /**< OK rpc-reply */
    NC_RPL_DATA,  /**< DATA rpc-reply */
    NC_RPL_ERROR, /**< ERROR rpc-reply */
    NC_RPL_NOTIF  /**< notification (client-only) */
} NC_RPL;

/**
 * @brief Enumeration of function parameter treatments.
 */
typedef enum NC_PARAMTYPE {
    NC_PARAMTYPE_CONST,       /**< use the parameter directly, do not free */
    NC_PARAMTYPE_FREE,        /**< use the parameter directly, free afterwards */
    NC_PARAMTYPE_DUP_AND_FREE /**< make a copy of the argument, free afterwards */
} NC_PARAMTYPE;

/** @} Miscellaneous */

#ifdef __cplusplus
}
#endif

#endif /* NC_NETCONF_H_ */
