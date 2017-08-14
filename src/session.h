/**
 * \file session.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 session manipulation
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_SESSION_H_
#define NC_SESSION_H_

#include "netconf.h"

#ifdef NC_ENABLED_SSH

/**
 * @brief Enumeration of NETCONF SSH authentication methods
 */
typedef enum {
    NC_SSH_AUTH_PUBLICKEY = 0x01,  /**< publickey SSH authentication */
    NC_SSH_AUTH_PASSWORD = 0x02,   /**< password SSH authentication */
    NC_SSH_AUTH_INTERACTIVE = 0x04 /**< interactive SSH authentication */
} NC_SSH_AUTH_TYPE;

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

/**
 * @brief Enumeration of cert-to-name mapping types
 */
typedef enum {
    NC_TLS_CTN_UNKNOWN = 0,     /**< unknown mapping */
    NC_TLS_CTN_SPECIFIED,       /**< username explicitly specified */
    NC_TLS_CTN_SAN_RFC822_NAME, /**< email address as username */
    NC_TLS_CTN_SAN_DNS_NAME,    /**< DNS name as username */
    NC_TLS_CTN_SAN_IP_ADDRESS,  /**< IP address as username */
    NC_TLS_CTN_SAN_ANY,         /**< any certificate Subject Alternative Name as username */
    NC_TLS_CTN_COMMON_NAME      /**< common name as username */
} NC_TLS_CTN_MAPTYPE;

#endif /* NC_ENABLED_TLS */

/**
 * @brief Enumeration of possible session statuses
 */
typedef enum {
    NC_STATUS_ERR = -1,   /**< error return code for function getting the session status */
    NC_STATUS_STARTING = 0, /**< session is not yet fully initiated */
    NC_STATUS_CLOSING,      /**< session is being closed */
    NC_STATUS_INVALID,      /**< session is not running and is supposed to be closed (nc_session_free()) */
    NC_STATUS_RUNNING       /**< up and running */
} NC_STATUS;

/**
 * @brief Enumeration of transport implementations (ways how libnetconf implements NETCONF transport protocol)
 */
typedef enum {
    NC_TI_NONE = 0,   /**< none - session is not connected yet */
    NC_TI_FD,         /**< file descriptors - use standard input/output, transport protocol is implemented
                           outside the current application */
#ifdef NC_ENABLED_SSH
    NC_TI_LIBSSH,     /**< libssh - use libssh library, only for NETCONF over SSH transport */
#endif
#ifdef NC_ENABLED_TLS
    NC_TI_OPENSSL     /**< OpenSSL - use OpenSSL library, only for NETCONF over TLS transport */
#endif
} NC_TRANSPORT_IMPL;

/**
 * @brief Enumeration of Call Home connection types.
 */
typedef enum {
    NC_CH_CT_NOT_SET = 0,
    NC_CH_PERSIST,
    NC_CH_PERIOD
} NC_CH_CONN_TYPE;

/**
 * @brief Enumeration of Call Home client priority policy.
 */
typedef enum {
    NC_CH_FIRST_LISTED = 0, //default
    NC_CH_LAST_CONNECTED
} NC_CH_START_WITH;

/**
 * @brief Enumeration of SSH key types.
 */
typedef enum {
    NC_SSH_KEY_UNKNOWN = 0,
    NC_SSH_KEY_DSA,
    NC_SSH_KEY_RSA,
    NC_SSH_KEY_ECDSA
} NC_SSH_KEY_TYPE;

/**
 * @brief NETCONF session object
 */
struct nc_session;

/**
 * @brief Get session status.
 *
 * @param[in] session Session to get the information from.
 * @return Session status.
 */
NC_STATUS nc_session_get_status(const struct nc_session *session);

/**
 * @brief Get session termination reason.
 *
 * @param[in] session Session to get the information from.
 * @return Session termination reason enum value.
 */
NC_SESSION_TERM_REASON nc_session_get_term_reason(const struct nc_session *session);

/**
 * @brief Get session killer session ID.
 *
 * @param[in] session Session to get the information from.
 * @return Session killer ID.
 */
uint32_t nc_session_get_killed_by(const struct nc_session *session);

/**
 * @brief Get session ID.
 *
 * @param[in] session Session to get the information from.
 * @return Session ID.
 */
uint32_t nc_session_get_id(const struct nc_session *session);

/**
 * @brief Get session NETCONF version.
 *
 * @param[in] session Session to get the information from.
 * @return 0 for version 1.0, non-zero for version 1.1.
 */
int nc_session_get_version(const struct nc_session *session);

/**
 * @brief Get session transport used.
 *
 * @param[in] session Session to get the information from.
 * @return Session transport.
 */
NC_TRANSPORT_IMPL nc_session_get_ti(const struct nc_session *session);

/**
 * @brief Get session username.
 *
 * @param[in] session Session to get the information from.
 * @return Session username.
 */
const char *nc_session_get_username(const struct nc_session *session);

/**
 * @brief Get session host.
 *
 * @param[in] session Session to get the information from.
 * @return Session host.
 */
const char *nc_session_get_host(const struct nc_session *session);

/**
 * @brief Get session port.
 *
 * @param[in] session Session to get the information from.
 * @return Session port.
 */
uint16_t nc_session_get_port(const struct nc_session *session);

/**
 * @brief Get session context.
 *
 * @param[in] session Session to get the information from.
 * @return Session context.
 */
struct ly_ctx *nc_session_get_ctx(const struct nc_session *session);

/**
 * @brief Assign arbitrary data to a session.
 *
 * @param[in] session Session to modify.
 * @param[in] data Data to be stored in the session.
 */
void nc_session_set_data(struct nc_session *session, void *data);

/**
 * @brief Get the data assigned to a session.
 *
 * @param[in] session Session to get the data from.
 * @return Session-specific data.
 */
void *nc_session_get_data(const struct nc_session *session);

/**
 * @brief Free the NETCONF session object.
 *
 * @param[in] session Object to free.
 * @param[in] data_free Session user data destructor.
 */
void nc_session_free(struct nc_session *session, void (*data_free)(void *));

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)

/**
 * @brief Free all the dynamically allocated thread-specific libssl/libcrypto
 * resources.
 *
 * This function should be called only if init (nc_client_init(), respectively nc_server_init()) was called.
 * Call it in every thread your application creates just before the thread exits. In the last thread
 * (usually the main one) call nc_client_destroy(), respectively nc_server_destroy().
 */
void nc_thread_destroy(void);

#endif /* NC_ENABLED_SSH || NC_ENABLED_TLS */

#endif /* NC_SESSION_H_ */
