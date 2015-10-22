/**
 * \file session.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 session manipulation
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

#ifndef NC_SESSION_H_
#define NC_SESSION_H_

#include <stdint.h>

#ifdef ENABLE_LIBSSH
#   include <libssh/libssh.h>
#endif /* ENABLE_LIBSSH */

#ifdef ENABLE_TLS
#   include <openssl/ssl.h>
#endif /* ENABLE_TLS */

#include "messages.h"

/**
 * @brief Enumeration of possible session statuses
 */
typedef enum {
    NC_STATUS_STARTING, /**< session is not yet fully initiated */
    NC_STATUS_CLOSING,  /**< session is being closed */
    NC_STATUS_INVALID,  /**< session is corrupted and it is supposed to be closed (nc_session_free()) */
    NC_STATUS_RUNNING   /**< up and running */
} NC_STATUS;

/**
 * @brief NETCONF session object
 */
struct nc_session;

#ifdef NC_CLIENT_H_

/**
 * @brief Set location where libnetconf tries to search for YANG/YIN schemas.
 *
 * The location is search when connecting to a NETCONF server and building
 * YANG context for further processing of the NETCONF messages and data.
 *
 * Function is provided only via nc_client.h header file.
 *
 * @param[in] path Directory where to search for YANG/YIN schemas.
 * @return 0 on success, 1 on (memory allocation) failure.
 */
int nc_schema_searchpath(const char *path);

/**
 * @brief Connect to the NETCONF server via proviaded input/output file descriptors.
 *
 * Transport layer is supposed to be already set. Function do not cover authentication
 * or any other manipulation with the transport layer, it only establish NETCONF session
 * by sending and processing NETCONF \<hello\> messages.
 *
 * Function is provided only via nc_client.h header file.
 *
 * @param[in] fdin Input file descriptor for reading (clear) data from NETCONF server.
 * @param[in] fdout Output file descriptor for writing (clear) data for NETCONF server.
 * @param[in] ctx Optional parameter. If set, provides strict YANG context for the session
 *                (ignoring what is actually supported by the server side). If not set,
 *                YANG context is created for the session using \<get-schema\> (if supported
 *                by the server side) or/and by searching for YANG schemas in the searchpath
 *                (see nc_schema_searchpath()).
 * @return Created NETCONF session object or NULL in case of error.
 */
struct nc_session *nc_connect_inout(int fdin, int fdout, struct ly_ctx *ctx);

#ifdef ENABLE_LIBSSH

/**
 * @brief Connect to the NETCONF server using SSH transport (via libssh).
 *
 * SSH session is created with default options. If a caller need to change SSH session properties,
 * it is supposed to use nc_connect_libssh().
 *
 * Function is provided only via nc_client.h header file and only when libnetconf2 is compiled with libssh support.
 *
 * @param[in] host Hostname or address (both Ipv4 and IPv6 are accepted) of the target server.
 *                 'localhost' is used by default if NULL is specified.
 * @param[in] port Port number of the target server. Default value 830 is used if 0 is specified.
 * @param[in] username Name of the user to login to the server. The user running the application (detected from the
 *                 effective UID) is used if NULL is specified.
 * @param[in] ctx Optional parameter. If set, provides strict YANG context for the session
 *                (ignoring what is actually supported by the server side). If not set,
 *                YANG context is created for the session using \<get-schema\> (if supported
 *                by the server side) or/and by searching for YANG schemas in the searchpath
 *                (see nc_schema_searchpath()).
 * @return Created NETCONF session object or NULL in case of error.
 */
struct nc_session *nc_connect_ssh(const char *host, unsigned short port, const char* username, struct ly_ctx *ctx);

/**
 * @brief Connect to the NETCONF server using the provided SSH (libssh) session.
 *
 * Function is provided only via nc_client.h header file and only when libnetconf2 is compiled with libssh support.
 *
 * @param[in] ssh_session libssh structure representing SSH session object.
 * @param[in] ctx Optional parameter. If set, provides strict YANG context for the session
 *                (ignoring what is actually supported by the server side). If not set,
 *                YANG context is created for the session using \<get-schema\> (if supported
 *                by the server side) or/and by searching for YANG schemas in the searchpath
 *                (see nc_schema_searchpath()).
 * @return Created NETCONF session object or NULL in case of error.
 */
struct nc_session *nc_connect_libssh(ssh_session *ssh_session, struct ly_ctx *ctx);

/**
 * @brief Create another NETCONF session on existing SSH session using separated SSH channel.
 *
 * Function is provided only via nc_client.h header file and only when libnetconf2 is compiled with libssh support.
 *
 * @param[in] session Existing NETCONF session. The session has to be created on SSH transport layer using libssh -
 *                    it has to be created by nc_connect_ssh(), nc_connect_libssh() or nc_connect_ssh_channel().
 * @return Created NETCONF session object or NULL in case of error.
 */
struct nc_session *nc_connect_ssh_channel(struct nc_session *session);

#endif /* ENABLE_LIBSSH */

#ifdef ENABLE_TLS

/**
 * @brief Connect to the NETCONF server using TLS transport (via libssl)
 *
 * TLS session is created with default options. If a caller need to change TLS session properties,
 * it is supposed to use nc_connect_libssl().
 *
 * Function is provided only via nc_client.h header file and only when libnetconf2 is compiled with TLS support.
 *
 * @param[in] host Hostname or address (both Ipv4 and IPv6 are accepted) of the target server.
 *                 'localhost' is used by default if NULL is specified.
 * @param[in] port Port number of the target server. Default value 6513 is used if 0 is specified.
 * @param[in] username Name of the user to login to the server. The user running the application (detected from the
 *                 effective UID) is used if NULL is specified.
 * @param[in] ctx Optional parameter. If set, provides strict YANG context for the session
 *                (ignoring what is actually supported by the server side). If not set,
 *                YANG context is created for the session using \<get-schema\> (if supported
 *                by the server side) or/and by searching for YANG schemas in the searchpath
 *                (see nc_schema_searchpath()).
 * @return Created NETCONF session object or NULL in case of error.
 */
struct nc_session *nc_connect_tls(const char *host, unsigned short port, const char *username, struct ly_ctx *ctx);

/**
 * @brief Connect to the NETCONF server using the provided TLS (libssl) session.
 *
 * Function is provided only via nc_client.h header file and only when libnetconf2 is compiled with TLS support.
 *
 * @param[in] tls libssl structure representing TLS session object.
 * @param[in] ctx Optional parameter. If set, provides strict YANG context for the session
 *                (ignoring what is actually supported by the server side). If not set,
 *                YANG context is created for the session using \<get-schema\> (if supported
 *                by the server side) or/and by searching for YANG schemas in the searchpath
 *                (see nc_schema_searchpath()).
 * @return Created NETCONF session object or NULL in case of error.
 */
struct nc_session *nc_connect_libssl(SSL *tls, struct ly_ctx *ctx);

#endif /* ENABLE_TLS */

#endif /* NC_CLIENT_H_ */

/**
 * @brief Free the NETCONF session object.
 *
 * @param[in] session Object to free.
 */
void nc_session_free(struct nc_session *session);

/**
 * @brief Receive NETCONF RPC.
 *
 * @param[in] session NETCONF session from which the function gets data. It must be the
 *            server side session object.
 * @param[in] timeout Timeout for reading in milliseconds. Use negative value for infinite
 *            waiting and 0 for immediate return if data are not available on wire.
 * @param[out] notif Resulting object of NETCONF RPC.
 * @return NC_MSG_RPC for success, NC_MSG_WOULDBLOCK if timeout reached and NC_MSG_ERROR
 *         when reading has failed.
 */
NC_MSG_TYPE nc_recv_rpc(struct nc_session* session, int timeout, struct nc_rpc_server **rpc);

/**
 * @brief Receive NETCONF RPC reply.
 *
 * @param[in] session NETCONF session from which the function gets data. It must be the
 *            client side session object.
 * @param[in] timeout Timeout for reading in milliseconds. Use negative value for infinite
 *            waiting and 0 for immediate return if data are not available on wire.
 * @param[out] reply Resulting object of NETCONF RPC reply.
 * @return NC_MSG_REPLY for success, NC_MSG_WOULDBLOCK if timeout reached and NC_MSG_ERROR
 *         when reading has failed.
 */
NC_MSG_TYPE nc_recv_reply(struct nc_session* session, int timeout, struct nc_reply **reply);

/**
 * @brief Receive NETCONF Notification.
 *
 * @param[in] session NETCONF session from which the function gets data. It must be the
 *            client side session object.
 * @param[in] timeout Timeout for reading in milliseconds. Use negative value for infinite
 *            waiting and 0 for immediate return if data are not available on wire.
 * @param[out] notif Resulting object of NETCONF Notification.
 * @return NC_MSG_NOTIF for success, NC_MSG_WOULDBLOCK if timeout reached and NC_MSG_ERROR
 *         when reading has failed.
 */
NC_MSG_TYPE nc_recv_notif(struct nc_session* session, int timeout, struct nc_notif **notif);

/**
 * @brief Send NETCONF RPC message via the session.
 *
 * @param[in] session NETCONF session where the RPC will be written.
 * @param[in] rpc NETCOFN RPC object to send via specified session. Object can be created by
              nc_rpc_lock(), nc_rpc_unlock() and nc_rpc_generic() functions.
 * @return #NC_MSG_RPC on success, #NC_MSG_WOULDBLOCK in case of busy session
 * (try to repeat the function call) and #NC_MSG_ERROR in case of error.
 */
NC_MSG_TYPE nc_send_rpc(struct nc_session *session, struct nc_rpc *rpc);

#endif /* NC_SESSION_H_ */
