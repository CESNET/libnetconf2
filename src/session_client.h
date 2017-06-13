/**
 * \file session_client.h
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 session client manipulation
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_SESSION_CLIENT_H_
#define NC_SESSION_CLIENT_H_

#include <libyang/libyang.h>

#ifdef NC_ENABLED_SSH

#include <libssh/libssh.h>

#endif

#ifdef NC_ENABLED_TLS

#include <openssl/ssl.h>

#endif

#include "session.h"
#include "netconf.h"
#include "messages_client.h"

/**
 * @addtogroup client
 * @{
 */

/**
 * @brief Set location where libnetconf tries to search for YANG/YIN schemas.
 *
 * The location is searched when connecting to a NETCONF server and building
 * YANG context for further processing of the NETCONF messages and data.
 *
 * The searchpath is also used to store schemas retreived via \<get-schema\>
 * operation - if the schema is not found in searchpath neither via schema
 * callback provided via nc_client_set_schema_callback() and server supports
 * the NETCONF \<get-schema\> operation, the schema is retrieved this way and
 * stored into the searchpath (if specified).
 *
 * @param[in] path Directory where to search for YANG/YIN schemas.
 * @return 0 on success, 1 on (memory allocation) failure.
 */
int nc_client_set_schema_searchpath(const char *path);

/**
 * @brief Get schema searchpath that was set by nc_client_set_schema_searchpath().
 *
 * @return Schema searchpath directory, NULL if not set.
 */
const char *nc_client_get_schema_searchpath(void);

/**
 * @brief Set callback function to get missing schemas.
 *
 * @param[in] clb Callback responsible for returning the missing model.
 * @param[in] user_data Arbitrary data that will always be passed to the callback \p clb.
 * @return 0 on success, 1 on (memory allocation) failure.
 */
int nc_client_set_schema_callback(ly_module_imp_clb clb, void *user_data);

/**
 * @brief Get callback function used to get missing schemas.
 *
 * @param[out] user_data Optionally return the private data set with the callback.
 * Note that the caller is responsible for freeing the private data, so before
 * changing the callback, private data used for the previous callback should be
 * freed.
 * @return Pointer to the set callback, NULL if no such callback was set.
 */
ly_module_imp_clb nc_client_get_schema_callback(void **user_data);

/**
 * @brief Use the provided thread-specific client's context in the current thread.
 *
 * Note that from this point the context is shared with the thread from which the context was taken and any
 * nc_client_*set* functions and functions creating connection in these threads should be protected from the
 * concurrent execution.
 *
 * Context contains schema searchpath/callback, call home binds, TLS and SSH authentication data (username, keys,
 * various certificates and callbacks).
 *
 * @param[in] context Client's thread-specific context provided by nc_client_get_thread_context().
 */
void nc_client_set_thread_context(void *context);

/**
 * @brief Get thread-specific client context for sharing with some other thread using
 * nc_client_set_thread_context().
 *
 * @return Pointer to the client's context of the current thread.
 */
void *nc_client_get_thread_context(void);

/**
 * @brief Initialize libssh and/or libssl/libcrypto for use in the client.
 */
void nc_client_init(void);

/**
 * @brief Destroy all libssh and/or libssl/libcrypto dynamic memory and
 *        the client options, for both SSH and TLS, and for Call Home too.
 */
void nc_client_destroy(void);

/**@} Client */

/**
 * @defgroup client_session Client Session
 * @ingroup client
 *
 * @brief Client-side NETCONF session manipulation.
 * @{
 */

/**
 * @brief Connect to the NETCONF server via proviaded input/output file descriptors.
 *
 * Transport layer is supposed to be already set. Function do not cover authentication
 * or any other manipulation with the transport layer, it only establish NETCONF session
 * by sending and processing NETCONF \<hello\> messages.
 *
 * @param[in] fdin Input file descriptor for reading (clear) data from NETCONF server.
 * @param[in] fdout Output file descriptor for writing (clear) data for NETCONF server.
 * @param[in] ctx Optional parameter. If set, provides strict YANG context for the session
 *                (ignoring what is actually supported by the server side). If not set,
 *                YANG context is created for the session using \<get-schema\> (if supported
 *                by the server side) or/and by searching for YANG schemas in the searchpath
 *                (see nc_client_schema_searchpath()). In every case except not providing context
 *                to connect to a server supporting \<get-schema\> it is possible that
 *                the session context will not include all the models supported by the server.
 * @return Created NETCONF session object or NULL in case of error.
 */
struct nc_session *nc_connect_inout(int fdin, int fdout, struct ly_ctx *ctx);

/**@} Client Session */

#ifdef NC_ENABLED_SSH

/**
 * @defgroup client_ssh Client SSH
 * @ingroup client
 *
 * @brief Client-side settings for SSH connections.
 * @{
 */

/**
 * @brief Set SSH authentication hostkey check (knownhosts) callback.
 *
 * Repetitive calling causes replacing of the previous callback and its private data. Caller is responsible for
 * freeing the private data when necessary (the private data can be obtained by
 * nc_client_ssh_get_auth_hostkey_check_clb()).
 *
 * @param[in] auth_hostkey_check Function to call, returns 0 on success, non-zero in error.
 *                               If NULL, the default callback is set.
 * @param[in] priv Optional private data to be passed to the callback function.
 */
void nc_client_ssh_set_auth_hostkey_check_clb(int (*auth_hostkey_check)(const char *hostname, ssh_session session, void *priv),
                                              void *priv);

/**
 * @brief Get currently set SSH authentication hostkey check (knownhosts) callback and its private data previously set
 * by nc_client_ssh_set_auth_hostkey_check_clb().
 *
 * @param[out] auth_hostkey_check Currently set callback, NULL in case of the default callback.
 * @param[out] priv Currently set (optional) private data to be passed to the callback function.
 */
void nc_client_ssh_get_auth_hostkey_check_clb(int (**auth_hostkey_check)(const char *hostname, ssh_session session, void *priv),
                                              void **priv);

/**
 * @brief Set SSH password authentication callback.
 *
 * Repetitive calling causes replacing of the previous callback and its private data. Caller is responsible for
 * freeing the private data when necessary (the private data can be obtained by
 * nc_client_ssh_get_auth_password_clb()).
 *
 * @param[in] auth_password Function to call, returns the password for username\@hostname.
 *                          If NULL, the default callback is set.
 * @param[in] priv Optional private data to be passed to the callback function.
 */
void nc_client_ssh_set_auth_password_clb(char *(*auth_password)(const char *username, const char *hostname, void *priv),
                                         void *priv);

/**
 * @brief Get currently set SSH password authentication callback and its private data previously set
 * by nc_client_ssh_set_auth_password_clb().
 *
 * @param[out] auth_password Currently set callback, NULL in case of the default callback.
 * @param[out] priv Currently set (optional) private data to be passed to the callback function.
 */
void nc_client_ssh_get_auth_password_clb(char *(**auth_password)(const char *username, const char *hostname, void *priv),
                                         void **priv);

/**
 * @brief Set SSH interactive authentication callback.
 *
 * Repetitive calling causes replacing of the previous callback and its private data. Caller is responsible for
 * freeing the private data when necessary (the private data can be obtained by
 * nc_client_ssh_get_auth_interactive_clb()).
 *
 * @param[in] auth_interactive Function to call for every question, returns the answer for
 *                             authentication name with instruction and echoing prompt.
 *                             If NULL, the default callback is set.
 * @param[in] priv Optional private data to be passed to the callback function.
 */
void nc_client_ssh_set_auth_interactive_clb(char *(*auth_interactive)(const char *auth_name, const char *instruction,
                                                                      const char *prompt, int echo, void *priv),
                                            void *priv);

/**
 * @brief Get currently set SSH interactive authentication callback and its private data previously set
 * by nc_client_ssh_set_auth_interactive_clb().
 *
 * @param[out] auth_interactive Currently set callback, NULL in case of the default callback.
 * @param[out] priv Currently set (optional) private data to be passed to the callback function.
 */
void nc_client_ssh_get_auth_interactive_clb(char *(**auth_interactive)(const char *auth_name, const char *instruction,
                                                                       const char *prompt, int echo, void *priv),
                                            void **priv);

/**
 * @brief Set SSH publickey authentication encrypted private key passphrase callback.
 *
 * Repetitive calling causes replacing of the previous callback and its private data. Caller is responsible for
 * freeing the private data when necessary (the private data can be obtained by
 * nc_client_ssh_get_auth_privkey_passphrase_clb()).
 *
 * @param[in] auth_privkey_passphrase Function to call for every question, returns
 *                                    the passphrase for the specific private key.
 * @param[in] priv Optional private data to be passed to the callback function.
 */
void nc_client_ssh_set_auth_privkey_passphrase_clb(char *(*auth_privkey_passphrase)(const char *privkey_path, void *priv),
                                                   void *priv);

/**
 * @brief Get currently set SSH publickey authentication encrypted private key passphrase callback and its private data
 * previously set by nc_client_ssh_set_auth_privkey_passphrase_clb().
 *
 * @param[out] auth_privkey_passphrase Currently set callback, NULL in case of the default callback.
 * @param[out] priv Currently set (optional) private data to be passed to the callback function.
 */
void nc_client_ssh_get_auth_privkey_passphrase_clb(char *(**auth_privkey_passphrase)(const char *privkey_path, void *priv),
                                                   void **priv);

/**
 * @brief Add an SSH public and private key pair to be used for client authentication.
 *
 * Private key can be encrypted, the passphrase will be asked for before using it.
 *
 * @param[in] pub_key Path to the public key.
 * @param[in] priv_key Path to the private key.
 * @return 0 on success, -1 on error.
 */
int nc_client_ssh_add_keypair(const char *pub_key, const char *priv_key);

/**
 * @brief Remove an SSH public and private key pair that was used for client authentication.
 *
 * @param[in] idx Index of the keypair starting with 0.
 * @return 0 on success, -1 on error.
 */
int nc_client_ssh_del_keypair(int idx);

/**
 * @brief Get the number of public an private key pairs set to be used for client authentication.
 *
 * @return Keypair count.
 */
int nc_client_ssh_get_keypair_count(void);

/**
 * @brief Get a specific keypair set to be used for client authentication.
 *
 * @param[in] idx Index of the specific keypair.
 * @param[out] pub_key Path to the public key.
 * @param[out] priv_key Path to the private key.
 * @return 0 on success, -1 on error.
 */
int nc_client_ssh_get_keypair(int idx, const char **pub_key, const char **priv_key);

/**
 * @brief Set SSH authentication method preference.
 *
 * The default preference is as follows:
 * - interactive authentication (3)
 * - password authentication (2)
 * - public key authentication (1)
 *
 * @param[in] auth_type Authentication method to modify the preference of.
 * @param[in] pref Preference of \p auth_type. Higher number increases priority, negative values disable the method.
 */
void nc_client_ssh_set_auth_pref(NC_SSH_AUTH_TYPE auth_type, int16_t pref);

/**
 * @brief Get SSH authentication method preference.
 *
 * @param[in] auth_type Authentication method to retrieve the prefrence of.
 * @return Preference of the \p auth_type.
 */
int16_t nc_client_ssh_get_auth_pref(NC_SSH_AUTH_TYPE auth_type);

/**
 * @brief Set client SSH username used for authentication.
 *
 * @param[in] username Username to use.
 * @return 0 on success, -1 on error.
 */
int nc_client_ssh_set_username(const char *username);

/**
 * @brief Get client SSH username used for authentication.
 *
 * @return Username used.
 */
const char *nc_client_ssh_get_username(void);

/**
 * @brief Connect to the NETCONF server using SSH transport (via libssh).
 *
 * SSH session is created with default options. If the caller needs to use specific SSH session properties,
 * they are supposed to use nc_connect_libssh().
 *
 * @param[in] host Hostname or address (both Ipv4 and IPv6 are accepted) of the target server.
 *                 'localhost' is used by default if NULL is specified.
 * @param[in] port Port number of the target server. Default value 830 is used if 0 is specified.
 * @param[in] ctx Optional parameter. If set, provides strict YANG context for the session
 *                (ignoring what is actually supported by the server side). If not set,
 *                YANG context is created for the session using \<get-schema\> (if supported
 *                by the server side) or/and by searching for YANG schemas in the searchpath
 *                (see nc_client_schema_searchpath()). In every case except not providing context
 *                to connect to a server supporting \<get-schema\> it is possible that
 *                the session context will not include all the models supported by the server.
 * @return Created NETCONF session object or NULL on error.
 */
struct nc_session *nc_connect_ssh(const char *host, uint16_t port, struct ly_ctx *ctx);

/**
 * @brief Connect to the NETCONF server using the provided SSH (libssh) session.
 *
 * SSH session can have any options set, they will not be modified. If no options were set,
 * host 'localhost', port 22, and the username detected from the EUID is used. If socket is
 * set and connected only the host and the username must be set/is detected. Or the \p ssh_session
 * can already be authenticated in which case it is used directly.
 *
 * @param[in] ssh_session libssh structure representing SSH session object. After passing it
 *                        to libnetconf2 this way, it is fully managed by it (including freeing!).
 * @param[in] ctx Optional parameter. If set, provides strict YANG context for the session
 *                (ignoring what is actually supported by the server side). If not set,
 *                YANG context is created for the session using \<get-schema\> (if supported
 *                by the server side) or/and by searching for YANG schemas in the searchpath
 *                (see nc_client_schema_searchpath()). In every case except not providing context
 *                to connect to a server supporting \<get-schema\> it is possible that
 *                the session context will not include all the models supported by the server.
 * @return Created NETCONF session object or NULL on error.
 */
struct nc_session *nc_connect_libssh(ssh_session ssh_session, struct ly_ctx *ctx);

/**
 * @brief Create another NETCONF session on existing SSH session using separated SSH channel.
 *
 * @param[in] session Existing NETCONF session. The session has to be created on SSH transport layer using libssh -
 *                    it has to be created by nc_connect_ssh(), nc_connect_libssh() or nc_connect_ssh_channel().
 * @param[in] ctx Optional parameter. If set, provides strict YANG context for the session
 *                (ignoring what is actually supported by the server side). If not set,
 *                YANG context is created for the session using \<get-schema\> (if supported
 *                by the server side) or/and by searching for YANG schemas in the searchpath
 *                (see nc_client_schema_searchpath()). In every case except not providing context
 *                to connect to a server supporting \<get-schema\> it is possible that
 *                the session context will not include all the models supported by the server.
 * @return Created NETCONF session object or NULL on error.
 */
struct nc_session *nc_connect_ssh_channel(struct nc_session *session, struct ly_ctx *ctx);

/**@} Client SSH */

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

/**
 * @defgroup client_tls Client TLS
 * @ingroup client
 *
 * @brief Client-side settings for TLS connections.
 * @{
 */

/**
 * @brief Set client authentication identity - a certificate and a private key.
 *
 * @param[in] client_cert Path to the file containing the client certificate.
 * @param[in] client_key Path to the file containing the private key for the \p client_cert.
 *                       If NULL, key is expected to be stored with \p client_cert.
 * @return 0 on success, -1 on error.
 */
int nc_client_tls_set_cert_key_paths(const char *client_cert, const char *client_key);

/**
 * @brief Get client authentication identity - a certificate and a private key.
 *
 * @param[out] client_cert Path to the file containing the client certificate. Can be NULL.
 * @param[out] client_key Path to the file containing the private key for the \p client_cert. Can be NULL.
 */
void nc_client_tls_get_cert_key_paths(const char **client_cert, const char **client_key);

/**
 * @brief Set client trusted CA certificates paths.
 *
 * @param[in] ca_file Location of the CA certificate file used to verify server certificates.
 *                    For more info, see the documentation for SSL_CTX_load_verify_locations() from OpenSSL.
 * @param[in] ca_dir Location of the CA certificates directory used to verify the server certificates.
 *                   For more info, see the documentation for SSL_CTX_load_verify_locations() from OpenSSL.
 * @return 0 on success, -1 on error.
 */
int nc_client_tls_set_trusted_ca_paths(const char *ca_file, const char *ca_dir);

/**
 * @brief Get client trusted CA certificates paths.
 *
 * @param[out] ca_file Location of the CA certificate file used to verify server certificates.
 *                     Can be NULL.
 * @param[out] ca_dir Location of the CA certificates directory used to verify the server certificates.
 *                    Can be NULL.
 */
void nc_client_tls_get_trusted_ca_paths(const char **ca_file, const char **ca_dir);

/**
 * @brief Set client Certificate Revocation List paths.
 *
 * @param[in] crl_file Location of the CRL certificate file used to check for revocated certificates.
 * @param[in] crl_dir Location of the CRL certificate directory used to check for revocated certificates.
 * @return 0 on success, -1 on error.
 */
int nc_client_tls_set_crl_paths(const char *crl_file, const char *crl_dir);

/**
 * @brief Get client Certificate Revocation List paths.
 *
 * @param[out] crl_file Location of the CRL certificate file used to check for revocated certificates.
 * @param[out] crl_dir Location of the CRL certificate directory used to check for revocated certificates.
 */
void nc_client_tls_get_crl_paths(const char **crl_file, const char **crl_dir);

/**
 * @brief Connect to the NETCONF server using TLS transport (via libssl)
 *
 * TLS session is created with the certificates set using nc_client_tls_* functions, which must be called beforehand!
 * If the caller needs to use specific TLS session properties, they are supposed to use nc_connect_libssl().
 *
 * @param[in] host Hostname or address (both Ipv4 and IPv6 are accepted) of the target server.
 *                 'localhost' is used by default if NULL is specified.
 * @param[in] port Port number of the target server. Default value 6513 is used if 0 is specified.
 * @param[in] ctx Optional parameter. If set, provides strict YANG context for the session
 *                (ignoring what is actually supported by the server side). If not set,
 *                YANG context is created for the session using \<get-schema\> (if supported
 *                by the server side) or/and by searching for YANG schemas in the searchpath
 *                (see nc_client_schema_searchpath()). In every case except not providing context
 *                to connect to a server supporting \<get-schema\> it is possible that
 *                the session context will not include all the models supported by the server.
 * @return Created NETCONF session object or NULL on error.
 */
struct nc_session *nc_connect_tls(const char *host, uint16_t port, struct ly_ctx *ctx);

/**
 * @brief Connect to the NETCONF server using the provided TLS (libssl) session.
 *
 * The TLS session supplied is expected to be fully connected and authenticated!
 *
 * @param[in] tls libssl structure representing the TLS session object.
 * @param[in] ctx Optional parameter. If set, provides strict YANG context for the session
 *                (ignoring what is actually supported by the server side). If not set,
 *                YANG context is created for the session using \<get-schema\> (if supported
 *                by the server side) or/and by searching for YANG schemas in the searchpath
 *                (see nc_client_schema_searchpath()). In every case except not providing context
 *                to connect to a server supporting \<get-schema\> it is possible that
 *                the session context will not include all the models supported by the server.
 * @return Created NETCONF session object or NULL on error.
 */
struct nc_session *nc_connect_libssl(SSL *tls, struct ly_ctx *ctx);

/**@} Client TLS */

#endif /* NC_ENABLED_TLS */

/**
 * @addtogroup client_session
 * @{
 */

/**
 * @brief Get session capabilities.
 *
 * @param[in] session Session to get the information from.
 * @return NULL-terminated array of the \p session capabilities.
 */
const char * const *nc_session_get_cpblts(const struct nc_session *session);

/**
 * @brief Check capability presence in a session.
 *
 * @param[in] session Session to check.
 * @param[in] capab Capability to look for, capability with any additional suffix will match.
 * @return Matching capability, NULL if none found.
 */
const char *nc_session_cpblt(const struct nc_session *session, const char *capab);

/**
 * @brief Check whether the session has a notification thread running.
 *
 * @param[in] session Session to check.
 * @return 1 if notfication thread is running, 0 otherwise.
 */
int nc_session_ntf_thread_running(const struct nc_session *session);

/**
 * @brief Receive NETCONF RPC reply.
 *
 * Be careful, normally there is a whole RPC reply (output) of an RPC in the \p reply.
 * However, if a reply to \<get\> or \<get-config\> RPC is received, the \p reply is
 * actually the configuration (with either state data or not). This means, for example,
 * that the reply data in these cases should not be validated with \b LYD_OPT_RPCREPLY,
 * but \b LYD_OPT_GET and \b LYD_OPT_GETCONFIG, respectively.
 *
 * @param[in] session NETCONF session from which the function gets data. It must be the
 *            client side session object.
 * @param[in] rpc Original RPC this should be the reply to.
 * @param[in] msgid Expected message ID of the reply.
 * @param[in] timeout Timeout for reading in milliseconds. Use negative value for infinite
 *            waiting and 0 for immediate return if data are not available on the wire.
 * @param[in] parseroptions libyang parseroptions flags, do not set the data type, it is set
 *            internally. \b LYD_OPT_DESTRUCT and \b LYD_OPT_NOSIBLINGS is ignored.
 * @param[out] reply Resulting object of NETCONF RPC reply.
 * @return #NC_MSG_REPLY for success,
 *         #NC_MSG_WOULDBLOCK if \p timeout has elapsed,
 *         #NC_MSG_ERROR if reading has failed,
 *         #NC_MSG_NOTIF if a notification was read instead (call this function again to get the reply), and
 *         #NC_MSG_REPLY_ERR_MSGID if a reply with missing or wrong message-id was received.
 */
NC_MSG_TYPE nc_recv_reply(struct nc_session *session, struct nc_rpc *rpc, uint64_t msgid, int timeout,
                          int parseroptions, struct nc_reply **reply);

/**
 * @brief Receive NETCONF Notification.
 *
 * @param[in] session NETCONF session from which the function gets data. It must be the
 *            client side session object.
 * @param[in] timeout Timeout for reading in milliseconds. Use negative value for infinite
 *            waiting and 0 for immediate return if data are not available on the wire.
 * @param[out] notif Resulting object of NETCONF Notification.
 * @return #NC_MSG_NOTIF for success,
 *         #NC_MSG_WOULDBLOCK if \p timeout has elapsed,
 *         #NC_MSG_ERROR if reading has failed, and
 *         #NC_MSG_REPLY if a reply was read instead (call this function again to get a notification).
 */
NC_MSG_TYPE nc_recv_notif(struct nc_session* session, int timeout, struct nc_notif **notif);

/**
 * @brief Receive NETCONF Notifications in a separate thread until the session is terminated
 *        or \<notificationComplete\> is received.
 *
 * @param[in] session Netconf session to read notifications from.
 * @param[in] notif_clb Function that is called for every received notification (including
 *            \<notificationComplete\>). Parameters are the session the notification was received on
 *            and the notification itself.
 * @return 0 if the thread was successfully created, -1 on error.
 */
int nc_recv_notif_dispatch(struct nc_session *session,
                           void (*notif_clb)(struct nc_session *session, const struct nc_notif *notif));

/**
 * @brief Send NETCONF RPC message via the session.
 *
 * @param[in] session NETCONF session where the RPC will be written.
 * @param[in] rpc NETCOFN RPC object to send via specified session. Object can be created by
 *            nc_rpc_lock(), nc_rpc_unlock() and nc_rpc_generic() functions.
 * @param[in] timeout Timeout for writing in milliseconds. Use negative value for infinite
 *            waiting and 0 for return if data cannot be sent immediately.
 * @param[out] msgid If RPC was successfully sent, this is it's message ID.
 * @return #NC_MSG_RPC on success,
 *         #NC_MSG_WOULDBLOCK in case of a busy session, and
 *         #NC_MSG_ERROR on error.
 */
NC_MSG_TYPE nc_send_rpc(struct nc_session *session, struct nc_rpc *rpc, int timeout, uint64_t *msgid);

/**
 * @brief Make a session not strict when sending RPCs and receiving RPC replies. In other words,
 *        it will silently skip unknown nodes without an error.
 *
 * Generally, no such data should be worked with, so use this function only when you know what you
 * are doing and you understand the consequences.
 *
 * @param[in] session NETCONF client session.
 */
void nc_client_session_set_not_strict(struct nc_session *session);

/**@} Client Session */

#endif /* NC_SESSION_CLIENT_H_ */
