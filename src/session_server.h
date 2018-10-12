/**
 * \file session_server.h
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 session server manipulation
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_SESSION_SERVER_H_
#define NC_SESSION_SERVER_H_

#include <stdint.h>
#include <libyang/libyang.h>

#ifdef NC_ENABLED_TLS
#   include <openssl/x509.h>
#endif

#ifdef NC_ENABLED_SSH
#   include <libssh/libssh.h>
#   include <libssh/callbacks.h>
#   include <libssh/server.h>
#endif

#include "session.h"
#include "netconf.h"

/**
 * @defgroup server_session Server Session
 * @ingroup server
 *
 * @brief Server-side NETCONF session manipulation.
 * @{
 */

/**
 * @brief Prototype of callbacks that are called if some RPCs are received.
 *
 * If \p session termination reason is changed in the callback, one last reply
 * is sent and then the session is considered invalid.
 *
 * The callback is set via nc_set_global_rpc_clb().
 *
 * @param[in] rpc Parsed client RPC request.
 * @param[in] session Session the RPC arrived on.
 * @return Server reply. If NULL, an operation-failed error will be sent to the client.
 */
typedef struct nc_server_reply *(*nc_rpc_clb)(struct lyd_node *rpc, struct nc_session *session);

/**
 * @brief Set the termination reason for a session. Use only in #nc_rpc_clb callbacks.
 *
 * @param[in] session Session to modify.
 * @param[in] reason Reason of termination.
 */
void nc_session_set_term_reason(struct nc_session *session, NC_SESSION_TERM_REASON reason);

/**
 * @brief Set the session-id of the session responsible for this session's termination.
 *
 * @param[in] session Session to modify. Must have term_reason set to #NC_SESSION_TERM_KILLED.
 * @param[in] sid SID of the killing session.
 */
void nc_session_set_killed_by(struct nc_session *session, uint32_t sid);

/**
 * @brief Set the status of a session.
 *
 * @param[in] session Session to modify.
 * @param[in] status Status of the session.
 */
void nc_session_set_status(struct nc_session *session, NC_STATUS status);

/**
 * @brief Set a global nc_rpc_clb that is called if the particular RPC request is
 * received and the private field in the corresponding RPC schema node is NULL.
 *
 * @param[in] clb An user-defined nc_rpc_clb function callback, NULL to default.
 */
void nc_set_global_rpc_clb(nc_rpc_clb clb);

/**@} Server Session */

/**
 * @addtogroup server
 * @{
 */

/**
 * @brief Initialize libssh and/or libssl/libcrypto and the server using a libyang context.
 *
 * The context is not modified internally, only its dictionary is used for holding
 * all the strings, which is thread-safe. Reading models is considered thread-safe
 * as models cannot be removed and are rarely modified (augments or deviations).
 *
 * If the RPC callbacks on schema nodes (mentioned in @ref howtoserver) are modified after
 * server initialization with that particular context, they will be called (changes
 * will take effect). However, there could be race conditions as the access to
 * these callbacks is not thread-safe.
 *
 * Server capabilities are generated based on its content. Changing the context
 * in ways that result in changed capabilities (adding models, changing features)
 * is discouraged after sessions are established as it is not possible to change
 * capabilities of a session.
 *
 * This context can safely be destroyed only after calling the last libnetconf2
 * function in an application.
 *
 * Supported RPCs of models in the context are expected to have their callback
 * in the corresponding RPC schema node set to a nc_rpc_clb function callback using nc_set_rpc_callback().
 * This callback is called by nc_ps_poll() if the particular RPC request is
 * received. Callbacks for ietf-netconf:get-schema (supporting YANG and YIN format
 * only) and ietf-netconf:close-session are set internally if left unset.
 *
 * @param[in] ctx Core NETCONF server context.
 * @return 0 on success, -1 on error.
 */
int nc_server_init(struct ly_ctx *ctx);

/**
 * @brief Destroy any dynamically allocated libssh and/or libssl/libcrypto and
 *        server resources.
 */
void nc_server_destroy(void);

/**
 * @brief Set the with-defaults capability extra parameters.
 *
 * For the capability to be actually advertised, the server context must also
 * include the ietf-netconf-with-defaults model.
 *
 * Changing this option has the same ill effects as changing capabilities while
 * sessions are already established.
 *
 * @param[in] basic_mode basic-mode with-defaults parameter.
 * @param[in] also_supported NC_WD_MODE bit array, also-supported with-defaults
 * parameter.
 * @return 0 on success, -1 on error.
 */
int nc_server_set_capab_withdefaults(NC_WD_MODE basic_mode, int also_supported);

/**
 * @brief Get with-defaults capability extra parameters.
 *
 * At least one argument must be non-NULL.
 *
 * @param[in,out] basic_mode basic-mode parameter.
 * @param[in,out] also_supported also-supported parameter.
 */
void nc_server_get_capab_withdefaults(NC_WD_MODE *basic_mode, int *also_supported);

/**
 * @brief Set capability of the server.
 *
 * Capability can be used when some behavior or extension of the server is not defined
 * as a YANG module. The provided value will be advertised in the server's \<hello\>
 * messages. Note, that libnetconf only checks that the provided value is non-empty
 * string.
 *
 * @param[in] value Capability string to be advertised in server's \<hello\> messages.
 */
int nc_server_set_capability(const char *value);

/**
 * @brief Set server timeout for receiving a hello message.
 *
 * @param[in] hello_timeout Hello message timeout. 0 for infinite waiting.
 */
void nc_server_set_hello_timeout(uint16_t hello_timeout);

/**
 * @brief get server timeout for receiving a hello message.
 *
 * @return Hello message timeout, 0 is infinite.
 */
uint16_t nc_server_get_hello_timeout(void);

/**
 * @brief Set server timeout for dropping an idle session.
 *
 * @param[in] idle_timeout Idle session timeout. 0 to never drop a session
 *                         because of inactivity.
 */
void nc_server_set_idle_timeout(uint16_t idle_timeout);

/**
 * @brief Get server timeout for dropping an idle session.
 *
 * @return Idle session timeout, 0 for for never dropping
 *         a session because of inactivity.
 */
uint16_t nc_server_get_idle_timeout(void);

/**
 * @brief Get all the server capabilities including all the schemas.
 *
 * A few capabilities (with-defaults, interleave) depend on the current
 * server options.
 *
 * @param[in] ctx Context to read most capabilities from.
 * @return Array of capabilities stored in the \p ctx dictionary, NULL on error.
 */
const char **nc_server_get_cpblts(struct ly_ctx *ctx);

/**
 * @brief Get the server capabilities including the schemas with the specified YANG version.
 *
 * A few capabilities (with-defaults, interleave) depend on the current
 * server options.
 *
 * @param[in] ctx Context to read most capabilities from.
 * @param[in] version YANG version of the schemas to be included in result, with
 * LYS_VERSION_UNDEF the result is the same as from nc_server_get_cpblts().
 * @return Array of capabilities stored in the \p ctx dictionary, NULL on error.
 */
const char **nc_server_get_cpblts_version(struct ly_ctx *ctx, LYS_VERSION version);

/**@} Server */

/**
 * @addtogroup server_session
 * @{
 */

/**
 * @brief Accept a new session on a pre-established transport session.
 *
 * @param[in] fdin File descriptor to read (unencrypted) XML data from.
 * @param[in] fdout File descriptor to write (unencrypted) XML data to.
 * @param[in] username NETCONF username as provided by the transport protocol.
 * @param[out] session New session on success.
 * @return NC_MSG_HELLO on success, NC_MSG_BAD_HELLO on client \<hello\> message
 *         parsing fail, NC_MSG_WOULDBLOCK on timeout, NC_MSG_ERROR on other errors.
 */
NC_MSG_TYPE nc_accept_inout(int fdin, int fdout, const char *username, struct nc_session **session);

/**
 * @brief Create an empty structure for polling sessions.
 *
 * @return Empty pollsession structure, NULL on error.
 */
struct nc_pollsession *nc_ps_new(void);

/**
 * @brief Free a pollsession structure.
 *
 * !IMPORTANT! Make sure that \p ps is not accessible (is not used)
 * by any thread before and after this call!
 *
 * @param[in] ps Pollsession structure to free.
 */
void nc_ps_free(struct nc_pollsession *ps);

/**
 * @brief Add a session to a pollsession structure.
 *
 * @param[in] ps Pollsession structure to modify.
 * @param[in] session Session to add to \p ps.
 * @return 0 on success, -1 on error.
 */
int nc_ps_add_session(struct nc_pollsession *ps, struct nc_session *session);

/**
 * @brief Remove a session from a pollsession structure.
 *
 * @param[in] ps Pollsession structure to modify.
 * @param[in] session Session to remove from \p ps.
 * @return 0 on success, -1 on not found.
 */
int nc_ps_del_session(struct nc_pollsession *ps, struct nc_session *session);

/**
 * @brief Get a session from a pollsession structure matching the session ID.
 *
 * @param[in] ps Pollsession structure to read from.
 * @param[in] idx Index of the session.
 * @return Session on index, NULL if out-of-bounds.
 */
struct nc_session *nc_ps_get_session(const struct nc_pollsession *ps, uint16_t idx);

/**
 * @brief Learn the number of sessions in a pollsession structure.
 *
 * Does not lock \p ps structure for efficiency.
 *
 * @param[in] ps Pollsession structure to check.
 * @return Number of sessions (even invalid ones) in \p ps, -1 on error.
 */
uint16_t nc_ps_session_count(struct nc_pollsession *ps);

#define NC_PSPOLL_NOSESSIONS 0x0001    /**< No sessions to poll. */
#define NC_PSPOLL_TIMEOUT 0x0002       /**< Timeout elapsed. */
#define NC_PSPOLL_RPC 0x0004           /**< RPC was correctly parsed and processed. */
#define NC_PSPOLL_BAD_RPC 0x0008       /**< RPC was received, but failed to be parsed. */
#define NC_PSPOLL_REPLY_ERROR 0x0010   /**< Response to the RPC was a \<rpc-reply\> of type error. */
#define NC_PSPOLL_SESSION_TERM 0x0020  /**< Some session was terminated. */
#define NC_PSPOLL_SESSION_ERROR 0x0040 /**< Some session was terminated incorrectly (not by a \<close-session\> or \<kill-session\> RPC). */
#define NC_PSPOLL_ERROR 0x0080         /**< Other fatal errors (they are printed). */

#ifdef NC_ENABLED_SSH
#   define NC_PSPOLL_SSH_MSG 0x00100      /**< SSH message received (and processed, if relevant, only with SSH support). */
#   define NC_PSPOLL_SSH_CHANNEL 0x0200   /**< New SSH channel opened on an existing session (only with SSH support). */
#endif

/**
 * @brief Poll sessions and process any received RPCs.
 *
 * Only one event on one session is handled in one function call. If this event
 * is a session termination (#NC_PSPOLL_SESSION_TERM returned), the session
 * should be removed from \p ps.
 *
 * @param[in] ps Pollsession structure to use.
 * @param[in] timeout Poll timeout in milliseconds. 0 for non-blocking call, -1 for
 *                    infinite waiting.
 * @param[in] session Session that was processed and that specific return bits concern.
 *                    Can be NULL.
 * @return Bitfield of NC_PSPOLL_* macros.
 */
int nc_ps_poll(struct nc_pollsession *ps, int timeout, struct nc_session **session);

/**
 * @brief Remove sessions from a pollsession structure and
 *        call nc_session_free() on them.
 *
 * Calling this function with \p all false makes sense if nc_ps_poll() returned #NC_PSPOLL_SESSION_TERM.
 *
 * @param[in] ps Pollsession structure to clear.
 * @param[in] all Whether to free all sessions, or only the invalid ones.
 * @param[in] data_free Session user data destructor.
 */
void nc_ps_clear(struct nc_pollsession *ps, int all, void (*data_free)(void *));

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)

/**@} Server Session */

/**
 * @addtogroup server
 * @{
 */

/**
 * @brief Add a new endpoint.
 *
 * Before the endpoint can accept any connections, its address and port must
 * be set via nc_server_endpt_set_address() and nc_server_endpt_set_port().
 *
 * @param[in] name Arbitrary unique endpoint name.
 * @param[in] ti Transport protocol to use.
 * @return 0 on success, -1 on error.
 */
int nc_server_add_endpt(const char *name, NC_TRANSPORT_IMPL ti);

/**
 * @brief Stop listening on and remove an endpoint.
 *
 * @param[in] name Endpoint name. NULL matches all endpoints.
 * @param[in] ti Endpoint transport protocol. NULL matches any protocol.
 *               Redundant to set if \p name is set, endpoint names are
 *               unique disregarding their protocol.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_del_endpt(const char *name, NC_TRANSPORT_IMPL ti);

/**
 * @brief Get the number of currently configured listening endpoints.
 * Note that an ednpoint without address and/or port will be included
 * even though it is not, in fact, listening.
 *
 * @return Number of added listening endpoints.
 */
int nc_server_endpt_count(void);

/**
 * @brief Change endpoint listening address.
 *
 * On error the previous listening socket (if any) is left untouched.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] address New listening address.
 * @return 0 on success, -1 on error.
 */
int nc_server_endpt_set_address(const char *endpt_name, const char *address);

/**
 * @brief Change endpoint listening port.
 *
 * On error the previous listening socket (if any) is left untouched.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] port New listening port.
 * @return 0 on success, -1 on error.
 */
int nc_server_endpt_set_port(const char *endpt_name, uint16_t port);

/**@} Server */

/**
 * @addtogroup server_session
 */

/**
 * @brief Accept new sessions on all the listening endpoints.
 *
 * Once a new (TCP/IP) conection is established a different (quite long) timeout
 * is used for waiting for transport-related data, which means this call can block
 * for much longer that \p timeout, but only with slow/faulty/malicious clients.
 *
 * @param[in] timeout Timeout for receiving a new connection in milliseconds, 0 for
 *                    non-blocking call, -1 for infinite waiting.
 * @param[out] session New session.
 * @return NC_MSG_HELLO on success, NC_MSG_BAD_HELLO on client \<hello\> message
 *         parsing fail, NC_MSG_WOULDBLOCK on timeout, NC_MSG_ERROR on other errors.
 */
NC_MSG_TYPE nc_accept(int timeout, struct nc_session **session);

#endif /* NC_ENABLED_SSH || NC_ENABLED_TLS */

#ifdef NC_ENABLED_SSH

/**
 * @brief Accept a new NETCONF session on an SSH session of a running NETCONF \p orig_session.
 *        Call this function only when nc_ps_poll() returns #NC_PSPOLL_SSH_CHANNEL on \p orig_session.
 *
 * @param[in] orig_session Session that has a new SSH channel ready.
 * @param[out] session New session.
 * @return NC_MSG_HELLO on success, NC_MSG_BAD_HELLO on client \<hello\> message
 *         parsing fail, NC_MSG_WOULDBLOCK on timeout, NC_MSG_ERROR on other errors.
 */
NC_MSG_TYPE nc_session_accept_ssh_channel(struct nc_session *orig_session, struct nc_session **session);

/**
 * @brief Accept a new NETCONF session on an SSH session of a running NETCONF session
 *        that was polled in \p ps. Call this function only when nc_ps_poll() on \p ps returns #NC_PSPOLL_SSH_CHANNEL.
 *        The new session is only returned in \p session, it is not added to \p ps.
 *
 * @param[in] ps Unmodified pollsession structure from the previous nc_ps_poll() call.
 * @param[out] session New session.
 * @return NC_MSG_HELLO on success, NC_MSG_BAD_HELLO on client \<hello\> message
 *         parsing fail, NC_MSG_WOULDBLOCK on timeout, NC_MSG_ERROR on other errors.
 */
NC_MSG_TYPE nc_ps_accept_ssh_channel(struct nc_pollsession *ps, struct nc_session **session);

/**@} Server Session */

/**
 * @defgroup server_ssh Server SSH
 * @ingroup server
 *
 * @brief Server-side settings for SSH connections.
 * @{
 */

/**
 * @brief Add an authorized client SSH public key. This public key can be used for
 *        publickey authentication (for any SSH connection, even Call Home) afterwards.
 *
 * @param[in] pubkey_base64 Authorized public key binary content encoded in base64.
 * @param[in] type Authorized public key SSH type.
 * @param[in] username Username that the client with the public key must use.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_add_authkey(const char *pubkey_base64, NC_SSH_KEY_TYPE type, const char *username);

/**
 * @brief Add an authorized client SSH public key. This public key can be used for
 *        publickey authentication (for any SSH connection, even Call Home) afterwards.
 *
 * @param[in] pubkey_path Path to the public key.
 * @param[in] username Username that the client with the public key must use.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_add_authkey_path(const char *pubkey_path, const char *username);

/**
 * @brief Remove an authorized client SSH public key.
 *
 * @param[in] pubkey_path Path to an authorized public key. NULL matches all the keys.
 * @param[in] pubkey_base64 Authorized public key content. NULL matches any key.
 * @param[in] type Authorized public key type. 0 matches all types.
 * @param[in] username Username for an authorized public key. NULL matches all the usernames.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_ssh_del_authkey(const char *pubkey_path, const char *pubkey_base64, NC_SSH_KEY_TYPE type,
                              const char *username);

/**
 * @brief Add endpoint SSH host keys the server will identify itself with. Only the name is set, the key itself
 *        wil be retrieved using a callback.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] name Arbitrary name of the host key.
 * @param[in] idx Optional index where to add the key. -1 adds at the end.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_endpt_add_hostkey(const char *endpt_name, const char *name, int16_t idx);

/**
 * @brief Set the callback for SSH password authentication. If none is set, local system users are used.
 *
 * @param[in] passwd_auth_clb Callback that should authenticate the user. Username can be directly obtained from \p session.
 *                            Zero return indicates success, non-zero an error.
 * @param[in] user_data Optional arbitrary user data that will be passed to \p passwd_auth_clb.
 * @param[in] free_user_data Optional callback that will be called during cleanup to free any \p user_data.
 */
void nc_server_ssh_set_passwd_auth_clb(int (*passwd_auth_clb)(const struct nc_session *session, const char *password,
                                                              void *user_data),
                                       void *user_data, void (*free_user_data)(void *user_data));

/**
 * @brief Set the callback for SSH interactive authentication. If none is set, local system users are used.
 *
 * @param[in] interactive_auth_clb Callback that should authenticate the user.
 *                            Zero return indicates success, non-zero an error.
 * @param[in] user_data Optional arbitrary user data that will be passed to \p passwd_auth_clb.
 * @param[in] free_user_data Optional callback that will be called during cleanup to free any \p user_data.
 */
void nc_server_ssh_set_interactive_auth_clb(int (*interactive_auth_clb)(const struct nc_session *session, const ssh_message msg,
                                                              void *user_data),
                                           void *user_data, void (*free_user_data)(void *user_data));

/**
 * @brief Set the callback for SSH public key authentication. If none is set, local system users are used.
 *
 * @param[in] pubkey_auth_clb Callback that should authenticate the user.
 *                            Zero return indicates success, non-zero an error.
 * @param[in] user_data Optional arbitrary user data that will be passed to \p passwd_auth_clb.
 * @param[in] free_user_data Optional callback that will be called during cleanup to free any \p user_data.
 */
 void nc_server_ssh_set_pubkey_auth_clb(int (*pubkey_auth_clb)(const struct nc_session *session, ssh_key key, void *user_data),
                                       void *user_data, void (*free_user_data)(void *user_data));

/**
 * @brief Set the callback for retrieving host keys. Any RSA, DSA, and ECDSA keys can be added. However,
 *        a maximum of one key of each type will be used during SSH authentication, later keys replacing
 *        the earlier ones.
 *
 * @param[in] hostkey_clb Callback that should return the key itself. Zero return indicates success, non-zero
 *                        an error. On success exactly ONE of \p privkey_path or \p privkey_data is expected
 *                        to be set. The one set will be freed.
 *                        - \p privkey_path expects a PEM file,
 *                        - \p privkey_data expects a base-64 encoded ANS.1 DER data,
 *                        - \p privkey_data_rsa flag whether \p privkey_data are the data of an RSA (1) or a DSA (0) key.
 * @param[in] user_data Optional arbitrary user data that will be passed to \p hostkey_clb.
 * @param[in] free_user_data Optional callback that will be called during cleanup to free any \p user_data.
 */
void nc_server_ssh_set_hostkey_clb(int (*hostkey_clb)(const char *name, void *user_data, char **privkey_path,
                                                      char **privkey_data, int *privkey_data_rsa),
                                   void *user_data, void (*free_user_data)(void *user_data));

/**
 * @brief Delete endpoint SSH host key. Their order is preserved.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] name Name of the host key. NULL matches all the keys, but if \p idx != -1 then this must be NULL.
 * @param[in] idx Index of the hostkey. -1 matches all indices, but if \p name != NULL then this must be -1.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_endpt_del_hostkey(const char *endpt_name, const char *name, int16_t idx);

/**
 * @brief Move endpoint SSH host key.
 *
 * @param[in] endpt_name Exisitng endpoint name.
 * @param[in] key_mov Name of the host key that will be moved.
 * @param[in] key_after Name of the key that will preceed \p key_mov. NULL if \p key_mov is to be moved at the beginning.
 * @return 0 in success, -1 on error.
 */
int nc_server_ssh_endpt_mov_hostkey(const char *endpt_name, const char *key_mov, const char *key_after);

/**
 * @brief Modify endpoint SSH host key.
 *
 * @param[in] endpt_name Exisitng endpoint name.
 * @param[in] name Name of an existing host key.
 * @param[in] new_name New name of the host key \p name.
 * @return 0 in success, -1 on error.
 */
int nc_server_ssh_endpt_mod_hostkey(const char *endpt_name, const char *name, const char *new_name);

/**
 * @brief Set endpoint accepted SSH authentication methods. All (publickey, password, interactive)
 *        are supported by default.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] auth_methods Accepted authentication methods bit field of NC_SSH_AUTH_TYPE.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_endpt_set_auth_methods(const char *endpt_name, int auth_methods);

/**
 * @brief Set endpoint SSH authentication attempts of every client. 3 by default.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] auth_attempts Failed authentication attempts before a client is dropped.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_endpt_set_auth_attempts(const char *endpt_name, uint16_t auth_attempts);

/**
 * @brief Set endpoint SSH authentication timeout. 10 seconds by default.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] auth_timeout Number of seconds before an unauthenticated client is dropped.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_endpt_set_auth_timeout(const char *endpt_name, uint16_t auth_timeout);

/**@} Server SSH */

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

/**
 * @defgroup server_tls Server TLS
 * @ingroup server
 *
 * @brief Server-side settings for TLS connections.
 * @{
 */

/**
 * @brief Set the server TLS certificate. Only the name is set, the certificate itself
 *        wil be retrieved using a callback.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] name Arbitrary certificate name.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_set_server_cert(const char *endpt_name, const char *name);

/**
 * @brief Set the callback for retrieving server certificate and matching private key.
 *
 * @param[in] cert_clb Callback that should return the certificate and the key itself. Zero return indicates success,
 *                     non-zero an error. On success exactly ONE of \p cert_path or \p cert_data and ONE of
 *                     \p privkey_path and \p privkey_data is expected to be set. Those set will be freed.
 *                     - \p cert_path expects a PEM file,
 *                     - \p cert_data expects a base-64 encoded ASN.1 DER data,
 *                     - \p privkey_path expects a PEM file,
 *                     - \p privkey_data expects a base-64 encoded ANS.1 DER data,
 *                     - \p privkey_data_rsa flag whether \p privkey_data are the data of an RSA (1) or a DSA (0) key.
 * @param[in] user_data Optional arbitrary user data that will be passed to \p cert_clb.
 * @param[in] free_user_data Optional callback that will be called during cleanup to free any \p user_data.
 */
void nc_server_tls_set_server_cert_clb(int (*cert_clb)(const char *name, void *user_data, char **cert_path, char **cert_data,
                                                       char **privkey_path, char **privkey_data, int *privkey_data_rsa),
                                       void *user_data, void (*free_user_data)(void *user_data));

/**
 * @brief Set the callback for retrieving server certificate chain
 *
 * @param[in] cert_chain_clb Callback that should return all the certificates of the chain. Zero return indicates success,
 *                           non-zero an error. On success, \p cert_paths and \p cert_data are expected to be set or left
 *                           NULL. Both will be (deeply) freed.
 *                           - \p cert_paths expect an array of PEM files,
 *                           - \p cert_path_count number of \p cert_paths array members,
 *                           - \p cert_data expect an array of base-64 encoded ASN.1 DER cert data,
 *                           - \p cert_data_count number of \p cert_data array members.
 * @param[in] user_data Optional arbitrary user data that will be passed to \p cert_clb.
 * @param[in] free_user_data Optional callback that will be called during cleanup to free any \p user_data.
 */
void nc_server_tls_set_server_cert_chain_clb(int (*cert_chain_clb)(const char *name, void *user_data, char ***cert_paths,
                                                                   int *cert_path_count, char ***cert_data, int *cert_data_count),
                                             void *user_data, void (*free_user_data)(void *user_data));

/**
 * @brief Add a trusted certificate list. Can be both a CA or a client one. Can be
 *        safely used together with nc_server_tls_endpt_set_trusted_ca_paths().
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] name Arbitary name identifying this certificate list.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_add_trusted_cert_list(const char *endpt_name, const char *name);

/**
 * @brief Set the callback for retrieving trusted certificates.
 *
 * @param[in] cert_list_clb Callback that should return all the certificates of a list. Zero return indicates success,
 *                          non-zero an error. On success, \p cert_paths and \p cert_data are expected to be set or left
 *                          NULL. Both will be (deeply) freed.
 *                          - \p cert_paths expect an array of PEM files,
 *                          - \p cert_path_count number of \p cert_paths array members,
 *                          - \p cert_data expect an array of base-64 encoded ASN.1 DER cert data,
 *                          - \p cert_data_count number of \p cert_data array members.
 * @param[in] user_data Optional arbitrary user data that will be passed to \p cert_clb.
 * @param[in] free_user_data Optional callback that will be called during cleanup to free any \p user_data.
 */
void nc_server_tls_set_trusted_cert_list_clb(int (*cert_list_clb)(const char *name, void *user_data, char ***cert_paths,
                                                                  int *cert_path_count, char ***cert_data, int *cert_data_count),
                                             void *user_data, void (*free_user_data)(void *user_data));

/**
 * @brief Remove a trusted certificate.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] name Name of the certificate list to delete. NULL deletes all the lists.
 * @return 0 on success, -1 on not found.
 */
int nc_server_tls_endpt_del_trusted_cert_list(const char *endpt_name, const char *name);

/**
 * @brief Set trusted Certificate Authority certificate locations. There can only be
 *        one file and one directory, they are replaced if already set. Can be safely
 *        used with nc_server_tls_endpt_add_trusted_cert() or its _path variant.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] ca_file Path to a trusted CA cert store file in PEM format. Can be NULL.
 * @param[in] ca_dir Path to a trusted CA cert store hashed directory (c_rehash utility
 *                   can be used to create hashes) with PEM files. Can be NULL.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_set_trusted_ca_paths(const char *endpt_name, const char *ca_file, const char *ca_dir);

/**
 * @brief Set Certificate Revocation List locations. There can only be one file
 *        and one directory, they are replaced if already set.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] crl_file Path to a CRL store file in PEM format. Can be NULL.
 * @param[in] crl_dir Path to a CRL store hashed directory (c_rehash utility
 *                    can be used to create hashes) with PEM files. Can be NULL.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_set_crl_paths(const char *endpt_name, const char *crl_file, const char *crl_dir);

/**
 * @brief Destroy and clean CRLs. Certificates, private keys, and CTN entries are
 *        not affected.
 *
 * @param[in] endpt_name Existing endpoint name.
 */
void nc_server_tls_endpt_clear_crls(const char *endpt_name);

/**
 * @brief Add a cert-to-name entry.
 *
 * It is possible to add an entry step-by-step, specifying first only \p ip and in later calls
 * \p fingerprint, \p map_type, and optionally \p name spearately.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] id Priority of the entry. It must be unique. If already exists, the entry with this id
 *               is modified.
 * @param[in] fingerprint Matching certificate fingerprint. If NULL, kept temporarily unset.
 * @param[in] map_type Type of username-certificate mapping. If 0, kept temporarily unset.
 * @param[in] name Specific username used only if \p map_type == NC_TLS_CTN_SPECIFED.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_add_ctn(const char *endpt_name, uint32_t id, const char *fingerprint,
                                NC_TLS_CTN_MAPTYPE map_type, const char *name);

/**
 * @brief Remove a cert-to-name entry.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] id Priority of the entry. -1 matches all the priorities.
 * @param[in] fingerprint Fingerprint fo the entry. NULL matches all the fingerprints.
 * @param[in] map_type Mapping type of the entry. 0 matches all the mapping types.
 * @param[in] name Specific username for the entry. NULL matches all the usernames.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_tls_endpt_del_ctn(const char *endpt_name, int64_t id, const char *fingerprint,
                                NC_TLS_CTN_MAPTYPE map_type, const char *name);

/**
 * @brief Get a cert-to-name entry.
 *
 * If a parameter is NULL, it is ignored. If its dereferenced value is NULL,
 * it is filled and returned. If the value is set, it is used as a filter.
 * Returns first matching entry.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in,out] id Priority of the entry.
 * @param[in,out] fingerprint Fingerprint fo the entry.
 * @param[in,out] map_type Mapping type of the entry.
 * @param[in,out] name Specific username for the entry.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_tls_endpt_get_ctn(const char *endpt_name, uint32_t *id, char **fingerprint, NC_TLS_CTN_MAPTYPE *map_type,
                                char **name);

/**
 * @brief Get client certificate.
 *
 * @param[in] session Session to get the information from.
 * @return Const session client certificate.
 */
const X509 *nc_session_get_client_cert(const struct nc_session *session);

/**
 * @brief Set TLS authentication additional verify callback.
 *
 * Server will always perform cert-to-name based on its configuration. Only after it passes
 * and this callback is set, it is also called. It should return exactly what OpenSSL
 * verify callback meaning 1 for success, 0 to deny the user.
 *
 * @param[in] verify_clb Additional user verify callback.
 */
void nc_server_tls_set_verify_clb(int (*verify_clb)(const struct nc_session *session));

/**@} Server TLS */

#endif /* NC_ENABLED_TLS */

/**
 * @addtogroup server_session
 * @{
 */

/**
 * @brief Get session start time.
 *
 * @param[in] session Session to get the information from.
 * @return Session start time.
 */
time_t nc_session_get_start_time(const struct nc_session *session);

/**
 * @brief Set session notification subscription flag.
 *
 * It is used only to ignore timeouts, because they are
 * ignored for sessions with active subscriptions.
 *
 * @param[in] session Session to modify.
 * @param[in] notif_status 0 for no active subscriptions, non-zero for an active subscription.
 */
void nc_session_set_notif_status(struct nc_session *session, int notif_status);

/**
 * @brief Get session notification subscription flag.
 *
 * @param[in] session Session to get the information from.
 * @return 0 for no active subscription, non-zero for an active subscription.
 */
int nc_session_get_notif_status(const struct nc_session *session);

/**@} Server Session */

#endif /* NC_SESSION_SERVER_H_ */
