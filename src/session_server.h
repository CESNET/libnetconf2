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

#include "session.h"
#include "netconf.h"

/**
 * @brief Prototype of callbacks that are called if some RPCs are received.
 *
 * If \p session termination reason is changed in the callback, one last reply
 * is sent and then the session is considered invalid.
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
 * @brief Initialize libssh and/or libssl/libcrypto and the server using a libyang context.
 *
 * The context is not modified internally, only its dictionary is used for holding
 * all the strings, which is thread-safe. Reading models is considered thread-safe
 * as models cannot be removed and are rarely modified (augments or deviations).
 *
 * If the callbacks on schema nodes (their private data) are modified after
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
 * Supported RPCs of models in the context are expected to have the private field
 * in the corresponding RPC schema node set to a nc_rpc_clb function callback.
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
 * @brief Set the interleave capability.
 *
 * For the capability to be actually advertised, the server context must also
 * include the nc-notifications model.
 *
 * Changing this option has the same ill effects as changing capabilities while
 * sessions are already established.
 *
 * @param[in] interleave_support 1 to suport interleave, 0 to not.
 */
void nc_server_set_capab_interleave(int interleave_support);

/**
 * @brief Get the interleave capability state.
 *
 * @return 1 for supported, 0 for not supported.
 */
int nc_server_get_capab_interleave(void);

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
 * @brief Accept a new session on a pre-established transport session.
 *
 * @param[in] fdin File descriptor to read (unencrypted) XML data from.
 * @param[in] fdout File descriptor to write (unencrypted) XML data to.
 * @param[in] username NETCONF username as provided by the transport protocol.
 * @param[out] session New session on success.
 * @return 0 on success, -1 on error.
 */
int nc_accept_inout(int fdin, int fdout, const char *username, struct nc_session **session);

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
 * @brief Learn the number of sessions in a pollsession structure.
 *
 * @param[in] ps Pollsession structure to check.
 * @return Number of sessions (even invalid ones) in \p ps.
 */
uint16_t nc_ps_session_count(struct nc_pollsession *ps);

/**
 * @brief Poll sessions and process any received RPCs.
 *
 * All the sessions must be running. If a session fails causing it to change its
 * status, it can be learnt from the return value. Only one event on one session
 * is handled in one function call.
 *
 * @param[in] ps Pollsession structure to use.
 * @param[in] timeout Poll timeout in milliseconds. 0 for non-blocking call, -1 for
 *                    infinite waiting.
 * @return 0 on elapsed timeout,
 *         1 if an RPC was processed (even if it was not known - it failed to be
 *           parsed into session ctx),
 *         2 if an RPC was processed and there are unhandled events on other sessions,
 *         3 if a session from \p ps changed its status (was invalidated),
 *         -1 on error (a session likely changed its status as well).
 *
 *         Only with SSH support:
 *         4 if an SSH message was processed,
 *         5 if a new NETCONF SSH channel was created; call nc_ps_accept_ssh_channel()
 *           to establish a new NETCONF session.
 */
int nc_ps_poll(struct nc_pollsession *ps, int timeout);

/**
 * @brief Remove sessions from a pollsession structure and
 *        call nc_session_free() on them.
 *
 * Calling this function with \p all false makes sense if nc_ps_poll() returned 3.
 *
 * @param[in] ps Pollsession structure to clear.
 * @param[in] all Whether to free all sessions, or only the invalid ones.
 * @param[in] data_free Session user data destructor.
 */
void nc_ps_clear(struct nc_pollsession *ps, int all, void (*data_free)(void *));

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)

/**
 * @brief Accept new sessions on all the listening endpoints.
 *
 * @param[in] timeout Timeout for receiving a new connection in milliseconds, 0 for
 * non-blocking call, -1 for infinite waiting.
 * @param[out] session New session.
 * @return 1 on success, 0 on timeout, -1 on error.
 */
int nc_accept(int timeout, struct nc_session **session);

#endif /* NC_ENABLED_SSH || NC_ENABLED_TLS */

#ifdef NC_ENABLED_SSH

/**
 * @brief Accept a new NETCONF session on an SSH session of a running NETCONF session
 *        that was polled in \p ps. Call this function only when nc_ps_poll() on \p ps returns 5.
 *        The new session is only returned in \p session, it is not added to \p ps.
 *
 * @param[in] ps Unmodified pollsession structure from the previous nc_ps_poll() call.
 * @param[out] session New session.
 * @return 0 on success, -1 on error.
 */
int nc_ps_accept_ssh_channel(struct nc_pollsession *ps, struct nc_session **session);

/**
 * @brief Add a new SSH endpoint and start listening on it.
 *
 * @param[in] name Arbitrary unique endpoint name. There can be a TLS endpoint with
 *                 the same name.
 * @param[in] address IP address to listen on.
 * @param[in] port Port to listen on.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_add_endpt_listen(const char *name, const char *address, uint16_t port);

/**
 * @brief Change SSH endpoint listening address.
 *
 * On error the previous listening socket is left untouched.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] address New listening address.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_endpt_set_address(const char *endpt_name, const char *address);

/**
 * @brief Change SSH endpoint listening port.
 *
 * On error the previous listening socket is left untouched.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] port New listening port.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_endpt_set_port(const char *endpt_name, uint16_t port);

/**
 * @brief Stop listening on and remove an SSH endpoint.
 *
 * @param[in] name Endpoint name. NULL matches all (SSH) endpoints.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_ssh_del_endpt(const char *name);

/**
 * @brief Set endpoint SSH host keys the server will identify itself with. Each of RSA, DSA, and
 *        ECDSA keys can be set. If the particular type was already set, it is replaced.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] privkey_path Path to a private key.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_endpt_set_hostkey(const char *endpt_name, const char *privkey_path);

/**
 * @brief Set endpoint SSH banner the server will send to every client.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] banner SSH banner.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_endpt_set_banner(const char *endpt_name, const char *banner);

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

/**
 * @brief Add an endpoint authorized client SSH public key. This public key can be used for
 *        publickey authentication afterwards.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] pubkey_path Path to the public key.
 * @param[in] username Username that the client with the public key must use.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_endpt_add_authkey(const char *endpt_name, const char *pubkey_path, const char *username);

/**
 * @brief Remove an endpoint authorized client SSH public key.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] pubkey_path Path to an authorized public key. NULL matches all the keys.
 * @param[in] username Username for an authorized public key. NULL matches all the usernames.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_ssh_endpt_del_authkey(const char *endpt_name, const char *pubkey_path, const char *username);

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

/**
 * @brief Add a new TLS endpoint and start listening on it.
 *
 * @param[in] name Arbitrary unique endpoint name. There can be an SSH endpoint with
 *                 the same name.
 * @param[in] address IP address to listen on.
 * @param[in] port Port to listen on.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_add_endpt_listen(const char *name, const char *address, uint16_t port);

/**
 * @brief Change TLS endpoint listening address.
 *
 * On error the previous listening socket is left untouched.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] address New listening address.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_set_address(const char *endpt_name, const char *address);

/**
 * @brief Change TLS endpoint listening port.
 *
 * On error the previous listening socket is left untouched.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] port New listening port.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_set_port(const char *endpt_name, uint16_t port);

/**
 * @brief Stop listening on and remove a TLS endpoint.
 *
 * @param[in] name Endpoint name. NULL matches all (TLS) endpoints.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_tls_del_endpt(const char *name);

/**
 * @brief Set server TLS certificate. Alternative to nc_tls_server_set_cert_path().
 *        There can only be one certificate for each key type, it is replaced if
 *        already set.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] cert Base64-encoded certificate in ASN.1 DER encoding.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_set_cert(const char *endpt_name, const char *cert);

/**
 * @brief Set server TLS certificate. Alternative to nc_tls_server_set_cert().
 *        There can only be one certificate for each key type, it is replaced if
 *        already set.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] cert_path Path to a certificate file in PEM format.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_set_cert_path(const char *endpt_name, const char *cert_path);

/**
 * @brief Set server TLS private key matching the certificate.
 *        Alternative to nc_tls_server_set_key_path(). There can only be one of
 *        every key type, it is replaced if already set.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] privkey Base64-encoded certificate in ASN.1 DER encoding.
 * @param[in] is_rsa Whether \p privkey are the data of an RSA (1) or DSA (0) key.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_set_key(const char *endpt_name, const char *privkey, int is_rsa);

/**
 * @brief Set server TLS private key matching the certificate.
 *        Alternative to nc_tls_server_set_key_path(). There can only be one of
 *        every key type, it is replaced if already set.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] privkey_path Path to a private key file in PEM format.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_set_key_path(const char *endpt_name, const char *privkey_path);

/**
 * @brief Add a trusted certificate. Can be both a CA or a client one. Can be
 *        safely used together with nc_server_tls_endpt_set_trusted_ca_paths().
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] cert Base64-enocded certificate in ASN.1 DER encoding.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_add_trusted_cert(const char *endpt_name, const char *cert);

/**
 * @brief Add a trusted certificate. Can be both a CA or a client one. Can be
 *        safely used together with nc_server_tls_endpt_set_trusted_ca_paths().
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] cert_path Path to a trusted certificate file in PEM format.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_add_trusted_cert_path(const char *endpt_name, const char *cert_path);

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
 * @brief Destroy and clean all the set certificates and private keys. CRLs and
 *        CTN entries are not affected.
 *
 * @param[in] endpt_name Existing endpoint name.
 */
void nc_server_tls_endpt_clear_certs(const char *endpt_name);

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
 * @brief Add a Cert-to-name entry.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] id Priority of the entry.
 * @param[in] fingerprint Matching certificate fingerprint.
 * @param[in] map_type Type of username-certificate mapping.
 * @param[in] name Specific username if \p map_type == NC_TLS_CTN_SPECIFED. Must be NULL otherwise.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_endpt_add_ctn(const char *endpt_name, uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name);

/**
 * @brief Remove a Cert-to-name entry.
 *
 * @param[in] endpt_name Existing endpoint name.
 * @param[in] id Priority of the entry. -1 matches all the priorities.
 * @param[in] fingerprint Fingerprint fo the entry. NULL matches all the fingerprints.
 * @param[in] map_type Mapping type of the entry. 0 matches all the mapping types.
 * @param[in] name Specific username for the entry. NULL matches all the usernames.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_tls_endpt_del_ctn(const char *endpt_name, int64_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name);

#endif /* NC_ENABLED_TLS */

#endif /* NC_SESSION_SERVER_H_ */
