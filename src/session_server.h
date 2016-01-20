/**
 * \file session_server.h
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 session server manipulation
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
 * @brief Set the termination reason for a session.
 *
 * @param[in] session Session to modify.
 * @param[in] reason Reason of termination.
 */
void nc_session_set_term_reason(struct nc_session *session, NC_SESSION_TERM_REASON reason);

/**
 * @brief Initialize the server using a libyang context.
 *
 * The context is not modified internally, only its dictionary is used for holding
 * all the strings. When the dictionary is being written to or removed from,
 * libnetconf2 always holds ctx lock using nc_ctx_lock(). Reading models is considered
 * thread-safe as models cannot be removed and are rarely modified.
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
 * Access to the context in libnetconf2 functions is not managed in any way,
 * the application is responsible for handling it in a thread-safe manner.
 *
 * @param[in] ctx Core NETCONF server context.
 * @return 0 on success, -1 on error.
 */
int nc_server_init(struct ly_ctx *ctx);

/**
 * @brief Destroy any dynamically allocated server resources.
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
 * @brief Set server timeout for receiving a hello message.
 *
 * @param[in] hello_timeout Hello message timeout. 0 for infinite waiting.
 */
void nc_server_set_hello_timeout(uint16_t hello_timeout);

/**
 * @brief Set server timeout for dropping an idle session.
 *
 * @param[in] idle_timeout Idle session timeout. 0 to never drop a session
 * because of inactivity.
 */
void nc_server_set_idle_timeout(uint16_t idle_timeout);

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
 * @return 0 on success, 1 if not found, -1 on error.
 */
int nc_ps_del_session(struct nc_pollsession *ps, struct nc_session *session);

/**
 * @brief Poll sessions and process any received RPCs.
 *
 * All the sessions must be running. If a session fails causing it to change its
 * status, it can be learnt from the return value. Only one event (new RPC, TODO
 * new SSH channel request) on one session is handled in one function call.
 *
 * @param[in] ps Pollsession structure to use.
 * @param[in] timeout Poll timeout in milliseconds. 0 for non-blocking call, -1 for
 * infinite waiting.
 * @return 0 on elapsed timeout,
 *         1 if an RPC was processed,
 *         2 if an RPC was processed and there are unhandled events on other sessions,
 *         3 if a session from \p ps changed its status (was invalidated),
 *         -1 on error.
 */
int nc_ps_poll(struct nc_pollsession *ps, int timeout);

/**
 * @brief Lock server context.
 *
 * @param[in] timeout Timeout in milliseconds. 0 for non-blocking call, -1 for
 * infinite waiting.
 * @param[out] elapsed Elapsed milliseconds will be added to this variable.
 * Can be NULL.
 * @return 0 on elapsed timeout, 1 on success, -1 on error.
 */
int nc_ctx_lock(int timeout, int *elapsed);

/**
 * @brief Unlock server context.
 *
 * @return 0 on success, -1 on error.
 */
int nc_ctx_unlock(void);

#if defined(ENABLE_SSH) || defined(ENABLE_TLS)

/**
 * @brief Add a new server bind and start listening on it.
 *
 * @param[in] address IP address to bind to.
 * @param[in] port Port to bind to.
 * @param[in] ti Expected transport protocol of incoming connections.
 * @return 0 on success, -1 on error.
 */
int nc_server_add_bind_listen(const char *address, uint16_t port, NC_TRANSPORT_IMPL ti);

/**
 * @brief Stop listening on and remove a server bind.
 *
 * @param[in] address IP address the bind was bound to. NULL matches all the addresses.
 * @param[in] port Port the bind was bound to. NULL matches all the ports.
 * @param[in] ti Expected transport. 0 matches all.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_del_bind(const char *address, uint16_t port, NC_TRANSPORT_IMPL ti);

/**
 * @brief Accept new sessions on all the listening binds.
 *
 * @param[in] timeout Timeout for receiving a new connection in milliseconds, 0 for
 * non-blocking call, -1 for infinite waiting.
 * @param[out] session New session on success.
 * @return 1 on success, 0 on timeout, -1 or error.
 */
int nc_accept(int timeout, struct nc_session **session);

#endif /* ENABLE_SSH || ENABLE_TLS */

#ifdef ENABLE_SSH

/**
 * @brief Set SSH host keys the server will identify itself with. Each of RSA, DSA, and
 * ECDSA key can be set. If the particular type was already set, it is replaced.
 *
 * @param[in] privkey_path Path to a private key.
 * @return 0 on success, -1 on error.
 */
int nc_ssh_server_set_hostkey(const char *privkey_path);

/**
 * @brief Set SSH banner the server will send to every client.
 *
 * @param[in] banner SSH banner.
 * @return 0 on success, -1 on error.
 */
int nc_ssh_server_set_banner(const char *banner);

/**
 * @brief Set accepted SSH authentication methods. All (publickey, password, interactive)
 * are supported by default.
 *
 * @param[in] auth_methods Accepted authentication methods bit field of NC_SSH_AUTH_TYPE.
 * @return 0 on success, -1 on error.
 */
int nc_ssh_server_set_auth_methods(int auth_methods);

/**
 * @brief Set SSH authentication attempts of every client. 3 by default.
 *
 * @param[in] auth_attempts Failed authentication attempts before a client is dropped.
 * @return 0 on success, -1 on error.
 */
int nc_ssh_server_set_auth_attempts(uint16_t auth_attempts);

/**
 * @brief Set SSH authentication timeout. 10 seconds by default.
 *
 * @param[in] auth_timeout Number of seconds before an unauthenticated client is dropped.
 * @return 0 on success, -1 on error.
 */
int nc_ssh_server_set_auth_timeout(uint16_t auth_timeout);

/**
 * @brief Add an authorized client SSH public key. This public key can be used for
 * publickey authentication afterwards.
 *
 * @param[in] pubkey_path Path to the public key.
 * @param[in] username Username that the client with the public key must use.
 * @return 0 on success, -1 on error.
 */
int nc_ssh_server_add_authkey(const char *pubkey_path, const char *username);

/**
 * @brief Remove an authorized client SSH public key.
 *
 * @param[in] pubkey_path Path to an authorized public key. NULL matches all the keys.
 * @param[in] username Username for an authorized public key. NULL matches all the usernames.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_ssh_server_del_authkey(const char *pubkey_path, const char *username);

/**
 * @brief Free all the various SSH server options.
 */
void nc_ssh_server_free_opts(void);

#endif /* ENABLE_SSH */

#ifdef ENABLE_TLS

/**
 * @brief Set server TLS certificate. Alternative to nc_tls_server_set_cert_path().
 * There can only be one certificate for each key type, it is replaced if already set.
 *
 * @param[in] cert Base64-encoded certificate in ASN.1 DER encoding.
 * @return 0 on success, -1 on error.
 */
int nc_tls_server_set_cert(const char *cert);

/**
 * @brief Set server TLS certificate. Alternative to nc_tls_server_set_cert().
 * There can only be one certificate for each key type, it is replaced if already set.
 *
 * @param[in] cert_path Path to a certificate file in PEM format.
 * @return 0 on success, -1 on error.
 */
int nc_tls_server_set_cert_path(const char *cert_path);

/**
 * @brief Set server TLS private key matching the certificate.
 * Alternative to nc_tls_server_set_key_path(). There can only be one of every key
 * type, it is replaced if already set.
 *
 * @param[in] privkey Base64-encoded certificate in ASN.1 DER encoding.
 * @param[in] is_rsa Whether \p privkey are the data of an RSA (1) or DSA (0) key.
 * @return 0 on success, -1 on error.
 */
int nc_tls_server_set_key(const char *privkey, int is_rsa);

/**
 * @brief Set server TLS private key matching the certificate.
 * Alternative to nc_tls_server_set_key_path(). There can only be one of every key
 * type, it is replaced if already set.
 *
 * @param[in] privkey_path Path to a private key file in PEM format.
 * @return 0 on success, -1 on error.
 */
int nc_tls_server_set_key_path(const char *privkey_path);

/**
 * @brief Add a trusted certificate. Can be both a CA or a client one.
 *
 * @param[in] cert Base64-enocded certificate in ASN.1DER encoding.
 * @return 0 on success, -1 on error.
 */
int nc_tls_server_add_trusted_cert(const char *cert);

/**
 * @brief Add a trusted certificate. Can be both a CA or a client one.
 *
 * @param[in] cert_path Path to a trusted certificate file in PEM format.
 * @return 0 on success, -1 on error.
 */
int nc_tls_server_add_trusted_cert_path(const char *cert_path);

/**
 * @brief Set trusted Certificate Authority certificate locations. There can only be
 * one file and one directory, they are replaced if already set.
 *
 * @param[in] cacert_file_path Path to a trusted CA cert store file in PEM format.
 * Can be NULL.
 * @param[in] cacert_dir_path Path to a trusted CA cert store hashed directory
 * (c_rehash utility can be used to create hashes) with PEM files. Can be NULL.
 * @return 0 on success, -1 on error.
 */
int nc_tls_server_set_trusted_cacert_locations(const char *cacert_file_path, const char *cacert_dir_path);

/**
 * @brief Destroy and clean all the set certificates and private keys. CRLs and
 * CTN entries are not affected.
 */
void nc_tls_server_destroy_certs(void);

/**
 * @brief Set Certificate Revocation List locations. There can only be one file
 * and one directory, they are replaced if already set.
 *
 * @param[in] crl_file_path Path to a CRL store file in PEM format. Can be NULL.
 * @param[in] crl_dir_path Path to a CRL store hashed directory (c_rehash utility
 * can be used to create hashes) with PEM files. Can be NULL.
 * @return 0 on success, -1 on error.
 */
int nc_tls_server_set_crl_locations(const char *crl_file_path, const char *crl_dir_path);

/**
 * @brief Destroy and clean CRLs. Certificates, priavte keys, and CTN entries are
 * not affected.
 */
void nc_tls_server_destroy_crls(void);

/**
 * @brief Add a Cert-to-name entry.
 *
 * @param[in] id Priority of the entry.
 * @param[in] fingerprint Matching certificate fingerprint.
 * @param[in] map_type Type of username-certificate mapping.
 * @param[in] name Specific username if \p map_type == NC_TLS_CTN_SPECIFED. Must be NULL otherwise.
 * @return 0 on success, -1 on error.
 */
int nc_tls_server_add_ctn(uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name);

/**
 * @brief Remove a Cert-to-name entry.
 *
 * @param[in] id Priority of the entry. -1 matches all the priorities.
 * @param[in] fingerprint Fingerprint fo the entry. NULL matches all the fingerprints.
 * @param[in] map_type Mapping type of the entry. 0 matches all the mapping types.
 * @param[in] name Specific username for the entry. NULL matches all the usernames.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_tls_server_del_ctn(int64_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name);

/**
 * @brief Free all the various TLS server options.
 */
void nc_tls_server_free_opts(void);

#endif /* ENABLE_TLS */

#endif /* NC_SESSION_SERVER_H_ */
