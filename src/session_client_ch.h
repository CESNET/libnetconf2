/**
 * @file session_client_ch.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 Call Home session client manipulation
 *
 * @copyright
 * Copyright (c) 2015 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_SESSION_CLIENT_CH_H_
#define NC_SESSION_CLIENT_CH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <libyang/libyang.h>

#ifdef NC_ENABLED_SSH_TLS
# include <libssh/libssh.h>
#endif /* NC_ENABLED_SSH_TLS */

#include "messages_client.h"
#include "netconf.h"
#include "session.h"

#ifdef NC_ENABLED_SSH_TLS

/**
 * @defgroup client_ch Client-side Call Home
 * @ingroup client
 *
 * @brief Call Home functionality for client-side applications.
 * @{
 */

/**
 * @brief Accept a Call Home connection on any of the listening binds.
 *
 * @param[in] timeout Timeout for receiving a new connection in milliseconds, 0 for
 * non-blocking call, -1 for infinite waiting.
 * @param[in,out] ctx Optional custom context to use for the session. If not set, a default context is created.
 * Any YANG modules not present in the context and supported by the server are loaded using \<get-schema\>
 * (if supported) and/or by searching the searchpath (see ::nc_client_set_schema_searchpath()).
 * @param[out] session New session.
 * @return 1 on success, 0 on timeout, -1 on error.
 */
int nc_accept_callhome(int timeout, struct ly_ctx *ctx, struct nc_session **session);

/** @} Client-side Call Home */

/**
 * @defgroup client_ch_ssh Client-side Call Home on SSH
 * @ingroup client_ch
 *
 * @brief SSH settings for the Call Home functionality
 * @{
 */

/**
 * @brief Set SSH Call Home behaviour of checking the host key and adding/reading entries to/from the known_hosts file.
 *
 * The default mode is ::NC_SSH_KNOWNHOSTS_ASK.
 *
 * @param[in] mode Server host key checking mode.
 */
void nc_client_ssh_ch_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_MODE mode);

/**
 * @brief Set SSH Call Home path to the known_hosts file for connections.
 *
 * Repetetive calling replaces the value. If the given file doesn't exist and the process has sufficient
 * rights, it gets created whenever the file is needed, otherwise an error occurs. If NULL is passed or the
 * path isn't set, the default known_hosts file will be used.
 *
 * @param[in] path Path to the known_hosts file.
 * @return 0 on success, 1 on error.
 */
int nc_client_ssh_ch_set_knownhosts_path(const char *path);

/**
 * @brief Set SSH Call Home password authentication callback.
 *
 * Repetitive calling causes replacing of the previous callback and its private data. Caller is responsible for
 * freeing the private data when necessary (the private data can be obtained by
 * nc_client_ssh_ch_get_auth_password_clb()).
 *
 * @param[in] auth_password Function to call, returns the password for username\@hostname.
 * If NULL, the default callback is set.
 * @param[in] priv Optional private data to be passed to the callback function.
 */
void nc_client_ssh_ch_set_auth_password_clb(char *(*auth_password)(const char *username, const char *hostname, void *priv),
        void *priv);

/**
 * @brief Get currently set SSH Call Home password authentication callback and its private data
 * previously set by nc_client_ssh_ch_set_auth_password_clb().
 *
 * @param[out] auth_password Currently set callback, NULL in case of the default callback.
 * @param[out] priv Currently set (optional) private data to be passed to the callback function.
 */
void nc_client_ssh_ch_get_auth_password_clb(char *(**auth_password)(const char *username, const char *hostname, void *priv),
        void **priv);

/**
 * @brief Set SSH Call Home interactive authentication callback.
 *
 * Repetitive calling causes replacing of the previous callback and its private data. Caller is responsible for
 * freeing the private data when necessary (the private data can be obtained by
 * nc_client_ssh_ch_get_auth_interactive_clb()).
 *
 * @param[in] auth_interactive Function to call for every question, returns the answer for
 * authentication name with instruction and echoing prompt. If NULL, the default callback is set.
 * @param[in] priv Optional private data to be passed to the callback function.
 */
void nc_client_ssh_ch_set_auth_interactive_clb(char *(*auth_interactive)(const char *auth_name, const char *instruction,
        const char *prompt, int echo, void *priv),
        void *priv);

/**
 * @brief Get currently set SSH Call Home interactive authentication callback and its private data
 * previously set by nc_client_ssh_ch_set_auth_interactive_clb().
 *
 * @param[out] auth_interactive Currently set callback, NULL in case of the default callback.
 * @param[out] priv Currently set (optional) private data to be passed to the callback function.
 */
void nc_client_ssh_ch_get_auth_interactive_clb(char *(**auth_interactive)(const char *auth_name, const char *instruction,
        const char *prompt, int echo, void *priv),
        void **priv);

/**
 * @brief Set SSH Call Home publickey authentication encrypted private key passphrase callback.
 *
 * Repetitive calling causes replacing of the previous callback and its private data. Caller is responsible for
 * freeing the private data when necessary (the private data can be obtained by
 * nc_client_ssh_ch_get_auth_privkey_passphrase_clb()).
 *
 * @param[in] auth_privkey_passphrase Function to call for every question, returns the passphrase for the specific
 * private key.
 * @param[in] priv Optional private data to be passed to the callback function.
 */
void nc_client_ssh_ch_set_auth_privkey_passphrase_clb(char *(*auth_privkey_passphrase)(const char *privkey_path, void *priv),
        void *priv);

/**
 * @brief Get currently set SSH Call Home publickey authentication encrypted private key passphrase callback and its
 * private data previously set by nc_client_ssh_ch_set_auth_privkey_passphrase_clb().
 *
 * @param[out] auth_privkey_passphrase Currently set callback, NULL in case of the default callback.
 * @param[out] priv Currently set (optional) private data to be passed to the callback function.
 */
void nc_client_ssh_ch_get_auth_privkey_passphrase_clb(char *(**auth_privkey_passphrase)(const char *privkey_path, void *priv),
        void **priv);

/**
 * @brief Add a new client bind and start listening on it for SSH Call Home connections.
 *
 * @param[in] address IP address to bind to.
 * @param[in] port Port to bind to.
 * @return 0 on success, -1 on error.
 */
int nc_client_ssh_ch_add_bind_listen(const char *address, uint16_t port);

/**
 * @brief Remove an SSH listening client bind.
 *
 * @param[in] address IP address the socket was bound to. NULL matches all.
 * @param[in] port Port the socket was bound to. 0 matches all.
 * @return 0 on success, -1 on not found.
 */
int nc_client_ssh_ch_del_bind(const char *address, uint16_t port);

/**
 * @brief Add an SSH public and private key pair to be used for Call Home client authentication.
 *
 * Private key can be encrypted, the passphrase will be asked for before using it.
 *
 * @param[in] pub_key Path to the public key.
 * @param[in] priv_key Path to the private key.
 * @return 0 on success, -1 on error.
 */
int nc_client_ssh_ch_add_keypair(const char *pub_key, const char *priv_key);

/**
 * @brief Remove an SSH public and private key pair that was used for Call Home client authentication.
 *
 * @param[in] idx Index of the keypair starting with 0.
 * @return 0 on success, -1 on error.
 */
int nc_client_ssh_ch_del_keypair(int idx);

/**
 * @brief Get the number of public an private key pairs set to be used for Call Home client authentication.
 *
 * @return Keypair count.
 */
int nc_client_ssh_ch_get_keypair_count(void);

/**
 * @brief Get a specific keypair set to be used for Call Home client authentication.
 *
 * @param[in] idx Index of the specific keypair.
 * @param[out] pub_key Path to the public key.
 * @param[out] priv_key Path to the private key.
 * @return 0 on success, -1 on error.
 */
int nc_client_ssh_ch_get_keypair(int idx, const char **pub_key, const char **priv_key);

/**
 * @brief Set SSH Call Home authentication method preference.
 *
 * The default preference is as follows:
 * - public key authentication (3)
 * - password authentication (2)
 * - interactive authentication (1)
 *
 * @param[in] auth_type Authentication method to modify the preference of.
 * @param[in] pref Preference of @p auth_type. Higher number increases priority, negative values disable the method.
 */
void nc_client_ssh_ch_set_auth_pref(NC_SSH_AUTH_TYPE auth_type, int16_t pref);

/**
 * @brief Get SSH Call Home authentication method preference.
 *
 * @param[in] auth_type Authentication method to retrieve the prefrence of.
 * @return Preference of the @p auth_type.
 */
int16_t nc_client_ssh_ch_get_auth_pref(NC_SSH_AUTH_TYPE auth_type);

/**
 * @brief Set client Call Home SSH username used for authentication.
 *
 * @param[in] username Username to use.
 * @return 0 on success, -1 on error.
 */
int nc_client_ssh_ch_set_username(const char *username);

/**
 * @brief Get client Call Home SSH username used for authentication.
 *
 * @return Username used.
 */
const char *nc_client_ssh_ch_get_username(void);

/** @} Client-side Call Home on SSH */

/**
 * @defgroup client_ch_tls Client-side Call Home on TLS
 * @ingroup client_ch
 *
 * @brief TLS settings for the Call Home functionality
 * @{
 */

/**
 * @brief Add a new client bind and start listening on it for TLS Call Home connections.
 *
 * @param[in] address IP address to bind to.
 * @param[in] port Port to bind to.
 * @return 0 on success, -1 on error.
 */
int nc_client_tls_ch_add_bind_listen(const char *address, uint16_t port);

/**
 * @brief Add a new client bind and start listening on it for TLS Call Home connections coming from the specified hostname.
 *
 * @param[in] address IP address to bind to.
 * @param[in] port Port to bind to.
 * @param[in] hostname Expected server hostname, verified by TLS when connecting to it. If NULL, the check is skipped.
 * @return 0 on success, -1 on error.
 */
int nc_client_tls_ch_add_bind_hostname_listen(const char *address, uint16_t port, const char *hostname);

/**
 * @brief Remove a TLS listening client bind.
 *
 * @param[in] address IP address the socket was bound to. NULL matches all.
 * @param[in] port Port the socket was bound to. 0 matches all.
 * @return 0 on success, -1 on not found.
 */
int nc_client_tls_ch_del_bind(const char *address, uint16_t port);

/**
 * @brief Set client Call Home authentication identity - a certificate and a private key.
 *
 * @param[in] client_cert Path to the file containing the client certificate.
 * @param[in] client_key Path to the file containing the private key for the @p client_cert.
 * If NULL, key is expected to be stored with @p client_cert.
 * @return 0 on success, -1 on error.
 */
int nc_client_tls_ch_set_cert_key_paths(const char *client_cert, const char *client_key);

/**
 * @brief Get client Call Home authentication identity - a certificate and a private key.
 *
 * @param[out] client_cert Path to the file containing the client certificate. Can be NULL.
 * @param[out] client_key Path to the file containing the private key for the @p client_cert. Can be NULL.
 */
void nc_client_tls_ch_get_cert_key_paths(const char **client_cert, const char **client_key);

/**
 * @brief Set client Call Home trusted CA certificates.
 *
 * @param[in] ca_file Location of the CA certificate file used to verify server certificates.
 * For more info, see the documentation for SSL_CTX_load_verify_locations() from OpenSSL.
 * @param[in] ca_dir Location of the CA certificates directory used to verify the server certificates.
 * For more info, see the documentation for SSL_CTX_load_verify_locations() from OpenSSL.
 * @return 0 on success, -1 on error.
 */
int nc_client_tls_ch_set_trusted_ca_paths(const char *ca_file, const char *ca_dir);

/**
 * @brief Get client Call Home trusted CA certificates.
 *
 * @param[out] ca_file Location of the CA certificate file used to verify server certificates. Can be NULL.
 * @param[out] ca_dir Location of the CA certificates directory used to verify the server certificates. Can be NULL.
 */
void nc_client_tls_ch_get_trusted_ca_paths(const char **ca_file, const char **ca_dir);

/**
 * @brief Deprecated.
 */
int nc_client_tls_ch_set_crl_paths(const char *crl_file, const char *crl_dir);

/**
 * @brief Deprecated.
 */
void nc_client_tls_ch_get_crl_paths(const char **crl_file, const char **crl_dir);

/** @} Client-side Call Home on TLS */

#endif /* NC_ENABLED_SSH_TLS */

#ifdef __cplusplus
}
#endif

#endif /* NC_SESSION_CLIENT_CH_H_ */
