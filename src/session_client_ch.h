/**
 * \file session_client_ch.h
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 Call Home session client manipulation
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

#ifndef NC_SESSION_CLIENT_CH_H_
#define NC_SESSION_CLIENT_CH_H_

#include <libyang/libyang.h>

#include "session.h"
#include "netconf.h"
#include "messages_client.h"

#if defined(ENABLE_SSH) || defined(ENABLE_TLS)

/**
 * @brief Accept a Call Home connection on any of the listening binds.
 *
 * @param[in] timeout Timeout for receiving a new connection in milliseconds, 0 for
 *            non-blocking call, -1 for infinite waiting.
 * @param[in] ctx Session context to use. Can be NULL.
 * @param[out] session New session.
 * @return 1 on success, 0 on timeout, -1 on error.
 */
int nc_accept_callhome(int timeout, struct ly_ctx *ctx, struct nc_session **session);

#endif /* ENABLE_SSH || ENABLE_TLS */

#ifdef ENABLE_SSH

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
 * Function is provided only via nc_client.h header file and only when libnetconf2 is compiled with libssh support.
 *
 * @param[in] pub_key Path to the public key.
 * @param[in] priv_key Path to the private key.
 * @return 0 on success, -1 on error.
 */
int nc_client_ssh_ch_add_keypair(const char *pub_key, const char *priv_key);

/**
 * @brief Remove an SSH public and private key pair that was used for Call Home client authentication.
 *
 * Function is provided only via nc_client.h header file and only when libnetconf2 is compiled with libssh support.
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
 * Function is provided only via nc_client.h header file and only when libnetconf2 is compiled with libssh support.
 *
 * @param[in] auth_type Authentication method to modify the prefrence of.
 * @param[in] pref Preference of \p auth_type. Negative values disable the method.
 */
void nc_client_ssh_ch_set_auth_pref(NC_SSH_AUTH_TYPE auth_type, int16_t pref);

/**
 * @brief Get SSH Call Home authentication method preference.
 *
 * Function is provided only via nc_client.h header file and only when libnetconf2 is compiled with libssh support.
 *
 * @param[in] auth_type Authentication method to retrieve the prefrence of.
 * @return Preference of the \p auth_type.
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

#endif /* ENABLE_SSH */

#ifdef ENABLE_TLS

/**
 * @brief Add a new client bind and start listening on it for TLS Call Home connections.
 *
 * @param[in] address IP address to bind to.
 * @param[in] port Port to bind to.
 * @return 0 on success, -1 on error.
 */
int nc_client_tls_ch_add_bind_listen(const char *address, uint16_t port);

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
 * Function is provided only via nc_client.h header file and only when libnetconf2 is compiled with TLS support.
 *
 * @param[in] client_cert Path to the file containing the client certificate.
 * @param[in] client_key Path to the file containing the private key for the \p client_cert.
 *                       If NULL, key is expected to be stored with \p client_cert.
 * @return 0 on success, -1 on error.
 */
int nc_client_tls_ch_set_cert_key_paths(const char *client_cert, const char *client_key);

/**
 * @brief Get client Call Home authentication identity - a certificate and a private key.
 *
 * Function is provided only via nc_client.h header file and only when libnetconf2 is compiled with TLS support.
 *
 * @param[out] client_cert Path to the file containing the client certificate. Can be NULL.
 * @param[out] client_key Path to the file containing the private key for the \p client_cert.
 *                        Can be NULL.
 */
void nc_client_tls_ch_get_cert_key_paths(const char **client_cert, const char **client_key);

/**
 * @brief Set client Call Home trusted CA certificates.
 *
 * @param[in] ca_file Location of the CA certificate file used to verify server certificates.
 *                    For more info, see the documentation for SSL_CTX_load_verify_locations() from OpenSSL.
 * @param[in] ca_dir Location of the CA certificates directory used to verify the server certificates.
 *                   For more info, see the documentation for SSL_CTX_load_verify_locations() from OpenSSL.
 * @return 0 on success, -1 on error.
 */
int nc_client_tls_ch_set_trusted_ca_paths(const char *ca_file, const char *ca_dir);

/**
 * @brief Get client Call Home trusted CA certificates.
 *
 * @param[out] ca_file Location of the CA certificate file used to verify server certificates.
 *                     Can be NULL.
 * @param[out] ca_dir Location of the CA certificates directory used to verify the server certificates.
 *                    Can be NULL.
 */
void nc_client_tls_ch_get_trusted_ca_paths(const char **ca_file, const char **ca_dir);

/**
 * @brief Set client Call Home Certificate Revocation Lists.
 *
 * @param[in] crl_file Location of the CRL certificate file used to check for revocated certificates.
 * @param[in] crl_dir Location of the CRL certificate directory used to check for revocated certificates.
 * @return 0 on success, -1 on error.
 */
int nc_client_tls_ch_set_crl_paths(const char *crl_file, const char *crl_dir);

/**
 * @brief Get client Call Home Certificate Revocation Lists.
 *
 * @param[out] crl_file Location of the CRL certificate file used to check for revocated certificates.
 *                      Can be NULL.
 * @param[out] crl_dir Location of the CRL certificate directory used to check for revocated certificates.
 *                     Can be NULL.
 */
void nc_client_tls_ch_get_crl_paths(const char **crl_file, const char **crl_dir);

#endif /* ENABLE_TLS */

#endif /* NC_SESSION_CLIENT_CH_H_ */
