/**
 * \file session_server_ch.h
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 Call Home session server manipulation
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_SESSION_SERVER_CH_H_
#define NC_SESSION_SERVER_CH_H_

#include <stdint.h>
#include <libyang/libyang.h>

#include "session.h"
#include "netconf.h"

#ifdef NC_ENABLED_SSH

/**
 * @brief Establish an SSH Call Home connection with a listening NETCONF client.
 *
 * @param[in] host Host the client is listening on.
 * @param[in] port Port the client is listening on.
 * @param[out] session New Call Home session.
 * @return 1 on success, 0 on timeout, -1 on error.
 */
int nc_connect_callhome_ssh(const char *host, uint16_t port, struct nc_session **session);

/**
 * @brief Set Call Home SSH host keys the server will identify itself with. Each of RSA, DSA, and
 *        ECDSA keys can be set. If the particular type was already set, it is replaced.
 *
 * @param[in] privkey_path Path to a private key.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_ch_set_hostkey(const char *privkey_path);

/**
 * @brief Set Call Home SSH banner the server will send to every client.
 *
 * @param[in] banner SSH banner.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_ch_set_banner(const char *banner);

/**
 * @brief Set accepted Call Home SSH authentication methods. All (publickey, password, interactive)
 *        are supported by default.
 *
 * @param[in] auth_methods Accepted authentication methods bit field of NC_SSH_AUTH_TYPE.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_ch_set_auth_methods(int auth_methods);

/**
 * @brief Set Call Home SSH authentication attempts of every client. 3 by default.
 *
 * @param[in] auth_attempts Failed authentication attempts before a client is dropped.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_ch_set_auth_attempts(uint16_t auth_attempts);

/**
 * @brief Set Call Home SSH authentication timeout. 10 seconds by default.
 *
 * @param[in] auth_timeout Number of seconds before an unauthenticated client is dropped.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_ch_set_auth_timeout(uint16_t auth_timeout);

/**
 * @brief Add an authorized Call Home client SSH public key. This public key can be used for
 *        publickey authentication afterwards.
 *
 * @param[in] pubkey_path Path to the public key.
 * @param[in] username Username that the client with the public key must use.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_ch_add_authkey(const char *pubkey_path, const char *username);

/**
 * @brief Remove an authorized Call Home client SSH public key.
 *
 * @param[in] pubkey_path Path to an authorized public key. NULL matches all the keys.
 * @param[in] username Username for an authorized public key. NULL matches all the usernames.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_ssh_ch_del_authkey(const char *pubkey_path, const char *username);

/**
 * @brief Clear all the SSH Call Home options. Afterwards a new set of options
 *        can be set for the next client to connect to.
 */
void nc_server_ssh_ch_clear_opts(void);

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

/**
 * @brief Establish a TLS Call Home connection with a listening NETCONF client.
 *
 * @param[in] host Host the client is listening on.
 * @param[in] port Port the client is listening on.
 * @param[out] session New Call Home session.
 * @return 1 on success, 0 on timeout, -1 on error.
 */
int nc_connect_callhome_tls(const char *host, uint16_t port, struct nc_session **session);

/**
 * @brief Set server Call Home TLS certificate. Alternative to nc_tls_server_set_cert_path().
 *        There can only be one certificate for each key type, it is replaced if already set.
 *
 * @param[in] cert Base64-encoded certificate in ASN.1 DER encoding.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_set_cert(const char *cert);

/**
 * @brief Set server Call Home TLS certificate. Alternative to nc_tls_server_set_cert().
 *        There can only be one certificate for each key type, it is replaced if already set.
 *
 * @param[in] cert_path Path to a certificate file in PEM format.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_set_cert_path(const char *cert_path);

/**
 * @brief Set server Call Home TLS private key matching the certificate.
 *        Alternative to nc_tls_server_set_key_path(). There can only be one of every key
 *        type, it is replaced if already set.
 *
 * @param[in] privkey Base64-encoded certificate in ASN.1 DER encoding.
 * @param[in] is_rsa Whether \p privkey are the data of an RSA (1) or DSA (0) key.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_set_key(const char *privkey, int is_rsa);

/**
 * @brief Set server Call Home TLS private key matching the certificate.
 *        Alternative to nc_tls_server_set_key_path(). There can only be one of every key
 *        type, it is replaced if already set.
 *
 * @param[in] privkey_path Path to a private key file in PEM format.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_set_key_path(const char *privkey_path);

/**
 * @brief Add a Call Home trusted certificate. Can be both a CA or a client one.
 *
 * @param[in] cert Base64-enocded certificate in ASN.1 DER encoding.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_add_trusted_cert(const char *cert);

/**
 * @brief Add a Call Home trusted certificate. Can be both a CA or a client one.
 *
 * @param[in] cert_path Path to a trusted certificate file in PEM format.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_add_trusted_cert_path(const char *cert_path);

/**
 * @brief Set trusted Call Home Certificate Authority certificate locations. There
 *        can only be one file and one directory, they are replaced if already set.
 *
 * @param[in] ca_file Path to a trusted CA cert store file in PEM format.
 *                    Can be NULL.
 * @param[in] ca_dir Path to a trusted CA cert store hashed directory
 *                   (c_rehash utility can be used to create hashes)
 *                   with PEM files. Can be NULL.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_set_trusted_ca_paths(const char *ca_file, const char *ca_dir);

/**
 * @brief Destroy and clean all the set Call Home certificates and private keys.
 *        CRLs and CTN entries are not affected.
 */
void nc_server_tls_ch_clear_certs(void);

/**
 * @brief Set Call Home Certificate Revocation List locations. There can only be
 *        one file and one directory, they are replaced if already set.
 *
 * @param[in] crl_file Path to a CRL store file in PEM format. Can be NULL.
 * @param[in] crl_dir Path to a CRL store hashed directory (c_rehash utility
 *                    can be used to create hashes) with PEM files. Can be NULL.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_set_crl_paths(const char *crl_file, const char *crl_dir);

/**
 * @brief Destroy and clean Call Home CRLs. Call Home certificates, private keys,
 *        and CTN entries are not affected.
 */
void nc_server_tls_ch_clear_crls(void);

/**
 * @brief Add a Call Home Cert-to-name entry.
 *
 * @param[in] id Priority of the entry.
 * @param[in] fingerprint Matching certificate fingerprint.
 * @param[in] map_type Type of username-certificate mapping.
 * @param[in] name Specific username if \p map_type == NC_TLS_CTN_SPECIFED. Must be NULL otherwise.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_add_ctn(uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name);

/**
 * @brief Remove a Call Home Cert-to-name entry.
 *
 * @param[in] id Priority of the entry. -1 matches all the priorities.
 * @param[in] fingerprint Fingerprint fo the entry. NULL matches all the fingerprints.
 * @param[in] map_type Mapping type of the entry. 0 matches all the mapping types.
 * @param[in] name Specific username for the entry. NULL matches all the usernames.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_tls_ch_del_ctn(int64_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name);

/**
 * @brief Clear all the TLS Call Home options. Afterwards a new set of options
 *        can be set for the next client to connect.
 */
void nc_server_tls_ch_clear_opts(void);

#endif /* NC_ENABLED_TLS */

#endif /* NC_SESSION_SERVER_CH_H_ */
