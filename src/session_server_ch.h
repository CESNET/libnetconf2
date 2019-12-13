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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <libyang/libyang.h>

#include "session.h"
#include "netconf.h"

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)

/**
 * @defgroup server_ch Server-side Call Home
 * @ingroup server
 *
 * @brief Call Home functionality for server-side applications.
 * @{
 */

/**
 * @brief Add a new Call Home client.
 *
 * @param[in] name Arbitrary unique client name.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_add_client(const char *name);

/**
 * @brief Drop any connections, stop connecting and remove a client.
 *
 * @param[in] name Client name. NULL matches all the clients.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_ch_del_client(const char *name);

/**
 * @brief Add a new Call Home client endpoint.
 *
 * @param[in] client_name Existing client name.
 * @param[in] endpt_name Arbitrary unique (within the client) endpoint name.
 * @param[in] ti Transport protocol to use.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_add_endpt(const char *client_name, const char *endpt_name, NC_TRANSPORT_IMPL ti);

/**
 * @brief Remove a Call Home client endpoint.
 *
 * @param[in] client_name Existing client name.
 * @param[in] endpt_name Existing endpoint of \p client_name. NULL matches all endpoints.
 * @param[in] ti Client transport protocol. NULL matches any protocol.
 *               Redundant to set if \p endpt_name is set, client names are
 *               unique disregarding their protocol.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_del_endpt(const char *client_name, const char *endpt_name, NC_TRANSPORT_IMPL ti);

/**
 * @brief Change Call Home client endpoint listening address.
 *
 * On error the previous listening socket (if any) is left untouched.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of \p client_name.
 * @param[in] address New listening address.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_endpt_set_address(const char *client_name, const char *endpt_name, const char *address);

/**
 * @brief Change Call Home client endpoint listening port.
 *
 * On error the previous listening socket (if any) is left untouched.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of \p client_name.
 * @param[in] port New listening port.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_endpt_set_port(const char *client_name, const char *endpt_name, uint16_t port);

/**
 * @brief Change Call Home client endpoint keepalives state. Affects only new connections.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of \p client_name.
 * @param[in] enable Whether to enable or disable keepalives.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_endpt_enable_keepalives(const char *client_name, const char *endpt_name, int enable);

/**
 * @brief Change Call Home client endpoint keepalives parameters. Affects only new connections.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of \p client_name.
 * @param[in] idle_time Keepalive idle time in seconds, 1 by default, -1 to keep previous value.
 * @param[in] max_probes Keepalive max probes sent, 10 by default, -1 to keep previous value.
 * @param[in] probe_interval Keepalive probe interval in seconds, 5 by default, -1 to keep previous value.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_endpt_set_keepalives(const char *client_name, const char *endpt_name, int idle_time,
        int max_probes, int probe_interval);

/**
 * @brief Set Call Home client connection type.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] conn_type Call Home connection type.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_set_conn_type(const char *client_name, NC_CH_CONN_TYPE conn_type);

/**
 * @brief Set Call Home client periodic connection period for reconnecting.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] period Call Home periodic connection period in minutes.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_periodic_set_period(const char *client_name, uint16_t period);

/**
 * @brief Set Call Home client periodic connection period anchor time.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] anchor_time Call Home periodic connection anchor time for the period.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_periodic_set_anchor_time(const char *client_name, time_t anchor_time);

/**
 * @brief Set Call Home client periodic connection idle timeout.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] idle_timeout Call Home periodic idle timeout.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_periodic_set_idle_timeout(const char *client_name, uint16_t idle_timeout);

/**
 * @brief Set Call Home client start-with policy.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] start_with Call Home client start-with.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_set_start_with(const char *client_name, NC_CH_START_WITH start_with);

/**
 * @brief Set Call Home client overall max attempts.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] max_attempts Call Home overall max reconnect attempts.
 * @return 0 on success, -1 on error.
 */
int nc_server_ch_client_set_max_attempts(const char *client_name, uint8_t max_attempts);

/**
 * @brief Establish a Call Home connection with a listening NETCONF client.
 *
 * @param[in] client_name Existing client name.
 * @param[out] session_clb Function that is called for every established session on the client. \p new_session
 *             pointer is internally discarded afterwards.
 * @return 0 if the thread was successfully created, -1 on error.
 */
int nc_connect_ch_client_dispatch(const char *client_name,
        void (*session_clb)(const char *client_name, struct nc_session *new_session));

/** @} Server-side Call Home */

#endif /* NC_ENABLED_SSH || NC_ENABLED_TLS */

#ifdef NC_ENABLED_SSH

/**
 * @defgroup server_ch_ssh Server-side Call Home on SSH
 * @ingroup server_ch
 *
 * @brief SSH settings for the Call Home functionality
 * @{
 */

/**
 * @brief Add Call Home SSH host keys the server will identify itself with. Only the name is set, the key itself
 *        wil be retrieved using a callback.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] name Arbitrary name of the host key.
 * @param[in] idx Optional index where to add the key. -1 adds at the end.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_ch_client_endpt_add_hostkey(const char *client_name, const char *endpt_name, const char *name, int16_t idx);

/**
 * @brief Delete Call Home SSH host keys. Their order is preserved.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] name Name of the host key. NULL matches all the keys, but if \p idx != -1 then this must be NULL.
 * @param[in] idx Index of the hostkey. -1 matches all indices, but if \p name != NULL then this must be -1.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_ch_client_endpt_del_hostkey(const char *client_name, const char *endpt_name, const char *name, int16_t idx);

/**
 * @brief Move Call Home SSH host key.
 *
 * @param[in] client_name Exisitng Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] key_mov Name of the host key that will be moved.
 * @param[in] key_after Name of the key that will preceed \p key_mov. NULL if \p key_mov is to be moved at the beginning.
 * @return 0 in success, -1 on error.
 */
int nc_server_ssh_ch_client_endpt_mov_hostkey(const char *client_name, const char *endpt_name, const char *key_mov,
        const char *key_after);

/**
 * @brief Set accepted Call Home SSH authentication methods. All (publickey, password, interactive)
 *        are supported by default.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] auth_methods Accepted authentication methods bit field of NC_SSH_AUTH_TYPE.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_ch_client_endpt_set_auth_methods(const char *client_name, const char *endpt_name, int auth_methods);

/**
 * @brief Get accepted Call Home SSH authentication methods.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @return Accepted authentication methods bit field of NC_SSH_AUTH_TYPE.
 */
int nc_server_ssh_ch_client_endpt_get_auth_methods(const char *client_name, const char *endpt_name);

/**
 * @brief Set Call Home SSH authentication attempts of every client. 3 by default.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] auth_attempts Failed authentication attempts before a client is dropped.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_ch_client_endpt_set_auth_attempts(const char *client_name, const char *endpt_name, uint16_t auth_attempts);

/**
 * @brief Set Call Home SSH authentication timeout. 30 seconds by default.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] auth_timeout Number of seconds before an unauthenticated client is dropped.
 * @return 0 on success, -1 on error.
 */
int nc_server_ssh_ch_client_endpt_set_auth_timeout(const char *client_name, const char *endpt_name, uint16_t auth_timeout);

/** @} Server-side Call Home on SSH */

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

/**
 * @defgroup server_ch_tls Server-side Call Home on TLS
 * @ingroup server_ch
 *
 * @brief TLS settings for the Call Home functionality
 * @{
 */

/**
 * @brief Set the server Call Home TLS certificate. Only the name is set, the certificate itself
 *        wil be retrieved using a callback.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] name Arbitrary certificate name.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_client_endpt_set_server_cert(const char *client_name, const char *endpt_name, const char *name);

/**
 * @brief Add a Call Home trusted certificate list. Can be both a CA or a client one.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] name Arbitary name identifying this certificate list.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_client_endpt_add_trusted_cert_list(const char *client_name, const char *endpt_name, const char *name);

/**
 * @brief Remove a set Call Home trusted certificate list. CRLs and CTN entries are not affected.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] name Name of the certificate list to delete. NULL deletes all the lists.
 * @return 0 on success, -1 on not found.
 */
int nc_server_tls_ch_client_endpt_del_trusted_cert_list(const char *client_name, const char *endpt_name, const char *name);

/**
 * @brief Set trusted Call Home Certificate Authority certificate locations. There
 *        can only be one file and one directory, they are replaced if already set.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] ca_file Path to a trusted CA cert store file in PEM format.
 *                    Can be NULL.
 * @param[in] ca_dir Path to a trusted CA cert store hashed directory
 *                   (c_rehash utility can be used to create hashes)
 *                   with PEM files. Can be NULL.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_client_endpt_set_trusted_ca_paths(const char *client_name, const char *endpt_name, const char *ca_file,
        const char *ca_dir);

/**
 * @brief Set Call Home Certificate Revocation List locations. There can only be
 *        one file and one directory, they are replaced if already set.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] crl_file Path to a CRL store file in PEM format. Can be NULL.
 * @param[in] crl_dir Path to a CRL store hashed directory (c_rehash utility
 *                    can be used to create hashes) with PEM files. Can be NULL.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_client_endpt_set_crl_paths(const char *client_name, const char *endpt_name, const char *crl_file,
        const char *crl_dir);

/**
 * @brief Destroy and clean Call Home CRLs. Call Home certificates, private keys,
 *        and CTN entries are not affected.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 */
void nc_server_tls_ch_client_endpt_clear_crls(const char *client_name, const char *endpt_name);

/**
 * @brief Add a cert-to-name entry.
 *
 * It is possible to add an entry step-by-step, specifying first only \p ip and in later calls
 * \p fingerprint, \p map_type, and optionally \p name spearately.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] id Priority of the entry. It must be unique. If already exists, the entry with this id
 *               is modified.
 * @param[in] fingerprint Matching certificate fingerprint. If NULL, kept temporarily unset.
 * @param[in] map_type Type of username-certificate mapping. If 0, kept temporarily unset.
 * @param[in] name Specific username used only if \p map_type == NC_TLS_CTN_SPECIFED.
 * @return 0 on success, -1 on error.
 */
int nc_server_tls_ch_client_endpt_add_ctn(const char *client_name, const char *endpt_name, uint32_t id,
        const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name);

/**
 * @brief Remove a Call Home cert-to-name entry.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in] id Priority of the entry. -1 matches all the priorities.
 * @param[in] fingerprint Fingerprint fo the entry. NULL matches all the fingerprints.
 * @param[in] map_type Mapping type of the entry. 0 matches all the mapping types.
 * @param[in] name Specific username for the entry. NULL matches all the usernames.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_tls_ch_client_endpt_del_ctn(const char *client_name, const char *endpt_name, int64_t id,
        const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name);

/**
 * @brief Get a Call Home cert-to-name entry.
 *
 * If a parameter is NULL, it is ignored. If its dereferenced value is NULL,
 * it is filled and returned. If the value is set, it is used as a filter.
 * Returns first matching entry.
 *
 * @param[in] client_name Existing Call Home client name.
 * @param[in] endpt_name Existing endpoint name of the client.
 * @param[in,out] id Priority of the entry.
 * @param[in,out] fingerprint Fingerprint fo the entry.
 * @param[in,out] map_type Mapping type of the entry.
 * @param[in,out] name Specific username for the entry.
 * @return 0 on success, -1 on not finding any match.
 */
int nc_server_tls_ch_client_endpt_get_ctn(const char *client_name, const char *endpt_name, uint32_t *id, char **fingerprint,
        NC_TLS_CTN_MAPTYPE *map_type, char **name);

/** @} Server-side Call Home on TLS */

#endif /* NC_ENABLED_TLS */

#ifdef __cplusplus
}
#endif

#endif /* NC_SESSION_SERVER_CH_H_ */
