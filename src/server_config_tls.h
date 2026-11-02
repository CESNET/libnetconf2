/**
 * @file server_config_tls.h
 * @author Roman Janota <janota@cesnet.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 server TLS configuration
 *
 * @copyright
 * Copyright (c) 2023 - 2026 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_CONFIG_SERVER_TLS_H_
#define NC_CONFIG_SERVER_TLS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdint.h>

#include <libyang/libyang.h>

#include "session.h"

/**
 * @defgroup server_config_tls TLS Server Configuration
 * @ingroup server_config
 *
 * @brief TLS server configuration creation and deletion
 * @{
 */

/**
 * @brief Creates new YANG configuration data nodes for a server's certificate.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its server certificate will be changed.
 * @param[in] privkey_path Path to the server's PEM encoded private key file.
 * @param[in] pubkey_path Optional path to the server's public key file. If not provided,
 * it will be generated from the private key.
 * @param[in] cert_path Path to the server's certificate file.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_tls_server_cert(const struct ly_ctx *ctx, const char *endpt_name, const char *privkey_path,
        const char *pubkey_path, const char *cert_path, struct lyd_node **config);

/**
 * @brief Deletes the server's certificate from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note Deleting the server certificate makes the configuration invalid.
 * Add a new server certificate to make it valid again.
 */
int nc_server_config_del_tls_server_cert(const char *endpt_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a keystore reference to the TLS server's certificate.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] asym_key_ref Name of the asymmetric key pair in the keystore to be referenced.
 * @param[in] cert_ref Name of the certificate, which must belong to the given asymmetric key pair, to be referenced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_tls_keystore_ref(const struct ly_ctx *ctx, const char *endpt_name, const char *asym_key_ref,
        const char *cert_ref, struct lyd_node **config);

/**
 * @brief Deletes a TLS server certificate keystore reference from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note Deleting the keystore reference makes the configuration invalid.
 * Add a new keystore reference to make it valid again.
 */
int nc_server_config_del_tls_keystore_ref(const char *endpt_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a client's (end-entity) certificate.
 *
 * A client certificate is authenticated if it is an exact match to a configured client certificate.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] cert_name Arbitrary identifier of the client's certificate.
 * If a client certificate with this identifier already exists, it will be changed.
 * @param[in] cert_path Path to the client's certificate file.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_tls_client_cert(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config);

/**
 * @brief Deletes a client (end-entity) certificate from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] cert_name Optional name of a certificate to be deleted.
 * If NULL, all of the end-entity certificates on the given endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note If the last certificate is deleted, the parent ee-certs container and
 * possibly the client-authentication container are also deleted to maintain
 * a valid YANG data tree.
 */
int nc_server_config_del_tls_client_cert(const char *endpt_name, const char *cert_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a truststore reference to a set of client (end-entity) certificates.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] cert_bag_ref Identifier of the certificate bag in the truststore to be referenced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_tls_client_cert_truststore_ref(const struct ly_ctx *ctx, const char *endpt_name,
        const char *cert_bag_ref, struct lyd_node **config);

/**
 * @brief Deletes a client (end-entity) certificates truststore reference from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note The parent ee-certs container and possibly the client-authentication
 * container are also deleted to maintain a valid YANG data tree.
 */
int nc_server_config_del_tls_client_cert_truststore_ref(const char *endpt_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a client certificate authority (trust-anchor) certificate.
 *
 * A client certificate is authenticated if it has a valid chain of trust to any configured CA cert.
 * The configured CA cert, up to which the valid chain of trust can be built, does not have to be
 * self-signed (the root CA). That means that the chain may be incomplete, yet the client will be authenticated.
 *
 * For example assume a certificate chain
 * A < B < C,
 * where A is the root CA, then the client certificate C will be authenticated either
 * if solely B is configured, or if both A and B are configured. C will not be authenticated
 * if just A is configured as a CA certificate.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] cert_name Arbitrary identifier of the certificate authority certificate.
 * If a CA with this identifier already exists, it will be changed.
 * @param[in] cert_path Path to the CA certificate file.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_tls_ca_cert(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config);

/**
 * @brief Deletes a client certificate authority (trust-anchor) certificate from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] cert_name Optional name of a certificate to be deleted.
 * If NULL, all of the CA certificates on the given endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note If the last certificate is deleted, the parent ca-certs container and
 * possibly the client-authentication container are also deleted to maintain
 * a valid YANG data tree.
 */
int nc_server_config_del_tls_ca_cert(const char *endpt_name, const char *cert_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a truststore reference to a set of client certificate authority (trust-anchor) certificates.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] cert_bag_ref Identifier of the certificate bag in the truststore to be referenced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_tls_ca_cert_truststore_ref(const struct ly_ctx *ctx, const char *endpt_name,
        const char *cert_bag_ref, struct lyd_node **config);

/**
 * @brief Deletes a client certificate authority (trust-anchor) certificates truststore reference from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note The parent ca-certs container and possibly the client-authentication
 * container are also deleted to maintain a valid YANG data tree.
 */
int nc_server_config_del_tls_ca_cert_truststore_ref(const char *endpt_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes, which will be a reference to another TLS endpoint's certificates.
 *
 * Whenever an user tries to connect to the referencing endpoint, all of its certificates will be tried first. If no match is
 * found, the referenced endpoint's configured certificates will be tried. The same applies to cert-to-name entries.
 *
 * @param[in] ctx libyang context
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] referenced_endpt Identifier of an endpoint, which has to exist whenever this data
 * is applied. The referenced endpoint can reference another one and so on, but there mustn't be a cycle.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_tls_endpoint_client_ref(const struct ly_ctx *ctx, const char *endpt_name,
        const char *referenced_endpt, struct lyd_node **config);

/**
 * @brief Deletes reference to another TLS endpoint's users from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_tls_endpoint_client_ref(const char *endpt_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a cert-to-name entry.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] id ID of the entry. The lower the ID, the higher the priority of the entry (it will be checked earlier).
 * @param[in] fingerprint Optional fingerprint of the entry. The fingerprint should always be set, however if it is
 * not set, it will match any certificate. Entry with no fingerprint should therefore be placed only as the last entry.
 * @param[in] map_type Mapping username to the certificate option.
 * @param[in] name Username for this cert-to-name entry. Mandatory if @p map_type is set to ::NC_TLS_CTN_SPECIFIED.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_tls_ctn(const struct ly_ctx *ctx, const char *endpt_name, uint32_t id, const char *fingerprint,
        NC_TLS_CTN_MAPTYPE map_type, const char *name, struct lyd_node **config);

/**
 * @brief Deletes a cert-to-name entry from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] id Optional ID of the CTN entry.
 * If 0, all of the cert-to-name entries on the given endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note If the last cert-to-name entry is deleted, the configuration becomes
 * invalid. Add a new cert-to-name entry to make it valid again.
 */
int nc_server_config_del_tls_ctn(const char *endpt_name, uint32_t id, struct lyd_node **config);

/**
 * @} TLS Server Configuration
 */

/**
 * @defgroup server_config_ch_tls TLS Call Home Server Configuration
 * @ingroup server_config_ch
 *
 * @brief TLS Call Home server configuration creation and deletion
 * @{
 */

/**
 * @brief Creates new YANG configuration data nodes for a Call Home server's certificate.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] privkey_path Path to the server's PEM encoded private key file.
 * @param[in] pubkey_path Optional path to the server's public key file. If not provided,
 * it will be generated from the private key.
 * @param[in] cert_path Path to the server's certificate file.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_tls_server_cert(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *privkey_path, const char *pubkey_path, const char *cert_path, struct lyd_node **config);

/**
 * @brief Deletes a Call Home server certificate from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note Deleting the server certificate makes the configuration invalid.
 * Add a new server certificate to make it valid again.
 */
int nc_server_config_del_ch_tls_server_cert(const char *client_name, const char *endpt_name,
        struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a keystore reference to the Call Home TLS server's certificate.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] asym_key_ref Name of the asymmetric key pair in the keystore to be referenced.
 * @param[in] cert_ref Name of the certificate, which must belong to the given asymmetric key pair, to be referenced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_tls_keystore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *asym_key_ref, const char *cert_ref, struct lyd_node **config);

/**
 * @brief Deletes a TLS server certificate keystore reference from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note Deleting the keystore reference makes the configuration invalid.
 * Add a new keystore reference to make it valid again.
 */
int nc_server_config_del_ch_tls_keystore_ref(const char *client_name, const char *endpt_name,
        struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home client's (end-entity) certificate.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] cert_name Arbitrary identifier of the Call Home endpoint's end-entity certificate.
 * If an Call Home endpoint's end-entity certificate with this identifier already exists, its contents will be changed.
 * @param[in] cert_path Path to the certificate file.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_tls_client_cert(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *cert_name, const char *cert_path, struct lyd_node **config);

/**
 * @brief Deletes a Call Home client (end-entity) certificate from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in] cert_name Optional identifier of a client certificate to be deleted.
 * If NULL, all of the client certificates will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note If the last certificate is deleted, the parent ee-certs container and
 * possibly the client-authentication container are also deleted to maintain
 * a valid YANG data tree.
 */
int nc_server_config_del_ch_tls_client_cert(const char *client_name, const char *endpt_name,
        const char *cert_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home truststore reference to a set of client (end-entity) certificates.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] cert_bag_ref Identifier of the certificate bag in the truststore to be referenced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_tls_client_cert_truststore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *cert_bag_ref, struct lyd_node **config);

/**
 * @brief Deletes a Call Home client (end-entity) certificates truststore reference from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note The parent ee-certs container and possibly the client-authentication
 * container are also deleted to maintain a valid YANG data tree.
 */
int nc_server_config_del_ch_tls_client_cert_truststore_ref(const char *client_name, const char *endpt_name,
        struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a client certificate authority (trust-anchor) certificate.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] cert_name Arbitrary identifier of the Call Home endpoint's certificate authority certificate.
 * If an Call Home endpoint's CA certificate with this identifier already exists, its contents will be changed.
 * @param[in] cert_path Path to the certificate file.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_tls_ca_cert(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *cert_name, const char *cert_path, struct lyd_node **config);

/**
 * @brief Deletes a Call Home client certificate authority (trust-anchor) certificate from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in] cert_name Optional identifier of a CA certificate to be deleted.
 * If NULL, all of the CA certificates will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note If the last certificate is deleted, the parent ca-certs container and
 * possibly the client-authentication container are also deleted to maintain
 * a valid YANG data tree.
 */
int nc_server_config_del_ch_tls_ca_cert(const char *client_name, const char *endpt_name,
        const char *cert_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home truststore reference to a set of client certificate authority (trust-anchor) certificates.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] cert_bag_ref Identifier of the certificate bag in the truststore to be referenced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_tls_ca_cert_truststore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *cert_bag_ref, struct lyd_node **config);

/**
 * @brief Deletes a Call Home client certificate authority (trust-anchor) certificates truststore reference from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note The parent ca-certs container and possibly the client-authentication
 * container are also deleted to maintain a valid YANG data tree.
 */
int nc_server_config_del_ch_tls_ca_cert_truststore_ref(const char *client_name, const char *endpt_name,
        struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home cert-to-name entry.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] id ID of the entry. The lower the ID, the higher the priority of the entry (it will be checked earlier).
 * @param[in] fingerprint Optional fingerprint of the entry. The fingerprint should always be set, however if it is
 * not set, it will match any certificate. Entry with no fingerprint should therefore be placed only as the last entry.
 * @param[in] map_type Mapping username to the certificate option.
 * @param[in] name Username for this cert-to-name entry. Mandatory if @p map_type is set to ::NC_TLS_CTN_SPECIFIED.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_tls_ctn(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name, struct lyd_node **config);

/**
 * @brief Deletes a Call Home cert-to-name entry from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in] id Optional identifier of the Call Home CTN entry to be deleted.
 * If 0, all of the CTN entries will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note If the last cert-to-name entry is deleted, the configuration becomes
 * invalid. Add a new cert-to-name entry to make it valid again.
 */
int nc_server_config_del_ch_tls_ctn(const char *client_name, const char *endpt_name,
        uint32_t id, struct lyd_node **config);

/**
 * @} TLS Call Home Server Configuration
 */

#ifdef __cplusplus
}
#endif

#endif /* NC_CONFIG_SERVER_TLS_H_ */
