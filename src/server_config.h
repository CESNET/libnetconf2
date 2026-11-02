/**
 * @file server_config.h
 * @author Roman Janota <janota@cesnet.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 server configuration
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

#ifndef NC_CONFIG_SERVER_H_
#define NC_CONFIG_SERVER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdint.h>

#include <libyang/libyang.h>

#include "session.h"

/**
 * @defgroup server_config Server Configuration
 * @ingroup server
 *
 * @brief Server-side configuration creation and application
 * @{
 */

/**
 * @} Server Configuration
 */

/**
 * @defgroup server_config_functions Server Configuration Functions
 * @ingroup server_config
 *
 * @brief Server-side configuration functions
 * @{
 */

/**
 * @brief Implements all the required modules and their features in the context.
 * Needs to be called before any other configuration functions.
 *
 * If ctx is :
 *      - NULL: a new context will be created and if the call is successful you have to free it,
 *      - non NULL: modules will simply be implemented.
 *
 * Implemented modules: ietf-netconf-server, ietf-x509-cert-to-name, ietf-crypto-types,
 * ietf-tcp-common, ietf-ssh-common, iana-ssh-encryption-algs, iana-ssh-key-exchange-algs,
 * iana-ssh-mac-algs, iana-ssh-public-key-algs, ietf-keystore, ietf-ssh-server, ietf-truststore,
 * ietf-tls-server and libnetconf2-netconf-server.
 *
 * Note that the SSH authentication depends on the value of the 'local-users-supported' feature in the ietf-ssh-server module.
 * If the feature, and its dependent if-features, are disabled, the SSH authentication will use the system users.
 * Otherwise, the SSH authentication will use the local users from the configuration (the default).
 *
 * @param[in, out] ctx Optional context in which the modules will be implemented. Created if *ctx is null.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_load_modules(struct ly_ctx **ctx);

/**
 * @brief Configure server based on the given diff.
 *
 * Context must already have implemented the required modules, see ::nc_server_config_load_modules().
 *
 * @note All the implicit nodes, such as non-presence containers and
 * leafs with default values, must be present in the diff.
 *
 * @param[in] diff YANG diff belonging to either ietf-netconf-server, ietf-keystore or ietf-truststore modules.
 * The top level node HAS to have an operation (create, replace, delete or none).
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup_diff(const struct lyd_node *diff);

/**
 * @brief Configure server based on the given data.
 *
 * The current configuration will be completely replaced by the given data.
 *
 * Context must already have implemented the required modules, see ::nc_server_config_load_modules().
 *
 * @note All the implicit nodes, such as non-presence containers and
 * leafs with default values, must be present in the data.
 *
 * @param[in] data YANG data belonging to either ietf-netconf-server, ietf-keystore or ietf-truststore modules.
 * This data __must be valid__. No node can have an operation attribute.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup_data(const struct lyd_node *data);

/**
 * @brief Configure server based on the given data stored in a file.
 *
 * Wrapper around ::nc_server_config_setup_data() hiding work with parsing the data.
 * Context must already have implemented the required modules, see ::nc_server_config_load_modules().
 *
 * @param[in] ctx libyang context.
 * @param[in] path Path to a file with ietf-netconf-server, ietf-keystore or ietf-truststore YANG data.
 * This data __must be valid__. No node can have an operation attribute.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup_path(const struct ly_ctx *ctx, const char *path);

#if defined (NC_SSH) || defined (NC_TLS)

/**
 * @brief Creates new YANG configuration data nodes for address and port.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents might be changed.
 * @param[in] transport Either SSH or TLS transport of the given endpoint.
 * @param[in] address New listening address.
 * @param[in] port New listening port.
 * @param[in,out] config Configuration YANG data tree. If NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_address_port(const struct ly_ctx *ctx, const char *endpt_name, NC_TRANSPORT_IMPL transport,
        const char *address, uint16_t port, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for an asymmetric key in the keystore.
 *
 * @param[in] ctx libyang context.
 * @param[in] ti Transport in which the key pair will be used. Either SSH or TLS.
 * @param[in] asym_key_name Identifier of the asymmetric key pair.
 * This identifier is used to reference the key pair.
 * @param[in] privkey_path Path to a private key file.
 * @param[in] pubkey_path Optional path a public key file.
 * If not supplied, it will be generated from the private key.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_keystore_asym_key(const struct ly_ctx *ctx, NC_TRANSPORT_IMPL ti, const char *asym_key_name,
        const char *privkey_path, const char *pubkey_path, struct lyd_node **config);

/**
 * @brief Deletes a keystore's asymmetric key from the YANG data.
 *
 * @param[in] asym_key_name Optional identifier of the asymmetric key to be deleted.
 * If NULL, all of the asymmetric keys in the keystore will be deleted.
 * @param[in,out] config Configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_keystore_asym_key(const char *asym_key_name, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a certificate in the keystore.
 *
 * A certificate can not exist without its asymmetric key, so you must create an asymmetric key
 * with the same identifier you pass to this function.
 *
 * @param[in] ctx libyang context.
 * @param[in] asym_key_name Arbitrary identifier of the asymmetric key.
 * If an asymmetric key pair with this name already exists, its contents will be changed.
 * @param[in] cert_name Arbitrary identifier of the key pair's certificate.
 * If a certificate with this name already exists, its contents will be changed.
 * @param[in] cert_path Path to the PEM encoded certificate file.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_keystore_cert(const struct ly_ctx *ctx, const char *asym_key_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config);

/**
 * @brief Deletes a keystore's certificate from the YANG data.
 *
 * @param[in] asym_key_name Identifier of an existing asymmetric key pair.
 * @param[in] cert_name Optional identifier of a certificate to be deleted.
 * If NULL, all of the certificates belonging to the asymmetric key pair will be deleted.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_keystore_cert(const char *asym_key_name, const char *cert_name, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a public key in the truststore.
 *
 * @param[in] ctx libyang context.
 * @param[in] pub_bag_name Arbitrary identifier of the public key bag.
 * This name is used to reference the public keys in the bag.
 * If a public key bag with this name already exists, its contents will be changed.
 * @param[in] pubkey_name Arbitrary identifier of the public key.
 * If a public key with this name already exists in the given bag, its contents will be changed.
 * @param[in] pubkey_path Path to a file containing a public key.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_truststore_pubkey(const struct ly_ctx *ctx, const char *pub_bag_name, const char *pubkey_name,
        const char *pubkey_path, struct lyd_node **config);

/**
 * @brief Deletes a truststore's public key from the YANG data.
 *
 * @param[in] pub_bag_name Identifier of an existing public key bag.
 * @param[in] pubkey_name Optional identifier of a public key to be deleted.
 * If NULL, all of the public keys in the given bag will be deleted.
 * @param[in,out] config Configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_truststore_pubkey(const char *pub_bag_name, const char *pubkey_name, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a certificate in the truststore.
 *
 * @param[in] ctx libyang context.
 * @param[in] cert_bag_name Arbitrary identifier of the certificate bag.
 * This name is used to reference the certificates in the bag.
 * If a certificate bag with this name already exists, its contents will be changed.
 * @param[in] cert_name Arbitrary identifier of the certificate.
 * If a certificate with this name already exists in the given bag, its contents will be changed.
 * @param[in] cert_path Path to a file containing a PEM encoded certificate.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_truststore_cert(const struct ly_ctx *ctx, const char *cert_bag_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config);

/**
 * @brief Deletes a truststore's certificate from the YANG data.
 *
 * @param[in] cert_bag_name Identifier of an existing certificate bag.
 * @param[in] cert_name Optional identifier of a certificate to be deleted.
 * If NULL, all of the certificates in the given bag will be deleted.
 * @param[in,out] config Configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_truststore_cert(const char *cert_bag_name, const char *cert_name, struct lyd_node **config);

#endif /* NC_SSH or NC_TLS */

/**
 * @brief Deletes an endpoint from the YANG data.
 *
 * @note If the last endpoint is deleted, the parent listen presence container
 * is also deleted to maintain a valid YANG data tree.
 *
 * @param[in] endpt_name Optional identifier of an endpoint to be deleted.
 * If NULL, all of the endpoints will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_endpt(const char *endpt_name, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a UNIX socket endpoint.
 *
 * To learn how authentication works, look at ::nc_server_config_add_unix_user_mapping().
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents might be changed.
 * @param[in] path Path to the UNIX socket. The parent directory must be writable by the server process.
 * @param[in] mode Optional UNIX socket file mode in octal format (e.g., "0777").
 * If NULL, the default value ("0660") will be used.
 * @param[in] owner Optional owner of the UNIX socket file.
 * If NULL, the owner will be set to the user running the server process.
 * @param[in] group Optional group of the UNIX socket file.
 * If NULL, the group will be set to the group of the user running the server process.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_unix_socket(const struct ly_ctx *ctx, const char *endpt_name, const char *path,
        const char *mode, const char *owner, const char *group, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a UNIX username mapping.
 *
 * Specifies who can connect to a UNIX socket endpoint. There are 3 following scenarios:
 *
 * 1) If no mappings are configured for the client @p system_user, then the client can
 * only connect if its username matches @p netconf_user.
 *
 * 2) If a mapping for the client @p system_user is configured, but no @p netconf_user s
 * are specified, then the client cannot connect with any username.
 *
 * 3) If a mapping for the client @p system_user is configured, and at least one @p netconf_user
 * is specified, then the client can connect only with one of the specified usernames.
 * If a wildcard value "*" is configured for @p netconf_user, then the client can connect
 * with any NETCONF username.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents might be changed.
 * @param[in] system_user System user name, who the mapping will be created for.
 * @param[in] netconf_user Username that the @p system_user can use to connect to the endpoint.
 * Special value "*" can be used to allow any username.
 * If NULL, empty mapping will be created, which means that the @p system_user
 * can not connect to the endpoint with any username.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_unix_user_mapping(const struct ly_ctx *ctx, const char *endpt_name,
        const char *system_user, const char *netconf_user, struct lyd_node **config);

/**
 * @brief Deletes a UNIX username mapping from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] system_user Optional identifier of a system user whose mapping will be deleted.
 * If NULL, all of the mappings for the endpoint will be deleted.
 * @param[in,out] config Configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_unix_user_mapping(const char *endpt_name, const char *system_user,
        struct lyd_node **config);

#ifdef NC_SSH

/**
 * @brief Gets all the SSH transport algorithms supported by the server.
 *
 * @note Actual usable algorithms depend on the underlying libssh library version,
 * the returned list is based on libssh v0.11.0.
 *
 * @param[in] ctx libyang context.
 * @param[out] supported_algs Supported SSH transport algorithms.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_oper_get_supported_ssh_algs(const struct ly_ctx *ctx, struct lyd_node **supported_algs);

/**
 * @brief Gets the last modified time of an SSH user's password.
 *
 * @param[in] ch_client Name of the call-home client the user is configured on. NULL if the user is on a listening endpoint.
 * @param[in] endpoint Name of the endpoint the user is configured on. Can be either a listening or call-home endpoint.
 * @param[in] username Name of the SSH user.
 * @param[out] last_modified Time of the last password modification.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_oper_get_user_password_last_modified(const char *ch_client, const char *endpoint,
        const char *username, time_t *last_modified);

/**
 * @brief Hashes a clear-text 'iana-crypt-hash' password the way the server stores it in its configuration.
 *
 * Only "$0$<clear-text>" is a clear-text password, which is hashed into a crypt(3) SHA-512 digest
 * under a freshly generated random salt ("$6$<salt>$<digest>"). Any other @p crypt_hash is already
 * hashed, so nothing is done and NULL is returned in @p hashed_password.
 *
 * @param[in] crypt_hash 'iana-crypt-hash:crypt-hash' value, "$0$<clear-text>" for a clear-text password.
 * @param[out] hashed_password Hashed password or NULL if @p crypt_hash was not clear text.
 * Memory is allocated and has to be freed by the caller.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_hash_password(const char *crypt_hash, char **hashed_password);

#endif /* NC_SSH */

#ifdef NC_TLS

/**
 * @brief Gets all the TLS transport cipher suites supported by the server.
 *
 * @note Actual usable cipher suites depend on the underlying TLS library and its version.
 *
 * @param[in] ctx libyang context.
 * @param[out] supported_algs Supported cipher suites.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_oper_get_supported_tls_algs(const struct ly_ctx *ctx, struct lyd_node **supported_algs);

#endif /* NC_TLS */

/**
 * @} Server Configuration Functions
 */

#if defined (NC_SSH) || defined (NC_TLS)

/**
 * @defgroup server_config_ch Call Home Server Configuration
 * @ingroup server_config
 *
 * @brief Call Home server configuration creation and deletion
 * @{
 */

/**
 * @} Call Home Server Configuration
 */

/**
 * @defgroup server_config_ch_functions Call Home Server Configuration Functions
 * @ingroup server_config_ch
 *
 * @brief Call Home server configuration functions
 * @{
 */

/**
 * @brief Creates new YANG configuration data nodes for a Call Home client's address and port.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] transport Transport protocol to be used on this endpoint - either SSH or TLS.
 * @param[in] address Address to connect to.
 * @param[in] port Port to connect to.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_address_port(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        NC_TRANSPORT_IMPL transport, const char *address, const char *port, struct lyd_node **config);

/**
 * @brief Deletes a Call Home client from the YANG data.
 *
 * @param[in] client_name Optional identifier of a client to be deleted.
 * If NULL, all of the Call Home clients will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note If the last client is deleted, the parent call-home presence container
 * is also deleted to maintain a valid YANG data tree.
 */
int nc_server_config_del_ch_client(const char *client_name, struct lyd_node **config);

/**
 * @brief Deletes a Call Home endpoint from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Optional identifier of a CH endpoint to be deleted.
 * If NULL, all of the CH endpoints which belong to the given client will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 *
 * @note If the last endpoint of the client is deleted, the configuration
 * becomes invalid. Add a new endpoint to make it valid again.
 */
int nc_server_config_del_ch_endpt(const char *client_name, const char *endpt_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for the Call Home persistent connection type.
 *
 * This is the default connection type. If periodic connection type was set before, it will be unset.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_persistent(const struct ly_ctx *ctx, const char *client_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for the period parameter of the Call Home periodic connection type.
 *
 * If called, the persistent connection type will be replaced by periodic.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] period Duration between periodic connections in minutes.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_period(const struct ly_ctx *ctx, const char *client_name, uint16_t period,
        struct lyd_node **config);

/**
 * @brief Deletes the Call Home period parameter of the periodic connection type from the YANG data.
 *
 * This behaves the same as setting the period to 60 minutes, which is the default value of this node.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_ch_period(const char *client_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for the anchor time parameter of the Call Home periodic connection type.
 *
 * If called, the persistent connection type will be replaced by periodic.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] anchor_time Timestamp before or after which a series of periodic connections are determined.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_anchor_time(const struct ly_ctx *ctx, const char *client_name,
        const char *anchor_time, struct lyd_node **config);

/**
 * @brief Deletes the Call Home anchor time parameter of the periodic connection type from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_ch_anchor_time(const char *client_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for the idle timeout parameter of the Call Home periodic connection type.
 *
 * If called, the persistent connection type will be replaced by periodic.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] idle_timeout Specifies the maximum number of seconds that a session may remain idle.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_idle_timeout(const struct ly_ctx *ctx, const char *client_name,
        uint16_t idle_timeout, struct lyd_node **config);

/**
 * @brief Deletes the Call Home idle timeout parameter of the periodic connection type from the YANG data.
 *
 * This behaves the same as setting the timeout to 180 seconds, which is the default value of this node.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_ch_idle_timeout(const char *client_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for the Call Home reconnect strategy.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] start_with Specifies which endpoint to try if a connection is unsuccessful. Default value is NC_CH_FIRST_LISTED.
 * @param[in] max_wait The number of seconds after which a connection to an endpoint is deemed unsuccessful. Default value if 5.
 * @param[in] max_attempts The number of unsuccessful connection attempts before moving to the next endpoint. Default value is 3.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_add_ch_reconnect_strategy(const struct ly_ctx *ctx, const char *client_name,
        NC_CH_START_WITH start_with, uint16_t max_wait, uint8_t max_attempts, struct lyd_node **config);

/**
 * @brief Resets the values of the Call Home reconnect strategy nodes to their defaults.
 *
 * The default values are: start-with = NC_CH_FIRST_LISTED, max-wait = 5 and max-attempts = 3.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_ch_reconnect_strategy(const char *client_name, struct lyd_node **config);

/**
 * @} Call Home Server Configuration Functions
 */

#endif /* NC_SSH or NC_TLS */

#ifdef __cplusplus
}
#endif

#endif /* NC_CONFIG_SERVER_H_ */
