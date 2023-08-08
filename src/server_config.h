/**
 * @file server_config.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server configuration
 *
 * @copyright
 * Copyright (c) 2023 CESNET, z.s.p.o.
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
 * @param[in, out] ctx Optional context in which the modules will be implemented. Created if ctx is null.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_load_modules(struct ly_ctx **ctx);

/**
 * @brief Configure server based on the given diff data.
 *
 * Expected data are a validated instance of a ietf-netconf-server YANG data.
 * The data must be in the diff format and supported operations are: create, replace,
 * delete and none. Context must already have implemented the required modules, see
 * ::nc_server_config_load_modules().
 *
 * @param[in] diff ietf-netconf-server YANG diff data.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup_diff(const struct lyd_node *diff);

/**
 * @brief Configure server based on the given data.
 *
 * Expected data is a validated instance of a ietf-netconf-server YANG data.
 * Behaves as if all the nodes in data had the replace operation. That means that the current configuration will be deleted
 * and just the given data will all be applied.
 * The data must not contain any operation attribute, see ::nc_server_config_setup_diff() which works with diff.
 * Context must already have implemented the required modules, see ::nc_server_config_load_modules().
 *
 * @param[in] data ietf-netconf-server YANG data.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup_data(const struct lyd_node *data);

/**
 * @brief Configure server based on the given ietf-netconf-server YANG data from a file.
 * Wrapper around ::nc_server_config_setup_data() hiding work with parsing the data.
 *
 * @param[in] ctx libyang context.
 * @param[in] path Path to the file with ietf-netconf-server YANG data.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup_path(const struct ly_ctx *ctx, const char *path);

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Creates new YANG configuration data nodes for local-address and local-port.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents might be changed.
 * @param[in] transport Either SSH or TLS transport for the given endpoint.
 * @param[in] address New listening address.
 * @param[in] port New listening port.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_address_port(const struct ly_ctx *ctx, const char *endpt_name, NC_TRANSPORT_IMPL transport,
        const char *address, uint16_t port, struct lyd_node **config);

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Deletes an endpoint from the YANG data.
 *
 * @param[in] endpt_name Optional identifier of an endpoint to be deleted.
 * If NULL, all of the endpoints will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_del_endpt(const char *endpt_name, struct lyd_node **config);

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Creates new YANG data nodes for an asymmetric key in the keystore.
 *
 * @param[in] ctx libyang context.
 * @param[in] asym_key_name Identifier of the asymmetric key pair.
 * This identifier is used to reference the key pair.
 * @param[in] privkey_path Path to a private key file.
 * @param[in] pubkey_path Optional path a public key file.
 * If not supplied, it will be generated from the private key.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_keystore_asym_key(const struct ly_ctx *ctx, const char *asym_key_name, const char *privkey_path,
        const char *pubkey_path, struct lyd_node **config);

/**
 * @brief Deletes a keystore's asymmetric key from the YANG data.
 *
 * @param[in] asym_key_name Optional identifier of the asymmetric key to be deleted.
 * If NULL, all of the asymmetric keys in the keystore will be deleted.
 * @param[in,out] config Configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_del_keystore_asym_key(const char *asym_key_name, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a certificate in the keystore.
 *
 * A certificate can not exist without its asymmetric key, so you must call ::nc_server_config_new_keystore_asym_key()
 * either before or after calling this with the same identifier for the asymmetric key.
 *
 * An asymmetric key pair can have zero or more certificates associated with this key pair, however a certificate must
 * have exactly one key pair it belongs to.
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
int nc_server_config_new_keystore_cert(const struct ly_ctx *ctx, const char *asym_key_name, const char *cert_name,
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
int nc_server_config_new_del_keystore_cert(const char *asym_key_name, const char *cert_name, struct lyd_node **config);

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
int nc_server_config_new_truststore_pubkey(const struct ly_ctx *ctx, const char *pub_bag_name, const char *pubkey_name,
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
int nc_server_config_new_del_truststore_pubkey(const char *pub_bag_name, const char *pubkey_name, struct lyd_node **config);

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
int nc_server_config_new_truststore_cert(const struct ly_ctx *ctx, const char *cert_bag_name, const char *cert_name,
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
int nc_server_config_new_del_truststore_cert(const char *cert_bag_name,
        const char *cert_name, struct lyd_node **config);

/**
 * @} Server Configuration Functions
 */

/**
 * @defgroup server_config_ssh SSH Server Configuration
 * @ingroup server_config
 *
 * @brief SSH server configuration creation and deletion
 * @{
 */

/**
 * @brief Creates new YANG configuration data nodes for a hostkey.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its hostkey might be changed.
 * @param[in] hostkey_name Arbitrary identifier of the hostkey.
 * If a hostkey with this identifier already exists, its contents will be changed.
 * @param[in] privkey_path Path to a file containing a private key.
 * The private key has to be in a PEM format. Only RSA and ECDSA keys are supported.
 * @param[in] pubkey_path Optional path to a file containing a public key. If NULL, public key will be
 * generated from the private key.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_hostkey(const struct ly_ctx *ctx, const char *endpt_name, const char *hostkey_name,
        const char *privkey_path, const char *pubkey_path, struct lyd_node **config);

/**
 * @brief Deletes a hostkey from the YANG data.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] hostkey_name Optional identifier of the hostkey to be deleted.
 * If NULL, all of the hostkeys on this endpoint will be deleted.
 * @param[in,out] config Configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_hostkey(const struct ly_ctx *ctx, const char *endpt_name,
        const char *hostkey_name, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a reference to an asymmetric key located in the keystore.
 *
 * This asymmetric key pair will be used as the SSH hostkey.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of an endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] hostkey_name Arbitrary identifier of the endpoint's hostkey.
 * If an endpoint's hostkey with this identifier already exists, its contents will be changed.
 * @param[in] keystore_reference Name of the asymmetric key pair to be referenced and used as a hostkey.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_keystore_reference(const struct ly_ctx *ctx, const char *endpt_name, const char *hostkey_name,
        const char *keystore_reference, struct lyd_node **config);

/**
 * @brief Deletes a keystore reference from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] hostkey_name Identifier of an existing hostkey on the given endpoint.
 * @param[in,out] config Configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_keystore_reference(const char *endpt_name, const char *hostkey_name,
        struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for the maximum amount of failed SSH authentication attempts.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents might be changed.
 * @param[in] auth_attempts Maximum amount of failed SSH authentication attempts after which a
 * client is disconnected. The default value is 3.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_auth_attempts(const struct ly_ctx *ctx, const char *endpt_name, uint16_t auth_attempts,
        struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for an SSH authentication timeout.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents might be changed.
 * @param[in] auth_timeout Maximum amount of time in seconds after which the authentication is deemed
 * unsuccessful. The default value is 10.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_auth_timeout(const struct ly_ctx *ctx, const char *endpt_name, uint16_t auth_timeout,
        struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for an SSH user's public key authentication method.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its user might be changed.
 * @param[in] user_name Arbitrary identifier of the user.
 * If an user with this identifier already exists, its contents will be changed.
 * @param[in] pubkey_name Arbitrary identifier of the user's public key.
 * If a public key with this identifier already exists for this user, its contents will be changed.
 * @param[in] pubkey_path Path to a file containing the user's public key.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_user_pubkey(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *pubkey_name, const char *pubkey_path, struct lyd_node **config);

/**
 * @brief Deletes an SSH user's public key from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] user_name Identifier of an existing user on the given endpoint.
 * @param[in] pubkey_name Optional identifier of a public key to be deleted.
 * If NULL, all of the users public keys will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_user_pubkey(const char *endpt_name, const char *user_name,
        const char *pubkey_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for an SSH user's password authentication method.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its user might be changed.
 * @param[in] user_name Arbitrary identifier of the user.
 * If an user with this identifier already exists, its contents will be changed.
 * @param[in] password Clear-text password to be set for the user. It will be hashed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_user_password(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *password, struct lyd_node **config);

/**
 * @brief Deletes an SSH user's password from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] user_name Identifier of an existing user on the given endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_user_password(const char *endpt_name, const char *user_name,
        struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for an SSH user's none authentication method.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its user might be changed.
 * @param[in] user_name Arbitrary identifier of the user.
 * If an user with this identifier already exists, its contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_user_none(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Deletes an SSH user's none authentication method from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] user_name Identifier of an existing user on the given endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_user_none(const char *endpt_name, const char *user_name,
        struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for an SSH user's keyboard interactive authentication method.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its user might be changed.
 * @param[in] user_name Arbitrary identifier of the user.
 * If an user with this identifier already exists, its contents will be changed.
 * @param[in] pam_config_name Name of the PAM configuration file.
 * @param[in] pam_config_dir Optional. The absolute path to the directory in which the configuration file
 * with the name pam_config_name is located. A newer version (>= 1.4) of PAM library is required to be able to specify
 * the path. If NULL is passed, then the PAM's system directories will be searched (usually /etc/pam.d/).
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_user_interactive(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *pam_config_name, const char *pam_config_dir, struct lyd_node **config);

/**
 * @brief Deletes an SSH user's keyboard interactive authentication from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] user_name Identifier of an existing user on the given endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_user_interactive(const char *endpt_name, const char *user_name,
        struct lyd_node **config);

/**
 * @brief Deletes an SSH user from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] user_name Optional identifier of an user to be deleted.
 * If NULL, all of the users on this endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_user(const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a reference to a public key bag located in the truststore.
 *
 * The public key's located in the bag will be used for client authentication.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of an endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] user_name Arbitrary identifier of the endpoint's user.
 * If an endpoint's user with this identifier already exists, its contents will be changed.
 * @param[in] truststore_reference Name of the public key bag to be referenced and used for authentication.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_truststore_reference(const struct ly_ctx *ctx, const char *endpt_name, const char *user_name,
        const char *truststore_reference, struct lyd_node **config);

/**
 * @brief Deletes a truststore reference from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] user_name Identifier of an user on the given endpoint whose truststore reference will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_truststore_reference(const char *endpt_name, const char *user_name,
        struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes, which will be a reference to another SSH endpoint's users.
 *
 * Whenever a client tries to connect to the referencing endpoint, all of its users will be tried first. If no match is
 * found, the referenced endpoint's configured users will be tried.
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
int nc_config_new_ssh_endpoint_user_reference(const struct ly_ctx *ctx, const char *endpt_name,
        const char *referenced_endpt, struct lyd_node **config);

/**
 * @brief Deletes reference to another SSH endpoint's users from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_config_new_ssh_del_endpoint_user_reference(const char *endpt_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for host-key algorithms replacing any previous ones.
 *
 * Supported algorithms are: ssh-ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521,
 * rsa-sha2-512, rsa-sha2-256, ssh-rsa and ssh-dss.
 *
 * @param[in] ctx libyang context
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its host-key algorithms will be replaced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of host-key algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_host_key_algs(const struct ly_ctx *ctx, const char *endpt_name,
        struct lyd_node **config, int alg_count, ...);

/**
 * @brief Deletes a hostkey algorithm from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] alg Optional algorithm to be deleted.
 * If NULL, all of the hostkey algorithms on this endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_host_key_alg(const char *endpt_name, const char *alg, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for key exchange algorithms replacing any previous ones.
 *
 * Supported algorithms are: diffie-hellman-group-exchange-sha1, curve25519-sha256, ecdh-sha2-nistp256,
 * ecdh-sha2-nistp384, ecdh-sha2-nistp521, diffie-hellman-group18-sha512, diffie-hellman-group16-sha512,
 * diffie-hellman-group-exchange-sha256 and diffie-hellman-group14-sha256.
 *
 * @param[in] ctx libyang context
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its key exchange algorithms will be replaced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of key exchange algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_key_exchange_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...);

/**
 * @brief Deletes a key exchange algorithm from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] alg Optional algorithm to be deleted.
 * If NULL, all of the key exchange algorithms on this endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_key_exchange_alg(const char *endpt_name, const char *alg, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for encryption algorithms replacing any previous ones.
 *
 * Supported algorithms are: aes256-ctr, aes192-ctr, aes128-ctr, aes256-cbc, aes192-cbc, aes128-cbc, blowfish-cbc
 * triple-des-cbc and none.
 *
 * @param[in] ctx libyang context
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its encryption algorithms will be replaced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of encryption algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_encryption_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...);

/**
 * @brief Deletes an encryption algorithm from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] alg Optional algorithm to be deleted.
 * If NULL, all of the encryption algorithms on this endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_encryption_alg(const char *endpt_name, const char *alg, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for mac algorithms replacing any previous ones.
 *
 * Supported algorithms are: hmac-sha2-256, hmac-sha2-512 and hmac-sha1.
 *
 * @param[in] ctx libyang context
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its mac algorithms will be replaced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of mac algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_mac_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...);

/**
 * @brief Deletes a mac algorithm from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] alg Optional algorithm to be deleted.
 * If NULL, all of the mac algorithms on this endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_del_mac_alg(const char *endpt_name, const char *alg, struct lyd_node **config);

/**
 * @} SSH Server Configuration
 */

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
 * @param[in] certificate_path Path to the server's certificate file.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_server_certificate(const struct ly_ctx *ctx, const char *endpt_name, const char *privkey_path,
        const char *pubkey_path, const char *certificate_path, struct lyd_node **config);

/**
 * @brief Deletes the server's certificate from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_del_server_certificate(const char *endpt_name, struct lyd_node **config);

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
int nc_server_config_new_tls_keystore_reference(const struct ly_ctx *ctx, const char *endpt_name, const char *asym_key_ref,
        const char *cert_ref, struct lyd_node **config);

/**
 * @brief Deletes a TLS server certificate keystore reference from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_del_keystore_reference(const char *endpt_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a client's (end-entity) certificate.
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
int nc_server_config_new_tls_client_certificate(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config);

/**
 * @brief Deletes a client (end-entity) certificate from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] cert_name Optional name of a certificate to be deleted.
 * If NULL, all of the end-entity certificates on the given endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_del_client_certificate(const char *endpt_name, const char *cert_name, struct lyd_node **config);

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
int nc_server_config_new_tls_client_cert_truststore_ref(const struct ly_ctx *ctx, const char *endpt_name,
        const char *cert_bag_ref, struct lyd_node **config);

/**
 * @brief Deletes a client (end-entity) certificates truststore reference from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_del_client_cert_truststore_ref(const char *endpt_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a client certificate authority (trust-anchor) certificate.
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
int nc_server_config_new_tls_client_ca(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config);

/**
 * @brief Deletes a client certificate authority (trust-anchor) certificate from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] cert_name Optional name of a certificate to be deleted.
 * If NULL, all of the CA certificates on the given endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_del_client_ca(const char *endpt_name, const char *cert_name, struct lyd_node **config);

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
int nc_server_config_new_tls_client_ca_truststore_ref(const struct ly_ctx *ctx, const char *endpt_name,
        const char *cert_bag_ref, struct lyd_node **config);

/**
 * @brief Deletes a client certificate authority (trust-anchor) certificates truststore reference from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_del_client_ca_truststore_ref(const char *endpt_name, struct lyd_node **config);

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
 * @param[in] name Username for this cert-to-name entry.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_ctn(const struct ly_ctx *ctx, const char *endpt_name, uint32_t id, const char *fingerprint,
        NC_TLS_CTN_MAPTYPE map_type, const char *name, struct lyd_node **config);

/**
 * @brief Deletes a cert-to-name entry from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] id Optional ID of the CTN entry.
 * If 0, all of the cert-to-name entries on the given endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_del_ctn(const char *endpt_name, uint32_t id, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a TLS version.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] tls_version TLS version to be used. Call this multiple times to set
 * the accepted versions of the TLS protocol and let the client and server negotiate
 * the given version.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_version(const struct ly_ctx *ctx, const char *endpt_name,
        NC_TLS_VERSION tls_version, struct lyd_node **config);

/**
 * @brief Deletes a TLS version from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] tls_version TLS version to be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_del_version(const char *endpt_name, NC_TLS_VERSION tls_version, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a TLS cipher.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] cipher_count Number of following ciphers.
 * @param[in] ... TLS ciphers. These ciphers MUST be in the format as listed in the
 * iana-tls-cipher-suite-algs YANG model (lowercase and separated by dashes). Regardless
 * of the TLS protocol version used, all of these ciphers will be tried and some of them
 * might not be set (TLS handshake might fail then). For the list of supported ciphers see
 * the OpenSSL documentation.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_ciphers(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int cipher_count, ...);

/**
 * @brief Deletes a TLS cipher from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] cipher TLS cipher to be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_del_cipher(const char *endpt_name, const char *cipher, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Certificate Revocation List via a local file.
 *
 * Beware that you can choose up to one function between the three CRL alternatives on a given endpoint and calling
 * this function will remove any CRL YANG nodes created by the other two functions.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] crl_path Path to a DER/PEM encoded CRL file.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_crl_path(const struct ly_ctx *ctx, const char *endpt_name,
        const char *crl_path, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Certificate Revocation List via an URL.
 *
 * Beware that you can choose up to one function between the three CRL alternatives on a given endpoint and calling
 * this function will remove any CRL YANG nodes created by the other two functions.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in] crl_url URL from which the CRL file will be downloaded. The file has to be in the DER or PEM format.
 * The allowed protocols are all the protocols supported by CURL.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_crl_url(const struct ly_ctx *ctx, const char *endpt_name, const char *crl_url, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Certificate Revocation List via certificate extensions.
 *
 * The chain of configured Certificate Authorities will be examined. For each certificate in this chain all the
 * CRLs from the URLs specified in their extension fields CRL Distribution Points will be downloaded and used.
 *
 * Beware that you can choose up to one function between the three CRL alternatives on a given endpoint and calling
 * this function will remove any CRL YANG nodes created by the other two functions.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, its contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_crl_cert_ext(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config);

/**
 * @brief Deletes all the CRL nodes from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_tls_del_crl(const char *endpt_name, struct lyd_node **config);

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
int nc_config_new_tls_endpoint_client_reference(const struct ly_ctx *ctx, const char *endpt_name,
        const char *referenced_endpt, struct lyd_node **config);

/**
 * @brief Deletes reference to another TLS endpoint's users from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_config_new_tls_del_endpoint_client_reference(const char *endpt_name, struct lyd_node **config);

/**
 * @} TLS Server Configuration
 */

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
int nc_server_config_new_ch_address_port(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        NC_TRANSPORT_IMPL transport, const char *address, const char *port, struct lyd_node **config);

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Deletes a Call Home client from the YANG data.
 *
 * @param[in] client_name Optional identifier of a client to be deleted.
 * If NULL, all of the Call Home clients will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_del_ch_client(const char *client_name, struct lyd_node **config);

/**
 * @brief Deletes a Call Home endpoint from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Optional identifier of a CH endpoint to be deleted.
 * If NULL, all of the CH endpoints which belong to the given client will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_del_endpt(const char *client_name, const char *endpt_name, struct lyd_node **config);

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
int nc_server_config_new_ch_persistent(const struct ly_ctx *ctx, const char *client_name, struct lyd_node **config);

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
int nc_server_config_new_ch_period(const struct ly_ctx *ctx, const char *client_name, uint16_t period,
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
int nc_server_config_new_ch_del_period(const char *client_name, struct lyd_node **config);

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
int nc_server_config_new_ch_anchor_time(const struct ly_ctx *ctx, const char *client_name,
        const char *anchor_time, struct lyd_node **config);

/**
 * @brief Deletes the Call Home anchor time parameter of the periodic connection type from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_del_anchor_time(const char *client_name, struct lyd_node **config);

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
int nc_server_config_new_ch_idle_timeout(const struct ly_ctx *ctx, const char *client_name,
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
int nc_server_config_new_ch_del_idle_timeout(const char *client_name, struct lyd_node **config);

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
int nc_server_config_new_ch_reconnect_strategy(const struct ly_ctx *ctx, const char *client_name,
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
int nc_server_config_new_ch_del_reconnect_strategy(const char *client_name, struct lyd_node **config);

/**
 * @} Call Home Server Configuration Functions
 */

#ifdef NC_ENABLED_SSH_TLS

/**
 * @defgroup server_config_ch_ssh SSH Call Home Server Configuration
 * @ingroup server_config_ch
 *
 * @brief SSH Call Home server configuration creation and deletion
 * @{
 */

/**
 * @brief Creates new YANG data nodes for a Call Home SSH hostkey.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] hostkey_name Arbitrary identifier of the endpoint's hostkey.
 * If the endpoint's hostkey with this identifier already exists, its contents will be changed.
 * @param[in] privkey_path Path to a file containing a private key.
 * The private key has to be in a PEM format. Only RSA and ECDSA keys are supported.
 * @param[in] pubkey_path Path to a file containing a public key. If NULL, public key will be
 * generated from the private key.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_hostkey(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *hostkey_name, const char *privkey_path, const char *pubkey_path, struct lyd_node **config);

/**
 * @brief Deletes a Call Home hostkey from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] hostkey_name Optional identifier of a hostkey to be deleted.
 * If NULL, all of the hostkeys on the given endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_hostkey(const char *client_name, const char *endpt_name,
        const char *hostkey_name, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a reference to an asymmetric key located in the keystore.
 *
 * This asymmetric key pair will be used as the Call Home SSH hostkey.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] hostkey_name Arbitrary identifier of the endpoint's hostkey.
 * If the endpoint's hostkey with this identifier already exists, its contents will be changed.
 * @param[in] keystore_reference Name of the asymmetric key pair to be referenced and used as a hostkey.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_keystore_reference(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *hostkey_name, const char *keystore_reference, struct lyd_node **config);

/**
 * @brief Deletes a Call Home keystore reference from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] hostkey_name Identifier of an existing hostkey that belongs to the given CH endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_keystore_reference(const char *client_name, const char *endpt_name,
        const char *hostkey_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for the maximum amount of failed Call Home SSH authentication attempts.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] auth_attempts Maximum amount of failed SSH authentication attempts after which a
 * client is disconnected. The default value is 3.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_auth_attempts(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        uint16_t auth_attempts, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home SSH authentication timeout.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] auth_timeout Maximum amount of time in seconds after which the authentication is deemed
 * unsuccessful. The default value is 10.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_auth_timeout(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        uint16_t auth_timeout, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a Call Home SSH user's public key authentication method.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] user_name Arbitrary identifier of the endpoint's user.
 * If the endpoint's user with this identifier already exists, its contents will be changed.
 * @param[in] pubkey_name Arbitrary identifier of the user's public key.
 * If the user's public key with this identifier already exists, its contents will be changed.
 * @param[in] pubkey_path Path to a file containing a public key.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_user_pubkey(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *user_name, const char *pubkey_name, const char *pubkey_path, struct lyd_node **config);

/**
 * @brief Deletes a Call Home SSH user's public key from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] user_name Identifier of an existing SSH user that belongs to the given CH endpoint.
 * @param[in] pubkey_name Optional identifier of a public key to be deleted.
 * If NULL, all of the public keys which belong to the given SSH user will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_user_pubkey(const char *client_name, const char *endpt_name,
        const char *user_name, const char *pubkey_name, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a Call Home SSH user's password authentication method.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] user_name Arbitrary identifier of the endpoint's user.
 * If the endpoint's user with this identifier already exists, its contents will be changed.
 * @param[in] password Clear-text password to be set for the user. It will be hashed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_user_password(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *user_name, const char *password, struct lyd_node **config);

/**
 * @brief Deletes a Call Home SSH user's password from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] user_name Identifier of an existing SSH user that belongs to the given CH endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_user_password(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home SSH user's none authentication method.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] user_name Arbitrary identifier of the endpoint's user.
 * If the endpoint's user with this identifier already exists, its contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_user_none(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Deletes a Call Home SSH user's none authentication method from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] user_name Identifier of an existing SSH user that belongs to the given CH endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_user_none(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home SSH user's keyboard interactive authentication method.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] user_name Arbitrary identifier of the endpoint's user.
 * If the endpoint's user with this identifier already exists, its contents will be changed.
 * @param[in] pam_config_name Name of the PAM configuration file.
 * @param[in] pam_config_dir Optional. The absolute path to the directory in which the configuration file
 * with the name pam_config_name is located. A newer version (>= 1.4) of PAM library is required to be able to specify
 * the path. If NULL is passed, then the PAM's system directories will be searched (usually /etc/pam.d/).
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_user_interactive(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *user_name, const char *pam_config_name, const char *pam_config_dir, struct lyd_node **config);

/**
 * @brief Deletes a Call Home SSH user's keyboard interactive authentication from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] user_name Identifier of an existing SSH user that belongs to the given CH endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_user_interactive(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Deletes a Call Home SSH user from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] user_name Identifier of an existing SSH user that belongs to the given CH endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_user(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Creates new YANG data nodes for a reference to a public key bag located in the truststore.
 *
 * The public key's located in the bag will be used for Call Home SSH client authentication.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] user_name Arbitrary identifier of the endpoint's user.
 * If the endpoint's user with this identifier already exists, its contents will be changed.
 * @param[in] truststore_reference Name of the public key bag to be referenced and used for authentication.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_truststore_reference(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *user_name, const char *truststore_reference, struct lyd_node **config);

/**
 * @brief Deletes a Call Home SSH truststore reference from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] user_name Identifier of an existing SSH user that belongs to the given CH endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_truststore_reference(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for Call Home host-key algorithms replacing any previous ones.
 *
 * Supported algorithms are: ssh-ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521,
 * rsa-sha2-512, rsa-sha2-256, ssh-rsa and ssh-dss.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of host-key algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_host_key_algs(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        struct lyd_node **config, int alg_count, ...);

/**
 * @brief Deletes a Call Home hostkey algorithm from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] alg Optional algorithm to be deleted.
 * If NULL, all of the hostkey algorithms on this endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_host_key_alg(const char *client_name, const char *endpt_name,
        const char *alg, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for Call Home key exchange algorithms replacing any previous ones.
 *
 * Supported algorithms are: diffie-hellman-group-exchange-sha1, curve25519-sha256, ecdh-sha2-nistp256,
 * ecdh-sha2-nistp384, ecdh-sha2-nistp521, diffie-hellman-group18-sha512, diffie-hellman-group16-sha512,
 * diffie-hellman-group-exchange-sha256 and diffie-hellman-group14-sha256.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of key exchange algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_key_exchange_algs(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        struct lyd_node **config, int alg_count, ...);

/**
 * @brief Deletes a Call Home key exchange algorithm from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] alg Optional algorithm to be deleted.
 * If NULL, all of the key exchange algorithms on this endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_key_exchange_alg(const char *client_name, const char *endpt_name,
        const char *alg, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for Call Home encryption algorithms replacing any previous ones.
 *
 * Supported algorithms are: aes256-ctr, aes192-ctr, aes128-ctr, aes256-cbc, aes192-cbc, aes128-cbc, blowfish-cbc
 * triple-des-cbc and none.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of encryption algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_encryption_algs(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        struct lyd_node **config, int alg_count, ...);

/**
 * @brief Deletes a Call Home encryption algorithm from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] alg Optional algorithm to be deleted.
 * If NULL, all of the encryption algorithms on this endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_encryption_alg(const char *client_name, const char *endpt_name,
        const char *alg, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for Call Home mac algorithms replacing any previous ones.
 *
 * Supported algorithms are: hmac-sha2-256, hmac-sha2-512 and hmac-sha1.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the client's endpoint.
 * If the client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of mac algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_mac_algs(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        struct lyd_node **config, int alg_count, ...);

/**
 * @brief Deletes a Call Home mac algorithm from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] alg Optional algorithm to be deleted.
 * If NULL, all of the mac algorithms on this endpoint will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_ssh_del_mac_alg(const char *client_name, const char *endpt_name,
        const char *alg, struct lyd_node **config);

/**
 * @} SSH Call Home Server Configuration
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
 * @param[in] certificate_path Path to the server's certificate file.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_server_certificate(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *privkey_path, const char *pubkey_path, const char *certificate_path, struct lyd_node **config);

/**
 * @brief Deletes a Call Home server certificate from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_del_server_certificate(const char *client_name, const char *endpt_name,
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
int nc_server_config_new_ch_tls_keystore_reference(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *asym_key_ref, const char *cert_ref, struct lyd_node **config);

/**
 * @brief Deletes a TLS server certificate keystore reference from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_del_keystore_reference(const char *client_name, const char *endpt_name,
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
int nc_server_config_new_ch_tls_client_certificate(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
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
 */
int nc_server_config_new_ch_tls_del_client_certificate(const char *client_name, const char *endpt_name,
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
int nc_server_config_new_ch_tls_client_cert_truststore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *cert_bag_ref, struct lyd_node **config);

/**
 * @brief Deletes a Call Home client (end-entity) certificates truststore reference from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_del_client_cert_truststore_ref(const char *client_name, const char *endpt_name,
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
int nc_server_config_new_ch_tls_client_ca(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
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
 */
int nc_server_config_new_ch_tls_del_client_ca(const char *client_name, const char *endpt_name,
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
int nc_server_config_new_ch_tls_client_ca_truststore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *cert_bag_ref, struct lyd_node **config);

/**
 * @brief Deletes a Call Home client certificate authority (trust-anchor) certificates truststore reference from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_del_client_ca_truststore_ref(const char *client_name, const char *endpt_name,
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
 * @param[in] name Username for this cert-to-name entry.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_ctn(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
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
 */
int nc_server_config_new_ch_tls_del_ctn(const char *client_name, const char *endpt_name,
        uint32_t id, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home TLS version.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] tls_version TLS version to be used. Call this multiple times to set the accepted versions
 * of the TLS protocol and let the client and server negotiate the given version.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_version(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        NC_TLS_VERSION tls_version, struct lyd_node **config);

/**
 * @brief Deletes a TLS version from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in] tls_version TLS version to be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_del_version(const char *client_name, const char *endpt_name,
        NC_TLS_VERSION tls_version, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home TLS cipher.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] cipher_count Number of following ciphers.
 * @param[in] ... TLS ciphers. These ciphers MUST be in the format as listed in the
 * iana-tls-cipher-suite-algs YANG model (lowercase and separated by dashes). Regardless
 * of the TLS protocol version used, all of these ciphers will be tried and some of them
 * might not be set (TLS handshake might fail then). For the list of supported ciphers see
 * the OpenSSL documentation.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_ciphers(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        struct lyd_node **config, int cipher_count, ...);

/**
 * @brief Deletes a Call Home TLS cipher from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in] cipher TLS cipher to be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_del_cipher(const char *client_name, const char *endpt_name,
        const char *cipher, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home Certificate Revocation List via a local file.
 *
 * Beware that you can choose up to one function between the three CRL alternatives on a given endpoint and calling
 * this function will remove any CRL YANG nodes created by the other two functions.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] crl_path Path to a DER/PEM encoded CRL file.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_crl_path(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *crl_path, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home Certificate Revocation List via an URL.
 *
 * Beware that you can choose up to one function between the three CRL alternatives on a given endpoint and calling
 * this function will remove any CRL YANG nodes created by the other two functions.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in] crl_url URL from which the CRL file will be downloaded. The file has to be in the DER or PEM format.
 * The allowed protocols are all the protocols supported by CURL.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_crl_url(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *crl_url, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home Certificate Revocation List via certificate extensions.
 *
 * The chain of configured Certificate Authorities will be examined. For each certificate in this chain all the
 * CRLs from the URLs specified in their extension fields CRL Distribution Points will be downloaded and used.
 *
 * Beware that you can choose up to one function between the three CRL alternatives on a given endpoint and calling
 * this function will remove any CRL YANG nodes created by the other two functions.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Arbitrary identifier of the Call Home client.
 * If a Call Home client with this identifier already exists, its contents will be changed.
 * @param[in] endpt_name Arbitrary identifier of the Call Home client's endpoint.
 * If a Call Home client's endpoint with this identifier already exists, its contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_crl_cert_ext(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        struct lyd_node **config);

/**
 * @brief Deletes all the CRL nodes from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing Call Home endpoint that belongs to the given client.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ch_tls_del_crl(const char *client_name, const char *endpt_name, struct lyd_node **config);

/**
 * @} TLS Call Home Server Configuration
 */

#endif /* NC_ENABLED_SSH_TLS */

#ifdef __cplusplus
}
#endif

#endif /* NC_SESSION_SERVER_H_ */
