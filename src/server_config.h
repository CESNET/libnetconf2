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
 * @param[in] diff YANG diff belonging to either ietf-netconf-server, ietf-keystore or ietf-truststore modules.
 * The top level node HAS to have an operation (create, replace, delete or none).
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup_diff(const struct lyd_node *diff);

/**
 * @brief Configure server based on the given data.
 *
 * Behaves as if all the nodes in data had the replace operation. That means that the current configuration will be deleted
 * and just the given data will be applied.
 * Context must already have implemented the required modules, see ::nc_server_config_load_modules().
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

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Creates new YANG configuration data nodes for address and port.
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
int nc_server_config_add_address_port(const struct ly_ctx *ctx, const char *endpt_name, NC_TRANSPORT_IMPL transport,
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
int nc_server_config_del_endpt(const char *endpt_name, struct lyd_node **config);

#ifdef NC_ENABLED_SSH_TLS

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
int nc_server_config_del_truststore_cert(const char *cert_bag_name,
        const char *cert_name, struct lyd_node **config);

/**
 * @brief Gets the hostkey algorithms supported by the server from the 'iana-ssh-public-key-algs' YANG module.
 *
 * @param[in] ctx libyang context.
 * @param[out] hostkey_algs Container with leaf-lists containing the supported algorithms.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_oper_get_hostkey_algs(const struct ly_ctx *ctx, struct lyd_node **hostkey_algs);

/**
 * @brief Gets the key exchange algorithms supported by the server from the 'iana-ssh-key-exchange-algs' YANG module.
 *
 * @param[in] ctx libyang context.
 * @param[out] kex_algs Container with leaf-lists containing the supported algorithms.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_oper_get_kex_algs(const struct ly_ctx *ctx, struct lyd_node **kex_algs);

/**
 * @brief Gets the encryption algorithms supported by the server from the 'iana-ssh-encryption-algs' YANG module.
 *
 * @param[in] ctx libyang context.
 * @param[out] encryption_algs Container with leaf-lists containing the supported algorithms.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_oper_get_encryption_algs(const struct ly_ctx *ctx, struct lyd_node **encryption_algs);

/**
 * @brief Gets the MAC algorithms supported by the server from the 'iana-ssh-mac-algs' YANG module.
 *
 * @param[in] ctx libyang context.
 * @param[out] mac_algs Container with leaf-lists containing the supported algorithms.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_oper_get_mac_algs(const struct ly_ctx *ctx, struct lyd_node **mac_algs);

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
int nc_server_config_add_ssh_hostkey(const struct ly_ctx *ctx, const char *endpt_name, const char *hostkey_name,
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
int nc_server_config_del_ssh_hostkey(const struct ly_ctx *ctx, const char *endpt_name,
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
int nc_server_config_add_ssh_keystore_ref(const struct ly_ctx *ctx, const char *endpt_name, const char *hostkey_name,
        const char *keystore_reference, struct lyd_node **config);

/**
 * @brief Deletes a keystore reference from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] hostkey_name Identifier of an existing hostkey on the given endpoint.
 * @param[in,out] config Configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_ssh_keystore_ref(const char *endpt_name, const char *hostkey_name,
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
int nc_server_config_add_ssh_user_pubkey(const struct ly_ctx *ctx, const char *endpt_name,
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
int nc_server_config_del_ssh_user_pubkey(const char *endpt_name, const char *user_name,
        const char *pubkey_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for an SSH user that will use system's authorized_keys to authenticate.
 *
 * The path to the authorized_keys file must be configured to successfully
 * authenticate, see ::nc_server_ssh_set_authkey_path_format().
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
int nc_server_config_add_ssh_user_authkey(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Deletes an SSH user's authorized_keys method from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] user_name Identifier of an existing user on the given endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_ssh_user_authkey(const char *endpt_name, const char *user_name, struct lyd_node **config);

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
int nc_server_config_add_ssh_user_password(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *password, struct lyd_node **config);

/**
 * @brief Deletes an SSH user's password from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] user_name Identifier of an existing user on the given endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_ssh_user_password(const char *endpt_name, const char *user_name,
        struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for an SSH user's keyboard interactive authentication method.
 *
 * One of Linux PAM, local users, or user callback is used to authenticate users with this SSH method (see \ref ln2doc_kbdint "the documentation").
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
int nc_server_config_add_ssh_user_interactive(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Deletes an SSH user's keyboard interactive authentication from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] user_name Identifier of an existing user on the given endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_ssh_user_interactive(const char *endpt_name, const char *user_name,
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
int nc_server_config_del_ssh_user(const char *endpt_name,
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
int nc_server_config_add_ssh_truststore_ref(const struct ly_ctx *ctx, const char *endpt_name, const char *user_name,
        const char *truststore_reference, struct lyd_node **config);

/**
 * @brief Deletes a truststore reference from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in] user_name Identifier of an user on the given endpoint whose truststore reference will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_ssh_truststore_ref(const char *endpt_name, const char *user_name,
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
int nc_server_config_add_ssh_endpoint_client_ref(const struct ly_ctx *ctx, const char *endpt_name,
        const char *referenced_endpt, struct lyd_node **config);

/**
 * @brief Deletes reference to another SSH endpoint's users from the YANG data.
 *
 * @param[in] endpt_name Identifier of an existing endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_ssh_endpoint_client_ref(const char *endpt_name, struct lyd_node **config);

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
 * A <- B <- C,
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
 * @param[in] name Username for this cert-to-name entry.
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
 */
int nc_server_config_del_tls_ctn(const char *endpt_name, uint32_t id, struct lyd_node **config);

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
int nc_server_config_add_ch_address_port(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
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
int nc_server_config_del_ch_client(const char *client_name, struct lyd_node **config);

/**
 * @brief Deletes a Call Home endpoint from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Optional identifier of a CH endpoint to be deleted.
 * If NULL, all of the CH endpoints which belong to the given client will be deleted.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
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
int nc_server_config_add_ch_ssh_hostkey(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
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
int nc_server_config_del_ch_ssh_hostkey(const char *client_name, const char *endpt_name,
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
int nc_server_config_add_ch_ssh_keystore_ref(const struct ly_ctx *ctx, const char *client_name,
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
int nc_server_config_del_ch_ssh_keystore_ref(const char *client_name, const char *endpt_name,
        const char *hostkey_name, struct lyd_node **config);

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
int nc_server_config_add_ch_ssh_user_pubkey(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
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
int nc_server_config_del_ch_ssh_user_pubkey(const char *client_name, const char *endpt_name,
        const char *user_name, const char *pubkey_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home SSH user that will use system's authorized_keys to authenticate.
 *
 * The path to the authorized_keys file must be configured to successfully
 * authenticate, see ::nc_server_ssh_set_authkey_path_format().
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
int nc_server_config_add_ch_ssh_user_authkey(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *user_name, struct lyd_node **config);

/**
 * @brief Deletes a Call Home SSH user's authorized_keys method from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] user_name Identifier of an existing user on the given endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_ch_del_ssh_user_authkey(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

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
int nc_server_config_add_ch_ssh_user_password(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
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
int nc_server_config_del_ch_ssh_user_password(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a Call Home SSH user's keyboard interactive authentication method.
 *
 * One of Linux PAM, local users, or user callback is used to authenticate users with this SSH method (see \ref ln2doc_kbdint "the documentation").
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
int nc_server_config_add_ch_ssh_user_interactive(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Deletes a Call Home SSH user's keyboard interactive authentication from the YANG data.
 *
 * @param[in] client_name Identifier of an existing Call Home client.
 * @param[in] endpt_name Identifier of an existing endpoint that belongs to the given CH client.
 * @param[in] user_name Identifier of an existing SSH user that belongs to the given CH endpoint.
 * @param[in,out] config Modified configuration YANG data tree.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_del_ch_ssh_user_interactive(const char *client_name, const char *endpt_name,
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
int nc_server_config_del_ch_ssh_user(const char *client_name, const char *endpt_name,
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
int nc_server_config_add_ch_ssh_truststore_ref(const struct ly_ctx *ctx, const char *client_name,
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
int nc_server_config_del_ch_ssh_truststore_ref(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

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
 * @param[in] name Username for this cert-to-name entry.
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
 */
int nc_server_config_del_ch_tls_ctn(const char *client_name, const char *endpt_name,
        uint32_t id, struct lyd_node **config);

/**
 * @} TLS Call Home Server Configuration
 */

#endif /* NC_ENABLED_SSH_TLS */

#ifdef __cplusplus
}
#endif

#endif /* NC_SESSION_SERVER_H_ */
