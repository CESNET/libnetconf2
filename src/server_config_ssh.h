/**
 * @file server_config.h
 * @author Roman Janota <janota@cesnet.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 server SSH configuration
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

#ifndef NC_CONFIG_SERVER_SSH_H_
#define NC_CONFIG_SERVER_SSH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdint.h>

#include <libyang/libyang.h>

#include "session.h"

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
 *
 * @note If the last hostkey is deleted, the configuration becomes invalid.
 * Add a new hostkey to make it valid again.
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
 *
 * @note If the last hostkey is deleted, the configuration becomes invalid.
 * Add a new hostkey to make it valid again.
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

#ifdef __cplusplus
}
#endif

#endif /* NC_CONFIG_SERVER_SSH_H_ */
