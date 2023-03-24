/**
 * @file config_new.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server new configuration creation
 *
 * @copyright
 * Copyright (c) 2015 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_CONFIG_NEW_H_
#define NC_CONFIG_NEW_H_

#include <libyang/libyang.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NC_ALG_HOSTKEY,
    NC_ALG_KEY_EXCHANGE,
    NC_ALG_ENCRYPTION,
    NC_ALG_MAC
} NC_ALG_TYPE;

/**
 * @brief Creates new YANG configuration data nodes for a hostkey.
 *
 * @param[in] privkey_path Path to a file containing a private key.
 * The private key has to be in a PEM format. Only RSA and ECDSA keys are supported.
 * @param[in] pubkey_path Path to a file containing a public key. If NULL, public key will be
 * generated from the private key.
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, it's hostkey might be changed.
 * @param[in] hostkey_name Arbitrary identifier of the hostkey.
 * If a hostkey with this identifier already exists, it's contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_ssh_new_hostkey(const char *privkey_path, const char *pubkey_path, const struct ly_ctx *ctx,
        const char *endpt_name, const char *hostkey_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a local-address and local-port.
 *
 * @param[in] address New listening address.
 * @param[in] port New listening port.
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, it's address and port will be overriden.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_ssh_new_address_port(const char *address, const char *port, const struct ly_ctx *ctx,
        const char *endpt_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for host-key algorithms replacing any previous ones.
 *
 * Supported algorithms are: ssh-ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521,
 * rsa-sha2-512, rsa-sha2-256, ssh-rsa and ssh-dss.
 *
 * @param[in] ctx libyang context
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, it's host-key algorithms will be replaced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of host-key algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_ssh_new_host_key_algs(const struct ly_ctx *ctx, const char *endpt_name,
        struct lyd_node **config, int alg_count, ...);

/**
 * @brief Creates new YANG configuration data nodes for key exchange algorithms replacing any previous ones.
 *
 * Supported algorithms are: diffie-hellman-group-exchange-sha1, curve25519-sha256, ecdh-sha2-nistp256,
 * ecdh-sha2-nistp384, ecdh-sha2-nistp521, diffie-hellman-group18-sha512, diffie-hellman-group16-sha512,
 * diffie-hellman-group-exchange-sha256 and diffie-hellman-group14-sha256.
 *
 * @param[in] ctx libyang context
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, it's key exchange algorithms will be replaced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of key exchange algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_ssh_new_key_exchange_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...);

/**
 * @brief Creates new YANG configuration data nodes for encryption algorithms replacing any previous ones.
 *
 * Supported algorithms are: aes256-ctr, aes192-ctr, aes128-ctr, aes256-cbc, aes192-cbc, aes128-cbc, blowfish-cbc
 * triple-des-cbc and none.
 *
 * @param[in] ctx libyang context
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, it's encryption algorithms will be replaced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of encryption algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_ssh_new_encryption_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...);

/**
 * @brief Creates new YANG configuration data nodes for mac algorithms replacing any previous ones.
 *
 * Supported algorithms are: hmac-sha2-256, hmac-sha2-512 and hmac-sha1.
 *
 * @param[in] ctx libyang context
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, it's mac algorithms will be replaced.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @param[in] alg_count Number of following algorithms.
 * @param[in] ... String literals of mac algorithms in a decreasing order of preference.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_ssh_new_mac_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...);

/**
 * @brief Creates new YANG configuration data nodes for a user.
 *
 * @param[in] pubkey_path Path to a file containing the user's public key.
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, it's user might be changed.
 * @param[in] user_name Arbitrary identifier of the user.
 * If an user with this identifier already exists, it's contents will be changed.
 * @param[in] pubkey_name Arbitrary identifier of the user's public key.
 * If a public key with this identifier already exists for this user, it's contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_ssh_new_user(const char *pubkey_path, const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *pubkey_name, struct lyd_node **config);

#ifdef __cplusplus
}
#endif

#endif /* NC_CONFIG_NEW_H_ */
