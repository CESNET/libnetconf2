/**
 * @file server_config.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server configuration
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

#ifndef NC_CONFIG_SERVER_H_
#define NC_CONFIG_SERVER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <libyang/libyang.h>
#include <stdint.h>

#include "netconf.h"
#include "session.h"
#include "session_p.h"

/**
 * @brief Configure server based on the given diff data.
 *
 * Expected data is a validated instance of a ietf-netconf-server YANG data.
 * The data must be in the diff format and supported operations are: create, replace,
 * delete and none. Context must already have implemented the required modules, see
 * ::nc_config_load_modules().
 *
 * @param[in] data ietf-netconf-server YANG data.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup(const struct lyd_node *data);

/**
 * @brief Configure server based on the given data.
 *
 * Expected data is a validated instance of a ietf-netconf-server YANG data.
 * Behaves as if all the nodes in data had the replace operation. That means that the current configuration will be deleted
 * and just the given data will all be applied.
 * The data must not contain any operation attribute, see ::nc_config_setup() which works with diff.
 * Context must already have implemented the required modules, see * ::nc_config_load_modules().
 *
 * @param[in] data ietf-netconf-server YANG data.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup2(const struct lyd_node *data);

/**
 * @brief Configure server based on the given ietf-netconf-server YANG data.
 * Wrapper around ::nc_config_setup_server() hiding work with parsing the data.
 *
 * @param[in] ctx libyang context.
 * @param[in] path Path to the file with YANG data in XML format.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup_path(const struct ly_ctx *ctx, const char *path);

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
int nc_server_config_new_ssh_hostkey(const char *privkey_path, const char *pubkey_path, const struct ly_ctx *ctx,
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
int nc_server_config_new_ssh_address_port(const char *address, const char *port, const struct ly_ctx *ctx,
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
int nc_server_config_new_ssh_host_key_algs(const struct ly_ctx *ctx, const char *endpt_name,
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
int nc_server_config_new_ssh_key_exchange_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
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
int nc_server_config_new_ssh_encryption_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
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
int nc_server_config_new_ssh_mac_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...);

/**
 * @brief Creates new YANG configuration data nodes for a client, which supports the public key authentication method.
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
int nc_server_config_new_ssh_client_auth_pubkey(const char *pubkey_path, const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *pubkey_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a client, which supports the password authentication method.
 *
 * This function sets the password for the given user.
 *
 * @param[in] password Cleartext user's password.
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, it's user might be changed.
 * @param[in] user_name Arbitrary identifier of the user.
 * If an user with this identifier already exists, it's contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_client_auth_password(const char *password, const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a client, which supports the none authentication method.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, it's user might be changed.
 * @param[in] user_name Arbitrary identifier of the user.
 * If an user with this identifier already exists, it's contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_client_auth_none(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

/**
 * @brief Creates new YANG configuration data nodes for a client, which supports the interactive authentication method.
 *
 * @param[in] pam_config_name Name of the PAM configuration file.
 * @param[in] pam_config_name Optional. The absolute path to the directory in which the configuration file
 * with the name conf_name is located. A newer version (>= 1.4) of PAM library is required to be able to specify
 * the path. If NULL is passed, then the PAM's system directories will be searched (usually /etc/pam.d/).
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Arbitrary identifier of the endpoint.
 * If an endpoint with this identifier already exists, it's user might be changed.
 * @param[in] user_name Arbitrary identifier of the user.
 * If an user with this identifier already exists, it's contents will be changed.
 * @param[in,out] config Configuration YANG data tree. If *config is NULL, it will be created.
 * Otherwise the new YANG data will be added to the previous data and may override it.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_new_ssh_client_auth_interactive(const char *pam_config_name, const char *pam_config_dir,
        const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config);

#ifdef __cplusplus
}
#endif

#endif /* NC_SESSION_SERVER_H_ */
