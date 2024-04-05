/**
 * @file server_config_util.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server configuration utlities header
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

#ifndef NC_SERVER_CONFIG_UTIL_H_
#define NC_SERVER_CONFIG_UTIL_H_

#include <libyang/libyang.h>

#include "session_p.h"

#ifdef NC_ENABLED_SSH_TLS

/* private key's pkcs8 header */
#define NC_PKCS8_PRIVKEY_HEADER "-----BEGIN PRIVATE KEY-----\n"

/* private key's pkcs8 footer */
#define NC_PKCS8_PRIVKEY_FOOTER "\n-----END PRIVATE KEY-----\n"

/* private key's openssh header */
#define NC_OPENSSH_PRIVKEY_HEADER "-----BEGIN OPENSSH PRIVATE KEY-----\n"

/* private key's openssh footer */
#define NC_OPENSSH_PRIVKEY_FOOTER "\n-----END OPENSSH PRIVATE KEY-----\n"

/* private key's pkcs1 rsa header */
#define NC_PKCS1_RSA_PRIVKEY_HEADER "-----BEGIN RSA PRIVATE KEY-----\n"

/* private key's pkcs1 rsa footer */
#define NC_PKCS1_RSA_PRIVKEY_FOOTER "\n-----END RSA PRIVATE KEY-----\n"

/* private key's sec1 ec header */
#define NC_SEC1_EC_PRIVKEY_HEADER "-----BEGIN EC PRIVATE KEY-----\n"

/* private key's sec1 ec footer */
#define NC_SEC1_EC_PRIVKEY_FOOTER "\n-----END EC PRIVATE KEY-----\n"

/* private key's header when getting an EC/RSA privkey from file using libssh */
#define NC_LIBSSH_PRIVKEY_HEADER "-----BEGIN PRIVATE KEY-----\n"

/* private key's footer when getting an EC/RSA privkey from file using libssh */
#define NC_LIBSSH_PRIVKEY_FOOTER "\n-----END PRIVATE KEY-----\n"

/* public key's ssh2 header */
#define NC_SSH2_PUBKEY_HEADER "---- BEGIN SSH2 PUBLIC KEY ----\n"

/* public key's SubjectPublicKeyInfo format header */
#define NC_SUBJECT_PUBKEY_INFO_HEADER "-----BEGIN PUBLIC KEY-----\n"

/* public key's SubjectPublicKeyInfo format footer */
#define NC_SUBJECT_PUBKEY_INFO_FOOTER "\n-----END PUBLIC KEY-----\n"

/* certificate's PEM format header */
#define NC_PEM_CERTIFICATE_HEADER "-----BEGIN CERTIFICATE-----\n"

/* certificate's PEM format footer */
#define NC_PEM_CERTIFICATE_FOOTER "\n-----END CERTIFICATE-----\n"

typedef enum {
    NC_ALG_HOSTKEY,
    NC_ALG_KEY_EXCHANGE,
    NC_ALG_ENCRYPTION,
    NC_ALG_MAC
} NC_ALG_TYPE;

/**
 * @brief Gets asymmetric key pair from private key (and optionally public key) file(s).
 *
 * @param[in] privkey_path Path to private key.
 * @param[in] pubkey_path Optional path to public key. If not set, PK will be generated from private key.
 * @param[in] wanted_pubkey_type Wanted public key format to be generated (SPKI/SSH)
 * @param[out] privkey Base64 encoded private key.
 * @param[out] privkey_type Type of the private key. (RSA, EC, etc)
 * @param[out] pubkey Base64 encoded public key.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_util_get_asym_key_pair(const char *privkey_path, const char *pubkey_path, NC_PUBKEY_FORMAT wanted_pubkey_type,
        char **privkey, NC_PRIVKEY_FORMAT *privkey_type, char **pubkey);

/**
 * @brief Gets public key from a file and converts it to the SSH format if need be.
 *
 * @param[in] pubkey_path Path to the public key.
 * @param[out] pubkey Base64 encoded public key.
 *
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_util_get_ssh_pubkey_file(const char *pubkey_path, char **pubkey);

/**
 * @brief Gets a certificate from a file.
 *
 * @param[in] cert_path Path to the certificate.
 * @param[out] cert Base64 PEM encoded certificate data.
 *
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_util_read_certificate(const char *cert_path, char **cert);

/**
 * @brief Converts private key format to its associated identityref value.
 *
 * @param[in] format Private key format.
 *
 * @return Identityref on success, NULL on failure.
 */
const char *nc_server_config_util_privkey_format_to_identityref(NC_PRIVKEY_FORMAT format);

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Creates YANG data nodes in a path and gives the final node a value.
 *
 * @param[in] ctx libyang context.
 * @param[in, out] tree The YANG data tree where the insertion will happen. On success
 * this is set to the top level container.
 * @param[in] value Value assigned to the final node in the path.
 * @param[in] path_fmt Format of the path.
 * @param[in] ... Parameters for the path format, essentially representing the lists' keys.
 * @return 0 on success, 1 otherwise.
 */
int nc_server_config_create(const struct ly_ctx *ctx, struct lyd_node **tree, const char *value, const char *path_fmt, ...);

/**
 * @brief Creates a YANG data node by appending it to a specified parent node.
 *
 * @param[in] ctx libyang context.
 * @param[in] parent_path Path to the parent node.
 * @param[in] child_name Name of the parent's child node to be created.
 * @param[in] value Value given to the child node.
 * @param[out] tree YANG data tree where the insertion will happen. On success
 * this is set to the top level container.
 * @return 0 on success, 1 otherwise.
 */
int nc_server_config_append(const struct ly_ctx *ctx, const char *parent_path, const char *child_name,
        const char *value, struct lyd_node **tree);

/**
 * @brief Deletes a subtree from the YANG data.
 *
 * @param tree YANG data from which the subtree will be deleted.
 * @param[in] path_fmt Format of the path. The last node will be the top level node of the deleted tree.
 * @param[in] ... Parameters for the path format, essentially representing the lists' keys.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_delete(struct lyd_node **tree, const char *path_fmt, ...);

/**
 * @brief Deletes a subtree from the YANG data, but doesn't return an error if the node doesn't exist.
 *
 * @param tree YANG data from which the subtree will be deleted.
 * @param[in] path_fmt Format of the path. The last node will be the top level node of the deleted tree.
 * @param[in] ... Parameters for the path format, essentially representing the lists' keys.
 * @return 0 on success, non-zero otherwise.
 */
int nc_server_config_check_delete(struct lyd_node **tree, const char *path_fmt, ...);

#endif /* NC_CONFIG_NEW_H_ */
