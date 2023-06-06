/**
 * @file config_new.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server new configuration creation header
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

#ifndef NC_CONFIG_NEW_H_
#define NC_CONFIG_NEW_H_

#include <libyang/libyang.h>

#include "session_p.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/* private key's sec1 ec header */
#define NC_SEC1_EC_PRIVKEY_HEADER "-----BEGIN EC PRIVATE KEY-----\n"

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

int nc_server_config_new_get_keys(const char *privkey_path, const char *pubkey_path,
        char **privkey, char **pubkey, NC_PRIVKEY_FORMAT *privkey_type, NC_PUBKEY_FORMAT *pubkey_type);

int nc_server_config_new_get_pubkey(const char *pubkey_path, char **pubkey, NC_PUBKEY_FORMAT *pubkey_type);

int nc_server_config_new_read_certificate(const char *cert_path, char **cert);

const char * nc_config_new_privkey_format_to_identityref(NC_PRIVKEY_FORMAT format);

#endif /* NC_ENABLED_SSH_TLS */

int nc_config_new_check_add_operation(const struct ly_ctx *ctx, struct lyd_node *top);

#ifdef __cplusplus
}
#endif

#endif /* NC_CONFIG_NEW_H_ */
