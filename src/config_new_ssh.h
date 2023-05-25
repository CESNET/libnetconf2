/**
 * @file config_new_ssh.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server new configuration creation
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

#ifndef NC_CONFIG_NEW_SSH_H_
#define NC_CONFIG_NEW_SSH_H_

#include <libyang/libyang.h>

#include "session_p.h"

#ifdef __cplusplus
extern "C" {
#endif

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

typedef enum {
    NC_ALG_HOSTKEY,
    NC_ALG_KEY_EXCHANGE,
    NC_ALG_ENCRYPTION,
    NC_ALG_MAC
} NC_ALG_TYPE;

#ifdef __cplusplus
}
#endif

#endif /* NC_CONFIG_NEW_SSH_H_ */
