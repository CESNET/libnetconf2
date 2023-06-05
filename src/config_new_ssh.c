/**
 * @file config_new_ssh.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server new SSH configuration creation functions
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

#define _GNU_SOURCE

#include <crypt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "config_new.h"
#include "log_p.h"
#include "server_config.h"
#include "session_p.h"

#if !defined (HAVE_CRYPT_R)
extern pthread_mutex_t crypt_lock;
#endif

API int
nc_server_config_new_ssh_hostkey(const struct ly_ctx *ctx,
        const char *endpt_name, const char *hostkey_name, const char *privkey_path, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL, *privkey = NULL, *pubkey_stripped, *privkey_stripped;
    struct lyd_node *new_tree;
    char *tree_path = NULL;
    NC_PRIVKEY_FORMAT privkey_type;
    NC_PUBKEY_FORMAT pubkey_type;
    const char *privkey_identity;

    NC_CHECK_ARG_RET(NULL, privkey_path, config, ctx, endpt_name, hostkey_name, 1);

    /* get the keys as a string from the given files */
    ret = nc_server_config_new_get_keys(privkey_path, pubkey_path, &privkey, &pubkey, &privkey_type, &pubkey_type);
    if (ret) {
        ERR(NULL, "Getting keys from file(s) failed.");
        goto cleanup;
    }

    /* prepare path where leaves will get inserted */
    asprintf(&tree_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/"
            "server-identity/host-key[name='%s']/public-key/local-definition", endpt_name, hostkey_name);
    if (!tree_path) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* create all the nodes in the path if they weren't there */
    ret = lyd_new_path(*config, ctx, tree_path, NULL, LYD_NEW_PATH_UPDATE, &new_tree);
    if (ret) {
        goto cleanup;
    }
    if (!*config) {
        *config = new_tree;
    }

    /* find the node where leaves will get inserted */
    ret = lyd_find_path(*config, tree_path, 0, &new_tree);
    if (ret) {
        goto cleanup;
    }

    /* insert pubkey format */
    if (pubkey_type == NC_PUBKEY_FORMAT_SSH2) {
        ret = lyd_new_term(new_tree, NULL, "public-key-format", "ietf-crypto-types:ssh-public-key-format", 0, NULL);
    } else {
        ret = lyd_new_term(new_tree, NULL, "public-key-format", "ietf-crypto-types:subject-public-key-info-format", 0, NULL);
    }
    if (ret) {
        goto cleanup;
    }

    /* strip pubkey's header and footer only if it's generated from pkcs8 key (using OpenSSL),
     * otherwise it's already stripped
     */
    if (!pubkey_path && (privkey_type == NC_PRIVKEY_FORMAT_X509)) {
        pubkey_stripped = pubkey + strlen(NC_SUBJECT_PUBKEY_INFO_HEADER);
        pubkey_stripped[strlen(pubkey_stripped) - strlen(NC_SUBJECT_PUBKEY_INFO_FOOTER)] = '\0';
    } else {
        pubkey_stripped = pubkey;
    }

    /* insert pubkey b64 */
    ret = lyd_new_term(new_tree, NULL, "public-key", pubkey_stripped, 0, NULL);
    if (ret) {
        goto cleanup;
    }

    /* get privkey identityref value */
    privkey_identity = nc_config_new_privkey_format_to_identityref(privkey_type);
    if (!privkey_identity) {
        ret = 1;
        goto cleanup;
    }

    /* insert private key format */
    ret = lyd_new_term(new_tree, NULL, "private-key-format", privkey_identity, 0, NULL);
    if (ret) {
        goto cleanup;
    }

    if (privkey_type == NC_PRIVKEY_FORMAT_OPENSSH) {
        /* only OpenSSH private keys have different header and footer after processing */
        privkey_stripped = privkey + strlen(NC_OPENSSH_PRIVKEY_HEADER);
        privkey_stripped[strlen(privkey_stripped) - strlen(NC_OPENSSH_PRIVKEY_FOOTER)] = '\0';
    } else {
        /* the rest share the same header and footer */
        privkey_stripped = privkey + strlen(NC_PKCS8_PRIVKEY_HEADER);
        privkey_stripped[strlen(privkey_stripped) - strlen(NC_PKCS8_PRIVKEY_FOOTER)] = '\0';
    }

    ret = lyd_new_term(new_tree, NULL, "cleartext-private-key", privkey_stripped, 0, NULL);
    if (ret) {
        goto cleanup;
    }

    /* check if top-level container has operation and if not, add it */
    ret = nc_config_new_check_add_operation(ctx, *config);
    if (ret) {
        goto cleanup;
    }

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(privkey);
    free(pubkey);
    free(tree_path);
    return ret;
}

static int
nc_server_config_new_ssh_transport_params_prep(const struct ly_ctx *ctx, const char *endpt_name,
        struct lyd_node *config, struct lyd_node **new_tree, struct lyd_node **alg_tree)
{
    int ret = 0;
    char *tree_path = NULL;

    /* prepare path */
    asprintf(&tree_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
            "ssh/ssh-server-parameters/transport-params", endpt_name);
    if (!tree_path) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* create all the nodes in the path */
    ret = lyd_new_path2(config, ctx, tree_path, NULL, 0, 0, LYD_NEW_PATH_UPDATE, new_tree, alg_tree);
    if (ret) {
        ERR(NULL, "Creating new path to transport-params failed.");
        goto cleanup;
    }

    if (!*alg_tree) {
        /* no new nodes added */
        ret = lyd_find_path(config, tree_path, 0, alg_tree);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    free(tree_path);
    return ret;
}

static int
nc_server_config_new_ssh_transport_params(const struct ly_ctx *ctx, NC_ALG_TYPE alg_type, int alg_count, va_list ap,
        struct lyd_node *tree)
{
    int i, ret = 0;
    char *alg, *alg_ident;
    const char *module, *alg_path, *old_path;
    struct lyd_node *old = NULL;

    /* get the correct module with the indentity base and the path in the ietf-netconf-server module */
    switch (alg_type) {
    case NC_ALG_HOSTKEY:
        module = "iana-ssh-public-key-algs";
        alg_path = "host-key/host-key-alg";
        old_path = "host-key";
        break;
    case NC_ALG_KEY_EXCHANGE:
        module = "iana-ssh-key-exchange-algs";
        alg_path = "key-exchange/key-exchange-alg";
        old_path = "key-exchange";
        break;
    case NC_ALG_ENCRYPTION:
        module = "iana-ssh-encryption-algs";
        alg_path = "encryption/encryption-alg";
        old_path = "encryption";
        break;
    case NC_ALG_MAC:
        module = "iana-ssh-mac-algs";
        alg_path = "mac/mac-alg";
        old_path = "mac";
        break;
    default:
        ret = 1;
        ERR(NULL, "Unknown algorithm type.");
        goto cleanup;
    }

    /* delete all older algorithms (if any) se they can be replaced by the new ones */
    lyd_find_path(tree, old_path, 0, &old);
    if (old) {
        lyd_free_tree(old);
    }

    for (i = 0; i < alg_count; i++) {
        alg = va_arg(ap, char *);

        asprintf(&alg_ident, "%s:%s", module, alg);
        if (!alg_ident) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }

        /* create the leaf list */
        ret = lyd_new_path(tree, ctx, alg_path, alg_ident, 0, NULL);
        if (ret) {
            ERR(NULL, "Creating new algorithm leaf-list failed.");
            goto cleanup;
        }

        free(alg_ident);
    }

cleanup:
    va_end(ap);
    return ret;
}

API int
nc_server_config_new_ssh_host_key_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...)
{
    int ret = 0;
    struct lyd_node *new_tree, *alg_tree;
    va_list ap;

    ret = nc_server_config_new_ssh_transport_params_prep(ctx, endpt_name, *config, &new_tree, &alg_tree);
    if (ret) {
        goto cleanup;
    }

    if (!*config) {
        *config = new_tree;
    }

    va_start(ap, alg_count);

    ret = nc_server_config_new_ssh_transport_params(ctx, NC_ALG_HOSTKEY, alg_count, ap, alg_tree);
    if (ret) {
        goto cleanup;
    }

    /* check if top-level container has operation and if not, add it */
    ret = nc_config_new_check_add_operation(ctx, *config);
    if (ret) {
        goto cleanup;
    }

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }
cleanup:
    return ret;
}

API int
nc_server_config_ssh_new_key_exchange_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...)
{
    int ret = 0;
    struct lyd_node *new_tree, *alg_tree;
    va_list ap;

    ret = nc_server_config_new_ssh_transport_params_prep(ctx, endpt_name, *config, &new_tree, &alg_tree);
    if (ret) {
        goto cleanup;
    }

    if (!*config) {
        *config = new_tree;
    }

    va_start(ap, alg_count);

    ret = nc_server_config_new_ssh_transport_params(ctx, NC_ALG_KEY_EXCHANGE, alg_count, ap, alg_tree);
    if (ret) {
        goto cleanup;
    }

    /* check if top-level container has operation and if not, add it */
    ret = nc_config_new_check_add_operation(ctx, *config);
    if (ret) {
        goto cleanup;
    }

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }
cleanup:
    return ret;
}

API int
nc_server_config_new_ssh_encryption_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...)
{
    int ret = 0;
    struct lyd_node *new_tree, *alg_tree;
    va_list ap;

    ret = nc_server_config_new_ssh_transport_params_prep(ctx, endpt_name, *config, &new_tree, &alg_tree);
    if (ret) {
        goto cleanup;
    }

    if (!*config) {
        *config = new_tree;
    }

    va_start(ap, alg_count);

    ret = nc_server_config_new_ssh_transport_params(ctx, NC_ALG_ENCRYPTION, alg_count, ap, alg_tree);
    if (ret) {
        goto cleanup;
    }

    /* check if top-level container has operation and if not, add it */
    ret = nc_config_new_check_add_operation(ctx, *config);
    if (ret) {
        goto cleanup;
    }

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }
cleanup:
    return ret;
}

API int
nc_server_config_ssh_new_mac_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...)
{
    int ret = 0;
    struct lyd_node *new_tree, *alg_tree;
    va_list ap;

    ret = nc_server_config_new_ssh_transport_params_prep(ctx, endpt_name, *config, &new_tree, &alg_tree);
    if (ret) {
        goto cleanup;
    }

    if (!*config) {
        *config = new_tree;
    }

    va_start(ap, alg_count);

    ret = nc_server_config_new_ssh_transport_params(ctx, NC_ALG_MAC, alg_count, ap, alg_tree);
    if (ret) {
        goto cleanup;
    }

    /* check if top-level container has operation and if not, add it */
    ret = nc_config_new_check_add_operation(ctx, *config);
    if (ret) {
        goto cleanup;
    }

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }
cleanup:
    return ret;
}

API int
nc_server_config_new_ssh_client_auth_pubkey(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *pubkey_name, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL, *tree_path = NULL;
    struct lyd_node *new_tree;
    NC_PUBKEY_FORMAT pubkey_type;

    ret = nc_server_config_new_get_pubkey(pubkey_path, &pubkey, &pubkey_type);
    if (ret) {
        goto cleanup;
    }

    /* prepare path where leaves will get inserted */
    asprintf(&tree_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/public-keys/local-definition/public-key[name='%s']", endpt_name, user_name, pubkey_name);
    if (!tree_path) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* create all the nodes in the path if they weren't there */
    ret = lyd_new_path(*config, ctx, tree_path, NULL, LYD_NEW_PATH_UPDATE, &new_tree);
    if (ret) {
        goto cleanup;
    }
    if (!*config) {
        *config = new_tree;
    }

    /* find the node where leaves will get inserted */
    ret = lyd_find_path(*config, tree_path, 0, &new_tree);
    if (ret) {
        goto cleanup;
    }

    /* insert pubkey format */
    if (pubkey_type == NC_PUBKEY_FORMAT_SSH2) {
        ret = lyd_new_term(new_tree, NULL, "public-key-format", "ietf-crypto-types:ssh-public-key-format", 0, NULL);
    } else {
        ret = lyd_new_term(new_tree, NULL, "public-key-format", "ietf-crypto-types:subject-public-key-info-format", 0, NULL);
    }
    if (ret) {
        goto cleanup;
    }

    /* insert pubkey b64 */
    ret = lyd_new_term(new_tree, NULL, "public-key", pubkey, 0, NULL);
    if (ret) {
        goto cleanup;
    }

    /* check if top-level container has operation and if not, add it */
    ret = nc_config_new_check_add_operation(ctx, *config);
    if (ret) {
        goto cleanup;
    }

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(tree_path);
    free(pubkey);
    return ret;
}

API int
nc_server_config_new_ssh_client_auth_password(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *password, struct lyd_node **config)
{
    int ret = 0;
    char *tree_path = NULL, *hashed_pw = NULL;
    struct lyd_node *new_tree;
    const char *salt = "$6$idsizuippipk$";

#ifdef HAVE_CRYPT_R
    struct crypt_data cdata;
#endif

    /* prepare path where the leaf will get inserted */
    asprintf(&tree_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']", endpt_name, user_name);
    if (!tree_path) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* create all the nodes in the path if they weren't there */
    ret = lyd_new_path(*config, ctx, tree_path, NULL, LYD_NEW_PATH_UPDATE, &new_tree);
    if (ret) {
        goto cleanup;
    }
    if (!*config) {
        *config = new_tree;
    }

    /* find the node where the leaf will get inserted */
    ret = lyd_find_path(*config, tree_path, 0, &new_tree);
    if (ret) {
        goto cleanup;
    }

#ifdef HAVE_CRYPT_R
    cdata.initialized = 0;
    hashed_pw = crypt_r(password, salt, &data);
#else
    pthread_mutex_lock(&crypt_lock);
    hashed_pw = crypt(password, salt);
    pthread_mutex_unlock(&crypt_lock);
#endif

    if (!hashed_pw) {
        ERR(NULL, "Hashing password failed.");
        ret = 1;
        goto cleanup;
    }

    /* insert SHA-512 hashed password */
    ret = lyd_new_term(new_tree, NULL, "password", hashed_pw, 0, NULL);
    if (ret) {
        goto cleanup;
    }

    /* check if top-level container has operation and if not, add it */
    ret = nc_config_new_check_add_operation(ctx, *config);
    if (ret) {
        goto cleanup;
    }

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(tree_path);
    return ret;
}

API int
nc_server_config_new_ssh_client_auth_none(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    int ret = 0;
    char *tree_path = NULL;
    struct lyd_node *new_tree;

    /* prepare path where the leaf will get inserted */
    asprintf(&tree_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']", endpt_name, user_name);
    if (!tree_path) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* create all the nodes in the path if they weren't there */
    ret = lyd_new_path(*config, ctx, tree_path, NULL, LYD_NEW_PATH_UPDATE, &new_tree);
    if (ret) {
        goto cleanup;
    }
    if (!*config) {
        *config = new_tree;
    }

    /* find the node where the leaf will get inserted */
    ret = lyd_find_path(*config, tree_path, 0, &new_tree);
    if (ret) {
        goto cleanup;
    }

    /* insert none leaf */
    ret = lyd_new_term(new_tree, NULL, "none", NULL, 0, NULL);
    if (ret) {
        goto cleanup;
    }

    /* check if top-level container has operation and if not, add it */
    ret = nc_config_new_check_add_operation(ctx, *config);
    if (ret) {
        goto cleanup;
    }

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(tree_path);
    return ret;
}

API int
nc_server_config_new_ssh_client_auth_interactive(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *pam_config_name, const char *pam_config_dir, struct lyd_node **config)
{
    int ret = 0;
    char *tree_path = NULL;
    struct lyd_node *new_tree;

    /* prepare path where the leaf will get inserted */
    asprintf(&tree_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/libnetconf2-netconf-server:keyboard-interactive", endpt_name, user_name);
    if (!tree_path) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* create all the nodes in the path if they weren't there */
    ret = lyd_new_path(*config, ctx, tree_path, NULL, LYD_NEW_PATH_UPDATE, &new_tree);
    if (ret) {
        goto cleanup;
    }
    if (!*config) {
        *config = new_tree;
    }

    /* find the node where the leaf will get inserted */
    ret = lyd_find_path(*config, tree_path, 0, &new_tree);
    if (ret) {
        goto cleanup;
    }

    /* insert file-name leaf */
    ret = lyd_new_term(new_tree, NULL, "pam-config-file-name", pam_config_name, 0, NULL);
    if (ret) {
        goto cleanup;
    }

    if (pam_config_dir) {
        /* insert file-path leaf */
        ret = lyd_new_term(new_tree, NULL, "pam-config-file-dir", pam_config_dir, 0, NULL);
        if (ret) {
            goto cleanup;
        }
    }

    /* check if top-level container has operation and if not, add it */
    ret = nc_config_new_check_add_operation(ctx, *config);
    if (ret) {
        goto cleanup;
    }

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(tree_path);
    return ret;
}
