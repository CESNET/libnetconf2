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
nc_server_config_new_ssh_hostkey(const struct ly_ctx *ctx, const char *endpt_name, const char *hostkey_name,
        const char *privkey_path, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL, *privkey = NULL;
    NC_PRIVKEY_FORMAT privkey_type;
    NC_PUBKEY_FORMAT pubkey_type;
    const char *privkey_format, *pubkey_format;

    NC_CHECK_ARG_RET(NULL, privkey_path, config, ctx, endpt_name, hostkey_name, 1);

    /* get the keys as a string from the given files */
    ret = nc_server_config_new_get_keys(privkey_path, pubkey_path, &privkey, &pubkey, &privkey_type, &pubkey_type);
    if (ret) {
        ERR(NULL, "Getting keys from file(s) failed.");
        goto cleanup;
    }

    /* pubkey format to str */
    if (pubkey_type == NC_PUBKEY_FORMAT_SSH2) {
        pubkey_format = "ietf-crypto-types:ssh-public-key-format";
    } else {
        pubkey_format = "ietf-crypto-types:subject-public-key-info-format";
    }

    /* get privkey identityref value */
    privkey_format = nc_config_new_privkey_format_to_identityref(privkey_type);
    if (!privkey_format) {
        ret = 1;
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, pubkey_format, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/"
            "server-identity/host-key[name='%s']/public-key/inline-definition/public-key-format", endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, pubkey, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/"
            "server-identity/host-key[name='%s']/public-key/inline-definition/public-key", endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, privkey_format, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/"
            "server-identity/host-key[name='%s']/public-key/inline-definition/private-key-format", endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, privkey, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/"
            "server-identity/host-key[name='%s']/public-key/inline-definition/cleartext-private-key", endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(privkey);
    free(pubkey);
    return ret;
}

API int
nc_server_config_new_ssh_del_hostkey(const struct ly_ctx *ctx, const char *endpt_name, const char *hostkey_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, config, 1);

    if (hostkey_name) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/"
                "server-identity/host-key[name='%s']", endpt_name, hostkey_name);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/"
                "server-identity/host-key", endpt_name);
    }
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

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }
cleanup:
    return ret;
}

API int
nc_server_config_new_ssh_del_host_key_alg(const char *endpt_name, const char *alg, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (alg) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
                "ssh/ssh-server-parameters/transport-params/host-key/"
                "host-key-alg[.='iana-ssh-public-key-algs:%s']", endpt_name, alg);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
                "ssh/ssh-server-parameters/transport-params/host-key", endpt_name);
    }
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

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }
cleanup:
    return ret;
}

API int
nc_server_config_new_ssh_del_key_exchange_alg(const char *endpt_name, const char *alg, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (alg) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
                "ssh/ssh-server-parameters/transport-params/key-exchange/"
                "key-exchange-alg[.='iana-ssh-key-exchange-algs:%s']", endpt_name, alg);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
                "ssh/ssh-server-parameters/transport-params/key-exchange", endpt_name);
    }
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

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }
cleanup:
    return ret;
}

API int
nc_server_config_new_ssh_del_encryption_alg(const char *endpt_name, const char *alg, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (alg) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
                "ssh/ssh-server-parameters/transport-params/encryption/"
                "encryption-alg[.='iana-ssh-encryption-algs:%s']", endpt_name, alg);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
                "ssh/ssh-server-parameters/transport-params/encryption", endpt_name);
    }
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

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }
cleanup:
    return ret;
}

API int
nc_server_config_new_ssh_del_mac_alg(const char *endpt_name, const char *alg, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (alg) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
                "ssh/ssh-server-parameters/transport-params/mac/"
                "mac-alg[.='iana-ssh-mac-algs:%s']", endpt_name, alg);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
                "ssh/ssh-server-parameters/transport-params/mac", endpt_name);
    }
}

API int
nc_server_config_new_ssh_del_user(const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (user_name) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/"
                "ssh-server-parameters/client-authentication/users/user[name='%s']", endpt_name, user_name);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/"
                "ssh-server-parameters/client-authentication/users/user", endpt_name);
    }
}

API int
nc_server_config_new_ssh_user_pubkey(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *pubkey_name, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL;
    NC_PUBKEY_FORMAT pubkey_type;
    const char *pubkey_format;

    /* get pubkey data */
    ret = nc_server_config_new_get_pubkey(pubkey_path, &pubkey, &pubkey_type);
    if (ret) {
        goto cleanup;
    }

    /* get pubkey format */
    if (pubkey_type == NC_PUBKEY_FORMAT_SSH2) {
        pubkey_format = "ietf-crypto-types:ssh-public-key-format";
    } else {
        pubkey_format = "ietf-crypto-types:subject-public-key-info-format";
    }

    ret = nc_config_new_create(ctx, config, pubkey_format, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/public-keys/inline-definition/public-key[name='%s']/public-key-format", endpt_name, user_name, pubkey_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, pubkey, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/public-keys/inline-definition/public-key[name='%s']/public-key", endpt_name, user_name, pubkey_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(pubkey);
    return ret;
}

API int
nc_server_config_new_ssh_del_user_pubkey(const char *endpt_name, const char *user_name,
        const char *pubkey_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, user_name, config, 1);

    if (pubkey_name) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/"
                "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/inline-definition/"
                "public-key[name='%s']", endpt_name, user_name, pubkey_name);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/"
                "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/inline-definition/"
                "public-key", endpt_name, user_name);
    }
}

API int
nc_server_config_new_ssh_user_password(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *password, struct lyd_node **config)
{
    int ret = 0;
    char *hashed_pw = NULL;
    const char *salt = "$6$idsizuippipk$";

#ifdef HAVE_CRYPT_R
    struct crypt_data cdata;
#endif

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

    ret = nc_config_new_create(ctx, config, hashed_pw, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/password", endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_ssh_del_user_password(const char *endpt_name, const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, user_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/password", endpt_name, user_name);
}

API int
nc_server_config_new_ssh_user_none(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, user_name, config, 1);

    return nc_config_new_create(ctx, config, NULL, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/none", endpt_name, user_name);
}

API int
nc_server_config_new_ssh_del_user_none(const char *endpt_name, const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, user_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/none", endpt_name, user_name);
}

API int
nc_server_config_new_ssh_user_interactive(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *pam_config_name, const char *pam_config_dir, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, user_name, pam_config_name, config, 1);

    ret = nc_config_new_create(ctx, config, pam_config_name, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/libnetconf2-netconf-server:keyboard-interactive/pam-config-file-name", endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

    if (pam_config_dir) {
        ret = nc_config_new_create(ctx, config, pam_config_dir, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
                "users/user[name='%s']/libnetconf2-netconf-server:keyboard-interactive/pam-config-file-dir", endpt_name, user_name);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_ssh_del_user_interactive(const char *endpt_name, const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, user_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/"
            "libnetconf2-netconf-server:keyboard-interactive", endpt_name, user_name);
}

API int
nc_config_new_ssh_endpoint_user_reference(const struct ly_ctx *ctx, const char *endpt_name,
        const char *referenced_endpt, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, referenced_endpt, config, 1);

    return nc_config_new_create(ctx, config, referenced_endpt, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:endpoint-client-auth", endpt_name);
}

API int
nc_config_new_ssh_del_endpoint_user_reference(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/ssh-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:endpoint-client-auth", endpt_name);
}

API int
nc_server_config_new_ch_ssh_hostkey(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *hostkey_name, const char *privkey_path, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL, *privkey = NULL;
    NC_PRIVKEY_FORMAT privkey_type;
    NC_PUBKEY_FORMAT pubkey_type;
    const char *privkey_format, *pubkey_format;

    NC_CHECK_ARG_RET(NULL, privkey_path, config, ctx, endpt_name, hostkey_name, 1);

    /* get the keys as a string from the given files */
    ret = nc_server_config_new_get_keys(privkey_path, pubkey_path, &privkey, &pubkey, &privkey_type, &pubkey_type);
    if (ret) {
        ERR(NULL, "Getting keys from file(s) failed.");
        goto cleanup;
    }

    /* pubkey format to str */
    if (pubkey_type == NC_PUBKEY_FORMAT_SSH2) {
        pubkey_format = "ietf-crypto-types:ssh-public-key-format";
    } else {
        pubkey_format = "ietf-crypto-types:subject-public-key-info-format";
    }

    /* get privkey identityref value */
    privkey_format = nc_config_new_privkey_format_to_identityref(privkey_type);
    if (!privkey_format) {
        ret = 1;
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, pubkey_format, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
            "host-key[name='%s']/public-key/inline-definition/public-key-format", client_name, endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, pubkey, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
            "host-key[name='%s']/public-key/inline-definition/public-key", client_name, endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, privkey_format, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
            "host-key[name='%s']/public-key/inline-definition/private-key-format", client_name, endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, privkey, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
            "host-key[name='%s']/public-key/inline-definition/cleartext-private-key", client_name, endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(privkey);
    free(pubkey);
    return ret;
}

API int
nc_server_config_new_ch_ssh_del_hostkey(const char *client_name, const char *endpt_name,
        const char *hostkey_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    if (hostkey_name) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
                "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
                "host-key[name='%s']", client_name, endpt_name, hostkey_name);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
                "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
                "host-key", client_name, endpt_name);
    }
}

API int
nc_server_config_new_ch_ssh_user_pubkey(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *user_name, const char *pubkey_name, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL;
    NC_PUBKEY_FORMAT pubkey_type;
    const char *pubkey_format;

    /* get pubkey data */
    ret = nc_server_config_new_get_pubkey(pubkey_path, &pubkey, &pubkey_type);
    if (ret) {
        goto cleanup;
    }

    /* get pubkey format */
    if (pubkey_type == NC_PUBKEY_FORMAT_SSH2) {
        pubkey_format = "ietf-crypto-types:ssh-public-key-format";
    } else {
        pubkey_format = "ietf-crypto-types:subject-public-key-info-format";
    }

    ret = nc_config_new_create(ctx, config, pubkey_format, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/public-keys/inline-definition/public-key[name='%s']/"
            "public-key-format", client_name, endpt_name, user_name, pubkey_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, pubkey, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/public-keys/inline-definition/public-key[name='%s']/"
            "public-key", client_name, endpt_name, user_name, pubkey_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(pubkey);
    return ret;
}

API int
nc_server_config_new_ch_ssh_del_user_pubkey(const char *client_name, const char *endpt_name,
        const char *user_name, const char *pubkey_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, user_name, config, 1);

    if (pubkey_name) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
                "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
                "users/user[name='%s']/public-keys/inline-definition/public-key[name='%s']", client_name,
                endpt_name, user_name, pubkey_name);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
                "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
                "users/user[name='%s']/public-keys/inline-definition/public-key", client_name,
                endpt_name, user_name);
    }
}

API int
nc_server_config_new_ssh_keystore_reference(const struct ly_ctx *ctx, const char *endpt_name, const char *hostkey_name,
        const char *keystore_reference, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, hostkey_name, keystore_reference, config, 1);

    return nc_config_new_create(ctx, config, keystore_reference, "/ietf-netconf-server:netconf-server/listen/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/host-key[name='%s']/public-key/"
            "keystore-reference", endpt_name, hostkey_name);
}

API int
nc_server_config_new_ssh_del_keystore_reference(const char *endpt_name, const char *hostkey_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/host-key[name='%s']/public-key/"
            "keystore-reference", endpt_name, hostkey_name);
}

API int
nc_server_config_new_ssh_truststore_reference(const struct ly_ctx *ctx, const char *endpt_name, const char *user_name,
        const char *truststore_reference, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, user_name, truststore_reference, config, 1);

    return nc_config_new_create(ctx, config, truststore_reference, "/ietf-netconf-server:netconf-server/listen/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/"
            "truststore-reference", endpt_name, user_name);
}

API int
nc_server_config_new_ssh_del_truststore_reference(const char *endpt_name, const char *user_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, user_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/"
            "truststore-reference", endpt_name, user_name);
}
