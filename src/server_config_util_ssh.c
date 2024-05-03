/**
 * @file server_config_util_ssh.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server SSH configuration utilities
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

#include "server_config_util.h"

#include <crypt.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "server_config.h"
#include "session_p.h"

static int
_nc_server_config_add_ssh_hostkey(const struct ly_ctx *ctx, const char *tree_path,
        const char *privkey_path, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL, *privkey = NULL;
    NC_PRIVKEY_FORMAT privkey_type;
    const char *privkey_format, *pubkey_format = "ietf-crypto-types:ssh-public-key-format";

    NC_CHECK_ARG_RET(NULL, ctx, tree_path, privkey_path, config, 1);

    /* get the keys as a string from the given files */
    ret = nc_server_config_util_get_asym_key_pair(privkey_path, pubkey_path, NC_PUBKEY_FORMAT_SSH, &privkey,
            &privkey_type, &pubkey);
    if (ret) {
        goto cleanup;
    }

    /* get privkey identityref value */
    privkey_format = nc_server_config_util_privkey_format_to_identityref(privkey_type);
    if (!privkey_format) {
        ret = 1;
        goto cleanup;
    }

    ret = nc_server_config_append(ctx, tree_path, "inline-definition/public-key-format", pubkey_format, config);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_append(ctx, tree_path, "inline-definition/public-key", pubkey, config);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_append(ctx, tree_path, "inline-definition/private-key-format", privkey_format, config);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_append(ctx, tree_path, "inline-definition/cleartext-private-key", privkey, config);
    if (ret) {
        goto cleanup;
    }

    /* delete keystore choice nodes if present */
    ret = nc_server_config_check_delete(config, "%s/central-keystore-reference", tree_path);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(privkey);
    free(pubkey);
    return ret;
}

API int
nc_server_config_add_ssh_hostkey(const struct ly_ctx *ctx, const char *endpt_name, const char *hostkey_name,
        const char *privkey_path, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, hostkey_name, privkey_path, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/"
            "server-identity/host-key[name='%s']/public-key", endpt_name, hostkey_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_ssh_hostkey(ctx, path, privkey_path, pubkey_path, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_add_ch_ssh_hostkey(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *hostkey_name, const char *privkey_path, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, hostkey_name, privkey_path, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
            "host-key[name='%s']/public-key", client_name, endpt_name, hostkey_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_ssh_hostkey(ctx, path, privkey_path, pubkey_path, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_ssh_hostkey(const struct ly_ctx *ctx, const char *endpt_name, const char *hostkey_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, config, 1);

    if (hostkey_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/"
                "ssh/ssh-server-parameters/server-identity/host-key[name='%s']", endpt_name, hostkey_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/"
                "ssh/ssh-server-parameters/server-identity/host-key", endpt_name);
    }
}

API int
nc_server_config_del_ch_ssh_hostkey(const char *client_name, const char *endpt_name,
        const char *hostkey_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    if (hostkey_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
                "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
                "host-key[name='%s']", client_name, endpt_name, hostkey_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
                "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
                "host-key", client_name, endpt_name);
    }
}

API int
nc_server_config_add_ssh_keystore_ref(const struct ly_ctx *ctx, const char *endpt_name, const char *hostkey_name,
        const char *keystore_reference, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, hostkey_name, keystore_reference, config, 1);

    ret = nc_server_config_create(ctx, config, keystore_reference, "/ietf-netconf-server:netconf-server/listen/"
            "endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/host-key[name='%s']/public-key/"
            "central-keystore-reference", endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition nodes if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/listen/"
            "endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/host-key[name='%s']/public-key/"
            "inline-definition", endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_add_ch_ssh_keystore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *hostkey_name, const char *keystore_reference, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, hostkey_name, keystore_reference, config, 1);

    ret = nc_server_config_create(ctx, config, keystore_reference, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
            "host-key[name='%s']/public-key/central-keystore-reference", client_name, endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition nodes if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
            "host-key[name='%s']/public-key/inline-definition", client_name, endpt_name, hostkey_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_del_ssh_keystore_ref(const char *endpt_name, const char *hostkey_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/host-key[name='%s']/public-key/"
            "central-keystore-reference", endpt_name, hostkey_name);
}

API int
nc_server_config_del_ch_ssh_keystore_ref(const char *client_name, const char *endpt_name,
        const char *hostkey_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, hostkey_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/server-identity/"
            "host-key[name='%s']/public-key/central-keystore-reference", client_name, endpt_name, hostkey_name);
}

static int
_nc_server_config_add_ssh_user_pubkey(const struct ly_ctx *ctx, const char *tree_path, const char *pubkey_path,
        struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL;
    const char *pubkey_format = "ietf-crypto-types:ssh-public-key-format";

    /* get pubkey data */
    ret = nc_server_config_util_get_ssh_pubkey_file(pubkey_path, &pubkey);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_append(ctx, tree_path, "public-key-format", pubkey_format, config);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_append(ctx, tree_path, "public-key", pubkey, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(pubkey);
    return ret;
}

API int
nc_server_config_add_ssh_user_pubkey(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *pubkey_name, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, user_name, pubkey_name, pubkey_path, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/inline-definition/"
            "public-key[name='%s']", endpt_name, user_name, pubkey_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_ssh_user_pubkey(ctx, path, pubkey_path, config);
    if (ret) {
        goto cleanup;
    }

    /* delete truststore reference if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/central-truststore-reference",
            endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

    /* delete use system auth if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/"
            "libnetconf2-netconf-server:use-system-keys", endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_add_ch_ssh_user_pubkey(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *user_name, const char *pubkey_name, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, user_name, pubkey_name, pubkey_path, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/public-keys/inline-definition/public-key[name='%s']", client_name,
            endpt_name, user_name, pubkey_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_ssh_user_pubkey(ctx, path, pubkey_path, config);
    if (ret) {
        goto cleanup;
    }

    /* delete truststore reference if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']/"
            "public-keys/central-truststore-reference", client_name, endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

    /* delete use system auth if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/"
            "libnetconf2-netconf-server:use-system-keys", client_name, endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_ssh_user_pubkey(const char *endpt_name, const char *user_name,
        const char *pubkey_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, user_name, config, 1);

    if (pubkey_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
                "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/inline-definition/"
                "public-key[name='%s']", endpt_name, user_name, pubkey_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
                "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/inline-definition/"
                "public-key", endpt_name, user_name);
    }
}

API int
nc_server_config_del_ch_ssh_user_pubkey(const char *client_name, const char *endpt_name,
        const char *user_name, const char *pubkey_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, user_name, config, 1);

    if (pubkey_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
                "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
                "users/user[name='%s']/public-keys/inline-definition/public-key[name='%s']", client_name,
                endpt_name, user_name, pubkey_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
                "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
                "users/user[name='%s']/public-keys/inline-definition/public-key", client_name,
                endpt_name, user_name);
    }
}

API int
nc_server_config_add_ssh_user_authkey(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, user_name, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/"
            "client-authentication/users/user[name='%s']/public-keys", endpt_name, user_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = nc_server_config_append(ctx, path, "libnetconf2-netconf-server:use-system-keys", NULL, config);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition nodes if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/inline-definition",
            endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

    /* delete truststore reference if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/central-truststore-reference",
            endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_add_ch_ssh_user_authkey(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *user_name, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, user_name, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users"
            "/user[name='%s']/public-keys", client_name, endpt_name, user_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = nc_server_config_append(ctx, path, "libnetconf2-netconf-server:use-system-keys", NULL, config);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition nodes if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']/"
            "public-keys/inline-definition", client_name, endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

    /* delete truststore reference if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']/"
            "public-keys/central-truststore-reference", client_name, endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_ssh_user_authkey(const char *endpt_name, const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, user_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/"
            "public-keys/libnetconf2-netconf-server:use-system-keys", endpt_name, user_name);
}

API int
nc_server_config_ch_del_ssh_user_authkey(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, user_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']/"
            "public-keys/libnetconf2-netconf-server:use-system-keys", client_name, endpt_name, user_name);
}

static int
_nc_server_config_add_ssh_user_password(const struct ly_ctx *ctx, const char *tree_path,
        const char *password, struct lyd_node **config)
{
    int ret = 0;
    char *hashed_pw = NULL;
    const char *salt = "$6$idsizuippipk$";
    struct crypt_data cdata = {0};

    NC_CHECK_ARG_RET(NULL, ctx, tree_path, password, config, 1);

    hashed_pw = crypt_r(password, salt, &cdata);
    if (!hashed_pw) {
        ERR(NULL, "Hashing password failed (%s).", strerror(errno));
        ret = 1;
        goto cleanup;
    }

    ret = nc_server_config_append(ctx, tree_path, "password", hashed_pw, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_add_ssh_user_password(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *password, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, user_name, password, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/"
            "client-authentication/users/user[name='%s']", endpt_name, user_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_ssh_user_password(ctx, path, password, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_add_ch_ssh_user_password(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *user_name, const char *password, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, user_name, password, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']", client_name, endpt_name, user_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_ssh_user_password(ctx, path, password, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_ssh_user_password(const char *endpt_name, const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, user_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/password", endpt_name, user_name);
}

API int
nc_server_config_del_ch_ssh_user_password(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, user_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/password", client_name, endpt_name, user_name);
}

API int
nc_server_config_add_ssh_user_interactive(const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, user_name, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/"
            "client-authentication/users/user[name='%s']/libnetconf2-netconf-server:keyboard-interactive", endpt_name, user_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = nc_server_config_append(ctx, path, "use-system-auth", NULL, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_add_ch_ssh_user_interactive(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, user_name, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']/"
            "libnetconf2-netconf-server:keyboard-interactive", client_name, endpt_name, user_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = nc_server_config_append(ctx, path, "use-system-auth", NULL, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_ssh_user_interactive(const char *endpt_name, const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, user_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/"
            "libnetconf2-netconf-server:keyboard-interactive", endpt_name, user_name);
}

API int
nc_server_config_del_ch_ssh_user_interactive(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, user_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']/"
            "libnetconf2-netconf-server:keyboard-interactive", client_name, endpt_name, user_name);
}

API int
nc_server_config_del_ssh_user(const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (user_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
                "ssh-server-parameters/client-authentication/users/user[name='%s']", endpt_name, user_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
                "ssh-server-parameters/client-authentication/users/user", endpt_name);
    }
}

API int
nc_server_config_del_ch_ssh_user(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    if (user_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
                "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']", client_name,
                endpt_name, user_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
                "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user", client_name, endpt_name);
    }
}

API int
nc_server_config_add_ssh_endpoint_client_ref(const struct ly_ctx *ctx, const char *endpt_name,
        const char *referenced_endpt, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, referenced_endpt, config, 1);

    return nc_server_config_create(ctx, config, referenced_endpt, "/ietf-netconf-server:netconf-server/listen/endpoints/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/libnetconf2-netconf-server:endpoint-reference",
            endpt_name);
}

API int
nc_server_config_del_ssh_endpoint_client_ref(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/"
            "ssh/ssh-server-parameters/client-authentication/libnetconf2-netconf-server:endpoint-reference", endpt_name);
}

API int
nc_server_config_add_ssh_truststore_ref(const struct ly_ctx *ctx, const char *endpt_name, const char *user_name,
        const char *truststore_reference, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, user_name, truststore_reference, config, 1);

    ret = nc_server_config_create(ctx, config, truststore_reference, "/ietf-netconf-server:netconf-server/listen/"
            "endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/"
            "central-truststore-reference", endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition nodes if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/inline-definition",
            endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

    /* delete use system auth if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/"
            "libnetconf2-netconf-server:use-system-keys", endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_add_ch_ssh_truststore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *user_name, const char *truststore_reference, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, user_name, truststore_reference, config, 1);

    ret = nc_server_config_create(ctx, config, truststore_reference, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/public-keys/central-truststore-reference", client_name, endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition nodes if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']/"
            "public-keys/inline-definition", client_name, endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

    /* delete use system auth if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/"
            "libnetconf2-netconf-server:use-system-keys", client_name, endpt_name, user_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_del_ssh_truststore_ref(const char *endpt_name, const char *user_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, user_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/"
            "endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/users/user[name='%s']/public-keys/"
            "central-truststore-reference", endpt_name, user_name);
}

API int
nc_server_config_del_ch_ssh_truststore_ref(const char *client_name, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, user_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/ssh-server-parameters/client-authentication/"
            "users/user[name='%s']/public-keys/central-truststore-reference", client_name, endpt_name, user_name);
}
