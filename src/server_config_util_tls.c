/**
 * @file server_config_util_tls.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server TLS configuration utilities
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

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "server_config.h"
#include "session.h"
#include "session_p.h"

static int
_nc_server_config_add_tls_server_cert(const struct ly_ctx *ctx, const char *tree_path, const char *privkey_path,
        const char *pubkey_path, const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *privkey = NULL, *pubkey = NULL, *cert = NULL;
    NC_PRIVKEY_FORMAT privkey_type;
    const char *privkey_format, *pubkey_format = "ietf-crypto-types:subject-public-key-info-format";

    NC_CHECK_ARG_RET(NULL, ctx, tree_path, privkey_path, cert_path, config, 1);

    /* get the keys as a string from the given files */
    ret = nc_server_config_util_get_asym_key_pair(privkey_path, pubkey_path, NC_PUBKEY_FORMAT_X509, &privkey, &privkey_type, &pubkey);
    if (ret) {
        ERR(NULL, "Getting keys from file(s) failed.");
        goto cleanup;
    }

    /* get cert data from file */
    ret = nc_server_config_util_read_certificate(cert_path, &cert);
    if (ret) {
        ERR(NULL, "Getting certificate from file \"%s\" failed.", cert_path);
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

    ret = nc_server_config_append(ctx, tree_path, "inline-definition/cert-data", cert, config);
    if (ret) {
        goto cleanup;
    }

    /* delete keystore if present */
    ret = nc_server_config_check_delete(config, "%s/central-keystore-reference", tree_path);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(privkey);
    free(pubkey);
    free(cert);
    return ret;
}

API int
nc_server_config_add_tls_server_cert(const struct ly_ctx *ctx, const char *endpt_name, const char *privkey_path,
        const char *pubkey_path, const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, privkey_path, cert_path, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/"
            "tls/tls-server-parameters/server-identity/certificate", endpt_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_tls_server_cert(ctx, path, privkey_path, pubkey_path,
            cert_path, config);
    if (ret) {
        ERR(NULL, "Creating new TLS server certificate YANG data failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_tls_server_cert(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/"
            "tls/tls-server-parameters/server-identity/certificate/inline-definition", endpt_name);
}

API int
nc_server_config_add_ch_tls_server_cert(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *privkey_path, const char *pubkey_path, const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, privkey_path, cert_path, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/server-identity/"
            "certificate", client_name, endpt_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_tls_server_cert(ctx, path, privkey_path, pubkey_path,
            cert_path, config);
    if (ret) {
        ERR(NULL, "Creating new CH TLS server certificate YANG data failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_ch_tls_server_cert(const char *client_name, const char *endpt_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/server-identity/"
            "certificate/inline-definition", client_name, endpt_name);
}

static int
_nc_server_config_add_tls_keystore_ref(const struct ly_ctx *ctx, const char *tree_path, const char *asym_key_ref,
        const char *cert_ref, struct lyd_node **config)
{
    int ret = 0;

    /* create asymmetric key pair reference */
    ret = nc_server_config_append(ctx, tree_path, "central-keystore-reference/asymmetric-key", asym_key_ref, config);
    if (ret) {
        goto cleanup;
    }

    /* create cert reference, this cert has to belong to the asym key */
    ret = nc_server_config_append(ctx, tree_path, "central-keystore-reference/certificate", cert_ref, config);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition if present */
    ret = nc_server_config_check_delete(config, "%s/inline-definition", tree_path);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_add_tls_keystore_ref(const struct ly_ctx *ctx, const char *endpt_name, const char *asym_key_ref,
        const char *cert_ref, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, asym_key_ref, cert_ref, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/"
            "tls/tls-server-parameters/server-identity/certificate", endpt_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_tls_keystore_ref(ctx, path, asym_key_ref, cert_ref, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_tls_keystore_ref(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/"
            "tls/tls-server-parameters/server-identity/certificate/central-keystore-reference", endpt_name);
}

API int
nc_server_config_add_ch_tls_keystore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *asym_key_ref, const char *cert_ref, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, asym_key_ref, cert_ref, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
            "endpoint[name='%s']/tls/tls-server-parameters/server-identity/certificate", client_name, endpt_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_tls_keystore_ref(ctx, path, asym_key_ref, cert_ref, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_ch_tls_keystore_ref(const char *client_name, const char *endpt_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/server-identity/certificate/"
            "central-keystore-reference", client_name, endpt_name);
}

static int
_nc_server_config_add_tls_client_cert(const struct ly_ctx *ctx, const char *tree_path,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *cert = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, tree_path, cert_path, config, 1);

    ret = nc_server_config_util_read_certificate(cert_path, &cert);
    if (ret) {
        ERR(NULL, "Getting certificate from file \"%s\" failed.", cert_path);
        goto cleanup;
    }

    ret = nc_server_config_append(ctx, tree_path, "cert-data", cert, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(cert);
    return ret;
}

API int
nc_server_config_add_tls_client_cert(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_name, cert_path, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ee-certs/inline-definition/certificate[name='%s']", endpt_name, cert_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_tls_client_cert(ctx, path, cert_path, config);
    if (ret) {
        ERR(NULL, "Creating new TLS client certificate YANG data failed.");
        goto cleanup;
    }

    /* delete truststore if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/"
            "tls/tls-server-parameters/client-authentication/ee-certs/central-truststore-reference", endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_tls_client_cert(const char *endpt_name, const char *cert_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (cert_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
                "tls-server-parameters/client-authentication/ee-certs/inline-definition/"
                "certificate[name='%s']", endpt_name, cert_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
                "tls-server-parameters/client-authentication/ee-certs/inline-definition/"
                "certificate", endpt_name);
    }
}

API int
nc_server_config_add_ch_tls_client_cert(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *cert_name, const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, cert_name, cert_path, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ee-certs/"
            "inline-definition/certificate[name='%s']", client_name, endpt_name, cert_name) == -1;
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_tls_client_cert(ctx, path, cert_path, config);
    if (ret) {
        ERR(NULL, "Creating new CH TLS client certificate YANG data failed.");
        goto cleanup;
    }

    /* delete truststore if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ee-certs/central-truststore-reference", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_ch_tls_client_cert(const char *client_name, const char *endpt_name,
        const char *cert_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    if (cert_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ee-certs/"
                "inline-definition/certificate[name='%s']", client_name, endpt_name, cert_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ee-certs/"
                "inline-definition/certificate", client_name, endpt_name);
    }
}

API int
nc_server_config_add_tls_client_cert_truststore_ref(const struct ly_ctx *ctx, const char *endpt_name,
        const char *cert_bag_ref, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_bag_ref, config, 1);

    ret = nc_server_config_create(ctx, config, cert_bag_ref, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ee-certs/central-truststore-reference", endpt_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ee-certs/inline-definition", endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_del_tls_client_cert_truststore_ref(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ee-certs/central-truststore-reference", endpt_name);
}

API int
nc_server_config_add_ch_tls_client_cert_truststore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *cert_bag_ref, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, cert_bag_ref, config, 1);

    ret = nc_server_config_create(ctx, config, cert_bag_ref, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ee-certs/central-truststore-reference", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ee-certs/inline-definition", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_del_ch_tls_client_cert_truststore_ref(const char *client_name, const char *endpt_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ee-certs/central-truststore-reference", client_name, endpt_name);
}

API int
nc_server_config_add_tls_ca_cert(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_name, cert_path, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/inline-definition/certificate[name='%s']", endpt_name, cert_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_tls_client_cert(ctx, path, cert_path, config);
    if (ret) {
        ERR(NULL, "Creating new TLS client certificate authority YANG data failed.");
        goto cleanup;
    }

    /* delete truststore if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/"
            "tls/tls-server-parameters/client-authentication/ca-certs/central-truststore-reference", endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_tls_ca_cert(const char *endpt_name, const char *cert_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (cert_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
                "tls-server-parameters/client-authentication/ca-certs/inline-definition/"
                "certificate[name='%s']", endpt_name, cert_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
                "tls-server-parameters/client-authentication/ca-certs/inline-definition/"
                "certificate", endpt_name);
    }
}

API int
nc_server_config_add_ch_tls_ca_cert(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *cert_name, const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, cert_name, cert_path, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ca-certs/"
            "inline-definition/certificate[name='%s']", client_name, endpt_name, cert_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_tls_client_cert(ctx, path, cert_path, config);
    if (ret) {
        ERR(NULL, "Creating new CH TLS client certificate authority YANG data failed.");
        goto cleanup;
    }

    /* delete truststore if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/central-truststore-reference", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_ch_tls_ca_cert(const char *client_name, const char *endpt_name,
        const char *cert_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    if (cert_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ca-certs/"
                "inline-definition/certificate[name='%s']", client_name, endpt_name, cert_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ca-certs/"
                "inline-definition/certificate", client_name, endpt_name);
    }
}

API int
nc_server_config_add_tls_ca_cert_truststore_ref(const struct ly_ctx *ctx, const char *endpt_name,
        const char *cert_bag_ref, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_bag_ref, config, 1);

    ret = nc_server_config_create(ctx, config, cert_bag_ref, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ca-certs/central-truststore-reference", endpt_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ca-certs/inline-definition", endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_del_tls_ca_cert_truststore_ref(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ca-certs/central-truststore-reference", endpt_name);
}

API int
nc_server_config_add_ch_tls_ca_cert_truststore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *cert_bag_ref, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, cert_bag_ref, config, 1);

    ret = nc_server_config_create(ctx, config, cert_bag_ref, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/central-truststore-reference", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition if present */
    ret = nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/inline-definition", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_del_ch_tls_ca_cert_truststore_ref(const char *client_name, const char *endpt_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/central-truststore-reference", client_name, endpt_name);
}

static const char *
nc_server_config_tls_maptype2str(NC_TLS_CTN_MAPTYPE map_type)
{
    switch (map_type) {
    case NC_TLS_CTN_SPECIFIED:
        return "ietf-x509-cert-to-name:specified";
    case NC_TLS_CTN_SAN_RFC822_NAME:
        return "ietf-x509-cert-to-name:san-rfc822-name";
    case NC_TLS_CTN_SAN_DNS_NAME:
        return "ietf-x509-cert-to-name:san-dns-name";
    case NC_TLS_CTN_SAN_IP_ADDRESS:
        return "ietf-x509-cert-to-name:san-ip-address";
    case NC_TLS_CTN_SAN_ANY:
        return "ietf-x509-cert-to-name:san-any";
    case NC_TLS_CTN_COMMON_NAME:
        return "ietf-x509-cert-to-name:common-name";
    case NC_TLS_CTN_UNKNOWN:
    default:
        ERR(NULL, "Unknown CTN mapping type.");
        return NULL;
    }
}

static int
_nc_server_config_add_tls_ctn(const struct ly_ctx *ctx, const char *tree_path, const char *fingerprint,
        NC_TLS_CTN_MAPTYPE map_type, const char *name, struct lyd_node **config)
{
    int ret = 0;
    const char *map;

    NC_CHECK_ARG_RET(NULL, ctx, tree_path, name, config, 1);

    if (fingerprint) {
        /* optional */
        ret = nc_server_config_append(ctx, tree_path, "fingerprint", fingerprint, config);
        if (ret) {
            goto cleanup;
        }
    }

    /* get map str */
    map = nc_server_config_tls_maptype2str(map_type);
    if (!map) {
        ret = 1;
        goto cleanup;
    }

    ret = nc_server_config_append(ctx, tree_path, "map-type", map, config);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_append(ctx, tree_path, "name", name, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_add_tls_ctn(const struct ly_ctx *ctx, const char *endpt_name, uint32_t id, const char *fingerprint,
        NC_TLS_CTN_MAPTYPE map_type, const char *name, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, id, name, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/netconf-server-parameters/"
            "client-identity-mappings/cert-to-name[id='%" PRIu32 "']", endpt_name, id);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_tls_ctn(ctx, path, fingerprint, map_type, name, config);
    if (ret) {
        ERR(NULL, "Creating new TLS cert-to-name YANG data failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_tls_ctn(const char *endpt_name, uint32_t id, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (id) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
                "netconf-server-parameters/client-identity-mappings/cert-to-name[id='%" PRIu32 "']", endpt_name, id);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/"
                "netconf-server-parameters/client-identity-mappings/cert-to-name", endpt_name);
    }
}

API int
nc_server_config_add_ch_tls_ctn(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, id, name, config, 1);

    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/netconf-server-parameters/client-identity-mappings/"
            "cert-to-name[id='%" PRIu32 "']", client_name, endpt_name, id);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    ret = _nc_server_config_add_tls_ctn(ctx, path, fingerprint, map_type, name, config);
    if (ret) {
        ERR(NULL, "Creating new CH TLS cert-to-name YANG data failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_ch_tls_ctn(const char *client_name, const char *endpt_name,
        uint32_t id, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    if (id) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/netconf-server-parameters/client-identity-mappings/"
                "cert-to-name[id='%u']", client_name, endpt_name, id);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/netconf-server-parameters/client-identity-mappings/"
                "cert-to-name", client_name, endpt_name);
    }
}

API int
nc_server_config_add_tls_endpoint_client_ref(const struct ly_ctx *ctx, const char *endpt_name, const char *referenced_endpt, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, referenced_endpt, config, 1);

    return nc_server_config_create(ctx, config, referenced_endpt, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:endpoint-reference", endpt_name);
}

API int
nc_server_config_del_tls_endpoint_client_ref(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:endpoint-reference", endpt_name);
}
