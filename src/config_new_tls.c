/**
 * @file config_new_tls.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 TLS server new configuration creation functions
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

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "config_new.h"
#include "log_p.h"
#include "server_config.h"
#include "session.h"
#include "session_p.h"

static int
_nc_server_config_new_tls_server_certificate(const struct ly_ctx *ctx, const char *tree_path, const char *pubkey_path,
        const char *privkey_path, const char *certificate_path, struct lyd_node **config)
{
    int ret = 0;
    char *privkey = NULL, *pubkey = NULL, *cert = NULL;
    NC_PRIVKEY_FORMAT privkey_type;
    NC_PUBKEY_FORMAT pubkey_type;
    const char *privkey_format, *pubkey_format;

    /* get the keys as a string from the given files */
    ret = nc_server_config_new_get_keys(privkey_path, pubkey_path, &privkey, &pubkey, &privkey_type, &pubkey_type);
    if (ret) {
        ERR(NULL, "Getting keys from file(s) failed.");
        goto cleanup;
    }

    /* get cert data from file */
    ret = nc_server_config_new_read_certificate(certificate_path, &cert);
    if (ret) {
        ERR(NULL, "Getting certificate from file \"%s\" failed.", certificate_path);
        goto cleanup;
    }

    /* get pubkey format str */
    if (pubkey_type == NC_PUBKEY_FORMAT_X509) {
        pubkey_format = "ietf-crypto-types:public-key-info-format";
    } else {
        pubkey_format = "ietf-crypto-types:ssh-public-key-format";
    }

    /* get privkey identityref value */
    privkey_format = nc_config_new_privkey_format_to_identityref(privkey_type);
    if (!privkey_format) {
        ret = 1;
        goto cleanup;
    }

    ret = nc_config_new_create_append(ctx, tree_path, "inline-definition/public-key-format", pubkey_format, config);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create_append(ctx, tree_path, "inline-definition/public-key", pubkey, config);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create_append(ctx, tree_path, "inline-definition/private-key-format", privkey_format, config);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create_append(ctx, tree_path, "inline-definition/cleartext-private-key", privkey, config);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create_append(ctx, tree_path, "inline-definition/cert-data", cert, config);
    if (ret) {
        goto cleanup;
    }

    /* delete keystore if present */
    ret = nc_config_new_check_delete(config, "%s/keystore-reference", tree_path);
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
nc_server_config_new_tls_server_certificate(const struct ly_ctx *ctx, const char *endpt_name, const char *pubkey_path,
        const char *privkey_path, const char *certificate_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, privkey_path, certificate_path, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
            "tls/tls-server-parameters/server-identity/certificate", endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_server_certificate(ctx, path, pubkey_path, privkey_path,
            certificate_path, config);
    if (ret) {
        ERR(NULL, "Creating new TLS server certificate YANG data failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_tls_del_server_certificate(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
            "tls/tls-server-parameters/server-identity/certificate/inline-definition", endpt_name);
}

API int
nc_server_config_new_ch_tls_server_certificate(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *pubkey_path, const char *privkey_path, const char *certificate_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, privkey_path, certificate_path, 1);
    NC_CHECK_ARG_RET(NULL, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/server-identity/"
            "certificate", client_name, endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_server_certificate(ctx, path, pubkey_path, privkey_path,
            certificate_path, config);
    if (ret) {
        ERR(NULL, "Creating new CH TLS server certificate YANG data failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_ch_tls_del_server_certificate(const char *client_name, const char *endpt_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/server-identity/"
            "certificate/inline-definition", client_name, endpt_name);
}

static int
_nc_server_config_new_tls_keystore_reference(const struct ly_ctx *ctx, const char *tree_path, const char *asym_key_ref,
        const char *cert_ref, struct lyd_node **config)
{
    int ret = 0;

    /* create asymmetric key pair reference */
    ret = nc_config_new_create_append(ctx, tree_path, "keystore-reference/asymmetric-key", asym_key_ref, config);
    if (ret) {
        goto cleanup;
    }

    /* create cert reference, this cert has to belong to the asym key */
    ret = nc_config_new_create_append(ctx, tree_path, "keystore-reference/certificate", cert_ref, config);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition if present */
    ret = nc_config_new_check_delete(config, "%s/inline-definition", tree_path);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_tls_keystore_reference(const struct ly_ctx *ctx, const char *endpt_name, const char *asym_key_ref,
        const char *cert_ref, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, asym_key_ref, cert_ref, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
            "tls/tls-server-parameters/server-identity/certificate", endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_keystore_reference(ctx, path, asym_key_ref, cert_ref, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_tls_del_keystore_reference(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
            "tls/tls-server-parameters/server-identity/certificate/keystore-reference", endpt_name);
}

API int
nc_server_config_new_ch_tls_keystore_reference(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *asym_key_ref, const char *cert_ref, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, asym_key_ref, cert_ref, 1);
    NC_CHECK_ARG_RET(NULL, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
            "endpoint[name='%s']/tls/tls-server-parameters/server-identity/certificate", client_name, endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_keystore_reference(ctx, path, asym_key_ref, cert_ref, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_ch_tls_del_keystore_reference(const char *client_name, const char *endpt_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/server-identity/certificate/"
            "keystore-reference", client_name, endpt_name);
}

static int
_nc_server_config_new_tls_client_certificate(const struct ly_ctx *ctx, const char *tree_path,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *cert = NULL;

    ret = nc_server_config_new_read_certificate(cert_path, &cert);
    if (ret) {
        ERR(NULL, "Getting certificate from file \"%s\" failed.", cert_path);
        goto cleanup;
    }

    ret = nc_config_new_create_append(ctx, tree_path, "cert-data", cert, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(cert);
    return ret;
}

API int
nc_server_config_new_tls_client_certificate(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_name, cert_path, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ee-certs/inline-definition/certificate[name='%s']", endpt_name, cert_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_client_certificate(ctx, path, cert_path, config);
    if (ret) {
        ERR(NULL, "Creating new TLS client certificate YANG data failed.");
        goto cleanup;
    }

    /* delete truststore if present */
    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ee-certs/truststore-reference", endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_tls_del_client_certificate(const char *endpt_name, const char *cert_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (cert_name) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
                "tls-server-parameters/client-authentication/ee-certs/inline-definition/"
                "certificate[name='%s']", endpt_name, cert_name);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
                "tls-server-parameters/client-authentication/ee-certs/inline-definition/"
                "certificate", endpt_name);
    }
}

API int
nc_server_config_new_ch_tls_client_certificate(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *cert_name, const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, cert_name, cert_path, 1);
    NC_CHECK_ARG_RET(NULL, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ee-certs/"
            "inline-definition/certificate[name='%s']", client_name, endpt_name, cert_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_client_certificate(ctx, path, cert_path, config);
    if (ret) {
        ERR(NULL, "Creating new CH TLS client certificate YANG data failed.");
        goto cleanup;
    }

    /* delete truststore if present */
    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ee-certs/truststore-reference", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_ch_tls_del_client_certificate(const char *client_name, const char *endpt_name,
        const char *cert_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    if (cert_name) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ee-certs/"
                "inline-definition/certificate[name='%s']", client_name, endpt_name, cert_name);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ee-certs/"
                "inline-definition/certificate", client_name, endpt_name);
    }
}

API int
nc_server_config_new_tls_client_cert_truststore_ref(const struct ly_ctx *ctx, const char *endpt_name,
        const char *cert_bag_ref, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_bag_ref, config, 1);

    ret = nc_config_new_create(ctx, config, cert_bag_ref, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ee-certs/truststore-reference", endpt_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition if present */
    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ee-certs/inline-definition", endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_tls_del_client_cert_truststore_ref(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ee-certs/truststore-reference", endpt_name);
}

API int
nc_server_config_new_ch_tls_client_cert_truststore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *cert_bag_ref, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, cert_bag_ref, config, 1);

    ret = nc_config_new_create(ctx, config, cert_bag_ref, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ee-certs/truststore-reference", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition if present */
    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ee-certs/inline-definition", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_ch_tls_del_client_cert_truststore_ref(const char *client_name, const char *endpt_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ee-certs/truststore-reference", client_name, endpt_name);
}

API int
nc_server_config_new_tls_client_ca(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_name, cert_path, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/inline-definition/certificate[name='%s']", endpt_name, cert_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_client_certificate(ctx, path, cert_path, config);
    if (ret) {
        ERR(NULL, "Creating new TLS client certificate authority YANG data failed.");
        goto cleanup;
    }

    /* delete truststore if present */
    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/truststore-reference", endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_tls_del_client_ca(const char *endpt_name, const char *cert_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (cert_name) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
                "tls-server-parameters/client-authentication/ca-certs/inline-definition/"
                "certificate[name='%s']", endpt_name, cert_name);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
                "tls-server-parameters/client-authentication/ca-certs/inline-definition/"
                "certificate", endpt_name);
    }
}

API int
nc_server_config_new_ch_tls_client_ca(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *cert_name, const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, cert_name, cert_path, 1);
    NC_CHECK_ARG_RET(NULL, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ca-certs/"
            "inline-definition/certificate[name='%s']", client_name, endpt_name, cert_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_client_certificate(ctx, path, cert_path, config);
    if (ret) {
        ERR(NULL, "Creating new CH TLS client certificate authority YANG data failed.");
        goto cleanup;
    }

    /* delete truststore if present */
    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/truststore-reference", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_ch_tls_del_client_ca(const char *client_name, const char *endpt_name,
        const char *cert_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    if (cert_name) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ca-certs/"
                "inline-definition/certificate[name='%s']", client_name, endpt_name, cert_name);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/tls-server-parameters/client-authentication/ca-certs/"
                "inline-definition/certificate", client_name, endpt_name);
    }
}

API int
nc_server_config_new_tls_client_ca_truststore_ref(const struct ly_ctx *ctx, const char *endpt_name,
        const char *cert_bag_ref, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_bag_ref, config, 1);

    ret = nc_config_new_create(ctx, config, cert_bag_ref, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ca-certs/truststore-reference", endpt_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition if present */
    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ca-certs/inline-definition", endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_tls_del_client_ca_truststore_ref(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
            "tls-server-parameters/client-authentication/ca-certs/truststore-reference", endpt_name);
}

API int
nc_server_config_new_ch_tls_client_ca_truststore_ref(const struct ly_ctx *ctx, const char *client_name,
        const char *endpt_name, const char *cert_bag_ref, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, cert_bag_ref, config, 1);

    ret = nc_config_new_create(ctx, config, cert_bag_ref, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/truststore-reference", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

    /* delete inline definition if present */
    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/inline-definition", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_ch_tls_del_client_ca_truststore_ref(const char *client_name, const char *endpt_name,
        struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/truststore-reference", client_name, endpt_name);
}

static const char *
nc_config_new_tls_maptype2str(NC_TLS_CTN_MAPTYPE map_type)
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
        ERR(NULL, "Unknown map_type.");
        return NULL;
    }
}

static int
_nc_server_config_new_tls_ctn(const struct ly_ctx *ctx, const char *tree_path, const char *fingerprint,
        NC_TLS_CTN_MAPTYPE map_type, const char *name, struct lyd_node **config)
{
    int ret = 0;
    const char *map;

    if (fingerprint) {
        /* optional */
        ret = nc_config_new_create_append(ctx, tree_path, "fingerprint", fingerprint, config);
        if (ret) {
            goto cleanup;
        }
    }

    /* get map str */
    map = nc_config_new_tls_maptype2str(map_type);
    if (!map) {
        ret = 1;
        goto cleanup;
    }

    ret = nc_config_new_create_append(ctx, tree_path, "map-type", map, config);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create_append(ctx, tree_path, "name", name, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_tls_ctn(const struct ly_ctx *ctx, const char *endpt_name, uint32_t id, const char *fingerprint,
        NC_TLS_CTN_MAPTYPE map_type, const char *name, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, id, name, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/netconf-server-parameters/"
            "client-identity-mappings/cert-to-name[id='%u']", endpt_name, id) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_ctn(ctx, path, fingerprint, map_type, name, config);
    if (ret) {
        ERR(NULL, "Creating new TLS cert-to-name YANG data failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_tls_del_ctn(const char *endpt_name, uint32_t id, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    if (id) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
                "netconf-server-parameters/client-identity-mappings/cert-to-name[id='%u']", endpt_name, id);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
                "netconf-server-parameters/client-identity-mappings/cert-to-name", endpt_name);
    }
}

API int
nc_server_config_new_ch_tls_ctn(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, id, name, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/netconf-server-parameters/client-identity-mappings/"
            "cert-to-name[id='%u']", client_name, endpt_name, id) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_ctn(ctx, path, fingerprint, map_type, name, config);
    if (ret) {
        ERR(NULL, "Creating new TLS cert-to-name YANG data failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_ch_tls_del_ctn(const char *client_name, const char *endpt_name,
        uint32_t id, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    if (id) {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/netconf-server-parameters/client-identity-mappings/"
                "cert-to-name[id='%u']", client_name, endpt_name, id);
    } else {
        return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']/tls/netconf-server-parameters/client-identity-mappings/"
                "cert-to-name", client_name, endpt_name);
    }
}

static const char *
nc_config_new_tls_tlsversion2str(NC_TLS_VERSION version)
{
    switch (version) {
    case NC_TLS_VERSION_10:
        return "ietf-tls-common:tls10";
    case NC_TLS_VERSION_11:
        return "ietf-tls-common:tls11";
    case NC_TLS_VERSION_12:
        return "ietf-tls-common:tls12";
    case NC_TLS_VERSION_13:
        return "ietf-tls-common:tls13";
    default:
        ERR(NULL, "Unknown TLS version.");
        return NULL;
    }
}

API int
nc_server_config_new_tls_version(const struct ly_ctx *ctx, const char *endpt_name,
        NC_TLS_VERSION tls_version, struct lyd_node **config)
{
    int ret = 0;
    const char *version;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, config, 1);

    version = nc_config_new_tls_tlsversion2str(tls_version);
    if (!version) {
        ret = 1;
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, version, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "hello-params/tls-versions/tls-version", endpt_name);
    if (ret) {
        ERR(NULL, "Creating new YANG data nodes for TLS version failed.");
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_ch_tls_version(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        NC_TLS_VERSION tls_version, struct lyd_node **config)
{
    int ret = 0;
    const char *version;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, config, 1);

    version = nc_config_new_tls_tlsversion2str(tls_version);
    if (!version) {
        ret = 1;
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, version, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "hello-params/tls-versions/tls-version", client_name, endpt_name);
    if (ret) {
        ERR(NULL, "Creating new YANG data nodes for Call-Home TLS version failed.");
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_tls_del_version(const char *endpt_name, NC_TLS_VERSION tls_version, struct lyd_node **config)
{
    int ret = 0;
    const char *version;

    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    version = nc_config_new_tls_tlsversion2str(tls_version);
    if (!version) {
        ret = 1;
        goto cleanup;
    }

    ret = nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
            "tls-server-parameters/hello-params/tls-versions/tls-version[.='%s']", endpt_name, version);

cleanup:
    return ret;
}

API int
nc_server_config_new_ch_tls_del_version(const char *client_name, const char *endpt_name,
        NC_TLS_VERSION tls_version, struct lyd_node **config)
{
    int ret = 0;
    const char *version;

    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    version = nc_config_new_tls_tlsversion2str(tls_version);
    if (!version) {
        ret = 1;
        goto cleanup;
    }

    ret = nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/"
            "tls-server-parameters/hello-params/tls-versions/tls-version[.='%s']", client_name, endpt_name, version);

cleanup:
    return ret;
}

static int
_nc_server_config_new_tls_ciphers(const struct ly_ctx *ctx, const char *tree_path,
        int cipher_count, va_list ap, struct lyd_node **config)
{
    int ret = 0, i;
    struct lyd_node *old = NULL;
    char *cipher = NULL, *cipher_ident = NULL;

    /* delete all older algorithms (if any) se they can be replaced by the new ones */
    lyd_find_path(*config, tree_path, 0, &old);
    if (old) {
        lyd_free_tree(old);
    }

    for (i = 0; i < cipher_count; i++) {
        cipher = va_arg(ap, char *);

        ret = asprintf(&cipher_ident, "iana-tls-cipher-suite-algs:%s", cipher);
        if (ret == -1) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }

        ret = nc_config_new_create_append(ctx, tree_path, "cipher-suite", cipher_ident, config);
        if (ret) {
            goto cleanup;
        }

        free(cipher_ident);
        cipher_ident = NULL;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_tls_ciphers(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int cipher_count, ...)
{
    int ret = 0;
    va_list ap;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cipher_count, config, 1);

    va_start(ap, cipher_count);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
            "tls-server-parameters/hello-params/cipher-suites", endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_ciphers(ctx, path, cipher_count, ap, config);
    if (ret) {
        ERR(NULL, "Creating new TLS cipher YANG data nodes failed.");
    }

cleanup:
    va_end(ap);
    free(path);
    return ret;
}

API int
nc_server_config_new_ch_tls_ciphers(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        struct lyd_node **config, int cipher_count, ...)
{
    int ret = 0;
    va_list ap;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, cipher_count, config, 1);

    va_start(ap, cipher_count);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
            "endpoint[name='%s']/tls/tls-server-parameters/hello-params/cipher-suites", client_name, endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_ciphers(ctx, path, cipher_count, ap, config);
    if (ret) {
        ERR(NULL, "Creating new Call-Home TLS cipher YANG data nodes failed.");
    }

cleanup:
    va_end(ap);
    free(path);
    return ret;
}

API int
nc_server_config_new_tls_del_cipher(const char *endpt_name, const char *cipher, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, cipher, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
            "tls/tls-server-parameters/hello-params/cipher-suites/"
            "cipher-suite[.='iana-tls-cipher-suite-algs:%s']", endpt_name, cipher);
}

API int
nc_server_config_new_ch_tls_del_cipher(const char *client_name, const char *endpt_name,
        const char *cipher, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, cipher, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/hello-params/cipher-suites/"
            "cipher-suite[.='iana-tls-cipher-suite-algs:%s']", client_name, endpt_name, cipher);
}

static int
_nc_server_config_new_tls_crl_path(const struct ly_ctx *ctx, const char *tree_path,
        const char *crl_path, struct lyd_node **config)
{
    int ret = 0;
    struct lyd_node *node = NULL;
    char *url_path = NULL, *ext_path = NULL;

    if (asprintf(&url_path, "%s/libnetconf2-netconf-server:crl-url", tree_path) == -1) {
        ERRMEM;
        url_path = NULL;
        ret = 1;
        goto cleanup;
    }

    if (asprintf(&ext_path, "%s/libnetconf2-netconf-server:crl-cert-ext", tree_path) == -1) {
        ERRMEM;
        ext_path = NULL;
        ret = 1;
        goto cleanup;
    }

    /* delete other choice nodes if they are present */
    ret = lyd_find_path(*config, url_path, 0, &node);
    if (!ret) {
        lyd_free_tree(node);
    }
    ret = lyd_find_path(*config, ext_path, 0, &node);
    if (!ret) {
        lyd_free_tree(node);
    }

    /* create the crl path node */
    ret = nc_config_new_create_append(ctx, tree_path, "libnetconf2-netconf-server:crl-path", crl_path, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(url_path);
    free(ext_path);
    return ret;
}

API int
nc_server_config_new_tls_crl_path(const struct ly_ctx *ctx, const char *endpt_name,
        const char *crl_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, crl_path, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication", endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_crl_path(ctx, path, crl_path, config);
    if (ret) {
        ERR(NULL, "Creating new CRL YANG data nodes failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_ch_tls_crl_path(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *crl_path, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, crl_path, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication", client_name, endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_crl_path(ctx, path, crl_path, config);
    if (ret) {
        ERR(NULL, "Creating new Call-Home CRL YANG data nodes failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

static int
_nc_server_config_new_tls_crl_url(const struct ly_ctx *ctx, const char *tree_path,
        const char *crl_url, struct lyd_node **config)
{
    int ret = 0;
    struct lyd_node *node = NULL;
    char *crl_path = NULL, *ext_path = NULL;

    if (asprintf(&crl_path, "%s/libnetconf2-netconf-server:crl-path", tree_path) == -1) {
        ERRMEM;
        crl_path = NULL;
        ret = 1;
        goto cleanup;
    }

    if (asprintf(&ext_path, "%s/libnetconf2-netconf-server:crl-cert-ext", tree_path) == -1) {
        ERRMEM;
        ext_path = NULL;
        ret = 1;
        goto cleanup;
    }

    /* delete other choice nodes if they are present */
    ret = lyd_find_path(*config, crl_path, 0, &node);
    if (!ret) {
        lyd_free_tree(node);
    }
    ret = lyd_find_path(*config, ext_path, 0, &node);
    if (!ret) {
        lyd_free_tree(node);
    }

    /* create the crl path node */
    ret = nc_config_new_create_append(ctx, tree_path, "libnetconf2-netconf-server:crl-url", crl_url, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(crl_path);
    free(ext_path);
    return ret;
}

API int
nc_server_config_new_tls_crl_url(const struct ly_ctx *ctx, const char *endpt_name, const char *crl_url, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, crl_url, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication", endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_crl_url(ctx, path, crl_url, config);
    if (ret) {
        ERR(NULL, "Creating new CRL YANG data nodes failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_ch_tls_crl_url(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        const char *crl_url, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, crl_url, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication", client_name, endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_crl_url(ctx, path, crl_url, config);
    if (ret) {
        ERR(NULL, "Creating new Call-Home CRL YANG data nodes failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

static int
_nc_server_config_new_tls_crl_cert_ext(const struct ly_ctx *ctx, const char *tree_path, struct lyd_node **config)
{
    int ret = 0;
    struct lyd_node *node = NULL;
    char *crl_path = NULL, *url_path = NULL;

    if (asprintf(&crl_path, "%s/libnetconf2-netconf-server:crl-path", tree_path) == -1) {
        ERRMEM;
        crl_path = NULL;
        ret = 1;
        goto cleanup;
    }

    if (asprintf(&url_path, "%s/libnetconf2-netconf-server:crl-url", tree_path) == -1) {
        ERRMEM;
        url_path = NULL;
        ret = 1;
        goto cleanup;
    }

    /* delete other choice nodes if they are present */
    ret = lyd_find_path(*config, crl_path, 0, &node);
    if (!ret) {
        lyd_free_tree(node);
    }
    ret = lyd_find_path(*config, url_path, 0, &node);
    if (!ret) {
        lyd_free_tree(node);
    }

    /* create the crl path node */
    ret = nc_config_new_create_append(ctx, tree_path, "libnetconf2-netconf-server:crl-cert-ext", NULL, config);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(crl_path);
    free(url_path);
    return ret;
}

API int
nc_server_config_new_tls_crl_cert_ext(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication", endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_crl_cert_ext(ctx, path, config);
    if (ret) {
        ERR(NULL, "Creating new CRL YANG data nodes failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_ch_tls_crl_cert_ext(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, config, 1);

    if (asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication", client_name, endpt_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    ret = _nc_server_config_new_tls_crl_cert_ext(ctx, path, config);
    if (ret) {
        ERR(NULL, "Creating new Call-Home CRL YANG data nodes failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_new_tls_del_crl(const char *endpt_name, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-path", endpt_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-url", endpt_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-cert-ext", endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_ch_tls_del_crl(const char *client_name, const char *endpt_name, struct lyd_node **config)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, client_name, endpt_name, config, 1);

    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-path", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-url", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
            "endpoints/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-cert-ext", client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_config_new_tls_endpoint_client_reference(const struct ly_ctx *ctx, const char *endpt_name, const char *referenced_endpt, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, referenced_endpt, config, 1);

    return nc_config_new_create(ctx, config, referenced_endpt, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:endpoint-client-auth", endpt_name);
}

API int
nc_config_new_tls_del_endpoint_client_reference(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, endpt_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:endpoint-client-auth", endpt_name);
}
