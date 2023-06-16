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

API int
nc_server_config_new_tls_server_certificate(const struct ly_ctx *ctx, const char *endpt_name, const char *pubkey_path,
        const char *privkey_path, const char *certificate_path, struct lyd_node **config)
{
    int ret = 0;
    char *privkey = NULL, *pubkey = NULL, *cert = NULL;
    NC_PRIVKEY_FORMAT privkey_type;
    NC_PUBKEY_FORMAT pubkey_type;
    const char *privkey_format, *pubkey_format;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, privkey_path, certificate_path, 1);
    NC_CHECK_ARG_RET(NULL, config, 1);

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

    ret = nc_config_new_insert(ctx, config, pubkey_format, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
        "tls/tls-server-parameters/server-identity/certificate/inline-definition/public-key-format", endpt_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_insert(ctx, config, pubkey, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
        "tls/tls-server-parameters/server-identity/certificate/inline-definition/public-key", endpt_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_insert(ctx, config, privkey_format, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
        "tls/tls-server-parameters/server-identity/certificate/inline-definition/private-key-format", endpt_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_insert(ctx, config, privkey, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
        "tls/tls-server-parameters/server-identity/certificate/inline-definition/cleartext-private-key", endpt_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_insert(ctx, config, cert, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
        "tls/tls-server-parameters/server-identity/certificate/inline-definition/cert-data", endpt_name);
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
nc_server_config_new_tls_client_certificate(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *cert = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_name, cert_path, config, 1);

    ret = nc_server_config_new_read_certificate(cert_path, &cert);
    if (ret) {
        ERR(NULL, "Getting certificate from file \"%s\" failed.", cert_path);
        goto cleanup;
    }

    ret = nc_config_new_insert(ctx, config, cert, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ee-certs/inline-definition/certificate[name='%s']/cert-data", endpt_name, cert_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(cert);
    return ret;
}

API int
nc_server_config_new_tls_client_ca(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *cert = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_name, cert_path, config, 1);

    ret = nc_server_config_new_read_certificate(cert_path, &cert);
    if (ret) {
        ERR(NULL, "Getting certificate from file \"%s\" failed.", cert_path);
        goto cleanup;
    }

    ret = nc_config_new_insert(ctx, config, cert, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/inline-definition/certificate[name='%s']/cert-data", endpt_name, cert_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(cert);
    return ret;
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

API int
nc_server_config_new_tls_ctn(const struct ly_ctx *ctx, const char *endpt_name, uint32_t id, const char *fingerprint,
        NC_TLS_CTN_MAPTYPE map_type, const char *name, struct lyd_node **config)
{
    int ret = 0;
    const char *map;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, id, map_type, name, 1);
    NC_CHECK_ARG_RET(NULL, config, 1);

    if (fingerprint) {
        /* optional */
        ret = nc_config_new_insert(ctx, config, fingerprint, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
                "netconf-server-parameters/client-identity-mappings/cert-to-name[id='%d']/fingerprint", endpt_name, id);
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

    ret = nc_config_new_insert(ctx, config, map, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
                "netconf-server-parameters/client-identity-mappings/cert-to-name[id='%d']/map-type", endpt_name, id);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_insert(ctx, config, name, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
                "netconf-server-parameters/client-identity-mappings/cert-to-name[id='%d']/name", endpt_name, id);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
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

    ret = nc_config_new_insert(ctx, config, version, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "hello-params/tls-versions/tls-version", endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_tls_ciphers(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int cipher_count, ...)
{
    int ret = 0;
    struct lyd_node *old = NULL;
    va_list ap;
    char *cipher = NULL, *cipher_ident = NULL, *old_path = NULL;
    int i;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, config, 1);

    va_start(ap, cipher_count);

    ret = asprintf(&old_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
            "tls/tls-server-parameters/hello-params/cipher-suites", endpt_name);
    if (ret == -1) {
        ERRMEM;
        old_path = NULL;
        goto cleanup;
    }

    /* delete all older algorithms (if any) se they can be replaced by the new ones */
    ret = lyd_find_path(*config, old_path, 0, &old);
    if (!ret) {
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

        ret = nc_config_new_insert(ctx, config, cipher_ident, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/"
            "tls/tls-server-parameters/hello-params/cipher-suites/cipher-suite", endpt_name);
        if (ret) {
            goto cleanup;
        }

        free(cipher_ident);
        cipher_ident = NULL;
    }

cleanup:
    va_end(ap);
    free(old_path);
    return ret;
}

API int
nc_server_config_new_tls_crl_path(const struct ly_ctx *ctx, const char *endpt_name, const char *path, struct lyd_node **config)
{
    int ret = 0;
    struct lyd_node *node = NULL;
    char *url_path = NULL, *ext_path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, path, config, 1);

    ret = nc_config_new_insert(ctx, config, path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-path", endpt_name);
    if (ret) {
        goto cleanup;
    }

    if (asprintf(&url_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-url", endpt_name) == -1) {
        ERRMEM;
        url_path = NULL;
        ret = 1;
        goto cleanup;
    }

    if (asprintf(&ext_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-cert-ext", endpt_name) == -1) {
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
    /* don't care about the return values from lyd_find_path */
    ret = 0;

cleanup:
    free(url_path);
    free(ext_path);
    return ret;
}

API int
nc_server_config_new_tls_crl_url(const struct ly_ctx *ctx, const char *endpt_name, const char *url, struct lyd_node **config)
{
    int ret = 0;
    struct lyd_node *node = NULL;
    char *crl_path = NULL, *ext_path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, url, config, 1);

    ret = nc_config_new_insert(ctx, config, url, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-url", endpt_name);
    if (ret) {
        goto cleanup;
    }

    if (asprintf(&crl_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-path", endpt_name) == -1) {
        ERRMEM;
        crl_path = NULL;
        ret = 1;
        goto cleanup;
    }

    if (asprintf(&ext_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-cert-ext", endpt_name) == -1) {
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
    /* don't care about the return values from lyd_find_path */
    ret = 0;

cleanup:
    free(crl_path);
    free(ext_path);
    return ret;
}

API int
nc_server_config_new_tls_crl_cert_ext(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config)
{
    int ret = 0;
    struct lyd_node *node = NULL;
    char *crl_path = NULL, *url_path = NULL;

    ret = nc_config_new_insert(ctx, config, NULL, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-cert-ext", endpt_name);
    if (ret) {
        goto cleanup;
    }

    if (asprintf(&crl_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-path", endpt_name) == -1) {
        ERRMEM;
        crl_path = NULL;
        ret = 1;
        goto cleanup;
    }

    if (asprintf(&url_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/libnetconf2-netconf-server:crl-url", endpt_name) == -1) {
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
    /* don't care about the return values from lyd_find_path */
    ret = 0;

cleanup:
    free(crl_path);
    free(url_path);
    return ret;
}
