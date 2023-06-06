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
nc_server_config_new_tls_ctn(const struct ly_ctx *ctx, const char *endpt_name, uint32_t id, const char *fingerprint,
        NC_TLS_CTN_MAPTYPE map_type, const char *name, struct lyd_node **config)
{
    int ret = 0;
    char *tree_path = NULL;
    struct lyd_node *new_tree;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, id, map_type, name, 1);
    NC_CHECK_ARG_RET(NULL, config, 1);

    /* prepare path for instertion of leaves later */
    asprintf(&tree_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/"
            "netconf-server-parameters/client-identity-mappings/cert-to-name[id='%d']", endpt_name, id);
    if (!tree_path) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* create all the nodes in the path */
    ret = lyd_new_path(*config, ctx, tree_path, NULL, LYD_NEW_PATH_UPDATE, &new_tree);
    if (ret) {
        goto cleanup;
    }
    if (!*config) {
        *config = new_tree;
    }

    if (!new_tree) {
        /* no new nodes were created */
        ret = lyd_find_path(*config, tree_path, 0, &new_tree);
    } else {
        /* config was NULL */
        ret = lyd_find_path(new_tree, tree_path, 0, &new_tree);
    }
    if (ret) {
        ERR(NULL, "Unable to find netconf-server-parameters container.");
        goto cleanup;
    }

    /* not mandatory */
    if (fingerprint) {
        ret = lyd_new_term(new_tree, NULL, "fingerprint", fingerprint, 0, NULL);
        if (ret) {
            goto cleanup;
        }
    }

    /* insert map-type */
    switch (map_type) {
    case NC_TLS_CTN_SPECIFIED:
        ret = lyd_new_term(new_tree, NULL, "map-type", "ietf-x509-cert-to-name:specified", 0, NULL);
        break;
    case NC_TLS_CTN_SAN_RFC822_NAME:
        ret = lyd_new_term(new_tree, NULL, "map-type", "ietf-x509-cert-to-name:san-rfc822-name", 0, NULL);
        break;
    case NC_TLS_CTN_SAN_DNS_NAME:
        ret = lyd_new_term(new_tree, NULL, "map-type", "ietf-x509-cert-to-name:san-dns-name", 0, NULL);
        break;
    case NC_TLS_CTN_SAN_IP_ADDRESS:
        ret = lyd_new_term(new_tree, NULL, "map-type", "ietf-x509-cert-to-name:san-ip-address", 0, NULL);
        break;
    case NC_TLS_CTN_SAN_ANY:
        ret = lyd_new_term(new_tree, NULL, "map-type", "ietf-x509-cert-to-name:san-any", 0, NULL);
        break;
    case NC_TLS_CTN_COMMON_NAME:
        ret = lyd_new_term(new_tree, NULL, "map-type", "ietf-x509-cert-to-name:common-name", 0, NULL);
        break;
    case NC_TLS_CTN_UNKNOWN:
    default:
        ERR(NULL, "Unknown map_type.");
        ret = 1;
        break;
    }
    if (ret) {
        goto cleanup;
    }

    /* insert name */
    ret = lyd_new_term(new_tree, NULL, "name", name, 0, NULL);
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
nc_server_config_new_tls_server_certificate(const struct ly_ctx *ctx, const char *endpt_name, const char *pubkey_path,
        const char *privkey_path, const char *certificate_path, struct lyd_node **config)
{
    int ret = 0;
    char *tree_path = NULL, *privkey = NULL, *pubkey = NULL, *pubkey_stripped = NULL, *privkey_stripped, *cert = NULL;
    struct lyd_node *new_tree;
    NC_PRIVKEY_FORMAT privkey_type;
    NC_PUBKEY_FORMAT pubkey_type;
    const char *privkey_identity;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, privkey_path, certificate_path, 1);
    NC_CHECK_ARG_RET(NULL, config, 1);

    /* get the keys as a string from the given files */
    ret = nc_server_config_new_get_keys(privkey_path, pubkey_path, &privkey, &pubkey, &privkey_type, &pubkey_type);
    if (ret) {
        ERR(NULL, "Getting keys from file(s) failed.");
        goto cleanup;
    }

    ret = nc_server_config_new_read_certificate(certificate_path, &cert);
    if (ret) {
        ERR(NULL, "Getting certificate from file \"%s\" failed.", certificate_path);
        goto cleanup;
    }

    /* prepare path for instertion of leaves later */
    asprintf(&tree_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/server-identity/certificate/inline-definition", endpt_name);
    if (!tree_path) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* create all the nodes in the path */
    ret = lyd_new_path(*config, ctx, tree_path, NULL, LYD_NEW_PATH_UPDATE, &new_tree);
    if (ret) {
        goto cleanup;
    }
    if (!*config) {
        *config = new_tree;
    }

    if (!new_tree) {
        /* no new nodes were created */
        ret = lyd_find_path(*config, tree_path, 0, &new_tree);
    } else {
        /* config was NULL */
        ret = lyd_find_path(new_tree, tree_path, 0, &new_tree);
    }
    if (ret) {
        ERR(NULL, "Unable to find inline-definition container.");
        goto cleanup;
    }

    /* insert pubkey format */
    if (pubkey_type == NC_PUBKEY_FORMAT_X509) {
        ret = lyd_new_term(new_tree, NULL, "public-key-format", "ietf-crypto-types:public-key-info-format", 0, NULL);
    } else {
        ret = lyd_new_term(new_tree, NULL, "public-key-format", "ietf-crypto-types:ssh-public-key-format", 0, NULL);
    }
    if (ret) {
        goto cleanup;
    }

    /* strip pubkey's header and footer only if it's generated from pkcs8 key (using OpenSSL),
     * otherwise it's already stripped
     */
    if (!pubkey_path && (privkey_type == NC_PRIVKEY_FORMAT_X509)) {
        pubkey_stripped = pubkey + strlen("-----BEGIN PUBLIC KEY-----") + 1;
        pubkey_stripped[strlen(pubkey_stripped) - strlen("-----END PUBLIC KEY-----") - 2] = '\0';
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

    ret = lyd_new_term(new_tree, NULL, "cert-data", cert, 0, NULL);
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
    free(cert);
    free(tree_path);
    return ret;
}

API int
nc_server_config_new_tls_client_certificate(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    struct lyd_node *new_tree;
    char *tree_path = NULL, *cert = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_name, cert_path, config, 1);

    ret = nc_server_config_new_read_certificate(cert_path, &cert);
    if (ret) {
        ERR(NULL, "Getting certificate from file \"%s\" failed.", cert_path);
        goto cleanup;
    }

    /* prepare path for instertion of leaves later */
    asprintf(&tree_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ee-certs/inline-definition/certificate[name='%s']", endpt_name, cert_name);
    if (!tree_path) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* create all the nodes in the path */
    ret = lyd_new_path(*config, ctx, tree_path, NULL, LYD_NEW_PATH_UPDATE, &new_tree);
    if (ret) {
        goto cleanup;
    }
    if (!*config) {
        *config = new_tree;
    }

    if (!new_tree) {
        /* no new nodes were created */
        ret = lyd_find_path(*config, tree_path, 0, &new_tree);
    } else {
        /* config was NULL */
        ret = lyd_find_path(new_tree, tree_path, 0, &new_tree);
    }
    if (ret) {
        goto cleanup;
    }

    /* insert cert-data */
    ret = lyd_new_term(new_tree, NULL, "cert-data", cert, 0, NULL);
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
    free(cert);
    free(tree_path);
    return ret;
}

API int
nc_server_config_new_tls_client_ca(const struct ly_ctx *ctx, const char *endpt_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    struct lyd_node *new_tree;
    char *tree_path = NULL, *cert = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, cert_name, cert_path, config, 1);

    ret = nc_server_config_new_read_certificate(cert_path, &cert);
    if (ret) {
        ERR(NULL, "Getting certificate from file \"%s\" failed.", cert_path);
        goto cleanup;
    }

    /* prepare path for instertion of leaves later */
    asprintf(&tree_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tls-server-parameters/"
            "client-authentication/ca-certs/inline-definition/certificate[name='%s']", endpt_name, cert_name);
    if (!tree_path) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* create all the nodes in the path */
    ret = lyd_new_path(*config, ctx, tree_path, NULL, LYD_NEW_PATH_UPDATE, &new_tree);
    if (ret) {
        goto cleanup;
    }
    if (!*config) {
        *config = new_tree;
    }

    if (!new_tree) {
        /* no new nodes were created */
        ret = lyd_find_path(*config, tree_path, 0, &new_tree);
    } else {
        /* config was NULL */
        ret = lyd_find_path(new_tree, tree_path, 0, &new_tree);
    }
    if (ret) {
        goto cleanup;
    }

    /* insert cert-data */
    ret = lyd_new_term(new_tree, NULL, "cert-data", cert, 0, NULL);
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
    free(cert);
    free(tree_path);
    return ret;
}
