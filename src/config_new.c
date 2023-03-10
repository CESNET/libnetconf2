/**
 * @file config_new.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server new configuration creation functions
 *
 * @copyright
 * Copyright (c) 2015 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "compat.h"
#include "config_new.h"
#include "libnetconf.h"
#include "server_config.h"

static int
nc_server_config_ssh_new_get_keys(const char *privkey_path, const char *pubkey_path,
        char **privkey, char **pubkey, EVP_PKEY **priv_pkey_p)
{
    int ret = 0;
    EVP_PKEY *priv_pkey = NULL, *pub_pkey = NULL;
    FILE *f_privkey = NULL, *f_pubkey = NULL;
    BIO *bio_pub = NULL, *bio_priv = NULL;
    int pub_len, priv_len;

    assert(privkey_path);
    assert(privkey);
    assert(pubkey);
    assert(priv_pkey_p);
    *privkey = NULL;
    *pubkey = NULL;
    *priv_pkey_p = NULL;

    /* get private key first */
    f_privkey = fopen(privkey_path, "r");
    if (!f_privkey) {
        ERR(NULL, "Unable to open file \"%s\".", privkey_path);
        ret = 1;
        goto cleanup;
    }

    priv_pkey = PEM_read_PrivateKey(f_privkey, NULL, NULL, NULL);
    if (!priv_pkey) {
        ret = -1;
        goto cleanup;
    }
    /* set out param */
    *priv_pkey_p = priv_pkey;

    bio_priv = BIO_new(BIO_s_mem());
    if (!bio_priv) {
        ret = -1;
        goto cleanup;
    }

    ret = PEM_write_bio_PrivateKey(bio_priv, priv_pkey, NULL, NULL, 0, NULL, NULL);
    if (!ret) {
        ret = -1;
        goto cleanup;
    }

    priv_len = BIO_pending(bio_priv);
    if (priv_len <= 0) {
        ret = -1;
        goto cleanup;
    }

    *privkey = malloc(priv_len + 1);
    if (!*privkey) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    ret = BIO_read(bio_priv, *privkey, priv_len);
    if (ret <= 0) {
        ret = -1;
        goto cleanup;
    }
    (*privkey)[priv_len] = '\0';

    /* if public key is supplied, then read it */
    if (pubkey_path) {
        f_pubkey = fopen(pubkey_path, "r");
        if (!f_pubkey) {
            ERR(NULL, "Unable to open file \"%s\"", pubkey_path);
            ret = 1;
            goto cleanup;
        }
        pub_pkey = PEM_read_PUBKEY(f_pubkey, NULL, NULL, NULL);
        if (!pub_pkey) {
            ret = -1;
            goto cleanup;
        }
    }

    bio_pub = BIO_new(BIO_s_mem());
    if (!bio_pub) {
        ret = -1;
        goto cleanup;
    }

    /* get public key either from the private key or from the given file */
    if (pubkey_path) {
        ret = PEM_write_bio_PUBKEY(bio_pub, pub_pkey);
    } else {
        ret = PEM_write_bio_PUBKEY(bio_pub, priv_pkey);
    }
    if (!ret) {
        ret = -1;
        goto cleanup;
    }

    pub_len = BIO_pending(bio_pub);
    if (pub_len <= 0) {
        ret = -1;
        goto cleanup;
    }

    *pubkey = malloc(pub_len + 1);
    if (!*pubkey) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    ret = BIO_read(bio_pub, *pubkey, pub_len);
    if (ret <= 0) {
        ret = -1;
        goto cleanup;
    }
    (*pubkey)[pub_len] = '\0';

    ret = 0;
cleanup:
    if (ret < 0) {
        ERR(NULL, "Error getting keys from file: \"%s\".", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
    }
    EVP_PKEY_free(pub_pkey);
    if (f_privkey) {
        fclose(f_privkey);
    }
    if (f_pubkey) {
        fclose(f_pubkey);
    }
    BIO_free(bio_priv);
    BIO_free(bio_pub);
    return ret;
}

API int
nc_server_config_ssh_new_hostkey(const char *privkey_path, const char *pubkey_path, const struct ly_ctx *ctx,
        const char *endpt_name, const char *hostkey_name, struct lyd_node **config)
{
    int ret = 0;
    char *pub_key = NULL, *priv_key = NULL, *pub_key_stripped, *priv_key_stripped;
    struct lyd_node *new_tree;
    char *tree_path = NULL;
    EVP_PKEY *priv_pkey = NULL;

    if (!privkey_path || !config || !ctx || !endpt_name || !hostkey_name) {
        ERRARG("privkey_path or config or ctx or endpt_name or hostkey_name");
    }

    /* get the keys as a string from the given files */
    ret = nc_server_config_ssh_new_get_keys(privkey_path, pubkey_path, &priv_key, &pub_key, &priv_pkey);
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

    /* give the top level container create operation */
    ret = lyd_new_meta(ctx, *config, NULL, "yang:operation", "create", 0, NULL);
    if (ret) {
        goto cleanup;
    }

    /* find the node where leaves will get inserted */
    ret = lyd_find_path(*config, tree_path, 0, &new_tree);
    if (ret) {
        goto cleanup;
    }

    /* insert pubkey format */
    if (!strstr(pub_key, "---- BEGIN SSH2 PUBLIC KEY ----")) {
        ret = lyd_new_term(new_tree, NULL, "public-key-format", "ietf-crypto-types:ssh-public-key-format", 0, NULL);
    } else {
        ret = lyd_new_term(new_tree, NULL, "public-key-format", "ietf-crypto-types:subject-public-key-info-format", 0, NULL);
    }
    if (ret) {
        goto cleanup;
    }

    /* strip pubkey's header and footer */
    pub_key_stripped = pub_key + strlen("-----BEGIN PUBLIC KEY-----") + 1;
    pub_key_stripped[strlen(pub_key_stripped) - strlen("-----END PUBLIC KEY-----") - 2] = '\0';

    /* insert pubkey b64 */
    ret = lyd_new_term(new_tree, NULL, "public-key", pub_key_stripped, 0, NULL);
    if (ret) {
        goto cleanup;
    }

    /* do the same for private key */
    if (EVP_PKEY_is_a(priv_pkey, "RSA")) {
        ret = lyd_new_term(new_tree, NULL, "private-key-format", "ietf-crypto-types:rsa-private-key-format", 0, NULL);
    } else if (EVP_PKEY_is_a(priv_pkey, "EC")) {
        ret = lyd_new_term(new_tree, NULL, "private-key-format", "ietf-crypto-types:ec-private-key-format", 0, NULL);
    } else {
        ERR(NULL, "Private key type not supported.");
        ret = 1;
    }
    if (ret) {
        goto cleanup;
    }

    priv_key_stripped = priv_key + strlen("-----BEGIN PRIVATE KEY-----") + 1;
    priv_key_stripped[strlen(priv_key_stripped) - strlen("-----END PRIVATE KEY-----") - 2] = '\0';

    ret = lyd_new_term(new_tree, NULL, "cleartext-private-key", priv_key_stripped, 0, NULL);
    if (ret) {
        goto cleanup;
    }

cleanup:
    EVP_PKEY_free(priv_pkey);
    free(priv_key);
    free(pub_key);
    free(tree_path);
    return ret;
}

API int
nc_server_config_ssh_new_address_port(const char *address, const char *port, const struct ly_ctx *ctx,
        const char *endpt_name, struct lyd_node **config)
{
    int ret = 0;
    char *tree_path = NULL;
    struct lyd_node *new_tree;

    if (!address || !port || !ctx || !endpt_name || !config) {
        ERRARG("args");
        ret = 1;
        goto cleanup;
    }

    /* prepare path for instertion of leaves later */
    asprintf(&tree_path, "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/tcp-server-parameters", endpt_name);
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

    /* lyd_new_path sets the out param to the first node created,
     * so in case the original tree was empty new_tree has to be set correctly */
    ret = lyd_find_path(new_tree, tree_path, 0, &new_tree);
    if (ret) {
        ERR(NULL, "Unable to find tcp-server-parameters container.");
        goto cleanup;
    }

    ret = lyd_new_term(new_tree, NULL, "local-address", address, 0, NULL);
    if (ret) {
        goto cleanup;
    }

    ret = lyd_new_term(new_tree, NULL, "local-port", port, 0, NULL);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(tree_path);
    return ret;
}

static int
nc_server_config_ssh_new_transport_params_prep(const struct ly_ctx *ctx, const char *endpt_name,
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

cleanup:
    free(tree_path);
    return ret;
}

static int
nc_server_config_ssh_new_transport_params(const struct ly_ctx *ctx, NC_ALG_TYPE alg_type, int alg_count, va_list ap,
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
nc_server_config_ssh_new_host_key_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...)
{
    int ret = 0;
    struct lyd_node *new_tree, *alg_tree;
    va_list ap;

    ret = nc_server_config_ssh_new_transport_params_prep(ctx, endpt_name, *config, &new_tree, &alg_tree);
    if (ret) {
        goto cleanup;
    }

    if (!*config) {
        *config = new_tree;
    }

    va_start(ap, alg_count);

    ret = nc_server_config_ssh_new_transport_params(ctx, NC_ALG_HOSTKEY, alg_count, ap, alg_tree);
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

    ret = nc_server_config_ssh_new_transport_params_prep(ctx, endpt_name, *config, &new_tree, &alg_tree);
    if (ret) {
        goto cleanup;
    }

    if (!*config) {
        *config = new_tree;
    }

    va_start(ap, alg_count);

    ret = nc_server_config_ssh_new_transport_params(ctx, NC_ALG_KEY_EXCHANGE, alg_count, ap, alg_tree);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_ssh_new_encryption_algs(const struct ly_ctx *ctx, const char *endpt_name, struct lyd_node **config,
        int alg_count, ...)
{
    int ret = 0;
    struct lyd_node *new_tree, *alg_tree;
    va_list ap;

    ret = nc_server_config_ssh_new_transport_params_prep(ctx, endpt_name, *config, &new_tree, &alg_tree);
    if (ret) {
        goto cleanup;
    }

    if (!*config) {
        *config = new_tree;
    }

    va_start(ap, alg_count);

    ret = nc_server_config_ssh_new_transport_params(ctx, NC_ALG_ENCRYPTION, alg_count, ap, alg_tree);
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

    ret = nc_server_config_ssh_new_transport_params_prep(ctx, endpt_name, *config, &new_tree, &alg_tree);
    if (ret) {
        goto cleanup;
    }

    if (!*config) {
        *config = new_tree;
    }

    va_start(ap, alg_count);

    ret = nc_server_config_ssh_new_transport_params(ctx, NC_ALG_MAC, alg_count, ap, alg_tree);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}
