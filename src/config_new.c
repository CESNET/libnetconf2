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
#include <crypt.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "compat.h"
#include "config_new.h"
#include "libnetconf.h"
#include "server_config.h"
#include "session_server.h"

#if !defined (HAVE_CRYPT_R)
extern pthread_mutex_t crypt_lock;
#endif

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

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
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
    struct lyd_node *new_tree, *port_node;

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

    if (!new_tree) {
        /* no new nodes were created */
        ret = lyd_find_path(*config, tree_path, 0, &new_tree);
    } else {
        /* config was NULL */
        ret = lyd_find_path(new_tree, tree_path, 0, &new_tree);
    }
    if (ret) {
        ERR(NULL, "Unable to find tcp-server-parameters container.");
        goto cleanup;
    }

    ret = lyd_new_term(new_tree, NULL, "local-address", address, 0, NULL);
    if (ret) {
        goto cleanup;
    }

    ret = lyd_find_path(new_tree, "local-port", 0, &port_node);
    if (!ret) {
        ret = lyd_change_term(port_node, port);
    } else if (ret == LY_ENOTFOUND) {
        ret = lyd_new_term(new_tree, NULL, "local-port", port, 0, NULL);
    }

    if (ret && (ret != LY_EEXIST) && (ret != LY_ENOT)) {
        /* only fail if there was actually an error */
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

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
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

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }
cleanup:
    return ret;
}

static int
nc_server_config_ssh_read_openssh_pubkey(FILE *f, char **pubkey)
{
    int ret = 0;
    char *buffer = NULL;
    size_t len = 0;
    char *start, *end;

    if (getline(&buffer, &len, f) < 0) {
        ERR(NULL, "Reading line from file failed.");
        return 1;
    }

    if (len < 8) {
        ERR(NULL, "Unexpected public key format.");
        ret = 1;
        goto cleanup;
    }

    start = buffer;
    if (!strncmp(buffer, "ssh-rsa ", 8)) {
        start += strlen("ssh-rsa ");
        end = strchr(start, ' ');
        if (!end) {
            ERR(NULL, "Unexpected public key format.");
            ret = 1;
            goto cleanup;
        }

        *pubkey = strdup(start);
        if (!*pubkey) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }

        (*pubkey)[strlen(*pubkey) - strlen(end)] = '\0';
    }

cleanup:
    free(buffer);
    return ret;
}

static int
nc_server_config_ssh_read_ssh2_pubkey(FILE *f, char **pubkey)
{
    char *buffer = NULL;
    size_t len = 0;
    size_t pubkey_len = 0;
    void *tmp;

    while (getline(&buffer, &len, f) > 0) {
        if (!strncmp(buffer, "----", 4)) {
            free(buffer);
            buffer = NULL;
            continue;
        }

        if (!strncmp(buffer, "Comment:", 8)) {
            free(buffer);
            buffer = NULL;
            continue;
        }

        len = strlen(buffer);

        tmp = realloc(*pubkey, pubkey_len + len + 1);
        if (!tmp) {
            ERRMEM;
            free(buffer);
            buffer = NULL;
            return 1;
        }

        *pubkey = tmp;
        memcpy(*pubkey + pubkey_len, buffer, len);
        pubkey_len += len;
        free(buffer);
        buffer = NULL;
    }

    if (!pubkey_len) {
        ERR(NULL, "Unexpected public key format.");
        return 1;
    }

    (*pubkey)[pubkey_len - 1] = '\0';
    free(buffer);
    return 0;
}

static int
nc_server_config_ssh_read_subject_pubkey(FILE *f, char **pubkey)
{
    int ret = 0;
    EVP_PKEY *pkey;
    BIO *bio;
    BUF_MEM *mem;
    char *tmp;

    pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    if (!pkey) {
        ret = -1;
        goto cleanup;
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ret = -1;
        goto cleanup;
    }

    ret = PEM_write_bio_PUBKEY(bio, pkey);
    if (!ret) {
        ret = -1;
        goto cleanup;
    }
    ret = 0;

    BIO_get_mem_ptr(bio, &mem);
    tmp = malloc(mem->length + 1);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    memcpy(tmp, mem->data, mem->length);
    tmp[mem->length] = '\0';

    *pubkey = strdup(tmp + strlen("-----BEGIN PUBLIC KEY-----\n"));
    (*pubkey)[strlen(*pubkey) - strlen("\n-----END PUBLIC KEY-----\n")] = '\0';

cleanup:
    if (ret == -1) {
        ERR(NULL, "Error getting public key from file (OpenSSL Error): \"%s\".", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
    }

    BIO_free(bio);
    EVP_PKEY_free(pkey);
    free(tmp);

    return ret;
}

static int
nc_server_config_ssh_new_get_pubkey(const char *pubkey_path, char **pubkey, NC_SSH_PUBKEY_TYPE *pubkey_type)
{
    int ret = 0;
    FILE *f = NULL;
    char *buffer = NULL;
    size_t len = 0;

    *pubkey = NULL;

    f = fopen(pubkey_path, "r");
    if (!f) {
        ERR(NULL, "Unable to open file \"%s\".", pubkey_path);
        ret = 1;
        goto cleanup;
    }

    if (getline(&buffer, &len, f) < 0) {
        ERR(NULL, "Error reading header from file \"%s\".", pubkey_path);
        ret = 1;
        goto cleanup;
    }

    rewind(f);

    if (!strncmp(buffer, "-----BEGIN PUBLIC KEY-----\n", strlen("-----BEGIN PUBLIC KEY-----\n"))) {
        ret = nc_server_config_ssh_read_subject_pubkey(f, pubkey);
        *pubkey_type = NC_SSH_PUBKEY_X509;
    } else if (!strncmp(buffer, "---- BEGIN SSH2 PUBLIC KEY ----\n", strlen("---- BEGIN SSH2 PUBLIC KEY ----\n"))) {
        ret = nc_server_config_ssh_read_ssh2_pubkey(f, pubkey);
        *pubkey_type = NC_SSH_PUBKEY_SSH2;
    } else {
        ret = nc_server_config_ssh_read_openssh_pubkey(f, pubkey);
        *pubkey_type = NC_SSH_PUBKEY_SSH2;
    }

    if (ret) {
        ERR(NULL, "Error getting public key from file \"%s\".", pubkey_path);
        goto cleanup;
    }

cleanup:
    if (f) {
        fclose(f);
    }

    free(buffer);

    return ret;
}

API int
nc_server_config_ssh_new_client_auth_pubkey(const char *pubkey_path, const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *pubkey_name, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL, *tree_path = NULL;
    struct lyd_node *new_tree;
    NC_SSH_PUBKEY_TYPE pubkey_type;

    ret = nc_server_config_ssh_new_get_pubkey(pubkey_path, &pubkey, &pubkey_type);
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
    if (pubkey_type == NC_SSH_PUBKEY_SSH2) {
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
nc_server_config_ssh_new_client_auth_password(const char *password, const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
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
nc_server_config_ssh_new_client_auth_none(const struct ly_ctx *ctx, const char *endpt_name,
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
nc_server_config_ssh_new_client_auth_interactive(const char *pam_config_name, const char *pam_config_dir,
        const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, struct lyd_node **config)
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

    /* Add all default nodes */
    ret = lyd_new_implicit_tree(*config, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(tree_path);
    return ret;
}
