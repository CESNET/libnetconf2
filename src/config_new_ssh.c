/**
 * @file config_new_ssh.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server new configuration creation functions
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
#include "config_new_ssh.h"
#include "libnetconf.h"
#include "server_config.h"
#include "session_server.h"

#if !defined (HAVE_CRYPT_R)
extern pthread_mutex_t crypt_lock;
#endif

static int
nc_server_config_new_ssh_read_ssh2_pubkey(FILE *f, char **pubkey)
{
    char *buffer = NULL;
    size_t size = 0, pubkey_len = 0;
    void *tmp;
    ssize_t read;
    int ret = 0;

    while ((read = getline(&buffer, &size, f)) > 0) {
        if (!strncmp(buffer, "----", 4)) {
            continue;
        }

        if (!strncmp(buffer, "Comment:", 8)) {
            continue;
        }

        if (buffer[read - 1] == '\n') {
            read--;
        }

        tmp = realloc(*pubkey, pubkey_len + read + 1);
        if (!tmp) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }

        *pubkey = tmp;
        memcpy(*pubkey + pubkey_len, buffer, read);
        pubkey_len += read;
    }

    if (!pubkey_len) {
        ERR(NULL, "Unexpected public key format.");
        ret = 1;
        goto cleanup;
    }

    (*pubkey)[pubkey_len] = '\0';

cleanup:
    free(buffer);
    return ret;
}

static int
nc_server_config_new_ssh_read_pubkey_openssl(FILE *f, char **pubkey)
{
    int ret = 0;
    EVP_PKEY *pkey;
    BIO *bio;
    char *key = NULL;
    int pub_len;

    /* read the pubkey from file */
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

    /* write the pubkey into bio */
    ret = PEM_write_bio_PUBKEY(bio, pkey);
    if (!ret) {
        ret = -1;
        goto cleanup;
    }

    pub_len = BIO_pending(bio);
    if (pub_len <= 0) {
        ret = -1;
        goto cleanup;
    }

    /* get pubkey's length */
    key = malloc(pub_len + 1);
    if (!key) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* read the public key from bio */
    ret = BIO_read(bio, key, pub_len);
    if (ret <= 0) {
        ret = -1;
        goto cleanup;
    }
    key[pub_len] = '\0';

    /* strip the pubkey of the header and footer */
    *pubkey = strdup(key + strlen(NC_SUBJECT_PUBKEY_INFO_HEADER));
    if (!*pubkey) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    (*pubkey)[strlen(*pubkey) - strlen(NC_SUBJECT_PUBKEY_INFO_FOOTER)] = '\0';

    ret = 0;
cleanup:
    if (ret == -1) {
        ERR(NULL, "Error getting public key from file (OpenSSL Error): \"%s\".", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
    }

    BIO_free(bio);
    EVP_PKEY_free(pkey);
    free(key);

    return ret;
}

static int
nc_server_config_new_ssh_read_pubkey_libssh(const char *pubkey_path, char **pubkey)
{
    int ret = 0;
    ssh_key pub_sshkey = NULL;

    ret = ssh_pki_import_pubkey_file(pubkey_path, &pub_sshkey);
    if (ret) {
        ERR(NULL, "Importing public key from file \"%s\" failed.", pubkey_path);
        return ret;
    }

    ret = ssh_pki_export_pubkey_base64(pub_sshkey, pubkey);
    if (ret) {
        ERR(NULL, "Exporting public key to base64 failed.");
    }

    ssh_key_free(pub_sshkey);
    return ret;
}

static int
nc_server_config_new_ssh_get_pubkey(const char *pubkey_path, char **pubkey, NC_SSH_PUBKEY_TYPE *pubkey_type)
{
    int ret = 0;
    FILE *f = NULL;
    char *header = NULL;
    size_t len = 0;

    NC_CHECK_ARG_RET(NULL, pubkey, pubkey_type, 1);

    *pubkey = NULL;

    f = fopen(pubkey_path, "r");
    if (!f) {
        ERR(NULL, "Unable to open file \"%s\".", pubkey_path);
        ret = 1;
        goto cleanup;
    }

    if (getline(&header, &len, f) < 0) {
        ERR(NULL, "Error reading header from file \"%s\".", pubkey_path);
        ret = 1;
        goto cleanup;
    }
    rewind(f);

    if (!strncmp(header, NC_SUBJECT_PUBKEY_INFO_HEADER, strlen(NC_SUBJECT_PUBKEY_INFO_HEADER))) {
        /* it's subject public key info public key */
        ret = nc_server_config_new_ssh_read_pubkey_openssl(f, pubkey);
        *pubkey_type = NC_SSH_PUBKEY_X509;
    } else if (!strncmp(header, NC_SSH2_PUBKEY_HEADER, strlen(NC_SSH2_PUBKEY_HEADER))) {
        /* it's ssh2 public key */
        ret = nc_server_config_new_ssh_read_ssh2_pubkey(f, pubkey);
        *pubkey_type = NC_SSH_PUBKEY_SSH2;
    } else {
        /* it's probably OpenSSH public key */
        ret = nc_server_config_new_ssh_read_pubkey_libssh(pubkey_path, pubkey);
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

    free(header);

    return ret;
}

static int
nc_server_config_new_ssh_get_privkey_openssl(FILE *f, char **privkey, EVP_PKEY **priv_pkey)
{
    int ret = 0, priv_len;
    BIO *bio = NULL;

    NC_CHECK_ARG_RET(NULL, privkey, priv_pkey, 1);

    /* read private key from file */
    *priv_pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    if (!*priv_pkey) {
        ret = -1;
        goto cleanup;
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ret = -1;
        goto cleanup;
    }

    /* write the private key in to bio */
    ret = PEM_write_bio_PrivateKey(bio, *priv_pkey, NULL, NULL, 0, NULL, NULL);
    if (!ret) {
        ret = -1;
        goto cleanup;
    }

    priv_len = BIO_pending(bio);
    if (priv_len <= 0) {
        ret = -1;
        goto cleanup;
    }

    /* get private key's length */
    *privkey = malloc(priv_len + 1);
    if (!*privkey) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* read the private key from bio */
    ret = BIO_read(bio, *privkey, priv_len);
    if (ret <= 0) {
        ret = -1;
        goto cleanup;
    }
    (*privkey)[priv_len] = '\0';

    ret = 0;
cleanup:
    if (ret < 0) {
        ERR(NULL, "Getting private key from file failed (%s).", ERR_reason_error_string(ERR_get_error()));
    }
    BIO_free(bio);
    return ret;
}

static int
nc_server_config_new_ssh_privkey_to_pubkey_openssl(EVP_PKEY *priv_pkey, char **pubkey)
{
    int ret = 0, pub_len;
    BIO *bio = NULL;

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ret = -1;
        goto cleanup;
    }

    /* write the pubkey into bio */
    ret = PEM_write_bio_PUBKEY(bio, priv_pkey);
    if (!ret) {
        ret = -1;
        goto cleanup;
    }

    /* get the length of the pubkey */
    pub_len = BIO_pending(bio);
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

    /* read the pubkey from the bio */
    ret = BIO_read(bio, *pubkey, pub_len);
    if (ret <= 0) {
        ret = -1;
        goto cleanup;
    }
    (*pubkey)[pub_len] = '\0';

    ret = 0;

cleanup:
    if (ret < 0) {
        ERR(NULL, "Converting private to public key failed (%s).", ERR_reason_error_string(ERR_get_error()));
    }
    BIO_free(bio);
    return ret;
}

static int
nc_server_config_new_ssh_privkey_to_pubkey_libssh(const ssh_key priv_sshkey, char **pubkey)
{
    int ret;
    ssh_key pub_sshkey = NULL;

    ret = ssh_pki_export_privkey_to_pubkey(priv_sshkey, &pub_sshkey);
    if (ret) {
        ERR(NULL, "Exporting privkey to pubkey failed.");
        return ret;
    }

    ret = ssh_pki_export_pubkey_base64(pub_sshkey, pubkey);
    if (ret) {
        ERR(NULL, "Exporting pubkey to base64 failed.");
    }

    ssh_key_free(pub_sshkey);
    return ret;
}

static int
nc_server_config_new_ssh_privkey_to_pubkey(EVP_PKEY *priv_pkey, const ssh_key priv_sshkey, NC_PRIVKEY_FORMAT privkey_type, char **pubkey, NC_SSH_PUBKEY_TYPE *pubkey_type)
{
    switch (privkey_type) {
    case NC_PRIVKEY_FORMAT_RSA:
    case NC_PRIVKEY_FORMAT_EC:
    case NC_PRIVKEY_FORMAT_OPENSSH:
        *pubkey_type = NC_SSH_PUBKEY_SSH2;
        return nc_server_config_new_ssh_privkey_to_pubkey_libssh(priv_sshkey, pubkey);
    case NC_PRIVKEY_FORMAT_PKCS8:
        *pubkey_type = NC_SSH_PUBKEY_X509;
        return nc_server_config_new_ssh_privkey_to_pubkey_openssl(priv_pkey, pubkey);
    }

    return 1;
}

static int
nc_server_config_new_ssh_get_privkey_libssh(const char *privkey_path, char **privkey, ssh_key *priv_sshkey)
{
    int ret;

    *priv_sshkey = NULL;

    ret = ssh_pki_import_privkey_file(privkey_path, NULL, NULL, NULL, priv_sshkey);
    if (ret) {
        ERR(NULL, "Importing privkey from file \"%s\" failed.", privkey_path);
        return ret;
    }

    ret = ssh_pki_export_privkey_base64(*priv_sshkey, NULL, NULL, NULL, privkey);
    if (ret) {
        ERR(NULL, "Exporting privkey from file \"%s\" to base64 failed.", privkey_path);
    }

    return ret;
}

static int
nc_server_config_new_ssh_get_keys(const char *privkey_path, const char *pubkey_path,
        char **privkey, char **pubkey, NC_PRIVKEY_FORMAT *privkey_type, NC_SSH_PUBKEY_TYPE *pubkey_type)
{
    int ret = 0;
    EVP_PKEY *priv_pkey = NULL;
    ssh_key priv_sshkey = NULL;
    FILE *f_privkey = NULL;
    char *header = NULL;
    size_t len = 0;

    NC_CHECK_ARG_RET(NULL, privkey_path, privkey, pubkey, privkey_type, 1);

    *privkey = NULL;
    *pubkey = NULL;

    /* get private key first */
    f_privkey = fopen(privkey_path, "r");
    if (!f_privkey) {
        ERR(NULL, "Unable to open file \"%s\".", privkey_path);
        ret = 1;
        goto cleanup;
    }

    if (getline(&header, &len, f_privkey) < 0) {
        ERR(NULL, "Error reading header from file \"%s\".", privkey_path);
        ret = 1;
        goto cleanup;
    }
    rewind(f_privkey);

    if (!strncmp(header, NC_PKCS8_PRIVKEY_HEADER, strlen(NC_PKCS8_PRIVKEY_HEADER))) {
        /* it's PKCS8 (X.509) private key */
        *privkey_type = NC_PRIVKEY_FORMAT_PKCS8;
        ret = nc_server_config_new_ssh_get_privkey_openssl(f_privkey, privkey, &priv_pkey);
    } else if (!strncmp(header, NC_OPENSSH_PRIVKEY_HEADER, strlen(NC_OPENSSH_PRIVKEY_HEADER))) {
        /* it's OpenSSH private key */
        *privkey_type = NC_PRIVKEY_FORMAT_OPENSSH;
        ret = nc_server_config_new_ssh_get_privkey_libssh(privkey_path, privkey, &priv_sshkey);
    } else if (!strncmp(header, NC_PKCS1_RSA_PRIVKEY_HEADER, strlen(NC_PKCS1_RSA_PRIVKEY_HEADER))) {
        /* it's RSA privkey in PKCS1 format */
        *privkey_type = NC_PRIVKEY_FORMAT_RSA;
        ret = nc_server_config_new_ssh_get_privkey_libssh(privkey_path, privkey, &priv_sshkey);
    } else if (!strncmp(header, NC_SEC1_EC_PRIVKEY_HEADER, strlen(NC_SEC1_EC_PRIVKEY_HEADER))) {
        /* it's EC privkey in SEC1 format */
        *privkey_type = NC_PRIVKEY_FORMAT_EC;
        ret = nc_server_config_new_ssh_get_privkey_libssh(privkey_path, privkey, &priv_sshkey);
    } else {
        ERR(NULL, "Private key format not supported.");
        ret = 1;
        goto cleanup;
    }

    if (ret) {
        goto cleanup;
    }

    if (pubkey_path) {
        ret = nc_server_config_new_ssh_get_pubkey(pubkey_path, pubkey, pubkey_type);
    } else {
        ret = nc_server_config_new_ssh_privkey_to_pubkey(priv_pkey, priv_sshkey, *privkey_type, pubkey, pubkey_type);
    }

    if (ret) {
        ERR(NULL, "Getting public key failed.");
        goto cleanup;
    }

cleanup:
    if (f_privkey) {
        fclose(f_privkey);
    }

    free(header);

    ssh_key_free(priv_sshkey);
    EVP_PKEY_free(priv_pkey);

    return ret;
}

API int
nc_server_config_new_ssh_hostkey(const char *privkey_path, const char *pubkey_path, const struct ly_ctx *ctx,
        const char *endpt_name, const char *hostkey_name, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL, *privkey = NULL, *pubkey_stripped, *privkey_stripped;
    struct lyd_node *new_tree;
    char *tree_path = NULL;
    NC_PRIVKEY_FORMAT privkey_type;
    NC_SSH_PUBKEY_TYPE pubkey_type;

    NC_CHECK_ARG_RET(NULL, privkey_path, config, ctx, endpt_name, hostkey_name, 1);

    /* get the keys as a string from the given files */
    ret = nc_server_config_new_ssh_get_keys(privkey_path, pubkey_path, &privkey, &pubkey, &privkey_type, &pubkey_type);
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
    if (pubkey_type == NC_SSH_PUBKEY_SSH2) {
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
    if (!pubkey_path && (privkey_type == NC_PRIVKEY_FORMAT_PKCS8)) {
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

    /* insert private key format */
    if (privkey_type == NC_PRIVKEY_FORMAT_RSA) {
        ret = lyd_new_term(new_tree, NULL, "private-key-format", "ietf-crypto-types:rsa-private-key-format", 0, NULL);
    } else if (privkey_type == NC_PRIVKEY_FORMAT_EC) {
        ret = lyd_new_term(new_tree, NULL, "private-key-format", "ietf-crypto-types:ec-private-key-format", 0, NULL);
    } else if (privkey_type == NC_PRIVKEY_FORMAT_PKCS8) {
        ret = lyd_new_term(new_tree, NULL, "private-key-format", "libnetconf2-netconf-server:subject-private-key-info-format", 0, NULL);
    } else if (privkey_type == NC_PRIVKEY_FORMAT_OPENSSH) {
        ret = lyd_new_term(new_tree, NULL, "private-key-format", "libnetconf2-netconf-server:openssh-private-key-format", 0, NULL);
    } else {
        ERR(NULL, "Private key type not supported.");
        ret = 1;
    }

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

API int
nc_server_config_new_ssh_address_port(const char *address, const char *port, const struct ly_ctx *ctx,
        const char *endpt_name, struct lyd_node **config)
{
    int ret = 0;
    char *tree_path = NULL;
    struct lyd_node *new_tree, *port_node;

    NC_CHECK_ARG_RET(NULL, address, port, ctx, endpt_name, config, 1);

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
nc_server_config_new_ssh_client_auth_pubkey(const char *pubkey_path, const struct ly_ctx *ctx, const char *endpt_name,
        const char *user_name, const char *pubkey_name, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL, *tree_path = NULL;
    struct lyd_node *new_tree;
    NC_SSH_PUBKEY_TYPE pubkey_type;

    ret = nc_server_config_new_ssh_get_pubkey(pubkey_path, &pubkey, &pubkey_type);
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
nc_server_config_new_ssh_client_auth_password(const char *password, const struct ly_ctx *ctx, const char *endpt_name,
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
nc_server_config_new_ssh_client_auth_interactive(const char *pam_config_name, const char *pam_config_dir,
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
