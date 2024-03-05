/**
 * @file server_config_util.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server configuration utilities
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

#include <libyang/libyang.h>

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef NC_ENABLED_SSH_TLS
#include <libssh/libssh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif /* NC_ENABLED_SSH_TLS */

#include "compat.h"
#include "log_p.h"
#include "session.h"
#include "session_p.h"

int
nc_server_config_create(const struct ly_ctx *ctx, struct lyd_node **tree, const char *value, const char *path_fmt, ...)
{
    int ret = 0;
    va_list ap;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, tree, path_fmt, 1);

    va_start(ap, path_fmt);

    /* create the path from the format */
    ret = vasprintf(&path, path_fmt, ap);
    NC_CHECK_ERRMEM_GOTO(ret == -1, ret = 1; path = NULL, cleanup);

    /* create the nodes in the path */
    if (!*tree) {
        ret = lyd_new_path(*tree, ctx, path, value, LYD_NEW_PATH_UPDATE, tree);
    } else {
        /* this could output NULL if no new nodes, lyd_find_path would fail then */
        ret = lyd_new_path(*tree, ctx, path, value, LYD_NEW_PATH_UPDATE, NULL);
    }
    if (ret) {
        goto cleanup;
    }

    /* set the node to the top level node */
    ret = lyd_find_path(*tree, "/ietf-netconf-server:netconf-server", 0, tree);
    if (ret) {
        goto cleanup;
    }

    /* add all default nodes */
    ret = lyd_new_implicit_tree(*tree, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    va_end(ap);
    return ret;
}

int
nc_server_config_append(const struct ly_ctx *ctx, const char *parent_path, const char *child_name,
        const char *value, struct lyd_node **tree)
{
    int ret = 0;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, parent_path, child_name, tree, 1);

    /* create the path by appending child to the parent path */
    ret = asprintf(&path, "%s/%s", parent_path, child_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, ret = 1; path = NULL, cleanup);

    /* create the nodes in the path */
    if (!*tree) {
        ret = lyd_new_path(*tree, ctx, path, value, LYD_NEW_PATH_UPDATE, tree);
    } else {
        /* this could output NULL if no new nodes, lyd_find_path would fail then */
        ret = lyd_new_path(*tree, ctx, path, value, LYD_NEW_PATH_UPDATE, NULL);
    }
    if (ret) {
        goto cleanup;
    }

    /* set the node to the top level node */
    ret = lyd_find_path(*tree, "/ietf-netconf-server:netconf-server", 0, tree);
    if (ret) {
        goto cleanup;
    }

    /* add all default nodes */
    ret = lyd_new_implicit_tree(*tree, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

int
nc_server_config_delete(struct lyd_node **tree, const char *path_fmt, ...)
{
    int ret = 0;
    va_list ap;
    char *path = NULL;
    struct lyd_node *sub = NULL;

    NC_CHECK_ARG_RET(NULL, tree, path_fmt, 1);

    va_start(ap, path_fmt);

    /* create the path from the format */
    ret = vasprintf(&path, path_fmt, ap);
    NC_CHECK_ERRMEM_GOTO(ret == -1, ret = 1; path = NULL, cleanup);

    /* find the node we want to delete */
    ret = lyd_find_path(*tree, path, 0, &sub);
    if (ret) {
        goto cleanup;
    }

    lyd_free_tree(sub);

    /* set the node to top level container */
    ret = lyd_find_path(*tree, "/ietf-netconf-server:netconf-server", 0, tree);
    if (ret) {
        goto cleanup;
    }

    /* add all default nodes */
    ret = lyd_new_implicit_tree(*tree, LYD_IMPLICIT_NO_STATE, NULL);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    va_end(ap);
    return ret;
}

int
nc_server_config_check_delete(struct lyd_node **tree, const char *path_fmt, ...)
{
    int ret = 0;
    va_list ap;
    char *path = NULL;
    struct lyd_node *sub = NULL;

    NC_CHECK_ARG_RET(NULL, tree, path_fmt, 1);

    va_start(ap, path_fmt);

    /* create the path from the format */
    ret = vasprintf(&path, path_fmt, ap);
    NC_CHECK_ERRMEM_GOTO(ret == -1, ret = 1; path = NULL, cleanup);

    /* find the node we want to delete */
    ret = lyd_find_path(*tree, path, 0, &sub);
    if ((ret == LY_EINCOMPLETE) || (ret == LY_ENOTFOUND)) {
        ret = 0;
        goto cleanup;
    } else if (ret) {
        ERR(NULL, "Unable to delete node in the path \"%s\".", path);
        goto cleanup;
    }

    lyd_free_tree(sub);

    /* set the node to top level container */
    ret = lyd_find_path(*tree, "/ietf-netconf-server:netconf-server", 0, tree);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(path);
    va_end(ap);
    return ret;
}

#ifdef NC_ENABLED_SSH_TLS

const char *
nc_server_config_util_privkey_format_to_identityref(NC_PRIVKEY_FORMAT format)
{
    switch (format) {
    case NC_PRIVKEY_FORMAT_RSA:
        return "ietf-crypto-types:rsa-private-key-format";
    case NC_PRIVKEY_FORMAT_EC:
        return "ietf-crypto-types:ec-private-key-format";
    case NC_PRIVKEY_FORMAT_X509:
        return "libnetconf2-netconf-server:private-key-info-format";
    case NC_PRIVKEY_FORMAT_OPENSSH:
        return "libnetconf2-netconf-server:openssh-private-key-format";
    default:
        ERR(NULL, "Private key type not supported.");
        return NULL;
    }
}

static int
nc_server_config_util_pubkey_bin_to_b64(const unsigned char *pub_bin, int bin_len, char **pubkey)
{
    int ret = 0, b64_len;
    char *pub_b64 = NULL;

    NC_CHECK_ARG_RET(NULL, pub_bin, bin_len, pubkey, 1);

    /* get b64 buffer len, for ever 3 bytes of bin 4 bytes of b64 + NULL terminator */
    if (bin_len % 3 == 0) {
        pub_b64 = malloc((bin_len / 3) * 4 + 1);
    } else {
        /* bin len not divisible by 3, need to add 4 bytes for some padding so that the len is divisible by 4 */
        pub_b64 = malloc((bin_len / 3) * 4 + 4 + 1);
    }
    NC_CHECK_ERRMEM_GOTO(!pub_b64, ret = 1, cleanup);

    /* bin to b64 */
    b64_len = EVP_EncodeBlock((unsigned char *)pub_b64, pub_bin, bin_len);
    *pubkey = strndup(pub_b64, b64_len);
    NC_CHECK_ERRMEM_GOTO(!*pubkey, ret = 1, cleanup);

cleanup:
    free(pub_b64);
    return ret;
}

static int
nc_server_config_util_bn_to_bin(const BIGNUM *bn, unsigned char **bin, int *bin_len)
{
    int ret = 0;
    unsigned char *bin_tmp = NULL;

    NC_CHECK_ARG_RET(NULL, bn, bin, bin_len, 1);

    *bin = NULL;

    /* prepare buffer for converting BN to binary */
    bin_tmp = calloc(BN_num_bytes(bn), sizeof *bin_tmp);
    NC_CHECK_ERRMEM_RET(!bin_tmp, 1);

    /* convert to binary */
    *bin_len = BN_bn2bin(bn, bin_tmp);

    /* if the highest bit in the MSB is set a byte with the value 0 has to be prepended */
    if (bin_tmp[0] & 0x80) {
        *bin = malloc(*bin_len + 1);
        NC_CHECK_ERRMEM_GOTO(!*bin, ret = 1, cleanup);
        (*bin)[0] = 0;
        memcpy(*bin + 1, bin_tmp, *bin_len);
        (*bin_len)++;
    } else {
        *bin = malloc(*bin_len);
        NC_CHECK_ERRMEM_GOTO(!*bin, ret = 1, cleanup);
        memcpy(*bin, bin_tmp, *bin_len);
    }

cleanup:
    free(bin_tmp);
    return ret;
}

/* ssh pubkey defined in RFC 4253 section 6.6 */
static int
nc_server_config_util_evp_pkey_to_ssh_pubkey(EVP_PKEY *pkey, char **pubkey)
{
    int ret = 0, e_len, n_len, p_len, bin_len;
    BIGNUM *e = NULL, *n = NULL, *p = NULL;
    unsigned char *e_bin = NULL, *n_bin = NULL, *p_bin = NULL, *bin = NULL, *bin_tmp;
    const char *algorithm_name, *curve_name;
    char *ec_group = NULL;
    uint32_t alg_name_len, curve_name_len, alg_name_len_be, curve_name_len_be, p_len_be, e_len_be, n_len_be;
    size_t ec_group_len;

    NC_CHECK_ARG_RET(NULL, pkey, pubkey, 1);

    if (EVP_PKEY_is_a(pkey, "RSA")) {
        /* RSA key */
        algorithm_name = "ssh-rsa";

        /* get the public key params */
        if (!EVP_PKEY_get_bn_param(pkey, "e", &e) || !EVP_PKEY_get_bn_param(pkey, "n", &n)) {
            ERR(NULL, "Getting public key parameters from RSA private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
            ret = 1;
            goto cleanup;
        }

        /* BIGNUM to bin */
        if (nc_server_config_util_bn_to_bin(e, &e_bin, &e_len) || nc_server_config_util_bn_to_bin(n, &n_bin, &n_len)) {
            ret = 1;
            goto cleanup;
        }

        alg_name_len = strlen(algorithm_name);
        /* buffer for public key in binary, which looks like this:
         * alg_name len (4 bytes), alg_name, PK exponent len (4 bytes), PK exponent, modulus len (4 bytes), modulus
         */
        bin_len = 4 + alg_name_len + 4 + e_len + 4 + n_len;
        bin = malloc(bin_len);
        NC_CHECK_ERRMEM_GOTO(!bin, ret = 1, cleanup);

        /* to network byte order (big endian) */
        alg_name_len_be = htonl(alg_name_len);
        e_len_be = htonl(e_len);
        n_len_be = htonl(n_len);

        /* create the public key in binary */
        bin_tmp = bin;
        memcpy(bin_tmp, &alg_name_len_be, 4);
        bin_tmp += 4;
        memcpy(bin_tmp, algorithm_name, alg_name_len);
        bin_tmp += alg_name_len;
        memcpy(bin_tmp, &e_len_be, 4);
        bin_tmp += 4;
        memcpy(bin_tmp, e_bin, e_len);
        bin_tmp += e_len;
        memcpy(bin_tmp, &n_len_be, 4);
        bin_tmp += 4;
        memcpy(bin_tmp, n_bin, n_len);
    } else if (EVP_PKEY_is_a(pkey, "EC")) {
        /* EC Private key, get it's group first */
        /* get group len */
        ret = EVP_PKEY_get_utf8_string_param(pkey, "group", NULL, 0, &ec_group_len);
        if (!ret) {
            ret = 1;
            goto cleanup;
        }
        /* alloc mem for group + 1 for \0 */
        ec_group = malloc(ec_group_len + 1);
        NC_CHECK_ERRMEM_GOTO(!ec_group, ret = 1, cleanup);
        /* get the group */
        ret = EVP_PKEY_get_utf8_string_param(pkey, "group", ec_group, ec_group_len + 1, NULL);
        if (!ret) {
            ERR(NULL, "Getting public key parameter from EC private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
            ret = 1;
            goto cleanup;
        }

        /* get alg and curve names */
        if (!strcmp(ec_group, "P-256") || !strcmp(ec_group, "secp256r1") || !strcmp(ec_group, "prime256v1")) {
            algorithm_name = "ecdsa-sha2-nistp256";
            curve_name = "nistp256";
        } else if (!strcmp(ec_group, "P-384") || !strcmp(ec_group, "secp384r1")) {
            algorithm_name = "ecdsa-sha2-nistp384";
            curve_name = "nistp384";
        } else if (!strcmp(ec_group, "P-521") || !strcmp(ec_group, "secp521r1")) {
            algorithm_name = "ecdsa-sha2-nistp521";
            curve_name = "nistp521";
        } else {
            ERR(NULL, "EC group \"%s\" not supported.", ec_group);
            ret = 1;
            goto cleanup;
        }

        /* get the public key - p, which is a point on the elliptic curve */
        ret = EVP_PKEY_get_bn_param(pkey, "p", &p);
        if (!ret) {
            ERR(NULL, "Getting public key point from the EC private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
            ret = 1;
            goto cleanup;
        }

        /* prepare buffer for converting p to binary */
        p_bin = malloc(BN_num_bytes(p));
        NC_CHECK_ERRMEM_GOTO(!p_bin, ret = 1, cleanup);
        /* convert to binary */
        p_len = BN_bn2bin(p, p_bin);

        alg_name_len = strlen(algorithm_name);
        curve_name_len = strlen(curve_name);
        /* buffer for public key in binary, which looks like so:
         * alg_name len (4 bytes), alg_name, curve_name len (4 bytes), curve_name, PK point p len (4 bytes), PK point p
         */
        bin_len = 4 + alg_name_len + 4 + curve_name_len + 4 + p_len;
        bin = malloc(bin_len);
        NC_CHECK_ERRMEM_GOTO(!bin, ret = 1, cleanup);

        /* to network byte order (big endian) */
        alg_name_len_be = htonl(alg_name_len);
        curve_name_len_be = htonl(curve_name_len);
        p_len_be = htonl(p_len);

        /* create the public key in binary */
        bin_tmp = bin;
        memcpy(bin_tmp, &alg_name_len_be, 4);
        bin_tmp += 4;
        memcpy(bin_tmp, algorithm_name, alg_name_len);
        bin_tmp += alg_name_len;
        memcpy(bin_tmp, &curve_name_len_be, 4);
        bin_tmp += 4;
        memcpy(bin_tmp, curve_name, curve_name_len);
        bin_tmp += curve_name_len;
        memcpy(bin_tmp, &p_len_be, 4);
        bin_tmp += 4;
        memcpy(bin_tmp, p_bin, p_len);
    } else if (EVP_PKEY_is_a(pkey, "ED25519")) {
        ERR(NULL, "Generating PEM ED25519 key from OpenSSH is not supported by libssh yet.");
        ret = 1;
        goto cleanup;
    } else {
        ERR(NULL, "Unable to generate public key from private key (Private key type not supported).");
        ret = 1;
        goto cleanup;
    }

    /* convert created bin to b64 */
    ret = nc_server_config_util_pubkey_bin_to_b64(bin, bin_len, pubkey);
    if (ret) {
        ERR(NULL, "Converting public key from binary to base64 failed.");
        goto cleanup;
    }

cleanup:
    free(bin);
    free(e_bin);
    free(n_bin);
    free(ec_group);
    free(p_bin);
    BN_free(e);
    BN_free(n);
    BN_free(p);
    return ret;
}

/* spki = subject public key info */
static int
nc_server_config_util_evp_pkey_to_spki_pubkey(EVP_PKEY *pkey, char **pubkey)
{
    int ret = 0, len;
    BIO *bio = NULL;
    char *pub_b64 = NULL;

    NC_CHECK_ARG_RET(NULL, pkey, pubkey, 1);

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ERR(NULL, "Creating new BIO failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    /* write the evp_pkey contents to bio */
    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        ERR(NULL, "Writing public key to BIO failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    /* read the pubkey from bio */
    len = BIO_get_mem_data(bio, &pub_b64);
    if (len <= 0) {
        ERR(NULL, "Reading base64 private key from BIO failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    /* copy the public key without the header and footer */
    *pubkey = strndup(pub_b64 + strlen(NC_SUBJECT_PUBKEY_INFO_HEADER),
            len - strlen(NC_SUBJECT_PUBKEY_INFO_HEADER) - strlen(NC_SUBJECT_PUBKEY_INFO_FOOTER));
    NC_CHECK_ERRMEM_GOTO(!*pubkey, ret = 1, cleanup);

cleanup:
    BIO_free(bio);
    return ret;
}

int
nc_server_config_util_read_certificate(const char *cert_path, char **cert)
{
    int ret = 0, cert_len;
    X509 *x509 = NULL;
    FILE *f = NULL;
    BIO *bio = NULL;
    char *c = NULL;

    NC_CHECK_ARG_RET(NULL, cert_path, cert, 1);

    f = fopen(cert_path, "r");
    if (!f) {
        ERR(NULL, "Unable to open certificate file \"%s\".", cert_path);
        ret = 1;
        goto cleanup;
    }

    /* load the cert into memory */
    x509 = PEM_read_X509(f, NULL, NULL, NULL);
    if (!x509) {
        ret = -1;
        goto cleanup;
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ret = -1;
        goto cleanup;
    }

    ret = PEM_write_bio_X509(bio, x509);
    if (!ret) {
        ret = -1;
        goto cleanup;
    }

    cert_len = BIO_pending(bio);
    if (cert_len <= 0) {
        ret = -1;
        goto cleanup;
    }

    c = malloc(cert_len + 1);
    NC_CHECK_ERRMEM_GOTO(!c, ret = 1, cleanup);

    /* read the cert from bio */
    ret = BIO_read(bio, c, cert_len);
    if (ret <= 0) {
        ret = -1;
        goto cleanup;
    }
    c[cert_len] = '\0';

    /* strip the cert of the header and footer */
    *cert = strdup(c + strlen(NC_PEM_CERTIFICATE_HEADER));
    NC_CHECK_ERRMEM_GOTO(!*cert, ret = 1, cleanup);

    (*cert)[strlen(*cert) - strlen(NC_PEM_CERTIFICATE_FOOTER)] = '\0';

    ret = 0;

cleanup:
    if (ret == -1) {
        ERR(NULL, "Error getting certificate from file \"%s\" (OpenSSL Error): \"%s\".", cert_path, ERR_reason_error_string(ERR_get_error()));
        ret = 1;
    }
    if (f) {
        fclose(f);
    }

    BIO_free(bio);
    X509_free(x509);
    free(c);
    return ret;
}

static int
nc_server_config_util_read_pubkey_ssh2(FILE *f, char **pubkey)
{
    char *buffer = NULL;
    size_t size = 0, pubkey_len = 0;
    void *tmp;
    ssize_t read;
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, f, pubkey, 1);

    /* read lines from the file and create the public key without NL from it */
    while ((read = getline(&buffer, &size, f)) > 0) {
        if (!strncmp(buffer, "----", 4)) {
            /* skip header and footer */
            continue;
        }

        if (!strncmp(buffer, "Comment:", 8)) {
            /* skip a comment */
            continue;
        }

        if (buffer[read - 1] == '\n') {
            /* avoid NL */
            read--;
        }

        tmp = realloc(*pubkey, pubkey_len + read + 1);
        NC_CHECK_ERRMEM_GOTO(!tmp, ret = 1, cleanup);

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
nc_server_config_util_read_pubkey_openssl(FILE *f, char **pubkey)
{
    int ret = 0;
    EVP_PKEY *pub_pkey = NULL;

    NC_CHECK_ARG_RET(NULL, f, pubkey, 1);

    /* read the pubkey from file */
    pub_pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    if (!pub_pkey) {
        ERR(NULL, "Reading public key from file failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    ret = nc_server_config_util_evp_pkey_to_ssh_pubkey(pub_pkey, pubkey);

    EVP_PKEY_free(pub_pkey);
    return ret;
}

static int
nc_server_config_util_read_pubkey_libssh(const char *pubkey_path, char **pubkey)
{
    int ret = 0;
    ssh_key pub_sshkey = NULL;

    NC_CHECK_ARG_RET(NULL, pubkey_path, pubkey, 1);

    ret = ssh_pki_import_pubkey_file(pubkey_path, &pub_sshkey);
    if (ret) {
        ERR(NULL, "Importing public key from file \"%s\" failed.", pubkey_path);
        return ret;
    }

    ret = ssh_pki_export_pubkey_base64(pub_sshkey, pubkey);
    if (ret) {
        ERR(NULL, "Importing pubkey failed.");
        goto cleanup;
    }

cleanup:
    ssh_key_free(pub_sshkey);
    return 0;
}

int
nc_server_config_util_get_ssh_pubkey_file(const char *pubkey_path, char **pubkey)
{
    int ret = 0;
    FILE *f = NULL;
    char *header = NULL;
    size_t len = 0;

    NC_CHECK_ARG_RET(NULL, pubkey_path, pubkey, 1);

    *pubkey = NULL;

    f = fopen(pubkey_path, "r");
    if (!f) {
        ERR(NULL, "Unable to open file \"%s\".", pubkey_path);
        ret = 1;
        goto cleanup;
    }

    /* read the header */
    if (getline(&header, &len, f) < 0) {
        ERR(NULL, "Error reading header from file \"%s\".", pubkey_path);
        ret = 1;
        goto cleanup;
    }
    rewind(f);

    if (!strncmp(header, NC_SUBJECT_PUBKEY_INFO_HEADER, strlen(NC_SUBJECT_PUBKEY_INFO_HEADER))) {
        /* it's subject public key info public key */
        ret = nc_server_config_util_read_pubkey_openssl(f, pubkey);
    } else if (!strncmp(header, NC_SSH2_PUBKEY_HEADER, strlen(NC_SSH2_PUBKEY_HEADER))) {
        /* it's ssh2 public key */
        ret = nc_server_config_util_read_pubkey_ssh2(f, pubkey);
    } else {
        /* it's probably OpenSSH public key */
        ret = nc_server_config_util_read_pubkey_libssh(pubkey_path, pubkey);
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

int
nc_server_config_util_get_spki_pubkey_file(const char *pubkey_path, char **pubkey)
{
    int ret = 0;
    FILE *f = NULL;
    EVP_PKEY *pub_pkey = NULL;

    NC_CHECK_ARG_RET(NULL, pubkey_path, pubkey, 1);

    *pubkey = NULL;

    f = fopen(pubkey_path, "r");
    if (!f) {
        ERR(NULL, "Unable to open file \"%s\".", pubkey_path);
        ret = 1;
        goto cleanup;
    }

    /* read the pubkey from file */
    pub_pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    if (!pub_pkey) {
        ERR(NULL, "Reading public key from file failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    ret = nc_server_config_util_evp_pkey_to_spki_pubkey(pub_pkey, pubkey);
    if (ret) {
        goto cleanup;
    }

cleanup:
    if (f) {
        fclose(f);
    }

    EVP_PKEY_free(pub_pkey);
    return ret;
}

static int
nc_server_config_util_privkey_header_to_format(FILE *f_privkey, const char *privkey_path, NC_PRIVKEY_FORMAT *privkey_format)
{
    char *privkey_header = NULL;
    size_t len = 0;

    NC_CHECK_ARG_RET(NULL, f_privkey, privkey_path, privkey_format, 1);

    /* read header */
    if (getline(&privkey_header, &len, f_privkey) < 0) {
        ERR(NULL, "Error reading header from file \"%s\".", privkey_path);
        return 1;
    }

    if (!strncmp(privkey_header, NC_PKCS8_PRIVKEY_HEADER, strlen(NC_PKCS8_PRIVKEY_HEADER))) {
        /* it's PKCS8 (X.509) private key */
        *privkey_format = NC_PRIVKEY_FORMAT_X509;
    } else if (!strncmp(privkey_header, NC_OPENSSH_PRIVKEY_HEADER, strlen(NC_OPENSSH_PRIVKEY_HEADER))) {
        /* it's OpenSSH private key */
        *privkey_format = NC_PRIVKEY_FORMAT_OPENSSH;
    } else if (!strncmp(privkey_header, NC_PKCS1_RSA_PRIVKEY_HEADER, strlen(NC_PKCS1_RSA_PRIVKEY_HEADER))) {
        /* it's RSA privkey in PKCS1 format */
        *privkey_format = NC_PRIVKEY_FORMAT_RSA;
    } else if (!strncmp(privkey_header, NC_SEC1_EC_PRIVKEY_HEADER, strlen(NC_SEC1_EC_PRIVKEY_HEADER))) {
        /* it's EC privkey in SEC1 format */
        *privkey_format = NC_PRIVKEY_FORMAT_EC;
    } else {
        ERR(NULL, "Private key format (%s) not supported.", privkey_header);
        free(privkey_header);
        return 1;
    }

    /* reset the reading head */
    rewind(f_privkey);
    free(privkey_header);
    return 0;
}

static int
nc_server_config_util_get_privkey_openssl(const char *privkey_path, FILE *f_privkey, char **privkey, EVP_PKEY **pkey)
{
    int ret = 0, len;
    BIO *bio = NULL;
    char *priv_b64 = NULL;

    NC_CHECK_ARG_RET(NULL, privkey_path, f_privkey, privkey, pkey, 1);

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ERR(NULL, "Creating new BIO failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    /* read the privkey file, create EVP_PKEY */
    *pkey = PEM_read_PrivateKey(f_privkey, NULL, NULL, NULL);
    if (!*pkey) {
        ERR(NULL, "Getting private key from file \"%s\" failed (%s).", privkey_path, ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    /* write the privkey to bio */
    if (!PEM_write_bio_PrivateKey(bio, *pkey, NULL, NULL, 0, NULL, NULL)) {
        ERR(NULL, "Writing private key to BIO failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    /* read the privkey from bio */
    len = BIO_get_mem_data(bio, &priv_b64);
    if (len <= 0) {
        ERR(NULL, "Reading base64 private key from BIO failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    *privkey = strndup(priv_b64, len);
    NC_CHECK_ERRMEM_GOTO(!*privkey, ret = 1, cleanup);

cleanup:
    /* priv_b64 is freed with BIO */
    BIO_free(bio);
    return ret;
}

static int
nc_server_config_util_get_privkey_libssh(const char *privkey_path, char **privkey, EVP_PKEY **pkey)
{
    int ret = 0;
    BIO *bio = NULL;
    char *priv_b64 = NULL;
    ssh_key key = NULL;

    NC_CHECK_ARG_RET(NULL, privkey_path, privkey, pkey, 1);

    ret = ssh_pki_import_privkey_file(privkey_path, NULL, NULL, NULL, &key);
    if (ret) {
        ERR(NULL, "Importing privkey from file \"%s\" failed.", privkey_path);
        goto cleanup;
    }

    /* exports the key in a format in which OpenSSL can read it */
    ret = ssh_pki_export_privkey_base64(key, NULL, NULL, NULL, &priv_b64);
    if (ret) {
        ERR(NULL, "Exporting privkey to base64 failed.");
        goto cleanup;
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ERR(NULL, "Creating new BIO failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    ret = BIO_write(bio, priv_b64, strlen(priv_b64));
    if (ret <= 0) {
        ERR(NULL, "Writing private key to BIO failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    /* create EVP_PKEY from the b64 */
    *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!*pkey) {
        ERR(NULL, "Getting private key from file \"%s\" failed (%s).", privkey_path, ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    *privkey = strndup(priv_b64, ret);
    NC_CHECK_ERRMEM_GOTO(!*privkey, ret = 1, cleanup);

    /* ok */
    ret = 0;

cleanup:
    free(priv_b64);
    BIO_free(bio);
    ssh_key_free(key);
    return ret;
}

static int
nc_server_config_util_get_privkey(const char *privkey_path, NC_PRIVKEY_FORMAT *privkey_format, char **privkey, EVP_PKEY **pkey)
{
    int ret = 0;
    FILE *f_privkey = NULL;
    char *priv = NULL;

    NC_CHECK_ARG_RET(NULL, privkey_path, privkey_format, privkey, pkey, 1);

    f_privkey = fopen(privkey_path, "r");
    if (!f_privkey) {
        ERR(NULL, "Unable to open file \"%s\".", privkey_path);
        ret = 1;
        goto cleanup;
    }

    /* read the first line from the privkey to determine it's type */
    ret = nc_server_config_util_privkey_header_to_format(f_privkey, privkey_path, privkey_format);
    if (ret) {
        ERR(NULL, "Getting private key format from file \"%s\" failed.", privkey_path);
        goto cleanup;
    }

    switch (*privkey_format) {
    /* fall-through */
    case NC_PRIVKEY_FORMAT_RSA:
    case NC_PRIVKEY_FORMAT_EC:
    case NC_PRIVKEY_FORMAT_X509:
        /* OpenSSL solely can do this */
        ret = nc_server_config_util_get_privkey_openssl(privkey_path, f_privkey, &priv, pkey);
        break;
    case NC_PRIVKEY_FORMAT_OPENSSH:
        /* need the help of libssh */
        ret = nc_server_config_util_get_privkey_libssh(privkey_path, &priv, pkey);
        /* if the function returned successfully, the key is no longer OpenSSH, it was converted to x509 */
        *privkey_format = NC_PRIVKEY_FORMAT_X509;
        break;
    default:
        ERR(NULL, "Private key format not recognized.");
        ret = 1;
        break;
    }
    if (ret) {
        goto cleanup;
    }

    /* strip private key's header and footer */
    *privkey = strdup(priv + strlen(NC_PKCS8_PRIVKEY_HEADER));
    NC_CHECK_ERRMEM_GOTO(!*privkey, ret = 1, cleanup);
    (*privkey)[strlen(*privkey) - strlen(NC_PKCS8_PRIVKEY_FOOTER)] = '\0';

cleanup:
    if (f_privkey) {
        fclose(f_privkey);
    }

    free(priv);
    return ret;
}

int
nc_server_config_util_get_asym_key_pair(const char *privkey_path, const char *pubkey_path, NC_PUBKEY_FORMAT wanted_pubkey_format,
        char **privkey, NC_PRIVKEY_FORMAT *privkey_type, char **pubkey)
{
    int ret = 0;
    EVP_PKEY *priv_pkey = NULL;

    NC_CHECK_ARG_RET(NULL, privkey_path, privkey, privkey_type, pubkey, 1);

    *privkey = NULL;
    *pubkey = NULL;

    /* get private key base64 and EVP_PKEY */
    ret = nc_server_config_util_get_privkey(privkey_path, privkey_type, privkey, &priv_pkey);
    if (ret) {
        ERR(NULL, "Getting private key from file \"%s\" failed.", privkey_path);
        goto cleanup;
    }

    /* get public key, either from file or generate it from the EVP_PKEY */
    if (!pubkey_path) {
        if (wanted_pubkey_format == NC_PUBKEY_FORMAT_SSH) {
            ret = nc_server_config_util_evp_pkey_to_ssh_pubkey(priv_pkey, pubkey);
        } else {
            ret = nc_server_config_util_evp_pkey_to_spki_pubkey(priv_pkey, pubkey);
        }
    } else {
        if (wanted_pubkey_format == NC_PUBKEY_FORMAT_SSH) {
            ret = nc_server_config_util_get_ssh_pubkey_file(pubkey_path, pubkey);
        } else {
            ret = nc_server_config_util_get_spki_pubkey_file(pubkey_path, pubkey);
        }
    }
    if (ret) {
        if (pubkey_path) {
            ERR(NULL, "Getting public key from file \"%s\" failed.", pubkey_path);
        } else {
            ERR(NULL, "Generating public key from private key failed.");
        }
        goto cleanup;
    }

cleanup:
    EVP_PKEY_free(priv_pkey);
    return ret;
}

API int
nc_server_config_add_address_port(const struct ly_ctx *ctx, const char *endpt_name, NC_TRANSPORT_IMPL transport,
        const char *address, uint16_t port, struct lyd_node **config)
{
    int ret = 0;
    const char *address_fmt, *port_fmt;
    char port_buf[6] = {0};

    NC_CHECK_ARG_RET(NULL, ctx, endpt_name, address, config, 1);

    if (transport == NC_TI_LIBSSH) {
        /* SSH path */
        address_fmt = "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/tcp-server-parameters/local-address";
        port_fmt = "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/ssh/tcp-server-parameters/local-port";
    } else if (transport == NC_TI_OPENSSL) {
        /* TLS path */
        address_fmt = "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/tcp-server-parameters/local-address";
        port_fmt = "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']/tls/tcp-server-parameters/local-port";
    } else {
        ERR(NULL, "Can not set address and port of a non SSH/TLS endpoint.");
        ret = 1;
        goto cleanup;
    }

    ret = nc_server_config_create(ctx, config, address, address_fmt, endpt_name);
    if (ret) {
        goto cleanup;
    }

    sprintf(port_buf, "%d", port);
    ret = nc_server_config_create(ctx, config, port_buf, port_fmt, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_add_ch_address_port(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        NC_TRANSPORT_IMPL transport, const char *address, const char *port, struct lyd_node **config)
{
    int ret = 0;
    const char *address_fmt, *port_fmt;

    NC_CHECK_ARG_RET(NULL, ctx, client_name, endpt_name, address, port, config, 1);

    if (transport == NC_TI_LIBSSH) {
        /* SSH path */
        address_fmt = "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/tcp-client-parameters/remote-address";
        port_fmt = "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/endpoint[name='%s']/ssh/tcp-client-parameters/remote-port";
    } else if (transport == NC_TI_OPENSSL) {
        /* TLS path */
        address_fmt = "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tcp-client-parameters/remote-address";
        port_fmt = "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/endpoint[name='%s']/tls/tcp-client-parameters/remote-port";
    } else {
        ERR(NULL, "Transport not supported.");
        ret = 1;
        goto cleanup;
    }

    ret = nc_server_config_create(ctx, config, address, address_fmt, client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_create(ctx, config, port, port_fmt, client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_del_endpt(const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, config, 1);

    if (endpt_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='%s']", endpt_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint");
    }
}

API int
nc_server_config_del_ch_client(const char *ch_client_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, config, 1);

    if (ch_client_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']", ch_client_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client");
    }
}

API int
nc_server_config_del_ch_endpt(const char *client_name, const char *endpt_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, client_name, config, 1);

    if (endpt_name) {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint[name='%s']", client_name, endpt_name);
    } else {
        return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/"
                "endpoints/endpoint", client_name);
    }
}

API int
nc_server_config_add_keystore_asym_key(const struct ly_ctx *ctx, NC_TRANSPORT_IMPL ti, const char *asym_key_name,
        const char *privkey_path, const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *privkey = NULL, *pubkey = NULL;
    NC_PRIVKEY_FORMAT privkey_type;
    const char *privkey_format, *pubkey_format;

    NC_CHECK_ARG_RET(NULL, ctx, asym_key_name, privkey_path, config, 1);

    /* get the keys as a string from the given files */
    if (ti == NC_TI_LIBSSH) {
        ret = nc_server_config_util_get_asym_key_pair(privkey_path, pubkey_path, NC_PUBKEY_FORMAT_SSH, &privkey,
                &privkey_type, &pubkey);
    } else if (ti == NC_TI_OPENSSL) {
        ret = nc_server_config_util_get_asym_key_pair(privkey_path, pubkey_path, NC_PUBKEY_FORMAT_X509, &privkey,
                &privkey_type, &pubkey);
    } else {
        ERR(NULL, "Only SSH and TLS transports can be used to create an asymmetric key pair in the keystore.");
        ret = 1;
        goto cleanup;
    }
    if (ret) {
        ERR(NULL, "Getting keys from file(s) failed.");
        goto cleanup;
    }

    /* get pubkey format str */
    if (ti == NC_TI_LIBSSH) {
        pubkey_format = "ietf-crypto-types:ssh-public-key-format";
    } else {
        pubkey_format = "ietf-crypto-types:subject-public-key-info-format";
    }

    /* get privkey identityref value */
    privkey_format = nc_server_config_util_privkey_format_to_identityref(privkey_type);
    if (!privkey_format) {
        ret = 1;
        goto cleanup;
    }

    ret = nc_server_config_create(ctx, config, pubkey_format, "/ietf-keystore:keystore/asymmetric-keys/"
            "asymmetric-key[name='%s']/public-key-format", asym_key_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_create(ctx, config, pubkey, "/ietf-keystore:keystore/asymmetric-keys/"
            "asymmetric-key[name='%s']/public-key", asym_key_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_create(ctx, config, privkey_format, "/ietf-keystore:keystore/asymmetric-keys/"
            "asymmetric-key[name='%s']/private-key-format", asym_key_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_create(ctx, config, privkey, "/ietf-keystore:keystore/asymmetric-keys/"
            "asymmetric-key[name='%s']/cleartext-private-key", asym_key_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(privkey);
    free(pubkey);
    return ret;
}

API int
nc_server_config_del_keystore_asym_key(const char *asym_key_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, config, 1);

    if (asym_key_name) {
        return nc_server_config_delete(config, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='%s']", asym_key_name);
    } else {
        return nc_server_config_delete(config, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key");
    }
}

API int
nc_server_config_add_keystore_cert(const struct ly_ctx *ctx, const char *asym_key_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *cert = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, asym_key_name, cert_name, cert_path, config, 1);

    /* get cert data */
    ret = nc_server_config_util_read_certificate(cert_path, &cert);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_create(ctx, config, cert, "/ietf-keystore:keystore/asymmetric-keys/"
            "asymmetric-key[name='%s']/certificates/certificate[name='%s']/cert-data", asym_key_name, cert_name);

cleanup:
    free(cert);
    return ret;
}

API int
nc_server_config_del_keystore_cert(const char *asym_key_name, const char *cert_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, asym_key_name, config, 1);

    if (cert_name) {
        return nc_server_config_delete(config, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='%s']/"
                "certificates/certificate[name='%s']", asym_key_name, cert_name);
    } else {
        return nc_server_config_delete(config, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='%s']/"
                "certificates/certificate", asym_key_name);
    }
}

API int
nc_server_config_add_truststore_pubkey(const struct ly_ctx *ctx, const char *pub_bag_name, const char *pubkey_name,
        const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL;
    const char *pubkey_format = "ietf-crypto-types:ssh-public-key-format";

    NC_CHECK_ARG_RET(NULL, ctx, pub_bag_name, pubkey_name, pubkey_path, config, 1);

    ret = nc_server_config_util_get_ssh_pubkey_file(pubkey_path, &pubkey);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_create(ctx, config, pubkey_format, "/ietf-truststore:truststore/public-key-bags/"
            "public-key-bag[name='%s']/public-key[name='%s']/public-key-format", pub_bag_name, pubkey_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_create(ctx, config, pubkey, "/ietf-truststore:truststore/public-key-bags/"
            "public-key-bag[name='%s']/public-key[name='%s']/public-key", pub_bag_name, pubkey_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(pubkey);
    return ret;
}

API int
nc_server_config_del_truststore_pubkey(const char *pub_bag_name,
        const char *pubkey_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, pub_bag_name, config, 1);

    if (pubkey_name) {
        return nc_server_config_delete(config, "/ietf-truststore:truststore/public-key-bags/"
                "public-key-bag[name='%s']/public-key[name='%s']", pub_bag_name, pubkey_name);
    } else {
        return nc_server_config_delete(config, "/ietf-truststore:truststore/public-key-bags/"
                "public-key-bag[name='%s']/public-key", pub_bag_name);
    }
}

API int
nc_server_config_add_truststore_cert(const struct ly_ctx *ctx, const char *cert_bag_name, const char *cert_name,
        const char *cert_path, struct lyd_node **config)
{
    int ret = 0;
    char *cert = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, cert_bag_name, cert_name, cert_path, config, 1);

    ret = nc_server_config_util_read_certificate(cert_path, &cert);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_create(ctx, config, cert, "/ietf-truststore:truststore/certificate-bags/"
            "certificate-bag[name='%s']/certificate[name='%s']/cert-data", cert_bag_name, cert_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(cert);
    return ret;
}

API int
nc_server_config_del_truststore_cert(const char *cert_bag_name,
        const char *cert_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, cert_bag_name, config, 1);

    if (cert_name) {
        return nc_server_config_delete(config, "/ietf-truststore:truststore/certificate-bags/"
                "certificate-bag[name='%s']/certificate[name='%s']", cert_bag_name, cert_name);
    } else {
        return nc_server_config_delete(config, "/ietf-truststore:truststore/certificate-bags/"
                "certificate-bag[name='%s']/certificate", cert_bag_name);
    }
}

#endif /* NC_ENABLED_SSH_TLS */

API int
nc_server_config_add_ch_persistent(const struct ly_ctx *ctx, const char *ch_client_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, ch_client_name, config, 1);

    /* delete periodic tree if exists */
    if (nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/periodic", ch_client_name)) {
        return 1;
    }

    return nc_server_config_create(ctx, config, NULL, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/persistent", ch_client_name);
}

API int
nc_server_config_add_ch_period(const struct ly_ctx *ctx, const char *ch_client_name, uint16_t period,
        struct lyd_node **config)
{
    char buf[6] = {0};

    NC_CHECK_ARG_RET(NULL, ctx, ch_client_name, config, 1);

    /* delete persistent tree if exists */
    if (nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/persistent", ch_client_name)) {
        return 1;
    }

    sprintf(buf, "%" PRIu16, period);
    return nc_server_config_create(ctx, config, buf, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/periodic/period", ch_client_name);
}

API int
nc_server_config_del_ch_period(const char *ch_client_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ch_client_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/periodic/period", ch_client_name);
}

API int
nc_server_config_add_ch_anchor_time(const struct ly_ctx *ctx, const char *ch_client_name,
        const char *anchor_time, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, ch_client_name, anchor_time, config, 1);

    /* delete persistent tree if exists */
    if (nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/persistent", ch_client_name)) {
        return 1;
    }

    return nc_server_config_create(ctx, config, anchor_time, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/periodic/anchor-time", ch_client_name);
}

API int
nc_server_config_del_ch_anchor_time(const char *ch_client_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ch_client_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/periodic/anchor-time", ch_client_name);
}

API int
nc_server_config_add_ch_idle_timeout(const struct ly_ctx *ctx, const char *ch_client_name,
        uint16_t idle_timeout, struct lyd_node **config)
{
    char buf[6] = {0};

    NC_CHECK_ARG_RET(NULL, ctx, ch_client_name, config, 1);

    /* delete persistent tree if exists */
    if (nc_server_config_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/persistent", ch_client_name)) {
        return 1;
    }

    sprintf(buf, "%" PRIu16, idle_timeout);
    return nc_server_config_create(ctx, config, buf, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/periodic/idle-timeout", ch_client_name);
}

API int
nc_server_config_del_ch_idle_timeout(const char *ch_client_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ch_client_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/periodic/idle-timeout", ch_client_name);
}

API int
nc_server_config_add_ch_reconnect_strategy(const struct ly_ctx *ctx, const char *ch_client_name,
        NC_CH_START_WITH start_with, uint16_t max_wait, uint8_t max_attempts, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;
    char buf[6] = {0};
    const char *start_with_val;

    NC_CHECK_ARG_RET(NULL, ctx, ch_client_name, config, 1);

    /* prepared the path */
    ret = asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/reconnect-strategy", ch_client_name);
    NC_CHECK_ERRMEM_GOTO(ret == -1, path = NULL; ret = 1, cleanup);

    /* get string value from enum */
    if (start_with == NC_CH_FIRST_LISTED) {
        start_with_val = "first-listed";
    } else if (start_with == NC_CH_LAST_CONNECTED) {
        start_with_val = "last-connected";
    } else if (start_with == NC_CH_RANDOM) {
        start_with_val = "random-selection";
    } else {
        ERR(NULL, "Unknown reconnect strategy.");
        goto cleanup;
    }

    ret = nc_server_config_append(ctx, path, "start-with", start_with_val, config);
    if (ret) {
        goto cleanup;
    }

    if (max_attempts) {
        sprintf(buf, "%" PRIu8, max_attempts);
        ret = nc_server_config_append(ctx, path, "max-attempts", buf, config);
        if (ret) {
            goto cleanup;
        }
        memset(buf, 0, 6);
    }

    if (max_wait) {
        sprintf(buf, "%" PRIu16, max_wait);
        ret = nc_server_config_append(ctx, path, "max-wait", buf, config);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    free(path);
    return ret;
}

API int
nc_server_config_del_ch_reconnect_strategy(const char *ch_client_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ch_client_name, config, 1);

    return nc_server_config_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/reconnect-strategy", ch_client_name);
}
