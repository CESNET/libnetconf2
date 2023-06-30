/**
 * @file config_new.c
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

#include <libyang/libyang.h>
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
#include "config_new.h"
#include "log_p.h"
#include "session.h"
#include "session_p.h"

#ifdef NC_ENABLED_SSH_TLS

const char *
nc_config_new_privkey_format_to_identityref(NC_PRIVKEY_FORMAT format)
{
    switch (format) {
    case NC_PRIVKEY_FORMAT_RSA:
        return "ietf-crypto-types:rsa-private-key-format";
    case NC_PRIVKEY_FORMAT_EC:
        return "ietf-crypto-types:ec-private-key-format";
    case NC_PRIVKEY_FORMAT_X509:
        return "libnetconf2-netconf-server:subject-private-key-info-format";
    case NC_PRIVKEY_FORMAT_OPENSSH:
        return "libnetconf2-netconf-server:openssh-private-key-format";
    default:
        ERR(NULL, "Private key type not supported.");
        return NULL;
    }
}

int
nc_server_config_new_read_certificate(const char *cert_path, char **cert)
{
    int ret = 0, cert_len;
    X509 *x509 = NULL;
    FILE *f = NULL;
    BIO *bio = NULL;
    char *c = NULL;

    *cert = NULL;

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
    if (!c) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* read the cert from bio */
    ret = BIO_read(bio, c, cert_len);
    if (ret <= 0) {
        ret = -1;
        goto cleanup;
    }
    c[cert_len] = '\0';

    /* strip the cert of the header and footer */
    *cert = strdup(c + strlen(NC_PEM_CERTIFICATE_HEADER));
    if (!*cert) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

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
nc_server_config_new_read_ssh2_pubkey(FILE *f, char **pubkey)
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
nc_server_config_new_read_pubkey_openssl(FILE *f, char **pubkey)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
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
nc_server_config_new_read_pubkey_libssh(const char *pubkey_path, char **pubkey)
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

int
nc_server_config_new_get_pubkey(const char *pubkey_path, char **pubkey, NC_PUBKEY_FORMAT *pubkey_type)
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
        ret = nc_server_config_new_read_pubkey_openssl(f, pubkey);
        *pubkey_type = NC_PUBKEY_FORMAT_X509;
    } else if (!strncmp(header, NC_SSH2_PUBKEY_HEADER, strlen(NC_SSH2_PUBKEY_HEADER))) {
        /* it's ssh2 public key */
        ret = nc_server_config_new_read_ssh2_pubkey(f, pubkey);
        *pubkey_type = NC_PUBKEY_FORMAT_SSH2;
    } else {
        /* it's probably OpenSSH public key */
        ret = nc_server_config_new_read_pubkey_libssh(pubkey_path, pubkey);
        *pubkey_type = NC_PUBKEY_FORMAT_SSH2;
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
nc_server_config_new_get_privkey_openssl(FILE *f, char **privkey, EVP_PKEY **priv_pkey)
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
nc_server_config_new_privkey_to_pubkey_openssl(EVP_PKEY *priv_pkey, char **pubkey)
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
nc_server_config_new_privkey_to_pubkey_libssh(const ssh_key priv_sshkey, char **pubkey)
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
nc_server_config_new_privkey_to_pubkey(EVP_PKEY *priv_pkey, const ssh_key priv_sshkey, NC_PRIVKEY_FORMAT privkey_type, char **pubkey, NC_PUBKEY_FORMAT *pubkey_type)
{
    switch (privkey_type) {
    case NC_PRIVKEY_FORMAT_RSA:
    case NC_PRIVKEY_FORMAT_EC:
    case NC_PRIVKEY_FORMAT_OPENSSH:
        *pubkey_type = NC_PUBKEY_FORMAT_SSH2;
        return nc_server_config_new_privkey_to_pubkey_libssh(priv_sshkey, pubkey);
    case NC_PRIVKEY_FORMAT_X509:
        *pubkey_type = NC_PUBKEY_FORMAT_X509;
        return nc_server_config_new_privkey_to_pubkey_openssl(priv_pkey, pubkey);
    default:
        break;
    }

    return 1;
}

static int
nc_server_config_new_get_privkey_libssh(const char *privkey_path, char **privkey, ssh_key *priv_sshkey)
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

int
nc_server_config_new_get_keys(const char *privkey_path, const char *pubkey_path,
        char **privkey, char **pubkey, NC_PRIVKEY_FORMAT *privkey_type, NC_PUBKEY_FORMAT *pubkey_type)
{
    int ret = 0;
    EVP_PKEY *priv_pkey = NULL;
    ssh_key priv_sshkey = NULL;
    FILE *f_privkey = NULL;
    char *header = NULL;
    size_t len = 0;
    char *priv = NULL, *pub = NULL;

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
        *privkey_type = NC_PRIVKEY_FORMAT_X509;
        ret = nc_server_config_new_get_privkey_openssl(f_privkey, &priv, &priv_pkey);
    } else if (!strncmp(header, NC_OPENSSH_PRIVKEY_HEADER, strlen(NC_OPENSSH_PRIVKEY_HEADER))) {
        /* it's OpenSSH private key */
        *privkey_type = NC_PRIVKEY_FORMAT_OPENSSH;
        ret = nc_server_config_new_get_privkey_libssh(privkey_path, &priv, &priv_sshkey);
    } else if (!strncmp(header, NC_PKCS1_RSA_PRIVKEY_HEADER, strlen(NC_PKCS1_RSA_PRIVKEY_HEADER))) {
        /* it's RSA privkey in PKCS1 format */
        *privkey_type = NC_PRIVKEY_FORMAT_RSA;
        ret = nc_server_config_new_get_privkey_libssh(privkey_path, &priv, &priv_sshkey);
    } else if (!strncmp(header, NC_SEC1_EC_PRIVKEY_HEADER, strlen(NC_SEC1_EC_PRIVKEY_HEADER))) {
        /* it's EC privkey in SEC1 format */
        *privkey_type = NC_PRIVKEY_FORMAT_EC;
        ret = nc_server_config_new_get_privkey_libssh(privkey_path, &priv, &priv_sshkey);
    } else {
        ERR(NULL, "Private key format not supported.");
        ret = 1;
        goto cleanup;
    }
    if (ret) {
        goto cleanup;
    }

    if (pubkey_path) {
        ret = nc_server_config_new_get_pubkey(pubkey_path, &pub, pubkey_type);
    } else {
        ret = nc_server_config_new_privkey_to_pubkey(priv_pkey, priv_sshkey, *privkey_type, &pub, pubkey_type);
    }
    if (ret) {
        ERR(NULL, "Getting public key failed.");
        goto cleanup;
    }

    /* strip pubkey's header and footer only if it's generated from pkcs8 key (using OpenSSL),
     * otherwise it's already stripped
     */
    if (!pubkey_path && (*privkey_type == NC_PRIVKEY_FORMAT_X509)) {
        *pubkey = strdup(pub + strlen(NC_SUBJECT_PUBKEY_INFO_HEADER));
        if (!*pubkey) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }
        (*pubkey)[strlen(*pubkey) - strlen(NC_SUBJECT_PUBKEY_INFO_FOOTER)] = '\0';
    } else {
        *pubkey = strdup(pub);
        if (!*pubkey) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }
    }

    /* strip private key's header and footer */
    if (*privkey_type == NC_PRIVKEY_FORMAT_OPENSSH) {
        /* only OpenSSH private keys have different header and footer after processing */
        *privkey = strdup(priv + strlen(NC_OPENSSH_PRIVKEY_HEADER));
        if (!*privkey) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }
        (*privkey)[strlen(*privkey) - strlen(NC_OPENSSH_PRIVKEY_FOOTER)] = '\0';
    } else {
        /* the rest share the same header and footer */
        *privkey = strdup(priv + strlen(NC_PKCS8_PRIVKEY_HEADER));
        if (!*privkey) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }
        (*privkey)[strlen(*privkey) - strlen(NC_PKCS8_PRIVKEY_FOOTER)] = '\0';
    }

cleanup:
    if (f_privkey) {
        fclose(f_privkey);
    }

    free(header);
    free(pub);
    free(priv);

    ssh_key_free(priv_sshkey);
    EVP_PKEY_free(priv_pkey);

    return ret;
}

API int
nc_server_config_new_address_port(const struct ly_ctx *ctx, const char *endpt_name, NC_TRANSPORT_IMPL transport,
        const char *address, uint16_t port, struct lyd_node **config)
{
    int ret = 0;
    const char *address_fmt, *port_fmt;
    char port_buf[6] = {0};

    NC_CHECK_ARG_RET(NULL, address, ctx, endpt_name, config, 1);

    if (transport == NC_TI_LIBSSH) {
        /* SSH path */
        address_fmt = "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/tcp-server-parameters/local-address";
        port_fmt = "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/ssh/tcp-server-parameters/local-port";
    } else if (transport == NC_TI_OPENSSL) {
        /* TLS path */
        address_fmt = "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tcp-server-parameters/local-address";
        port_fmt = "/ietf-netconf-server:netconf-server/listen/endpoint[name='%s']/tls/tcp-server-parameters/local-port";
    } else {
        ERR(NULL, "Transport not supported.");
        ret = 1;
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, address, address_fmt, endpt_name);
    if (ret) {
        goto cleanup;
    }

    sprintf(port_buf, "%d", port);
    ret = nc_config_new_create(ctx, config, port_buf, port_fmt, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_ch_address_port(const struct ly_ctx *ctx, const char *ch_client_name, const char *endpt_name,
        NC_TRANSPORT_IMPL transport, const char *address, const char *port, struct lyd_node **config)
{
    int ret = 0;
    const char *address_fmt, *port_fmt;

    NC_CHECK_ARG_RET(NULL, address, port, ctx, endpt_name, config, 1);

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

    ret = nc_config_new_create(ctx, config, address, address_fmt, ch_client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, port, port_fmt, ch_client_name, endpt_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    return ret;
}

API int
nc_server_config_new_del_ch_client(const struct ly_ctx *ctx, const char *ch_client_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, ch_client_name, config, 1);

    return nc_config_new_delete(config, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']", ch_client_name);
}

API int
nc_server_config_new_keystore_asym_key(const struct ly_ctx *ctx, const char *name, const char *privkey_path,
        const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *privkey = NULL, *pubkey = NULL;
    NC_PRIVKEY_FORMAT privkey_type;
    NC_PUBKEY_FORMAT pubkey_type;
    const char *privkey_format, *pubkey_format;

    NC_CHECK_ARG_RET(NULL, ctx, name, privkey_path, config, 1);

    /* get the keys as a string from the given files */
    ret = nc_server_config_new_get_keys(privkey_path, pubkey_path, &privkey, &pubkey, &privkey_type, &pubkey_type);
    if (ret) {
        ERR(NULL, "Getting keys from file(s) failed.");
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

    ret = nc_config_new_create(ctx, config, pubkey_format, "/ietf-keystore:keystore/asymmetric-keys/"
            "asymmetric-key[name='%s']/public-key-format", name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, pubkey, "/ietf-keystore:keystore/asymmetric-keys/"
            "asymmetric-key[name='%s']/public-key", name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, privkey_format, "/ietf-keystore:keystore/asymmetric-keys/"
            "asymmetric-key[name='%s']/private-key-format", name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, privkey, "/ietf-keystore:keystore/asymmetric-keys/"
            "asymmetric-key[name='%s']/cleartext-private-key", name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(privkey);
    free(pubkey);
    return ret;
}

API int
nc_server_config_new_truststore_pubkey(const struct ly_ctx *ctx, const char *bag_name, const char *pubkey_name,
        const char *pubkey_path, struct lyd_node **config)
{
    int ret = 0;
    char *pubkey = NULL;
    NC_PUBKEY_FORMAT pubkey_format;
    const char *format;

    NC_CHECK_ARG_RET(NULL, ctx, bag_name, pubkey_name, pubkey_path, config, 1);

    ret = nc_server_config_new_get_pubkey(pubkey_path, &pubkey, &pubkey_format);
    if (ret) {
        goto cleanup;
    }

    /* pubkey format to str */
    if (pubkey_format == NC_PUBKEY_FORMAT_SSH2) {
        format = "ietf-crypto-types:ssh-public-key-format";
    } else {
        format = "ietf-crypto-types:subject-public-key-info-format";
    }

    ret = nc_config_new_create(ctx, config, format, "/ietf-truststore:truststore/public-key-bags/"
            "public-key-bag[name='%s']/public-key[name='%s']/public-key-format", bag_name, pubkey_name);
    if (ret) {
        goto cleanup;
    }

    ret = nc_config_new_create(ctx, config, pubkey, "/ietf-truststore:truststore/public-key-bags/"
            "public-key-bag[name='%s']/public-key[name='%s']/public-key", bag_name, pubkey_name);
    if (ret) {
        goto cleanup;
    }

cleanup:
    free(pubkey);
    return ret;
}

#endif /* NC_ENABLED_SSH_TLS */

int
nc_config_new_delete(struct lyd_node **tree, const char *path_fmt, ...)
{
    int ret = 0;
    va_list ap;
    char *path = NULL;
    struct lyd_node *sub = NULL;

    va_start(ap, path_fmt);

    /* create the path from the format */
    ret = vasprintf(&path, path_fmt, ap);
    if (ret == -1) {
        ERRMEM;
        path = NULL;
        goto cleanup;
    }

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
nc_config_new_create(const struct ly_ctx *ctx, struct lyd_node **tree, const char *value, const char *path_fmt, ...)
{
    int ret = 0;
    va_list ap;
    char *path = NULL;

    va_start(ap, path_fmt);

    /* create the path from the format */
    ret = vasprintf(&path, path_fmt, ap);
    if (ret == -1) {
        ERRMEM;
        path = NULL;
        goto cleanup;
    }

    /* create the nodes in the path */
    ret = lyd_new_path(*tree, ctx, path, value, LYD_NEW_PATH_UPDATE, tree);
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
nc_config_new_create_append(const struct ly_ctx *ctx, const char *parent_path, const char *child_name,
        const char *value, struct lyd_node **tree)
{
    int ret = 0;
    char *path = NULL;

    /* create the path by appending child to the parent path */
    ret = asprintf(&path, "%s/%s", parent_path, child_name);
    if (ret == -1) {
        ERRMEM;
        path = NULL;
        goto cleanup;
    }

    /* create the nodes in the path */
    ret = lyd_new_path(*tree, ctx, path, value, LYD_NEW_PATH_UPDATE, tree);
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
nc_config_new_check_delete(struct lyd_node **tree, const char *path_fmt, ...)
{
    int ret = 0;
    va_list ap;
    char *path = NULL;
    struct lyd_node *sub = NULL;

    va_start(ap, path_fmt);

    /* create the path from the format */
    ret = vasprintf(&path, path_fmt, ap);
    if (ret == -1) {
        ERRMEM;
        path = NULL;
        goto cleanup;
    }

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

API int
nc_server_config_new_ch_persistent(const struct ly_ctx *ctx, const char *ch_client_name, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, ch_client_name, config, 1);

    /* delete periodic tree if exists */
    if (nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/periodic", ch_client_name)) {
        return 1;
    }

    return nc_config_new_create(ctx, config, NULL, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/persistent", ch_client_name);
}

API int
nc_server_config_new_ch_period(const struct ly_ctx *ctx, const char *ch_client_name, uint16_t period,
        struct lyd_node **config)
{
    char buf[6] = {0};

    NC_CHECK_ARG_RET(NULL, ctx, ch_client_name, period, 1);

    /* delete persistent tree if exists */
    if (nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/persistent", ch_client_name)) {
        return 1;
    }

    sprintf(buf, "%u", period);
    return nc_config_new_create(ctx, config, buf, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/periodic/period", ch_client_name);
}

API int
nc_server_config_new_ch_anchor_time(const struct ly_ctx *ctx, const char *ch_client_name,
        const char *anchor_time, struct lyd_node **config)
{
    NC_CHECK_ARG_RET(NULL, ctx, ch_client_name, anchor_time, 1);

    /* delete persistent tree if exists */
    if (nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/persistent", ch_client_name)) {
        return 1;
    }

    return nc_config_new_create(ctx, config, anchor_time, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/periodic/anchor-time", ch_client_name);
}

API int
nc_server_config_new_ch_idle_timeout(const struct ly_ctx *ctx, const char *ch_client_name,
        uint16_t idle_timeout, struct lyd_node **config)
{
    char buf[6] = {0};

    NC_CHECK_ARG_RET(NULL, ctx, ch_client_name, 1);

    /* delete persistent tree if exists */
    if (nc_config_new_check_delete(config, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/persistent", ch_client_name)) {
        return 1;
    }

    sprintf(buf, "%u", idle_timeout);
    return nc_config_new_create(ctx, config, buf, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/connection-type/periodic/idle-timeout", ch_client_name);
}

API int
nc_server_config_new_ch_reconnect_strategy(const struct ly_ctx *ctx, const char *ch_client_name,
        NC_CH_START_WITH start_with, uint8_t max_attempts, uint16_t max_wait, struct lyd_node **config)
{
    int ret = 0;
    char *path = NULL;
    char buf[6] = {0};
    const char *start_with_val;

    NC_CHECK_ARG_RET(NULL, ctx, ch_client_name, config, 1);

    /* prepared the path */
    if (asprintf(&path, "/ietf-netconf-server:netconf-server/call-home/"
            "netconf-client[name='%s']/reconnect-strategy", ch_client_name) == -1) {
        ERRMEM;
        path = NULL;
        ret = 1;
        goto cleanup;
    }

    if (start_with) {
        /* get string value from enum */
        if (start_with == NC_CH_FIRST_LISTED) {
            start_with_val = "first-listed";
        } else if (start_with == NC_CH_LAST_CONNECTED) {
            start_with_val = "last-connected";
        } else {
            start_with_val = "random-selection";
        }

        ret = nc_config_new_create_append(ctx, path, "start-with", start_with_val, config);
        if (ret) {
            goto cleanup;
        }
    }

    if (max_attempts) {
        sprintf(buf, "%u", max_attempts);
        ret = nc_config_new_create_append(ctx, path, "max-attempts", buf, config);
        if (ret) {
            goto cleanup;
        }
        memset(buf, 0, 6);
    }

    if (max_wait) {
        sprintf(buf, "%u", max_wait);
        ret = nc_config_new_create_append(ctx, path, "max-wait", buf, config);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    free(path);
    return ret;
}
