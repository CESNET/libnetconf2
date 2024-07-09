/**
 * @file session_openssl.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 - wrapped OpenSSL function calls for TLS/asymmetric cryptography support
 *
 * This file is a wrapper for OpenSSL function calls. The implementation is done
 * in such a way that the original libnetconf2 code is not dependent on OpenSSL.
 * This file is included in the build process only if OpenSSL is being used.
 *
 * @copyright
 * Copyright (c) 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "session.h"
#include "session_p.h"
#include "session_wrapper.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

void *
nc_tls_session_new_wrap(void *tls_cfg)
{
    SSL *session;

    session = SSL_new(tls_cfg);
    if (!session) {
        ERR(NULL, "Setting up TLS session failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }

    return session;
}

void
nc_tls_session_destroy_wrap(void *tls_session)
{
    SSL_free(tls_session);
}

void *
nc_tls_config_new_wrap(int side)
{
    SSL_CTX *tls_cfg;

    if ((side != NC_SERVER) && (side != NC_CLIENT)) {
        ERRINT;
        return NULL;
    }

    if (side == NC_SERVER) {
        tls_cfg = SSL_CTX_new(TLS_server_method());
    } else {
        tls_cfg = SSL_CTX_new(TLS_client_method());
    }
    NC_CHECK_ERRMEM_RET(!tls_cfg, NULL)

    return tls_cfg;
}

void
nc_tls_config_destroy_wrap(void *tls_cfg)
{
    SSL_CTX_free(tls_cfg);
}

void *
nc_tls_cert_new_wrap(void)
{
    X509 *cert;

    cert = X509_new();
    NC_CHECK_ERRMEM_RET(!cert, NULL)

    return cert;
}

void
nc_tls_cert_destroy_wrap(void *cert)
{
    X509_free(cert);
}

void
nc_tls_privkey_destroy_wrap(void *pkey)
{
    EVP_PKEY_free(pkey);
}

void *
nc_tls_cert_store_new_wrap(void)
{
    X509_STORE *store;

    store = X509_STORE_new();
    NC_CHECK_ERRMEM_RET(!store, NULL);

    return store;
}

void
nc_tls_cert_store_destroy_wrap(void *cert_store)
{
    X509_STORE_free(cert_store);
}

void *
nc_tls_crl_store_new_wrap(void)
{
    return nc_tls_cert_store_new_wrap();
}

void
nc_tls_crl_store_destroy_wrap(void *crl_store)
{
    X509_STORE_free(crl_store);
}

void *
nc_tls_pem_to_cert_wrap(const char *cert_data)
{
    BIO *bio;
    X509 *cert;

    bio = BIO_new_mem_buf(cert_data, strlen(cert_data));
    if (!bio) {
        ERR(NULL, "Creating new bio failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        ERR(NULL, "Parsing certificate data failed (%s).", ERR_reason_error_string(ERR_get_error()));
    }
    BIO_free(bio);
    return cert;
}

int
nc_tls_add_cert_to_store_wrap(void *cert, void *cert_store)
{
    int rc;

    /* on success increases ref count to cert, so free it */
    rc = X509_STORE_add_cert(cert_store, cert);
    if (!rc) {
        ERR(NULL, "Adding certificate to store failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    X509_free(cert);
    return 0;
}

void *
nc_tls_pem_to_privkey_wrap(const char *privkey_data)
{
    BIO *bio;
    EVP_PKEY *pkey;

    bio = BIO_new_mem_buf(privkey_data, strlen(privkey_data));
    if (!bio) {
        ERR(NULL, "Creating new bio failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        ERR(NULL, "Parsing certificate data failed (%s).", ERR_reason_error_string(ERR_get_error()));
    }
    BIO_free(bio);
    return pkey;
}

int
nc_server_tls_add_crl_to_store_wrap(const unsigned char *crl_data, size_t size, void *crl_store)
{
    int ret = 0;
    X509_CRL *crl = NULL;
    BIO *bio = NULL;

    bio = BIO_new_mem_buf(crl_data, size);
    if (!bio) {
        ERR(NULL, "Creating new bio failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    /* try DER first */
    crl = d2i_X509_CRL_bio(bio, NULL);
    if (crl) {
        /* it was DER */
        goto ok;
    }

    /* DER failed, try PEM next */
    crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
    if (!crl) {
        ERR(NULL, "Parsing downloaded CRL failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

ok:
    /* we obtained the CRL, now add it to the CRL store */
    ret = X509_STORE_add_crl(crl_store, crl);
    if (!ret) {
        ERR(NULL, "Error adding CRL to store (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }
    /* ok */
    ret = 0;

cleanup:
    X509_CRL_free(crl);
    BIO_free(bio);
    return ret;
}

int
nc_server_tls_set_tls_versions_wrap(void *tls_cfg, unsigned int tls_versions)
{
    int rc = 1;

    /* first set the minimum version */
    if (tls_versions & NC_TLS_VERSION_10) {
        rc = SSL_CTX_set_min_proto_version(tls_cfg, TLS1_VERSION);
    } else if (tls_versions & NC_TLS_VERSION_11) {
        rc = SSL_CTX_set_min_proto_version(tls_cfg, TLS1_1_VERSION);
    } else if (tls_versions & NC_TLS_VERSION_12) {
        rc = SSL_CTX_set_min_proto_version(tls_cfg, TLS1_2_VERSION);
    } else if (tls_versions & NC_TLS_VERSION_13) {
        rc = SSL_CTX_set_min_proto_version(tls_cfg, TLS1_3_VERSION);
    }
    if (!rc) {
        ERR(NULL, "Setting TLS min version failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    /* then set the maximum version */
    if (tls_versions & NC_TLS_VERSION_13) {
        rc = SSL_CTX_set_max_proto_version(tls_cfg, TLS1_3_VERSION);
    } else if (tls_versions & NC_TLS_VERSION_12) {
        rc = SSL_CTX_set_max_proto_version(tls_cfg, TLS1_2_VERSION);
    } else if (tls_versions & NC_TLS_VERSION_11) {
        rc = SSL_CTX_set_max_proto_version(tls_cfg, TLS1_1_VERSION);
    } else if (tls_versions & NC_TLS_VERSION_10) {
        rc = SSL_CTX_set_max_proto_version(tls_cfg, TLS1_VERSION);
    }
    if (!rc) {
        ERR(NULL, "Setting TLS max version failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    return 0;
}

/**
 * @brief Verify a certificate.
 *
 * @param[in] preverify_ok The result of the in-built verification.
 * @param[in] x509_ctx Verification context.
 * @return 1 on success, 0 on error.
 */
static int
nc_server_tls_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    int ret = 0, depth, err;
    struct nc_tls_verify_cb_data *data;
    SSL *ssl;
    SSL_CTX *ctx;
    X509 *cert;

    /* retrieve callback data stored inside the SSL_CTX struct */
    ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (!ssl) {
        ERRINT;
        return 0;
    }
    ctx = SSL_get_SSL_CTX(ssl);
    if (!ctx) {
        ERRINT;
        return 0;
    }
    data = SSL_CTX_get_ex_data(ctx, 0);
    if (!data) {
        ERRINT;
        return 0;
    }

    /* get the cert chain once */
    if (!data->chain) {
        data->chain = X509_STORE_CTX_get0_chain(x509_ctx);
        if (!data->chain) {
            ERRINT;
            return 0;
        }
    }

    /* get current cert and its depth */
    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    depth = X509_STORE_CTX_get_error_depth(x509_ctx);

    if (preverify_ok) {
        /* in-built verification was successful */
        ret = nc_server_tls_verify_cert(cert, depth, 1, data);
    } else {
        /* in-built verification failed, but the client still may be authenticated if:
         * 1) the peer cert matches any configured end-entity cert
         * 2) the peer cert has a valid chain of trust to any configured certificate authority cert
         * otherwise just continue until we reach the peer cert (depth = 0)
         */
        err = X509_STORE_CTX_get_error(x509_ctx);
        if ((depth == 0) && ((err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) || (err == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE))) {
            /* not trusted (possibly self-signed) peer certificate, case 1) */
            ret = nc_server_tls_verify_cert(cert, depth, 0, data);
        } else if ((err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) || (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)) {
            /* full chain of trust is invalid, but it may be valid partially, case 2) */
            ret = nc_server_tls_verify_cert(cert, depth, 0, data);
        } else if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
            /* self-signed certificate in the chain, check if peer cert complies with 1) in order to continue,
             * if yes, this callback will be called again with the same cert, but with preverify_ok = 1
             */
            cert = X509_STORE_CTX_get0_cert(x509_ctx);
            ret = nc_server_tls_verify_peer_cert(cert, data->opts);
            if (ret) {
                VRB(NULL, "Cert verify: fail (%s).", X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));
                ret = -1;
            }
        } else {
            VRB(NULL, "Cert verify: fail (%s).", X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));
            ret = 1;
        }
    }

    if (ret == -1) {
        /* fatal error */
        return 0;
    } else if (!ret) {
        /* success */
        if ((depth == 0) && (!data->session->opts.server.client_cert)) {
            /* copy the client cert */
            data->session->opts.server.client_cert = X509_dup(cert);
            NC_CHECK_ERRMEM_RET(!data->session->opts.server.client_cert, 0);
        }
        return 1;
    } else {
        if (depth > 0) {
            /* chain verify failed */
            return 1;
        } else {
            /* peer cert did not match */
            return 0;
        }
    }
}

void
nc_server_tls_set_verify_wrap(void *tls_cfg, struct nc_tls_verify_cb_data *cb_data)
{
    /* set verify cb and its data */
    SSL_CTX_set_ex_data(tls_cfg, 0, cb_data);
    SSL_CTX_set_verify(tls_cfg, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_server_tls_verify_cb);
}

void
nc_client_tls_set_verify_wrap(void *tls_cfg)
{
    SSL_CTX_set_verify(tls_cfg, SSL_VERIFY_PEER, NULL);
}

char *
nc_server_tls_get_subject_wrap(void *cert)
{
    return X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
}

char *
nc_server_tls_get_issuer_wrap(void *cert)
{
    return X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
}

void *
nc_tls_get_sans_wrap(void *cert)
{
    return X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
}

void
nc_tls_sans_destroy_wrap(void *sans)
{
    sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
}

int
nc_tls_get_num_sans_wrap(void *sans)
{
    return sk_GENERAL_NAME_num(sans);
}

int
nc_tls_get_san_value_type_wrap(void *sans, int idx, char **san_value, NC_TLS_CTN_MAPTYPE *san_type)
{
    int ret = 0;
    GENERAL_NAME *san;
    ASN1_OCTET_STRING *ip;

    *san_value = NULL;
    *san_type = NC_TLS_CTN_UNKNOWN;

    /* find the san */
    san = sk_GENERAL_NAME_value(sans, idx);
    if (!san) {
        return -1;
    }

    /* get its type and value */
    switch (san->type) {
    case GEN_EMAIL:
        *san_type = NC_TLS_CTN_SAN_RFC822_NAME;
        *san_value = strdup((char *)ASN1_STRING_get0_data(san->d.rfc822Name));
        NC_CHECK_ERRMEM_RET(!*san_value, -1);
        break;
    case GEN_DNS:
        *san_type = NC_TLS_CTN_SAN_DNS_NAME;
        *san_value = strdup((char *)ASN1_STRING_get0_data(san->d.dNSName));
        NC_CHECK_ERRMEM_RET(!*san_value, -1);
        break;
    case GEN_IPADD:
        *san_type = NC_TLS_CTN_SAN_IP_ADDRESS;
        ip = san->d.iPAddress;
        if (ip->length == 4) {
            if (asprintf(san_value, "%d.%d.%d.%d", ip->data[0], ip->data[1], ip->data[2], ip->data[3]) == -1) {
                ERRMEM;
                *san_value = NULL;
                ret = -1;
            }
        } else if (ip->length == 16) {
            if (asprintf(san_value, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    ip->data[0], ip->data[1], ip->data[2], ip->data[3], ip->data[4], ip->data[5],
                    ip->data[6], ip->data[7], ip->data[8], ip->data[9], ip->data[10], ip->data[11],
                    ip->data[12], ip->data[13], ip->data[14], ip->data[15]) == -1) {
                ERRMEM;
                *san_value = NULL;
                ret = -1;
            }
        } else {
            WRN(NULL, "SAN IP address in an unknown format (length is %d).", ip->length);
            ret = 1;
        }
        break;
    default:
        /* we dont care about other types */
        *san_type = NC_TLS_CTN_UNKNOWN;
        ret = 1;
        break;
    }

    return ret;
}

int
nc_tls_get_num_certs_wrap(void *chain)
{
    return sk_X509_num(chain);
}

void
nc_tls_get_cert_wrap(void *chain, int idx, void **cert)
{
    *cert = sk_X509_value(chain, idx);
}

int
nc_server_tls_certs_match_wrap(void *cert1, void *cert2)
{
    return !X509_cmp(cert1, cert2);
}

int
nc_server_tls_md5_wrap(void *cert, unsigned char *buf)
{
    int rc;

    rc = X509_digest(cert, EVP_md5(), buf, NULL);
    if (!rc) {
        ERR(NULL, "Calculating MD-5 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    return 0;
}

int
nc_server_tls_sha1_wrap(void *cert, unsigned char *buf)
{
    int rc;

    rc = X509_digest(cert, EVP_sha1(), buf, NULL);
    if (!rc) {
        ERR(NULL, "Calculating SHA-1 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    return 0;
}

int
nc_server_tls_sha224_wrap(void *cert, unsigned char *buf)
{
    int rc;

    rc = X509_digest(cert, EVP_sha224(), buf, NULL);
    if (!rc) {
        ERR(NULL, "Calculating SHA-224 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    return 0;
}

int
nc_server_tls_sha256_wrap(void *cert, unsigned char *buf)
{
    int rc;

    rc = X509_digest(cert, EVP_sha256(), buf, NULL);
    if (!rc) {
        ERR(NULL, "Calculating SHA-256 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    return 0;
}

int
nc_server_tls_sha384_wrap(void *cert, unsigned char *buf)
{
    int rc;

    rc = X509_digest(cert, EVP_sha384(), buf, NULL);
    if (!rc) {
        ERR(NULL, "Calculating SHA-384 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    return 0;
}

int
nc_server_tls_sha512_wrap(void *cert, unsigned char *buf)
{
    int rc;

    rc = X509_digest(cert, EVP_sha512(), buf, NULL);
    if (!rc) {
        ERR(NULL, "Calculating SHA-512 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    return 0;
}

void
nc_server_tls_set_fd_wrap(void *tls_session, int sock, struct nc_tls_ctx *UNUSED(tls_ctx))
{
    SSL_set_fd(tls_session, sock);
}

int
nc_server_tls_handshake_step_wrap(void *tls_session)
{
    int ret = 0;

    ret = SSL_accept(tls_session);
    if (ret == 1) {
        return 1;
    } else if (ret == -1) {
        if ((SSL_get_error(tls_session, ret) == SSL_ERROR_WANT_READ) || (SSL_get_error(tls_session, ret) == SSL_ERROR_WANT_WRITE)) {
            return 0;
        }
    }

    return -1;
}

int
nc_client_tls_handshake_step_wrap(void *tls_session, int UNUSED(sock))
{
    int ret = 0;

    ret = SSL_connect(tls_session);
    if (ret == 1) {
        return 1;
    } else if (ret == -1) {
        if ((SSL_get_error(tls_session, ret) == SSL_ERROR_WANT_READ) || (SSL_get_error(tls_session, ret) == SSL_ERROR_WANT_WRITE)) {
            return 0;
        }
    }

    return -1;
}

void
nc_tls_ctx_destroy_wrap(struct nc_tls_ctx *UNUSED(tls_ctx))
{
    return;
}

int
nc_client_tls_load_cert_key_wrap(const char *cert_path, const char *key_path, void **cert, void **pkey)
{
    BIO *bio;
    X509 *cert_tmp;
    EVP_PKEY *pkey_tmp;

    NC_CHECK_ARG_RET(NULL, cert_path, key_path, cert, pkey, 1);

    bio = BIO_new_file(cert_path, "r");
    if (!bio) {
        ERR(NULL, "Opening the client certificate file \"%s\" failed.", cert_path);
        return 1;
    }

    cert_tmp = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert_tmp) {
        ERR(NULL, "Parsing the client certificate file \"%s\" failed.", cert_path);
        return 1;
    }

    bio = BIO_new_file(key_path, "r");
    if (!bio) {
        ERR(NULL, "Opening the client private key file \"%s\" failed.", key_path);
        X509_free(cert_tmp);
        return 1;
    }

    pkey_tmp = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey_tmp) {
        ERR(NULL, "Parsing the client private key file \"%s\" failed.", key_path);
        X509_free(cert_tmp);
        return 1;
    }

    *cert = cert_tmp;
    *pkey = pkey_tmp;

    return 0;
}

int
nc_client_tls_load_trusted_certs_wrap(void *cert_store, const char *file_path, const char *dir_path)
{
    if (!X509_STORE_load_locations(cert_store, file_path, dir_path)) {
        ERR(NULL, "Loading CA certs from file \"%s\" or directory \"%s\" failed (%s).",
                file_path, dir_path, ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    return 0;
}

int
nc_client_tls_set_hostname_wrap(void *tls_session, const char *hostname)
{
    int ret = 0;
    X509_VERIFY_PARAM *vpm = NULL;

    vpm = X509_VERIFY_PARAM_new();
    NC_CHECK_ERRMEM_RET(!vpm, 1);

    if (!X509_VERIFY_PARAM_set1_host(vpm, hostname, 0)) {
        ERR(NULL, "Failed to set expected hostname (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }
    if (!SSL_set1_param(tls_session, vpm)) {
        ERR(NULL, "Failed to set verify param (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

cleanup:
    X509_VERIFY_PARAM_free(vpm);
    return ret;
}

int
nc_tls_init_ctx_wrap(int UNUSED(sock), void *cert, void *pkey, void *cert_store, void *crl_store, struct nc_tls_ctx *tls_ctx)
{
    tls_ctx->cert = cert;
    tls_ctx->pkey = pkey;
    tls_ctx->cert_store = cert_store;
    tls_ctx->crl_store = crl_store;
    return 0;
}

/**
 * @brief Move CRLs from one store to another.
 *
 * @param[in] src Source store.
 * @param[in] dst Destination store.
 * @return 0 on success, 1 on error.
 */
static int
nc_tls_move_crls_to_store(const X509_STORE *src, X509_STORE *dst)
{
    int i, nobjs = 0;

    STACK_OF(X509_OBJECT) * objs;
    X509_OBJECT *obj;
    X509_CRL *crl;

    objs = X509_STORE_get0_objects(src);
    nobjs = sk_X509_OBJECT_num(objs);
    for (i = 0; i < nobjs; i++) {
        obj = sk_X509_OBJECT_value(objs, i);
        crl = X509_OBJECT_get0_X509_CRL(obj);
        if (!crl) {
            /* not a CRL */
            continue;
        }
        if (!X509_STORE_add_crl(dst, crl)) {
            ERR(NULL, "Adding CRL to the store failed (%s).", ERR_reason_error_string(ERR_get_error()));
            return 1;
        }
    }

    return 0;
}

int
nc_tls_setup_config_from_ctx_wrap(struct nc_tls_ctx *tls_ctx, int side, void *tls_cfg)
{
    if (SSL_CTX_use_certificate(tls_cfg, tls_ctx->cert) != 1) {
        ERR(NULL, "Setting up TLS certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    if (SSL_CTX_use_PrivateKey(tls_cfg, tls_ctx->pkey) != 1) {
        ERR(NULL, "Setting up TLS private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    /* disable server-side automatic chain building */
    if (side == NC_SERVER) {
        SSL_CTX_set_mode(tls_cfg, SSL_MODE_NO_AUTO_CHAIN);
    }

    if (tls_ctx->crl_store) {
        /* move CRLs from crl_store to cert_store, because SSL_CTX can only have one store */
        if (nc_tls_move_crls_to_store(tls_ctx->crl_store, tls_ctx->cert_store)) {
            return 1;
        }

        /* enable CRL checks */
        X509_STORE_set_flags(tls_ctx->cert_store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }

    SSL_CTX_set_cert_store(tls_cfg, tls_ctx->cert_store);

    X509_free(tls_ctx->cert);
    tls_ctx->cert = NULL;
    EVP_PKEY_free(tls_ctx->pkey);
    tls_ctx->pkey = NULL;
    X509_STORE_free(tls_ctx->crl_store);
    tls_ctx->crl_store = NULL;

    return 0;
}

uint32_t
nc_tls_get_verify_result_wrap(void *tls_session)
{
    return SSL_get_verify_result(tls_session);
}

char *
nc_tls_verify_error_string_wrap(uint32_t err_code)
{
    return strdup(X509_verify_cert_error_string(err_code));
}

void
nc_client_tls_print_connect_err_wrap(int connect_ret, const char *peername, void *tls_session)
{
    switch (SSL_get_error(tls_session, connect_ret)) {
    case SSL_ERROR_SYSCALL:
        ERR(NULL, "TLS connection to \"%s\" failed (%s).", peername, errno ? strerror(errno) : "unexpected EOF");
        break;
    case SSL_ERROR_SSL:
        ERR(NULL, "TLS connection to \"%s\" failed (%s).", peername, ERR_reason_error_string(ERR_get_error()));
        break;
    default:
        ERR(NULL, "TLS connection to \"%s\" failed.", peername);
        break;
    }
}

void
nc_server_tls_print_accept_err_wrap(int accept_ret, void *tls_session)
{
    switch (SSL_get_error(tls_session, accept_ret)) {
    case SSL_ERROR_SYSCALL:
        ERR(NULL, "TLS accept failed (%s).", strerror(errno));
        break;
    case SSL_ERROR_SSL:
        ERR(NULL, "TLS accept failed (%s).", ERR_reason_error_string(ERR_get_error()));
        break;
    default:
        ERR(NULL, "TLS accept failed.");
        break;
    }
}

int
nc_tls_is_der_subpubkey_wrap(unsigned char *der, long len)
{
    int ret;
    EVP_PKEY *pkey;

    pkey = d2i_PUBKEY(NULL, (const unsigned char **)&der, len);
    if (pkey) {
        /* success */
        ret = 1;
    } else {
        /* fail */
        ret = 0;
    }

    EVP_PKEY_free(pkey);
    return ret;
}

int
nc_base64_decode_wrap(const char *base64, unsigned char **bin)
{
    int ret;

    *bin = malloc((strlen(base64) / 4) * 3);
    NC_CHECK_ERRMEM_RET(!*bin, -1);

    ret = EVP_DecodeBlock(*bin, (const unsigned char *)base64, strlen(base64));
    if (ret == -1) {
        ERR(NULL, "Base64 decoding failed (%s).", ERR_reason_error_string(ERR_get_error()));
        free(*bin);
        *bin = NULL;
    }
    return ret;
}

int
nc_base64_encode_wrap(const unsigned char *bin, size_t len, char **base64)
{
    int ret, size;

    /* calculate the size, for every 3B of in 4B of out, + padding if not divisible + null terminator */
    if (len % 3) {
        size = (len / 3) * 4 + 4 + 1;
    } else {
        size = (len / 3) * 4 + 1;
    }

    *base64 = malloc(size);
    NC_CHECK_ERRMEM_RET(!*base64, -1);

    ret = EVP_EncodeBlock((unsigned char *)*base64, bin, len);
    if (ret == -1) {
        ERR(NULL, "Base64 encoding failed (%s).", ERR_reason_error_string(ERR_get_error()));
        free(*base64);
        *base64 = NULL;
        return -1;
    }

    return 0;
}

/**
 * @brief Get all OpenSSL error reasons.
 *
 * @return String with all OpenSSL error reasons or NULL.
 */
static char *
nc_tls_get_err_reasons(void)
{
    unsigned int e;
    int reason_size, reason_len;
    char *reasons = NULL;

    reason_size = 1;
    reason_len = 0;
    while ((e = ERR_get_error())) {
        if (reason_len) {
            /* add "; " */
            reason_size += 2;
            reasons = nc_realloc(reasons, reason_size);
            NC_CHECK_ERRMEM_RET(!reasons, NULL);
            reason_len += sprintf(reasons + reason_len, "; ");
        }
        reason_size += strlen(ERR_reason_error_string(e));
        reasons = nc_realloc(reasons, reason_size);
        NC_CHECK_ERRMEM_RET(!reasons, NULL);
        reason_len += sprintf(reasons + reason_len, "%s", ERR_reason_error_string(e));
    }

    return reasons;
}

int
nc_tls_read_wrap(struct nc_session *session, unsigned char *buf, size_t size)
{
    int rc, err;
    char *reasons;
    SSL *tls_session = session->ti.tls.session;

    ERR_clear_error();
    rc = SSL_read(tls_session, buf, size);
    if (rc <= 0) {
        err = SSL_get_error(tls_session, rc);
        switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            rc = 0;
            break;
        case SSL_ERROR_ZERO_RETURN:
            ERR(session, "Communication socket unexpectedly closed (OpenSSL).");
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_DROPPED;
            rc = -1;
            break;
        case SSL_ERROR_SYSCALL:
            ERR(session, "TLS socket error (%s).", errno ? strerror(errno) : "unexpected EOF");
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_OTHER;
            rc = -1;
            break;
        case SSL_ERROR_SSL:
            reasons = nc_tls_get_err_reasons();
            ERR(session, "TLS communication error (%s).", reasons);
            free(reasons);
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_OTHER;
            rc = -1;
            break;
        default:
            ERR(session, "Unknown TLS error occurred (err code %d).", err);
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_OTHER;
            rc = -1;
            break;
        }
    }

    return rc;
}

int
nc_tls_write_wrap(struct nc_session *session, const unsigned char *buf, size_t size)
{
    int rc, err;
    char *reasons;
    SSL *tls_session = session->ti.tls.session;

    ERR_clear_error();
    rc = SSL_write(tls_session, buf, size);
    if (rc < 1) {
        err = SSL_get_error(tls_session, rc);
        switch (err) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
            rc = 0;
            break;
        case SSL_ERROR_ZERO_RETURN:
            ERR(session, "TLS connection was properly closed.");
            rc = -1;
            break;
        case SSL_ERROR_SYSCALL:
            ERR(session, "TLS socket error (%s).", errno ? strerror(errno) : "unexpected EOF");
            rc = -1;
            break;
        case SSL_ERROR_SSL:
            reasons = nc_tls_get_err_reasons();
            ERR(session, "TLS communication error (%s).", reasons);
            free(reasons);
            rc = -1;
            break;
        default:
            ERR(session, "Unknown TLS error occurred (err code %d).", err);
            rc = -1;
            break;
        }
    }

    return rc;
}

int
nc_tls_get_num_pending_bytes_wrap(void *tls_session)
{
    return SSL_pending(tls_session);
}

int
nc_tls_get_fd_wrap(const struct nc_session *session)
{
    return session->ti.tls.session ? SSL_get_fd(session->ti.tls.session) : -1;
}

void
nc_tls_close_notify_wrap(void *tls_session)
{
    SSL_shutdown(tls_session);
}

void *
nc_tls_import_privkey_file_wrap(const char *key_path)
{
    EVP_PKEY *pkey;
    FILE *file;

    file = fopen(key_path, "r");
    if (!file) {
        ERR(NULL, "Opening the private key file \"%s\" failed.", key_path);
        return NULL;
    }

    pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    if (!pkey) {
        ERR(NULL, "Parsing the private key file \"%s\" failed (%s).", key_path, ERR_reason_error_string(ERR_get_error()));
    }

    return pkey;
}

void *
nc_tls_import_cert_file_wrap(const char *cert_path)
{
    X509 *cert;
    FILE *file;

    file = fopen(cert_path, "r");
    if (!file) {
        ERR(NULL, "Opening the certificate file \"%s\" failed.", cert_path);
        return NULL;
    }

    cert = PEM_read_X509(file, NULL, NULL, NULL);
    fclose(file);
    if (!cert) {
        ERR(NULL, "Parsing the certificate file \"%s\" failed (%s).", cert_path, ERR_reason_error_string(ERR_get_error()));
    }
    return cert;
}

char *
nc_tls_export_privkey_pem_wrap(void *pkey)
{
    BIO *bio = NULL;
    char *pem = NULL;

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ERR(NULL, "Creating new bio failed (%s).", ERR_reason_error_string(ERR_get_error()));
        goto cleanup;
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        ERR(NULL, "Exporting the private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
        goto cleanup;
    }

    pem = malloc(BIO_number_written(bio) + 1);
    NC_CHECK_ERRMEM_GOTO(!pem, , cleanup);

    BIO_read(bio, pem, BIO_number_written(bio));
    pem[BIO_number_written(bio)] = '\0';

cleanup:
    BIO_free(bio);
    return pem;
}

char *
nc_tls_export_cert_pem_wrap(void *cert)
{
    BIO *bio = NULL;
    char *pem = NULL;

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ERR(NULL, "Creating new bio failed (%s).", ERR_reason_error_string(ERR_get_error()));
        goto cleanup;
    }

    if (!PEM_write_bio_X509(bio, cert)) {
        ERR(NULL, "Exporting the certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
        goto cleanup;
    }

    pem = malloc(BIO_number_written(bio) + 1);
    NC_CHECK_ERRMEM_GOTO(!pem, , cleanup);

    BIO_read(bio, pem, BIO_number_written(bio));
    pem[BIO_number_written(bio)] = '\0';

cleanup:
    BIO_free(bio);
    return pem;
}

char *
nc_tls_export_pubkey_pem_wrap(void *pkey)
{
    BIO *bio = NULL;
    char *pem = NULL;

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        ERR(NULL, "Creating new bio failed (%s).", ERR_reason_error_string(ERR_get_error()));
        goto cleanup;
    }

    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        ERR(NULL, "Exporting the public key failed (%s).", ERR_reason_error_string(ERR_get_error()));
        goto cleanup;
    }

    pem = malloc(BIO_number_written(bio) + 1);
    NC_CHECK_ERRMEM_GOTO(!pem, , cleanup);

    BIO_read(bio, pem, BIO_number_written(bio));
    pem[BIO_number_written(bio)] = '\0';

cleanup:
    BIO_free(bio);
    return pem;
}

int
nc_tls_privkey_is_rsa_wrap(void *pkey)
{
    return EVP_PKEY_is_a(pkey, "RSA");
}

int
nc_tls_get_rsa_pubkey_params_wrap(void *pkey, void **e, void **n)
{
    BIGNUM *exp = NULL, *mod = NULL;

    if (!EVP_PKEY_get_bn_param(pkey, "e", &exp)) {
        ERR(NULL, "Getting the RSA public exponent failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    if (!EVP_PKEY_get_bn_param(pkey, "n", &mod)) {
        ERR(NULL, "Getting the RSA modulus failed (%s).", ERR_reason_error_string(ERR_get_error()));
        BN_free(exp);
        return 1;
    }

    *e = exp;
    *n = mod;
    return 0;
}

void
nc_tls_destroy_mpi_wrap(void *mpi)
{
    BN_free(mpi);
}

int
nc_tls_privkey_is_ec_wrap(void *pkey)
{
    return EVP_PKEY_is_a(pkey, "EC");
}

char *
nc_tls_get_ec_group_wrap(void *pkey)
{
    size_t ec_group_len = 0;
    char *ec_group = NULL;

    if (!EVP_PKEY_get_utf8_string_param(pkey, "group", NULL, 0, &ec_group_len)) {
        ERR(NULL, "Getting EC group length failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }

    /* alloc mem for group + 1 for \0 */
    ec_group = malloc(ec_group_len + 1);
    NC_CHECK_ERRMEM_RET(!ec_group, NULL);

    /* get the group */
    if (!EVP_PKEY_get_utf8_string_param(pkey, "group", ec_group, ec_group_len + 1, NULL)) {
        ERR(NULL, "Getting EC group failed (%s).", ERR_reason_error_string(ERR_get_error()));
        free(ec_group);
        return NULL;
    }

    return ec_group;
}

int
nc_tls_get_ec_pubkey_params_wrap(void *pkey, void **q, void **UNUSED(q_grp))
{
    BIGNUM *p = NULL;

    if (!EVP_PKEY_get_bn_param(pkey, "p", &p)) {
        ERR(NULL, "Getting public key point from the EC private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    *q = p;

    return 0;
}

int
nc_tls_ec_point_to_bin_wrap(void *q, void *UNUSED(q_grp), unsigned char **bin, int *bin_len)
{
    /* prepare buffer for converting p to binary */
    *bin = malloc(BN_num_bytes(q));
    NC_CHECK_ERRMEM_RET(!*bin, 1);

    /* convert to binary */
    *bin_len = BN_bn2bin(q, *bin);
    return 0;
}

void
nc_tls_ec_point_destroy_wrap(void *p)
{
    BN_free(p);
}

void
nc_tls_ec_group_destroy_wrap(void *UNUSED(grp))
{
    return;
}

int
nc_tls_mpi2bin_wrap(void *mpi, unsigned char **bin, int *bin_len)
{
    /* prepare buffer for converting mpi to binary */
    *bin = malloc(BN_num_bytes(mpi));
    NC_CHECK_ERRMEM_RET(!*bin, 1);

    /* convert to binary */
    *bin_len = BN_bn2bin(mpi, *bin);
    return 0;
}

void *
nc_tls_import_pubkey_file_wrap(const char *pubkey_path)
{
    FILE *f;
    EVP_PKEY *pk = NULL;

    f = fopen(pubkey_path, "r");
    if (!f) {
        ERR(NULL, "Unable to open file \"%s\".", pubkey_path);
        return NULL;
    }

    /* read the pubkey from file */
    pk = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!pk) {
        ERR(NULL, "Reading public key from file \"%s\" failed (%s).", pubkey_path, ERR_reason_error_string(ERR_get_error()));
        return NULL;
    }

    return pk;
}

int
nc_server_tls_get_crl_distpoint_uris_wrap(void *leaf_cert, void *cert_store, char ***uris, int *uri_count)
{
    int ret = 0, i, j, k, gtype;

    STACK_OF(X509_OBJECT) * objs;
    X509_OBJECT *obj;
    X509 *cert;

    STACK_OF(DIST_POINT) * dist_points;
    DIST_POINT *dist_point;
    GENERAL_NAMES *general_names;
    GENERAL_NAME *general_name;
    ASN1_STRING *asn_string_uri;
    void *tmp;

    *uris = NULL;
    *uri_count = 0;

    NC_CHECK_ARG_RET(NULL, cert_store, uris, uri_count, 1);

    /* treat all entries in the cert_store as X509_OBJECTs */
    objs = X509_STORE_get0_objects(cert_store);
    if (!objs) {
        ERR(NULL, "Getting certificates from store failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = -1;
        goto cleanup;
    }

    /* iterate over all the CAs */
    for (i = -1; i < sk_X509_OBJECT_num(objs); i++) {
        if (i == -1) {
            cert = leaf_cert;
        } else {
            obj = sk_X509_OBJECT_value(objs, i);
            cert = X509_OBJECT_get0_X509(obj);
        }

        if (!cert) {
            /* the object on this index was not a certificate */
            continue;
        }

        /* get all the distribution points for this CA */
        dist_points = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);

        /* iterate over all the dist points (there can be multiple for a single cert) */
        for (j = 0; j < sk_DIST_POINT_num(dist_points); j++) {
            dist_point = sk_DIST_POINT_value(dist_points, j);
            if (!dist_point) {
                continue;
            }
            general_names = dist_point->distpoint->name.fullname;

            /* iterate over all the GeneralesNames in the distribution point */
            for (k = 0; k < sk_GENERAL_NAME_num(general_names); k++) {
                general_name = sk_GENERAL_NAME_value(general_names, k);
                asn_string_uri = GENERAL_NAME_get0_value(general_name, &gtype);

                /* check if the general name is a URI and has a valid length */
                if ((gtype != GEN_URI) || (ASN1_STRING_length(asn_string_uri) <= 6)) {
                    continue;
                }

                /* found an URI */
                tmp = realloc(*uris, (*uri_count + 1) * sizeof **uris);
                NC_CHECK_ERRMEM_GOTO(!tmp, ret = 1, cleanup);
                *uris = tmp;

                (*uris)[*uri_count] = strdup((const char *) ASN1_STRING_get0_data(asn_string_uri));
                NC_CHECK_ERRMEM_GOTO(!(*uris)[*uri_count], ret = 1, cleanup);
                ++(*uri_count);
            }
        }
    }

cleanup:
    return ret;
}

int
nc_tls_process_cipher_suite_wrap(const char *cipher, char **out)
{
    int i;

    *out = malloc(strlen(cipher) + 1);
    NC_CHECK_ERRMEM_RET(!*out, 1);

    /* convert to uppercase */
    for (i = 0; cipher[i]; i++) {
        if (cipher[i] == '-') {
            /* OpenSSL requires _ instead of - in cipher names */
            (*out)[i] = '_';
        } else {
            (*out)[i] = toupper(cipher[i]);
        }
    }

    (*out)[i] = '\0';
    return 0;
}

int
nc_tls_append_cipher_suite_wrap(struct nc_server_tls_opts *opts, const char *cipher_suite)
{
    if (!opts->ciphers) {
        /* first entry */
        opts->ciphers = strdup(cipher_suite);
        NC_CHECK_ERRMEM_RET(!opts->ciphers, 1);
    } else {
        /* + 1 because of : between entries */
        opts->ciphers = nc_realloc(opts->ciphers, strlen(opts->ciphers) + strlen(cipher_suite) + 1 + 1);
        NC_CHECK_ERRMEM_RET(!opts->ciphers, 1);
        strcat(opts->ciphers, ":");
        strcat(opts->ciphers, cipher_suite);
    }

    return 0;
}

void
nc_server_tls_set_cipher_suites_wrap(void *tls_cfg, void *cipher_suites)
{
    /* set for TLS1.2 and lower */
    SSL_CTX_set_cipher_list(tls_cfg, cipher_suites);
    /* set for TLS1.3 */
    SSL_CTX_set_ciphersuites(tls_cfg, cipher_suites);
}

time_t
nc_tls_get_cert_exp_time_wrap(void *cert)
{
    int r;
    struct tm t = {0};

    r = ASN1_TIME_to_tm(X509_get0_notAfter(cert), &t);
    if (!r) {
        return -1;
    }

    /* let system figure out the DST */
    t.tm_isdst = -1;

    return timegm(&t);
}
