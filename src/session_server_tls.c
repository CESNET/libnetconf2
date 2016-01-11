/**
 * \file session_server_tls.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 TLS server session manipulation functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 */

#define _GNU_SOURCE

#include <string.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "session_server.h"
#include "config.h"
#include "session_p.h"

extern struct nc_server_opts server_opts;
struct nc_tls_server_opts tls_opts;

static char *
asn1time_to_str(ASN1_TIME *t)
{
    char *cp;
    BIO *bio;
    int n;

    if (!t) {
        return NULL;
    }
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return NULL;
    }
    ASN1_TIME_print(bio, t);
    n = BIO_pending(bio);
    cp = malloc(n + 1);
    n = BIO_read(bio, cp, n);
    if (n < 0) {
        BIO_free(bio);
        free(cp);
        return NULL;
    }
    cp[n] = '\0';
    BIO_free(bio);
    return cp;
}

static void
digest_to_str(const unsigned char *digest, unsigned int dig_len, char **str)
{
    unsigned int i;

    *str = malloc(dig_len * 3);
    for (i = 0; i < dig_len - 1; ++i) {
        sprintf((*str) + (i * 3), "%02x:", digest[i]);
    }
    sprintf((*str) + (i * 3), "%02x", digest[i]);
}

/* return NULL - SSL error can be retrieved */
static X509 *
base64der_to_cert(const char *in)
{
    X509 *out;
    char *buf;
    BIO *bio;

    if (in == NULL) {
        return NULL;
    }

    if (asprintf(&buf, "%s%s%s", "-----BEGIN CERTIFICATE-----\n", in, "\n-----END CERTIFICATE-----") == -1) {
        return NULL;
    }
    bio = BIO_new_mem_buf(buf, strlen(buf));
    if (!bio) {
        free(buf);
        return NULL;
    }

    out = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!out) {
        free(buf);
        BIO_free(bio);
        return NULL;
    }

    free(buf);
    BIO_free(bio);
    return out;
}

/* return NULL - either errno or SSL error */
static X509 *
pem_to_cert(const char *path)
{
    FILE *fp;
    X509 *out;

    fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }

    out = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return out;
}

static EVP_PKEY *
base64der_to_privatekey(const char *in, int rsa)
{
    EVP_PKEY *out;
    char *buf;
    BIO *bio;

    if (in == NULL) {
        return NULL;
    }

    if (asprintf(&buf, "%s%s%s%s%s%s%s", "-----BEGIN ", (rsa ? "RSA" : "DSA"), " PRIVATE KEY-----\n", in, "\n-----END ", (rsa ? "RSA" : "DSA"), " PRIVATE KEY-----") == -1) {
        return NULL;
    }
    bio = BIO_new_mem_buf(buf, strlen(buf));
    if (!bio) {
        free(buf);
        return NULL;
    }

    out = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!out) {
        free(buf);
        BIO_free(bio);
        return NULL;
    }

    free(buf);
    BIO_free(bio);
    return out;
}

static int
cert_pubkey_match(X509 *cert1, X509 *cert2)
{
    ASN1_BIT_STRING *bitstr1, *bitstr2;

    bitstr1 = X509_get0_pubkey_bitstr(cert1);
    bitstr2 = X509_get0_pubkey_bitstr(cert2);

    if (!bitstr1 || !bitstr2 || (bitstr1->length != bitstr2->length) ||
            memcmp(bitstr1->data, bitstr2->data, bitstr1->length)) {
        return 0;
    }

    return 1;
}

static int
nc_tls_ctn_get_username_from_cert(X509 *client_cert, NC_TLS_CTN_MAPTYPE map_type, char **username)
{
    STACK_OF(GENERAL_NAME) *san_names;
    GENERAL_NAME *san_name;
    ASN1_OCTET_STRING *ip;
    int i, san_count;
    char *subject, *common_name;

    if (map_type == NC_TLS_CTN_COMMON_NAME) {
        subject = X509_NAME_oneline(X509_get_subject_name(client_cert), NULL, 0);
        common_name = strstr(subject, "CN=");
        if (!common_name) {
            WRN("%s: cert does not include the commonName field", __func__);
            free(subject);
            return 1;
        }
        common_name += 3;
        if (strchr(common_name, '/')) {
            *strchr(common_name, '/') = '\0';
        }
        *username = strdup(common_name);
        free(subject);
    } else {
        /* retrieve subjectAltName's rfc822Name (email), dNSName and iPAddress values */
        san_names = X509_get_ext_d2i(client_cert, NID_subject_alt_name, NULL, NULL);
        if (!san_names) {
            WRN("%s: cert has no SANs or failed to retrieve them", __func__);
            return 1;
        }

        san_count = sk_GENERAL_NAME_num(san_names);
        for (i = 0; i < san_count; ++i) {
            san_name = sk_GENERAL_NAME_value(san_names, i);

            /* rfc822Name (email) */
            if ((map_type == NC_TLS_CTN_SAN_ANY || map_type == NC_TLS_CTN_SAN_RFC822_NAME) &&
                    san_name->type == GEN_EMAIL) {
                *username = strdup((char *)ASN1_STRING_data(san_name->d.rfc822Name));
                break;
            }

            /* dNSName */
            if ((map_type == NC_TLS_CTN_SAN_ANY || map_type == NC_TLS_CTN_SAN_DNS_NAME) &&
                    san_name->type == GEN_DNS) {
                *username = strdup((char *)ASN1_STRING_data(san_name->d.dNSName));
                break;
            }

            /* iPAddress */
            if ((map_type == NC_TLS_CTN_SAN_ANY || map_type == NC_TLS_CTN_SAN_IP_ADDRESS) &&
                    san_name->type == GEN_IPADD) {
                ip = san_name->d.iPAddress;
                if (ip->length == 4) {
                    if (asprintf(username, "%d.%d.%d.%d", ip->data[0], ip->data[1], ip->data[2], ip->data[3]) == -1) {
                        ERR("%s: asprintf() failed", __func__);
                        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                        return -1;
                    }
                    break;
                } else if (ip->length == 16) {
                    if (asprintf(username, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                            ip->data[0], ip->data[1], ip->data[2], ip->data[3], ip->data[4], ip->data[5],
                            ip->data[6], ip->data[7], ip->data[8], ip->data[9], ip->data[10], ip->data[11],
                            ip->data[12], ip->data[13], ip->data[14], ip->data[15]) == -1) {
                        ERR("%s: asprintf() failed", __func__);
                        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                        return -1;
                    }
                    break;
                } else {
                    WRN("%s: SAN IP address in an unknown format (length is %d)", __func__, ip->length);
                }
            }
        }
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

        if (i < san_count) {
            switch (map_type) {
            case NC_TLS_CTN_SAN_RFC822_NAME:
                WRN("%s: cert does not include the SAN rfc822Name field", __func__);
                break;
            case NC_TLS_CTN_SAN_DNS_NAME:
                WRN("%s: cert does not include the SAN dNSName field", __func__);
                break;
            case NC_TLS_CTN_SAN_IP_ADDRESS:
                WRN("%s: cert does not include the SAN iPAddress field", __func__);
                break;
            case NC_TLS_CTN_SAN_ANY:
                WRN("%s: cert does not include any relevant SAN fields", __func__);
                break;
            default:
                break;
            }
            return 1;
        }
    }

    return 0;
}

/* return: 0 - OK, 1 - no match, -1 - error */
static int
nc_tls_cert_to_name(X509 *cert, NC_TLS_CTN_MAPTYPE *map_type, const char **name)
{
    char *digest_md5 = NULL, *digest_sha1 = NULL, *digest_sha224 = NULL;
    char *digest_sha256 = NULL, *digest_sha384 = NULL, *digest_sha512 = NULL;
    uint16_t i;
    unsigned char *buf = malloc(64);
    unsigned int buf_len = 64;
    int ret = 0;

    if (cert == NULL || map_type == NULL || name == NULL) {
        free(buf);
        return -1;
    }

    for (i = 0; i < tls_opts.ctn_count; ++i) {
        /* MD5 */
        if (!strncmp(tls_opts.ctn[i].fingerprint, "01", 2)) {
            if (!digest_md5) {
                if (X509_digest(cert, EVP_md5(), buf, &buf_len) != 1) {
                    ERR("%s: calculating MD5 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_md5);
            }

            if (!strcasecmp(tls_opts.ctn[i].fingerprint + 3, digest_md5)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found");
                *map_type = tls_opts.ctn[i].map_type;
                if (tls_opts.ctn[i].map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = tls_opts.ctn[i].name;
                }
                break;
            }

        /* SHA-1 */
        } else if (!strncmp(tls_opts.ctn[i].fingerprint, "02", 2)) {
            if (!digest_sha1) {
                if (X509_digest(cert, EVP_sha1(), buf, &buf_len) != 1) {
                    ERR("%s: calculating SHA-1 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha1);
            }

            if (!strcasecmp(tls_opts.ctn[i].fingerprint + 3, digest_sha1)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found");
                *map_type = tls_opts.ctn[i].map_type;
                if (tls_opts.ctn[i].map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = tls_opts.ctn[i].name;
                }
                break;
            }

        /* SHA-224 */
        } else if (!strncmp(tls_opts.ctn[i].fingerprint, "03", 2)) {
            if (!digest_sha224) {
                if (X509_digest(cert, EVP_sha224(), buf, &buf_len) != 1) {
                    ERR("%s: calculating SHA-224 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha224);
            }

            if (!strcasecmp(tls_opts.ctn[i].fingerprint + 3, digest_sha224)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found");
                *map_type = tls_opts.ctn[i].map_type;
                if (tls_opts.ctn[i].map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = tls_opts.ctn[i].name;
                }
                break;
            }

        /* SHA-256 */
        } else if (!strncmp(tls_opts.ctn[i].fingerprint, "04", 2)) {
            if (!digest_sha256) {
                if (X509_digest(cert, EVP_sha256(), buf, &buf_len) != 1) {
                    ERR("%s: calculating SHA-256 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha256);
            }

            if (!strcasecmp(tls_opts.ctn[i].fingerprint + 3, digest_sha256)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found");
                *map_type = tls_opts.ctn[i].map_type;
                if (tls_opts.ctn[i].map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = tls_opts.ctn[i].name;
                }
                break;
            }

        /* SHA-384 */
        } else if (!strncmp(tls_opts.ctn[i].fingerprint, "05", 2)) {
            if (!digest_sha384) {
                if (X509_digest(cert, EVP_sha384(), buf, &buf_len) != 1) {
                    ERR("%s: calculating SHA-384 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha384);
            }

            if (!strcasecmp(tls_opts.ctn[i].fingerprint + 3, digest_sha384)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found");
                *map_type = tls_opts.ctn[i].map_type;
                if (tls_opts.ctn[i].map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = tls_opts.ctn[i].name;
                }
                break;
            }

        /* SHA-512 */
        } else if (!strncmp(tls_opts.ctn[i].fingerprint, "06", 2)) {
            if (!digest_sha512) {
                if (X509_digest(cert, EVP_sha512(), buf, &buf_len) != 1) {
                    ERR("%s: calculating SHA-512 digest: %s", __func__, ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha512);
            }

            if (!strcasecmp(tls_opts.ctn[i].fingerprint + 3, digest_sha512)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found");
                *map_type = tls_opts.ctn[i].map_type;
                if (tls_opts.ctn[i].map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = tls_opts.ctn[i].name;
                }
                break;
            }

        /* unknown */
        } else {
            WRN("%s: unknown fingerprint algorithm used (%s), skipping", __func__, tls_opts.ctn[i].fingerprint);
        }
    }

    if (i == tls_opts.ctn_count) {
        ret = 1;
    }

cleanup:
    free(digest_md5);
    free(digest_sha1);
    free(digest_sha224);
    free(digest_sha256);
    free(digest_sha384);
    free(digest_sha512);
    free(buf);
    return ret;
}

/* TODO */
struct nc_session *glob_session;

static int
nc_tlsclb_verify(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    X509_STORE_CTX store_ctx;
    X509_OBJECT obj;
    X509_NAME *subject;
    X509_NAME *issuer;
    X509 *cert;
    X509_CRL *crl;
    X509_REVOKED *revoked;
    STACK_OF(X509) *cert_stack;
    EVP_PKEY *pubkey;
    struct nc_session* session;
    long serial;
    int i, n, rc, depth;
    char *cp;
    const char *username = NULL;
    NC_TLS_CTN_MAPTYPE map_type = 0;
    ASN1_TIME *last_update = NULL, *next_update = NULL;

    /* get the new client structure */
    session = glob_session;

    /* get the last certificate, that is the peer (client) certificate */
    if (!session->cert) {
        cert_stack = X509_STORE_CTX_get1_chain(x509_ctx);
        /* TODO all that is needed, but function X509_up_ref not present in older OpenSSL versions
        session->cert = sk_X509_value(cert_stack, sk_X509_num(cert_stack) - 1);
        X509_up_ref(session->cert);
        sk_X509_pop_free(cert_stack, X509_free); */
        while ((cert = sk_X509_pop(cert_stack))) {
            X509_free(session->cert);
            session->cert = cert;
        }
        sk_X509_pop_free(cert_stack, X509_free);
    }

    /* standard certificate verification failed, so a trusted client cert must match to continue */
    if (!preverify_ok) {
        subject = X509_get_subject_name(session->cert);
        cert_stack = X509_STORE_get1_certs(x509_ctx, subject);
        if (cert_stack) {
            for (i = 0; i < sk_X509_num(cert_stack); ++i) {
                if (cert_pubkey_match(session->cert, sk_X509_value(cert_stack, i))) {
                    /* we are just overriding the failed standard certificate verification (preverify_ok == 0),
                     * this callback will be called again with the same current certificate and preverify_ok == 1 */
                    WRN("Cert verify: fail (%s), but the client certificate is trusted, continuing.",
                        X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));
                    X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
                    sk_X509_pop_free(cert_stack, X509_free);
                    return 1;
                }
            }
            sk_X509_pop_free(cert_stack, X509_free);
        }

        ERR("Cert verify: fail (%s).", X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));
        return 0;
    }

    /* print cert verify info */
    depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    VRB("Cert verify: depth %d", depth);

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    subject = X509_get_subject_name(cert);
    issuer = X509_get_issuer_name(cert);

    cp = X509_NAME_oneline(subject, NULL, 0);
    VRB("Cert verify: subject: %s", cp);
    OPENSSL_free(cp);
    cp = X509_NAME_oneline(issuer, NULL, 0);
    VRB("Cert verify: issuer:  %s", cp);
    OPENSSL_free(cp);

    /* check for revocation if set */
    if (tls_opts.crl_store) {
        /* try to retrieve a CRL corresponding to the _subject_ of
         * the current certificate in order to verify it's integrity */
        memset((char *)&obj, 0, sizeof(obj));
        X509_STORE_CTX_init(&store_ctx, tls_opts.crl_store, NULL, NULL);
        rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
        X509_STORE_CTX_cleanup(&store_ctx);
        crl = obj.data.crl;
        if (rc > 0 && crl) {
            cp = X509_NAME_oneline(subject, NULL, 0);
            VRB("Cert verify CRL: issuer: %s", cp);
            OPENSSL_free(cp);

            last_update = X509_CRL_get_lastUpdate(crl);
            next_update = X509_CRL_get_nextUpdate(crl);
            cp = asn1time_to_str(last_update);
            VRB("Cert verify CRL: last update: %s", cp);
            free(cp);
            cp = asn1time_to_str(next_update);
            VRB("Cert verify CRL: next update: %s", cp);
            free(cp);

            /* verify the signature on this CRL */
            pubkey = X509_get_pubkey(cert);
            if (X509_CRL_verify(crl, pubkey) <= 0) {
                ERR("Cert verify CRL: invalid signature.");
                X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
                X509_OBJECT_free_contents(&obj);
                if (pubkey) {
                    EVP_PKEY_free(pubkey);
                }
                return 0;
            }
            if (pubkey) {
                EVP_PKEY_free(pubkey);
            }

            /* check date of CRL to make sure it's not expired */
            if (!next_update) {
                ERR("Cert verify CRL: invalid nextUpdate field.");
                X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
                X509_OBJECT_free_contents(&obj);
                return 0;
            }
            if (X509_cmp_current_time(next_update) < 0) {
                ERR("Cert verify CRL: expired - revoking all certificates.");
                X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_HAS_EXPIRED);
                X509_OBJECT_free_contents(&obj);
                return 0;
            }
            X509_OBJECT_free_contents(&obj);
        }

        /* try to retrieve a CRL corresponding to the _issuer_ of
        * the current certificate in order to check for revocation */
        memset((char *)&obj, 0, sizeof(obj));
        X509_STORE_CTX_init(&store_ctx, tls_opts.crl_store, NULL, NULL);
        rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, issuer, &obj);
        X509_STORE_CTX_cleanup(&store_ctx);
        crl = obj.data.crl;
        if (rc > 0 && crl) {
            /* check if the current certificate is revoked by this CRL */
            n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
            for (i = 0; i < n; i++) {
                revoked = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
                if (ASN1_INTEGER_cmp(revoked->serialNumber, X509_get_serialNumber(cert)) == 0) {
                    serial = ASN1_INTEGER_get(revoked->serialNumber);
                    cp = X509_NAME_oneline(issuer, NULL, 0);
                    ERR("Cert verify CRL: certificate with serial %ld (0x%lX) revoked per CRL from issuer %s", serial, serial, cp);
                    OPENSSL_free(cp);
                    X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REVOKED);
                    X509_OBJECT_free_contents(&obj);
                    return 0;
                }
            }
            X509_OBJECT_free_contents(&obj);
        }
    }

    /* cert-to-name already successful */
    if (session->username) {
        return 1;
    }

    /* cert-to-name */
    rc = nc_tls_cert_to_name(cert, &map_type, &username);
    if (rc) {
        if (rc == -1) {
            /* fatal error */
            depth = 0;
        }
        /* rc == 1 is a normal CTN fail (no match found) */
        goto fail;
    }

    /* cert-to-name match, now to extract the specific field from the peer cert */
    if (map_type == NC_TLS_CTN_SPECIFIED) {
        session->username = lydict_insert(server_opts.ctx, username, 0);
    } else {
        rc = nc_tls_ctn_get_username_from_cert(session->cert, map_type, &cp);
        if (rc) {
            if (rc == -1) {
                depth = 0;
            }
            goto fail;
        }
        session->username = lydict_insert_zc(server_opts.ctx, cp);
    }

    VRB("Cert verify CTN: new client username recognized as \"%s\".", session->username);
    return 1;

fail:
    if (depth > 0) {
        VRB("Cert verify CTN: cert fail, cert-to-name will continue on the next cert in chain.");
        return 1;
    }

    VRB("Cert-to-name unsuccessful, dropping the new client.");
    X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
}

API int
nc_tls_server_set_cert(const char *cert)
{
    X509 *x509_cert;

    if (!cert) {
        ERRARG;
        return -1;
    }

    if (!tls_opts.tls_ctx) {
        tls_opts.tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!tls_opts.tls_ctx) {
           ERR("%s: failed to create TLS context.", __func__);
           return -1;
        }
        SSL_CTX_set_verify(tls_opts.tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    x509_cert = base64der_to_cert(cert);
    if (!x509_cert || (SSL_CTX_use_certificate(tls_opts.tls_ctx, x509_cert) != 1)) {
        ERR("%s: loading the server certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
        X509_free(x509_cert);
        return -1;
    }
    X509_free(x509_cert);

    return 0;
}

/* PEM only */
API int
nc_tls_server_set_cert_path(const char *cert_path)
{
    if (!cert_path) {
        ERRARG;
        return -1;
    }

    if (!tls_opts.tls_ctx) {
        tls_opts.tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!tls_opts.tls_ctx) {
           ERR("%s: failed to create TLS context.", __func__);
           return -1;
        }
        SSL_CTX_set_verify(tls_opts.tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    if (SSL_CTX_use_certificate_file(tls_opts.tls_ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
        ERR("%s: loading the server certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    return 0;
}

API int
nc_tls_server_set_key(const char *privkey, int is_rsa)
{
    EVP_PKEY *key;;

    if (!privkey) {
        ERRARG;
        return -1;
    }

    if (!tls_opts.tls_ctx) {
        tls_opts.tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!tls_opts.tls_ctx) {
           ERR("%s: failed to create TLS context.", __func__);
           return -1;
        }
        SSL_CTX_set_verify(tls_opts.tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    key = base64der_to_privatekey(privkey, is_rsa);
    if (!key || (SSL_CTX_use_PrivateKey(tls_opts.tls_ctx, key) != 1)) {
        ERR("%s: loading the server private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
        EVP_PKEY_free(key);
        return -1;
    }
    EVP_PKEY_free(key);

    return 0;
}

/* PEM only */
API int
nc_tls_server_set_key_path(const char *privkey_path)
{
    if (!privkey_path) {
        ERRARG;
        return -1;
    }

    if (!tls_opts.tls_ctx) {
        tls_opts.tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!tls_opts.tls_ctx) {
           ERR("%s: failed to create TLS context.", __func__);
           return -1;
        }
        SSL_CTX_set_verify(tls_opts.tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    if (SSL_CTX_use_PrivateKey_file(tls_opts.tls_ctx, privkey_path, SSL_FILETYPE_PEM) != 1) {
        ERR("%s: loading the server priavte key failed (%s).", ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    return 0;
}

API int
nc_tls_server_add_trusted_cert(const char *cert)
{
    X509_STORE *cert_store;
    X509 *x509_cert;

    if (!cert) {
        ERRARG;
        return -1;
    }

    if (!tls_opts.tls_ctx) {
        tls_opts.tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!tls_opts.tls_ctx) {
           ERR("%s: failed to create TLS context.", __func__);
           return -1;
        }
        SSL_CTX_set_verify(tls_opts.tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    cert_store = SSL_CTX_get_cert_store(tls_opts.tls_ctx);
    if (!cert_store) {
        cert_store = X509_STORE_new();
        SSL_CTX_set_cert_store(tls_opts.tls_ctx, cert_store);
    }

    x509_cert = base64der_to_cert(cert);
    if (!x509_cert || (X509_STORE_add_cert(cert_store, x509_cert) != 1)) {
        ERR("%s: adding a trusted certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
        X509_free(x509_cert);
        return -1;
    }
    X509_free(x509_cert);

    return 0;
}

API int
nc_tls_server_add_trusted_cert_path(const char *cert_path)
{
    X509_STORE *cert_store;
    X509 *x509_cert;

    if (!cert_path) {
        ERRARG;
        return -1;
    }

    if (!tls_opts.tls_ctx) {
        tls_opts.tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!tls_opts.tls_ctx) {
           ERR("%s: failed to create TLS context.", __func__);
           return -1;
        }
        SSL_CTX_set_verify(tls_opts.tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    cert_store = SSL_CTX_get_cert_store(tls_opts.tls_ctx);
    if (!cert_store) {
        cert_store = X509_STORE_new();
        SSL_CTX_set_cert_store(tls_opts.tls_ctx, cert_store);
    }

    errno = 0;
    x509_cert = pem_to_cert(cert_path);
    if (!x509_cert || (X509_STORE_add_cert(cert_store, x509_cert) != 1)) {
        ERR("%s: adding a trusted certificate failed (%s).",
            (errno ? strerror(errno) : ERR_reason_error_string(ERR_get_error())));
        X509_free(x509_cert);
        return -1;
    }
    X509_free(x509_cert);

    return 0;
}

API int
nc_tls_server_set_trusted_cacert_locations(const char *cacert_file_path, const char *cacert_dir_path)
{
    X509_STORE *cert_store;
    X509_LOOKUP *lookup;

    if (!cacert_file_path && !cacert_dir_path) {
        ERRARG;
        return -1;
    }

    if (!tls_opts.tls_ctx) {
        tls_opts.tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!tls_opts.tls_ctx) {
           ERR("%s: failed to create TLS context.", __func__);
           return -1;
        }
        SSL_CTX_set_verify(tls_opts.tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    cert_store = SSL_CTX_get_cert_store(tls_opts.tls_ctx);
    if (!cert_store) {
        cert_store = X509_STORE_new();
        SSL_CTX_set_cert_store(tls_opts.tls_ctx, cert_store);
    }

    if (cacert_file_path) {
        lookup = X509_STORE_add_lookup(cert_store, X509_LOOKUP_file());
        if (!lookup) {
            ERR("%s: failed to add lookup method.", __func__);
            return -1;
        }

        if (X509_LOOKUP_load_file(lookup, cacert_file_path, X509_FILETYPE_PEM) != 1) {
            ERR("%s: failed to add trusted cert file (%s).", __func__, ERR_reason_error_string(ERR_get_error()));
            return -1;
        }
    }

    if (cacert_dir_path) {
        lookup = X509_STORE_add_lookup(cert_store, X509_LOOKUP_hash_dir());
        if (!lookup) {
            ERR("%s: failed to add lookup method.", __func__);
            return -1;
        }

        if (X509_LOOKUP_add_dir(lookup, cacert_dir_path, X509_FILETYPE_PEM) != 1) {
            ERR("%s: failed to add trusted cert directory (%s).", __func__, ERR_reason_error_string(ERR_get_error()));
            return -1;
        }
    }

    return 0;
}

API void
nc_tls_server_destroy_certs(void)
{
    if (!tls_opts.tls_ctx) {
        return;
    }

    SSL_CTX_free(tls_opts.tls_ctx);
    tls_opts.tls_ctx = NULL;
}

/* PEM hash dir */
API int
nc_tls_server_set_crl_locations(const char *crl_file_path, const char *crl_dir_path)
{
    X509_LOOKUP *lookup;

    if (!crl_file_path && !crl_dir_path) {
        ERRARG;
        return -1;
    }

    if (!tls_opts.crl_store) {
        tls_opts.crl_store = X509_STORE_new();
    }

    if (crl_file_path) {
        lookup = X509_STORE_add_lookup(tls_opts.crl_store, X509_LOOKUP_file());
        if (!lookup) {
            ERR("%s: failed to add lookup method.", __func__);
            return -1;
        }

        if (X509_LOOKUP_load_file(lookup, crl_file_path, X509_FILETYPE_PEM) != 1) {
            ERR("%s: failed to add revocation lookup file (%s).", __func__, ERR_reason_error_string(ERR_get_error()));
            return -1;
        }
    }

    if (crl_dir_path) {
        lookup = X509_STORE_add_lookup(tls_opts.crl_store, X509_LOOKUP_hash_dir());
        if (!lookup) {
            ERR("%s: failed to add lookup method.", __func__);
            return -1;
        }

        if (X509_LOOKUP_add_dir(lookup, crl_dir_path, X509_FILETYPE_PEM) != 1) {
            ERR("%s: failed to add revocation lookup directory (%s).", __func__, ERR_reason_error_string(ERR_get_error()));
            return -1;
        }
    }

    return 0;
}

API void
nc_tls_server_destroy_crls(void)
{
    if (!tls_opts.crl_store) {
        return;
    }

    X509_STORE_free(tls_opts.crl_store);
    tls_opts.crl_store = NULL;
}

API int
nc_tls_server_add_ctn(uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name)
{
    if (!fingerprint || !map_type || ((map_type == NC_TLS_CTN_SPECIFIED) && !name)) {
        ERRARG;
        return -1;
    }

    ++tls_opts.ctn_count;
    tls_opts.ctn = realloc(tls_opts.ctn, tls_opts.ctn_count * sizeof *tls_opts.ctn);

    tls_opts.ctn[tls_opts.ctn_count - 1].id = id;
    tls_opts.ctn[tls_opts.ctn_count - 1].fingerprint = lydict_insert(server_opts.ctx, fingerprint, 0);
    tls_opts.ctn[tls_opts.ctn_count - 1].map_type = map_type;
    tls_opts.ctn[tls_opts.ctn_count - 1].name = lydict_insert(server_opts.ctx, name, 0);

    return 0;
}

API int
nc_tls_server_del_ctn(int64_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name)
{
    uint16_t i;
    int ret = -1;

    for (i = 0; i < tls_opts.ctn_count; ++i) {
        if (((!id < 0) || (tls_opts.ctn[i].id == id))
                && (!fingerprint || !strcmp(tls_opts.ctn[i].fingerprint, fingerprint))
                && (!map_type || (tls_opts.ctn[i].map_type == map_type))
                && (!name || (tls_opts.ctn[i].name && !strcmp(tls_opts.ctn[i].name, name)))) {
            lydict_remove(server_opts.ctx, tls_opts.ctn[i].fingerprint);
            lydict_remove(server_opts.ctx, tls_opts.ctn[i].name);

            --tls_opts.ctn_count;
            memmove(&tls_opts.ctn[i], &tls_opts.ctn[i + 1], (tls_opts.ctn_count - i) * sizeof *tls_opts.ctn);

            ret = 0;
        }
    }

    return ret;
}

API void
nc_tls_server_free_opts(void)
{
    uint16_t i;

    nc_tls_server_destroy_certs();
    nc_tls_server_destroy_crls();

    for (i = 0; i < tls_opts.ctn_count; ++i) {
        lydict_remove(server_opts.ctx, tls_opts.ctn[i].fingerprint);
        lydict_remove(server_opts.ctx, tls_opts.ctn[i].name);
    }
    free(tls_opts.ctn);
}

int
nc_accept_tls_session(struct nc_session *session, int sock, int timeout)
{
    int ret;
    struct pollfd pfd;

    pfd.fd = sock;
    pfd.events = POLLIN;
    pfd.revents = 0;

    /* poll for a new connection */
    errno = 0;
    ret = poll(&pfd, 1, timeout);
    if (!ret) {
        /* we timeouted */
        close(sock);
        return -1;
    } else if (ret == -1) {
        ERR("%s: poll failed (%s).", __func__, strerror(errno));
        close(sock);
        return -1;
    }

    /* data waiting */
    session->ti_type = NC_TI_OPENSSL;
    session->ti.tls = SSL_new(tls_opts.tls_ctx);
    if (!session->ti.tls) {
        ERRMEM;
        close(sock);
        return -1;
    }

    SSL_set_fd(session->ti.tls, sock);
    SSL_set_mode(session->ti.tls, SSL_MODE_AUTO_RETRY);

    /* generate new index for TLS-specific data, for the verify callback */
    /*netopeer_state.tls_state->last_tls_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    SSL_set_ex_data(new_client->tls, netopeer_state.tls_state->last_tls_idx, new_client);*/
    glob_session = session;

    ret = SSL_accept(session->ti.tls);
    if (ret != 1) {
        switch (SSL_get_error(session->ti.tls, ret)) {
        case SSL_ERROR_SYSCALL:
            ERR("%s: SSL_accept failed (%s).", __func__, strerror(errno));
            break;
        case SSL_ERROR_SSL:
            ERR("%s: SSL_accept failed (%s).", __func__, ERR_reason_error_string(ERR_get_error()));
            break;
        default:
            ERR("%s: SSL_accept failed.", __func__);
            break;
        }
        return -1;
    }

    return 0;
}
