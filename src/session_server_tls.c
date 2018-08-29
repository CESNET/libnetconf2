/**
 * \file session_server_tls.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 TLS server session manipulation functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <string.h>
#include <poll.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>

#include "session_server.h"
#include "session_server_ch.h"
#include "libnetconf.h"

struct nc_server_tls_opts tls_ch_opts;
pthread_mutex_t tls_ch_opts_lock = PTHREAD_MUTEX_INITIALIZER;
extern struct nc_server_opts server_opts;

static pthread_key_t verify_key;
static pthread_once_t verify_once = PTHREAD_ONCE_INIT;

static char *
asn1time_to_str(const ASN1_TIME *t)
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
    if (!cp) {
        ERRMEM;
        BIO_free(bio);
        return NULL;
    }
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
    if (!*str) {
        ERRMEM;
        return;
    }
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
            WRN("Certificate does not include the commonName field.");
            free(subject);
            return 1;
        }
        common_name += 3;
        if (strchr(common_name, '/')) {
            *strchr(common_name, '/') = '\0';
        }
        *username = strdup(common_name);
        if (!*username) {
            ERRMEM;
            return 1;
        }
        free(subject);
    } else {
        /* retrieve subjectAltName's rfc822Name (email), dNSName and iPAddress values */
        san_names = X509_get_ext_d2i(client_cert, NID_subject_alt_name, NULL, NULL);
        if (!san_names) {
            WRN("Certificate has no SANs or failed to retrieve them.");
            return 1;
        }

        san_count = sk_GENERAL_NAME_num(san_names);
        for (i = 0; i < san_count; ++i) {
            san_name = sk_GENERAL_NAME_value(san_names, i);

            /* rfc822Name (email) */
            if ((map_type == NC_TLS_CTN_SAN_ANY || map_type == NC_TLS_CTN_SAN_RFC822_NAME) &&
                    san_name->type == GEN_EMAIL) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
                *username = strdup((char *)ASN1_STRING_data(san_name->d.rfc822Name));
#else
                *username = strdup((char *)ASN1_STRING_get0_data(san_name->d.rfc822Name));
#endif
                if (!*username) {
                    ERRMEM;
                    return 1;
                }
                break;
            }

            /* dNSName */
            if ((map_type == NC_TLS_CTN_SAN_ANY || map_type == NC_TLS_CTN_SAN_DNS_NAME) &&
                    san_name->type == GEN_DNS) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
                *username = strdup((char *)ASN1_STRING_data(san_name->d.dNSName));
#else
                *username = strdup((char *)ASN1_STRING_get0_data(san_name->d.dNSName));
#endif
                if (!*username) {
                    ERRMEM;
                    return 1;
                }
                break;
            }

            /* iPAddress */
            if ((map_type == NC_TLS_CTN_SAN_ANY || map_type == NC_TLS_CTN_SAN_IP_ADDRESS) &&
                    san_name->type == GEN_IPADD) {
                ip = san_name->d.iPAddress;
                if (ip->length == 4) {
                    if (asprintf(username, "%d.%d.%d.%d", ip->data[0], ip->data[1], ip->data[2], ip->data[3]) == -1) {
                        ERRMEM;
                        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                        return -1;
                    }
                    break;
                } else if (ip->length == 16) {
                    if (asprintf(username, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                            ip->data[0], ip->data[1], ip->data[2], ip->data[3], ip->data[4], ip->data[5],
                            ip->data[6], ip->data[7], ip->data[8], ip->data[9], ip->data[10], ip->data[11],
                            ip->data[12], ip->data[13], ip->data[14], ip->data[15]) == -1) {
                        ERRMEM;
                        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                        return -1;
                    }
                    break;
                } else {
                    WRN("SAN IP address in an unknown format (length is %d).", ip->length);
                }
            }
        }
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

        if (i < san_count) {
            switch (map_type) {
            case NC_TLS_CTN_SAN_RFC822_NAME:
                WRN("Certificate does not include the SAN rfc822Name field.");
                break;
            case NC_TLS_CTN_SAN_DNS_NAME:
                WRN("Certificate does not include the SAN dNSName field.");
                break;
            case NC_TLS_CTN_SAN_IP_ADDRESS:
                WRN("Certificate does not include the SAN iPAddress field.");
                break;
            case NC_TLS_CTN_SAN_ANY:
                WRN("Certificate does not include any relevant SAN fields.");
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
nc_tls_cert_to_name(struct nc_ctn *ctn_first, X509 *cert, NC_TLS_CTN_MAPTYPE *map_type, const char **name)
{
    char *digest_md5 = NULL, *digest_sha1 = NULL, *digest_sha224 = NULL;
    char *digest_sha256 = NULL, *digest_sha384 = NULL, *digest_sha512 = NULL;
    unsigned char *buf = malloc(64);
    unsigned int buf_len = 64;
    int ret = 0;
    struct nc_ctn *ctn;

    if (!buf) {
        ERRMEM;
        return -1;
    }

    if (!ctn_first || !cert || !map_type || !name) {
        free(buf);
        return -1;
    }

    for (ctn = ctn_first; ctn; ctn = ctn->next) {
        /* first make sure the entry is valid */
        if (!ctn->fingerprint || !ctn->map_type || ((ctn->map_type == NC_TLS_CTN_SPECIFIED) && !ctn->name)) {
            VRB("Cert verify CTN: entry with id %u not valid, skipping.", ctn->id);
            continue;
        }

        /* MD5 */
        if (!strncmp(ctn->fingerprint, "01", 2)) {
            if (!digest_md5) {
                if (X509_digest(cert, EVP_md5(), buf, &buf_len) != 1) {
                    ERR("Calculating MD5 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_md5);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_md5)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found.");
                *map_type = ctn->map_type;
                if (ctn->map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = ctn->name;
                }
                break;
            }

        /* SHA-1 */
        } else if (!strncmp(ctn->fingerprint, "02", 2)) {
            if (!digest_sha1) {
                if (X509_digest(cert, EVP_sha1(), buf, &buf_len) != 1) {
                    ERR("Calculating SHA-1 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha1);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha1)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found.");
                *map_type = ctn->map_type;
                if (ctn->map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = ctn->name;
                }
                break;
            }

        /* SHA-224 */
        } else if (!strncmp(ctn->fingerprint, "03", 2)) {
            if (!digest_sha224) {
                if (X509_digest(cert, EVP_sha224(), buf, &buf_len) != 1) {
                    ERR("Calculating SHA-224 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha224);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha224)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found.");
                *map_type = ctn->map_type;
                if (ctn->map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = ctn->name;
                }
                break;
            }

        /* SHA-256 */
        } else if (!strncmp(ctn->fingerprint, "04", 2)) {
            if (!digest_sha256) {
                if (X509_digest(cert, EVP_sha256(), buf, &buf_len) != 1) {
                    ERR("Calculating SHA-256 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha256);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha256)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found.");
                *map_type = ctn->map_type;
                if (ctn->map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = ctn->name;
                }
                break;
            }

        /* SHA-384 */
        } else if (!strncmp(ctn->fingerprint, "05", 2)) {
            if (!digest_sha384) {
                if (X509_digest(cert, EVP_sha384(), buf, &buf_len) != 1) {
                    ERR("Calculating SHA-384 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha384);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha384)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found.");
                *map_type = ctn->map_type;
                if (ctn->map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = ctn->name;
                }
                break;
            }

        /* SHA-512 */
        } else if (!strncmp(ctn->fingerprint, "06", 2)) {
            if (!digest_sha512) {
                if (X509_digest(cert, EVP_sha512(), buf, &buf_len) != 1) {
                    ERR("Calculating SHA-512 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha512);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha512)) {
                /* we got ourselves a winner! */
                VRB("Cert verify CTN: entry with a matching fingerprint found.");
                *map_type = ctn->map_type;
                if (ctn->map_type == NC_TLS_CTN_SPECIFIED) {
                    *name = ctn->name;
                }
                break;
            }

        /* unknown */
        } else {
            WRN("Unknown fingerprint algorithm used (%s), skipping.", ctn->fingerprint);
        }
    }

    if (!ctn) {
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

#if OPENSSL_VERSION_NUMBER >= 0x10100000L // >= 1.1.0

static int
nc_tlsclb_verify(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    X509_STORE_CTX *store_ctx;
    X509_OBJECT *obj;
    X509_NAME *subject;
    X509_NAME *issuer;
    X509 *cert;
    X509_CRL *crl;
    X509_REVOKED *revoked;
    STACK_OF(X509) *cert_stack;
    EVP_PKEY *pubkey;
    struct nc_session* session;
    struct nc_server_tls_opts *opts;
    const ASN1_INTEGER *serial;
    int i, n, rc, depth;
    char *cp;
    const char *username = NULL;
    NC_TLS_CTN_MAPTYPE map_type = 0;
    const ASN1_TIME *last_update = NULL, *next_update = NULL;

    /* get the thread session */
    session = pthread_getspecific(verify_key);
    if (!session) {
        ERRINT;
        return 0;
    }

    opts = session->data;

    /* get the last certificate, that is the peer (client) certificate */
    if (!session->opts.server.client_cert) {
        cert_stack = X509_STORE_CTX_get1_chain(x509_ctx);
        session->opts.server.client_cert = sk_X509_value(cert_stack, 0);
        X509_up_ref(session->opts.server.client_cert);
        sk_X509_pop_free(cert_stack, X509_free);
    }

    /* standard certificate verification failed, so a trusted client cert must match to continue */
    if (!preverify_ok) {
        subject = X509_get_subject_name(session->opts.server.client_cert);
        cert_stack = X509_STORE_CTX_get1_certs(x509_ctx, subject);
        if (cert_stack) {
            for (i = 0; i < sk_X509_num(cert_stack); ++i) {
                if (cert_pubkey_match(session->opts.server.client_cert, sk_X509_value(cert_stack, i))) {
                    /* we are just overriding the failed standard certificate verification (preverify_ok == 0),
                     * this callback will be called again with the same current certificate and preverify_ok == 1 */
                    VRB("Cert verify: fail (%s), but the client certificate is trusted, continuing.",
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
    VRB("Cert verify: depth %d.", depth);

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    subject = X509_get_subject_name(cert);
    issuer = X509_get_issuer_name(cert);

    cp = X509_NAME_oneline(subject, NULL, 0);
    VRB("Cert verify: subject: %s.", cp);
    OPENSSL_free(cp);
    cp = X509_NAME_oneline(issuer, NULL, 0);
    VRB("Cert verify: issuer:  %s.", cp);
    OPENSSL_free(cp);

    /* check for revocation if set */
    if (opts->crl_store) {
        /* try to retrieve a CRL corresponding to the _subject_ of
         * the current certificate in order to verify it's integrity */
        store_ctx = X509_STORE_CTX_new();
        obj = X509_OBJECT_new();
        X509_STORE_CTX_init(store_ctx, opts->crl_store, NULL, NULL);
        rc = X509_STORE_get_by_subject(store_ctx, X509_LU_CRL, subject, obj);
        X509_STORE_CTX_free(store_ctx);
        crl = X509_OBJECT_get0_X509_CRL(obj);
        if (rc > 0 && crl) {
            cp = X509_NAME_oneline(subject, NULL, 0);
            VRB("Cert verify CRL: issuer: %s.", cp);
            OPENSSL_free(cp);

            last_update = X509_CRL_get0_lastUpdate(crl);
            next_update = X509_CRL_get0_nextUpdate(crl);
            cp = asn1time_to_str(last_update);
            VRB("Cert verify CRL: last update: %s.", cp);
            free(cp);
            cp = asn1time_to_str(next_update);
            VRB("Cert verify CRL: next update: %s.", cp);
            free(cp);

            /* verify the signature on this CRL */
            pubkey = X509_get_pubkey(cert);
            if (X509_CRL_verify(crl, pubkey) <= 0) {
                ERR("Cert verify CRL: invalid signature.");
                X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
                X509_OBJECT_free(obj);
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
                X509_OBJECT_free(obj);
                return 0;
            }
            if (X509_cmp_current_time(next_update) < 0) {
                ERR("Cert verify CRL: expired - revoking all certificates.");
                X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_HAS_EXPIRED);
                X509_OBJECT_free(obj);
                return 0;
            }
            X509_OBJECT_free(obj);
        }

        /* try to retrieve a CRL corresponding to the _issuer_ of
         * the current certificate in order to check for revocation */
        store_ctx = X509_STORE_CTX_new();
        obj = X509_OBJECT_new();
        X509_STORE_CTX_init(store_ctx, opts->crl_store, NULL, NULL);
        rc = X509_STORE_get_by_subject(store_ctx, X509_LU_CRL, issuer, obj);
        X509_STORE_CTX_free(store_ctx);
        crl = X509_OBJECT_get0_X509_CRL(obj);
        if (rc > 0 && crl) {
            /* check if the current certificate is revoked by this CRL */
            n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
            for (i = 0; i < n; i++) {
                revoked = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
                serial = X509_REVOKED_get0_serialNumber(revoked);
                if (ASN1_INTEGER_cmp(serial, X509_get_serialNumber(cert)) == 0) {
                    cp = X509_NAME_oneline(issuer, NULL, 0);
                    ERR("Cert verify CRL: certificate with serial %ld (0x%lX) revoked per CRL from issuer %s.", serial, serial, cp);
                    OPENSSL_free(cp);
                    X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REVOKED);
                    X509_OBJECT_free(obj);
                    return 0;
                }
            }
            X509_OBJECT_free(obj);
        }
    }

    /* cert-to-name already successful */
    if (session->username) {
        return 1;
    }

    /* cert-to-name */
    rc = nc_tls_cert_to_name(opts->ctn, cert, &map_type, &username);

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
        rc = nc_tls_ctn_get_username_from_cert(session->opts.server.client_cert, map_type, &cp);
        if (rc) {
            if (rc == -1) {
                depth = 0;
            }
            goto fail;
        }
        session->username = lydict_insert_zc(server_opts.ctx, cp);
    }

    VRB("Cert verify CTN: new client username recognized as \"%s\".", session->username);

    if (server_opts.user_verify_clb && !server_opts.user_verify_clb(session)) {
        VRB("Cert verify: user verify callback revoked authorization.");
        X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }

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

#else

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
    struct nc_server_tls_opts *opts;
    long serial;
    int i, n, rc, depth;
    char *cp;
    const char *username = NULL;
    NC_TLS_CTN_MAPTYPE map_type = 0;
    ASN1_TIME *last_update = NULL, *next_update = NULL;

    /* get the thread session */
    session = pthread_getspecific(verify_key);
    if (!session) {
        ERRINT;
        return 0;
    }

    opts = session->data;

    /* get the last certificate, that is the peer (client) certificate */
    if (!session->opts.server.client_cert) {
        cert_stack = X509_STORE_CTX_get1_chain(x509_ctx);
        while ((cert = sk_X509_pop(cert_stack))) {
            X509_free(session->opts.server.client_cert);
            session->opts.server.client_cert = cert;
        }
        sk_X509_pop_free(cert_stack, X509_free);
    }

    /* standard certificate verification failed, so a trusted client cert must match to continue */
    if (!preverify_ok) {
        subject = X509_get_subject_name(session->opts.server.client_cert);
        cert_stack = X509_STORE_get1_certs(x509_ctx, subject);
        if (cert_stack) {
            for (i = 0; i < sk_X509_num(cert_stack); ++i) {
                if (cert_pubkey_match(session->opts.server.client_cert, sk_X509_value(cert_stack, i))) {
                    /* we are just overriding the failed standard certificate verification (preverify_ok == 0),
                     * this callback will be called again with the same current certificate and preverify_ok == 1 */
                    VRB("Cert verify: fail (%s), but the client certificate is trusted, continuing.",
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
    VRB("Cert verify: depth %d.", depth);

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    subject = X509_get_subject_name(cert);
    issuer = X509_get_issuer_name(cert);

    cp = X509_NAME_oneline(subject, NULL, 0);
    VRB("Cert verify: subject: %s.", cp);
    OPENSSL_free(cp);
    cp = X509_NAME_oneline(issuer, NULL, 0);
    VRB("Cert verify: issuer:  %s.", cp);
    OPENSSL_free(cp);

    /* check for revocation if set */
    if (opts->crl_store) {
        /* try to retrieve a CRL corresponding to the _subject_ of
         * the current certificate in order to verify it's integrity */
        memset((char *)&obj, 0, sizeof(obj));
        X509_STORE_CTX_init(&store_ctx, opts->crl_store, NULL, NULL);
        rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
        X509_STORE_CTX_cleanup(&store_ctx);
        crl = obj.data.crl;
        if (rc > 0 && crl) {
            cp = X509_NAME_oneline(subject, NULL, 0);
            VRB("Cert verify CRL: issuer: %s.", cp);
            OPENSSL_free(cp);

            last_update = X509_CRL_get_lastUpdate(crl);
            next_update = X509_CRL_get_nextUpdate(crl);
            cp = asn1time_to_str(last_update);
            VRB("Cert verify CRL: last update: %s.", cp);
            free(cp);
            cp = asn1time_to_str(next_update);
            VRB("Cert verify CRL: next update: %s.", cp);
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
        X509_STORE_CTX_init(&store_ctx, opts->crl_store, NULL, NULL);
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
                    ERR("Cert verify CRL: certificate with serial %ld (0x%lX) revoked per CRL from issuer %s.", serial, serial, cp);
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
    rc = nc_tls_cert_to_name(opts->ctn, cert, &map_type, &username);

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
        rc = nc_tls_ctn_get_username_from_cert(session->opts.server.client_cert, map_type, &cp);
        if (rc) {
            if (rc == -1) {
                depth = 0;
            }
            goto fail;
        }
        session->username = lydict_insert_zc(server_opts.ctx, cp);
    }

    VRB("Cert verify CTN: new client username recognized as \"%s\".", session->username);

    if (server_opts.user_verify_clb && !server_opts.user_verify_clb(session)) {
        VRB("Cert verify: user verify callback revoked authorization.");
        X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }

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

#endif

static int
nc_server_tls_set_server_cert(const char *name, struct nc_server_tls_opts *opts)
{
    if (!name) {
        if (opts->server_cert) {
            lydict_remove(server_opts.ctx, opts->server_cert);
        }
        opts->server_cert = NULL;
        return 0;
    }

    if (opts->server_cert) {
        lydict_remove(server_opts.ctx, opts->server_cert);
    }
    opts->server_cert = lydict_insert(server_opts.ctx, name, 0);

    return 0;
}

API int
nc_server_tls_endpt_set_server_cert(const char *endpt_name, const char *name)
{
    int ret;
    struct nc_endpt *endpt;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_OPENSSL, NULL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_set_server_cert(name, endpt->opts.tls);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_tls_ch_client_set_server_cert(const char *client_name, const char *name)
{
    int ret;
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_OPENSSL, NULL);
    if (!client) {
        return -1;
    }

    ret = nc_server_tls_set_server_cert(name, client->opts.tls);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

API void
nc_server_tls_set_server_cert_clb(int (*cert_clb)(const char *name, void *user_data, char **cert_path, char **cert_data,
                                                  char **privkey_path, char **privkey_data, int *privkey_data_rsa),
                                  void *user_data, void (*free_user_data)(void *user_data))
{
    if (!cert_clb) {
        ERRARG("cert_clb");
        return;
    }

    server_opts.server_cert_clb = cert_clb;
    server_opts.server_cert_data = user_data;
    server_opts.server_cert_data_free = free_user_data;
}

API void
nc_server_tls_set_server_cert_chain_clb(int (*cert_chain_clb)(const char *name, void *user_data, char ***cert_paths,
                                                              int *cert_path_count, char ***cert_data, int *cert_data_count),
                                        void *user_data, void (*free_user_data)(void *user_data))
{
    if (!cert_chain_clb) {
        ERRARG("cert_chain_clb");
        return;
    }

    server_opts.server_cert_chain_clb = cert_chain_clb;
    server_opts.server_cert_chain_data = user_data;
    server_opts.server_cert_chain_data_free = free_user_data;
}

static int
nc_server_tls_add_trusted_cert_list(const char *name, struct nc_server_tls_opts *opts)
{
    if (!name) {
        ERRARG("name");
        return -1;
    }

    ++opts->trusted_cert_list_count;
    opts->trusted_cert_lists = nc_realloc(opts->trusted_cert_lists, opts->trusted_cert_list_count * sizeof *opts->trusted_cert_lists);
    if (!opts->trusted_cert_lists) {
        ERRMEM;
        return -1;
    }
    opts->trusted_cert_lists[opts->trusted_cert_list_count - 1] = lydict_insert(server_opts.ctx, name, 0);

    return 0;
}

API int
nc_server_tls_endpt_add_trusted_cert_list(const char *endpt_name, const char *name)
{
    int ret;
    struct nc_endpt *endpt;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_OPENSSL, NULL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_add_trusted_cert_list(name, endpt->opts.tls);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_tls_ch_client_add_trusted_cert_list(const char *client_name, const char *name)
{
    int ret;
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_OPENSSL, NULL);
    if (!client) {
        return -1;
    }

    ret = nc_server_tls_add_trusted_cert_list(name, client->opts.tls);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

API void
nc_server_tls_set_trusted_cert_list_clb(int (*cert_list_clb)(const char *name, void *user_data, char ***cert_paths,
                                                             int *cert_path_count, char ***cert_data, int *cert_data_count),
                                        void *user_data, void (*free_user_data)(void *user_data))
{
    if (!cert_list_clb) {
        ERRARG("cert_list_clb");
        return;
    }

    server_opts.trusted_cert_list_clb = cert_list_clb;
    server_opts.trusted_cert_list_data = user_data;
    server_opts.trusted_cert_list_data_free = free_user_data;
}

static int
nc_server_tls_del_trusted_cert_list(const char *name, struct nc_server_tls_opts *opts)
{
    uint16_t i;

    if (!name) {
        for (i = 0; i < opts->trusted_cert_list_count; ++i) {
            lydict_remove(server_opts.ctx, opts->trusted_cert_lists[i]);
        }
        free(opts->trusted_cert_lists);
        opts->trusted_cert_lists = NULL;
        opts->trusted_cert_list_count = 0;
        return 0;
    } else {
        for (i = 0; i < opts->trusted_cert_list_count; ++i) {
            if (!strcmp(opts->trusted_cert_lists[i], name)) {
                lydict_remove(server_opts.ctx, opts->trusted_cert_lists[i]);

                --opts->trusted_cert_list_count;
                if (i < opts->trusted_cert_list_count - 1) {
                    memmove(opts->trusted_cert_lists + i, opts->trusted_cert_lists + i + 1,
                            (opts->trusted_cert_list_count - i) * sizeof *opts->trusted_cert_lists);
                }
                return 0;
            }
        }
    }

    ERR("Certificate list \"%s\" not found.", name);
    return -1;
}

API int
nc_server_tls_endpt_del_trusted_cert_list(const char *endpt_name, const char *name)
{
    int ret;
    struct nc_endpt *endpt;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_OPENSSL, NULL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_del_trusted_cert_list(name, endpt->opts.tls);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_tls_ch_client_del_trusted_cert_list(const char *client_name, const char *name)
{
    int ret;
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_OPENSSL, NULL);
    if (!client) {
        return -1;
    }

    ret = nc_server_tls_del_trusted_cert_list(name, client->opts.tls);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static int
nc_server_tls_set_trusted_ca_paths(const char *ca_file, const char *ca_dir, struct nc_server_tls_opts *opts)
{
    if (!ca_file && !ca_dir) {
        ERRARG("ca_file and ca_dir");
        return -1;
    }

    if (ca_file) {
        if (opts->trusted_ca_file) {
            lydict_remove(server_opts.ctx, opts->trusted_ca_file);
        }
        opts->trusted_ca_file = lydict_insert(server_opts.ctx, ca_file, 0);
    }

    if (ca_dir) {
        if (opts->trusted_ca_dir) {
            lydict_remove(server_opts.ctx, opts->trusted_ca_dir);
        }
        opts->trusted_ca_dir = lydict_insert(server_opts.ctx, ca_dir, 0);
    }

    return 0;
}

API int
nc_server_tls_endpt_set_trusted_ca_paths(const char *endpt_name, const char *ca_file, const char *ca_dir)
{
    int ret;
    struct nc_endpt *endpt;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_OPENSSL, NULL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_set_trusted_ca_paths(ca_file, ca_dir, endpt->opts.tls);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_tls_ch_client_set_trusted_ca_paths(const char *client_name, const char *ca_file, const char *ca_dir)
{
    int ret;
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_OPENSSL, NULL);
    if (!client) {
        return -1;
    }

    ret = nc_server_tls_set_trusted_ca_paths(ca_file, ca_dir, client->opts.tls);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static int
nc_server_tls_set_crl_paths(const char *crl_file, const char *crl_dir, struct nc_server_tls_opts *opts)
{
    X509_LOOKUP *lookup;

    if (!crl_file && !crl_dir) {
        ERRARG("crl_file and crl_dir");
        return -1;
    }

    if (!opts->crl_store) {
        opts->crl_store = X509_STORE_new();
    }

    if (crl_file) {
        lookup = X509_STORE_add_lookup(opts->crl_store, X509_LOOKUP_file());
        if (!lookup) {
            ERR("Failed to add a lookup method.");
            goto fail;
        }

        if (X509_LOOKUP_load_file(lookup, crl_file, X509_FILETYPE_PEM) != 1) {
            ERR("Failed to add a revocation lookup file (%s).", ERR_reason_error_string(ERR_get_error()));
            goto fail;
        }
    }

    if (crl_dir) {
        lookup = X509_STORE_add_lookup(opts->crl_store, X509_LOOKUP_hash_dir());
        if (!lookup) {
            ERR("Failed to add a lookup method.");
            goto fail;
        }

        if (X509_LOOKUP_add_dir(lookup, crl_dir, X509_FILETYPE_PEM) != 1) {
            ERR("Failed to add a revocation lookup directory (%s).", ERR_reason_error_string(ERR_get_error()));
            goto fail;
        }
    }

    return 0;

fail:
    return -1;
}

API int
nc_server_tls_endpt_set_crl_paths(const char *endpt_name, const char *crl_file, const char *crl_dir)
{
    int ret;
    struct nc_endpt *endpt;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_OPENSSL, NULL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_set_crl_paths(crl_file, crl_dir, endpt->opts.tls);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_tls_ch_client_set_crl_paths(const char *client_name, const char *crl_file, const char *crl_dir)
{
    int ret;
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_OPENSSL, NULL);
    if (!client) {
        return -1;
    }

    ret = nc_server_tls_set_crl_paths(crl_file, crl_dir, client->opts.tls);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static void
nc_server_tls_clear_crls(struct nc_server_tls_opts *opts)
{
    if (!opts->crl_store) {
        return;
    }

    X509_STORE_free(opts->crl_store);
    opts->crl_store = NULL;
}

API void
nc_server_tls_endpt_clear_crls(const char *endpt_name)
{
    struct nc_endpt *endpt;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return;
    }

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_OPENSSL, NULL);
    if (!endpt) {
        return;
    }
    nc_server_tls_clear_crls(endpt->opts.tls);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);
}

API void
nc_server_tls_ch_client_clear_crls(const char *client_name)
{
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return;
    }

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_OPENSSL, NULL);
    if (!client) {
        return;
    }

    nc_server_tls_clear_crls(client->opts.tls);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);
}

static int
nc_server_tls_add_ctn(uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name,
                      struct nc_server_tls_opts *opts)
{
    struct nc_ctn *ctn, *new;

    if (!opts->ctn) {
        /* the first item */
        opts->ctn = new = calloc(1, sizeof *new);
        if (!new) {
            ERRMEM;
            return -1;
        }
    } else if (opts->ctn->id > id) {
        /* insert at the beginning */
        new = calloc(1, sizeof *new);
        if (!new) {
            ERRMEM;
            return -1;
        }
        new->next = opts->ctn;
        opts->ctn = new;
    } else {
        for (ctn = opts->ctn; ctn->next && ctn->next->id <= id; ctn = ctn->next);
        if (ctn->id == id) {
            /* it exists already */
            new = ctn;
        } else {
            /* insert after ctn */
            new = calloc(1, sizeof *new);
            if (!new) {
                ERRMEM;
                return -1;
            }
            new->next = ctn->next;
            ctn->next = new;
        }
    }

    new->id = id;
    if (fingerprint) {
        if (new->fingerprint) {
            lydict_remove(server_opts.ctx, new->fingerprint);
        }
        new->fingerprint = lydict_insert(server_opts.ctx, fingerprint, 0);
    }
    if (map_type) {
        new->map_type = map_type;
    }
    if (name) {
        if (new->name) {
            lydict_remove(server_opts.ctx, new->name);
        }
        new->name = lydict_insert(server_opts.ctx, name, 0);
    }

    return 0;
}

API int
nc_server_tls_endpt_add_ctn(const char *endpt_name, uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type,
                            const char *name)
{
    int ret;
    struct nc_endpt *endpt;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_OPENSSL, NULL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_add_ctn(id, fingerprint, map_type, name, endpt->opts.tls);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_tls_ch_client_add_ctn(const char *client_name, uint32_t id, const char *fingerprint,
                                NC_TLS_CTN_MAPTYPE map_type, const char *name)
{
    int ret;
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_OPENSSL, NULL);
    if (!client) {
        return -1;
    }

    ret = nc_server_tls_add_ctn(id, fingerprint, map_type, name, client->opts.tls);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static int
nc_server_tls_del_ctn(int64_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name,
                      struct nc_server_tls_opts *opts)
{
    struct nc_ctn *ctn, *next, *prev;
    int ret = -1;

    if ((id < 0) && !fingerprint && !map_type && !name) {
        ctn = opts->ctn;
        while (ctn) {
            lydict_remove(server_opts.ctx, ctn->fingerprint);
            lydict_remove(server_opts.ctx, ctn->name);

            next = ctn->next;
            free(ctn);
            ctn = next;

            ret = 0;
        }
        opts->ctn = NULL;
    } else {
        prev = NULL;
        ctn = opts->ctn;
        while (ctn) {
            if (((id < 0) || (ctn->id == id))
                    && (!fingerprint || !strcmp(ctn->fingerprint, fingerprint))
                    && (!map_type || (ctn->map_type == map_type))
                    && (!name || (ctn->name && !strcmp(ctn->name, name)))) {
                lydict_remove(server_opts.ctx, ctn->fingerprint);
                lydict_remove(server_opts.ctx, ctn->name);

                if (prev) {
                    prev->next = ctn->next;
                    next = ctn->next;
                } else {
                    opts->ctn = ctn->next;
                    next = ctn->next;
                }
                free(ctn);
                ctn = next;

                ret = 0;
            } else {
                prev = ctn;
                ctn = ctn->next;
            }
        }
    }

    return ret;
}

API int
nc_server_tls_endpt_del_ctn(const char *endpt_name, int64_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type,
                            const char *name)
{
    int ret;
    struct nc_endpt *endpt;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_OPENSSL, NULL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_del_ctn(id, fingerprint, map_type, name, endpt->opts.tls);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_tls_ch_client_del_ctn(const char *client_name, int64_t id, const char *fingerprint,
                                NC_TLS_CTN_MAPTYPE map_type, const char *name)
{
    int ret;
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_OPENSSL, NULL);
    if (!client) {
        return -1;
    }

    ret = nc_server_tls_del_ctn(id, fingerprint, map_type, name, client->opts.tls);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static int
nc_server_tls_get_ctn(uint32_t *id, char **fingerprint, NC_TLS_CTN_MAPTYPE *map_type, char **name,
                      struct nc_server_tls_opts *opts)
{
    struct nc_ctn *ctn;
    int ret = -1;

    for (ctn = opts->ctn; ctn; ctn = ctn->next) {
        if (id && *id && (*id != ctn->id)) {
            continue;
        }
        if (fingerprint && *fingerprint && (!ctn->fingerprint || strcmp(*fingerprint, ctn->fingerprint))) {
            continue;
        }
        if (map_type && *map_type && (!ctn->map_type || (*map_type != ctn->map_type))) {
            continue;
        }
        if (name && *name && (!ctn->name || strcmp(*name, ctn->name))) {
            continue;
        }

        /* first match, good enough */
        if (id && !(*id)) {
            *id = ctn->id;
        }
        if (fingerprint && !(*fingerprint) && ctn->fingerprint) {
            *fingerprint = strdup(ctn->fingerprint);
        }
        if (map_type && !(*map_type) && ctn->map_type) {
            *map_type = ctn->map_type;
        }
        if (name && !(*name) && ctn->name && ctn->name) {
            *name = strdup(ctn->name);
        }

        ret = 0;
        break;
    }

    return ret;
}

API int
nc_server_tls_endpt_get_ctn(const char *endpt_name, uint32_t *id, char **fingerprint, NC_TLS_CTN_MAPTYPE *map_type,
                            char **name)
{
    int ret;
    struct nc_endpt *endpt;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_OPENSSL, NULL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_get_ctn(id, fingerprint, map_type, name, endpt->opts.tls);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_tls_ch_client_get_ctn(const char *client_name, uint32_t *id, char **fingerprint, NC_TLS_CTN_MAPTYPE *map_type,
                                char **name)
{
    int ret;
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_OPENSSL, NULL);
    if (!client) {
        return -1;
    }

    ret = nc_server_tls_get_ctn(id, fingerprint, map_type, name, client->opts.tls);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

API const X509 *
nc_session_get_client_cert(const struct nc_session *session)
{
    if (!session || (session->side != NC_SERVER)) {
        ERRARG("session");
        return NULL;
    }

    return session->opts.server.client_cert;
}

API void
nc_server_tls_set_verify_clb(int (*verify_clb)(const struct nc_session *session))
{
    server_opts.user_verify_clb = verify_clb;
}

void
nc_server_tls_clear_opts(struct nc_server_tls_opts *opts)
{
    lydict_remove(server_opts.ctx, opts->server_cert);
    nc_server_tls_del_trusted_cert_list(NULL, opts);
    lydict_remove(server_opts.ctx, opts->trusted_ca_file);
    lydict_remove(server_opts.ctx, opts->trusted_ca_dir);
    nc_server_tls_clear_crls(opts);
    nc_server_tls_del_ctn(-1, NULL, 0, NULL, opts);
}

static void
nc_tls_make_verify_key(void)
{
    pthread_key_create(&verify_key, NULL);
}

static X509*
tls_load_cert(const char *cert_path, const char *cert_data)
{
    X509 *cert;

    if (cert_path) {
        cert = pem_to_cert(cert_path);
    } else {
        cert = base64der_to_cert(cert_data);
    }

    if (!cert) {
        if (cert_path) {
            ERR("Loading a trusted certificate (path \"%s\") failed (%s).", cert_path,
                ERR_reason_error_string(ERR_get_error()));
        } else {
            ERR("Loading a trusted certificate (data \"%s\") failed (%s).", cert_data,
                ERR_reason_error_string(ERR_get_error()));
        }
    }
    return cert;
}

static int
nc_tls_ctx_set_server_cert_chain(SSL_CTX *tls_ctx, const char *cert_name)
{
    char **cert_paths = NULL, **cert_data = NULL;
    int cert_path_count = 0, cert_data_count = 0, ret = 0, i = 0;
    X509 *cert = NULL;

    if (!server_opts.server_cert_chain_clb) {
        /* This is optional, so return OK */
        return 0;
    }

    if (server_opts.server_cert_chain_clb(cert_name, server_opts.server_cert_chain_data, &cert_paths,
                                          &cert_path_count, &cert_data, &cert_data_count)) {
        ERR("Server certificate chain callback failed.");
        return -1;
    }

    for (i = 0; i < cert_path_count; ++i) {
        cert = tls_load_cert(cert_paths[i], NULL);
        if (!cert || SSL_CTX_add_extra_chain_cert(tls_ctx, cert) != 1) {
            ERR("Loading the server certificate chain failed (%s).", ERR_reason_error_string(ERR_get_error()));
            ret = -1;
            goto cleanup;
        }
    }

    for (i = 0; i < cert_data_count; ++i) {
        cert = tls_load_cert(NULL, cert_data[i]);
        if (!cert || SSL_CTX_add_extra_chain_cert(tls_ctx, cert) != 1) {
            ERR("Loading the server certificate chain failed (%s).", ERR_reason_error_string(ERR_get_error()));
            ret = -1;
            goto cleanup;
        }
    }
cleanup:
    for (i = 0; i < cert_path_count; ++i) {
        free(cert_paths[i]);
    }
    free(cert_paths);
    for (i = 0; i < cert_data_count; ++i) {
        free(cert_data[i]);
    }
    free(cert_data);
    /* cert is owned by the SSL_CTX */

    return ret;
}

static int
nc_tls_ctx_set_server_cert_key(SSL_CTX *tls_ctx, const char *cert_name)
{
    char *cert_path = NULL, *cert_data = NULL, *privkey_path = NULL, *privkey_data = NULL;
    int privkey_data_rsa = 1, ret = 0;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;

    if (!cert_name) {
        ERR("Server certificate not set.");
        return -1;
    } else if (!server_opts.server_cert_clb) {
        ERR("Callback for retrieving the server certificate is not set.");
        return -1;
    }

    if (server_opts.server_cert_clb(cert_name, server_opts.server_cert_data, &cert_path, &cert_data, &privkey_path,
                                    &privkey_data, &privkey_data_rsa)) {
        ERR("Server certificate callback failed.");
        return -1;
    }

    /* load the certificate */
    if (cert_path) {
        if (SSL_CTX_use_certificate_file(tls_ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
            ERR("Loading the server certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
            ret = -1;
            goto cleanup;
        }
    } else {
        cert = base64der_to_cert(cert_data);
        if (!cert || (SSL_CTX_use_certificate(tls_ctx, cert) != 1)) {
            ERR("Loading the server certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
            ret = -1;
            goto cleanup;
        }
    }

    /* load the private key */
    if (privkey_path) {
        if (SSL_CTX_use_PrivateKey_file(tls_ctx, privkey_path, SSL_FILETYPE_PEM) != 1) {
            ERR("Loading the server private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
            ret = -1;
            goto cleanup;
        }
    } else {
        pkey = base64der_to_privatekey(privkey_data, privkey_data_rsa);
        if (!pkey || (SSL_CTX_use_PrivateKey(tls_ctx, pkey) != 1)) {
            ERR("Loading the server private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
            ret = -1;
            goto cleanup;
        }
    }

    ret = nc_tls_ctx_set_server_cert_chain(tls_ctx, cert_name);

cleanup:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    free(cert_path);
    free(cert_data);
    free(privkey_path);
    free(privkey_data);
    return ret;
}

static void
tls_store_add_trusted_cert(X509_STORE *cert_store, const char *cert_path, const char *cert_data)
{
    X509 *cert = tls_load_cert(cert_path, cert_data);
    if (!cert) {
        return;
    }

    /* add the trusted certificate */
    if (X509_STORE_add_cert(cert_store, cert) != 1) {
        ERR("Adding a trusted certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
        X509_free(cert);
        return;
    }
    X509_free(cert);
}

static int
nc_tls_store_set_trusted_certs(X509_STORE *cert_store, const char **trusted_cert_lists, uint16_t trusted_cert_list_count)
{
    uint16_t i;
    int j;
    char **cert_paths, **cert_data;
    int cert_path_count, cert_data_count;

    if (!server_opts.trusted_cert_list_clb) {
        ERR("Callback for retrieving trusted certificate lists is not set.");
        return -1;
    }

    for (i = 0; i < trusted_cert_list_count; ++i) {
        cert_paths = cert_data = NULL;
        cert_path_count = cert_data_count = 0;
        if (server_opts.trusted_cert_list_clb(trusted_cert_lists[i], server_opts.trusted_cert_list_data,
                                              &cert_paths, &cert_path_count, &cert_data, &cert_data_count)) {
            ERR("Trusted certificate list callback for \"%s\" failed.", trusted_cert_lists[i]);
            return -1;
        }

        for (j = 0; j < cert_path_count; ++j) {
            tls_store_add_trusted_cert(cert_store, cert_paths[j], NULL);
            free(cert_paths[j]);
        }
        free(cert_paths);

        for (j = 0; j < cert_data_count; ++j) {
            tls_store_add_trusted_cert(cert_store, NULL, cert_data[j]);
            free(cert_data[j]);
        }
        free(cert_data);
    }

    return 0;
}

int
nc_accept_tls_session(struct nc_session *session, int sock, int timeout)
{
    X509_STORE *cert_store;
    SSL_CTX *tls_ctx;
    X509_LOOKUP *lookup;
    struct nc_server_tls_opts *opts;
    int ret;
    struct timespec ts_timeout, ts_cur;

    opts = session->data;

    /* SSL_CTX */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L // >= 1.1.0
    tls_ctx = SSL_CTX_new(TLS_server_method());
#else
    tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
#endif
    if (!tls_ctx) {
        ERR("Failed to create TLS context.");
        goto error;
    }
    SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    if (nc_tls_ctx_set_server_cert_key(tls_ctx, opts->server_cert)) {
        goto error;
    }

    /* X509_STORE, managed (freed) with the context */
    cert_store = X509_STORE_new();
    SSL_CTX_set_cert_store(tls_ctx, cert_store);

    if (nc_tls_store_set_trusted_certs(cert_store, opts->trusted_cert_lists, opts->trusted_cert_list_count)) {
        goto error;
    }

    if (opts->trusted_ca_file) {
        lookup = X509_STORE_add_lookup(cert_store, X509_LOOKUP_file());
        if (!lookup) {
            ERR("Failed to add a lookup method.");
            goto error;
        }

        if (X509_LOOKUP_load_file(lookup, opts->trusted_ca_file, X509_FILETYPE_PEM) != 1) {
            ERR("Failed to add a trusted cert file (%s).", ERR_reason_error_string(ERR_get_error()));
            goto error;
        }
    }

    if (opts->trusted_ca_dir) {
        lookup = X509_STORE_add_lookup(cert_store, X509_LOOKUP_hash_dir());
        if (!lookup) {
            ERR("Failed to add a lookup method.");
            goto error;
        }

        if (X509_LOOKUP_add_dir(lookup, opts->trusted_ca_dir, X509_FILETYPE_PEM) != 1) {
            ERR("Failed to add a trusted cert directory (%s).", ERR_reason_error_string(ERR_get_error()));
            goto error;
        }
    }

    session->ti_type = NC_TI_OPENSSL;
    session->ti.tls = SSL_new(tls_ctx);

    /* context can be freed already, trusted certs must be freed manually */
    SSL_CTX_free(tls_ctx);
    tls_ctx = NULL;

    if (!session->ti.tls) {
        ERR("Failed to create TLS structure from context.");
        goto error;
    }

    SSL_set_fd(session->ti.tls, sock);
    sock = -1;
    SSL_set_mode(session->ti.tls, SSL_MODE_AUTO_RETRY);

    /* store session on per-thread basis */
    pthread_once(&verify_once, nc_tls_make_verify_key);
    pthread_setspecific(verify_key, session);

    if (timeout > -1) {
        nc_gettimespec_mono(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);
    }
    while (((ret = SSL_accept(session->ti.tls)) == -1) && (SSL_get_error(session->ti.tls, ret) == SSL_ERROR_WANT_READ)) {
        usleep(NC_TIMEOUT_STEP);
        if (timeout > -1) {
            nc_gettimespec_mono(&ts_cur);
            if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
                ERR("SSL_accept timeout.");
                return 0;
            }
        }
    }

    if (ret != 1) {
        switch (SSL_get_error(session->ti.tls, ret)) {
        case SSL_ERROR_SYSCALL:
            ERR("SSL_accept failed (%s).", strerror(errno));
            break;
        case SSL_ERROR_SSL:
            ERR("SSL_accept failed (%s).", ERR_reason_error_string(ERR_get_error()));
            break;
        default:
            ERR("SSL_accept failed.");
            break;
        }
        return -1;
    }

    return 1;

error:
    if (sock > -1) {
        close(sock);
    }
    SSL_CTX_free(tls_ctx);
    return -1;
}
