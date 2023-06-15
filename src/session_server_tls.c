/**
 * @file session_server_tls.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 TLS server session manipulation functions
 *
 * @copyright
 * Copyright (c) 2015 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "session.h"
#include "session_p.h"

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

static EVP_PKEY *
base64der_to_privatekey(const char *in, const char *key_str)
{
    EVP_PKEY *out;
    char *buf;
    BIO *bio;

    if (in == NULL) {
        return NULL;
    }

    if (asprintf(&buf, "%s%s%s%s%s%s%s", "-----BEGIN ", key_str, " PRIVATE KEY-----\n", in, "\n-----END ",
            key_str, " PRIVATE KEY-----") == -1) {
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
    STACK_OF(GENERAL_NAME) * san_names;
    GENERAL_NAME *san_name;
    ASN1_OCTET_STRING *ip;
    int i, san_count;
    char *subject, *common_name;

    *username = NULL;

    if (map_type == NC_TLS_CTN_COMMON_NAME) {
        subject = X509_NAME_oneline(X509_get_subject_name(client_cert), NULL, 0);
        common_name = strstr(subject, "CN=");
        if (!common_name) {
            WRN(NULL, "Certificate does not include the commonName field.");
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
            WRN(NULL, "Certificate has no SANs or failed to retrieve them.");
            return 1;
        }

        san_count = sk_GENERAL_NAME_num(san_names);
        for (i = 0; i < san_count; ++i) {
            san_name = sk_GENERAL_NAME_value(san_names, i);

            /* rfc822Name (email) */
            if (((map_type == NC_TLS_CTN_SAN_ANY) || (map_type == NC_TLS_CTN_SAN_RFC822_NAME)) &&
                    (san_name->type == GEN_EMAIL)) {
                *username = strdup((char *)ASN1_STRING_get0_data(san_name->d.rfc822Name));
                if (!*username) {
                    ERRMEM;
                    return 1;
                }
                break;
            }

            /* dNSName */
            if (((map_type == NC_TLS_CTN_SAN_ANY) || (map_type == NC_TLS_CTN_SAN_DNS_NAME)) &&
                    (san_name->type == GEN_DNS)) {
                *username = strdup((char *)ASN1_STRING_get0_data(san_name->d.dNSName));
                if (!*username) {
                    ERRMEM;
                    return 1;
                }
                break;
            }

            /* iPAddress */
            if (((map_type == NC_TLS_CTN_SAN_ANY) || (map_type == NC_TLS_CTN_SAN_IP_ADDRESS)) &&
                    (san_name->type == GEN_IPADD)) {
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
                    WRN(NULL, "SAN IP address in an unknown format (length is %d).", ip->length);
                }
            }
        }
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

        if (i == san_count) {
            switch (map_type) {
            case NC_TLS_CTN_SAN_RFC822_NAME:
                WRN(NULL, "Certificate does not include the SAN rfc822Name field.");
                break;
            case NC_TLS_CTN_SAN_DNS_NAME:
                WRN(NULL, "Certificate does not include the SAN dNSName field.");
                break;
            case NC_TLS_CTN_SAN_IP_ADDRESS:
                WRN(NULL, "Certificate does not include the SAN iPAddress field.");
                break;
            case NC_TLS_CTN_SAN_ANY:
                WRN(NULL, "Certificate does not include any relevant SAN fields.");
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
nc_tls_cert_to_name(struct nc_session *session, struct nc_ctn *ctn_first, X509 *cert)
{
    char *digest_md5 = NULL, *digest_sha1 = NULL, *digest_sha224 = NULL;
    char *digest_sha256 = NULL, *digest_sha384 = NULL, *digest_sha512 = NULL;
    unsigned char *buf = malloc(64);
    unsigned int buf_len = 64;
    int ret = 0;
    struct nc_ctn *ctn;
    NC_TLS_CTN_MAPTYPE map_type;
    char *username = NULL;

    if (!buf) {
        ERRMEM;
        return -1;
    }

    if (!session || !ctn_first || !cert) {
        free(buf);
        return -1;
    }

    for (ctn = ctn_first; ctn; ctn = ctn->next) {
        /* reset map_type */
        map_type = NC_TLS_CTN_UNKNOWN;

        /* first make sure the entry is valid */
        if (!ctn->map_type || ((ctn->map_type == NC_TLS_CTN_SPECIFIED) && !ctn->name)) {
            VRB(NULL, "Cert verify CTN: entry with id %u not valid, skipping.", ctn->id);
            continue;
        }

        /* if ctn has no fingerprint, it will match any certificate */
        if (!ctn->fingerprint) {
            map_type = ctn->map_type;

            /* MD5 */
        } else if (!strncmp(ctn->fingerprint, "01", 2)) {
            if (!digest_md5) {
                if (X509_digest(cert, EVP_md5(), buf, &buf_len) != 1) {
                    ERR(NULL, "Calculating MD5 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_md5);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_md5)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }
            free(digest_md5);
            digest_md5 = NULL;

            /* SHA-1 */
        } else if (!strncmp(ctn->fingerprint, "02", 2)) {
            if (!digest_sha1) {
                if (X509_digest(cert, EVP_sha1(), buf, &buf_len) != 1) {
                    ERR(NULL, "Calculating SHA-1 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha1);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha1)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }
            free(digest_sha1);
            digest_sha1 = NULL;

            /* SHA-224 */
        } else if (!strncmp(ctn->fingerprint, "03", 2)) {
            if (!digest_sha224) {
                if (X509_digest(cert, EVP_sha224(), buf, &buf_len) != 1) {
                    ERR(NULL, "Calculating SHA-224 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha224);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha224)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }
            free(digest_sha224);
            digest_sha224 = NULL;

            /* SHA-256 */
        } else if (!strncmp(ctn->fingerprint, "04", 2)) {
            if (!digest_sha256) {
                if (X509_digest(cert, EVP_sha256(), buf, &buf_len) != 1) {
                    ERR(NULL, "Calculating SHA-256 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha256);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha256)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }
            free(digest_sha256);
            digest_sha256 = NULL;

            /* SHA-384 */
        } else if (!strncmp(ctn->fingerprint, "05", 2)) {
            if (!digest_sha384) {
                if (X509_digest(cert, EVP_sha384(), buf, &buf_len) != 1) {
                    ERR(NULL, "Calculating SHA-384 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha384);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha384)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }
            free(digest_sha384);
            digest_sha384 = NULL;

            /* SHA-512 */
        } else if (!strncmp(ctn->fingerprint, "06", 2)) {
            if (!digest_sha512) {
                if (X509_digest(cert, EVP_sha512(), buf, &buf_len) != 1) {
                    ERR(NULL, "Calculating SHA-512 digest failed (%s).", ERR_reason_error_string(ERR_get_error()));
                    ret = -1;
                    goto cleanup;
                }
                digest_to_str(buf, buf_len, &digest_sha512);
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha512)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }
            free(digest_sha512);
            digest_sha512 = NULL;

            /* unknown */
        } else {
            WRN(NULL, "Unknown fingerprint algorithm used (%s), skipping.", ctn->fingerprint);
            continue;
        }

        if (map_type != NC_TLS_CTN_UNKNOWN) {
            /* found a fingerprint match */
            if (map_type == NC_TLS_CTN_SPECIFIED) {
                /* specified -> get username from the ctn entry */
                session->username = strdup(ctn->name);
                if (!session->username) {
                    ERRMEM;
                    ret = -1;
                    goto cleanup;
                }
            } else {
                /* try to get the username from the cert with this ctn's map type */
                ret = nc_tls_ctn_get_username_from_cert(session->opts.server.client_cert, map_type, &username);
                if (ret == -1) {
                    /* fatal error */
                    goto cleanup;
                } else if (ret) {
                    /* didn't get username, try next ctn entry */
                    continue;
                }

                /* success */
                session->username = username;
            }

            /* matching fingerprint found and username obtained, success */
            ret = 0;
            goto cleanup;
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

static int
nc_server_tls_check_crl(X509_STORE *crl_store, X509_STORE_CTX *x509_ctx, X509 *cert,
        const X509_NAME *subject, const X509_NAME *issuer)
{
    int n, i, ret = 0;
    X509_STORE_CTX *store_ctx = NULL;
    X509_OBJECT *obj = NULL;
    X509_CRL *crl;
    X509_REVOKED *revoked;
    EVP_PKEY *pubkey;
    const ASN1_INTEGER *serial;
    const ASN1_TIME *last_update = NULL, *next_update = NULL;
    char *cp;

    store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        ERRMEM;
        ret = -1;
        goto cleanup;
    }

    /* init store context */
    ret = X509_STORE_CTX_init(store_ctx, crl_store, NULL, NULL);
    if (!ret) {
        ERR(NULL, "Initializing x509 store ctx failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = -1;
        goto cleanup;
    }
    ret = 0;

    /* try to find a CRL entry that corresponds to the current certificate in question */
    obj = X509_STORE_CTX_get_obj_by_subject(store_ctx, X509_LU_CRL, subject);
    crl = X509_OBJECT_get0_X509_CRL(obj);
    X509_OBJECT_free(obj);
    if (crl) {
        /* found it */
        cp = X509_NAME_oneline(subject, NULL, 0);
        VRB(NULL, "Cert verify CRL: issuer: %s.", cp);
        OPENSSL_free(cp);

        last_update = X509_CRL_get0_lastUpdate(crl);
        next_update = X509_CRL_get0_nextUpdate(crl);
        cp = asn1time_to_str(last_update);
        VRB(NULL, "Cert verify CRL: last update: %s.", cp);
        free(cp);
        cp = asn1time_to_str(next_update);
        VRB(NULL, "Cert verify CRL: next update: %s.", cp);
        free(cp);

        /* verify the signature on this CRL */
        pubkey = X509_get0_pubkey(cert);
        if (X509_CRL_verify(crl, pubkey) <= 0) {
            ERR(NULL, "Cert verify CRL: invalid signature.");
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
            ret = -1;
            goto cleanup;
        }

        /* check date of CRL to make sure it's not expired */
        if (!next_update) {
            ERR(NULL, "Cert verify CRL: invalid nextUpdate field.");
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
            ret = -1;
            goto cleanup;
        }

        if (X509_cmp_current_time(next_update) < 0) {
            ERR(NULL, "Cert verify CRL: expired - revoking all certificates.");
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_HAS_EXPIRED);
            ret = -1;
            goto cleanup;
        }
    }

    /* try to retrieve a CRL corresponding to the _issuer_ of
     * the current certificate in order to check for revocation */
    obj = X509_STORE_CTX_get_obj_by_subject(store_ctx, X509_LU_CRL, issuer);
    crl = X509_OBJECT_get0_X509_CRL(obj);
    if (crl) {
        n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
        for (i = 0; i < n; i++) {
            revoked = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
            serial = X509_REVOKED_get0_serialNumber(revoked);
            if (ASN1_INTEGER_cmp(serial, X509_get_serialNumber(cert)) == 0) {
                cp = X509_NAME_oneline(issuer, NULL, 0);
                ERR(NULL, "Cert verify CRL: certificate with serial %ld (0x%lX) revoked per CRL from issuer %s.",
                        serial, serial, cp);
                OPENSSL_free(cp);
                X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REVOKED);
                ret = -1;
                goto cleanup;
            }
        }
    }

cleanup:
    X509_STORE_CTX_free(store_ctx);
    X509_OBJECT_free(obj);
    return ret;
}

static int
<<<<<<< HEAD
nc_server_tls_ts_ref_get_certs(const char *referenced_name, struct nc_certificate **certs, uint16_t *cert_count)
{
    uint16_t i;
    struct nc_truststore *ts = &server_opts.truststore;

    *certs = NULL;
    *cert_count = 0;

    /* lookup name */
    for (i = 0; i < ts->cert_bag_count; i++) {
        if (!strcmp(referenced_name, ts->cert_bags[i].name)) {
            break;
        }
    }

    if (i == ts->cert_bag_count) {
        ERR(NULL, "Truststore entry \"%s\" not found.", referenced_name);
        return -1;
    }

    *certs = ts->cert_bags[i].certs;
    *cert_count = ts->cert_bags[i].cert_count;
    return 0;
}

/* In case a CA chain verification failed an end-entity certificate must match.
 * The meaning of local_or_referenced is that it states, which end-entity certificates to check
 * (1 = current endpoint's, 2 = referenced endpoint's).
 */
static int
nc_server_tls_do_preverify(struct nc_session *session, X509_STORE_CTX *x509_ctx, int local_or_referenced)
{
    X509_STORE *store;
    struct nc_cert_grouping *ee_certs;
    int i, ret;
    X509 *cert;
    struct nc_certificate *certs;
    uint16_t cert_count;

    store = X509_STORE_CTX_get0_store(x509_ctx);
    if (!store) {
        ERR(session, "Error getting store from context (%s).", ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    /* get the data from the store */
    ee_certs = X509_STORE_get_ex_data(store, local_or_referenced);
    if (!ee_certs) {
        ERR(session, "Error getting data from store (%s).", ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    if (ee_certs->store == NC_STORE_LOCAL) {
        /* local definition */
        certs = ee_certs->certs;
        cert_count = ee_certs->cert_count;
    } else {
        /* truststore reference */
        if (nc_server_tls_ts_ref_get_certs(ee_certs->ts_ref, &certs, &cert_count)) {
            ERR(NULL, "Error getting end-entity certificates from the truststore reference \"%s\".", ee_certs->ts_ref);
            return -1;
        }
    }

    for (i = 0; i < cert_count; i++) {
        cert = base64der_to_cert(certs[i].data);
        ret = cert_pubkey_match(session->opts.server.client_cert, cert);
        X509_free(cert);
        if (ret) {
            /* we are just overriding the failed standard certificate verification (preverify_ok == 0),
             * this callback will be called again with the same current certificate and preverify_ok == 1 */
            VRB(session, "Cert verify: fail (%s), but the end-entity certificate is trusted, continuing.",
                    X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));
            X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
            return 1;
        }
    }

    return 0;
}

static int
=======
>>>>>>> d301c76 (config UPDATE implemented CRL for TLS)
nc_tlsclb_verify(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    X509_NAME *subject;
    X509_NAME *issuer;
    X509 *cert;
<<<<<<< HEAD
=======
    struct nc_cert_grouping *ee_certs;
>>>>>>> d301c76 (config UPDATE implemented CRL for TLS)
    char *cp;

    STACK_OF(X509) * cert_stack;
    struct nc_session *session;
    struct nc_server_tls_opts *opts;
<<<<<<< HEAD
    int rc, depth;
=======
    int i, rc, depth;
    const char *username = NULL;
    NC_TLS_CTN_MAPTYPE map_type = 0;
>>>>>>> d301c76 (config UPDATE implemented CRL for TLS)

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

    /* standard certificate verification failed, so an end-entity client cert must match to continue */
    if (!preverify_ok) {
<<<<<<< HEAD
        /* check current endpoint's end-entity certs */
        rc = nc_server_tls_do_preverify(session, x509_ctx, 1);
        if (rc == -1) {
=======
        /* get the store from the current context */
        X509_STORE *store = X509_STORE_CTX_get0_store(x509_ctx);

        if (!store) {
            ERR(session, "Error getting store from context (%s).", ERR_reason_error_string(ERR_get_error()));
>>>>>>> d301c76 (config UPDATE implemented CRL for TLS)
            return 0;
        } else if (rc == 1) {
            return 1;
        }

<<<<<<< HEAD
        /* no match, continue */
        if (opts->endpt_client_ref) {
            /* check referenced endpoint's end-entity certs */
            rc = nc_server_tls_do_preverify(session, x509_ctx, 2);
            if (rc == -1) {
                return 0;
            } else if (rc == 1) {
=======
        /* get the data from the store */
        ee_certs = X509_STORE_get_ex_data(store, 1);
        if (!ee_certs) {
            ERR(session, "Error getting data from store (%s).", ERR_reason_error_string(ERR_get_error()));
            return 0;
        }

        for (i = 0; i < ee_certs->cert_count; i++) {
            cert = base64der_to_cert(ee_certs->certs[i].data);
            rc = cert_pubkey_match(session->opts.server.client_cert, cert);
            X509_free(cert);
            if (rc) {
                /* we are just overriding the failed standard certificate verification (preverify_ok == 0),
                 * this callback will be called again with the same current certificate and preverify_ok == 1 */
                VRB(session, "Cert verify: fail (%s), but the end-entity certificate is trusted, continuing.",
                        X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));
                X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
>>>>>>> d301c76 (config UPDATE implemented CRL for TLS)
                return 1;
            }
        }

<<<<<<< HEAD
        /* no match, fail */
=======
>>>>>>> d301c76 (config UPDATE implemented CRL for TLS)
        ERR(session, "Cert verify: fail (%s).", X509_verify_cert_error_string(X509_STORE_CTX_get_error(x509_ctx)));
        return 0;
    }

    /* print cert verify info */
    depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    VRB(session, "Cert verify: depth %d.", depth);

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    subject = X509_get_subject_name(cert);
    issuer = X509_get_issuer_name(cert);

    cp = X509_NAME_oneline(subject, NULL, 0);
    VRB(session, "Cert verify: subject: %s.", cp);
    OPENSSL_free(cp);
    cp = X509_NAME_oneline(issuer, NULL, 0);
    VRB(session, "Cert verify: issuer:  %s.", cp);
    OPENSSL_free(cp);

    /* check if the current certificate is revoked if CRL is set */
    if (opts->crl_store) {
        rc = nc_server_tls_check_crl(opts->crl_store, x509_ctx, cert, subject, issuer);
        if (rc) {
            return 0;
        }
    }

    /* cert-to-name already successful */
    if (session->username) {
        return 1;
    }

    /* cert-to-name */
    rc = nc_tls_cert_to_name(session, opts->ctn, cert);
    if (rc == -1) {
        /* fatal error */
        depth = 0;
        goto fail;
    } else if ((rc == 1) && !opts->endpt_client_ref) {
        /* no match found and no referenced endpoint */
        goto fail;
    } else if ((rc == 1) && opts->endpt_client_ref) {
        /* no match found, but has a referenced endpoint so try it */
        rc = nc_tls_cert_to_name(session, opts->endpt_client_ref->opts.tls->ctn, cert);
        if (rc) {
            if (rc == -1) {
                /* fatal error */
                depth = 0;
            }
            /* rc == 1 is a normal CTN fail (no match found) */
            goto fail;
        }
    }

    VRB(session, "Cert verify CTN: new client username recognized as \"%s\".", session->username);

    if (server_opts.user_verify_clb && !server_opts.user_verify_clb(session)) {
        VRB(session, "Cert verify: user verify callback revoked authorization.");
        X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }

    return 1;

fail:
    if (depth > 0) {
        VRB(session, "Cert verify CTN: cert fail, cert-to-name will continue on the next cert in chain.");
        return 1;
    }

    VRB(session, "Cert-to-name unsuccessful, dropping the new client.");
    X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
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
        if (name && !(*name) && ctn->name) {
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

    NC_CHECK_ARG_RET(NULL, endpt_name, -1);

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_OPENSSL, NULL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_get_ctn(id, fingerprint, map_type, name, endpt->opts.tls);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);

    return ret;
}

API int
nc_server_tls_ch_client_endpt_get_ctn(const char *client_name, const char *endpt_name, uint32_t *id, char **fingerprint,
        NC_TLS_CTN_MAPTYPE *map_type, char **name)
{
    int ret;
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, NC_TI_OPENSSL, &client);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_tls_get_ctn(id, fingerprint, map_type, name, endpt->opts.tls);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

API const X509 *
nc_session_get_client_cert(const struct nc_session *session)
{
    if (!session || (session->side != NC_SERVER)) {
        ERRARG(session, "session");
        return NULL;
    }

    return session->opts.server.client_cert;
}

API void
nc_server_tls_set_verify_clb(int (*verify_clb)(const struct nc_session *session))
{
    server_opts.user_verify_clb = verify_clb;
}

static void
nc_tls_make_verify_key(void)
{
    pthread_key_create(&verify_key, NULL);
}

static int
nc_server_tls_ks_ref_get_cert_key(const char *referenced_key_name, const char *referenced_cert_name,
        char **privkey_data, NC_PRIVKEY_FORMAT *privkey_type, char **cert_data)
{
    uint16_t i, j;
    struct nc_keystore *ks = &server_opts.keystore;

    *privkey_data = NULL;
    *cert_data = NULL;

    /* lookup name */
    for (i = 0; i < ks->asym_key_count; i++) {
        if (!strcmp(referenced_key_name, ks->asym_keys[i].name)) {
            break;
        }
    }
    if (i == ks->asym_key_count) {
        ERR(NULL, "Keystore entry \"%s\" not found.", referenced_key_name);
        return -1;
    }

    for (j = 0; j < ks->asym_keys[i].cert_count; j++) {
        if (!strcmp(referenced_cert_name, ks->asym_keys[i].certs[i].name)) {
            break;
        }
    }
    if (j == ks->asym_keys[i].cert_count) {
        ERR(NULL, "Keystore certificate entry \"%s\" associated with the key \"%s\" not found.",
                referenced_cert_name, referenced_key_name);
        return -1;
    }

    *privkey_data = ks->asym_keys[i].privkey_data;
    *privkey_type = ks->asym_keys[i].privkey_type;
    *cert_data = ks->asym_keys[i].certs[j].data;
    return 0;
}

static int
nc_tls_ctx_set_server_cert_key(SSL_CTX *tls_ctx, struct nc_server_tls_opts *opts)
{
    char *privkey_data = NULL, *cert_data = NULL;
    int ret = 0;
    NC_PRIVKEY_FORMAT privkey_type;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;

    NC_CHECK_ARG_RET(NULL, tls_ctx, opts, -1);

    /* get data needed for setting the server cert */
    if (opts->store == NC_STORE_LOCAL) {
        /* local definition */
        cert_data = opts->cert_data;
        privkey_data = opts->privkey_data;
        privkey_type = opts->privkey_type;
    } else {
        /* keystore */
        ret = nc_server_tls_ks_ref_get_cert_key(opts->key_ref, opts->cert_ref, &privkey_data, &privkey_type, &cert_data);
        if (ret) {
            ERR(NULL, "Getting server certificate from the keystore reference \"%s\" failed.", opts->key_ref);
            return -1;
        }
    }

    /* load the cert */
    cert = base64der_to_cert(cert_data);
    if (!cert) {
        ERR(NULL, "Converting certificate data to certificate format failed.");
        ret = -1;
        goto cleanup;
    }

    /* set server cert */
    ret = SSL_CTX_use_certificate(tls_ctx, cert);
    if (ret != 1) {
        ERR(NULL, "Loading the server certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = -1;
        goto cleanup;
    }

    /* load the private key */
    pkey = base64der_to_privatekey(privkey_data, nc_privkey_format_to_str(privkey_type));
    if (!pkey) {
        ERR(NULL, "Converting private key data to private key format failed.");
        ret = -1;
        goto cleanup;
    }

    /* set server key */
    ret = SSL_CTX_use_PrivateKey(tls_ctx, pkey);
    if (ret != 1) {
        ERR(NULL, "Loading the server private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = -1;
        goto cleanup;
    }

    ret = 0;

cleanup:
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return ret;
}

static int
tls_store_add_trusted_cert(X509_STORE *cert_store, const char *cert_data)
{
    X509 *cert;

    cert = base64der_to_cert(cert_data);

    if (!cert) {
        ERR(NULL, "Loading a trusted certificate (data \"%s\") failed (%s).", cert_data,
                ERR_reason_error_string(ERR_get_error()));
        return -1;
    }

    /* add the trusted certificate */
    if (X509_STORE_add_cert(cert_store, cert) != 1) {
        ERR(NULL, "Adding a trusted certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
        X509_free(cert);
        return -1;
    }
    X509_free(cert);

    return 0;
}

static int
nc_tls_store_set_trusted_certs(X509_STORE *cert_store, struct nc_cert_grouping *ca_certs)
{
    uint16_t i;
    struct nc_certificate *certs;
    uint16_t cert_count;

    if (ca_certs->store == NC_STORE_LOCAL) {
        /* local definition */
        certs = ca_certs->certs;
        cert_count = ca_certs->cert_count;
    } else {
        /* truststore */
        if (nc_server_tls_ts_ref_get_certs(ca_certs->ts_ref, &certs, &cert_count)) {
            ERR(NULL, "Error getting certificate-authority certificates from the truststore reference \"%s\".", ca_certs->ts_ref);
            return -1;
        }
    }

    for (i = 0; i < cert_count; i++) {
        if (tls_store_add_trusted_cert(cert_store, certs[i].data)) {
            return -1;
        }
    }

    return 0;
}

static int
nc_server_tls_crl_path(struct nc_session *session, const char *crl_path, X509_STORE *store)
{
    int ret = 0;
    X509_CRL *crl = NULL;
    FILE *f;

    f = fopen(crl_path, "r");
    if (!f) {
        ERR(session, "Unable to open CRL file \"%s\".", crl_path);
        return -1;
    }

    /* try DER first */
    crl = d2i_X509_CRL_fp(f, NULL);
    if (crl) {
        /* success */
        goto ok;
    }

    /* DER failed, try PEM */
    rewind(f);
    crl = PEM_read_X509_CRL(f, NULL, NULL, NULL);
    if (!crl) {
        ERR(session, "Reading CRL from file \"%s\" failed.", crl_path);
        ret = -1;
        goto cleanup;
    }

ok:
    ret = X509_STORE_add_crl(store, crl);
    if (!ret) {
        ERR(session, "Error adding CRL to store (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = -1;
        goto cleanup;
    }
    /* ok */
    ret = 0;

cleanup:
    fclose(f);
    X509_CRL_free(crl);
    return ret;
}

static size_t
nc_server_tls_curl_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct nc_curl_data *data;

    size = nmemb;

    data = (struct nc_curl_data *)userdata;

    data->data = nc_realloc(data->data, data->size + size);
    if (!data->data) {
        ERRMEM;
        return 0;
    }

    memcpy(&data->data[data->size], ptr, size);
    data->size += size;

    return size;
}

static int
nc_server_tls_curl_init(struct nc_session *session, CURL **handle, struct nc_curl_data *data)
{
    NC_CHECK_ARG_RET(session, handle, data, -1);

    *handle = NULL;

    *handle = curl_easy_init();
    if (!*handle) {
        ERR(session, "Initializing CURL failed.");
        return -1;
    }

    if (curl_easy_setopt(*handle, CURLOPT_WRITEFUNCTION, nc_server_tls_curl_cb)) {
        ERR(session, "Setting curl callback failed.");
        return -1;
    }

    if (curl_easy_setopt(*handle, CURLOPT_WRITEDATA, data)) {
        ERR(session, "Setting curl callback data failed.");
        return -1;
    }

    return 0;
}

static int
nc_server_tls_curl_fetch(struct nc_session *session, CURL *handle, const char *url)
{
    char err_buf[CURL_ERROR_SIZE];

    /* set uri */
    if (curl_easy_setopt(handle, CURLOPT_URL, url)) {
        ERR(session, "Setting URI \"%s\" to download CRL from failed.", url);
        return -1;
    }

    /* set err buf */
    curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, err_buf);

    /* download */
    if (curl_easy_perform(handle)) {
        ERR(session, "Downloading CRL from \"%s\" failed (%s).", url, err_buf);
        return -1;
    }

    return 0;
}

static int
nc_server_tls_add_crl_to_store(struct nc_session *session, struct nc_curl_data *downloaded, X509_STORE *store)
{
    int ret = 0;
    X509_CRL *crl = NULL;
    BIO *bio = NULL;

    /* try DER first */
    crl = d2i_X509_CRL(NULL, (const unsigned char **) &downloaded->data, downloaded->size);
    if (crl) {
        /* it was DER */
        goto ok;
    }

    /* DER failed, try PEM next */
    bio = BIO_new_mem_buf(downloaded->data, downloaded->size);
    if (!bio) {
        ERR(session, "Creating new bio failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = -1;
        goto cleanup;
    }

    /* try to parse PEM from the downloaded data */
    crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
    if (!crl) {
        ERR(session, "Reading downloaded CRL failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = -1;
        goto cleanup;
    }

ok:
    /* we obtained the CRL, now add it to the CRL store */
    ret = X509_STORE_add_crl(store, crl);
    if (!ret) {
        ERR(session, "Error adding CRL to store (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = -1;
        goto cleanup;
    }
    /* ok */
    ret = 0;

cleanup:
    X509_CRL_free(crl);
    BIO_free(bio);
    return ret;
}

static int
nc_server_tls_crl_url(struct nc_session *session, const char *url, X509_STORE *store)
{
    int ret = 0;
    CURL *handle = NULL;
    struct nc_curl_data downloaded = {0};

    /* init curl */
    ret = nc_server_tls_curl_init(session, &handle, &downloaded);
    if (ret) {
        goto cleanup;
    }

    VRB(session, "Downloading CRL from \"%s\".", url);

    /* download the CRL */
    ret = nc_server_tls_curl_fetch(session, handle, url);
    if (ret) {
        goto cleanup;
    }

    /* convert the downloaded data to CRL and add it to the store */
    ret = nc_server_tls_add_crl_to_store(session, &downloaded, store);
    if (ret) {
        goto cleanup;
    }

cleanup:
    curl_easy_cleanup(handle);
    return ret;
}

static int
nc_server_tls_crl_cert_ext(struct nc_session *session, X509_STORE *cert_store, X509_STORE *crl_store)
{
    int ret = 0, i, j, k, gtype;
    CURL *handle = NULL;
    struct nc_curl_data downloaded = {0};

    STACK_OF(X509_OBJECT) * objs;
    X509_OBJECT *obj;
    X509 *cert;

    STACK_OF(DIST_POINT) * dist_points;
    DIST_POINT *dist_point;
    GENERAL_NAMES *general_names;
    GENERAL_NAME *general_name;
    ASN1_STRING *asn_string_uri;
    const char *crl_distpoint_uri;

    /* init curl */
    ret = nc_server_tls_curl_init(session, &handle, &downloaded);
    if (ret) {
        goto cleanup;
    }

    /* treat all entries in the cert_store as X509_OBJECTs */
    objs = X509_STORE_get0_objects(cert_store);
    if (!objs) {
        ERR(session, "Getting certificates from store failed (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = -1;
        goto cleanup;
    }

    /* iterate over all the CAs */
    for (i = 0; i < sk_X509_OBJECT_num(objs); i++) {
        obj = sk_X509_OBJECT_value(objs, i);
        cert = X509_OBJECT_get0_X509(obj);
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

                crl_distpoint_uri = (const char *) ASN1_STRING_get0_data(asn_string_uri);

                VRB(session, "Downloading CRL from \"%s\".", crl_distpoint_uri);

                /* download the CRL */
                ret = nc_server_tls_curl_fetch(session, handle, crl_distpoint_uri);
                if (ret) {
                    /* failed to download the CRL from this entry, try th next */
                    continue;
                }

                /* convert the downloaded data to CRL and add it to the store */
                ret = nc_server_tls_add_crl_to_store(session, &downloaded, crl_store);
                if (ret) {
                    goto cleanup;
                }

                /* the CRL was downloaded, no need to download it again using different protocol */
                break;
            }
        }
    }

cleanup:
    curl_easy_cleanup(handle);
    return ret;
}

static int
nc_tls_store_set_crl(struct nc_session *session, struct nc_server_tls_opts *opts, X509_STORE *store)
{
    if (!opts->crl_store) {
        /* first call on this endpoint */
        opts->crl_store = X509_STORE_new();
        if (!opts->crl_store) {
            ERRMEM;
            goto fail;
        }
    }

    if (opts->crl_path) {
        if (nc_server_tls_crl_path(session, opts->crl_path, opts->crl_store)) {
            goto fail;
        }
    } else if (opts->crl_url) {
        if (nc_server_tls_crl_url(session, opts->crl_url, opts->crl_store)) {
            goto fail;
        }
    } else {
        if (nc_server_tls_crl_cert_ext(session, store, opts->crl_store)) {
            goto fail;
        }
    }

    return 0;

fail:
    return -1;
}

static int
nc_server_tls_accept_check(int accept_ret, struct nc_session *session)
{
    int verify;

    /* check certificate verification result */
    verify = SSL_get_verify_result(session->ti.tls);
    switch (verify) {
    case X509_V_OK:
        if (accept_ret == 1) {
            VRB(session, "Client certificate verified.");
        }
        break;
    default:
        ERR(session, "Client certificate error (%s).", X509_verify_cert_error_string(verify));
    }

    if (accept_ret != 1) {
        switch (SSL_get_error(session->ti.tls, accept_ret)) {
        case SSL_ERROR_SYSCALL:
            ERR(session, "SSL accept failed (%s).", strerror(errno));
            break;
        case SSL_ERROR_SSL:
            ERR(session, "SSL accept failed (%s).", ERR_reason_error_string(ERR_get_error()));
            break;
        default:
            ERR(session, "SSL accept failed.");
            break;
        }
    }

    return accept_ret;
}

int
nc_accept_tls_session(struct nc_session *session, struct nc_server_tls_opts *opts, int sock, int timeout)
{
    X509_STORE *cert_store;
    SSL_CTX *tls_ctx;
    int ret;
    struct timespec ts_timeout;

    /* SSL_CTX */
    tls_ctx = SSL_CTX_new(TLS_server_method());

    if (!tls_ctx) {
        ERR(session, "Failed to create TLS context.");
        goto error;
    }

    SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    if (nc_tls_ctx_set_server_cert_key(tls_ctx, opts)) {
        goto error;
    }

    /* X509_STORE, managed (freed) with the context */
    cert_store = X509_STORE_new();
    if (!cert_store) {
        ERR(session, "Creating certificate store failed (%s).", ERR_reason_error_string(ERR_get_error()));
        goto error;
    }

    /* set end-entity certs as cert store data, retrieve them if verification fails later */
    ret = X509_STORE_set_ex_data(cert_store, 1, &opts->ee_certs);
    if (!ret) {
        ERR(session, "Setting certificate store data failed (%s).", ERR_reason_error_string(ERR_get_error()));
        goto error;
    }

    /* do the same for referenced endpoint's end entity certs */
    if (opts->endpt_client_ref) {
        ret = X509_STORE_set_ex_data(cert_store, 2, &opts->endpt_client_ref->opts.tls->ee_certs);
        if (!ret) {
            ERR(session, "Setting certificate store data failed (%s).", ERR_reason_error_string(ERR_get_error()));
            goto error;
        }
    }

    /* set store to the context */
    SSL_CTX_set_cert_store(tls_ctx, cert_store);

    /* set certificate authority certs */
    if (nc_tls_store_set_trusted_certs(cert_store, &opts->ca_certs)) {
        goto error;
    }

    /* set referenced endpoint's CA certs if set */
    if (opts->endpt_client_ref) {
        if (nc_tls_store_set_trusted_certs(cert_store, &opts->endpt_client_ref->opts.tls->ca_certs)) {
            goto error;
        }
    }

    /* set Certificate Revocation List if configured */
    if (opts->crl_path || opts->crl_url || opts->crl_cert_ext) {
        if (nc_tls_store_set_crl(session, opts, cert_store)) {
            goto error;
        }
    }

    session->ti_type = NC_TI_OPENSSL;
    session->ti.tls = SSL_new(tls_ctx);

    /* context can be freed already, trusted certs must be freed manually */
    SSL_CTX_free(tls_ctx);
    tls_ctx = NULL;

    if (!session->ti.tls) {
        ERR(session, "Failed to create TLS structure from context.");
        goto error;
    }

    /* set TLS versions for the current SSL session */
    if (opts->tls_versions) {
        if (!(opts->tls_versions & NC_TLS_VERSION_10)) {
            SSL_set_options(session->ti.tls, SSL_OP_NO_TLSv1);
        }
        if (!(opts->tls_versions & NC_TLS_VERSION_11)) {
            SSL_set_options(session->ti.tls, SSL_OP_NO_TLSv1_1);
        }
        if (!(opts->tls_versions & NC_TLS_VERSION_12)) {
            SSL_set_options(session->ti.tls, SSL_OP_NO_TLSv1_2);
        }
        if (!(opts->tls_versions & NC_TLS_VERSION_13)) {
            SSL_set_options(session->ti.tls, SSL_OP_NO_TLSv1_3);
        }
    }

    /* set TLS cipher suites */
    if (opts->ciphers) {
        /* set for TLS1.2 and lower */
        SSL_set_cipher_list(session->ti.tls, opts->ciphers);
        /* set for TLS1.3 */
        SSL_set_ciphersuites(session->ti.tls, opts->ciphers);
    }

    SSL_set_fd(session->ti.tls, sock);
    sock = -1;
    SSL_set_mode(session->ti.tls, SSL_MODE_AUTO_RETRY);

    /* store session on per-thread basis */
    pthread_once(&verify_once, nc_tls_make_verify_key);
    pthread_setspecific(verify_key, session);

    if (timeout > -1) {
        nc_timeouttime_get(&ts_timeout, timeout);
    }
    while (((ret = SSL_accept(session->ti.tls)) == -1) && (SSL_get_error(session->ti.tls, ret) == SSL_ERROR_WANT_READ)) {
        usleep(NC_TIMEOUT_STEP);
        if ((timeout > -1) && (nc_timeouttime_cur_diff(&ts_timeout) < 1)) {
            ERR(session, "SSL accept timeout.");
            return 0;
        }
    }
    if (nc_server_tls_accept_check(ret, session) != 1) {
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
