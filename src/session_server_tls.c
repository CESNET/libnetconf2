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
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "session_server.h"
#include "session_server_ch.h"
#include "libnetconf.h"

struct nc_server_tls_opts tls_ch_opts;
pthread_mutex_t tls_ch_opts_lock = PTHREAD_MUTEX_INITIALIZER;
extern struct nc_server_opts server_opts;

static pthread_key_t verify_key;
static pthread_once_t verify_once = PTHREAD_ONCE_INIT;

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
            WRN("Certificate does not include the commonName field.");
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
            WRN("Certificate has no SANs or failed to retrieve them.");
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

    if (!ctn_first || !cert || !map_type || !name) {
        free(buf);
        return -1;
    }

    for (ctn = ctn_first; ctn; ctn = ctn->next) {
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

    opts = session->ti_opts;

    /* get the last certificate, that is the peer (client) certificate */
    if (!session->tls_cert) {
        cert_stack = X509_STORE_CTX_get1_chain(x509_ctx);
        /* TODO all that is needed, but function X509_up_ref not present in older OpenSSL versions
        session->cert = sk_X509_value(cert_stack, sk_X509_num(cert_stack) - 1);
        X509_up_ref(session->cert);
        sk_X509_pop_free(cert_stack, X509_free); */
        while ((cert = sk_X509_pop(cert_stack))) {
            X509_free(session->tls_cert);
            session->tls_cert = cert;
        }
        sk_X509_pop_free(cert_stack, X509_free);
    }

    /* standard certificate verification failed, so a trusted client cert must match to continue */
    if (!preverify_ok) {
        subject = X509_get_subject_name(session->tls_cert);
        cert_stack = X509_STORE_get1_certs(x509_ctx, subject);
        if (cert_stack) {
            for (i = 0; i < sk_X509_num(cert_stack); ++i) {
                if (cert_pubkey_match(session->tls_cert, sk_X509_value(cert_stack, i))) {
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
        nc_ctx_lock(-1, NULL);
        session->username = lydict_insert(server_opts.ctx, username, 0);
        nc_ctx_unlock();
    } else {
        rc = nc_tls_ctn_get_username_from_cert(session->tls_cert, map_type, &cp);
        if (rc) {
            if (rc == -1) {
                depth = 0;
            }
            goto fail;
        }
        nc_ctx_lock(-1, NULL);
        session->username = lydict_insert_zc(server_opts.ctx, cp);
        nc_ctx_unlock();
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
nc_server_tls_add_endpt_listen(const char *name, const char *address, uint16_t port)
{
    return nc_server_add_endpt_listen(name, address, port, NC_TI_OPENSSL);
}

API int
nc_server_tls_endpt_set_address(const char *endpt_name, const char *address)
{
    return nc_server_endpt_set_address_port(endpt_name, address, 0, NC_TI_OPENSSL);
}

API int
nc_server_tls_endpt_set_port(const char *endpt_name, uint16_t port)
{
    return nc_server_endpt_set_address_port(endpt_name, NULL, port, NC_TI_OPENSSL);
}

API int
nc_server_tls_del_endpt(const char *name)
{
    return nc_server_del_endpt(name, NC_TI_OPENSSL);
}

static int
nc_server_tls_set_cert(const char *cert, struct nc_server_tls_opts *opts)
{
    X509 *x509_cert;

    if (!cert) {
        ERRARG;
        return -1;
    }

    if (!opts->tls_ctx) {
        opts->tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!opts->tls_ctx) {
           ERR("Failed to create TLS context.");
           goto fail;
        }
        SSL_CTX_set_verify(opts->tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    x509_cert = base64der_to_cert(cert);
    if (!x509_cert || (SSL_CTX_use_certificate(opts->tls_ctx, x509_cert) != 1)) {
        ERR("Loading the server certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
        X509_free(x509_cert);
        goto fail;
    }
    X509_free(x509_cert);

    return 0;

fail:
    return -1;
}

API int
nc_server_tls_endpt_set_cert(const char *endpt_name, const char *cert)
{
    int ret;
    struct nc_endpt *endpt;

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_set_cert(cert, endpt->ti_opts);
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_tls_ch_set_cert(const char *cert)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    ret = nc_server_tls_set_cert(cert, &tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);

    return ret;
}

static int
nc_server_tls_set_cert_path(const char *cert_path, struct nc_server_tls_opts *opts)
{
    if (!cert_path) {
        ERRARG;
        return -1;
    }

    if (!opts->tls_ctx) {
        opts->tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!opts->tls_ctx) {
           ERR("Failed to create TLS context.");
           goto fail;
        }
        SSL_CTX_set_verify(opts->tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    if (SSL_CTX_use_certificate_file(opts->tls_ctx, cert_path, SSL_FILETYPE_PEM) != 1) {
        ERR("Loading the server certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
        goto fail;
    }

    return 0;

fail:
    return -1;
}

API int
nc_server_tls_endpt_set_cert_path(const char *endpt_name, const char *cert_path)
{
    int ret;
    struct nc_endpt *endpt;

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_set_cert_path(cert_path, endpt->ti_opts);
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_tls_ch_set_cert_path(const char *cert_path)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    ret = nc_server_tls_set_cert_path(cert_path, &tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);

    return ret;
}

static int
nc_server_tls_set_key(const char *privkey, int is_rsa, struct nc_server_tls_opts *opts)
{
    EVP_PKEY *key;;

    if (!privkey) {
        ERRARG;
        return -1;
    }

    if (!opts->tls_ctx) {
        opts->tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!opts->tls_ctx) {
           ERR("Failed to create TLS context.");
           goto fail;
        }
        SSL_CTX_set_verify(opts->tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    key = base64der_to_privatekey(privkey, is_rsa);
    if (!key || (SSL_CTX_use_PrivateKey(opts->tls_ctx, key) != 1)) {
        ERR("Loading the server private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
        EVP_PKEY_free(key);
        goto fail;
    }
    EVP_PKEY_free(key);

    return 0;

fail:
    return -1;
}

API int
nc_server_tls_endpt_set_key(const char *endpt_name, const char *privkey, int is_rsa)
{
    int ret;
    struct nc_endpt *endpt;

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_set_key(privkey, is_rsa, endpt->ti_opts);
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_tls_ch_set_key(const char *privkey, int is_rsa)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    ret = nc_server_tls_set_key(privkey, is_rsa, &tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);

    return ret;
}

static int
nc_server_tls_set_key_path(const char *privkey_path, struct nc_server_tls_opts *opts)
{
    if (!privkey_path) {
        ERRARG;
        return -1;
    }

    if (!opts->tls_ctx) {
        opts->tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!opts->tls_ctx) {
           ERR("Failed to create TLS context.");
           goto fail;
        }
        SSL_CTX_set_verify(opts->tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    if (SSL_CTX_use_PrivateKey_file(opts->tls_ctx, privkey_path, SSL_FILETYPE_PEM) != 1) {
        ERR("Loading the server private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
        goto fail;
    }

    return 0;

fail:
    return -1;
}

API int
nc_server_tls_endpt_set_key_path(const char *endpt_name, const char *privkey_path)
{
    int ret;
    struct nc_endpt *endpt;

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_set_key_path(privkey_path, endpt->ti_opts);
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_tls_ch_set_key_path(const char *privkey_path)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    ret = nc_server_tls_set_key_path(privkey_path, &tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);

    return ret;
}

static int
nc_server_tls_add_trusted_cert(const char *cert, struct nc_server_tls_opts *opts)
{
    X509_STORE *cert_store;
    X509 *x509_cert;

    if (!cert) {
        ERRARG;
        return -1;
    }

    if (!opts->tls_ctx) {
        opts->tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!opts->tls_ctx) {
           ERR("Failed to create TLS context.");
           goto fail;
        }
        SSL_CTX_set_verify(opts->tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    cert_store = SSL_CTX_get_cert_store(opts->tls_ctx);
    if (!cert_store) {
        cert_store = X509_STORE_new();
        SSL_CTX_set_cert_store(opts->tls_ctx, cert_store);
    }

    x509_cert = base64der_to_cert(cert);
    if (!x509_cert || (X509_STORE_add_cert(cert_store, x509_cert) != 1)) {
        ERR("Adding a trusted certificate failed (%s).", ERR_reason_error_string(ERR_get_error()));
        X509_free(x509_cert);
        goto fail;
    }
    X509_free(x509_cert);

    return 0;

fail:
    return -1;
}

API int
nc_server_tls_endpt_add_trusted_cert(const char *endpt_name, const char *cert)
{
    int ret;
    struct nc_endpt *endpt;

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_add_trusted_cert(cert, endpt->ti_opts);
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_tls_ch_add_trusted_cert(const char *cert)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    ret = nc_server_tls_add_trusted_cert(cert, &tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);

    return ret;
}

static int
nc_server_tls_add_trusted_cert_path(const char *cert_path, struct nc_server_tls_opts *opts)
{
    X509_STORE *cert_store;
    X509 *x509_cert;

    if (!cert_path) {
        ERRARG;
        return -1;
    }

    if (!opts->tls_ctx) {
        opts->tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!opts->tls_ctx) {
           ERR("Failed to create TLS context.");
           goto fail;
        }
        SSL_CTX_set_verify(opts->tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    cert_store = SSL_CTX_get_cert_store(opts->tls_ctx);
    if (!cert_store) {
        cert_store = X509_STORE_new();
        SSL_CTX_set_cert_store(opts->tls_ctx, cert_store);
    }

    errno = 0;
    x509_cert = pem_to_cert(cert_path);
    if (!x509_cert || (X509_STORE_add_cert(cert_store, x509_cert) != 1)) {
        ERR("Adding a trusted certificate failed (%s).",
            (errno ? strerror(errno) : ERR_reason_error_string(ERR_get_error())));
        X509_free(x509_cert);
        goto fail;
    }
    X509_free(x509_cert);

    return 0;

fail:
    return -1;
}

API int
nc_server_tls_endpt_add_trusted_cert_path(const char *endpt_name, const char *cert_path)
{
    int ret;
    struct nc_endpt *endpt;

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_add_trusted_cert_path(cert_path, endpt->ti_opts);
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_tls_ch_add_trusted_cert_path(const char *cert_path)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    ret = nc_server_tls_add_trusted_cert_path(cert_path, &tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);

    return ret;
}

static int
nc_server_tls_set_trusted_ca_paths(const char *ca_file, const char *ca_dir, struct nc_server_tls_opts *opts)
{
    X509_STORE *cert_store;
    X509_LOOKUP *lookup;

    if (!ca_file && !ca_dir) {
        ERRARG;
        return -1;
    }

    if (!opts->tls_ctx) {
        opts->tls_ctx = SSL_CTX_new(TLSv1_2_server_method());
        if (!opts->tls_ctx) {
           ERR("Failed to create TLS context.");
           goto fail;
        }
        SSL_CTX_set_verify(opts->tls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nc_tlsclb_verify);
    }

    cert_store = SSL_CTX_get_cert_store(opts->tls_ctx);
    if (!cert_store) {
        cert_store = X509_STORE_new();
        SSL_CTX_set_cert_store(opts->tls_ctx, cert_store);
    }

    if (ca_file) {
        lookup = X509_STORE_add_lookup(cert_store, X509_LOOKUP_file());
        if (!lookup) {
            ERR("Failed to add a lookup method.");
            goto fail;
        }

        if (X509_LOOKUP_load_file(lookup, ca_file, X509_FILETYPE_PEM) != 1) {
            ERR("Failed to add a trusted cert file (%s).", ERR_reason_error_string(ERR_get_error()));
            goto fail;
        }
    }

    if (ca_dir) {
        lookup = X509_STORE_add_lookup(cert_store, X509_LOOKUP_hash_dir());
        if (!lookup) {
            ERR("Failed to add a lookup method.");
            goto fail;
        }

        if (X509_LOOKUP_add_dir(lookup, ca_dir, X509_FILETYPE_PEM) != 1) {
            ERR("Failed to add a trusted cert directory (%s).", ERR_reason_error_string(ERR_get_error()));
            goto fail;
        }
    }

    return 0;

fail:
    return -1;
}

API int
nc_server_tls_endpt_set_trusted_ca_paths(const char *endpt_name, const char *ca_file, const char *ca_dir)
{
    int ret;
    struct nc_endpt *endpt;

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_set_trusted_ca_paths(ca_file, ca_dir, endpt->ti_opts);
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_tls_ch_set_trusted_ca_paths(const char *ca_file, const char *ca_dir)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    ret = nc_server_tls_set_trusted_ca_paths(ca_file, ca_dir, &tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);

    return ret;
}

static void
nc_server_tls_clear_certs(struct nc_server_tls_opts *opts)
{
    if (!opts->tls_ctx) {
        return;
    }

    SSL_CTX_free(opts->tls_ctx);
    opts->tls_ctx = NULL;
}

API void
nc_server_tls_endpt_clear_certs(const char *endpt_name)
{
    struct nc_endpt *endpt;

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return;
    }
    nc_server_tls_clear_certs(endpt->ti_opts);
    nc_server_endpt_unlock(endpt);
}

API void
nc_server_tls_ch_clear_certs(void)
{
    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    nc_server_tls_clear_certs(&tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);
}

static int
nc_server_tls_set_crl_paths(const char *crl_file, const char *crl_dir, struct nc_server_tls_opts *opts)
{
    X509_LOOKUP *lookup;

    if (!crl_file && !crl_dir) {
        ERRARG;
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

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_set_crl_paths(crl_file, crl_dir, endpt->ti_opts);
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_tls_ch_set_crl_paths(const char *crl_file, const char *crl_dir)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    ret = nc_server_tls_set_crl_paths(crl_file, crl_dir, &tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);

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

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return;
    }
    nc_server_tls_clear_crls(endpt->ti_opts);
    nc_server_endpt_unlock(endpt);
}

API void
nc_server_tls_ch_clear_crls(void)
{
    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    nc_server_tls_clear_crls(&tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);
}

static int
nc_server_tls_add_ctn(uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name, struct nc_server_tls_opts *opts)
{
    struct nc_ctn *ctn, *new;

    if (!fingerprint || !map_type || ((map_type == NC_TLS_CTN_SPECIFIED) && !name)
            || ((map_type != NC_TLS_CTN_SPECIFIED) && name)) {
        ERRARG;
        return -1;
    }

    new = malloc(sizeof *new);

    nc_ctx_lock(-1, NULL);
    new->fingerprint = lydict_insert(server_opts.ctx, fingerprint, 0);
    new->name = lydict_insert(server_opts.ctx, name, 0);
    nc_ctx_unlock();
    new->id = id;
    new->map_type = map_type;
    new->next = NULL;

    if (!opts->ctn) {
        /* the first item */
        opts->ctn = new;
    } else if (opts->ctn->id > id) {
        /* insert at the beginning */
        new->next = opts->ctn;
        opts->ctn = new;
    } else {
        for (ctn = opts->ctn; ctn->next && ctn->next->id <= id; ctn = ctn->next);
        /* insert after ctn */
        new->next = ctn->next;
        ctn->next = new;
    }

    return 0;
}

API int
nc_server_tls_endpt_add_ctn(const char *endpt_name, uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name)
{
    int ret;
    struct nc_endpt *endpt;

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_add_ctn(id, fingerprint, map_type, name, endpt->ti_opts);
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_tls_ch_add_ctn(uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    ret = nc_server_tls_add_ctn(id, fingerprint, map_type, name, &tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);

    return ret;
}

static int
nc_server_tls_del_ctn(int64_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name, struct nc_server_tls_opts *opts)
{
    struct nc_ctn *ctn, *next, *prev;
    int ret = -1;

    if ((id < 0) && !fingerprint && !map_type && !name) {
        ctn = opts->ctn;
        nc_ctx_lock(-1, NULL);
        while (ctn) {
            lydict_remove(server_opts.ctx, ctn->fingerprint);
            lydict_remove(server_opts.ctx, ctn->name);

            next = ctn->next;
            free(ctn);
            ctn = next;

            ret = 0;
        }
        nc_ctx_unlock();
        opts->ctn = NULL;
    } else {
        prev = NULL;
        ctn = opts->ctn;
        while (ctn) {
            if (((id < 0) || (ctn->id == id))
                    && (!fingerprint || !strcmp(ctn->fingerprint, fingerprint))
                    && (!map_type || (ctn->map_type == map_type))
                    && (!name || (ctn->name && !strcmp(ctn->name, name)))) {
                nc_ctx_lock(-1, NULL);
                lydict_remove(server_opts.ctx, ctn->fingerprint);
                lydict_remove(server_opts.ctx, ctn->name);
                nc_ctx_unlock();

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
nc_server_tls_endpt_del_ctn(const char *endpt_name, int64_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name)
{
    int ret;
    struct nc_endpt *endpt;

    endpt = nc_server_endpt_lock(endpt_name, NC_TI_OPENSSL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_tls_del_ctn(id, fingerprint, map_type, name, endpt->ti_opts);
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_tls_ch_del_ctn(int64_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    ret = nc_server_tls_del_ctn(id, fingerprint, map_type, name, &tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);

    return ret;
}

void
nc_server_tls_clear_opts(struct nc_server_tls_opts *opts)
{
    nc_server_tls_clear_certs(opts);
    nc_server_tls_clear_crls(opts);
    nc_server_tls_del_ctn(-1, NULL, 0, NULL, opts);
}

API void
nc_server_tls_ch_clear_opts(void)
{
    /* OPTS LOCK */
    pthread_mutex_lock(&tls_ch_opts_lock);
    nc_server_tls_clear_opts(&tls_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&tls_ch_opts_lock);
}

static void
nc_tls_make_verify_key(void)
{
    pthread_key_create(&verify_key, NULL);
}

API int
nc_connect_callhome_tls(const char *host, uint16_t port, int timeout, struct nc_session **session)
{
    return nc_connect_callhome(host, port, NC_TI_OPENSSL, timeout, session);
}

int
nc_accept_tls_session(struct nc_session *session, int sock, int timeout)
{
    struct nc_server_tls_opts *opts;
    struct pollfd pfd;
    struct timespec old_ts, new_ts;
    int ret, elapsed = 0;

    opts = session->ti_opts;

    pfd.fd = sock;
    pfd.events = POLLIN;
    pfd.revents = 0;

    if (timeout > 0) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &old_ts);
    }

    /* poll for a new connection */
    errno = 0;
    ret = poll(&pfd, 1, timeout);
    if (!ret) {
        /* we timeouted */
        close(sock);
        return 0;
    } else if (ret == -1) {
        ERR("poll failed (%s).", strerror(errno));
        close(sock);
        return -1;
    }

    if (timeout > 0) {
        /* decrease timeout */
        clock_gettime(CLOCK_MONOTONIC_RAW, &new_ts);

        elapsed = (new_ts.tv_sec - old_ts.tv_sec) * 1000;
        elapsed += (new_ts.tv_nsec - old_ts.tv_nsec) / 1000000;
    }

    /* data waiting, prepare session */
    session->ti_type = NC_TI_OPENSSL;

    session->ti.tls = SSL_new(opts->tls_ctx);

    if (!session->ti.tls) {
        ERR("Failed to create TLS structure from context.");
        close(sock);
        return -1;
    }

    SSL_set_fd(session->ti.tls, sock);
    SSL_set_mode(session->ti.tls, SSL_MODE_AUTO_RETRY);

    /* store session on per-thread basis */
    pthread_once(&verify_once, nc_tls_make_verify_key);
    pthread_setspecific(verify_key, session);

    ret = SSL_accept(session->ti.tls);

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
}
