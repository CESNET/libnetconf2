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

#include <errno.h>
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

static int
nc_server_tls_ks_ref_get_cert_key(const char *referenced_key_name, const char *referenced_cert_name,
        char **privkey_data, enum nc_privkey_format *privkey_type, char **cert_data)
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
        if (!strcmp(referenced_cert_name, ks->asym_keys[i].certs[j].name)) {
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
nc_server_tls_truststore_ref_get_certs(const char *referenced_name, struct nc_certificate **certs, uint16_t *cert_count)
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

static void *
nc_base64der_to_privkey(const char *in, const char *key_str)
{
    char *buf = NULL;
    void *pkey;

    NC_CHECK_ARG_RET(NULL, in, NULL);

    if (asprintf(&buf, "%s%s%s%s%s%s%s", "-----BEGIN", key_str, "PRIVATE KEY-----\n", in, "\n-----END",
            key_str, "PRIVATE KEY-----") == -1) {
        ERRMEM;
        return NULL;
    }

    pkey = nc_tls_pem_to_privkey_wrap(buf);
    free(buf);
    return pkey;
}

static char *
nc_server_tls_digest_to_hex(const unsigned char *digest, unsigned int digest_len)
{
    unsigned int i;
    char *hex;

    hex = malloc(digest_len * 3);
    NC_CHECK_ERRMEM_RET(!hex, NULL);

    for (i = 0; i < digest_len - 1; ++i) {
        sprintf(hex + (i * 3), "%02x:", digest[i]);
    }
    sprintf(hex + (i * 3), "%02x", digest[i]);

    return hex;
}

static char *
nc_server_tls_md5(void *cert)
{
    int rc;
    unsigned int buf_len = 16;
    unsigned char buf[buf_len];

    /* compute MD-5 hash of cert and store it in buf */
    rc = nc_server_tls_md5_wrap(cert, buf);
    if (rc) {
        return NULL;
    }

    /* convert the hash to hex */
    return nc_server_tls_digest_to_hex(buf, buf_len);
}

static char *
nc_server_tls_sha1(void *cert)
{
    int rc;
    unsigned int buf_len = 20;
    unsigned char buf[buf_len];

    /* compute SHA-1 hash of cert and store it in buf */
    rc = nc_server_tls_sha1_wrap(cert, buf);
    if (rc) {
        return NULL;
    }

    /* convert the hash to hex */
    return nc_server_tls_digest_to_hex(buf, buf_len);
}

static char *
nc_server_tls_sha224(void *cert)
{
    int rc;
    unsigned int buf_len = 28;
    unsigned char buf[buf_len];

    /* compute SHA-224 hash of cert and store it in buf */
    rc = nc_server_tls_sha224_wrap(cert, buf);
    if (rc) {
        return NULL;
    }

    /* convert the hash to hex */
    return nc_server_tls_digest_to_hex(buf, buf_len);
}

static char *
nc_server_tls_sha256(void *cert)
{
    int rc;
    unsigned int buf_len = 32;
    unsigned char buf[buf_len];

    /* compute SHA-256 hash of cert and store it in buf */
    rc = nc_server_tls_sha256_wrap(cert, buf);
    if (rc) {
        return NULL;
    }

    /* convert the hash to hex */
    return nc_server_tls_digest_to_hex(buf, buf_len);
}

static char *
nc_server_tls_sha384(void *cert)
{
    int rc;
    unsigned int buf_len = 48;
    unsigned char buf[buf_len];

    /* compute SHA-384 hash of cert and store it in buf */
    rc = nc_server_tls_sha384_wrap(cert, buf);
    if (rc) {
        return NULL;
    }

    /* convert the hash to hex */
    return nc_server_tls_digest_to_hex(buf, buf_len);
}

static char *
nc_server_tls_sha512(void *cert)
{
    int rc;
    unsigned int buf_len = 64;
    unsigned char buf[buf_len];

    /* compute SHA-512 hash of cert and store it in buf */
    rc = nc_server_tls_sha512_wrap(cert, buf);
    if (rc) {
        return NULL;
    }

    /* convert the hash to hex */
    return nc_server_tls_digest_to_hex(buf, buf_len);
}

static int
nc_server_tls_get_username(void *cert, struct nc_ctn *ctn, char **username)
{
    char *subject, *cn, *san_value = NULL, rdn_separator;
    void *sans;
    int i, nsans = 0, rc;
    NC_TLS_CTN_MAPTYPE san_type = 0;

#ifdef HAVE_LIBMEDTLS
    rdn_separator = ',';
#else
    rdn_separator = '/';
#endif

    if (ctn->map_type == NC_TLS_CTN_SPECIFIED) {
        *username = strdup(ctn->name);
        NC_CHECK_ERRMEM_RET(!*username, -1);
    } else if (ctn->map_type == NC_TLS_CTN_COMMON_NAME) {
        subject = nc_server_tls_get_subject_wrap(cert);
        if (!subject) {
            return -1;
        }

        cn = strstr(subject, "CN=");
        if (!cn) {
            WRN(NULL, "Certificate does not include the commonName field.");
            free(subject);
            return 1;
        }

        /* skip "CN=" */
        cn += 3;
        if (strchr(cn, rdn_separator)) {
            *strchr(cn, rdn_separator) = '\0';
        }
        *username = strdup(cn);
        free(subject);
        NC_CHECK_ERRMEM_RET(!*username, -1);
    } else {
        sans = nc_tls_get_sans_wrap(cert);
        if (!sans) {
            WRN(NULL, "Certificate has no SANs or failed to retrieve them.");
            return 1;
        }
        nsans = nc_tls_get_num_sans_wrap(sans);

        for (i = 0; i < nsans; i++) {
            if ((rc = nc_tls_get_san_value_type_wrap(sans, i, &san_value, &san_type))) {
                if (rc == -1) {
                    /* fatal error */
                    nc_tls_sans_destroy_wrap(sans);
                    return -1;
                }

                /* got a type that we dont care about */
                continue;
            }

            if ((ctn->map_type == NC_TLS_CTN_SAN_ANY) || (ctn->map_type == san_type)) {
                /* found a match */
                *username = san_value;
                break;
            }
            free(san_value);
        }

        nc_tls_sans_destroy_wrap(sans);

        if (i == nsans) {
            switch (ctn->map_type) {
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

static int
nc_server_tls_cert_to_name(struct nc_ctn *ctn, void *cert_chain, char **username)
{
    int ret = 1, i, cert_count, fingerprint_match;
    char *digest_md5, *digest_sha1, *digest_sha224;
    char *digest_sha256, *digest_sha384, *digest_sha512;
    void *cert;

    /* first make sure the entry is valid */
    if (!ctn->map_type || ((ctn->map_type == NC_TLS_CTN_SPECIFIED) && !ctn->name)) {
        VRB(NULL, "Cert verify CTN: entry with id %u not valid, skipping.", ctn->id);
        return 1;
    }

    cert_count = nc_tls_get_num_certs_wrap(cert_chain);
    for (i = 0; i < cert_count; i++) {
        /* reset the flag */
        fingerprint_match = 0;

        /*get next cert */
        nc_tls_get_cert_wrap(cert_chain, i, &cert);
        if (!cert) {
            ERR(NULL, "Failed to get certificate from the chain.");
            ret = -1;
            goto cleanup;
        }

        if (!ctn->fingerprint) {
            /* if ctn has no fingerprint, it will match any certificate */
            fingerprint_match = 1;

            /* MD5 */
        } else if (!strncmp(ctn->fingerprint, "01", 2)) {
            digest_md5 = nc_server_tls_md5(cert);
            if (!digest_md5) {
                ret = -1;
                goto cleanup;
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_md5)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                fingerprint_match = 1;
            }
            free(digest_md5);

            /* SHA-1 */
        } else if (!strncmp(ctn->fingerprint, "02", 2)) {
            digest_sha1 = nc_server_tls_sha1(cert);
            if (!digest_sha1) {
                ret = -1;
                goto cleanup;
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha1)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                fingerprint_match = 1;
            }
            free(digest_sha1);

            /* SHA-224 */
        } else if (!strncmp(ctn->fingerprint, "03", 2)) {
            digest_sha224 = nc_server_tls_sha224(cert);
            if (!digest_sha224) {
                ret = -1;
                goto cleanup;
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha224)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                fingerprint_match = 1;
            }
            free(digest_sha224);

            /* SHA-256 */
        } else if (!strncmp(ctn->fingerprint, "04", 2)) {
            digest_sha256 = nc_server_tls_sha256(cert);
            if (!digest_sha256) {
                ret = -1;
                goto cleanup;
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha256)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                fingerprint_match = 1;
            }
            free(digest_sha256);

            /* SHA-384 */
        } else if (!strncmp(ctn->fingerprint, "05", 2)) {
            digest_sha384 = nc_server_tls_sha384(cert);
            if (!digest_sha384) {
                ret = -1;
                goto cleanup;
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha384)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                fingerprint_match = 1;
            }
            free(digest_sha384);

            /* SHA-512 */
        } else if (!strncmp(ctn->fingerprint, "06", 2)) {
            digest_sha512 = nc_server_tls_sha512(cert);
            if (!digest_sha512) {
                ret = -1;
                goto cleanup;
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha512)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                fingerprint_match = 1;
            }
            free(digest_sha512);

            /* unknown */
        } else {
            WRN(NULL, "Unknown fingerprint algorithm used (%s), skipping.", ctn->fingerprint);
            continue;
        }

        if (fingerprint_match) {
            /* found a fingerprint match, try to obtain the username */
            ret = nc_server_tls_get_username(cert, ctn, username);
            if (ret == -1) {
                /* fatal error */
                goto cleanup;
            } else if (!ret) {
                /* username found */
                goto cleanup;
            }
        }
    }

cleanup:
    return ret;
}

static int
_nc_server_tls_cert_to_name(struct nc_server_tls_opts *opts, void *cert_chain, char **username)
{
    int ret = 1;
    struct nc_endpt *referenced_endpt;
    struct nc_ctn *ctn;

    for (ctn = opts->ctn; ctn; ctn = ctn->next) {
        ret = nc_server_tls_cert_to_name(ctn, cert_chain, username);
        if (ret != 1) {
            /* fatal error or success */
            goto cleanup;
        }
    }

    /* do the same for referenced endpoint's ctn entries */
    if (opts->referenced_endpt_name) {
        if (nc_server_get_referenced_endpt(opts->referenced_endpt_name, &referenced_endpt)) {
            ERRINT;
            ret = -1;
            goto cleanup;
        }

        for (ctn = referenced_endpt->opts.tls->ctn; ctn; ctn = ctn->next) {
            ret = nc_server_tls_cert_to_name(ctn, cert_chain, username);
            if (ret != 1) {
                /* fatal error or success */
                goto cleanup;
            }
        }
    }

cleanup:
    return ret;
}

static int
_nc_server_tls_verify_peer_cert(void *peer_cert, struct nc_cert_grouping *ee_certs)
{
    int i, ret;
    void *cert;
    struct nc_certificate *certs;
    uint16_t cert_count;

    if (ee_certs->store == NC_STORE_LOCAL) {
        /* local definition */
        certs = ee_certs->certs;
        cert_count = ee_certs->cert_count;
    } else {
        /* truststore reference */
        if (nc_server_tls_truststore_ref_get_certs(ee_certs->ts_ref, &certs, &cert_count)) {
            ERR(NULL, "Error getting end-entity certificates from the truststore reference \"%s\".", ee_certs->ts_ref);
            return -1;
        }
    }

    for (i = 0; i < cert_count; i++) {
        /* import stored cert */
        cert = nc_base64der_to_cert(certs[i].data);

        /* compare stored with received */
        ret = nc_server_tls_certs_match_wrap(peer_cert, cert);
        nc_tls_cert_destroy_wrap(cert);
        if (ret) {
            /* found a match */
            VRB(NULL, "Cert verify: fail, but the end-entity certificate is trusted, continuing.");
            return 0;
        }
    }

    return 1;
}

int
nc_server_tls_verify_peer_cert(void *peer_cert, struct nc_server_tls_opts *opts)
{
    int rc;
    struct nc_endpt *referenced_endpt;

    rc = _nc_server_tls_verify_peer_cert(peer_cert, &opts->ee_certs);
    if (!rc) {
        return 0;
    }

    if (opts->referenced_endpt_name) {
        if (nc_server_get_referenced_endpt(opts->referenced_endpt_name, &referenced_endpt)) {
            ERRINT;
            return -1;
        }

        rc = _nc_server_tls_verify_peer_cert(peer_cert, &referenced_endpt->opts.tls->ee_certs);
        if (!rc) {
            return 0;
        }
    }

    return 1;
}

int
nc_server_tls_verify_cert(void *cert, int depth, int trusted, struct nc_tls_verify_cb_data *cb_data)
{
    int ret = 0;
    char *subject = NULL, *issuer = NULL;
    struct nc_server_tls_opts *opts = cb_data->opts;
    struct nc_session *session = cb_data->session;
    void *cert_chain = cb_data->chain;

    if (session->username) {
        /* already verified */
        return 0;
    }

    subject = nc_server_tls_get_subject_wrap(cert);
    issuer = nc_server_tls_get_issuer_wrap(cert);
    if (!subject || !issuer) {
        ERR(session, "Failed to get certificate's subject or issuer.");
        ret = -1;
        goto cleanup;
    }

    VRB(session, "Cert verify: depth %d.", depth);
    VRB(session, "Cert verify: subject: %s.", subject);
    VRB(session, "Cert verify: issuer: %s.", issuer);

    if (depth == 0) {
        if (!trusted) {
            /* peer cert is not trusted, so it must match any configured end-entity cert
             * on the given endpoint in order for the client to be authenticated */
            ret = nc_server_tls_verify_peer_cert(cert, opts);
            if (ret) {
                ERR(session, "Cert verify: fail (Client certificate not trusted and does not match any configured end-entity certificate).");
                goto cleanup;
            }
        }

        /* get username since we are at depth 0 and have the whole cert chain,
         * the whole chain is needed in order to comply with the following issue:
         * https://github.com/CESNET/netopeer2/issues/1596
         */
        ret = _nc_server_tls_cert_to_name(opts, cert_chain, &session->username);
        if (ret == -1) {
            /* fatal error */
            goto cleanup;
        }

        if (session->username) {
            VRB(NULL, "Cert verify CTN: new client username recognized as \"%s\".", session->username);
        } else {
            VRB(NULL, "Cert verify CTN: unsuccessful, dropping the new client.");
            ret = 1;
            goto cleanup;
        }

        if (server_opts.user_verify_clb && !server_opts.user_verify_clb(session)) {
            VRB(session, "Cert verify: user verify callback revoked authorization.");
            ret = 1;
            goto cleanup;
        }
    }

cleanup:
    free(subject);
    free(issuer);
    return ret;
}

API const void *
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
    /* CONFIG LOCK */
    pthread_rwlock_wrlock(&server_opts.config_lock);

    server_opts.user_verify_clb = verify_clb;

    /* CONFIG UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);
}

int
nc_server_tls_load_server_cert_key(struct nc_server_tls_opts *opts, void **srv_cert, void **srv_pkey)
{
    char *privkey_data = NULL, *cert_data = NULL;
    enum nc_privkey_format privkey_type;
    void *cert = NULL;
    void *pkey = NULL;

    *srv_cert = *srv_pkey = NULL;

    /* get data needed for setting the server cert */
    if (opts->store == NC_STORE_LOCAL) {
        /* local definition */
        cert_data = opts->cert_data;
        privkey_data = opts->privkey_data;
        privkey_type = opts->privkey_type;
    } else {
        /* keystore */
        if (nc_server_tls_ks_ref_get_cert_key(opts->key_ref, opts->cert_ref, &privkey_data, &privkey_type, &cert_data)) {
            ERR(NULL, "Getting server certificate from the keystore reference \"%s\" failed.", opts->key_ref);
            return 1;
        }
    }
    if (!cert_data || !privkey_data) {
        ERR(NULL, "Server certificate not configured.");
        return 1;
    }

    cert = nc_base64der_to_cert(cert_data);
    if (!cert) {
        return 1;
    }

    pkey = nc_base64der_to_privkey(privkey_data, nc_privkey_format_to_str(privkey_type));
    if (!pkey) {
        nc_tls_cert_destroy_wrap(cert);
        return 1;
    }

    *srv_cert = cert;
    *srv_pkey = pkey;
    return 0;
}

int
nc_server_tls_load_trusted_certs(struct nc_cert_grouping *ca_certs, void *cert_store)
{
    struct nc_certificate *certs;
    uint16_t i, cert_count;
    void *cert;

    if (ca_certs->store == NC_STORE_LOCAL) {
        /* local definition */
        certs = ca_certs->certs;
        cert_count = ca_certs->cert_count;
    } else {
        /* truststore */
        if (nc_server_tls_truststore_ref_get_certs(ca_certs->ts_ref, &certs, &cert_count)) {
            ERR(NULL, "Error getting certificate-authority certificates from the truststore reference \"%s\".", ca_certs->ts_ref);
            return 1;
        }
    }

    for (i = 0; i < cert_count; i++) {
        /* parse data into cert */
        cert = nc_base64der_to_cert(certs[i].data);
        if (!cert) {
            return 1;
        }

        /* store cert in cert store */
        if (nc_tls_add_cert_to_store_wrap(cert, cert_store)) {
            nc_tls_cert_destroy_wrap(cert);
            return 1;
        }
    }

    return 0;
}

static int
nc_server_tls_accept_check(int accept_ret, void *tls_session)
{
    uint32_t verify;
    char *err;

    /* check certificate verification result */
    verify = nc_tls_get_verify_result_wrap(tls_session);
    if (!verify && (accept_ret == 1)) {
        VRB(NULL, "Client certificate verified.");
    } else if (verify) {
        err = nc_tls_verify_error_string_wrap(verify);
        ERR(NULL, "Client certificate error (%s).", err);
        free(err);
    }

    if (accept_ret != 1) {
        nc_server_tls_print_accept_err_wrap(accept_ret, tls_session);
    }

    return accept_ret;
}

/**
 * @brief Get the number of certificates in a certificate grouping.
 *
 * @param[in] certs_grp Certificate grouping to get the number of certificates from.
 * @return Number of certificates in the grouping, or -1 on error.
 */
static uint16_t
nc_server_tls_get_num_certs(struct nc_cert_grouping *certs_grp)
{
    uint16_t count = 0;
    struct nc_certificate *certs;

    if (certs_grp->store == NC_STORE_LOCAL) {
        count = certs_grp->cert_count;
    } else if (certs_grp->store == NC_STORE_TRUSTSTORE) {
        if (nc_server_tls_truststore_ref_get_certs(certs_grp->ts_ref, &certs, &count)) {
            ERR(NULL, "Getting CA certificates from the truststore reference \"%s\" failed.", certs_grp->ts_ref);
            return -1;
        }
    }

    return count;
}

int
nc_accept_tls_session(struct nc_session *session, struct nc_server_tls_opts *opts, int sock, int timeout)
{
    int rc, timeouted = 0;
    struct timespec ts_timeout;
    struct nc_tls_verify_cb_data cb_data = {0};
    struct nc_endpt *referenced_endpt;
    void *tls_cfg, *srv_cert, *srv_pkey, *cert_store, *crl_store;
    uint32_t cert_count = 0;

    tls_cfg = srv_cert = srv_pkey = cert_store = crl_store = NULL;

    /* set verify cb data */
    cb_data.session = session;
    cb_data.opts = opts;

    /* prepare TLS context from which a session will be created */
    tls_cfg = nc_tls_config_new_wrap(NC_SERVER);
    if (!tls_cfg) {
        goto fail;
    }

    /* opaque CA/CRL certificate store */
    cert_store = nc_tls_cert_store_new_wrap();
    if (!cert_store) {
        goto fail;
    }

    /* load server's key and certificate */
    if (nc_server_tls_load_server_cert_key(opts, &srv_cert, &srv_pkey)) {
        ERR(session, "Loading server certificate and/or private key failed.");
        goto fail;
    }

    /* load trusted CA certificates */
    if (nc_server_tls_load_trusted_certs(&opts->ca_certs, cert_store)) {
        ERR(session, "Loading server CA certs failed.");
        goto fail;
    }

    /* load referenced endpoint's trusted CA certs if set */
    if (opts->referenced_endpt_name) {
        if (nc_server_get_referenced_endpt(opts->referenced_endpt_name, &referenced_endpt)) {
            ERR(session, "Referenced endpoint \"%s\" not found.", opts->referenced_endpt_name);
            goto fail;
        }

        if (nc_server_tls_load_trusted_certs(&referenced_endpt->opts.tls->ca_certs, cert_store)) {
            ERR(session, "Loading server CA certs from referenced endpoint failed.");
            goto fail;
        }
    }

    /* Check if there are no CA/end entity certs configured, which is a valid config.
     * However, that would imply not using TLS for auth, which is not (yet) supported */
    if (!opts->referenced_endpt_name) {
        cert_count = nc_server_tls_get_num_certs(&opts->ca_certs) + nc_server_tls_get_num_certs(&opts->ee_certs);
    } else {
        cert_count = nc_server_tls_get_num_certs(&opts->ca_certs) + nc_server_tls_get_num_certs(&opts->ee_certs) +
                nc_server_tls_get_num_certs(&referenced_endpt->opts.tls->ca_certs) +
                nc_server_tls_get_num_certs(&referenced_endpt->opts.tls->ee_certs);
    }
    if (cert_count <= 0) {
        ERR(session, "Neither CA nor end-entity certificates configured.");
        goto fail;
    }

    if (nc_session_tls_crl_from_cert_ext_fetch(srv_cert, cert_store, &crl_store)) {
        ERR(session, "Loading server CRL failed.");
        goto fail;
    }

    /* set supported TLS versions */
    if (opts->tls_versions) {
        if (nc_server_tls_set_tls_versions_wrap(tls_cfg, opts->tls_versions)) {
            ERR(session, "Setting supported server TLS versions failed.");
            goto fail;
        }
    }

    /* set supported cipher suites */
    if (opts->ciphers) {
        nc_server_tls_set_cipher_suites_wrap(tls_cfg, opts->ciphers);
    }

    /* set verify flags, callback and its data */
    nc_server_tls_set_verify_wrap(tls_cfg, &cb_data);

    /* init TLS context and store data which may be needed later in it */
    if (nc_tls_init_ctx_wrap(srv_cert, srv_pkey, cert_store, crl_store, &session->ti.tls.ctx)) {
        goto fail;
    }

    /* memory is managed by context now */
    srv_cert = srv_pkey = cert_store = crl_store = NULL;

    /* setup config from ctx */
    if (nc_tls_setup_config_from_ctx_wrap(&session->ti.tls.ctx, NC_SERVER, tls_cfg)) {
        goto fail;
    }
    session->ti.tls.config = tls_cfg;
    tls_cfg = NULL;

    /* fill session data and create TLS session from config */
    session->ti_type = NC_TI_TLS;
    if (!(session->ti.tls.session = nc_tls_session_new_wrap(session->ti.tls.config))) {
        goto fail;
    }

    /* if keylog file is set, log the tls secrets there */
    if (server_opts.tls_keylog_file) {
        nc_tls_keylog_session_wrap(session->ti.tls.session);
    }

    /* set session fd */
    nc_tls_set_fd_wrap(session->ti.tls.session, sock, &session->ti.tls.ctx);

    sock = -1;

    /* do the handshake */
    if (timeout > -1) {
        nc_timeouttime_get(&ts_timeout, timeout);
    }
    while ((rc = nc_server_tls_handshake_step_wrap(session->ti.tls.session)) == 0) {
        usleep(NC_TIMEOUT_STEP);
        if ((timeout > -1) && (nc_timeouttime_cur_diff(&ts_timeout) < 1)) {
            ERR(session, "TLS accept timeout.");
            timeouted = 1;
            goto fail;
        }
    }

    /* check if handshake was ok */
    if (nc_server_tls_accept_check(rc, session->ti.tls.session) != 1) {
        goto fail;
    }

    return 1;

fail:
    if (sock > -1) {
        close(sock);
    }

    nc_tls_config_destroy_wrap(tls_cfg);
    nc_tls_cert_destroy_wrap(srv_cert);
    nc_tls_privkey_destroy_wrap(srv_pkey);
    nc_tls_cert_store_destroy_wrap(cert_store);
    nc_tls_crl_store_destroy_wrap(crl_store);

    if (timeouted) {
        return 0;
    } else {
        return -1;
    }
}
