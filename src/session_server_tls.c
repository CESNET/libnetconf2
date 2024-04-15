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

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "session.h"
#include "session_p.h"
#include "session_wrapper.h"

struct nc_server_tls_opts tls_ch_opts;
extern struct nc_server_opts server_opts;

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

static void *
nc_base64der_to_cert(const char *in)
{
    char *buf = NULL;
    void *cert;

    NC_CHECK_ARG_RET(NULL, in, NULL);

    if (asprintf(&buf, "%s%s%s", "-----BEGIN CERTIFICATE-----\n", in, "\n-----END CERTIFICATE-----") == -1) {
        ERRMEM;
        return NULL;
    }

    cert = nc_tls_pem_to_cert_wrap(buf);
    free(buf);
    return cert;
}

static int
nc_base64der_to_cert_add_to_store(const char *in, void *cert_store)
{
    int ret;
    char *buf = NULL;

    NC_CHECK_ARG_RET(NULL, in, cert_store, 1);

    if (asprintf(&buf, "%s%s%s", "-----BEGIN CERTIFICATE-----\n", in, "\n-----END CERTIFICATE-----") == -1) {
        ERRMEM;
        return 1;
    }

    ret = nc_tls_pem_to_cert_add_to_store_wrap(buf, cert_store);
    free(buf);
    return ret;
}

static void *
nc_base64der_to_privkey(const char *in, const char *key_str)
{
    char *buf = NULL;
    void *pkey;

    NC_CHECK_ARG_RET(NULL, in, NULL);

    if (asprintf(&buf, "%s%s%s%s%s%s%s", "-----BEGIN ", key_str, " PRIVATE KEY-----\n", in, "\n-----END ",
            key_str, " PRIVATE KEY-----") == -1) {
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
nc_server_tls_cert_to_name(struct nc_ctn *ctn_first, void *cert, struct nc_ctn_data *data)
{
    int ret = 0;
    char *digest_md5 = NULL, *digest_sha1 = NULL, *digest_sha224 = NULL;
    char *digest_sha256 = NULL, *digest_sha384 = NULL, *digest_sha512 = NULL;
    struct nc_ctn *ctn;
    NC_TLS_CTN_MAPTYPE map_type;

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
                digest_md5 = nc_server_tls_md5(cert);
                if (!digest_md5) {
                    ret = -1;
                    goto cleanup;
                }
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_md5)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }

            /* SHA-1 */
        } else if (!strncmp(ctn->fingerprint, "02", 2)) {
            if (!digest_sha1) {
                digest_sha1 = nc_server_tls_sha1(cert);
                if (!digest_sha1) {
                    ret = -1;
                    goto cleanup;
                }
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha1)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }

            /* SHA-224 */
        } else if (!strncmp(ctn->fingerprint, "03", 2)) {
            if (!digest_sha224) {
                digest_sha224 = nc_server_tls_sha224(cert);
                if (!digest_sha224) {
                    ret = -1;
                    goto cleanup;
                }
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha224)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }

            /* SHA-256 */
        } else if (!strncmp(ctn->fingerprint, "04", 2)) {
            if (!digest_sha256) {
                digest_sha256 = nc_server_tls_sha256(cert);
                if (!digest_sha256) {
                    ret = -1;
                    goto cleanup;
                }
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha256)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }

            /* SHA-384 */
        } else if (!strncmp(ctn->fingerprint, "05", 2)) {
            if (!digest_sha384) {
                digest_sha384 = nc_server_tls_sha384(cert);
                if (!digest_sha384) {
                    ret = -1;
                    goto cleanup;
                }
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha384)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }

            /* SHA-512 */
        } else if (!strncmp(ctn->fingerprint, "06", 2)) {
            if (!digest_sha512) {
                digest_sha512 = nc_server_tls_sha512(cert);
                if (!digest_sha512) {
                    ret = -1;
                    goto cleanup;
                }
            }

            if (!strcasecmp(ctn->fingerprint + 3, digest_sha512)) {
                /* we got ourselves a potential winner! */
                VRB(NULL, "Cert verify CTN: entry with a matching fingerprint found.");
                map_type = ctn->map_type;
            }

            /* unknown */
        } else {
            WRN(NULL, "Unknown fingerprint algorithm used (%s), skipping.", ctn->fingerprint);
            continue;
        }

        if (map_type != NC_TLS_CTN_UNKNOWN) {
            /* found a fingerprint match */
            if (!(map_type & data->matched_ctns)) {
                data->matched_ctns |= map_type;
                data->matched_ctn_type[data->matched_ctn_count++] = map_type;
                if (!data->username && (map_type == NC_TLS_CTN_SPECIFIED)) {
                    data->username = ctn->name; // TODO make a copy?
                }
            }
        }
    }

cleanup:
    free(digest_md5);
    free(digest_sha1);
    free(digest_sha224);
    free(digest_sha256);
    free(digest_sha384);
    free(digest_sha512);
    return ret;
}

static int
nc_server_tls_verify_peer_cert(void *peer_cert, struct nc_cert_grouping *ee_certs)
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
        if (nc_server_tls_ts_ref_get_certs(ee_certs->ts_ref, &certs, &cert_count)) {
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
nc_server_tls_get_username_from_cert(void *cert, NC_TLS_CTN_MAPTYPE map_type, char **username)
{
    char *subject, *cn, *san_value = NULL;
    void *sans;
    int i, nsans = 0, rc;
    NC_TLS_CTN_MAPTYPE san_type = 0;

#ifdef HAVE_LIBMEDTLS
    char rdn_separator = ',';
#else
    char rdn_separator = '/';
#endif

    if (map_type == NC_TLS_CTN_COMMON_NAME) {
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

            if ((map_type == NC_TLS_CTN_SAN_ANY) || (map_type == san_type)) {
                /* found a match */
                *username = san_value;
                break;
            }
            free(san_value);
        }

        nc_tls_sans_destroy_wrap(sans);

        if (i == nsans) {
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

int
nc_server_tls_verify_cert(void *cert, int depth, int self_signed, struct nc_tls_verify_cb_data *cb_data)
{
    int ret = 0, i;
    char *subject = NULL, *issuer = NULL;
    struct nc_server_tls_opts *opts = cb_data->opts;
    struct nc_session *session = cb_data->session;
    struct nc_endpt *referenced_endpt;

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
        if (self_signed) {
            /* peer cert is not trusted, so it must match any configured end-entity cert
             * on the given endpoint in order for the client to be authenticated */
            ret = nc_server_tls_verify_peer_cert(cert, &opts->ee_certs);
            if (ret) {
                /* we can still check the referenced endpoint's ee certs */
                if (opts->referenced_endpt_name) {
                    if (nc_server_get_referenced_endpt(opts->referenced_endpt_name, &referenced_endpt)) {
                        ERRINT;
                        ret = -1;
                        goto cleanup;
                    }

                    ret = nc_server_tls_verify_peer_cert(cert, &referenced_endpt->opts.tls->ee_certs);
                }
                if (ret) {
                    ERR(session, "Cert verify: fail (Client certificate not trusted and does not match any configured end-entity certificate).");
                    goto cleanup;
                }
            }
        }
    }

    /* get matching ctn entries */
    ret = nc_server_tls_cert_to_name(opts->ctn, cert, &cb_data->ctn_data);
    if (ret == -1) {
        /* fatal error */
        goto cleanup;
    }

    /* check the referenced endpoint's ctn entries */
    if (opts->referenced_endpt_name) {
        if (nc_server_get_referenced_endpt(opts->referenced_endpt_name, &referenced_endpt)) {
            ERRINT;
            ret = -1;
            goto cleanup;
        }

        ret = nc_server_tls_cert_to_name(referenced_endpt->opts.tls->ctn, cert, &cb_data->ctn_data);
        if (ret == -1) {
            /* fatal error */
            goto cleanup;
        }
    }

    /* obtain username from matched ctn entries */
    if (depth == 0) {
        for (i = 0; i < cb_data->ctn_data.matched_ctn_count; i++) {
            if (cb_data->ctn_data.matched_ctn_type[i] == NC_TLS_CTN_SPECIFIED) {
                session->username = strdup(cb_data->ctn_data.username);
                NC_CHECK_ERRMEM_GOTO(!session->username, ret = -1, cleanup);
            } else {
                ret = nc_server_tls_get_username_from_cert(cert, cb_data->ctn_data.matched_ctn_type[i], &session->username);
                if (ret == -1) {
                    /* fatal error */
                    goto cleanup;
                } else if (!ret) {
                    /* username obtained */
                    break;
                }
            }
        }
        if (session->username) {
            VRB(NULL, "Cert verify CTN: new client username recognized as \"%s\".", session->username);
        } else {
            VRB(NULL, "Cert verify CTN: unsuccessful, dropping the new client.");
            ret = 1;
            goto cleanup;
        }
    }

    if (session->username && server_opts.user_verify_clb && !server_opts.user_verify_clb(session)) {
        VRB(session, "Cert verify: user verify callback revoked authorization.");
        ret = 1;
        goto cleanup;
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
    server_opts.user_verify_clb = verify_clb;
}

int
nc_server_tls_load_server_cert_key(struct nc_server_tls_opts *opts, void **srv_cert, void **srv_pkey)
{
    char *privkey_data = NULL, *cert_data = NULL;
    NC_PRIVKEY_FORMAT privkey_type;
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
        ret = -1;
        goto cleanup;
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

static size_t
nc_server_tls_curl_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct nc_curl_data *data;

    size = nmemb;

    data = (struct nc_curl_data *)userdata;

    data->data = nc_realloc(data->data, data->size + size);
    NC_CHECK_ERRMEM_RET(!data->data, 0);

    memcpy(&data->data[data->size], ptr, size);
    data->size += size;

    return size;
}

static int
nc_server_tls_curl_fetch(CURL *handle, const char *url)
{
    char err_buf[CURL_ERROR_SIZE];

    /* set uri */
    if (curl_easy_setopt(handle, CURLOPT_URL, url)) {
        ERR(NULL, "Setting URI \"%s\" to download CRL from failed.", url);
        return 1;
    }

    /* set err buf */
    if (curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, err_buf)) {
        ERR(NULL, "Setting CURL error buffer option failed.");
        return 1;
    }

    /* download */
    if (curl_easy_perform(handle)) {
        ERR(NULL, "Downloading CRL from \"%s\" failed (%s).", url, err_buf);
        return 1;
    }

    return 0;
}

static int
nc_server_tls_curl_init(CURL **handle, struct nc_curl_data *data)
{
    NC_CHECK_ARG_RET(NULL, handle, data, -1);

    *handle = NULL;

    *handle = curl_easy_init();
    if (!*handle) {
        ERR(NULL, "Initializing CURL failed.");
        return 1;
    }

    if (curl_easy_setopt(*handle, CURLOPT_WRITEFUNCTION, nc_server_tls_curl_cb)) {
        ERR(NULL, "Setting curl callback failed.");
        return 1;
    }

    if (curl_easy_setopt(*handle, CURLOPT_WRITEDATA, data)) {
        ERR(NULL, "Setting curl callback data failed.");
        return 1;
    }

    return 0;
}

static int
nc_server_tls_crl_path(const char *path, void *cert_store, void *crl_store)
{
    return nc_tls_import_crl_path_wrap(path, cert_store, crl_store);
}

static int
nc_server_tls_crl_url(const char *url, void *cert_store, void *crl_store)
{
    int ret = 0;
    CURL *handle = NULL;
    struct nc_curl_data downloaded = {0};

    /* init curl */
    ret = nc_server_tls_curl_init(&handle, &downloaded);
    if (ret) {
        goto cleanup;
    }

    VRB(NULL, "Downloading CRL from \"%s\".", url);

    /* download the CRL */
    ret = nc_server_tls_curl_fetch(handle, url);
    if (ret) {
        goto cleanup;
    }

    /* convert the downloaded data to CRL and add it to the store */
    ret = nc_server_tls_add_crl_to_store_wrap(downloaded.data, downloaded.size, cert_store, crl_store);
    if (ret) {
        goto cleanup;
    }

cleanup:
    curl_easy_cleanup(handle);
    return ret;
}

static int
nc_server_tls_crl_cert_ext(void *cert_store, void *crl_store)
{
    int ret = 0;
    CURL *handle = NULL;
    struct nc_curl_data downloaded = {0};
    char **uris = NULL;
    int uri_count = 0, i;

    /* init curl */
    ret = nc_server_tls_curl_init(&handle, &downloaded);
    if (ret) {
        goto cleanup;
    }

    /* get all the uris we can, even though some may point to the same CRL */
    ret = nc_server_tls_get_crl_distpoint_uris_wrap(cert_store, &uris, &uri_count);
    if (ret) {
        goto cleanup;
    }

    for (i = 0; i < uri_count; i++) {
        VRB(NULL, "Downloading CRL from \"%s\".", uris[i]);
        ret = nc_server_tls_curl_fetch(handle, uris[i]);
        if (ret) {
            /* failed to download the CRL from this entry, try the next entry */
            WRN(NULL, "Failed to fetch CRL from \"%s\".", uris[i]);
            continue;
        }

        /* convert the downloaded data to CRL and add it to the store */
        ret = nc_server_tls_add_crl_to_store_wrap(downloaded.data, downloaded.size, cert_store, crl_store);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    for (i = 0; i < uri_count; i++) {
        free(uris[i]);
    }
    free(uris);
    curl_easy_cleanup(handle);
    return ret;
}

int
nc_server_tls_load_crl(struct nc_server_tls_opts *opts, void *cert_store, void *crl_store)
{
    if (opts->crl_path) {
        if (nc_server_tls_crl_path(opts->crl_path, cert_store, crl_store)) {
            return 1;
        }
    } else if (opts->crl_url) {
        if (nc_server_tls_crl_url(opts->crl_url, cert_store, crl_store)) {
            return 1;
        }
    } else {
        if (nc_server_tls_crl_cert_ext(cert_store, crl_store)) {
            return 1;
        }
    }

    return 0;
}

int
nc_server_tls_load_trusted_certs(struct nc_cert_grouping *ca_certs, void *cert_store)
{
    struct nc_certificate *certs;
    uint16_t i, cert_count;

    if (ca_certs->store == NC_STORE_LOCAL) {
        /* local definition */
        certs = ca_certs->certs;
        cert_count = ca_certs->cert_count;
    } else {
        /* truststore */
        if (nc_server_tls_ts_ref_get_certs(ca_certs->ts_ref, &certs, &cert_count)) {
            ERR(NULL, "Error getting certificate-authority certificates from the truststore reference \"%s\".", ca_certs->ts_ref);
            return 1;
        }
    }

    for (i = 0; i < cert_count; i++) {
        if (nc_base64der_to_cert_add_to_store(certs[i].data, cert_store)) {
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
        nc_server_tls_print_accept_error_wrap(accept_ret, tls_session);
    }

    return accept_ret;
}

int
nc_accept_tls_session(struct nc_session *session, struct nc_server_tls_opts *opts, int sock, int timeout)
{
    int rc, timeouted = 0;
    struct timespec ts_timeout;
    struct nc_tls_verify_cb_data cb_data = {0};
    struct nc_endpt *referenced_endpt;
    void *tls_cfg, *srv_cert, *srv_pkey, *cert_store, *crl_store;

    tls_cfg = srv_cert = srv_pkey = cert_store = crl_store = NULL;

    /* set verify cb data */
    cb_data.session = session;
    cb_data.opts = opts;

    /* prepare TLS context from which a session will be created */
    tls_cfg = nc_server_tls_config_new_wrap();
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

    if (opts->crl_path || opts->crl_url || opts->crl_cert_ext) {
        /* opaque CRL store */
        crl_store = nc_tls_crl_store_new_wrap();
        if (!crl_store) {
            goto fail;
        }

        /* load CRLs into one of the stores */
        if (nc_server_tls_load_crl(opts, cert_store, crl_store)) {
            ERR(session, "Loading server CRL failed.");
            goto fail;
        }
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

    /* init TLS context and store data which may be needed later in it */
    if (nc_tls_init_ctx_wrap(&session->ti.tls.ctx, sock, srv_cert, srv_pkey, cert_store, crl_store)) {
        goto fail;
    }

    /* memory is managed by context now */
    srv_cert = srv_pkey = cert_store = crl_store = NULL;

    /* setup config from ctx */
    if (nc_tls_setup_config_wrap(tls_cfg, NC_SERVER, &session->ti.tls.ctx)) {
        goto fail;
    } // TODO free openssl shit
    session->ti.tls.config = tls_cfg;
    tls_cfg = NULL;

    /* fill session data and create TLS session from config */
    session->ti_type = NC_TI_TLS;
    if (!(session->ti.tls.session = nc_tls_session_new_wrap(session->ti.tls.config))) {
        goto fail;
    }

    /* set verify callback and its data */
    nc_server_tls_set_verify_cb_wrap(session->ti.tls.session, &cb_data);

    /* set session fd */
    nc_server_tls_set_fd_wrap(session->ti.tls.session, sock, &session->ti.tls.ctx);

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
