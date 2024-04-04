#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <sys/stat.h>
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

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/bignum.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/pem.h>
#include <mbedtls/oid.h>
#include <mbedtls/base64.h>

extern struct nc_server_opts server_opts;

void *
nc_tls_session_new_wrap(void *tls_cfg)
{
    int rc;
    mbedtls_ssl_context *session;

    session = malloc(sizeof *session);
    NC_CHECK_ERRMEM_RET(!session, NULL);

    mbedtls_ssl_init(session);

    rc = mbedtls_ssl_setup(session, tls_cfg);
    if (rc) {
        ERR(NULL, "Setting up TLS context failed (%s).", mbedtls_high_level_strerr(rc));
        mbedtls_ssl_free(session);
        free(session);
        return NULL;
    }

    return session;
}

void
nc_tls_session_destroy_wrap(void *tls_session)
{
    mbedtls_ssl_free(tls_session);
    free(tls_session);
}

void *
nc_server_tls_config_new_wrap()
{
    mbedtls_ssl_config *tls_cfg;

    tls_cfg = malloc(sizeof *tls_cfg);
    NC_CHECK_ERRMEM_RET(!tls_cfg, NULL);

    mbedtls_ssl_config_init(tls_cfg);
    return tls_cfg;
}

void *
nc_client_tls_config_new_wrap()
{
    mbedtls_ssl_config *tls_cfg;

    tls_cfg = malloc(sizeof *tls_cfg);
    NC_CHECK_ERRMEM_RET(!tls_cfg, NULL);

    mbedtls_ssl_config_init(tls_cfg);
    return tls_cfg;
}

void
nc_tls_config_destroy_wrap(void *tls_cfg)
{
    if (!tls_cfg) {
        return;
    }

    mbedtls_ssl_config_free(tls_cfg);
    free(tls_cfg);
}

void *
nc_tls_cert_new_wrap()
{
    mbedtls_x509_crt *cert;

    cert = malloc(sizeof *cert);
    NC_CHECK_ERRMEM_RET(!cert, NULL);

    mbedtls_x509_crt_init(cert);
    return cert;
}

void
nc_tls_cert_destroy_wrap(void *cert)
{
    mbedtls_x509_crt_free(cert);
    free(cert);
}

void *
nc_tls_privkey_new_wrap()
{
    mbedtls_pk_context *pkey;

    pkey = malloc(sizeof *pkey);
    NC_CHECK_ERRMEM_RET(!pkey, NULL);

    mbedtls_pk_init(pkey);
    return pkey;
}

void
nc_tls_privkey_destroy_wrap(void *pkey)
{
    mbedtls_pk_free(pkey);
    free(pkey);
}

void *
nc_tls_cert_store_new_wrap()
{
    return nc_tls_cert_new_wrap();
}

void
nc_tls_cert_store_destroy_wrap(void *cert_store)
{
    nc_tls_cert_destroy_wrap(cert_store);
}

void *
nc_tls_crl_store_new_wrap()
{
    mbedtls_x509_crl *crl;

    crl = malloc(sizeof *crl);
    NC_CHECK_ERRMEM_RET(!crl, NULL);

    mbedtls_x509_crl_init(crl);
    return crl;
}

void
nc_tls_crl_store_destroy_wrap(void *crl)
{
    mbedtls_x509_crl_free(crl);
    free(crl);
}

static int
nc_tls_rng_new(mbedtls_ctr_drbg_context **ctr_drbg, mbedtls_entropy_context **entropy)
{
    *ctr_drbg = NULL;
    *entropy = NULL;

    *entropy = malloc(sizeof **entropy);
    NC_CHECK_ERRMEM_GOTO(!*entropy, , fail);
    *ctr_drbg = malloc(sizeof **ctr_drbg);
    NC_CHECK_ERRMEM_GOTO(!*ctr_drbg, , fail);

    mbedtls_entropy_init(*entropy);
    mbedtls_ctr_drbg_init(*ctr_drbg);

    if (mbedtls_ctr_drbg_seed(*ctr_drbg, mbedtls_entropy_func, *entropy, NULL, 0)) {
        ERR(NULL, "Seeding ctr_drbg failed.");
        goto fail;
    }

    return 0;

fail:
    mbedtls_ctr_drbg_free(*ctr_drbg);
    free(*ctr_drbg);
    mbedtls_entropy_free(*entropy);
    free(*entropy);
    *ctr_drbg = NULL;
    *entropy = NULL;
    return 1;
}

static void
nc_tls_rng_destroy(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy)
{
    mbedtls_ctr_drbg_free(ctr_drbg);
    free(ctr_drbg);
    mbedtls_entropy_free(entropy);
    free(entropy);
}

void
nc_tls_set_authmode_wrap(void *tls_cfg)
{
    mbedtls_ssl_conf_authmode(tls_cfg, MBEDTLS_SSL_VERIFY_REQUIRED);
}

int
nc_server_tls_set_config_defaults_wrap(void *tls_cfg)
{
    int rc;

    rc = mbedtls_ssl_config_defaults(tls_cfg, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc) {
        ERR(NULL, "Setting default TLS config failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    return 0;
}

void *
nc_tls_pem_to_cert_wrap(const char *cert_data)
{
    int rc;
    mbedtls_x509_crt *cert;

    cert = nc_tls_cert_new_wrap();
    if (!cert) {
        return NULL;
    }

    rc = mbedtls_x509_crt_parse(cert, (const unsigned char *)cert_data, strlen(cert_data) + 1);
    if (rc) {
        ERR(NULL, "Parsing certificate data failed (%s).", mbedtls_high_level_strerr(rc));
        nc_tls_cert_destroy_wrap(cert);
        return NULL;
    }

    return cert;
}

void *
nc_tls_base64_to_cert_wrap(const char *cert_data)
{
    int rc;
    mbedtls_x509_crt *cert;
    char *pem = NULL;

    cert = nc_tls_cert_new_wrap();
    if (!cert) {
        return NULL;
    }

    rc = asprintf(&pem, "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", cert_data);
    if (rc == -1) {
        ERRMEM;
        nc_tls_cert_destroy_wrap(cert);
        return NULL;
    }

    rc = mbedtls_x509_crt_parse(cert, (const unsigned char *)pem, strlen(pem) + 1);
    if (rc) {
        ERR(NULL, "Parsing certificate data failed (%s).", mbedtls_high_level_strerr(rc));
        nc_tls_cert_destroy_wrap(cert);
        return NULL;
    }

    return cert;
}

int
nc_tls_pem_to_cert_add_to_store_wrap(const char *cert_data, void *cert_store)
{
    int rc;

    rc = mbedtls_x509_crt_parse(cert_store, (const unsigned char *)cert_data, strlen(cert_data) + 1);
    if (rc) {
        ERR(NULL, "Parsing certificate data failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    return 0;
}

void *
nc_tls_pem_to_privkey_wrap(const char *privkey_data)
{
    int rc;
    mbedtls_pk_context *pkey;
    mbedtls_ctr_drbg_context *ctr_drbg;
    mbedtls_entropy_context *entropy;

    if (nc_tls_rng_new(&ctr_drbg, &entropy)) {
        return NULL;
    }

    pkey = nc_tls_privkey_new_wrap();
    if (!pkey) {
        nc_tls_rng_destroy(ctr_drbg, entropy);
        return NULL;
    }

    rc = mbedtls_pk_parse_key(pkey, (const unsigned char *)privkey_data, strlen(privkey_data) + 1, NULL, 0, mbedtls_ctr_drbg_random, ctr_drbg);
    nc_tls_rng_destroy(ctr_drbg, entropy);
    if (rc) {
        ERR(NULL, "Parsing private key data failed (%s).", mbedtls_high_level_strerr(rc));
        nc_tls_privkey_destroy_wrap(pkey);
        return NULL;
    }
    return pkey;
}

int
nc_tls_load_cert_private_key_wrap(void *tls_cfg, void *cert, void *pkey)
{
    int rc;

    rc = mbedtls_ssl_conf_own_cert(tls_cfg, cert, pkey);
    if (rc) {
        ERR(NULL, "Loading the server certificate or private key failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    return 0;
}

int
nc_server_tls_crl_path_wrap(const char *crl_path, void *cert_store, void *crl_store)
{
    int rc;

    (void) cert_store;

    rc = mbedtls_x509_crl_parse_file(crl_store, crl_path);
    if (rc) {
        ERR(NULL, "Error adding CRL to store (%s)", mbedtls_high_level_strerr(rc));
        return 1;
    }

    return 0;
}

int
nc_server_tls_add_crl_to_store_wrap(const unsigned char *crl_data, size_t size, void *cert_store, void *crl_store)
{
    int rc;

    (void) cert_store;

    /* try DER first */
    rc = mbedtls_x509_crl_parse_der(crl_store, crl_data, size);
    if (!rc) {
        /* success, it was DER */
        return 0;
    }

    /* DER failed, try PEM */
    rc = mbedtls_x509_crl_parse(crl_store, crl_data, size);
    if (!rc) {
        /* success, it was PEM */
        return 0;
    }

    /* failed to parse it */
    ERR(NULL, "Reading downloaded CRL failed.");
    return 1;
}

void
nc_server_tls_set_certs_wrap(void *tls_cfg, void *cert_store, void *crl_store)
{
    mbedtls_ssl_conf_ca_chain(tls_cfg, cert_store, crl_store);
}

int
nc_server_tls_set_tls_versions_wrap(void *tls_cfg, unsigned int tls_versions)
{
    if ((tls_versions & NC_TLS_VERSION_10) || ((tls_versions & NC_TLS_VERSION_11))) {
        /* skip TLS versions 1.0 and 1.1 */
        WRN(NULL, "mbedTLS does not support TLS1.0 and TLS1.1");
    }

    /* first set the minimum version */
    if (tls_versions & NC_TLS_VERSION_12) {
        mbedtls_ssl_conf_min_tls_version(tls_cfg, MBEDTLS_SSL_VERSION_TLS1_2);
    } else if (tls_versions & NC_TLS_VERSION_13) {
        mbedtls_ssl_conf_min_tls_version(tls_cfg, MBEDTLS_SSL_VERSION_TLS1_3);
    }

    /* then set the maximum version */
    if (tls_versions & NC_TLS_VERSION_13) {
        mbedtls_ssl_conf_max_tls_version(tls_cfg, MBEDTLS_SSL_VERSION_TLS1_3);
    } else if (tls_versions & NC_TLS_VERSION_12) {
        mbedtls_ssl_conf_max_tls_version(tls_cfg, MBEDTLS_SSL_VERSION_TLS1_2);
    }

    return 0;
}

static int
nc_server_tls_verify_cb(void *cb_data, mbedtls_x509_crt *cert, int depth, uint32_t *flags)
{
    int ret = 0;
    struct nc_tls_verify_cb_data *data = cb_data;
    size_t buf_len = 256;
    char err_buf[buf_len];

    if (!*flags) {
        /* in-built verification was successful */
        ret = nc_server_tls_verify_cert(cert, depth, 0, data);
    } else {
        /* in-built verification was failed, either check if peer cert matches any configured cert, or just
         * return success and wait until we reach depth 0
         */
        if ((depth == 0) && (*flags == MBEDTLS_X509_BADCERT_NOT_TRUSTED)) {
            /* not trusted self-signed peer certificate */
            ret = nc_server_tls_verify_cert(cert, depth, 1, data);
            if (!ret) {
                *flags &= ~MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            }
        } else {
            buf_len = mbedtls_x509_crt_verify_info(err_buf, buf_len, "", *flags);
            if (buf_len > 0) {
                /* strip the NL and print it */
                err_buf[buf_len - 1] = '\0';
                ERR(data->session, "Cert verify: fail (%s).", err_buf);
            }
            ret = 1;
        }
    }

    if (ret == -1) {
        /* fatal error */
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    } else if (!ret) {
        /* success */
        return 0;
    } else {
        if (depth > 0) {
            /* chain verify failed, but peer cert can still match */
            return 0;
        } else {
            /* peer cert did not match */
            return 1;
        }
    }
}

void
nc_server_tls_set_verify_cb_wrap(void *tls_session, struct nc_tls_verify_cb_data *cb_data)
{
    mbedtls_ssl_set_verify(tls_session, nc_server_tls_verify_cb, cb_data);
}

static char *
nc_server_tls_dn2str(const mbedtls_x509_name *dn)
{
    char *str;
    size_t len = 64;
    int r;
    void *ptr;

    str = malloc(len);
    NC_CHECK_ERRMEM_RET(!str, NULL);

    while ((r = mbedtls_x509_dn_gets(str, len, dn)) == MBEDTLS_ERR_X509_BUFFER_TOO_SMALL)  {
        len <<= 1;
        ptr = realloc(str, len);
        if (!ptr) {
            ERRMEM;
            free(str);
            return NULL;
        }
        str = ptr;
    }
    if (r < 1) {
        free(str);
        ERRMEM;
        return NULL;
    }
    return str;
}

char *
nc_server_tls_get_subject_wrap(void *cert)
{
    return nc_server_tls_dn2str(&(((mbedtls_x509_crt *)cert)->subject));
}

char *
nc_server_tls_get_issuer_wrap(void *cert)
{
    return nc_server_tls_dn2str(&(((mbedtls_x509_crt *)cert)->issuer));
}

int
nc_server_tls_get_username_from_cert_wrap(void *cert, NC_TLS_CTN_MAPTYPE map_type, char **username)
{
    int rc;
    char *subject, *common_name;
    mbedtls_x509_subject_alternative_name san = {0};
    mbedtls_x509_sequence *cur = NULL;
    const mbedtls_x509_buf *ip;
    mbedtls_x509_crt *peer_cert = cert;

    *username = NULL;
    if (map_type == NC_TLS_CTN_COMMON_NAME) {
        subject = nc_server_tls_get_subject_wrap(peer_cert);
        NC_CHECK_ERRMEM_RET(!subject, -1);
        common_name = strstr(subject, "CN=");
        if (!common_name) {
            WRN(NULL, "Certificate does not include the commonName field.");
            free(subject);
            return 1;
        }
        common_name += 3;
        if (strchr(common_name, ',')) {
            *strchr(common_name, ',') = '\0';
        }
        *username = strdup(common_name);
        free(subject);
        NC_CHECK_ERRMEM_RET(!*username, -1);
    } else {
        /* retrieve subjectAltName's rfc822Name (email), dNSName and iPAddress values */
        cur = &peer_cert->subject_alt_names;
        while (cur) {
            rc = mbedtls_x509_parse_subject_alt_name(&cur->buf, &san);
            if (rc && (rc != MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE)) {
                ERR(NULL, "Getting SANs failed.");
                return 1;
            }

            if (((map_type == NC_TLS_CTN_SAN_ANY) || (map_type == NC_TLS_CTN_SAN_DNS_NAME)) &&
                    (san.type == MBEDTLS_X509_SAN_DNS_NAME)) {
                *username = strndup((const char *)san.san.unstructured_name.p, san.san.unstructured_name.len); // TODO: tolower()?
                NC_CHECK_ERRMEM_RET(!*username, -1);
                break;
            }

            if (((map_type == NC_TLS_CTN_SAN_ANY) || (map_type == NC_TLS_CTN_SAN_RFC822_NAME)) &&
                    (san.type == MBEDTLS_X509_SAN_RFC822_NAME)) {
                *username = strndup((const char *)san.san.unstructured_name.p, san.san.unstructured_name.len);
                NC_CHECK_ERRMEM_RET(!*username, -1);
                break;
            }

                    /* iPAddress */
            if (((map_type == NC_TLS_CTN_SAN_ANY) || (map_type == NC_TLS_CTN_SAN_IP_ADDRESS)) &&
                    (san.type == MBEDTLS_X509_SAN_IP_ADDRESS)) {
                ip = &san.san.unstructured_name;
                if (ip->len == 4) {
                    if (asprintf(username, "%d.%d.%d.%d", ip->p[0], ip->p[1], ip->p[2], ip->p[3]) == -1) {
                        ERRMEM;
                        return -1;
                    }
                    break;
                } else if (ip->len == 16) {
                    if (asprintf(username, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                            ip->p[0], ip->p[1], ip->p[2], ip->p[3], ip->p[4], ip->p[5],
                            ip->p[6], ip->p[7], ip->p[8], ip->p[9], ip->p[10], ip->p[11],
                            ip->p[12], ip->p[13], ip->p[14], ip->p[15]) == -1) {
                        ERRMEM;
                        return -1;
                    }
                    break;
                } else {
                    WRN(NULL, "SAN IP address in an unknown format (length is %d).", ip->len);
                }
            }

            cur = cur->next;
        }

        if (!*username) {
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
nc_server_tls_certs_match_wrap(void *cert1, void *cert2)
{
    mbedtls_x509_crt *c1 = cert1;
    mbedtls_x509_crt *c2 = cert2;

    if (!c1 || !c2) {
        return 0;
    }

    /* compare raw DER encoded data */
    if (!c1->raw.p || !c2->raw.p || (c1->raw.len != c2->raw.len) ||
            memcmp(c1->raw.p, c2->raw.p, c1->raw.len)) {
        return 0;
    }

    return 1;
}

int
nc_server_tls_md5_wrap(void *cert, unsigned char *buf)
{
    int rc;
    mbedtls_x509_crt *c = cert;

    rc = mbedtls_md5(c->raw.p, c->raw.len, buf);
    if (rc) {
        ERR(NULL, "Calculating MD5 digest failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    return 0;
}

int
nc_server_tls_sha1_wrap(void *cert, unsigned char *buf)
{
    int rc;
    mbedtls_x509_crt *c = cert;

    rc = mbedtls_sha1(c->raw.p, c->raw.len, buf);
    if (rc) {
        ERR(NULL, "Calculating SHA-1 digest failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    return 0;
}

int
nc_server_tls_sha224_wrap(void *cert, unsigned char *buf)
{
    int rc;
    mbedtls_x509_crt *c = cert;

    rc = mbedtls_sha256(c->raw.p, c->raw.len, buf, 1);
    if (rc) {
        ERR(NULL, "Calculating SHA-224 digest failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    return 0;
}

int
nc_server_tls_sha256_wrap(void *cert, unsigned char *buf)
{
    int rc;
    mbedtls_x509_crt *c = cert;

    rc = mbedtls_sha256(c->raw.p, c->raw.len, buf, 0);
    if (rc) {
        ERR(NULL, "Calculating SHA-256 digest failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    return 0;
}

int
nc_server_tls_sha384_wrap(void *cert, unsigned char *buf)
{
    int rc;
    mbedtls_x509_crt *c = cert;

    rc = mbedtls_sha512(c->raw.p, c->raw.len, buf, 1);
    if (rc) {
        ERR(NULL, "Calculating SHA-384 digest failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    return 0;
}

int
nc_server_tls_sha512_wrap(void *cert, unsigned char *buf)
{
    int rc;
    mbedtls_x509_crt *c = cert;

    rc = mbedtls_sha512(c->raw.p, c->raw.len, buf, 0);
    if (rc) {
        ERR(NULL, "Calculating SHA-512 digest failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    return 0;
}

void
nc_server_tls_set_fd_wrap(void *tls_session, int UNUSED(sock), struct nc_tls_ctx *tls_ctx)
{
    mbedtls_ssl_set_bio(tls_session, tls_ctx->sock, mbedtls_net_send, mbedtls_net_recv, NULL);
}

int
nc_server_tls_handshake_step_wrap(void *tls_session)
{
    int rc = 0;

    rc = mbedtls_ssl_handshake(tls_session);
    if (!rc) {
        return 1;
    } else if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0;
    } else {
        return -1;
    }
}

int
nc_server_tls_fill_config_wrap(void *tls_cfg, void *srv_cert, void *srv_pkey, void *cert_store, void *crl_store, struct nc_tls_ctx *tls_ctx)
{
    int rc;

    rc = mbedtls_ssl_config_defaults(tls_cfg, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc) {
        ERR(NULL, "Setting default TLS config failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    mbedtls_ssl_conf_rng(tls_cfg, mbedtls_ctr_drbg_random, tls_ctx->ctr_drbg);
    mbedtls_ssl_conf_authmode(tls_cfg, MBEDTLS_SSL_VERIFY_REQUIRED);

    mbedtls_ssl_conf_own_cert(tls_cfg, srv_cert, srv_pkey);
    mbedtls_ssl_conf_ca_chain(tls_cfg, cert_store, crl_store);

    tls_ctx->cert = srv_cert;
    tls_ctx->pkey = srv_pkey;
    tls_ctx->cert_store = cert_store;
    tls_ctx->crl_store = crl_store;
    return 0;
}

int
nc_server_tls_setup_config_fill_ctx_wrap(void *tls_cfg, struct nc_tls_ctx *tls_ctx, void *srv_cert, void *srv_pkey, void *cert_store, void *crl_store, int sock)
{
    int rc;

    rc = mbedtls_ssl_config_defaults(tls_cfg, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc) {
        ERR(NULL, "Setting default TLS config failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    rc = nc_tls_rng_new(&tls_ctx->ctr_drbg, &tls_ctx->entropy);
    if (rc) {
        return 1;
    }

    mbedtls_ssl_conf_rng(tls_cfg, mbedtls_ctr_drbg_random, tls_ctx->ctr_drbg);
    mbedtls_ssl_conf_authmode(tls_cfg, MBEDTLS_SSL_VERIFY_REQUIRED);

    mbedtls_ssl_conf_own_cert(tls_cfg, srv_cert, srv_pkey);
    mbedtls_ssl_conf_ca_chain(tls_cfg, cert_store, crl_store);

    tls_ctx->cert = srv_cert;
    tls_ctx->pkey = srv_pkey;
    tls_ctx->cert_store = cert_store;
    tls_ctx->crl_store = crl_store;
    tls_ctx->sock = malloc(sizeof *tls_ctx->sock);
    NC_CHECK_ERRMEM_RET(!tls_ctx->sock, 1);
    *tls_ctx->sock = sock;
    return 0;
}

void
nc_tls_ctx_destroy_wrap(struct nc_tls_ctx *tls_ctx)
{
    if (tls_ctx->ctr_drbg && tls_ctx->entropy) {
        nc_tls_rng_destroy(tls_ctx->ctr_drbg, tls_ctx->entropy);
    }
    nc_tls_cert_destroy_wrap(tls_ctx->cert);
    nc_tls_privkey_destroy_wrap(tls_ctx->pkey);
    nc_tls_cert_store_destroy_wrap(tls_ctx->cert_store);
    nc_tls_crl_store_destroy_wrap(tls_ctx->crl_store);
    free(tls_ctx->sock);
}

static mbedtls_pk_context *
nc_tls_file_to_privkey(const char *privkey_path)
{
    int rc;
    mbedtls_pk_context *pkey;
    mbedtls_ctr_drbg_context *ctr_drbg;
    mbedtls_entropy_context *entropy;

    if (nc_tls_rng_new(&ctr_drbg, &entropy)) {
        return NULL;
    }

    pkey = nc_tls_privkey_new_wrap();
    if (!pkey) {
        nc_tls_rng_destroy(ctr_drbg, entropy);
        return NULL;
    }

    rc = mbedtls_pk_parse_keyfile(pkey, privkey_path, NULL, mbedtls_ctr_drbg_random, ctr_drbg);
    nc_tls_rng_destroy(ctr_drbg, entropy);
    if (rc) {
        ERR(NULL, "Parsing private key data failed (%s).", mbedtls_high_level_strerr(rc));
        nc_tls_privkey_destroy_wrap(pkey);
        return NULL;
    }
    return pkey;
}

static int
read_pem_file(const char *cert_path, char **out)
{
    int ret = 0;
    FILE *f;
    char *buf = NULL;
    size_t size, read;

    f = fopen(cert_path, "r");
    if (!f) {
        ERR(NULL, "Unable to open file \"%s\".", cert_path);
        ret = 1;
        goto cleanup;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = malloc(size + 1);
    NC_CHECK_ERRMEM_GOTO(!buf, ret = 1, cleanup);

    read = fread(buf, 1, size, f);
    if (size != read) {
        ERR(NULL, "Error reading from file \"%s\".", cert_path);
        ret = 1;
        goto cleanup;
    }

    buf[size] = '\0';
    *out = buf;

cleanup:
    if (f) {
        fclose(f);
    }
    return ret;
}

int
nc_client_tls_load_cert_key_wrap(const char *cert_path, const char *key_path, void **cert, void **pkey)
{
    int ret = 0;
    mbedtls_x509_crt *c;
    mbedtls_pk_context *pk;
    char *buf = NULL, *ptr;
    const char *cert_footer = "-----END CERTIFICATE-----\n";

    c = nc_tls_cert_new_wrap();
    if (!c) {
        return 1;
    }

    ret = mbedtls_x509_crt_parse_file(c, cert_path);
    if (ret) {
        ERR(NULL, "Parsing certificate from file \"%s\" failed (%s).", cert_path, mbedtls_high_level_strerr(ret));
        goto cleanup;
    }

    if (key_path) {
        pk = nc_tls_file_to_privkey(key_path);
        if (!pk) {
            ret = 1;
            goto cleanup;
        }
    } else {
        ret = read_pem_file(cert_path, &buf);
        if (ret) {
            goto cleanup;
        }

        ptr = strstr(buf, cert_footer);
        if (!ptr) {
            ERR(NULL, "Invalid certificate file.");
            ret = 1;
            goto cleanup;
        }

        ptr += strlen(cert_footer);
        if (*ptr == '\0') {
            ERR(NULL, "File \"%s\" doesn't contain a private key.");
            ret = 1;
            goto cleanup;
        }

        pk = nc_tls_pem_to_privkey_wrap(ptr);
        if (!pk) {
            ret = 1;
            goto cleanup;
        }
    }

    *cert = c;
    *pkey = pk;

cleanup:
    return ret;
}

int
nc_client_tls_load_trusted_certs_wrap(void *cert_store, const char *file_path, const char *dir_path)
{
    int rc;

    if (file_path && ((rc = mbedtls_x509_crt_parse_file(cert_store, file_path)) < 0)) {
        ERR(NULL, "Loading CA certificate from file \"%s\" failed (%s).", file_path, mbedtls_high_level_strerr(rc));
        return 1;
    }

    if (dir_path && ((rc = mbedtls_x509_crt_parse_path(cert_store, dir_path)) < 0)) {
        ERR(NULL, "Loading CA certificate from directory \"%s\" failed (%s).", dir_path, mbedtls_low_level_strerr(rc));
        return 1;
    }

    return 0;
}

int
nc_client_tls_load_crl_wrap(void *UNUSED(cert_store), void *crl_store, const char *file_path, const char *dir_path)
{
    int rc;
    DIR *dir;
    struct dirent *entry;
    struct stat st = {0};
    char *path;

    if (file_path && (rc = mbedtls_x509_crl_parse_file(crl_store, file_path))) {
        ERR(NULL, "Loading CRL from file \"%s\" failed (%s).", file_path, mbedtls_high_level_strerr(rc));
        return 1;
    }

    if (dir_path) {
        /* parse the CRLs in the directory one by one */
        dir = opendir(dir_path);
        if (!dir) {
            ERR(NULL, "Failed to open directory \"%s\" (%s).", dir_path, strerror(errno));
        }

        while ((entry = readdir(dir))) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
                /* skip current and parent directory */
                continue;
            }

            if (asprintf(&path, "%s/%s", dir_path, entry->d_name) == -1) {
                ERRMEM;
                closedir(dir);
                return 1;
            }

            if (stat(path, &st) == -1) {
                if (errno == ENOENT) {
                    /* broken symbolic link, ignore */
                    free(path);
                    continue;
                } else {
                    ERR(NULL, "Failed to get information about \"%s\" (%s).", path, strerror(errno));
                    free(path);
                    closedir(dir);
                    return 1;
                }
            }

            if (!S_ISREG(st.st_mode)) {
                /* not a regular file, ignore */
                free(path);
                continue;
            }

            rc = mbedtls_x509_crl_parse_file(crl_store, path);
            if (rc) {
                ERR(NULL, "Loading CRL from file \"%s\" failed (%s).", path, mbedtls_high_level_strerr(rc));
            }

            free(path);
        }
    }

    return 0;
}

int
nc_client_tls_set_hostname_wrap(void *tls_session, const char *hostname)
{
    int rc;

    rc = mbedtls_ssl_set_hostname(tls_session, hostname);
    if (rc) {
        ERR(NULL, "Setting hostname failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    return 0;
}

int
nc_tls_setup_config_wrap(void *tls_cfg, int side, struct nc_tls_ctx *tls_ctx)
{
    int rc;

    /* set default config data */
    if (side == NC_SERVER) {
        rc = mbedtls_ssl_config_defaults(tls_cfg, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    } else {
        rc = mbedtls_ssl_config_defaults(tls_cfg, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    }
    if (rc) {
        ERR(NULL, "Setting default TLS config failed (%s).", mbedtls_high_level_strerr(rc));
        return 1;
    }

    /* set config's rng */
    mbedtls_ssl_conf_rng(tls_cfg, mbedtls_ctr_drbg_random, tls_ctx->ctr_drbg);
    /* set config's authmode */
    mbedtls_ssl_conf_authmode(tls_cfg, MBEDTLS_SSL_VERIFY_REQUIRED);
    /* set config's cert and key */
    mbedtls_ssl_conf_own_cert(tls_cfg, tls_ctx->cert, tls_ctx->pkey);
    /* set config's CA and CRL cert store */
    mbedtls_ssl_conf_ca_chain(tls_cfg, tls_ctx->cert_store, tls_ctx->crl_store);
    return 0;
}

int
nc_tls_init_ctx_wrap(struct nc_tls_ctx *tls_ctx, int sock, void *cli_cert, void *cli_pkey, void *cert_store, void *crl_store)
{
    /* setup rng */
    if (nc_tls_rng_new(&tls_ctx->ctr_drbg, &tls_ctx->entropy)) {
        return 1;
    }

    /* fill the context */
    tls_ctx->sock = malloc(sizeof *tls_ctx->sock);
    NC_CHECK_ERRMEM_RET(!tls_ctx->sock, 1);
    *tls_ctx->sock = sock;
    tls_ctx->cert = cli_cert;
    tls_ctx->pkey = cli_pkey;
    tls_ctx->cert_store = cert_store;
    tls_ctx->crl_store = crl_store;
    return 0;
}

int
nc_client_tls_handshake_step_wrap(void *tls_session)
{
    int rc = 0;

    rc = mbedtls_ssl_handshake(tls_session);
    if (!rc) {
        return 1;
    } else if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0;
    } else {
        return rc;
    }
}

uint32_t
nc_tls_get_verify_result_wrap(void *tls_session)
{
    return mbedtls_ssl_get_verify_result(tls_session);
}

const char *
nc_tls_verify_error_string_wrap(uint32_t err_code)
{
    const char *err;

    return (err = mbedtls_low_level_strerr(err_code)) ? err : "";
}

void
nc_tls_print_error_string_wrap(int connect_ret, const char *peername, void *UNUSED(tls_session))
{
    ERR(NULL, "TLS connection to \"%s\" failed (%s).", peername, mbedtls_high_level_strerr(connect_ret));
}

void
nc_server_tls_print_accept_error_wrap(int UNUSED(accept_ret), void *UNUSED(tls_session))
{
    ERR(NULL, "TLS accept failed.");
}

void
nc_tls_session_new_cleanup_wrap(void *tls_cfg, void *cli_cert, void *cli_pkey, void *cert_store, void *crl_store)
{
    mbedtls_ssl_config_free(tls_cfg);
    free(tls_cfg);
    mbedtls_x509_crt_free(cli_cert);
    free(cli_cert);
    mbedtls_pk_free(cli_pkey);
    free(cli_pkey);
    mbedtls_x509_crt_free(cert_store);
    free(cert_store);
    mbedtls_x509_crl_free(crl_store);
    free(crl_store);
}

int
nc_der_to_pubkey_wrap(const unsigned char *der, long len)
{
    int ret;
    mbedtls_pk_context *pkey;

    pkey = malloc(sizeof *pkey);
    NC_CHECK_ERRMEM_RET(!pkey, -1);
    mbedtls_pk_init(pkey);

    ret = mbedtls_pk_parse_public_key(pkey, (const unsigned char *)der, len);
    nc_tls_privkey_destroy_wrap(pkey);
    if (!ret) {
        /* success */
        return 0;
    } else {
        /* fail */
        return 1;
    }
}

int
nc_base64_decode_wrap(const char *base64, char **bin)
{
    size_t size;
    int ret;

    ret = mbedtls_base64_decode(NULL, 0, &size, (const unsigned char *)base64, strlen(base64));
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return -1;
    }

    *bin = malloc(size);
    NC_CHECK_ERRMEM_RET(!*bin, -1);

    ret = mbedtls_base64_decode((unsigned char *)*bin, size, &size, (const unsigned char *)base64, strlen(base64));
    if (ret) {
        free(*bin);
        *bin = NULL;
        return -1;
    }

    return size;
}

int
nc_base64_encode_wrap(const unsigned char *bin, size_t len, char **base64)
{
    size_t size;
    int ret;

    ret = mbedtls_base64_encode(NULL, 0, &size, bin, len);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return -1;
    }

    *base64 = malloc(size);
    NC_CHECK_ERRMEM_RET(!*base64, -1);

    ret = mbedtls_base64_encode((unsigned char *)*base64, size, &size, bin, len);
    if (ret) {
        free(*base64);
        *base64 = NULL;
        return -1;
    }

    return 0;
}

int
nc_tls_read_wrap(struct nc_session *session, unsigned char *buf, size_t size)
{
    int rc;
    mbedtls_ssl_context *tls_session = session->ti.tls.session;

    rc = mbedtls_ssl_read(tls_session, buf, size);
    if (rc <= 0) {
        switch (rc) {
        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            rc = 0;
            break;
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            ERR(session, "Communication socket unexpectedly closed (MbedTLS).");
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_DROPPED;
            rc = -1;
            break;
        default:
            ERR(session, "TLS communication error occurred (%s).", mbedtls_high_level_strerr(rc));
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
    int rc = 0;
    mbedtls_ssl_context *tls_session = session->ti.tls.session;

    rc = mbedtls_ssl_write(tls_session, buf, size);
    if (rc < 0) {
        switch (rc) {
        case MBEDTLS_ERR_SSL_WANT_READ:
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            rc = 0;
            break;
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            ERR(session, "TLS connection was properly closed.");
            rc = -1;
            break;
        default:
            ERR(session, "TLS communication error occurred (%s).", mbedtls_high_level_strerr(rc));
            rc = -1;
            break;
        }
    }

    return rc;
}

int
nc_tls_have_pending_wrap(void *tls_session)
{
    return mbedtls_ssl_get_bytes_avail(tls_session);
}

int
nc_tls_get_fd_wrap(const struct nc_session *session)
{
    if (!session->ti.tls.ctx.sock) {
        return -1;
    } else {
        return *session->ti.tls.ctx.sock;
    }
}

void
nc_tls_close_notify_wrap(void *tls_session)
{
    int rc;

    while ((rc = mbedtls_ssl_close_notify(tls_session))) {
        if ((rc != MBEDTLS_ERR_SSL_WANT_READ) && (rc != MBEDTLS_ERR_SSL_WANT_WRITE)) {
            /* some error occurred */
            return;
        }
    }
}

void *
nc_tls_import_key_file_wrap(const char *key_path, FILE *UNUSED(file))
{
    return nc_tls_file_to_privkey(key_path);
}

void *
nc_tls_import_cert_file_wrap(const char *cert_path)
{
    int rc;
    mbedtls_x509_crt *c;

    c = nc_tls_cert_new_wrap();
    if (!c) {
        return NULL;
    }

    rc = mbedtls_x509_crt_parse_file(c, cert_path);
    if (rc) {
        ERR(NULL, "Parsing certificate from file \"%s\" failed (%s).", cert_path, mbedtls_high_level_strerr(rc));
        nc_tls_cert_destroy_wrap(c);
        return NULL;
    }

    return c;
}

char *
nc_tls_export_key_wrap(void *pkey)
{
    int rc;
    char *pem;
    size_t size = 128;
    void *tmp;

    pem = malloc(size);
    NC_CHECK_ERRMEM_RET(!pem, NULL);

    while ((rc = mbedtls_pk_write_key_pem(pkey, (unsigned char *)pem, size)) == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        size <<= 1;
        tmp = realloc(pem, size);
        if (!tmp) {
            ERRMEM;
            free(pem);
            return NULL;
        }
        pem = tmp;
    }
    if (rc < 0) {
        ERR(NULL, "Exporting private key to PEM format failed (%s).", mbedtls_high_level_strerr(rc));
        free(pem);
        return NULL;
    }

    return pem;
}

char *
nc_tls_export_cert_wrap(void *cert)
{
    char *b64 = NULL, *pem = NULL;

    if (nc_base64_encode_wrap(((mbedtls_x509_crt *)cert)->raw.p, ((mbedtls_x509_crt *)cert)->raw.len, &b64)) {
        goto cleanup;
    }

    if (asprintf(&pem, "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", b64) == -1) {
        ERRMEM;
        pem = NULL;
        goto cleanup;
    }

cleanup:
    free(b64);
    return pem;
}

char *
nc_tls_export_pubkey_wrap(void *pkey)
{
    int rc;
    char *pem;
    size_t size = 128;
    void *tmp;

    pem = malloc(size);
    NC_CHECK_ERRMEM_RET(!pem, NULL);

    while ((rc = mbedtls_pk_write_pubkey_pem(pkey, (unsigned char *)pem, size)) == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        size <<= 1;
        tmp = realloc(pem, size);
        if (!tmp) {
            ERRMEM;
            free(pem);
            return NULL;
        }
        pem = tmp;
    }
    if (rc < 0) {
        ERR(NULL, "Exporting public key to PEM format failed (%s).", mbedtls_high_level_strerr(rc));
        free(pem);
        return NULL;
    }

    return pem;
}

int
nc_tls_export_key_der_wrap(void *pkey, unsigned char **der, size_t *size)
{
    int rc;

    *size = mbedtls_pk_get_len(pkey);
    *der = malloc(*size);
    NC_CHECK_ERRMEM_RET(!*der, 1);

    rc = mbedtls_pk_write_key_der(pkey, *der, *size);
    if (rc < 0) {
        ERR(NULL, "Exporting private key to DER format failed (%s).", mbedtls_high_level_strerr(rc));
        free(*der);
        *der = NULL;
        return 1;
    }

    return 0;
}

int
nc_tls_privkey_is_rsa_wrap(void *pkey)
{
    return mbedtls_pk_get_type(pkey) == MBEDTLS_PK_RSA;
}

int
nc_tls_get_rsa_pubkey_params_wrap(void *pkey, void **e, void **n)
{
    int rc;
    mbedtls_mpi *exp = NULL, *mod = NULL;

    exp = malloc(sizeof *exp);
    mod = malloc(sizeof *mod);
    if (!exp || !mod) {
        ERRMEM;
        goto fail;
    }
    mbedtls_mpi_init(exp);
    mbedtls_mpi_init(mod);

    if ((rc = mbedtls_rsa_export(mbedtls_pk_rsa(*(mbedtls_pk_context *)pkey), mod, NULL, NULL, NULL, exp))) {
        ERR(NULL, "Failed to export RSA public key parameters (%s).", mbedtls_high_level_strerr(rc));
        goto fail;
    }

    *e = exp;
    *n = mod;
    return 0;

fail:
    mbedtls_mpi_free(exp);
    mbedtls_mpi_free(mod);
    free(exp);
    free(mod);
    return 1;
}

int
nc_tls_privkey_is_ec_wrap(void *pkey)
{
    return mbedtls_pk_get_type(pkey) == MBEDTLS_PK_ECKEY;
}

char *
nc_tls_get_ec_group_wrap(void *pkey)
{
    const mbedtls_ecp_curve_info *curve_info;
    mbedtls_ecp_group_id group_id;
    mbedtls_ecp_keypair *ec;

    ec = mbedtls_pk_ec(*(mbedtls_pk_context *)pkey);
    group_id = ec->private_grp.id;
    curve_info = mbedtls_ecp_curve_info_from_grp_id(group_id);
    return strdup(curve_info->name);
}

int
nc_tls_get_ec_pubkey_param_wrap(void *pkey, unsigned char **bin, int *bin_len)
{
    int rc = 0;
    unsigned char *bin_tmp;
    size_t bin_len_tmp = 32, out_len;
    mbedtls_ecp_keypair *ec;
    void *tmp;

    bin_tmp = malloc(bin_len_tmp);
    NC_CHECK_ERRMEM_RET(!bin_tmp, 1);

    ec = mbedtls_pk_ec(*(mbedtls_pk_context *)pkey);
    while ((rc = mbedtls_ecp_point_write_binary(&ec->private_grp, &ec->private_Q, MBEDTLS_ECP_PF_COMPRESSED, &out_len, bin_tmp, bin_len_tmp)) == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL) {
        bin_len_tmp <<= 1;
        tmp = realloc(bin_tmp, bin_len_tmp);
        if (!tmp) {
            ERRMEM;
            free(bin_tmp);
            return 1;
        }
        bin_tmp = tmp;
    }
    if (rc) {
        ERR(NULL, "Failed to write public key binary (%s).", mbedtls_high_level_strerr(rc));
        free(bin_tmp);
        return 1;
    }

    *bin = bin_tmp;
    *bin_len = out_len;
    return 0;
}

int
nc_tls_get_bn_num_bytes_wrap(void *bn)
{
    return mbedtls_mpi_size(bn);
}

void
nc_tls_bn_bn2bin_wrap(void *bn, unsigned char *bin)
{
    mbedtls_mpi_write_binary(bn, bin, mbedtls_mpi_size(bn));
}

int
nc_tls_get_pubkey_file_wrap(const char *pubkey_path, char **pubout)
{
    int rc = 0, ret = 0;
    mbedtls_pk_context *pk = NULL;

    pk = nc_tls_privkey_new_wrap();
    if (!pk) {
        return 1;
    }

    rc = mbedtls_pk_parse_public_keyfile(pk, pubkey_path);
    if (rc) {
        ERR(NULL, "Parsing public key from file \"%s\" failed (%s).", pubkey_path, mbedtls_high_level_strerr(rc));
        ret = 1;
        goto cleanup;
    }

    *pubout = nc_tls_export_key_wrap(pk);
    if (!*pubout) {
        ret = 1;
        goto cleanup;
    }

cleanup:
    nc_tls_privkey_destroy_wrap(pk);
    return ret;
}

void *
nc_tls_import_pubkey_file_wrap(const char *pubkey_path)
{
    int rc = 0;
    mbedtls_pk_context *pk = NULL;

    pk = nc_tls_privkey_new_wrap();
    if (!pk) {
        return NULL;
    }

    rc = mbedtls_pk_parse_public_keyfile(pk, pubkey_path);
    if (rc) {
        ERR(NULL, "Parsing public key from file \"%s\" failed (%s).", pubkey_path, mbedtls_high_level_strerr(rc));
        nc_tls_privkey_destroy_wrap(pk);
        return NULL;
    }

    return pk;
}
