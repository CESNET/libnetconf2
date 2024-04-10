/**
 * @file session_client_tls.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 - TLS specific session client transport functions
 *
 * This source is compiled only with libssl.
 *
 * @copyright
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE /* pthread_rwlock_t, strdup */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/engine.h>

#include "config.h"
#include "log_p.h"
#include "session_client.h"
#include "session_client_ch.h"
#include "session_p.h"

struct nc_client_context *nc_client_context_location(void);

#define client_opts nc_client_context_location()->opts
#define tls_opts nc_client_context_location()->tls_opts
#define tls_ch_opts nc_client_context_location()->tls_ch_opts

static int tlsauth_ch;

static int
tlsauth_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    X509_STORE_CTX *store_ctx;
    X509_OBJECT *obj;
    X509_NAME *subject, *issuer;
    X509 *cert;
    X509_CRL *crl;
    X509_REVOKED *revoked;
    EVP_PKEY *pubkey;
    int i, n, rc;
    const ASN1_TIME *next_update = NULL;
    struct nc_client_tls_opts *opts;

    if (!preverify_ok) {
        return 0;
    }

    opts = (tlsauth_ch ? &tls_ch_opts : &tls_opts);

    if (!opts->crl_store) {
        /* nothing to check */
        return 1;
    }

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    subject = X509_get_subject_name(cert);
    issuer = X509_get_issuer_name(cert);

    /* try to retrieve a CRL corresponding to the _subject_ of
     * the current certificate in order to verify it's integrity */
    store_ctx = X509_STORE_CTX_new();
    obj = X509_OBJECT_new();
    X509_STORE_CTX_init(store_ctx, opts->crl_store, NULL, NULL);
    rc = X509_STORE_CTX_get_by_subject(store_ctx, X509_LU_CRL, subject, obj);
    X509_STORE_CTX_free(store_ctx);
    crl = X509_OBJECT_get0_X509_CRL(obj);
    if ((rc > 0) && crl) {
        next_update = X509_CRL_get0_nextUpdate(crl);

        /* verify the signature on this CRL */
        pubkey = X509_get_pubkey(cert);
        if (X509_CRL_verify(crl, pubkey) <= 0) {
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
            X509_OBJECT_free(obj);
            if (pubkey) {
                EVP_PKEY_free(pubkey);
            }
            return 0; /* fail */
        }
        if (pubkey) {
            EVP_PKEY_free(pubkey);
        }

        /* check date of CRL to make sure it's not expired */
        if (!next_update) {
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
            X509_OBJECT_free(obj);
            return 0; /* fail */
        }
        if (X509_cmp_current_time(next_update) < 0) {
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_HAS_EXPIRED);
            X509_OBJECT_free(obj);
            return 0; /* fail */
        }
        X509_OBJECT_free(obj);
    }

    /* try to retrieve a CRL corresponding to the _issuer_ of
     * the current certificate in order to check for revocation */
    store_ctx = X509_STORE_CTX_new();
    obj = X509_OBJECT_new();
    X509_STORE_CTX_init(store_ctx, opts->crl_store, NULL, NULL);
    rc = X509_STORE_CTX_get_by_subject(store_ctx, X509_LU_CRL, issuer, obj);
    X509_STORE_CTX_free(store_ctx);
    crl = X509_OBJECT_get0_X509_CRL(obj);
    if ((rc > 0) && crl) {
        /* check if the current certificate is revoked by this CRL */
        n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
        for (i = 0; i < n; i++) {
            revoked = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
            if (ASN1_INTEGER_cmp(X509_REVOKED_get0_serialNumber(revoked), X509_get_serialNumber(cert)) == 0) {
                ERR(NULL, "Certificate revoked!");
                X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REVOKED);
                X509_OBJECT_free(obj);
                return 0; /* fail */
            }
        }
        X509_OBJECT_free(obj);
    }

    return 1; /* success */
}

void
_nc_client_tls_destroy_opts(struct nc_client_tls_opts *opts)
{
    free(opts->cert_path);
    free(opts->key_path);
    free(opts->ca_file);
    free(opts->ca_dir);
    SSL_CTX_free(opts->tls_ctx);

    free(opts->crl_file);
    free(opts->crl_dir);
    X509_STORE_free(opts->crl_store);

    memset(opts, 0, sizeof *opts);
}

void
nc_client_tls_destroy_opts(void)
{
    _nc_client_tls_destroy_opts(&tls_opts);
    _nc_client_tls_destroy_opts(&tls_ch_opts);
}

static int
_nc_client_tls_set_cert_key_paths(const char *client_cert, const char *client_key, struct nc_client_tls_opts *opts)
{
    NC_CHECK_ARG_RET(NULL, client_cert, -1);

    free(opts->cert_path);
    free(opts->key_path);

    opts->cert_path = strdup(client_cert);
    NC_CHECK_ERRMEM_RET(!opts->cert_path, -1);

    if (client_key) {
        opts->key_path = strdup(client_key);
        NC_CHECK_ERRMEM_RET(!opts->key_path, -1);
    } else {
        opts->key_path = NULL;
    }

    opts->tls_ctx_change = 1;

    return 0;
}

API int
nc_client_tls_set_cert_key_paths(const char *client_cert, const char *client_key)
{
    return _nc_client_tls_set_cert_key_paths(client_cert, client_key, &tls_opts);
}

API int
nc_client_tls_ch_set_cert_key_paths(const char *client_cert, const char *client_key)
{
    return _nc_client_tls_set_cert_key_paths(client_cert, client_key, &tls_ch_opts);
}

static void
_nc_client_tls_get_cert_key_paths(const char **client_cert, const char **client_key, struct nc_client_tls_opts *opts)
{
    if (!client_cert && !client_key) {
        ERRARG(NULL, "client_cert and client_key");
        return;
    }

    if (client_cert) {
        *client_cert = opts->cert_path;
    }
    if (client_key) {
        *client_key = opts->key_path;
    }
}

API void
nc_client_tls_get_cert_key_paths(const char **client_cert, const char **client_key)
{
    _nc_client_tls_get_cert_key_paths(client_cert, client_key, &tls_opts);
}

API void
nc_client_tls_ch_get_cert_key_paths(const char **client_cert, const char **client_key)
{
    _nc_client_tls_get_cert_key_paths(client_cert, client_key, &tls_ch_opts);
}

static int
_nc_client_tls_set_trusted_ca_paths(const char *ca_file, const char *ca_dir, struct nc_client_tls_opts *opts)
{
    if (!ca_file && !ca_dir) {
        ERRARG(NULL, "ca_file and ca_dir");
        return -1;
    }

    free(opts->ca_file);
    free(opts->ca_dir);

    if (ca_file) {
        opts->ca_file = strdup(ca_file);
        NC_CHECK_ERRMEM_RET(!opts->ca_file, -1);
    } else {
        opts->ca_file = NULL;
    }

    if (ca_dir) {
        opts->ca_dir = strdup(ca_dir);
        NC_CHECK_ERRMEM_RET(!opts->ca_dir, -1);
    } else {
        opts->ca_dir = NULL;
    }

    opts->tls_ctx_change = 1;

    return 0;
}

API int
nc_client_tls_set_trusted_ca_paths(const char *ca_file, const char *ca_dir)
{
    return _nc_client_tls_set_trusted_ca_paths(ca_file, ca_dir, &tls_opts);
}

API int
nc_client_tls_ch_set_trusted_ca_paths(const char *ca_file, const char *ca_dir)
{
    return _nc_client_tls_set_trusted_ca_paths(ca_file, ca_dir, &tls_ch_opts);
}

static void
_nc_client_tls_get_trusted_ca_paths(const char **ca_file, const char **ca_dir, struct nc_client_tls_opts *opts)
{
    if (!ca_file && !ca_dir) {
        ERRARG(NULL, "ca_file and ca_dir");
        return;
    }

    if (ca_file) {
        *ca_file = opts->ca_file;
    }
    if (ca_dir) {
        *ca_dir = opts->ca_dir;
    }
}

API void
nc_client_tls_get_trusted_ca_paths(const char **ca_file, const char **ca_dir)
{
    _nc_client_tls_get_trusted_ca_paths(ca_file, ca_dir, &tls_opts);
}

API void
nc_client_tls_ch_get_trusted_ca_paths(const char **ca_file, const char **ca_dir)
{
    _nc_client_tls_get_trusted_ca_paths(ca_file, ca_dir, &tls_ch_opts);
}

static int
_nc_client_tls_set_crl_paths(const char *crl_file, const char *crl_dir, struct nc_client_tls_opts *opts)
{
    if (!crl_file && !crl_dir) {
        ERRARG(NULL, "crl_file and crl_dir");
        return -1;
    }

    free(opts->crl_file);
    free(opts->crl_dir);

    if (crl_file) {
        opts->crl_file = strdup(crl_file);
        NC_CHECK_ERRMEM_RET(!opts->crl_file, -1);
    } else {
        opts->crl_file = NULL;
    }

    if (crl_dir) {
        opts->crl_dir = strdup(crl_dir);
        NC_CHECK_ERRMEM_RET(!opts->crl_dir, -1);
    } else {
        opts->crl_dir = NULL;
    }

    opts->crl_store_change = 1;

    return 0;
}

API int
nc_client_tls_set_crl_paths(const char *crl_file, const char *crl_dir)
{
    return _nc_client_tls_set_crl_paths(crl_file, crl_dir, &tls_opts);
}

API int
nc_client_tls_ch_set_crl_paths(const char *crl_file, const char *crl_dir)
{
    return _nc_client_tls_set_crl_paths(crl_file, crl_dir, &tls_ch_opts);
}

static void
_nc_client_tls_get_crl_paths(const char **crl_file, const char **crl_dir, struct nc_client_tls_opts *opts)
{
    if (!crl_file && !crl_dir) {
        ERRARG(NULL, "crl_file and crl_dir");
        return;
    }

    if (crl_file) {
        *crl_file = opts->crl_file;
    }
    if (crl_dir) {
        *crl_dir = opts->crl_dir;
    }
}

API void
nc_client_tls_get_crl_paths(const char **crl_file, const char **crl_dir)
{
    _nc_client_tls_get_crl_paths(crl_file, crl_dir, &tls_opts);
}

API void
nc_client_tls_ch_get_crl_paths(const char **crl_file, const char **crl_dir)
{
    _nc_client_tls_get_crl_paths(crl_file, crl_dir, &tls_ch_opts);
}

API int
nc_client_tls_ch_add_bind_listen(const char *address, uint16_t port)
{
    return nc_client_ch_add_bind_listen(address, port, NULL, NC_TI_OPENSSL);
}

API int
nc_client_tls_ch_add_bind_hostname_listen(const char *address, uint16_t port, const char *hostname)
{
    return nc_client_ch_add_bind_listen(address, port, hostname, NC_TI_OPENSSL);
}

API int
nc_client_tls_ch_del_bind(const char *address, uint16_t port)
{
    return nc_client_ch_del_bind(address, port, NC_TI_OPENSSL);
}

static int
nc_client_tls_update_opts(struct nc_client_tls_opts *opts, const char *peername)
{
    int rc = 0;
    char *key;
    X509_LOOKUP *lookup;
    X509_VERIFY_PARAM *vpm = NULL;
    EVP_PKEY *pkey = NULL;
    ENGINE *pkcs11 = NULL;
    const char* pin = getenv("DEFAULT_USER_PIN");

    if (!opts->tls_ctx || opts->tls_ctx_change) {
        SSL_CTX_free(opts->tls_ctx);
        /* prepare global SSL context, highest available method is negotiated autmatically  */
        if (!(opts->tls_ctx = SSL_CTX_new(TLS_client_method()))) {
            ERR(NULL, "Unable to create OpenSSL context (%s).", ERR_reason_error_string(ERR_get_error()));
            rc = -1;
            goto cleanup;
        }
        SSL_CTX_set_verify(opts->tls_ctx, SSL_VERIFY_PEER, tlsauth_verify_callback);

        /* get peer certificate */
        if (SSL_CTX_use_certificate_file(opts->tls_ctx, opts->cert_path, SSL_FILETYPE_PEM) != 1) {
            ERR(NULL, "Loading the client certificate from \'%s\' failed (%s).", opts->cert_path,
                    ERR_reason_error_string(ERR_get_error()));
            rc = -1;
            goto cleanup;
        }

        /* if the file with private key not specified, expect that the private key is stored with the certificate */
        if (!opts->key_path) {
            key = opts->cert_path;
        } else {
            key = opts->key_path;
        }

        ENGINE_load_dynamic();
        pkcs11 = ENGINE_by_id("pkcs11");
        if (!pkcs11)
        {
            if (SSL_CTX_use_PrivateKey_file(opts->tls_ctx, key, SSL_FILETYPE_PEM) != 1) {
                ERR(NULL, "Loading the client private key from \'%s\' failed (%s).", key,
                        ERR_reason_error_string(ERR_get_error()));
                rc = -1;
                goto cleanup;
            }
        } else {
            if (!pin) {
                ERR(NULL, "DEFAULT_USER_PIN is not set. Loading private key using pkcs11 engine failed.");
                rc -1;
                goto cleanup;
            }

            if (!ENGINE_init(pkcs11))
            {
                ERR(NULL, "Initializing the pkcs11 engine failed (%s).", ERR_reason_error_string(ERR_get_error()));
                rc = -1;
                goto cleanup;
            }

            if (!ENGINE_ctrl_cmd_string(pkcs11, "PIN", pin, 0))
            {
                ERR(NULL, "Setting pin failed (%s).", ERR_reason_error_string(ERR_get_error()));
                rc = -1;
                goto cleanup;
            }

            /* load server key using pkcs11 engine*/
            pkey = ENGINE_load_private_key(pkcs11, key, NULL, NULL);
            if (!pkey)
            {
                ERR(NULL, "Reading the private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
                rc = -1;
                goto cleanup;
            }

            /* set server key */
            if ((SSL_CTX_use_PrivateKey(opts->tls_ctx, pkey) != 1))
            {
                ERR(NULL, "Loading the client private key failed (%s).", ERR_reason_error_string(ERR_get_error()));
                rc = -1;
                goto cleanup;
            }
        }

        if (!SSL_CTX_load_verify_locations(opts->tls_ctx, opts->ca_file, opts->ca_dir)) {
            ERR(NULL, "Failed to load the locations of trusted CA certificates (%s).",
                    ERR_reason_error_string(ERR_get_error()));
            rc = -1;
            goto cleanup;
        }

        if (peername) {
            /* server identity (hostname) verification */
            vpm = X509_VERIFY_PARAM_new();
            if (!X509_VERIFY_PARAM_set1_host(vpm, peername, 0)) {
                ERR(NULL, "Failed to set expected server hostname (%s).", ERR_reason_error_string(ERR_get_error()));
                rc = -1;
                goto cleanup;
            }
            if (!SSL_CTX_set1_param(opts->tls_ctx, vpm)) {
                ERR(NULL, "Failed to set verify params (%s).", ERR_reason_error_string(ERR_get_error()));
                rc = -1;
                goto cleanup;
            }
        }
    }

    if (opts->crl_store_change || (!opts->crl_store && (opts->crl_file || opts->crl_dir))) {
        /* set the revocation store with the correct paths for the callback */
        X509_STORE_free(opts->crl_store);

        opts->crl_store = X509_STORE_new();
        if (!opts->crl_store) {
            ERR(NULL, "Unable to create a certificate store (%s).", ERR_reason_error_string(ERR_get_error()));
            rc = -1;
            goto cleanup;
        }

        if (opts->crl_file) {
            if (!(lookup = X509_STORE_add_lookup(opts->crl_store, X509_LOOKUP_file()))) {
                ERR(NULL, "Failed to add lookup method to CRL checking.");
                rc = -1;
                goto cleanup;
            }
            if (X509_LOOKUP_add_dir(lookup, opts->crl_file, X509_FILETYPE_PEM) != 1) {
                ERR(NULL, "Failed to add the revocation lookup file \"%s\".", opts->crl_file);
                rc = -1;
                goto cleanup;
            }
        }

        if (opts->crl_dir) {
            if (!(lookup = X509_STORE_add_lookup(opts->crl_store, X509_LOOKUP_hash_dir()))) {
                ERR(NULL, "Failed to add lookup method to CRL checking.");
                rc = -1;
                goto cleanup;
            }
            if (X509_LOOKUP_add_dir(lookup, opts->crl_dir, X509_FILETYPE_PEM) != 1) {
                ERR(NULL, "Failed to add the revocation lookup directory \"%s\".", opts->crl_dir);
                rc = -1;
                goto cleanup;
            }
        }
    }

cleanup:
    if (pkcs11) {
        ENGINE_free(pkcs11);
    }
    if (pkey){
        EVP_PKEY_free(pkey);
    }
    X509_VERIFY_PARAM_free(vpm);
    return rc;
}

static int
nc_client_tls_connect_check(int connect_ret, SSL *tls, const char *peername)
{
    int verify;

    /* check certificate verification result */
    verify = SSL_get_verify_result(tls);
    switch (verify) {
    case X509_V_OK:
        if (connect_ret == 1) {
            VRB(NULL, "Server certificate verified (domain \"%s\").", peername);
        }
        break;
    default:
        ERR(NULL, "Server certificate error (%s).", X509_verify_cert_error_string(verify));
    }

    /* check TLS connection result */
    if (connect_ret != 1) {
        switch (SSL_get_error(tls, connect_ret)) {
        case SSL_ERROR_SYSCALL:
            ERR(NULL, "SSL connect to \"%s\" failed (%s).", peername, errno ? strerror(errno) : "unexpected EOF");
            break;
        case SSL_ERROR_SSL:
            ERR(NULL, "SSL connect to \"%s\" failed (%s).", peername, ERR_reason_error_string(ERR_get_error()));
            break;
        default:
            ERR(NULL, "SSL connect to \"%s\" failed.", peername);
            break;
        }
    }

    return connect_ret;
}

API struct nc_session *
nc_connect_tls(const char *host, unsigned short port, struct ly_ctx *ctx)
{
    struct nc_session *session = NULL;
    int sock, ret;
    struct timespec ts_timeout;
    char *ip_host = NULL;

    if (!tls_opts.cert_path) {
        ERR(NULL, "Client certificate not set.");
        return NULL;
    } else if (!tls_opts.ca_file && !tls_opts.ca_dir) {
        ERR(NULL, "Certificate authority certificates not set.");
        return NULL;
    }

    /* process parameters */
    if (!host || (host[0] == '\0')) {
        host = "localhost";
    }

    if (!port) {
        port = NC_PORT_TLS;
    }

    /* create/update TLS structures */
    if (nc_client_tls_update_opts(&tls_opts, host)) {
        return NULL;
    }

    /* prepare session structure */
    session = nc_new_session(NC_CLIENT, 0);
    NC_CHECK_ERRMEM_RET(!session, NULL);
    session->status = NC_STATUS_STARTING;

    /* fill the session */
    session->ti_type = NC_TI_OPENSSL;
    if (!(session->ti.tls = SSL_new(tls_opts.tls_ctx))) {
        ERR(NULL, "Failed to create a new TLS session structure (%s).", ERR_reason_error_string(ERR_get_error()));
        goto fail;
    }

    /* create and assign socket */
    sock = nc_sock_connect(host, port, -1, &client_opts.ka, NULL, &ip_host);
    if (sock == -1) {
        ERR(NULL, "Unable to connect to %s:%u (%s).", host, port, strerror(errno));
        goto fail;
    }
    SSL_set_fd(session->ti.tls, sock);

    /* set the SSL_MODE_AUTO_RETRY flag to allow OpenSSL perform re-handshake automatically */
    SSL_set_mode(session->ti.tls, SSL_MODE_AUTO_RETRY);

    /* connect and perform the handshake */
    nc_timeouttime_get(&ts_timeout, NC_TRANSPORT_TIMEOUT);
    tlsauth_ch = 0;
    while (((ret = SSL_connect(session->ti.tls)) != 1) && (SSL_get_error(session->ti.tls, ret) == SSL_ERROR_WANT_READ)) {
        usleep(NC_TIMEOUT_STEP);
        if (nc_timeouttime_cur_diff(&ts_timeout) < 1) {
            ERR(NULL, "SSL connect timeout.");
            goto fail;
        }
    }

    /* check for errors */
    if (nc_client_tls_connect_check(ret, session->ti.tls, host) != 1) {
        goto fail;
    }

    if (nc_client_session_new_ctx(session, ctx) != EXIT_SUCCESS) {
        goto fail;
    }
    ctx = session->ctx;

    /* NETCONF handshake */
    if (nc_handshake_io(session) != NC_MSG_HELLO) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    if (nc_ctx_check_and_fill(session) == -1) {
        goto fail;
    }

    /* store information into session and the dictionary */
    session->host = ip_host;
    session->port = port;
    session->username = strdup("certificate-based");

    return session;

fail:
    free(ip_host);
    nc_session_free(session, NULL);
    return NULL;
}

API struct nc_session *
nc_connect_libssl(SSL *tls, struct ly_ctx *ctx)
{
    struct nc_session *session;

    NC_CHECK_ARG_RET(NULL, tls, NULL);

    if (!SSL_is_init_finished(tls)) {
        ERR(NULL, "Supplied TLS session is not fully connected!");
        return NULL;
    }

    /* prepare session structure */
    session = nc_new_session(NC_CLIENT, 0);
    NC_CHECK_ERRMEM_RET(!session, NULL);
    session->status = NC_STATUS_STARTING;
    session->ti_type = NC_TI_OPENSSL;
    session->ti.tls = tls;

    if (nc_client_session_new_ctx(session, ctx) != EXIT_SUCCESS) {
        goto fail;
    }
    ctx = session->ctx;

    /* NETCONF handshake */
    if (nc_handshake_io(session) != NC_MSG_HELLO) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    if (nc_ctx_check_and_fill(session) == -1) {
        goto fail;
    }

    return session;

fail:
    session->ti_type = NC_TI_NONE;
    session->ti.tls = NULL;
    nc_session_free(session, NULL);
    return NULL;
}

struct nc_session *
nc_accept_callhome_tls_sock(int sock, const char *host, uint16_t port, struct ly_ctx *ctx, int timeout, const char *peername)
{
    int ret;
    SSL *tls = NULL;
    struct nc_session *session = NULL;
    struct timespec ts_timeout;

    /* create/update TLS structures with explicit expected peername, if any set, the host is just the IP */
    if (nc_client_tls_update_opts(&tls_ch_opts, peername)) {
        goto cleanup;
    }

    if (!(tls = SSL_new(tls_ch_opts.tls_ctx))) {
        ERR(NULL, "Failed to create new TLS session structure (%s).", ERR_reason_error_string(ERR_get_error()));
        goto cleanup;
    }

    SSL_set_fd(tls, sock);

    /* set the SSL_MODE_AUTO_RETRY flag to allow OpenSSL perform re-handshake automatically */
    SSL_set_mode(tls, SSL_MODE_AUTO_RETRY);

    /* connect and perform the handshake */
    if (timeout > -1) {
        nc_timeouttime_get(&ts_timeout, timeout);
    }
    tlsauth_ch = 1;
    while (((ret = SSL_connect(tls)) == -1) && (SSL_get_error(tls, ret) == SSL_ERROR_WANT_READ)) {
        usleep(NC_TIMEOUT_STEP);
        if ((timeout > -1) && (nc_timeouttime_cur_diff(&ts_timeout) < 1)) {
            ERR(NULL, "SSL connect timeout.");
            goto cleanup;
        }
    }

    /* check for errors */
    if (nc_client_tls_connect_check(ret, tls, peername ? peername : host) != 1) {
        goto cleanup;
    }

    /* connect */
    session = nc_connect_libssl(tls, ctx);
    if (!session) {
        goto cleanup;
    }

    session->flags |= NC_SESSION_CALLHOME;

    /* store information into session and the dictionary */
    session->host = strdup(host);
    session->port = port;
    session->username = strdup("certificate-based");

cleanup:
    if (!session) {
        SSL_free(tls);
        close(sock);
    }
    return session;
}
