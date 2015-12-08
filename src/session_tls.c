/**
 * \file session_tls.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 - TLS specific session transport functions
 *
 * This source is compiled only with libssl.
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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "libnetconf.h"
#include "session.h"
#include "session_p.h"

/* TLS certificate verification error messages */
static const char* verify_ret_msg[] = {
    "ok",
    "",
    "unable to get issuer certificate",
    "unable to get certificate CRL",
    "unable to decrypt certificate's signature",
    "unable to decrypt CRL's signature",
    "unable to decode issuer public key",
    "certificate signature failure",
    "CRL signature failure",
    "certificate is not yet valid",
    "certificate has expired",
    "CRL is not yet valid",
    "CRL has expired",
    "format error in certificate's notBefore field",
    "format error in certificate's notAfter field",
    "format error in CRL's lastUpdate field",
    "format error in CRL's nextUpdate field",
    "out of memory",
    "self signed certificate",
    "self signed certificate in certificate chain",
    "unable to get local issuer certificate",
    "unable to verify the first certificate",
    "certificate chain too long",
    "certificate revoked",
    "invalid CA certificate",
    "path length constraint exceeded",
    "unsupported certificate purpose",
    "certificate not trusted",
    "certificate rejected",
    "subject issuer mismatch",
    "authority and subject key identifier mismatch",
    "authority and issuer serial number mismatch",
    "key usage does not include certificate signing"
};

static struct nc_tls_auth_opts tls_opts;

static int
tlsauth_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    X509_STORE_CTX store_ctx;
    X509_OBJECT obj;
    X509_NAME *subject, *issuer;
    X509 *cert;
    X509_CRL *crl;
    X509_REVOKED *revoked;
    EVP_PKEY *pubkey;
    int i, n, rc;
    ASN1_TIME *next_update = NULL;

    if (!preverify_ok) {
        return 0;
    }

    cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    subject = X509_get_subject_name(cert);
    issuer = X509_get_issuer_name(cert);

    /* try to retrieve a CRL corresponding to the _subject_ of
     * the current certificate in order to verify it's integrity */
    memset((char *)&obj, 0, sizeof obj);
    X509_STORE_CTX_init(&store_ctx, tls_opts.tls_store, NULL, NULL);
    rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, subject, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl = obj.data.crl;
    if (rc > 0 && crl) {
        next_update = X509_CRL_get_nextUpdate(crl);

        /* verify the signature on this CRL */
        pubkey = X509_get_pubkey(cert);
        if (X509_CRL_verify(crl, pubkey) <= 0) {
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
            X509_OBJECT_free_contents(&obj);
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
            X509_OBJECT_free_contents(&obj);
            return 0; /* fail */
        }
        if (X509_cmp_current_time(next_update) < 0) {
            X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CRL_HAS_EXPIRED);
            X509_OBJECT_free_contents(&obj);
            return 0; /* fail */
        }
        X509_OBJECT_free_contents(&obj);
    }

    /* try to retrieve a CRL corresponding to the _issuer_ of
     * the current certificate in order to check for revocation */
    memset((char *)&obj, 0, sizeof obj);
    X509_STORE_CTX_init(&store_ctx, tls_opts.tls_store, NULL, NULL);
    rc = X509_STORE_get_by_subject(&store_ctx, X509_LU_CRL, issuer, &obj);
    X509_STORE_CTX_cleanup(&store_ctx);
    crl = obj.data.crl;
    if (rc > 0 && crl) {
        /* check if the current certificate is revoked by this CRL */
        n = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl));
        for (i = 0; i < n; i++) {
            revoked = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
            if (ASN1_INTEGER_cmp(revoked->serialNumber, X509_get_serialNumber(cert)) == 0) {
                ERR("Certificate revoked!");
                X509_STORE_CTX_set_error(x509_ctx, X509_V_ERR_CERT_REVOKED);
                X509_OBJECT_free_contents(&obj);
                return 0; /* fail */
            }
        }
        X509_OBJECT_free_contents(&obj);
    }

    return 1; /* success */
}

API int
nc_tls_client_init(const char *client_cert, const char *client_key, const char *ca_file, const char *ca_dir,
                   const char *crl_file, const char *crl_dir)
{
    const char *key_ = client_key;
    X509_LOOKUP *lookup;

    if (tls_opts.tls_ctx) {
        ERR("TLS context already initialized!");
        return EXIT_FAILURE;
    }

    /* init libssl */
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    SSL_library_init();

    if (!client_cert) {
        return EXIT_SUCCESS;
    }

    /* prepare global SSL context, allow only mandatory TLS 1.2  */
    if (!(tls_opts.tls_ctx = SSL_CTX_new(TLSv1_2_client_method()))) {
        ERR("Unable to create OpenSSL context (%s)", ERR_reason_error_string(ERR_get_error()));
        return EXIT_FAILURE;
    }

    if (crl_file || crl_dir) {
        /* set the revocation store with the correct paths for the callback */
        tls_opts.tls_store = X509_STORE_new();
        tls_opts.tls_store->cache = 0;

        if (crl_file) {
            if (!(lookup = X509_STORE_add_lookup(tls_opts.tls_store, X509_LOOKUP_file()))) {
                ERR("Failed to add lookup method to CRL checking.");
                return EXIT_FAILURE;
            }
            if (X509_LOOKUP_add_dir(lookup, crl_file, X509_FILETYPE_PEM) != 1) {
                ERR("Failed to add the revocation lookup file \"%s\".", crl_file);
                return EXIT_FAILURE;
            }
        }

        if (crl_dir) {
            if (!(lookup = X509_STORE_add_lookup(tls_opts.tls_store, X509_LOOKUP_hash_dir()))) {
                ERR("Failed to add lookup method to CRL checking.");
                return EXIT_FAILURE;
            }
            if (X509_LOOKUP_add_dir(lookup, crl_dir, X509_FILETYPE_PEM) != 1) {
                ERR("Failed to add the revocation lookup directory \"%s\".", crl_dir);
                return EXIT_FAILURE;
            }
        }

        SSL_CTX_set_verify(tls_opts.tls_ctx, SSL_VERIFY_PEER, tlsauth_verify_callback);
    } else {
        /* CRL checking will be skipped */
        SSL_CTX_set_verify(tls_opts.tls_ctx, SSL_VERIFY_PEER, NULL);
    }

    /* get peer certificate */
    if (SSL_CTX_use_certificate_file(tls_opts.tls_ctx, client_cert, SSL_FILETYPE_PEM) != 1) {
        ERR("Loading a peer certificate from \'%s\' failed (%s).", client_cert, ERR_reason_error_string(ERR_get_error()));
        return EXIT_FAILURE;
    }

    if (!key_) {
        /*
         * if the file with private key not specified, expect that the private
         * key is stored altogether with the certificate
         */
        key_ = client_cert;
    }
    if (SSL_CTX_use_PrivateKey_file(tls_opts.tls_ctx, key_, SSL_FILETYPE_PEM) != 1) {
        ERR("Loading the client certificate from \'%s\' failed (%s).", key_, ERR_reason_error_string(ERR_get_error()));
        return EXIT_FAILURE;
    }

    if (!SSL_CTX_load_verify_locations(tls_opts.tls_ctx, ca_file, ca_dir)) {
        ERR("Failed to load the locations of trusted CA certificates (%s).", ERR_reason_error_string(ERR_get_error()));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

API void
nc_tls_client_destroy()
{
    CRYPTO_THREADID crypto_tid;

    SSL_CTX_free(tls_opts.tls_ctx);

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
    CRYPTO_THREADID_current(&crypto_tid);
    ERR_remove_thread_state(&crypto_tid);
}

API struct nc_session *
nc_connect_tls(const char *host, unsigned short port, struct ly_ctx *ctx)
{
    struct nc_session *session = NULL;
    int sock, verify;

    /* was init called? */
    if (!tls_opts.tls_ctx) {
        ERR("TLS context was not initialized!");
        return NULL;
    }

    /* process parameters */
    if (!host || strisempty(host)) {
        host = "localhost";
    }

    if (!port) {
        port = NC_PORT_TLS;
    }

    /* prepare session structure */
    session = calloc(1, sizeof *session);
    if (!session) {
        ERRMEM;
        return NULL;
    }
    session->status = NC_STATUS_STARTING;
    session->side = NC_CLIENT;

    /* transport lock */
    session->ti_lock = malloc(sizeof *session->ti_lock);
    if (!session->ti_lock) {
        ERRMEM;
        goto fail;
    }
    pthread_mutex_init(session->ti_lock, NULL);

    /* fill the session */
    session->ti_type = NC_TI_OPENSSL;
    if (!(session->ti.tls = SSL_new(tls_opts.tls_ctx))) {
        ERR("Failed to create new TLS session structure (%s)", ERR_reason_error_string(ERR_get_error()));
        goto fail;
    }

    /* create and assign socket */
    sock = nc_connect_getsocket(host, port);
    if (sock == -1) {
        goto fail;
    }
    SSL_set_fd(session->ti.tls, sock);

    /* set the SSL_MODE_AUTO_RETRY flag to allow OpenSSL perform re-handshake automatically */
    SSL_set_mode(session->ti.tls, SSL_MODE_AUTO_RETRY);

    /* connect and perform the handshake */
    if (SSL_connect(session->ti.tls) != 1) {
        ERR("Connecting over TLS failed (%s).", ERR_reason_error_string(ERR_get_error()));
        goto fail;
    }

    /* check certificate verification result */
    verify = SSL_get_verify_result(session->ti.tls);
    switch (verify) {
    case X509_V_OK:
        VRB("Server certificate successfully verified.");
        break;
    default:
        WRN("Server certificate verification problem (%s).", verify_ret_msg[verify]);
    }

    /* assign context (dicionary needed for handshake) */
    if (!ctx) {
        ctx = ly_ctx_new(SCHEMAS_DIR);
    } else {
        session->flags |= NC_SESSION_SHAREDCTX;
    }
    session->ctx = ctx;

    /* NETCONF handshake */
    if (nc_handshake(session)) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    if (nc_ctx_check_and_fill(session)) {
        goto fail;
    }

    /* store information into session and the dictionary */
    session->host = lydict_insert(ctx, host, 0);
    session->port = port;
    session->username = lydict_insert(ctx, "certificate-based", 0);

    return session;

fail:
    nc_session_free(session);
    return NULL;
}

API struct nc_session *
nc_connect_libssl(SSL *tls, struct ly_ctx *ctx)
{
    struct nc_session *session;

    /* check TLS session status */
    if (!tls || !SSL_is_init_finished(tls)) {
        ERR("Supplied TLS session is not fully connected!");
        return NULL;
    }

    /* prepare session structure */
    session = calloc(1, sizeof *session);
    if (!session) {
        ERRMEM;
        return NULL;
    }
    session->status = NC_STATUS_STARTING;
    session->side = NC_CLIENT;

    /* transport lock */
    session->ti_lock = malloc(sizeof *session->ti_lock);
    if (!session->ti_lock) {
        ERRMEM;
        goto fail;
    }
    pthread_mutex_init(session->ti_lock, NULL);

    session->ti_type = NC_TI_OPENSSL;
    session->ti.tls = tls;

    /* assign context (dicionary needed for handshake) */
    if (!ctx) {
        ctx = ly_ctx_new(SCHEMAS_DIR);
    } else {
        session->flags |= NC_SESSION_SHAREDCTX;
    }
    session->ctx = ctx;

    /* NETCONF handshake */
    if (nc_handshake(session)) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    if (nc_ctx_check_and_fill(session)) {
        goto fail;
    }

    return session;

fail:
    nc_session_free(session);
    return NULL;
}

API struct nc_session *
nc_callhome_accept_tls(uint16_t port, int32_t timeout, struct ly_ctx *ctx)
{
    int sock, verify;
    char *server_host;
    SSL *tls;
    struct nc_session *session;

    if (!port) {
        port = NC_PORT_CH_TLS;
    }

    sock = nc_callhome_accept_connection(port, timeout, NULL, &server_host);
    if (sock == -1) {
        return NULL;
    }

    if (!(tls = SSL_new(tls_opts.tls_ctx))) {
        ERR("Failed to create new TLS session structure (%s).", ERR_reason_error_string(ERR_get_error()));
        close(sock);
        return NULL;
    }

    SSL_set_fd(tls, sock);

    /* set the SSL_MODE_AUTO_RETRY flag to allow OpenSSL perform re-handshake automatically */
    SSL_set_mode(tls, SSL_MODE_AUTO_RETRY);

    /* connect and perform the handshake */
    if (SSL_connect(tls) != 1) {
        ERR("Connecting over TLS failed (%s).", ERR_reason_error_string(ERR_get_error()));
        SSL_free(tls);
        return NULL;
    }

    /* check certificate verification result */
    verify = SSL_get_verify_result(tls);
    switch (verify) {
    case X509_V_OK:
        VRB("Server certificate successfully verified.");
        break;
    default:
        WRN("Server certificate verification problem (%s).", verify_ret_msg[verify]);
    }

    session = nc_connect_libssl(tls, ctx);
    if (session) {
        /* store information into session and the dictionary */
        session->host = lydict_insert_zc(session->ctx, server_host);
        session->port = port;
        session->username = lydict_insert(session->ctx, "certificate-based", 0);
    }

    return session;
}
