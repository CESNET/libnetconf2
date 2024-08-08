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
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "session_client.h"
#include "session_client_ch.h"
#include "session_p.h"
#include "session_wrapper.h"

struct nc_client_context *nc_client_context_location(void);

#define client_opts nc_client_context_location()->opts
#define tls_opts nc_client_context_location()->tls_opts
#define tls_ch_opts nc_client_context_location()->tls_ch_opts

void
_nc_client_tls_destroy_opts(struct nc_client_tls_opts *opts)
{
    free(opts->cert_path);
    free(opts->key_path);
    free(opts->ca_file);
    free(opts->ca_dir);
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

API int
nc_client_tls_set_crl_paths(const char *UNUSED(crl_file), const char *UNUSED(crl_dir))
{
    ERR(NULL, "nc_client_tls_set_crl_paths() is deprecated, do not use it.");
    return -1;
}

API int
nc_client_tls_ch_set_crl_paths(const char *UNUSED(crl_file), const char *UNUSED(crl_dir))
{
    ERR(NULL, "nc_client_tls_ch_set_crl_paths() is deprecated, do not use it.");
    return -1;
}

API void
nc_client_tls_get_crl_paths(const char **UNUSED(crl_file), const char **UNUSED(crl_dir))
{
    ERR(NULL, "nc_client_tls_get_crl_paths() is deprecated, do not use it.");
    return;
}

API void
nc_client_tls_ch_get_crl_paths(const char **UNUSED(crl_file), const char **UNUSED(crl_dir))
{
    ERR(NULL, "nc_client_tls_ch_get_crl_paths() is deprecated, do not use it.");
    return;
}

API int
nc_client_tls_ch_add_bind_listen(const char *address, uint16_t port)
{
    return nc_client_ch_add_bind_listen(address, port, NULL, NC_TI_TLS);
}

API int
nc_client_tls_ch_add_bind_hostname_listen(const char *address, uint16_t port, const char *hostname)
{
    return nc_client_ch_add_bind_listen(address, port, hostname, NC_TI_TLS);
}

API int
nc_client_tls_ch_del_bind(const char *address, uint16_t port)
{
    return nc_client_ch_del_bind(address, port, NC_TI_TLS);
}

static int
nc_client_tls_connect_check(int connect_ret, void *tls_session, const char *peername)
{
    uint32_t verify;
    char *err;

    /* check certificate verification result */
    verify = nc_tls_get_verify_result_wrap(tls_session);
    if (!verify && (connect_ret == 1)) {
        VRB(NULL, "Server certificate verified (domain \"%s\").", peername);
    } else if (verify) {
        err = nc_tls_verify_error_string_wrap(verify);
        ERR(NULL, "Server certificate error (%s).", err);
        free(err);
    }

    /* check TLS connection result */
    if (connect_ret != 1) {
        nc_client_tls_print_connect_err_wrap(connect_ret, peername, tls_session);
    }

    return connect_ret;
}

static void *
nc_client_tls_session_new(int sock, const char *host, int timeout, struct nc_client_tls_opts *opts, void **out_tls_cfg, struct nc_tls_ctx *tls_ctx)
{
    int ret = 0, sock_tmp = sock;
    struct timespec ts_timeout;
    void *tls_session, *tls_cfg, *cli_cert, *cli_pkey, *cert_store, *crl_store;

    tls_session = tls_cfg = cli_cert = cli_pkey = cert_store = crl_store = NULL;

    /* prepare TLS context from which a session will be created */
    tls_cfg = nc_tls_config_new_wrap(NC_CLIENT);
    if (!tls_cfg) {
        goto fail;
    }

    /* opaque CA/CRL certificate store */
    cert_store = nc_tls_cert_store_new_wrap();
    if (!cert_store) {
        goto fail;
    }

    /* load client's key and certificate */
    if (nc_client_tls_load_cert_key_wrap(opts->cert_path, opts->key_path, &cli_cert, &cli_pkey)) {
        goto fail;
    }

    /* load trusted CA certificates */
    if (nc_client_tls_load_trusted_certs_wrap(cert_store, opts->ca_file, opts->ca_dir)) {
        goto fail;
    }

    /* load CRLs from set certificates' extensions */
    if (nc_session_tls_crl_from_cert_ext_fetch(cli_cert, cert_store, &crl_store)) {
        goto fail;
    }

    /* set client's verify mode flags */
    nc_client_tls_set_verify_wrap(tls_cfg);

    /* init TLS context and store data which may be needed later in it */
    if (nc_tls_init_ctx_wrap(sock, cli_cert, cli_pkey, cert_store, crl_store, tls_ctx)) {
        goto fail;
    }

    /* memory is managed by context now */
    cli_cert = cli_pkey = cert_store = crl_store = NULL;

    /* setup config from ctx */
    if (nc_tls_setup_config_from_ctx_wrap(tls_ctx, NC_CLIENT, tls_cfg)) {
        goto fail;
    }

    /* session from config */
    tls_session = nc_tls_session_new_wrap(tls_cfg);
    if (!tls_session) {
        goto fail;
    }

    /* set session fd */
    nc_server_tls_set_fd_wrap(tls_session, sock, tls_ctx);

    sock = -1;

    /* set session hostname to check against in the server cert */
    if (nc_client_tls_set_hostname_wrap(tls_session, host)) {
        goto fail;
    }

    /* handshake */
    if (timeout > -1) {
        nc_timeouttime_get(&ts_timeout, timeout);
    }
    while ((ret = nc_client_tls_handshake_step_wrap(tls_session, sock_tmp)) == 0) {
        usleep(NC_TIMEOUT_STEP);
        if ((timeout > -1) && (nc_timeouttime_cur_diff(&ts_timeout) < 1)) {
            ERR(NULL, "SSL connect timeout.");
            goto fail;
        }
    }

    /* check if handshake was ok */
    if (nc_client_tls_connect_check(ret, tls_session, host) != 1) {
        goto fail;
    }

    *out_tls_cfg = tls_cfg;
    return tls_session;

fail:
    if (sock > -1) {
        close(sock);
    }

    nc_tls_session_destroy_wrap(tls_session);
    nc_tls_cert_destroy_wrap(cli_cert);
    nc_tls_privkey_destroy_wrap(cli_pkey);
    nc_tls_cert_store_destroy_wrap(cert_store);
    nc_tls_crl_store_destroy_wrap(crl_store);
    nc_tls_config_destroy_wrap(tls_cfg);
    return NULL;
}

API struct nc_session *
nc_connect_tls(const char *host, unsigned short port, struct ly_ctx *ctx)
{
    struct nc_session *session = NULL;
    int sock;
    char *ip_host = NULL;
    void *tls_cfg = NULL;
    struct nc_tls_ctx tls_ctx = {0};

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

    /* prepare session structure */
    session = nc_new_session(NC_CLIENT, 0);
    NC_CHECK_ERRMEM_RET(!session, NULL);
    session->status = NC_STATUS_STARTING;

    /* create and assign socket */
    sock = nc_sock_connect(NULL, 0, host, port, -1, &client_opts.ka, NULL, &ip_host);
    if (sock == -1) {
        ERR(NULL, "Unable to connect to %s:%u (%s).", host, port, strerror(errno));
        goto fail;
    }

    /* fill the session */
    session->ti_type = NC_TI_TLS;
    if (!(session->ti.tls.session = nc_client_tls_session_new(sock, host, NC_TRANSPORT_TIMEOUT, &tls_opts, &tls_cfg, &tls_ctx))) {
        goto fail;
    }
    session->ti.tls.config = tls_cfg;

    /* memory belongs to session */
    memcpy(&session->ti.tls.ctx, &tls_ctx, sizeof tls_ctx);
    memset(&tls_ctx, 0, sizeof tls_ctx);

    if (nc_client_session_new_ctx(session, ctx) != EXIT_SUCCESS) {
        goto fail;
    }

    /* NETCONF handshake */
    if (nc_handshake_io(session) != NC_MSG_HELLO) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    if (nc_ctx_check_and_fill(session) == -1) {
        goto fail;
    }

    /* store information into session */
    session->host = ip_host;
    session->port = port;
    session->username = strdup("certificate-based");

    return session;

fail:
    free(ip_host);
    nc_session_free(session, NULL);
    nc_tls_ctx_destroy_wrap(&tls_ctx);
    return NULL;
}

API struct nc_session *
nc_connect_libssl(void *UNUSED(tls), struct ly_ctx *UNUSED(ctx))
{
    ERR(NULL, "nc_connect_libssl() is deprecated, do not use it.");
    return NULL;
}

struct nc_session *
nc_accept_callhome_tls_sock(int sock, const char *host, uint16_t port, struct ly_ctx *ctx, int timeout, const char *peername)
{
    struct nc_session *session = NULL;
    void *tls_cfg = NULL;
    struct nc_tls_ctx tls_ctx = {0};

    /* prepare session structure */
    session = nc_new_session(NC_CLIENT, 0);
    NC_CHECK_ERRMEM_RET(!session, NULL);
    session->status = NC_STATUS_STARTING;

    /* fill the session */
    session->ti_type = NC_TI_TLS;
    if (!(session->ti.tls.session = nc_client_tls_session_new(sock, peername, timeout, &tls_ch_opts, &tls_cfg, &tls_ctx))) {
        goto fail;
    }
    session->ti.tls.config = tls_cfg;

    /* memory belongs to session */
    memcpy(&session->ti.tls.ctx, &tls_ctx, sizeof tls_ctx);
    memset(&tls_ctx, 0, sizeof tls_ctx);

    if (nc_client_session_new_ctx(session, ctx) != EXIT_SUCCESS) {
        goto fail;
    }

    /* NETCONF handshake */
    if (nc_handshake_io(session) != NC_MSG_HELLO) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    if (nc_ctx_check_and_fill(session) == -1) {
        goto fail;
    }

    session->flags |= NC_SESSION_CALLHOME;

    /* store information into session */
    session->host = strdup(host);
    session->port = port;
    session->username = strdup("certificate-based");

    return session;

fail:
    nc_session_free(session, NULL);
    nc_tls_ctx_destroy_wrap(&tls_ctx);
    return NULL;
}
