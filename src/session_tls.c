/**
 * \file session_ssh.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 - SSH specific session transport functions
 *
 * This source is compiled only with libssh.
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
#include <pwd.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "libnetconf.h"

/* internal functions from session.c */
struct nc_session *connect_init(struct ly_ctx *ctx);
int connect_getsocket(const char* host, unsigned short port);
int handshake(struct nc_session *session);

static int
connect_tls_socket(struct nc_session *session, int sock)
{
    (void) session;
    (void) sock;

    /* TODO - libssl magic */

    return 0;
}

API struct nc_session *
nc_connect_tls(const char *host, unsigned short port, const char *username, struct ly_ctx *ctx)
{
    struct passwd *pw;
    struct nc_session *session = NULL;

    /* process parameters */
    if (!host || strisempty(host)) {
        host = "localhost";
    }

    if (!port) {
        port = NC_PORT_TLS;
    }

    if (!username) {
        pw = getpwuid(getuid());
        if (!pw) {
            ERR("Unknwon username for the TLS connection (%s).", strerror(errno));
            return (NULL);
        } else {
            username = pw->pw_name;
        }
    }

    /* prepare session structure */
    session = connect_init(ctx);
    if (!session) {
        return NULL;
    }

    /* transport specific data */
    session->username = lydict_insert(session->ctx, username, 0);
    session->host = lydict_insert(session->ctx, host, 0);
    session->port = port;

    if (connect_tls_socket(session, connect_getsocket(host, port))) {
        goto error;
    }

    /* NETCONF handshake */
    if (handshake(session)) {
        goto error;
    }

    session->status = NC_STATUS_RUNNING;
    return session;

error:
    nc_session_free(session);
    return NULL;
}

API struct nc_session *
nc_connect_libssl(SSL *tls, struct ly_ctx *ctx)
{
    (void) tls;
    (void) ctx;

    return NULL;
}

