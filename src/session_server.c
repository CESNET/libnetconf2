/**
 * \file session_server.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 server session manipulation functions
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

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "log_p.h"
#include "session_p.h"
#include "session_server.h"

struct nc_server_opts server_opts;

int
nc_sock_listen(const char *address, uint32_t port)
{
    const int optVal = 1;
    const socklen_t optLen = sizeof(optVal);
    int is_ipv4, sock;
    struct sockaddr_storage saddr;

    struct sockaddr_in *saddr4;
    struct sockaddr_in6 *saddr6;


    if (!strchr(address, ':')) {
        is_ipv4 = 1;
    } else {
        is_ipv4 = 0;
    }

    sock = socket((is_ipv4 ? AF_INET : AF_INET6), SOCK_STREAM, 0);
    if (sock == -1) {
        ERR("%s: could not create socket (%s)", __func__, strerror(errno));
        goto fail;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&optVal, optLen)) {
        ERR("%s: could not set socket SO_REUSEADDR option (%s)", __func__, strerror(errno));
        goto fail;
    }

    bzero(&saddr, sizeof(struct sockaddr_storage));
    if (is_ipv4) {
        saddr4 = (struct sockaddr_in *)&saddr;

        saddr4->sin_family = AF_INET;
        saddr4->sin_port = htons(port);

        if (inet_pton(AF_INET, address, &saddr4->sin_addr) != 1) {
            ERR("%s: failed to convert IPv4 address \"%s\"", __func__, address);
            goto fail;
        }

        if (bind(sock, (struct sockaddr *)saddr4, sizeof(struct sockaddr_in)) == -1) {
            ERR("%s: could not bind \"%s\" port %d (%s)", __func__, address, port, strerror(errno));
            goto fail;
        }

    } else {
        saddr6 = (struct sockaddr_in6 *)&saddr;

        saddr6->sin6_family = AF_INET6;
        saddr6->sin6_port = htons(port);

        if (inet_pton(AF_INET6, address, &saddr6->sin6_addr) != 1) {
            ERR("%s: failed to convert IPv6 address \"%s\"", __func__, address);
            goto fail;
        }

        if (bind(sock, (struct sockaddr *)saddr6, sizeof(struct sockaddr_in6)) == -1) {
            ERR("%s: could not bind \"%s\" port %d (%s)", __func__, address, port, strerror(errno));
            goto fail;
        }
    }

    if (listen(sock, NC_REVERSE_QUEUE) == -1) {
        ERR("%s: unable to start listening on \"%s\" port %d (%s)", __func__, address, port, strerror(errno));
        goto fail;
    }

    return sock;

fail:
    if (sock > -1) {
        close(sock);
    }

    return -1;
}

int
nc_sock_accept(struct nc_bind *binds, uint16_t bind_count, int timeout, NC_TRANSPORT_IMPL *ti, char **host, uint16_t *port)
{
    uint16_t i;
    struct pollfd *pfd;
    struct sockaddr_storage saddr;
    socklen_t saddr_len = sizeof(saddr);
    int ret, sock = -1;

    pfd = malloc(bind_count * sizeof *pfd);
    for (i = 0; i < bind_count; ++i) {
        pfd[i].fd = binds[i].sock;
        pfd[i].events = POLLIN;
        pfd[i].revents = 0;
    }

    /* poll for a new connection */
    errno = 0;
    ret = poll(pfd, bind_count, timeout);
    if (!ret) {
        /* we timeouted */
        free(pfd);
        return 0;
    } else if (ret == -1) {
        ERR("%s: poll failed (%s)", __func__, strerror(errno));
        free(pfd);
        return -1;
    }

    for (i = 0; i < bind_count; ++i) {
        if (pfd[i].revents & POLLIN) {
            sock = pfd[i].fd;
            break;
        }
    }
    free(pfd);

    if (sock == -1) {
        ERR("%s: fatal error (%s:%d)", __func__, __FILE__, __LINE__);
        return -1;
    }

    ret = accept(sock, (struct sockaddr *)&saddr, &saddr_len);
    if (ret == -1) {
        ERR("%s: accept failed (%s)", __func__, strerror(errno));
        return -1;
    }

    if (ti) {
        *ti = binds[i].ti;
    }

    /* host was requested */
    if (host) {
        if (saddr.ss_family == AF_INET) {
            *host = malloc(15);
            if (!inet_ntop(AF_INET, &((struct sockaddr_in *)&saddr)->sin_addr.s_addr, *host, 15)) {
                ERR("%s: inet_ntop failed (%s)", __func__, strerror(errno));
                free(*host);
                *host = NULL;
            }

            if (port) {
                *port = ntohs(((struct sockaddr_in *)&saddr)->sin_port);
            }
        } else if (saddr.ss_family == AF_INET6) {
            *host = malloc(40);
            if (!inet_ntop(AF_INET6, ((struct sockaddr_in6 *)&saddr)->sin6_addr.s6_addr, *host, 40)) {
                ERR("%s: inet_ntop failed (%s)", __func__, strerror(errno));
                free(*host);
                *host = NULL;
            }

            if (port) {
                *port = ntohs(((struct sockaddr_in6 *)&saddr)->sin6_port);
            }
        } else {
            ERR("%s: source host of an unknown protocol family", __func__);
        }
    }

    return ret;
}

API int
nc_server_init(struct ly_ctx *ctx)
{
    if (!ctx) {
        ERRARG;
        return -1;
    }

    server_opts.ctx = ctx;
    return 0;
}

API int
nc_server_set_capab_withdefaults(NC_WD_MODE basic_mode, int also_supported)
{
    if (!basic_mode || (basic_mode == NC_WD_ALL_TAG)
            || (also_supported && !(also_supported & (NC_WD_ALL | NC_WD_ALL_TAG | NC_WD_TRIM | NC_WD_EXPLICIT)))) {
        ERRARG;
        return -1;
    }

    server_opts.wd_basic_mode = basic_mode;
    server_opts.wd_also_supported = also_supported;
    return 0;
}

API int
nc_server_set_capab_interleave(int interleave_support)
{
    if (interleave_support) {
        server_opts.interleave_capab = 1;
    } else {
        server_opts.interleave_capab = 0;
    }

    return 0;
}

API int
nc_server_set_hello_timeout(uint16_t hello_timeout)
{
    if (!hello_timeout) {
        ERRARG;
        return -1;
    }

    server_opts.hello_timeout = hello_timeout;
    return 0;
}

API int
nc_server_set_idle_timeout(uint16_t idle_timeout)
{
    if (!idle_timeout) {
        ERRARG;
        return -1;
    }

    server_opts.idle_timeout = idle_timeout;
    return 0;
}

API int
nc_server_set_max_sessions(uint16_t max_sessions)
{
    server_opts.max_sessions = max_sessions;
    return 0;
}

API struct nc_session *
nc_accept_inout(int fdin, int fdout, const char *username)
{
    struct nc_session *session = NULL;

    if (fdin < 0 || fdout < 0 || !username) {
        ERR("%s: Invalid parameter", __func__);
        return NULL;
    }

    if (!server_opts.ctx) {
        return NULL;
    }

    /* prepare session structure */
    session = calloc(1, sizeof *session);
    if (!session) {
        ERRMEM;
        return NULL;
    }
    session->status = NC_STATUS_STARTING;
    session->side = NC_SERVER;

    /* transport specific data */
    session->ti_type = NC_TI_FD;
    session->ti.fd.in = fdin;
    session->ti.fd.out = fdout;

    /* assign context (dicionary needed for handshake) */
    session->flags = NC_SESSION_SHAREDCTX;
    session->ctx = server_opts.ctx;

    /* NETCONF handshake */
    if (nc_handshake(session)) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    return session;

fail:
    nc_session_free(session);
    return NULL;
}

#if defined(ENABLE_SSH) || defined(ENABLE_TLS)

API int
nc_server_add_bind_listen(const char *address, uint16_t port, NC_TRANSPORT_IMPL ti)
{
    int sock;

    if (!address || !port || ((ti != NC_TI_LIBSSH) && (ti != NC_TI_OPENSSL))) {
        ERRARG;
        return -1;
    }

    sock = nc_sock_listen(address, port);
    if (sock == -1) {
        return -1;
    }

    ++server_opts.bind_count;
    server_opts.binds = realloc(server_opts.binds, server_opts.bind_count * sizeof *server_opts.binds);

    server_opts.binds[server_opts.bind_count - 1].address = strdup(address);
    server_opts.binds[server_opts.bind_count - 1].port = port;
    server_opts.binds[server_opts.bind_count - 1].sock = sock;
    server_opts.binds[server_opts.bind_count - 1].ti = ti;

    return 0;
}

API int
nc_server_del_bind(const char *address, uint16_t port, NC_TRANSPORT_IMPL ti)
{
    uint32_t i;
    int ret = -1;

    for (i = 0; i < server_opts.bind_count; ++i) {
        if ((!address || !strcmp(server_opts.binds[i].address, address))
                && (!port || (server_opts.binds[i].port == port))
                && (!ti || (server_opts.binds[i].ti == ti))) {
            close(server_opts.binds[i].sock);
            free(server_opts.binds[i].address);

            --server_opts.bind_count;
            memmove(&server_opts.binds[i], &server_opts.binds[i + 1], (server_opts.bind_count - i) * sizeof *server_opts.binds);

            ret = 0;
        }
    }

    return ret;
}

API void
nc_server_destroy_binds(void)
{
    uint32_t i;

    for (i = 0; i < server_opts.bind_count; ++i) {
        close(server_opts.binds[i].sock);
        free(server_opts.binds[i].address);
    }
    free(server_opts.binds);
}

API struct nc_session *
nc_accept(int timeout)
{
    NC_TRANSPORT_IMPL ti;
    int sock;
    char *host;
    uint16_t port;
    struct nc_session *session = NULL;

    if (!server_opts.ctx || !server_opts.binds) {
        ERRARG;
        return NULL;
    }

    sock = nc_sock_accept(server_opts.binds, server_opts.bind_count, timeout, &ti, &host, &port);
    if (sock == -1) {
        return NULL;
    }

    session = calloc(1, sizeof *session);
    if (!session) {
        ERRMEM;
        goto fail;
    }
    session->status = NC_STATUS_STARTING;
    session->side = NC_SERVER;
    session->ctx = server_opts.ctx;
    session->flags = NC_SESSION_SHAREDCTX;
    session->host = lydict_insert_zc(session->ctx, host);
    session->port = port;

    /* transport lock */
    session->ti_lock = malloc(sizeof *session->ti_lock);
    if (!session->ti_lock) {
        ERRMEM;
        goto fail;
    }
    pthread_mutex_init(session->ti_lock, NULL);

    if (ti == NC_TI_LIBSSH) {
        if (nc_accept_ssh_session(session, sock, timeout)) {
            goto fail;
        }
    } else if (ti == NC_TI_OPENSSL) {
        if (nc_accept_tls_session(session, sock, timeout)) {
            goto fail;
        }
    } else {
        ERRINT;
        goto fail;
    }

    /* NETCONF handshake */
    if (nc_handshake(session)) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    return session;

fail:
    if (sock > -1) {
        close(sock);
    }
    nc_session_free(session);

    return NULL;
}

API struct nc_pollsession *
nc_pollsession_new(void)
{
    return calloc(1, sizeof(struct nc_pollsession));
}

API void
nc_pollsession_free(struct nc_pollsession *ps)
{
    free(ps->sessions);
    free(ps);
}

API int
nc_pollsession_add_session(struct nc_pollsession *ps, struct nc_session *session)
{
    ++ps->session_count;
    ps->sessions = realloc(ps->sessions, ps->session_count * sizeof *ps->sessions);

    switch (session->ti_type) {
    case NC_TI_FD:
        ps->sessions[ps->session_count - 1].fd = session->ti.fd.in;
        break;

#ifdef ENABLE_SSH
    case NC_TI_LIBSSH:
        ps->sessions[ps->session_count - 1].fd = ssh_get_fd(session->ti.libssh.session);
        break;
#endif

#ifdef ENABLE_TLS
    case NC_TI_OPENSSL:
        ps->sessions[ps->session_count - 1].fd = SSL_get_rfd(session->ti.tls);
        break;
#endif

    default:
        ERRINT;
        return -1;
    }
    ps->sessions[ps->session_count - 1].events = POLLIN;
    ps->sessions[ps->session_count - 1].revents = 0;
    ps->sessions[ps->session_count - 1].session = session;

    return 0;
}

API int
nc_pollsession_poll(struct nc_pollsession *ps, int timeout)
{
    int ret;
    uint16_t i;
    struct nc_session *session;

    ret = poll((struct pollfd *)ps->sessions, ps->session_count, timeout);
    if (ret < 1) {
        return ret;
    }

    /* find the first fd with POLLIN, we don't care if there are more */
    for (i = 0; i < ps->session_count; ++i) {
        if (ps->sessions[i].revents & POLLIN) {
            break;
        }
    }

    if (i == ps->session_count) {
        ERRINT;
        return -1;
    }

    /* this is the session with some data available for reading */
    session = ps->sessions[i].session;

    /* TODO */

    return 1;
}

#endif /* ENABLE_SSH || ENABLE_TLS */
