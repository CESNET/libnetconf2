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

#include "libnetconf.h"
#include "session_server.h"

struct nc_server_opts server_opts;
uint32_t session_id = 1;

API void
nc_session_set_term_reason(struct nc_session *session, NC_SESSION_TERM_REASON reason)
{
    if (!session || !reason) {
        ERRARG;
        return;
    }

    session->term_reason = reason;
}

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

static struct nc_server_reply *
nc_clb_default_get_schema(struct lyd_node *rpc, struct nc_session *UNUSED(session))
{
    const char *identifier = NULL, *version = NULL, *format = NULL;
    char *model_data = NULL;
    const struct lys_module *module;
    struct nc_server_error *err;
    struct lyd_node *child, *data = NULL;
    const struct lys_node *sdata;

    LY_TREE_FOR(rpc->child, child) {
        if (!strcmp(child->schema->name, "identifier")) {
            identifier = ((struct lyd_node_leaf_list *)child)->value_str;
        } else if (!strcmp(child->schema->name, "version")) {
            version = ((struct lyd_node_leaf_list *)child)->value_str;
        } else if (!strcmp(child->schema->name, "format")) {
            format = ((struct lyd_node_leaf_list *)child)->value_str;
        }
    }

    /* check version */
    if (version && (strlen(version) != 10) && strcmp(version, "1.0")) {
        err = nc_err(NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, "The requested version is not supported.", "en");
        return nc_server_reply_err(err);
    }

    /* check and get module with the name identifier */
    module = ly_ctx_get_module(server_opts.ctx, identifier, version);
    if (!module) {
        err = nc_err(NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, "The requested schema was not found.", "en");
        return nc_server_reply_err(err);
    }

    /* check format */
    if (!format || !strcmp(format, "yang")) {
        lys_print_mem(&model_data, module, LYS_OUT_YANG, NULL);
    } else if (!strcmp(format, "yin")) {
        lys_print_mem(&model_data, module, LYS_OUT_YIN, NULL);
    } else {
        err = nc_err(NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, "The requested format is not supported.", "en");
        return nc_server_reply_err(err);
    }

    sdata = ly_ctx_get_node(server_opts.ctx, "/ietf-netconf-monitoring:get-schema/output/data");
    if (model_data) {
        data = lyd_output_new_anyxml(sdata, model_data);
    }
    free(model_data);
    if (!data) {
        ERRINT;
        return NULL;
    }

    return nc_server_reply_data(data, NC_PARAMTYPE_FREE);
}

static struct nc_server_reply *
nc_clb_default_close_session(struct lyd_node *UNUSED(rpc), struct nc_session *session)
{
    session->term_reason = NC_SESSION_TERM_CLOSED;
    return nc_server_reply_ok();
}

API int
nc_server_init(struct ly_ctx *ctx)
{
    const struct lys_node *rpc;

    if (!ctx) {
        ERRARG;
        return -1;
    }

    /* set default <get-schema> callback if not specified */
    rpc = ly_ctx_get_node(ctx, "/ietf-netconf-monitoring:get-schema");
    if (rpc && !rpc->private) {
        lys_set_private(rpc, nc_clb_default_get_schema);
    }

    /* set default <close-session> callback if not specififed */
    rpc = ly_ctx_get_node(ctx, "/ietf-netconf:close-session");
    if (rpc && !rpc->private) {
        lys_set_private(rpc, nc_clb_default_close_session);
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

API void
nc_server_set_capab_interleave(int interleave_support)
{
    if (interleave_support) {
        server_opts.interleave_capab = 1;
    } else {
        server_opts.interleave_capab = 0;
    }
}

API void
nc_server_set_hello_timeout(uint16_t hello_timeout)
{
    server_opts.hello_timeout = hello_timeout;
}

API void
nc_server_set_idle_timeout(uint16_t idle_timeout)
{
    server_opts.idle_timeout = idle_timeout;
}

API int
nc_accept_inout(int fdin, int fdout, const char *username, struct nc_session **session)
{
    if (fdin < 0 || fdout < 0 || !username || !session) {
        ERRARG;
        return -1;
    }

    /* prepare session structure */
    *session = calloc(1, sizeof **session);
    if (!(*session)) {
        ERRMEM;
        return -1;
    }
    (*session)->status = NC_STATUS_STARTING;
    (*session)->side = NC_SERVER;

    /* transport specific data */
    (*session)->ti_type = NC_TI_FD;
    (*session)->ti.fd.in = fdin;
    (*session)->ti.fd.out = fdout;

    /* assign context (dicionary needed for handshake) */
    (*session)->flags = NC_SESSION_SHAREDCTX;
    (*session)->ctx = server_opts.ctx;

    /* NETCONF handshake */
    (*session)->id = session_id++;
    if (nc_handshake(*session)) {
        goto fail;
    }
    (*session)->status = NC_STATUS_RUNNING;

    return 0;

fail:
    nc_session_free(*session);
    *session = NULL;
    return -1;
}

API struct nc_pollsession *
nc_ps_new(void)
{
    return calloc(1, sizeof(struct nc_pollsession));
}

API void
nc_ps_free(struct nc_pollsession *ps)
{
    free(ps->sessions);
    free(ps);
}

API int
nc_ps_add_session(struct nc_pollsession *ps, struct nc_session *session)
{
    if (!ps || !session) {
        ERRARG;
        return -1;
    }

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
nc_ps_del_session(struct nc_pollsession *ps, struct nc_session *session)
{
    uint16_t i;

    if (!ps || !session) {
        ERRARG;
        return -1;
    }

    for (i = 0; i < ps->session_count; ++i) {
        if (ps->sessions[i].session == session) {
            --ps->session_count;
            memmove(&ps->sessions[i], &ps->sessions[i + 1], ps->session_count - i);
            return 0;
        }
    }

    return 1;
}

/* must be called holding the session lock! */
static NC_MSG_TYPE
nc_recv_rpc(struct nc_session *session, struct nc_server_rpc **rpc)
{
    struct lyxml_elem *xml = NULL;
    NC_MSG_TYPE msgtype;

    if (!session || !rpc) {
        ERRARG;
        return NC_MSG_ERROR;
    } else if ((session->status != NC_STATUS_RUNNING) || (session->side != NC_SERVER)) {
        ERR("%s: invalid session to receive RPCs.", __func__);
        return NC_MSG_ERROR;
    }

    msgtype = nc_read_msg(session, &xml);

    switch (msgtype) {
    case NC_MSG_RPC:
        *rpc = malloc(sizeof **rpc);
        (*rpc)->tree = lyd_parse_xml(server_opts.ctx, &xml->child, LYD_OPT_DESTRUCT | LYD_OPT_RPC);
        (*rpc)->root = xml;
        break;
    case NC_MSG_HELLO:
        ERR("%s: session %u: received another <hello> message.", __func__, session->id);
        goto error;
    case NC_MSG_REPLY:
        ERR("%s: session %u: received <rpc-reply> from NETCONF client.", __func__, session->id);
        goto error;
    case NC_MSG_NOTIF:
        ERR("%s: session %u: received <notification> from NETCONF client.", __func__, session->id);
        goto error;
    default:
        /* NC_MSG_ERROR - pass it out;
         * NC_MSG_WOULDBLOCK and NC_MSG_NONE is not returned by nc_read_msg()
         */
        break;
    }

    return msgtype;

error:
    /* cleanup */
    lyxml_free(server_opts.ctx, xml);

    return NC_MSG_ERROR;
}

/* must be called holding the session lock! */
static NC_MSG_TYPE
nc_send_reply(struct nc_session *session, struct nc_server_rpc *rpc)
{
    nc_rpc_clb clb;
    struct nc_server_reply *reply;
    int ret;

    /* no callback, reply with a not-implemented error */
    if (!rpc->tree->schema->private) {
        reply = nc_server_reply_err(nc_err(NC_ERR_OP_NOT_SUPPORTED, NC_ERR_TYPE_PROT));
    } else {
        clb = (nc_rpc_clb)rpc->tree->schema->private;
        reply = clb(rpc->tree, session);
    }

    if (!reply) {
        reply = nc_server_reply_err(nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP));
    }

    ret = nc_write_msg(session, NC_MSG_REPLY, rpc->root, reply);

    /* special case if term_reason was set in callback, last reply was sent (needed for <close-session> if nothing else) */
    if ((session->status == NC_STATUS_RUNNING) && (session->term_reason != NC_SESSION_TERM_NONE)) {
        session->status = NC_STATUS_INVALID;
    }

    if (ret == -1) {
        ERR("%s: failed to write reply.", __func__);
        nc_server_reply_free(reply);
        return NC_MSG_ERROR;
    }
    nc_server_reply_free(reply);

    return NC_MSG_REPLY;
}

API int
nc_ps_poll(struct nc_pollsession *ps, int timeout)
{
    int ret;
    uint16_t i;
    NC_MSG_TYPE msgtype;
    struct nc_session *session;
    struct nc_server_rpc *rpc;
    struct timespec old_ts, new_ts;

    if (!ps || !ps->session_count) {
        ERRARG;
        return -1;
    }

    for (i = 0; i < ps->session_count; ++i) {
        if (ps->sessions[i].session->status != NC_STATUS_RUNNING) {
            ERR("%s: session %u: session not running.", __func__, ps->sessions[i].session->id);
            return -1;
        }
    }

    if (timeout > 0) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &old_ts);
    }

retry_poll:
    ret = poll((struct pollfd *)ps->sessions, ps->session_count, timeout);
    if (ret < 1) {
        return ret;
    }

    /* find the first fd with POLLIN, we don't care if there are more */
    for (i = 0; i < ps->session_count; ++i) {
        if (ps->sessions[i].revents & POLLIN) {
#ifdef ENABLE_SSH
            if (ps->sessions[i].session->ti_type == NC_TI_LIBSSH) {
                /* things are not that simple with SSH, we need to check the channel */
                ret = ssh_channel_poll_timeout(ps->sessions[i].session->ti.libssh.channel, 0, 0);
                /* not this one */
                if (!ret) {
                    if (i == ps->session_count - 1) {
                        /* last session and it is not the right channel, ... */
                        if (timeout > 0) {
                            /* ... decrease timeout, wait it all out and try again, last time */
                            clock_gettime(CLOCK_MONOTONIC_RAW, &new_ts);

                            timeout -= (new_ts.tv_sec - old_ts.tv_sec) * 1000;
                            timeout -= (new_ts.tv_nsec - old_ts.tv_nsec) / 1000000;
                            if (timeout < 0) {
                                ERRINT;
                                return -1;
                            }

                            old_ts = new_ts;
                        } else if (!timeout) {
                            /* ... timeout is 0, so that is it */
                            return 0;
                        } else {
                            /* ... retry polling reasonable time apart */
                            usleep(NC_TIMEOUT_STEP);
                            goto retry_poll;
                        }
                    }
                    /* check other sessions */
                    continue;
                } else if (ret == SSH_ERROR) {
                    ERR("%s: session %u: SSH channel error (%s).", __func__, ps->sessions[i].session->id,
                        ssh_get_error(ps->sessions[i].session->ti.libssh.session));
                    ps->sessions[i].session->status = NC_STATUS_INVALID;
                    ps->sessions[i].session->term_reason = NC_SESSION_TERM_OTHER;
                    return 2;
                } else if (ret == SSH_EOF) {
                    ERR("%s: session %u: communication channel unexpectedly closed (libssh).",
                        __func__, ps->sessions[i].session->id);
                    ps->sessions[i].session->status = NC_STATUS_INVALID;
                    ps->sessions[i].session->term_reason = NC_SESSION_TERM_DROPPED;
                    return 2;
                }
            }
#endif /* ENABLE_SSH */

            break;
        }
    }

    if (i == ps->session_count) {
        ERRINT;
        return -1;
    }

    /* this is the session with some data available for reading */
    session = ps->sessions[i].session;

    if (timeout > 0) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &new_ts);

        /* subtract elapsed time */
        timeout -= (new_ts.tv_sec - old_ts.tv_sec) * 1000;
        timeout -= (new_ts.tv_nsec - old_ts.tv_nsec) / 1000000;
        if (timeout < 0) {
            ERRINT;
            return -1;
        }
    }

    /* reading an RPC and sending a reply must be atomic */
    ret = session_ti_lock(session, timeout);
    if (ret > 0) {
        /* error */
        return -1;
    } else if (ret < 0) {
        /* timeout */
        return 0;
    }

    msgtype = nc_recv_rpc(session, &rpc);
    if (msgtype == NC_MSG_ERROR) {
        session_ti_unlock(session);
        if (session->status != NC_STATUS_RUNNING) {
            return 2;
        }
        return -1;
    }

    /* process RPC */
    msgtype = nc_send_reply(session, rpc);

    session_ti_unlock(session);

    if (msgtype == NC_MSG_ERROR) {
        nc_server_rpc_free(rpc);
        if (session->status != NC_STATUS_RUNNING) {
            return 2;
        }
        return -1;
    }

    nc_server_rpc_free(rpc);
    return 1;
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

    if (!address && !port && !ti) {
        for (i = 0; i < server_opts.bind_count; ++i) {
            close(server_opts.binds[i].sock);
            free(server_opts.binds[i].address);

            ret = 0;
        }
        free(server_opts.binds);
        server_opts.binds = NULL;
        server_opts.bind_count = 0;
    } else {
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
    }

    return ret;
}

API int
nc_accept(int timeout, struct nc_session **session)
{
    NC_TRANSPORT_IMPL ti;
    int sock, ret;
    char *host;
    uint16_t port;

    if (!server_opts.ctx || !server_opts.binds || !session) {
        ERRARG;
        return -1;
    }

    sock = nc_sock_accept(server_opts.binds, server_opts.bind_count, timeout, &ti, &host, &port);
    if (sock < 1) {
        return sock;
    }

    *session = calloc(1, sizeof **session);
    if (!session) {
        ERRMEM;
        close(sock);
        return -1;
    }
    (*session)->status = NC_STATUS_STARTING;
    (*session)->side = NC_SERVER;
    (*session)->ctx = server_opts.ctx;
    (*session)->flags = NC_SESSION_SHAREDCTX;
    (*session)->host = lydict_insert_zc(server_opts.ctx, host);
    (*session)->port = port;

    /* transport lock */
    (*session)->ti_lock = malloc(sizeof *(*session)->ti_lock);
    if (!(*session)->ti_lock) {
        ERRMEM;
        close(sock);
        ret = -1;
        goto fail;
    }
    pthread_mutex_init((*session)->ti_lock, NULL);

    /* sock gets assigned to session or closed */
    if (ti == NC_TI_LIBSSH) {
        ret = nc_accept_ssh_session(*session, sock, timeout);
        if (ret < 1) {
            goto fail;
        }
    } else if (ti == NC_TI_OPENSSL) {
        ret = nc_accept_tls_session(*session, sock, timeout);
        if (ret < 1) {
            goto fail;
        }
    } else {
        ERRINT;
        close(sock);
        ret = -1;
        goto fail;
    }

    /* NETCONF handshake */
    (*session)->id = session_id++;
    if (nc_handshake(*session)) {
        ret = -1;
        goto fail;
    }
    (*session)->status = NC_STATUS_RUNNING;

    return 1;

fail:
    nc_session_free(*session);
    *session = NULL;
    return -1;
}

#endif /* ENABLE_SSH || ENABLE_TLS */
