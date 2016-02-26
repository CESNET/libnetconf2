/**
 * \file session_server.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 server session manipulation functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
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
#include <pthread.h>
#include <time.h>

#include "libnetconf.h"
#include "session_server.h"

struct nc_server_opts server_opts = {
    .endpt_array_lock = PTHREAD_RWLOCK_INITIALIZER
};

extern struct nc_server_ssh_opts ssh_ch_opts;
extern pthread_mutex_t ssh_ch_opts_lock;

extern struct nc_server_tls_opts tls_ch_opts;
extern pthread_mutex_t tls_ch_opts_lock;

struct nc_endpt *
nc_server_endpt_lock(const char *name, NC_TRANSPORT_IMPL ti)
{
    uint16_t i;
    struct nc_endpt *endpt = NULL;

    /* READ LOCK */
    pthread_rwlock_rdlock(&server_opts.endpt_array_lock);

    for (i = 0; i < server_opts.endpt_count; ++i) {
        if ((server_opts.binds[i].ti == ti) && !strcmp(server_opts.endpts[i].name, name)) {
            endpt = &server_opts.endpts[i];
            break;
        }
    }

    if (!endpt) {
        ERR("Endpoint \"%s\" was not found.", name);
        /* READ UNLOCK */
        pthread_rwlock_unlock(&server_opts.endpt_array_lock);
        return NULL;
    }

    /* ENDPT LOCK */
    pthread_mutex_lock(&endpt->endpt_lock);

    return endpt;
}

void
nc_server_endpt_unlock(struct nc_endpt *endpt)
{
    /* ENDPT UNLOCK */
    pthread_mutex_unlock(&endpt->endpt_lock);

    /* READ UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_array_lock);
}

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
nc_sock_listen(const char *address, uint16_t port)
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
        ERR("Failed to create socket (%s).", strerror(errno));
        goto fail;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&optVal, optLen)) {
        ERR("Could not set socket SO_REUSEADDR socket option (%s).", strerror(errno));
        goto fail;
    }

    bzero(&saddr, sizeof(struct sockaddr_storage));
    if (is_ipv4) {
        saddr4 = (struct sockaddr_in *)&saddr;

        saddr4->sin_family = AF_INET;
        saddr4->sin_port = htons(port);

        if (inet_pton(AF_INET, address, &saddr4->sin_addr) != 1) {
            ERR("Failed to convert IPv4 address \"%s\".", address);
            goto fail;
        }

        if (bind(sock, (struct sockaddr *)saddr4, sizeof(struct sockaddr_in)) == -1) {
            ERR("Could not bind \"%s\" port %d (%s).", address, port, strerror(errno));
            goto fail;
        }

    } else {
        saddr6 = (struct sockaddr_in6 *)&saddr;

        saddr6->sin6_family = AF_INET6;
        saddr6->sin6_port = htons(port);

        if (inet_pton(AF_INET6, address, &saddr6->sin6_addr) != 1) {
            ERR("Failed to convert IPv6 address \"%s\".", address);
            goto fail;
        }

        if (bind(sock, (struct sockaddr *)saddr6, sizeof(struct sockaddr_in6)) == -1) {
            ERR("Could not bind \"%s\" port %d (%s).", address, port, strerror(errno));
            goto fail;
        }
    }

    if (listen(sock, NC_REVERSE_QUEUE) == -1) {
        ERR("Unable to start listening on \"%s\" port %d (%s).", address, port, strerror(errno));
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
nc_sock_accept_binds(struct nc_bind *binds, uint16_t bind_count, int timeout, char **host, uint16_t *port, uint16_t *idx)
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
        ERR("Poll failed (%s).", strerror(errno));
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
        ERRINT;
        return -1;
    }

    ret = accept(sock, (struct sockaddr *)&saddr, &saddr_len);
    if (ret < 0) {
        ERR("Accept failed (%s).", strerror(errno));
        return -1;
    }

    if (idx) {
        *idx = i;
    }

    /* host was requested */
    if (host) {
        if (saddr.ss_family == AF_INET) {
            *host = malloc(15);
            if (!inet_ntop(AF_INET, &((struct sockaddr_in *)&saddr)->sin_addr.s_addr, *host, 15)) {
                ERR("inet_ntop failed (%s).", strerror(errno));
                free(*host);
                *host = NULL;
            }

            if (port) {
                *port = ntohs(((struct sockaddr_in *)&saddr)->sin_port);
            }
        } else if (saddr.ss_family == AF_INET6) {
            *host = malloc(40);
            if (!inet_ntop(AF_INET6, ((struct sockaddr_in6 *)&saddr)->sin6_addr.s6_addr, *host, 40)) {
                ERR("inet_ntop failed (%s).", strerror(errno));
                free(*host);
                *host = NULL;
            }

            if (port) {
                *port = ntohs(((struct sockaddr_in6 *)&saddr)->sin6_port);
            }
        } else {
            ERR("Source host of an unknown protocol family.");
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
    const struct lys_node *sdata = NULL;

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
    if (model_data && sdata) {
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

    server_opts.new_session_id = 1;
    pthread_spin_init(&server_opts.sid_lock, PTHREAD_PROCESS_PRIVATE);

    return 0;
}

API void
nc_server_destroy(void)
{
    pthread_spin_destroy(&server_opts.sid_lock);

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
    nc_server_del_endpt(NULL, 0);
#endif
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
    if (!server_opts.ctx || (fdin < 0) || (fdout < 0) || !username || !session) {
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

    /* assign new SID atomically */
    pthread_spin_lock(&server_opts.sid_lock);
    (*session)->id = server_opts.new_session_id++;
    pthread_spin_unlock(&server_opts.sid_lock);

    /* NETCONF handshake */
    if (nc_handshake(*session)) {
        goto fail;
    }
    (*session)->status = NC_STATUS_RUNNING;
    (*session)->last_rpc = time(NULL);

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
    if (!ps) {
        return;
    }

    free(ps->pfds);
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
    ps->pfds = realloc(ps->pfds, ps->session_count * sizeof *ps->pfds);
    ps->sessions = realloc(ps->sessions, ps->session_count * sizeof *ps->sessions);

    switch (session->ti_type) {
    case NC_TI_FD:
        ps->pfds[ps->session_count - 1].fd = session->ti.fd.in;
        break;

#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
        ps->pfds[ps->session_count - 1].fd = ssh_get_fd(session->ti.libssh.session);
        break;
#endif

#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
        ps->pfds[ps->session_count - 1].fd = SSL_get_rfd(session->ti.tls);
        break;
#endif

    default:
        ERRINT;
        return -1;
    }
    ps->pfds[ps->session_count - 1].events = POLLIN;
    ps->pfds[ps->session_count - 1].revents = 0;
    ps->sessions[ps->session_count - 1] = session;

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
        if (ps->sessions[i] == session) {
            --ps->session_count;
            if (i < ps->session_count) {
                ps->sessions[i] = ps->sessions[ps->session_count];
                memcpy(&ps->pfds[i], &ps->pfds[ps->session_count], sizeof *ps->pfds);
            } else if (!ps->session_count) {
                free(ps->sessions);
                ps->sessions = NULL;
                free(ps->pfds);
                ps->pfds = NULL;
            }
            return 0;
        }
    }

    return -1;
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
        ERR("Session %u: invalid session to receive RPCs.", session->id);
        return NC_MSG_ERROR;
    }

    msgtype = nc_read_msg(session, &xml);

    switch (msgtype) {
    case NC_MSG_RPC:
        *rpc = malloc(sizeof **rpc);

        (*rpc)->tree = lyd_parse_xml(server_opts.ctx, &xml->child, LYD_OPT_DESTRUCT | LYD_OPT_RPC);
        if (!(*rpc)->tree) {
            ERR("Session %u: received message failed to be parsed into a known RPC.", session->id);
            msgtype = NC_MSG_NONE;
        }
        (*rpc)->root = xml;
        break;
    case NC_MSG_HELLO:
        ERR("Session %u: received another <hello> message.", session->id);
        goto error;
    case NC_MSG_REPLY:
        ERR("Session %u: received <rpc-reply> from a NETCONF client.", session->id);
        goto error;
    case NC_MSG_NOTIF:
        ERR("Session %u: received <notification> from a NETCONF client.", session->id);
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
    if (!rpc->tree || !rpc->tree->schema->private) {
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
        ERR("Session %u: failed to write reply.", session->id);
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
    time_t cur_time;
    NC_MSG_TYPE msgtype;
    struct nc_session *session;
    struct nc_server_rpc *rpc;

    if (!ps || !ps->session_count) {
        ERRARG;
        return -1;
    }

    cur_time = time(NULL);

    for (i = 0; i < ps->session_count; ++i) {
        if (ps->sessions[i]->status != NC_STATUS_RUNNING) {
            ERR("Session %u: session not running.", ps->sessions[i]->id);
            return -1;
        }

        /* TODO invalidate only sessions without subscription */
        if (server_opts.idle_timeout && (ps->sessions[i]->last_rpc + server_opts.idle_timeout >= cur_time)) {
            ERR("Session %u: session idle timeout elapsed.", ps->sessions[i]->id);
            ps->sessions[i]->status = NC_STATUS_INVALID;
            ps->sessions[i]->term_reason = NC_SESSION_TERM_TIMEOUT;
            return 3;
        }

        if (ps->pfds[i].revents) {
            break;
        }
    }

    if (i == ps->session_count) {
#ifdef NC_ENABLED_SSH
retry_poll:
#endif
        /* no leftover event */
        i = 0;
        ret = poll(ps->pfds, ps->session_count, timeout);
        if (ret < 1) {
            return ret;
        }
    }

    /* find the first fd with POLLIN, we don't care if there are more now */
    for (; i < ps->session_count; ++i) {
        if (ps->pfds[i].revents & POLLHUP) {
            ERR("Session %u: communication socket unexpectedly closed.", ps->sessions[i]->id);
            ps->sessions[i]->status = NC_STATUS_INVALID;
            ps->sessions[i]->term_reason = NC_SESSION_TERM_DROPPED;
            return 3;
        } else if (ps->pfds[i].revents & POLLERR) {
            ERR("Session %u: communication socket error.", ps->sessions[i]->id);
            ps->sessions[i]->status = NC_STATUS_INVALID;
            ps->sessions[i]->term_reason = NC_SESSION_TERM_OTHER;
            return 3;
        } else if (ps->pfds[i].revents & POLLIN) {
#ifdef NC_ENABLED_SSH
            if (ps->sessions[i]->ti_type == NC_TI_LIBSSH) {
                uint16_t j;

                /* things are not that simple with SSH... */
                ret = nc_ssh_pollin(ps->sessions[i], &timeout);

                /* clear POLLIN on sessions sharing this session's SSH session */
                if ((ret == 1) || (ret >= 4)) {
                    for (j = i + 1; j < ps->session_count; ++j) {
                        if (ps->pfds[j].fd == ps->pfds[i].fd) {
                            ps->pfds[j].revents = 0;
                        }
                    }
                }

                /* actual event happened */
                if ((ret <= 0) || (ret >= 3)) {
                    ps->pfds[i].revents = 0;
                    return ret;

                /* event occurred on some other channel */
                } else if (ret == 2) {
                    ps->pfds[i].revents = 0;
                    if (i == ps->session_count - 1) {
                        /* last session and it is not the right channel, ... */
                        if (!timeout) {
                            /* ... timeout is 0, so that is it */
                            return 0;
                        }
                        /* ... retry polling reasonable time apart ... */
                        usleep(NC_TIMEOUT_STEP);
                        if (timeout > 0) {
                            /* ... and decrease timeout, if not -1 */
                            timeout -= NC_TIMEOUT_STEP * 1000;
                        }
                        goto retry_poll;
                    }
                    /* check other sessions */
                    continue;
                }
            }
#endif /* NC_ENABLED_SSH */

            /* we are going to process it now */
            ps->pfds[i].revents = 0;
            break;
        }
    }

    if (i == ps->session_count) {
        ERRINT;
        return -1;
    }

    /* this is the session with some data available for reading */
    session = ps->sessions[i];

    /* reading an RPC and sending a reply must be atomic (no other RPC should be read) */
    ret = nc_timedlock(session->ti_lock, timeout, NULL);
    if (ret != 1) {
        /* error or timeout */
        return ret;
    }

    msgtype = nc_recv_rpc(session, &rpc);
    if (msgtype == NC_MSG_ERROR) {
        pthread_mutex_unlock(session->ti_lock);
        if (session->status != NC_STATUS_RUNNING) {
            return 3;
        }
        return -1;
    }

    /* NC_MSG_NONE is not a real (known) RPC */
    if (msgtype == NC_MSG_RPC) {
        session->last_rpc = time(NULL);
    }

    /* process RPC */
    msgtype = nc_send_reply(session, rpc);

    pthread_mutex_unlock(session->ti_lock);

    if (msgtype == NC_MSG_ERROR) {
        nc_server_rpc_free(rpc, server_opts.ctx);
        return -1;
    }
    nc_server_rpc_free(rpc, server_opts.ctx);

    /* status change takes precedence over leftover events (return 2) */
    if (session->status != NC_STATUS_RUNNING) {
        return 3;
    }

    /* is there some other socket waiting? */
    for (++i; i < ps->session_count; ++i) {
        if (ps->pfds[i].revents) {
            return 2;
        }
    }

    return 1;
}

API void
nc_ps_clear(struct nc_pollsession *ps)
{
    uint16_t i;
    struct nc_session *session;

    if (!ps) {
        ERRARG;
        return;
    }

    for (i = 0; i < ps->session_count; ) {
        if (ps->sessions[i]->status != NC_STATUS_RUNNING) {
            session = ps->sessions[i];
            nc_ps_del_session(ps, session);
            nc_session_free(session);
            continue;
        }

        ++i;
    }
}

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)

int
nc_server_add_endpt_listen(const char *name, const char *address, uint16_t port, NC_TRANSPORT_IMPL ti)
{
    int sock;
    uint16_t i;
#ifdef NC_ENABLED_SSH
    struct nc_server_ssh_opts *ssh_opts;
#endif

    if (!name || !address || !port) {
        ERRARG;
        return -1;
    }

    /* WRITE LOCK */
    pthread_rwlock_wrlock(&server_opts.endpt_array_lock);

    /* check name uniqueness */
    for (i = 0; i < server_opts.endpt_count; ++i) {
        if ((server_opts.binds[i].ti == ti) && !strcmp(server_opts.endpts[i].name, name)) {
            ERR("Endpoint \"%s\" already exists.", name);
            /* WRITE UNLOCK */
            pthread_rwlock_unlock(&server_opts.endpt_array_lock);
            return -1;
        }
    }

    sock = nc_sock_listen(address, port);
    if (sock == -1) {
        /* WRITE UNLOCK */
        pthread_rwlock_unlock(&server_opts.endpt_array_lock);
        return -1;
    }

    ++server_opts.endpt_count;
    server_opts.binds = realloc(server_opts.binds, server_opts.endpt_count * sizeof *server_opts.binds);
    server_opts.endpts = realloc(server_opts.endpts, server_opts.endpt_count * sizeof *server_opts.endpts);

    server_opts.endpts[server_opts.endpt_count - 1].name = lydict_insert(server_opts.ctx, name, 0);
    server_opts.binds[server_opts.endpt_count - 1].address = lydict_insert(server_opts.ctx, address, 0);
    server_opts.binds[server_opts.endpt_count - 1].port = port;
    server_opts.binds[server_opts.endpt_count - 1].sock = sock;
    server_opts.binds[server_opts.endpt_count - 1].ti = ti;
    switch (ti) {
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
        ssh_opts = calloc(1, sizeof *ssh_opts);
        /* set default values */
        ssh_opts->auth_methods = NC_SSH_AUTH_PUBLICKEY | NC_SSH_AUTH_PASSWORD | NC_SSH_AUTH_INTERACTIVE;
        ssh_opts->auth_attempts = 3;
        ssh_opts->auth_timeout = 10;

        server_opts.endpts[server_opts.endpt_count - 1].ti_opts = ssh_opts;
        break;
#endif
#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
        server_opts.endpts[server_opts.endpt_count - 1].ti_opts = calloc(1, sizeof(struct nc_server_tls_opts));
        break;
#endif
    default:
        ERRINT;
        server_opts.endpts[server_opts.endpt_count - 1].ti_opts = NULL;
        break;
    }
    pthread_mutex_init(&server_opts.endpts[server_opts.endpt_count - 1].endpt_lock, NULL);

    /* WRITE UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_array_lock);

    return 0;
}

int
nc_server_endpt_set_address_port(const char *endpt_name, const char *address, uint16_t port, NC_TRANSPORT_IMPL ti)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind = NULL;
    uint16_t i;
    int sock;

    if (!endpt_name || (!address && !port) || (address && port) || !ti) {
        ERRARG;
        return -1;
    }

    /* LOCK */
    endpt = nc_server_endpt_lock(endpt_name, ti);
    if (!endpt) {
        return -1;
    }

    /* we need to learn the index, to get the bind :-/ */
    for (i = 0; i < server_opts.endpt_count; ++i) {
        if (&server_opts.endpts[i] == endpt) {
            bind = &server_opts.binds[i];
        }
    }
    if (!bind) {
        ERRINT;
        goto fail;
    }

    if (address) {
        sock = nc_sock_listen(address, bind->port);
    } else {
        sock = nc_sock_listen(bind->address, port);
    }
    if (sock == -1) {
        goto fail;
    }

    /* close old socket, update parameters */
    close(bind->sock);
    bind->sock = sock;
    if (address) {
        lydict_remove(server_opts.ctx, bind->address);
        bind->address = lydict_insert(server_opts.ctx, address, 0);
    } else {
        bind->port = port;
    }

    /* UNLOCK */
    nc_server_endpt_unlock(endpt);
    return 0;

fail:
    /* UNLOCK */
    nc_server_endpt_unlock(endpt);
    return -1;
}

int
nc_server_del_endpt(const char *name, NC_TRANSPORT_IMPL ti)
{
    uint32_t i;
    int ret = -1;

    /* WRITE LOCK */
    pthread_rwlock_wrlock(&server_opts.endpt_array_lock);

    if (!name && !ti) {
        /* remove all */
        for (i = 0; i < server_opts.endpt_count; ++i) {
            lydict_remove(server_opts.ctx, server_opts.endpts[i].name);
            lydict_remove(server_opts.ctx, server_opts.binds[i].address);

            close(server_opts.binds[i].sock);
            pthread_mutex_destroy(&server_opts.endpts[i].endpt_lock);
            switch (server_opts.binds[i].ti) {
#ifdef NC_ENABLED_SSH
            case NC_TI_LIBSSH:
                nc_server_ssh_clear_opts(server_opts.endpts[i].ti_opts);
                break;
#endif
#ifdef NC_ENABLED_TLS
            case NC_TI_OPENSSL:
                nc_server_tls_clear_opts(server_opts.endpts[i].ti_opts);
                break;
#endif
            default:
                ERRINT;
                break;
            }
            free(server_opts.endpts[i].ti_opts);

            ret = 0;
        }
        free(server_opts.binds);
        server_opts.binds = NULL;
        free(server_opts.endpts);
        server_opts.endpts = NULL;
        server_opts.endpt_count = 0;

    } else {
        /* remove one name endpoint or all ti endpoints */
        for (i = 0; i < server_opts.endpt_count; ++i) {
            if ((server_opts.binds[i].ti == ti) &&
                    (!name || !strcmp(server_opts.endpts[i].name, name))) {

                lydict_remove(server_opts.ctx, server_opts.endpts[i].name);
                lydict_remove(server_opts.ctx, server_opts.binds[i].address);
                close(server_opts.binds[i].sock);
                pthread_mutex_destroy(&server_opts.endpts[i].endpt_lock);
                switch (server_opts.binds[i].ti) {
#ifdef NC_ENABLED_SSH
                case NC_TI_LIBSSH:
                    nc_server_ssh_clear_opts(server_opts.endpts[i].ti_opts);
                    break;
#endif
#ifdef NC_ENABLED_TLS
                case NC_TI_OPENSSL:
                    nc_server_tls_clear_opts(server_opts.endpts[i].ti_opts);
                    break;
#endif
                default:
                    ERRINT;
                    break;
                }
                free(server_opts.endpts[i].ti_opts);

                --server_opts.endpt_count;
                if (i < server_opts.endpt_count) {
                    memcpy(&server_opts.binds[i], &server_opts.binds[server_opts.endpt_count], sizeof *server_opts.binds);
                    memcpy(&server_opts.endpts[i], &server_opts.endpts[server_opts.endpt_count], sizeof *server_opts.endpts);
                } else if (!server_opts.endpt_count) {
                    free(server_opts.binds);
                    server_opts.binds = NULL;
                    free(server_opts.endpts);
                    server_opts.endpts = NULL;
                }

                ret = 0;

                if (name) {
                    /* one name endpoint removed, they are unique, we're done */
                    break;
                }
            }
        }
    }

    /* WRITE UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_array_lock);

    return ret;
}

API int
nc_accept(int timeout, struct nc_session **session)
{
    int sock, ret;
    char *host = NULL;
    uint16_t port, idx;

    if (!server_opts.ctx || !session) {
        ERRARG;
        return -1;
    }

    /* we have to hold WRITE for the whole time, since there is not
     * a way of downgrading the lock to READ */
    /* WRITE LOCK */
    pthread_rwlock_wrlock(&server_opts.endpt_array_lock);

    if (!server_opts.endpt_count) {
        ERRARG;
        /* WRITE UNLOCK */
        pthread_rwlock_unlock(&server_opts.endpt_array_lock);
        return -1;
    }

    ret = nc_sock_accept_binds(server_opts.binds, server_opts.endpt_count, timeout, &host, &port, &idx);

    if (ret < 1) {
        /* WRITE UNLOCK */
        pthread_rwlock_unlock(&server_opts.endpt_array_lock);
        free(host);
        return ret;
    }
    sock = ret;

    *session = calloc(1, sizeof **session);
    if (!(*session)) {
        ERRMEM;
        close(sock);
        free(host);
        ret = -1;
        goto fail;
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

    (*session)->ti_opts = server_opts.endpts[idx].ti_opts;

    /* sock gets assigned to session or closed */
#ifdef NC_ENABLED_SSH
    if (server_opts.binds[idx].ti == NC_TI_LIBSSH) {
        ret = nc_accept_ssh_session(*session, sock, timeout);
        if (ret < 1) {
            goto fail;
        }
    } else
#endif
#ifdef NC_ENABLED_TLS
    if (server_opts.binds[idx].ti == NC_TI_OPENSSL) {
        ret = nc_accept_tls_session(*session, sock, timeout);
        if (ret < 1) {
            goto fail;
        }
    } else
#endif
    {
        ERRINT;
        close(sock);
        ret = -1;
        goto fail;
    }

    /* WRITE UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_array_lock);

    /* assign new SID atomically */
    /* LOCK */
    pthread_spin_lock(&server_opts.sid_lock);
    (*session)->id = server_opts.new_session_id++;
    /* UNLOCK */
    pthread_spin_unlock(&server_opts.sid_lock);

    /* NETCONF handshake */
    if (nc_handshake(*session)) {
        nc_session_free(*session);
        *session = NULL;
        return -1;
    }
    (*session)->status = NC_STATUS_RUNNING;

    return 1;

fail:
    /* WRITE UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_array_lock);

    nc_session_free(*session);
    *session = NULL;
    return ret;
}

int
nc_connect_callhome(const char *host, uint16_t port, NC_TRANSPORT_IMPL ti, int timeout, struct nc_session **session)
{
    int sock, ret;

    if (!host || !port || !ti || !session) {
        ERRARG;
        return -1;
    }

    sock = nc_sock_connect(host, port);
    if (sock < 0) {
        return -1;
    }

    *session = calloc(1, sizeof **session);
    if (!(*session)) {
        ERRMEM;
        close(sock);
        return -1;
    }
    (*session)->status = NC_STATUS_STARTING;
    (*session)->side = NC_SERVER;
    (*session)->ctx = server_opts.ctx;
    (*session)->flags = NC_SESSION_SHAREDCTX | NC_SESSION_CALLHOME;
    (*session)->host = lydict_insert(server_opts.ctx, host, 0);
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
#ifdef NC_ENABLED_SSH
    if (ti == NC_TI_LIBSSH) {
        /* OPTS LOCK */
        pthread_mutex_lock(&ssh_ch_opts_lock);

        (*session)->ti_opts = &ssh_ch_opts;
        ret = nc_accept_ssh_session(*session, sock, timeout);
        (*session)->ti_opts = NULL;

        /* OPTS UNLOCK */
        pthread_mutex_unlock(&ssh_ch_opts_lock);

        if (ret < 1) {
            goto fail;
        }
    } else
#endif
#ifdef NC_ENABLED_TLS
    if (ti == NC_TI_OPENSSL) {
        /* OPTS LOCK */
        pthread_mutex_lock(&tls_ch_opts_lock);

        (*session)->ti_opts = &tls_ch_opts;
        ret = nc_accept_tls_session(*session, sock, timeout);
        (*session)->ti_opts = NULL;

        /* OPTS UNLOCK */
        pthread_mutex_unlock(&tls_ch_opts_lock);

        if (ret < 1) {
            goto fail;
        }
    } else
#endif
    {
        ERRINT;
        close(sock);
        ret = -1;
        goto fail;
    }

    /* assign new SID atomically */
    /* LOCK */
    pthread_spin_lock(&server_opts.sid_lock);
    (*session)->id = server_opts.new_session_id++;
    /* UNLOCK */
    pthread_spin_unlock(&server_opts.sid_lock);

    /* NETCONF handshake */
    if (nc_handshake(*session)) {
        ret = -1;
        goto fail;
    }
    (*session)->status = NC_STATUS_RUNNING;

    return 1;

fail:
    nc_session_free(*session);
    *session = NULL;
    return ret;
}

#endif /* NC_ENABLED_SSH || NC_ENABLED_TLS */
