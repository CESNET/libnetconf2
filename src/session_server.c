/**
 * \file session_server.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 server session manipulation functions
 *
 * Copyright (c) 2015 - 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE /* signals, threads, SO_PEERCRED */

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <pwd.h>

#include "libnetconf.h"
#include "session_server.h"
#include "session_server_ch.h"

struct nc_server_opts server_opts = {
#ifdef NC_ENABLED_SSH
    .authkey_lock = PTHREAD_MUTEX_INITIALIZER,
#endif
    .bind_lock = PTHREAD_MUTEX_INITIALIZER,
    .endpt_lock = PTHREAD_RWLOCK_INITIALIZER,
    .ch_client_lock = PTHREAD_RWLOCK_INITIALIZER
};

static nc_rpc_clb global_rpc_clb = NULL;

struct nc_endpt *
nc_server_endpt_lock_get(const char *name, NC_TRANSPORT_IMPL ti, uint16_t *idx)
{
    uint16_t i;
    struct nc_endpt *endpt = NULL;

    if (!name) {
        ERRARG("endpt_name");
        return NULL;
    }

    /* WRITE LOCK */
    pthread_rwlock_wrlock(&server_opts.endpt_lock);

    for (i = 0; i < server_opts.endpt_count; ++i) {
        if (!strcmp(server_opts.endpts[i].name, name) && (!ti || (server_opts.endpts[i].ti == ti))) {
            endpt = &server_opts.endpts[i];
            break;
        }
    }

    if (!endpt) {
        ERR("Endpoint \"%s\" was not found.", name);
        /* UNLOCK */
        pthread_rwlock_unlock(&server_opts.endpt_lock);
        return NULL;
    }

    if (idx) {
        *idx = i;
    }

    return endpt;
}

struct nc_ch_endpt *
nc_server_ch_client_lock(const char *name, const char *endpt_name, NC_TRANSPORT_IMPL ti, struct nc_ch_client **client_p)
{
    uint16_t i, j;
    struct nc_ch_client *client = NULL;
    struct nc_ch_endpt *endpt = NULL;

    *client_p = NULL;

    if (!name) {
        ERRARG("client_name");
        return NULL;
    }

    /* READ LOCK */
    pthread_rwlock_rdlock(&server_opts.ch_client_lock);

    for (i = 0; i < server_opts.ch_client_count; ++i) {
        if (!strcmp(server_opts.ch_clients[i].name, name)) {
            client = &server_opts.ch_clients[i];
            if (!endpt_name && !ti) {
                /* return only client */
                break;
            }
            for (j = 0; j < client->ch_endpt_count; ++j) {
                if (!strcmp(client->ch_endpts[j].name, endpt_name) && (!ti || (ti == client->ch_endpts[j].ti))) {
                    endpt = &client->ch_endpts[j];
                    break;
                }
            }
            break;
        }
    }

    if (!client) {
        ERR("Call Home client \"%s\" was not found.", name);

        /* READ UNLOCK */
        pthread_rwlock_unlock(&server_opts.ch_client_lock);
    } else if (endpt_name && ti && !endpt) {
        ERR("Call Home client \"%s\" endpoint \"%s\" was not found.", name, endpt_name);

        /* READ UNLOCK */
        pthread_rwlock_unlock(&server_opts.ch_client_lock);
    } else {
        /* CH CLIENT LOCK */
        pthread_mutex_lock(&client->lock);

        *client_p = client;
    }

    return endpt;
}

void
nc_server_ch_client_unlock(struct nc_ch_client *client)
{
    /* CH CLIENT UNLOCK */
    pthread_mutex_unlock(&client->lock);

    /* READ UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);
}

API void
nc_session_set_term_reason(struct nc_session *session, NC_SESSION_TERM_REASON reason)
{
    if (!session) {
        ERRARG("session");
        return;
    } else if (!reason) {
        ERRARG("reason");
        return;
    }

    if ((reason != NC_SESSION_TERM_KILLED) && (session->term_reason == NC_SESSION_TERM_KILLED)) {
        session->killed_by = 0;
    }
    session->term_reason = reason;
}

API void
nc_session_set_killed_by(struct nc_session *session, uint32_t sid)
{
    if (!session || (session->term_reason != NC_SESSION_TERM_KILLED)) {
        ERRARG("session");
        return;
    } else if (!sid) {
        ERRARG("sid");
        return;
    }

    session->killed_by = sid;
}

API void
nc_session_set_status(struct nc_session *session, NC_STATUS status)
{
    if (!session) {
        ERRARG("session");
        return;
    } else if (!status) {
        ERRARG("status");
        return;
    }

    session->status = status;
}

int
nc_sock_listen_inet(const char *address, uint16_t port, struct nc_keepalives *ka)
{
    int opt;
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

    /* these options will be inherited by accepted sockets */
    opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) == -1) {
        ERR("Could not set SO_REUSEADDR socket option (%s).", strerror(errno));
        goto fail;
    }
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof opt) == -1) {
        ERR("Could not set TCP_NODELAY socket option (%s).", strerror(errno));
        goto fail;
    }

    if (nc_sock_enable_keepalive(sock, ka)) {
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
nc_sock_listen_unix(const char *address, const struct nc_server_unix_opts *opts)
{
    struct sockaddr_un sun;
    int sock = -1;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        ERR("Failed to create socket (%s).", strerror(errno));
        goto fail;
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", address);

    unlink(sun.sun_path);
    if (bind(sock, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
        ERR("Could not bind \"%s\" (%s).", address, strerror(errno));
        goto fail;
    }

    if (opts->mode != (mode_t)-1) {
        if (chmod(sun.sun_path, opts->mode) < 0) {
            ERR("Failed to set unix socket permissions (%s).", strerror(errno));
            goto fail;
        }
    }

    if (opts->uid != (uid_t)-1 || opts->gid != (gid_t)-1) {
        if (chown(sun.sun_path, opts->uid, opts->gid) < 0) {
            ERR("Failed to set unix socket uid/gid (%s).", strerror(errno));
            goto fail;
        }
    }

    if (listen(sock, NC_REVERSE_QUEUE) == -1) {
        ERR("Unable to start listening on \"%s\" (%s).", address, strerror(errno));
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
    sigset_t sigmask, origmask;
    uint16_t i, j, pfd_count;
    struct pollfd *pfd;
    struct sockaddr_storage saddr;
    socklen_t saddr_len = sizeof(saddr);
    int ret, sock = -1, flags;

    pfd = malloc(bind_count * sizeof *pfd);
    if (!pfd) {
        ERRMEM;
        return -1;
    }

    for (i = 0, pfd_count = 0; i < bind_count; ++i) {
        if (binds[i].sock < 0) {
            /* invalid socket */
            continue;
        }
        if (binds[i].pollin) {
            binds[i].pollin = 0;
            /* leftover pollin */
            sock = binds[i].sock;
            break;
        }
        pfd[pfd_count].fd = binds[i].sock;
        pfd[pfd_count].events = POLLIN;
        pfd[pfd_count].revents = 0;

        ++pfd_count;
    }

    if (sock == -1) {
        /* poll for a new connection */
        sigfillset(&sigmask);
        pthread_sigmask(SIG_SETMASK, &sigmask, &origmask);
        ret = poll(pfd, pfd_count, timeout);
        pthread_sigmask(SIG_SETMASK, &origmask, NULL);

        if (!ret) {
            /* we timeouted */
            free(pfd);
            return 0;
        } else if (ret == -1) {
            ERR("Poll failed (%s).", strerror(errno));
            free(pfd);
            return -1;
        }

        for (i = 0, j = 0; j < pfd_count; ++i, ++j) {
            /* adjust i so that indices in binds and pfd always match */
            while (binds[i].sock != pfd[j].fd) {
                ++i;
            }

            if (pfd[j].revents & POLLIN) {
                --ret;

                if (!ret) {
                    /* the last socket with an event, use it */
                    sock = pfd[j].fd;
                    break;
                } else {
                    /* just remember the event for next time */
                    binds[i].pollin = 1;
                }
            }
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
    VRB("Accepted a connection on %s:%u.", binds[i].address, binds[i].port);

    /* make the socket non-blocking */
    if (((flags = fcntl(ret, F_GETFL)) == -1) || (fcntl(ret, F_SETFL, flags | O_NONBLOCK) == -1)) {
        ERR("Fcntl failed (%s).", strerror(errno));
        close(ret);
        return -1;
    }

    if (idx) {
        *idx = i;
    }

    /* host was requested */
    if (host) {
        if (saddr.ss_family == AF_INET) {
            *host = malloc(INET_ADDRSTRLEN);
            if (*host) {
                if (!inet_ntop(AF_INET, &((struct sockaddr_in *)&saddr)->sin_addr.s_addr, *host, INET_ADDRSTRLEN)) {
                    ERR("inet_ntop failed (%s).", strerror(errno));
                    free(*host);
                    *host = NULL;
                }

                if (port) {
                    *port = ntohs(((struct sockaddr_in *)&saddr)->sin_port);
                }
            } else {
                ERRMEM;
            }
        } else if (saddr.ss_family == AF_INET6) {
            *host = malloc(INET6_ADDRSTRLEN);
            if (*host) {
                if (!inet_ntop(AF_INET6, ((struct sockaddr_in6 *)&saddr)->sin6_addr.s6_addr, *host, INET6_ADDRSTRLEN)) {
                    ERR("inet_ntop failed (%s).", strerror(errno));
                    free(*host);
                    *host = NULL;
                }

                if (port) {
                    *port = ntohs(((struct sockaddr_in6 *)&saddr)->sin6_port);
                }
            } else {
                ERRMEM;
            }
        } else if (saddr.ss_family == AF_UNIX) {
            *host = strdup(((struct sockaddr_un *)&saddr)->sun_path);
            if (*host) {
                if (port) {
                    *port = 0;
                }
            } else {
                ERRMEM;
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
            if (version && version[0] == '\0') {
                version = NULL;
            }
        } else if (!strcmp(child->schema->name, "format")) {
            format = ((struct lyd_node_leaf_list *)child)->value_str;
        }
    }
    VRB("Schema \"%s\" was requested.", identifier);

    /* check version */
    if (version && (strlen(version) != 10) && strcmp(version, "1.0")) {
        err = nc_err(NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, "The requested version is not supported.", "en");
        return nc_server_reply_err(err);
    }

    /* check and get module with the name identifier */
    module = ly_ctx_get_module(server_opts.ctx, identifier, version, 0);
    if (!module) {
        module = (const struct lys_module *)ly_ctx_get_submodule(server_opts.ctx, NULL, NULL, identifier, version);
    }
    if (!module) {
        err = nc_err(NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, "The requested schema was not found.", "en");
        return nc_server_reply_err(err);
    }

    /* check format */
    if (!format || !strcmp(format, "ietf-netconf-monitoring:yang")) {
        lys_print_mem(&model_data, module, LYS_OUT_YANG, NULL, 0, 0);
    } else if (!strcmp(format, "ietf-netconf-monitoring:yin")) {
        lys_print_mem(&model_data, module, LYS_OUT_YIN, NULL, 0, 0);
    } else {
        err = nc_err(NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, "The requested format is not supported.", "en");
        return nc_server_reply_err(err);
    }
    if (!model_data) {
        ERRINT;
        return NULL;
    }

    sdata = ly_ctx_get_node(server_opts.ctx, NULL, "/ietf-netconf-monitoring:get-schema/data", 1);
    if (!sdata) {
        ERRINT;
        free(model_data);
        return NULL;
    }

    data = lyd_new_path(NULL, server_opts.ctx, "/ietf-netconf-monitoring:get-schema/data", model_data,
                        LYD_ANYDATA_STRING, LYD_PATH_OPT_OUTPUT);
    if (!data || lyd_validate(&data, LYD_OPT_RPCREPLY, NULL)) {
        ERRINT;
        free(model_data);
        return NULL;
    }

    return nc_server_reply_data(data, NC_WD_EXPLICIT, NC_PARAMTYPE_FREE);
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
    pthread_rwlockattr_t  attr;

    if (!ctx) {
        ERRARG("ctx");
        return -1;
    }

    nc_init();

    /* set default <get-schema> callback if not specified */
    rpc = ly_ctx_get_node(ctx, NULL, "/ietf-netconf-monitoring:get-schema", 0);
    if (rpc && !rpc->priv) {
        lys_set_private(rpc, nc_clb_default_get_schema);
    }

    /* set default <close-session> callback if not specififed */
    rpc = ly_ctx_get_node(ctx, NULL, "/ietf-netconf:close-session", 0);
    if (rpc && !rpc->priv) {
        lys_set_private(rpc, nc_clb_default_close_session);
    }

    server_opts.ctx = ctx;

    server_opts.new_session_id = 1;
    server_opts.new_client_id = 1;

    errno=0;

    if (pthread_rwlockattr_init(&attr) == 0) {
#if defined(HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)
        if (pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP) == 0) {
            if (pthread_rwlock_init(&server_opts.endpt_lock, &attr) != 0) {
                ERR("%s: failed to init rwlock(%s).", __FUNCTION__, strerror(errno));
            }
            if (pthread_rwlock_init(&server_opts.ch_client_lock, &attr) != 0) {
                ERR("%s: failed to init rwlock(%s).", __FUNCTION__, strerror(errno));
            }
        } else {
            ERR("%s: failed set attribute (%s).", __FUNCTION__, strerror(errno));
        }
#endif
        pthread_rwlockattr_destroy(&attr);
    } else {
        ERR("%s: failed init attribute (%s).", __FUNCTION__, strerror(errno));
    }
    return 0;
}

API void
nc_server_destroy(void)
{
    unsigned int i;

    for (i = 0; i < server_opts.capabilities_count; i++) {
        lydict_remove(server_opts.ctx, server_opts.capabilities[i]);
    }
    free(server_opts.capabilities);
    server_opts.capabilities = NULL;
    server_opts.capabilities_count = 0;

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
    nc_server_del_endpt(NULL, 0);
    nc_server_ch_del_client(NULL);
#endif
#ifdef NC_ENABLED_SSH
    if (server_opts.passwd_auth_data && server_opts.passwd_auth_data_free) {
        server_opts.passwd_auth_data_free(server_opts.passwd_auth_data);
    }
    server_opts.passwd_auth_data = NULL;
    server_opts.passwd_auth_data_free = NULL;

    nc_server_ssh_del_authkey(NULL, NULL, 0, NULL);

    if (server_opts.hostkey_data && server_opts.hostkey_data_free) {
        server_opts.hostkey_data_free(server_opts.hostkey_data);
    }
    server_opts.hostkey_data = NULL;
    server_opts.hostkey_data_free = NULL;
#endif
#ifdef NC_ENABLED_TLS
    if (server_opts.server_cert_data && server_opts.server_cert_data_free) {
        server_opts.server_cert_data_free(server_opts.server_cert_data);
    }
    server_opts.server_cert_data = NULL;
    server_opts.server_cert_data_free = NULL;
    if (server_opts.trusted_cert_list_data && server_opts.trusted_cert_list_data_free) {
        server_opts.trusted_cert_list_data_free(server_opts.trusted_cert_list_data);
    }
    server_opts.trusted_cert_list_data = NULL;
    server_opts.trusted_cert_list_data_free = NULL;
#endif
    nc_destroy();
}

API int
nc_server_set_capab_withdefaults(NC_WD_MODE basic_mode, int also_supported)
{
    if (!basic_mode || (basic_mode == NC_WD_ALL_TAG)) {
        ERRARG("basic_mode");
        return -1;
    } else if (also_supported && !(also_supported & (NC_WD_ALL | NC_WD_ALL_TAG | NC_WD_TRIM | NC_WD_EXPLICIT))) {
        ERRARG("also_supported");
        return -1;
    }

    server_opts.wd_basic_mode = basic_mode;
    server_opts.wd_also_supported = also_supported;
    return 0;
}

API void
nc_server_get_capab_withdefaults(NC_WD_MODE *basic_mode, int *also_supported)
{
    if (!basic_mode && !also_supported) {
        ERRARG("basic_mode and also_supported");
        return;
    }

    if (basic_mode) {
        *basic_mode = server_opts.wd_basic_mode;
    }
    if (also_supported) {
        *also_supported = server_opts.wd_also_supported;
    }
}

API int
nc_server_set_capability(const char *value)
{
    const char **new;

    if (!value || !value[0]) {
        ERRARG("value must not be empty");
        return EXIT_FAILURE;
    }

    server_opts.capabilities_count++;
    new = realloc(server_opts.capabilities, server_opts.capabilities_count * sizeof *server_opts.capabilities);
    if (!new) {
        ERRMEM;
        return EXIT_FAILURE;
    }
    server_opts.capabilities = new;
    server_opts.capabilities[server_opts.capabilities_count - 1] = lydict_insert(server_opts.ctx, value, 0);

    return EXIT_SUCCESS;
}

API void
nc_server_set_hello_timeout(uint16_t hello_timeout)
{
    server_opts.hello_timeout = hello_timeout;
}

API uint16_t
nc_server_get_hello_timeout(void)
{
    return server_opts.hello_timeout;
}

API void
nc_server_set_idle_timeout(uint16_t idle_timeout)
{
    server_opts.idle_timeout = idle_timeout;
}

API uint16_t
nc_server_get_idle_timeout(void)
{
    return server_opts.idle_timeout;
}

API NC_MSG_TYPE
nc_accept_inout(int fdin, int fdout, const char *username, struct nc_session **session)
{
    NC_MSG_TYPE msgtype;
    struct timespec ts_cur;

    if (!server_opts.ctx) {
        ERRINIT;
        return NC_MSG_ERROR;
    } else if (fdin < 0) {
        ERRARG("fdin");
        return NC_MSG_ERROR;
    } else if (fdout < 0) {
        ERRARG("fdout");
        return NC_MSG_ERROR;
    } else if (!username) {
        ERRARG("username");
        return NC_MSG_ERROR;
    } else if (!session) {
        ERRARG("session");
        return NC_MSG_ERROR;
    }

    /* prepare session structure */
    *session = nc_new_session(NC_SERVER, 0);
    if (!(*session)) {
        ERRMEM;
        return NC_MSG_ERROR;
    }
    (*session)->status = NC_STATUS_STARTING;

    /* transport specific data */
    (*session)->ti_type = NC_TI_FD;
    (*session)->ti.fd.in = fdin;
    (*session)->ti.fd.out = fdout;

    /* assign context (dicionary needed for handshake) */
    (*session)->flags = NC_SESSION_SHAREDCTX;
    (*session)->ctx = server_opts.ctx;

    /* assign new SID atomically */
    (*session)->id = ATOMIC_INC(&server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(*session);
    if (msgtype != NC_MSG_HELLO) {
        nc_session_free(*session, NULL);
        *session = NULL;
        return msgtype;
    }

    nc_gettimespec_mono(&ts_cur);
    (*session)->opts.server.last_rpc = ts_cur.tv_sec;
    nc_gettimespec_real(&ts_cur);
    (*session)->opts.server.session_start = ts_cur.tv_sec;

    (*session)->status = NC_STATUS_RUNNING;

    return msgtype;
}

static void
nc_ps_queue_add_id(struct nc_pollsession *ps, uint8_t *id)
{
    uint8_t q_last;

    if (ps->queue_len == NC_PS_QUEUE_SIZE) {
        ERRINT;
        return;
    }

    /* get a unique queue value (by adding 1 to the last added value, if any) */
    if (ps->queue_len) {
        q_last = (ps->queue_begin + ps->queue_len - 1) % NC_PS_QUEUE_SIZE;
        *id = ps->queue[q_last] + 1;
    } else {
        *id = 0;
    }

    /* add the id into the queue */
    ++ps->queue_len;
    q_last = (ps->queue_begin + ps->queue_len - 1) % NC_PS_QUEUE_SIZE;
    ps->queue[q_last] = *id;
}

static void
nc_ps_queue_remove_id(struct nc_pollsession *ps, uint8_t id)
{
    uint8_t i, q_idx, found = 0;

    for (i = 0; i < ps->queue_len; ++i) {
        /* get the actual queue idx */
        q_idx = (ps->queue_begin + i) % NC_PS_QUEUE_SIZE;

        if (found) {
            if (ps->queue[q_idx] == id) {
                /* another equal value, simply cannot be */
                ERRINT;
            }
            if (found == 2) {
                /* move the following values */
                ps->queue[q_idx ? q_idx - 1 : NC_PS_QUEUE_SIZE - 1] = ps->queue[q_idx];
            }
        } else if (ps->queue[q_idx] == id) {
            /* found our id, there can be no more equal valid values */
            if (i == 0) {
                found = 1;
            } else {
                /* this is not okay, our id is in the middle of the queue */
                found = 2;
            }
        }
    }
    if (!found) {
        ERRINT;
        return;
    }

    --ps->queue_len;
    if (found == 1) {
        /* remove the id by moving the queue, otherwise all the values in the queue were moved */
        ps->queue_begin = (ps->queue_begin + 1) % NC_PS_QUEUE_SIZE;
    }
}

int
nc_ps_lock(struct nc_pollsession *ps, uint8_t *id, const char *func)
{
    int ret;
    struct timespec ts;

    nc_gettimespec_real(&ts);
    nc_addtimespec(&ts, NC_PS_LOCK_TIMEOUT);

    /* LOCK */
    ret = pthread_mutex_timedlock(&ps->lock, &ts);
    if (ret) {
        ERR("%s: failed to lock a pollsession (%s).", func, strerror(ret));
        return -1;
    }

    /* check that the queue is long enough */
    if (ps->queue_len == NC_PS_QUEUE_SIZE) {
        ERR("%s: pollsession queue size (%d) too small.", func, NC_PS_QUEUE_SIZE);
        pthread_mutex_unlock(&ps->lock);
        return -1;
    }

    /* add ourselves into the queue */
    nc_ps_queue_add_id(ps, id);
    DBG("PS 0x%p TID %lu queue: added %u, head %u, lenght %u", ps, (long unsigned int)pthread_self(), *id,
            ps->queue[ps->queue_begin], ps->queue_len);

    /* is it our turn? */
    while (ps->queue[ps->queue_begin] != *id) {
        nc_gettimespec_real(&ts);
        nc_addtimespec(&ts, NC_PS_QUEUE_TIMEOUT);

        ret = pthread_cond_timedwait(&ps->cond, &ps->lock, &ts);
        if (ret) {
            /**
             * This may happen when another thread releases the lock and broadcasts the condition
             * and this thread had already timed out. When this thread is scheduled, it returns timed out error
             * but when actually this thread was ready for condition.
             */
            if ((ETIMEDOUT == ret) && (ps->queue[ps->queue_begin] == *id)) {
                break;
            }

            ERR("%s: failed to wait for a pollsession condition (%s).", func, strerror(ret));
            /* remove ourselves from the queue */
            nc_ps_queue_remove_id(ps, *id);
            pthread_mutex_unlock(&ps->lock);
            return -1;
        }
    }

    /* UNLOCK */
    pthread_mutex_unlock(&ps->lock);

    return 0;
}

int
nc_ps_unlock(struct nc_pollsession *ps, uint8_t id, const char *func)
{
    int ret;
    struct timespec ts;

    nc_gettimespec_real(&ts);
    nc_addtimespec(&ts, NC_PS_LOCK_TIMEOUT);

    /* LOCK */
    ret = pthread_mutex_timedlock(&ps->lock, &ts);
    if (ret) {
        ERR("%s: failed to lock a pollsession (%s).", func, strerror(ret));
        ret = -1;
    }

    /* we must be the first, it was our turn after all, right? */
    if (ps->queue[ps->queue_begin] != id) {
        ERRINT;
        /* UNLOCK */
        if (!ret) {
            pthread_mutex_unlock(&ps->lock);
        }
        return -1;
    }

    /* remove ourselves from the queue */
    nc_ps_queue_remove_id(ps, id);
    DBG("PS 0x%p TID %lu queue: removed %u, head %u, lenght %u", ps, (long unsigned int)pthread_self(), id,
            ps->queue[ps->queue_begin], ps->queue_len);

    /* broadcast to all other threads that the queue moved */
    pthread_cond_broadcast(&ps->cond);

    /* UNLOCK */
    if (!ret) {
        pthread_mutex_unlock(&ps->lock);
    }

    return ret;
}

API struct nc_pollsession *
nc_ps_new(void)
{
    struct nc_pollsession *ps;

    ps = calloc(1, sizeof(struct nc_pollsession));
    if (!ps) {
        ERRMEM;
        return NULL;
    }
    pthread_cond_init(&ps->cond, NULL);
    pthread_mutex_init(&ps->lock, NULL);

    return ps;
}

API void
nc_ps_free(struct nc_pollsession *ps)
{
    uint16_t i;

    if (!ps) {
        return;
    }

    if (ps->queue_len) {
        ERR("FATAL: Freeing a pollsession structure that is currently being worked with!");
    }

    for (i = 0; i < ps->session_count; i++) {
        free(ps->sessions[i]);
    }

    free(ps->sessions);
    pthread_mutex_destroy(&ps->lock);
    pthread_cond_destroy(&ps->cond);

    free(ps);
}

API int
nc_ps_add_session(struct nc_pollsession *ps, struct nc_session *session)
{
    uint8_t q_id;

    if (!ps) {
        ERRARG("ps");
        return -1;
    } else if (!session) {
        ERRARG("session");
        return -1;
    }

    /* LOCK */
    if (nc_ps_lock(ps, &q_id, __func__)) {
        return -1;
    }

    ++ps->session_count;
    ps->sessions = nc_realloc(ps->sessions, ps->session_count * sizeof *ps->sessions);
    if (!ps->sessions) {
        ERRMEM;
        /* UNLOCK */
        nc_ps_unlock(ps, q_id, __func__);
        return -1;
    }
    ps->sessions[ps->session_count - 1] = calloc(1, sizeof **ps->sessions);
    if (!ps->sessions[ps->session_count - 1]) {
        ERRMEM;
        --ps->session_count;
        /* UNLOCK */
        nc_ps_unlock(ps, q_id, __func__);
        return -1;
    }
    ps->sessions[ps->session_count - 1]->session = session;
    ps->sessions[ps->session_count - 1]->state = NC_PS_STATE_NONE;

    /* UNLOCK */
    return nc_ps_unlock(ps, q_id, __func__);
}

static int
_nc_ps_del_session(struct nc_pollsession *ps, struct nc_session *session, int index)
{
    uint16_t i;

    if (index >= 0) {
        i = (uint16_t)index;
        goto remove;
    }
    for (i = 0; i < ps->session_count; ++i) {
        if (ps->sessions[i]->session == session) {
remove:
            --ps->session_count;
            if (i <= ps->session_count) {
                free(ps->sessions[i]);
                ps->sessions[i] = ps->sessions[ps->session_count];
            }
            if (!ps->session_count) {
                free(ps->sessions);
                ps->sessions = NULL;
            }
            ps->last_event_session = 0;
            return 0;
        }
    }

    return -1;
}

API int
nc_ps_del_session(struct nc_pollsession *ps, struct nc_session *session)
{
    uint8_t q_id;
    int ret, ret2;

    if (!ps) {
        ERRARG("ps");
        return -1;
    } else if (!session) {
        ERRARG("session");
        return -1;
    }

    /* LOCK */
    if (nc_ps_lock(ps, &q_id, __func__)) {
        return -1;
    }

    ret = _nc_ps_del_session(ps, session, -1);

    /* UNLOCK */
    ret2 = nc_ps_unlock(ps, q_id, __func__);

    return (ret || ret2 ? -1 : 0);
}

API struct nc_session *
nc_ps_get_session(const struct nc_pollsession *ps, uint16_t idx)
{
    uint8_t q_id;
    struct nc_session *ret = NULL;

    if (!ps) {
        ERRARG("ps");
        return NULL;
    }

    /* LOCK */
    if (nc_ps_lock((struct nc_pollsession *)ps, &q_id, __func__)) {
        return NULL;
    }

    if (idx < ps->session_count) {
        ret = ps->sessions[idx]->session;
    }

    /* UNLOCK */
    nc_ps_unlock((struct nc_pollsession *)ps, q_id, __func__);

    return ret;
}

API uint16_t
nc_ps_session_count(struct nc_pollsession *ps)
{
    uint8_t q_id;
    uint16_t session_count;

    if (!ps) {
        ERRARG("ps");
        return 0;
    }

    /* LOCK (just for memory barrier so that we read the current value) */
    if (nc_ps_lock((struct nc_pollsession *)ps, &q_id, __func__)) {
        return 0;
    }

    session_count = ps->session_count;

    /* UNLOCK */
    nc_ps_unlock((struct nc_pollsession *)ps, q_id, __func__);

    return session_count;
}

/* should be called holding the session RPC lock! IO lock will be acquired as needed
 * returns: NC_PSPOLL_ERROR,
 *          NC_PSPOLL_BAD_RPC,
 *          NC_PSPOLL_BAD_RPC | NC_PSPOLL_REPLY_ERROR,
 *          NC_PSPOLL_RPC
 */
static int
nc_server_recv_rpc_io(struct nc_session *session, int io_timeout, struct nc_server_rpc **rpc)
{
    struct lyxml_elem *xml = NULL;
    NC_MSG_TYPE msgtype;
    struct nc_server_reply *reply = NULL;
    int ret;

    if (!session) {
        ERRARG("session");
        return NC_PSPOLL_ERROR;
    } else if (!rpc) {
        ERRARG("rpc");
        return NC_PSPOLL_ERROR;
    } else if ((session->status != NC_STATUS_RUNNING) || (session->side != NC_SERVER)) {
        ERR("Session %u: invalid session to receive RPCs.", session->id);
        return NC_PSPOLL_ERROR;
    }

    msgtype = nc_read_msg_io(session, io_timeout, &xml, 0);

    switch (msgtype) {
    case NC_MSG_RPC:
        *rpc = calloc(1, sizeof **rpc);
        if (!*rpc) {
            ERRMEM;
            goto error;
        }

        ly_errno = LY_SUCCESS;
        (*rpc)->tree = lyd_parse_xml(server_opts.ctx, &xml->child,
                                     LYD_OPT_RPC | LYD_OPT_DESTRUCT | LYD_OPT_NOEXTDEPS | LYD_OPT_STRICT, NULL);
        if (!(*rpc)->tree) {
            /* parsing RPC failed */
            reply = nc_server_reply_err(nc_err_libyang(server_opts.ctx));
            ret = nc_write_msg_io(session, io_timeout, NC_MSG_REPLY, xml, reply);
            nc_server_reply_free(reply);
            if (ret == -1) {
                ERR("Session %u: failed to write reply.", session->id);
            }
            ret = NC_PSPOLL_REPLY_ERROR | NC_PSPOLL_BAD_RPC;
        } else {
            ret = NC_PSPOLL_RPC;
        }
        (*rpc)->root = xml;
        break;
    case NC_MSG_HELLO:
        ERR("Session %u: received another <hello> message.", session->id);
        ret = NC_PSPOLL_BAD_RPC;
        goto error;
    case NC_MSG_REPLY:
        ERR("Session %u: received <rpc-reply> from a NETCONF client.", session->id);
        ret = NC_PSPOLL_BAD_RPC;
        goto error;
    case NC_MSG_NOTIF:
        ERR("Session %u: received <notification> from a NETCONF client.", session->id);
        ret = NC_PSPOLL_BAD_RPC;
        goto error;
    default:
        /* NC_MSG_ERROR,
         * NC_MSG_WOULDBLOCK and NC_MSG_NONE is not returned by nc_read_msg_io()
         */
        ret = NC_PSPOLL_ERROR;
        break;
    }

    return ret;

error:
    /* cleanup */
    lyxml_free(server_opts.ctx, xml);

    return NC_PSPOLL_ERROR;
}

API void
nc_set_global_rpc_clb(nc_rpc_clb clb)
{
    global_rpc_clb = clb;
}

API NC_MSG_TYPE
nc_server_notif_send(struct nc_session *session, struct nc_server_notif *notif, int timeout)
{
    NC_MSG_TYPE ret;

    /* check parameters */
    if (!session || (session->side != NC_SERVER) || !session->opts.server.ntf_status) {
        ERRARG("session");
        return NC_MSG_ERROR;
    } else if (!notif || !notif->tree || !notif->eventtime) {
        ERRARG("notif");
        return NC_MSG_ERROR;
    }

    /* we do not need RPC lock for this, IO lock will be acquired properly */
    ret = nc_write_msg_io(session, timeout, NC_MSG_NOTIF, notif);
    if (ret == NC_MSG_ERROR) {
        ERR("Session %u: failed to write notification.", session->id);
    }

    return ret;
}

/* must be called holding the session RPC lock! IO lock will be acquired as needed
 * returns: NC_PSPOLL_ERROR,
 *          NC_PSPOLL_ERROR | NC_PSPOLL_REPLY_ERROR,
 *          NC_PSPOLL_REPLY_ERROR,
 *          0
 */
static int
nc_server_send_reply_io(struct nc_session *session, int io_timeout, struct nc_server_rpc *rpc)
{
    nc_rpc_clb clb;
    struct nc_server_reply *reply;
    struct lys_node *rpc_act = NULL;
    struct lyd_node *next, *elem;
    int ret = 0;
    NC_MSG_TYPE r;

    if (!rpc) {
        ERRINT;
        return NC_PSPOLL_ERROR;
    }

    if (rpc->tree->schema->nodetype == LYS_RPC) {
        /* RPC */
        rpc_act = rpc->tree->schema;
    } else {
        /* action */
        LY_TREE_DFS_BEGIN(rpc->tree, next, elem) {
            if (elem->schema->nodetype == LYS_ACTION) {
                rpc_act = elem->schema;
                break;
            }
            LY_TREE_DFS_END(rpc->tree, next, elem);
        }
        if (!rpc_act) {
            ERRINT;
            return NC_PSPOLL_ERROR;
        }
    }

    if (!rpc_act->priv) {
        if (!global_rpc_clb) {
            /* no callback, reply with a not-implemented error */
            reply = nc_server_reply_err(nc_err(NC_ERR_OP_NOT_SUPPORTED, NC_ERR_TYPE_PROT));
        } else {
          reply = global_rpc_clb(rpc->tree, session);
        }
    } else {
        clb = (nc_rpc_clb)rpc_act->priv;
        reply = clb(rpc->tree, session);
    }

    if (!reply) {
        reply = nc_server_reply_err(nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP));
    }
    r = nc_write_msg_io(session, io_timeout, NC_MSG_REPLY, rpc->root, reply);
    if (reply->type == NC_RPL_ERROR) {
        ret |= NC_PSPOLL_REPLY_ERROR;
    }
    nc_server_reply_free(reply);

    if (r != NC_MSG_REPLY) {
        ERR("Session %u: failed to write reply.", session->id);
        ret |= NC_PSPOLL_ERROR;
    }

    /* special case if term_reason was set in callback, last reply was sent (needed for <close-session> if nothing else) */
    if ((session->status == NC_STATUS_RUNNING) && (session->term_reason != NC_SESSION_TERM_NONE)) {
        session->status = NC_STATUS_INVALID;
    }

    return ret;
}

/* session must be running and session RPC lock held!
 * returns: NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR, (msg filled)
 *          NC_PSPOLL_ERROR, (msg filled)
 *          NC_PSPOLL_TIMEOUT,
 *          NC_PSPOLL_RPC (some application data available),
 *          NC_PSPOLL_SSH_CHANNEL,
 *          NC_PSPOLL_SSH_MSG
 */
static int
nc_ps_poll_session_io(struct nc_session *session, int io_timeout, time_t now_mono, char *msg)
{
    struct pollfd pfd;
    int r, ret = 0;
#ifdef NC_ENABLED_SSH
    struct nc_session *new;
#endif

    /* check timeout first */
    if (!(session->flags & NC_SESSION_CALLHOME) && !session->opts.server.ntf_status && server_opts.idle_timeout
            && (now_mono >= session->opts.server.last_rpc + server_opts.idle_timeout)) {
        sprintf(msg, "session idle timeout elapsed");
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_TIMEOUT;
        return NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
    }

    r = nc_session_io_lock(session, io_timeout, __func__);
    if (r < 0) {
        sprintf(msg, "session IO lock failed to be acquired");
        return NC_PSPOLL_ERROR;
    } else if (!r) {
        return NC_PSPOLL_TIMEOUT;
    }

    switch (session->ti_type) {
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
        r = ssh_channel_poll_timeout(session->ti.libssh.channel, 0, 0);
        if (r == SSH_EOF) {
            sprintf(msg, "SSH channel unexpected EOF");
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_DROPPED;
            ret = NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
        } else if (r == SSH_ERROR) {
            sprintf(msg, "SSH channel poll error (%s)", ssh_get_error(session->ti.libssh.session));
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_OTHER;
            ret = NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
        } else if (!r) {
            if (session->flags & NC_SESSION_SSH_NEW_MSG) {
                /* new SSH message */
                session->flags &= ~NC_SESSION_SSH_NEW_MSG;
                if (session->ti.libssh.next) {
                    for (new = session->ti.libssh.next; new != session; new = new->ti.libssh.next) {
                        if ((new->status == NC_STATUS_STARTING) && new->ti.libssh.channel
                                && (new->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
                            /* new NETCONF SSH channel */
                            ret = NC_PSPOLL_SSH_CHANNEL;
                            break;
                        }
                    }
                    if (new != session) {
                        break;
                    }
                }

                /* just some SSH message */
                ret = NC_PSPOLL_SSH_MSG;
            } else {
                ret = NC_PSPOLL_TIMEOUT;
            }
        } else {
            /* we have some application data */
            ret = NC_PSPOLL_RPC;
        }
        break;
#endif
#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
        r = SSL_pending(session->ti.tls);
        if (!r) {
            /* no data pending in the SSL buffer, poll fd */
            pfd.fd = SSL_get_rfd(session->ti.tls);
            if (pfd.fd < 0) {
                sprintf(msg, "internal error (%s:%d)", __FILE__, __LINE__);
                ret = NC_PSPOLL_ERROR;
                break;
            }
            pfd.events = POLLIN;
            pfd.revents = 0;
            r = poll(&pfd, 1, 0);

            if ((r < 0) && (errno != EINTR)) {
                sprintf(msg, "poll failed (%s)", strerror(errno));
                session->status = NC_STATUS_INVALID;
                ret = NC_PSPOLL_ERROR;
            } else if (r > 0) {
                if (pfd.revents & (POLLHUP | POLLNVAL)) {
                    sprintf(msg, "communication socket unexpectedly closed");
                    session->status = NC_STATUS_INVALID;
                    session->term_reason = NC_SESSION_TERM_DROPPED;
                    ret = NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
                } else if (pfd.revents & POLLERR) {
                    sprintf(msg, "communication socket error");
                    session->status = NC_STATUS_INVALID;
                    session->term_reason = NC_SESSION_TERM_OTHER;
                    ret = NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
                } else {
                    ret = NC_PSPOLL_RPC;
                }
            } else {
                ret = NC_PSPOLL_TIMEOUT;
            }
        } else {
            ret = NC_PSPOLL_RPC;
        }
        break;
#endif
    case NC_TI_FD:
    case NC_TI_UNIX:
        pfd.fd = (session->ti_type == NC_TI_FD) ? session->ti.fd.in : session->ti.unixsock.sock;
        pfd.events = POLLIN;
        pfd.revents = 0;
        r = poll(&pfd, 1, 0);

        if ((r < 0) && (errno != EINTR)) {
            sprintf(msg, "poll failed (%s)", strerror(errno));
            session->status = NC_STATUS_INVALID;
            ret = NC_PSPOLL_ERROR;
        } else if (r > 0) {
            if (pfd.revents & (POLLHUP | POLLNVAL)) {
                sprintf(msg, "communication socket unexpectedly closed");
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_DROPPED;
                ret = NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
            } else if (pfd.revents & POLLERR) {
                sprintf(msg, "communication socket error");
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_OTHER;
                ret = NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
            } else {
                ret = NC_PSPOLL_RPC;
            }
        } else {
            ret = NC_PSPOLL_TIMEOUT;
        }
        break;
    case NC_TI_NONE:
        sprintf(msg, "internal error (%s:%d)", __FILE__, __LINE__);
        ret = NC_PSPOLL_ERROR;
        break;
    }

    nc_session_io_unlock(session, __func__);
    return ret;
}

API int
nc_ps_poll(struct nc_pollsession *ps, int timeout, struct nc_session **session)
{
    int ret, r;
    uint8_t q_id;
    uint16_t i, j;
    char msg[256];
    struct timespec ts_timeout, ts_cur;
    struct nc_session *cur_session;
    struct nc_ps_session *cur_ps_session;
    struct nc_server_rpc *rpc = NULL;

    if (!ps) {
        ERRARG("ps");
        return NC_PSPOLL_ERROR;
    }

    /* PS LOCK */
    if (nc_ps_lock(ps, &q_id, __func__)) {
        return NC_PSPOLL_ERROR;
    }

    if (!ps->session_count) {
        nc_ps_unlock(ps, q_id, __func__);
        return NC_PSPOLL_NOSESSIONS;
    }

    /* fill timespecs */
    nc_gettimespec_mono(&ts_cur);
    if (timeout > -1) {
        nc_gettimespec_mono(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);
    }

    /* poll all the sessions one-by-one */
    do {
        /* loop from i to j once (all sessions) */
        if (ps->last_event_session == ps->session_count - 1) {
            i = j = 0;
        } else {
            i = j = ps->last_event_session + 1;
        }
        do {
            cur_ps_session = ps->sessions[i];
            cur_session = cur_ps_session->session;

            /* SESSION RPC LOCK */
            r = nc_session_rpc_lock(cur_session, 0, __func__);
            if (r == -1) {
                ret = NC_PSPOLL_ERROR;
            } else if (r == 1) {
                /* no one else is currently working with the session, so we can, otherwise skip it */
                switch (cur_ps_session->state) {
                case NC_PS_STATE_NONE:
                    if (cur_session->status == NC_STATUS_RUNNING) {
                        /* session is fine, work with it */
                        cur_ps_session->state = NC_PS_STATE_BUSY;

                        ret = nc_ps_poll_session_io(cur_session, NC_SESSION_LOCK_TIMEOUT, ts_cur.tv_sec, msg);
                        switch (ret) {
                        case NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR:
                            ERR("Session %u: %s.", cur_session->id, msg);
                            cur_ps_session->state = NC_PS_STATE_INVALID;
                            break;
                        case NC_PSPOLL_ERROR:
                            ERR("Session %u: %s.", cur_session->id, msg);
                            cur_ps_session->state = NC_PS_STATE_NONE;
                            break;
                        case NC_PSPOLL_TIMEOUT:
#ifdef NC_ENABLED_SSH
                        case NC_PSPOLL_SSH_CHANNEL:
                        case NC_PSPOLL_SSH_MSG:
#endif
                            cur_ps_session->state = NC_PS_STATE_NONE;
                            break;
                        case NC_PSPOLL_RPC:
                            /* let's keep the state busy, we are not done with this session */
                            break;
                        }
                    } else {
                        /* session is not fine, let the caller know */
                        ret = NC_PSPOLL_SESSION_TERM;
                        if (cur_session->term_reason != NC_SESSION_TERM_CLOSED) {
                            ret |= NC_PSPOLL_SESSION_ERROR;
                        }
                        cur_ps_session->state = NC_PS_STATE_INVALID;
                    }
                    break;
                case NC_PS_STATE_BUSY:
                    /* it definitely should not be busy because we have the lock */
                    ERRINT;
                    ret = NC_PSPOLL_ERROR;
                    break;
                case NC_PS_STATE_INVALID:
                    /* we got it locked, but it will be freed, let it be */
                    ret = NC_PSPOLL_TIMEOUT;
                    break;
                }

                /* keep RPC lock in this one case */
                if (ret != NC_PSPOLL_RPC) {
                    /* SESSION RPC UNLOCK */
                    nc_session_rpc_unlock(cur_session, NC_SESSION_LOCK_TIMEOUT, __func__);
                }
            } else {
                /* timeout */
                ret = NC_PSPOLL_TIMEOUT;
            }

            /* something happened */
            if (ret != NC_PSPOLL_TIMEOUT) {
                break;
            }

            if (i == ps->session_count - 1) {
                i = 0;
            } else {
                ++i;
            }
        } while (i != j);

        /* no event, no session remains locked */
        if (ret == NC_PSPOLL_TIMEOUT) {
            usleep(NC_TIMEOUT_STEP);
            /* update current time */
            nc_gettimespec_mono(&ts_cur);

            if ((timeout > -1) && (nc_difftimespec(&ts_cur, &ts_timeout) < 1)) {
                /* final timeout */
                break;
            }
        }
    } while (ret == NC_PSPOLL_TIMEOUT);

    /* do we want to return the session? */
    switch (ret) {
    case NC_PSPOLL_RPC:
    case NC_PSPOLL_SESSION_TERM:
    case NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR:
#ifdef NC_ENABLED_SSH
    case NC_PSPOLL_SSH_CHANNEL:
    case NC_PSPOLL_SSH_MSG:
#endif
        if (session) {
            *session = cur_session;
        }
        ps->last_event_session = i;
        break;
    default:
        break;
    }

    /* PS UNLOCK */
    nc_ps_unlock(ps, q_id, __func__);

    /* we have some data available and the session is RPC locked (but not IO locked) */
    if (ret == NC_PSPOLL_RPC) {
        ret = nc_server_recv_rpc_io(cur_session, timeout, &rpc);
        if (ret & (NC_PSPOLL_ERROR | NC_PSPOLL_BAD_RPC)) {
            if (cur_session->status != NC_STATUS_RUNNING) {
                ret |= NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
                cur_ps_session->state = NC_PS_STATE_INVALID;
            } else {
                cur_ps_session->state = NC_PS_STATE_NONE;
            }
        } else {
            cur_session->opts.server.last_rpc = ts_cur.tv_sec;

            /* process RPC */
            ret |= nc_server_send_reply_io(cur_session, timeout, rpc);
            if (cur_session->status != NC_STATUS_RUNNING) {
                ret |= NC_PSPOLL_SESSION_TERM;
                if (!(cur_session->term_reason & (NC_SESSION_TERM_CLOSED | NC_SESSION_TERM_KILLED))) {
                    ret |= NC_PSPOLL_SESSION_ERROR;
                }
                cur_ps_session->state = NC_PS_STATE_INVALID;
            } else {
                cur_ps_session->state = NC_PS_STATE_NONE;
            }
        }
        nc_server_rpc_free(rpc, server_opts.ctx);

        /* SESSION RPC UNLOCK */
        nc_session_rpc_unlock(cur_session, NC_SESSION_LOCK_TIMEOUT, __func__);
    }

    return ret;
}

API void
nc_ps_clear(struct nc_pollsession *ps, int all, void (*data_free)(void *))
{
    uint8_t q_id;
    uint16_t i;
    struct nc_session *session;

    if (!ps) {
        ERRARG("ps");
        return;
    }

    /* LOCK */
    if (nc_ps_lock(ps, &q_id, __func__)) {
        return;
    }

    if (all) {
        for (i = 0; i < ps->session_count; i++) {
            nc_session_free(ps->sessions[i]->session, data_free);
            free(ps->sessions[i]);
        }
        free(ps->sessions);
        ps->sessions = NULL;
        ps->session_count = 0;
        ps->last_event_session = 0;
    } else {
        for (i = 0; i < ps->session_count; ) {
            if (ps->sessions[i]->session->status != NC_STATUS_RUNNING) {
                session = ps->sessions[i]->session;
                _nc_ps_del_session(ps, NULL, i);
                nc_session_free(session, data_free);
                continue;
            }

            ++i;
        }
    }

    /* UNLOCK */
    nc_ps_unlock(ps, q_id, __func__);
}

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)

static int
nc_accept_unix(struct nc_session *session, int sock)
{
    const struct passwd *pw;
    struct ucred ucred;
    char *username;
    socklen_t len;

    session->ti_type = NC_TI_UNIX;

    len = sizeof(ucred);
    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &len) < 0) {
        ERR("Failed to get credentials from unix socket (%s).",
            strerror(errno));
        close(sock);
        return -1;
    }

    pw = getpwuid(ucred.uid);
    if (pw == NULL) {
        ERR("Failed to find username for uid=%u (%s).\n", ucred.uid,
            strerror(errno));
        close(sock);
        return -1;
    }

    username = strdup(pw->pw_name);
    if (username == NULL) {
        ERRMEM;
        close(sock);
        return -1;
    }
    session->username = lydict_insert_zc(server_opts.ctx, username);

    session->ti.unixsock.sock = sock;

    return 1;
}

API int
nc_server_add_endpt(const char *name, NC_TRANSPORT_IMPL ti)
{
    uint16_t i;
    int ret = 0;

    if (!name) {
        ERRARG("name");
        return -1;
    }

    /* BIND LOCK */
    pthread_mutex_lock(&server_opts.bind_lock);

    /* ENDPT WRITE LOCK */
    pthread_rwlock_wrlock(&server_opts.endpt_lock);

    /* check name uniqueness */
    for (i = 0; i < server_opts.endpt_count; ++i) {
        if (!strcmp(server_opts.endpts[i].name, name)) {
            ERR("Endpoint \"%s\" already exists.", name);
            ret = -1;
            goto cleanup;
        }
    }

    ++server_opts.endpt_count;
    server_opts.endpts = nc_realloc(server_opts.endpts, server_opts.endpt_count * sizeof *server_opts.endpts);
    if (!server_opts.endpts) {
        ERRMEM;
        ret = -1;
        goto cleanup;
    }
    memset(&server_opts.endpts[server_opts.endpt_count - 1], 0, sizeof *server_opts.endpts);
    server_opts.endpts[server_opts.endpt_count - 1].name = lydict_insert(server_opts.ctx, name, 0);
    server_opts.endpts[server_opts.endpt_count - 1].ti = ti;
    server_opts.endpts[server_opts.endpt_count - 1].ka.idle_time = 1;
    server_opts.endpts[server_opts.endpt_count - 1].ka.max_probes = 10;
    server_opts.endpts[server_opts.endpt_count - 1].ka.probe_interval = 5;

    server_opts.binds = nc_realloc(server_opts.binds, server_opts.endpt_count * sizeof *server_opts.binds);
    if (!server_opts.binds) {
        ERRMEM;
        ret = -1;
        goto cleanup;
    }

    memset(&server_opts.binds[server_opts.endpt_count - 1], 0, sizeof *server_opts.binds);
    server_opts.binds[server_opts.endpt_count - 1].sock = -1;

    switch (ti) {
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
        server_opts.endpts[server_opts.endpt_count - 1].opts.ssh = calloc(1, sizeof(struct nc_server_ssh_opts));
        if (!server_opts.endpts[server_opts.endpt_count - 1].opts.ssh) {
            ERRMEM;
            ret = -1;
            goto cleanup;
        }
        server_opts.endpts[server_opts.endpt_count - 1].opts.ssh->auth_methods =
            NC_SSH_AUTH_PUBLICKEY | NC_SSH_AUTH_PASSWORD | NC_SSH_AUTH_INTERACTIVE;
        server_opts.endpts[server_opts.endpt_count - 1].opts.ssh->auth_attempts = 3;
        server_opts.endpts[server_opts.endpt_count - 1].opts.ssh->auth_timeout = 30;
        break;
#endif
#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
        server_opts.endpts[server_opts.endpt_count - 1].opts.tls = calloc(1, sizeof(struct nc_server_tls_opts));
        if (!server_opts.endpts[server_opts.endpt_count - 1].opts.tls) {
            ERRMEM;
            ret = -1;
            goto cleanup;
        }
        break;
#endif
    case NC_TI_UNIX:
        server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock = calloc(1, sizeof(struct nc_server_unix_opts));
        if (!server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock) {
            ERRMEM;
            ret = -1;
            goto cleanup;
        }
        server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock->mode = (mode_t)-1;
        server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock->uid = (uid_t)-1;
        server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock->gid = (gid_t)-1;
        break;
    default:
        ERRINT;
        ret = -1;
        goto cleanup;
    }

cleanup:
    /* ENDPT UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    /* BIND UNLOCK */
    pthread_mutex_unlock(&server_opts.bind_lock);

    return ret;
}

API int
nc_server_del_endpt(const char *name, NC_TRANSPORT_IMPL ti)
{
    uint32_t i;
    int ret = -1;

    /* BIND LOCK */
    pthread_mutex_lock(&server_opts.bind_lock);

    /* ENDPT WRITE LOCK */
    pthread_rwlock_wrlock(&server_opts.endpt_lock);

    if (!name && !ti) {
        /* remove all endpoints */
        for (i = 0; i < server_opts.endpt_count; ++i) {
            lydict_remove(server_opts.ctx, server_opts.endpts[i].name);
            switch (server_opts.endpts[i].ti) {
#ifdef NC_ENABLED_SSH
            case NC_TI_LIBSSH:
                nc_server_ssh_clear_opts(server_opts.endpts[i].opts.ssh);
                free(server_opts.endpts[i].opts.ssh);
                break;
#endif
#ifdef NC_ENABLED_TLS
            case NC_TI_OPENSSL:
                nc_server_tls_clear_opts(server_opts.endpts[i].opts.tls);
                free(server_opts.endpts[i].opts.tls);
                break;
#endif
            case NC_TI_UNIX:
                free(server_opts.endpts[i].opts.unixsock);
                break;
            default:
                ERRINT;
                /* won't get here ...*/
                break;
            }
            ret = 0;
        }
        free(server_opts.endpts);
        server_opts.endpts = NULL;

        /* remove all binds */
        for (i = 0; i < server_opts.endpt_count; ++i) {
            lydict_remove(server_opts.ctx, server_opts.binds[i].address);
            if (server_opts.binds[i].sock > -1) {
                close(server_opts.binds[i].sock);
            }
        }
        free(server_opts.binds);
        server_opts.binds = NULL;

        server_opts.endpt_count = 0;

    } else {
        /* remove one endpoint with bind(s) or all endpoints using one transport protocol */
        for (i = 0; i < server_opts.endpt_count; ++i) {
            if ((name && !strcmp(server_opts.endpts[i].name, name)) || (!name && (server_opts.endpts[i].ti == ti))) {
                /* remove endpt */
                lydict_remove(server_opts.ctx, server_opts.endpts[i].name);
                switch (server_opts.endpts[i].ti) {
#ifdef NC_ENABLED_SSH
                case NC_TI_LIBSSH:
                    nc_server_ssh_clear_opts(server_opts.endpts[i].opts.ssh);
                    free(server_opts.endpts[i].opts.ssh);
                    break;
#endif
#ifdef NC_ENABLED_TLS
                case NC_TI_OPENSSL:
                    nc_server_tls_clear_opts(server_opts.endpts[i].opts.tls);
                    free(server_opts.endpts[i].opts.tls);
                    break;
#endif
                case NC_TI_UNIX:
                    free(server_opts.endpts[i].opts.unixsock);
                    break;
                default:
                    ERRINT;
                    break;
                }

                /* remove bind(s) */
                lydict_remove(server_opts.ctx, server_opts.binds[i].address);
                if (server_opts.binds[i].sock > -1) {
                    close(server_opts.binds[i].sock);
                }

                /* move last endpt and bind(s) to the empty space */
                --server_opts.endpt_count;
                if (!server_opts.endpt_count) {
                    free(server_opts.binds);
                    server_opts.binds = NULL;
                    free(server_opts.endpts);
                    server_opts.endpts = NULL;
                } else if (i < server_opts.endpt_count) {
                    memcpy(&server_opts.binds[i], &server_opts.binds[server_opts.endpt_count], sizeof *server_opts.binds);
                    memcpy(&server_opts.endpts[i], &server_opts.endpts[server_opts.endpt_count], sizeof *server_opts.endpts);
                }

                ret = 0;
                if (name) {
                    break;
                }
            }
        }
    }

    /* ENDPT UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    /* BIND UNLOCK */
    pthread_mutex_unlock(&server_opts.bind_lock);

    return ret;
}

API int
nc_server_endpt_count(void)
{
    return server_opts.endpt_count;
}

int
nc_server_endpt_set_address_port(const char *endpt_name, const char *address, uint16_t port)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind = NULL;
    uint16_t i;
    int sock = -1, set_addr, ret = 0;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    } else if ((!address && !port) || (address && port)) {
        ERRARG("address and port");
        return -1;
    }

    if (address) {
        set_addr = 1;
    } else {
        set_addr = 0;
    }

    /* BIND LOCK */
    pthread_mutex_lock(&server_opts.bind_lock);

    /* ENDPT LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, 0, &i);
    if (!endpt) {
        /* BIND UNLOCK */
        pthread_mutex_unlock(&server_opts.bind_lock);
        return -1;
    }

    bind = &server_opts.binds[i];

    if (set_addr) {
        port = bind->port;
    } else {
        address = bind->address;
    }

    if (!set_addr && endpt->ti == NC_TI_UNIX) {
        ret = -1;
        goto cleanup;
    }

    /* we have all the information we need to create a listening socket */
    if (address && (port || endpt->ti == NC_TI_UNIX)) {
        /* create new socket, close the old one */
        if (endpt->ti == NC_TI_UNIX)
            sock = nc_sock_listen_unix(address, endpt->opts.unixsock);
        else
            sock = nc_sock_listen_inet(address, port, &endpt->ka);
        if (sock == -1) {
            ret = -1;
            goto cleanup;
        }

        if (bind->sock > -1) {
            close(bind->sock);
        }
        bind->sock = sock;
    } /* else we are just setting address or port */

    if (set_addr) {
        lydict_remove(server_opts.ctx, bind->address);
        bind->address = lydict_insert(server_opts.ctx, address, 0);
    } else {
        bind->port = port;
    }

    if (sock > -1) {
#if defined(NC_ENABLED_SSH) && defined(NC_ENABLED_TLS)
        VRB("Listening on %s:%u for %s connections.", address, port, (endpt->ti == NC_TI_LIBSSH ? "SSH" : "TLS"));
#elif defined(NC_ENABLED_SSH)
        VRB("Listening on %s:%u for SSH connections.", address, port);
#else
        VRB("Listening on %s:%u for TLS connections.", address, port);
#endif
    }

cleanup:
    /* ENDPT UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    /* BIND UNLOCK */
    pthread_mutex_unlock(&server_opts.bind_lock);

    return ret;
}

API int
nc_server_endpt_set_address(const char *endpt_name, const char *address)
{
    return nc_server_endpt_set_address_port(endpt_name, address, 0);
}

API int
nc_server_endpt_set_port(const char *endpt_name, uint16_t port)
{
    return nc_server_endpt_set_address_port(endpt_name, NULL, port);
}

API int
nc_server_endpt_set_perms(const char *endpt_name, mode_t mode, uid_t uid, gid_t gid)
{
    struct nc_endpt *endpt;
    uint16_t i;
    int ret = 0;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    } else if (mode == 0) {
        ERRARG("mode");
        return -1;
    }

    /* ENDPT LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, 0, &i);
    if (!endpt)
        return -1;

    if (endpt->ti != NC_TI_UNIX) {
        ret = -1;
        goto cleanup;
    }

    endpt->opts.unixsock->mode = mode;
    endpt->opts.unixsock->uid = uid;
    endpt->opts.unixsock->gid = gid;

cleanup:
    /* ENDPT UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_endpt_enable_keepalives(const char *endpt_name, int enable)
{
    struct nc_endpt *endpt;
    int ret = 0;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* ENDPT LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, 0, NULL);
    if (!endpt) {
        return -1;
    }

    endpt->ka.enabled = (enable ? 1 : 0);

    /* ENDPT UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_endpt_set_keepalives(const char *endpt_name, int idle_time, int max_probes, int probe_interval)
{
    struct nc_endpt *endpt;
    int ret = 0;

    if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* ENDPT LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, 0, NULL);
    if (!endpt) {
        return -1;
    }

    if (idle_time > -1) {
        endpt->ka.idle_time = idle_time;
    }
    if (max_probes > -1) {
        endpt->ka.max_probes = max_probes;
    }
    if (probe_interval > -1) {
        endpt->ka.probe_interval = probe_interval;
    }

    /* ENDPT UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API NC_MSG_TYPE
nc_accept(int timeout, struct nc_session **session)
{
    NC_MSG_TYPE msgtype;
    int sock, ret;
    char *host = NULL;
    uint16_t port, bind_idx;
    struct timespec ts_cur;

    if (!server_opts.ctx) {
        ERRINIT;
        return NC_MSG_ERROR;
    } else if (!session) {
        ERRARG("session");
        return NC_MSG_ERROR;
    }

    /* BIND LOCK */
    pthread_mutex_lock(&server_opts.bind_lock);

    if (!server_opts.endpt_count) {
        ERR("No endpoints to accept sessions on.");
        /* BIND UNLOCK */
        pthread_mutex_unlock(&server_opts.bind_lock);
        return NC_MSG_ERROR;
    }

    ret = nc_sock_accept_binds(server_opts.binds, server_opts.endpt_count, timeout, &host, &port, &bind_idx);
    if (ret < 1) {
        /* BIND UNLOCK */
        pthread_mutex_unlock(&server_opts.bind_lock);
        free(host);
        if (!ret) {
            return NC_MSG_WOULDBLOCK;
        }
        return NC_MSG_ERROR;
    }

    /* switch bind_lock for endpt_lock, so that another thread can accept another session */
    /* ENDPT READ LOCK */
    pthread_rwlock_rdlock(&server_opts.endpt_lock);

    /* BIND UNLOCK */
    pthread_mutex_unlock(&server_opts.bind_lock);

    sock = ret;

    *session = nc_new_session(NC_SERVER, 0);
    if (!(*session)) {
        ERRMEM;
        close(sock);
        free(host);
        msgtype = NC_MSG_ERROR;
        goto cleanup;
    }
    (*session)->status = NC_STATUS_STARTING;
    (*session)->ctx = server_opts.ctx;
    (*session)->flags = NC_SESSION_SHAREDCTX;
    (*session)->host = lydict_insert_zc(server_opts.ctx, host);
    (*session)->port = port;

    /* sock gets assigned to session or closed */
#ifdef NC_ENABLED_SSH
    if (server_opts.endpts[bind_idx].ti == NC_TI_LIBSSH) {
        (*session)->data = server_opts.endpts[bind_idx].opts.ssh;
        ret = nc_accept_ssh_session(*session, sock, NC_TRANSPORT_TIMEOUT);
        if (ret < 0) {
            msgtype = NC_MSG_ERROR;
            goto cleanup;
        } else if (!ret) {
            msgtype = NC_MSG_WOULDBLOCK;
            goto cleanup;
        }
    } else
#endif
#ifdef NC_ENABLED_TLS
    if (server_opts.endpts[bind_idx].ti == NC_TI_OPENSSL) {
        (*session)->data = server_opts.endpts[bind_idx].opts.tls;
        ret = nc_accept_tls_session(*session, sock, NC_TRANSPORT_TIMEOUT);
        if (ret < 0) {
            msgtype = NC_MSG_ERROR;
            goto cleanup;
        } else if (!ret) {
            msgtype = NC_MSG_WOULDBLOCK;
            goto cleanup;
        }
    } else
#endif
    if (server_opts.endpts[bind_idx].ti == NC_TI_UNIX) {
        (*session)->data = server_opts.endpts[bind_idx].opts.unixsock;
        ret = nc_accept_unix(*session, sock);
        if (ret < 0) {
            msgtype = NC_MSG_ERROR;
            goto cleanup;
        }
    } else {
        ERRINT;
        close(sock);
        msgtype = NC_MSG_ERROR;
        goto cleanup;
    }

    (*session)->data = NULL;

    /* ENDPT UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    /* assign new SID atomically */
    (*session)->id = ATOMIC_INC(&server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(*session);
    if (msgtype != NC_MSG_HELLO) {
        nc_session_free(*session, NULL);
        *session = NULL;
        return msgtype;
    }

    nc_gettimespec_mono(&ts_cur);
    (*session)->opts.server.last_rpc = ts_cur.tv_sec;
    nc_gettimespec_real(&ts_cur);
    (*session)->opts.server.session_start = ts_cur.tv_sec;
    (*session)->status = NC_STATUS_RUNNING;

    return msgtype;

cleanup:
    /* ENDPT UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    nc_session_free(*session, NULL);
    *session = NULL;
    return msgtype;
}

/* client is expected to be locked */
static int
_nc_server_ch_client_del_endpt(struct nc_ch_client *client, const char *endpt_name, NC_TRANSPORT_IMPL ti)
{
    uint16_t i;
    int ret = -1;

    if (!endpt_name) {
        /* remove all endpoints */
        for (i = 0; i < client->ch_endpt_count; ++i) {
            lydict_remove(server_opts.ctx, client->ch_endpts[i].name);
            lydict_remove(server_opts.ctx, client->ch_endpts[i].address);
            if (client->ch_endpts[i].sock_pending != -1) {
                close(client->ch_endpts[i].sock_pending);
            }
            switch (client->ch_endpts[i].ti) {
#ifdef NC_ENABLED_SSH
            case NC_TI_LIBSSH:
                nc_server_ssh_clear_opts(client->ch_endpts[i].opts.ssh);
                free(client->ch_endpts[i].opts.ssh);
                break;
#endif
#ifdef NC_ENABLED_TLS
            case NC_TI_OPENSSL:
                nc_server_tls_clear_opts(client->ch_endpts[i].opts.tls);
                free(client->ch_endpts[i].opts.tls);
                break;
#endif
            default:
                ERRINT;
                /* won't get here ...*/
                break;
            }
        }
        free(client->ch_endpts);
        client->ch_endpts = NULL;
        client->ch_endpt_count = 0;

        ret = 0;
    } else {
        for (i = 0; i < client->ch_endpt_count; ++i) {
            if (!strcmp(client->ch_endpts[i].name, endpt_name) && (!ti || (ti == client->ch_endpts[i].ti))) {
                lydict_remove(server_opts.ctx, client->ch_endpts[i].name);
                lydict_remove(server_opts.ctx, client->ch_endpts[i].address);
                if (client->ch_endpts[i].sock_pending != -1) {
                    close(client->ch_endpts[i].sock_pending);
                }
                switch (client->ch_endpts[i].ti) {
#ifdef NC_ENABLED_SSH
                case NC_TI_LIBSSH:
                    nc_server_ssh_clear_opts(client->ch_endpts[i].opts.ssh);
                    free(client->ch_endpts[i].opts.ssh);
                    break;
#endif
#ifdef NC_ENABLED_TLS
                case NC_TI_OPENSSL:
                    nc_server_tls_clear_opts(client->ch_endpts[i].opts.tls);
                    free(client->ch_endpts[i].opts.tls);
                    break;
#endif
                default:
                    ERRINT;
                    /* won't get here ...*/
                    break;
                }

                /* move last endpoint to the empty space */
                --client->ch_endpt_count;
                if (i < client->ch_endpt_count) {
                    memcpy(&client->ch_endpts[i], &client->ch_endpts[client->ch_endpt_count], sizeof *client->ch_endpts);
                } else if (!server_opts.ch_client_count) {
                    free(server_opts.ch_clients);
                    server_opts.ch_clients = NULL;
                }

                ret = 0;
                break;
            }
        }
    }

    return ret;
}

API int
nc_server_ch_add_client(const char *name)
{
    uint16_t i;
    struct nc_ch_client *client;

    if (!name) {
        ERRARG("name");
        return -1;
    }

    /* WRITE LOCK */
    pthread_rwlock_wrlock(&server_opts.ch_client_lock);

    /* check name uniqueness */
    for (i = 0; i < server_opts.ch_client_count; ++i) {
        if (!strcmp(server_opts.ch_clients[i].name, name)) {
            ERR("Call Home client \"%s\" already exists.", name);
            /* WRITE UNLOCK */
            pthread_rwlock_unlock(&server_opts.ch_client_lock);
            return -1;
        }
    }

    ++server_opts.ch_client_count;
    server_opts.ch_clients = nc_realloc(server_opts.ch_clients, server_opts.ch_client_count * sizeof *server_opts.ch_clients);
    if (!server_opts.ch_clients) {
        ERRMEM;
        /* WRITE UNLOCK */
        pthread_rwlock_unlock(&server_opts.ch_client_lock);
        return -1;
    }
    client = &server_opts.ch_clients[server_opts.ch_client_count - 1];

    client->name = lydict_insert(server_opts.ctx, name, 0);
    client->id = ATOMIC_INC(&server_opts.new_client_id);
    client->ch_endpts = NULL;
    client->ch_endpt_count = 0;
    client->conn_type = 0;

    /* set CH default options */
    client->start_with = NC_CH_FIRST_LISTED;
    client->max_attempts = 3;

    pthread_mutex_init(&client->lock, NULL);

    /* WRITE UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);

    return 0;
}

API int
nc_server_ch_del_client(const char *name)
{
    uint16_t i;
    int ret = -1;

    /* WRITE LOCK */
    pthread_rwlock_wrlock(&server_opts.ch_client_lock);

    if (!name) {
        /* remove all CH clients with endpoints */
        for (i = 0; i < server_opts.ch_client_count; ++i) {
            lydict_remove(server_opts.ctx, server_opts.ch_clients[i].name);

            /* remove all endpoints */
            _nc_server_ch_client_del_endpt(&server_opts.ch_clients[i], NULL, 0);

            pthread_mutex_destroy(&server_opts.ch_clients[i].lock);
            ret = 0;
        }
        free(server_opts.ch_clients);
        server_opts.ch_clients = NULL;

        server_opts.ch_client_count = 0;

    } else {
        /* remove one client with endpoints */
        for (i = 0; i < server_opts.ch_client_count; ++i) {
            if (!strcmp(server_opts.ch_clients[i].name, name)) {
                lydict_remove(server_opts.ctx, server_opts.ch_clients[i].name);

                /* remove all endpoints */
                _nc_server_ch_client_del_endpt(&server_opts.ch_clients[i], NULL, 0);

                pthread_mutex_destroy(&server_opts.ch_clients[i].lock);

                /* move last client and endpoint(s) to the empty space */
                --server_opts.ch_client_count;
                if (i < server_opts.ch_client_count) {
                    memcpy(&server_opts.ch_clients[i], &server_opts.ch_clients[server_opts.ch_client_count],
                            sizeof *server_opts.ch_clients);
                } else if (!server_opts.ch_client_count) {
                    free(server_opts.ch_clients);
                    server_opts.ch_clients = NULL;
                }

                ret = 0;
                break;
            }
        }
    }

    /* WRITE UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);

    return ret;
}

API int
nc_server_ch_client_add_endpt(const char *client_name, const char *endpt_name, NC_TRANSPORT_IMPL ti)
{
    uint16_t i;
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;
    int ret = -1;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    } else if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    } else if (!ti) {
        ERRARG("ti");
        return -1;
    }

    /* LOCK */
    nc_server_ch_client_lock(client_name, NULL, 0, &client);
    if (!client) {
        return -1;
    }

    for (i = 0; i < client->ch_endpt_count; ++i) {
        if (!strcmp(client->ch_endpts[i].name, endpt_name)) {
            ERR("Call Home client \"%s\" endpoint \"%s\" already exists.", client_name, endpt_name);
            goto cleanup;
        }
    }

    ++client->ch_endpt_count;
    client->ch_endpts = realloc(client->ch_endpts, client->ch_endpt_count * sizeof *client->ch_endpts);
    if (!client->ch_endpts) {
        ERRMEM;
        goto cleanup;
    }
    endpt = &client->ch_endpts[client->ch_endpt_count - 1];

    memset(endpt, 0, sizeof *client->ch_endpts);
    endpt->name = lydict_insert(server_opts.ctx, endpt_name, 0);
    endpt->ti = ti;
    endpt->sock_pending = -1;
    endpt->ka.idle_time = 1;
    endpt->ka.max_probes = 10;
    endpt->ka.probe_interval = 5;

    switch (ti) {
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
        endpt->opts.ssh = calloc(1, sizeof(struct nc_server_ssh_opts));
        if (!endpt->opts.ssh) {
            ERRMEM;
            goto cleanup;
        }
        endpt->opts.ssh->auth_methods = NC_SSH_AUTH_PUBLICKEY | NC_SSH_AUTH_PASSWORD | NC_SSH_AUTH_INTERACTIVE;
        endpt->opts.ssh->auth_attempts = 3;
        endpt->opts.ssh->auth_timeout = 30;
        break;
#endif
#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
        endpt->opts.tls = calloc(1, sizeof(struct nc_server_tls_opts));
        if (!endpt->opts.tls) {
            ERRMEM;
            goto cleanup;
        }
        break;
#endif
    default:
        ERRINT;
        goto cleanup;
    }

    /* success */
    ret = 0;

cleanup:
    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

API int
nc_server_ch_client_del_endpt(const char *client_name, const char *endpt_name, NC_TRANSPORT_IMPL ti)
{
    int ret;
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    nc_server_ch_client_lock(client_name, NULL, 0, &client);
    if (!client) {
        return -1;
    }

    ret = _nc_server_ch_client_del_endpt(client, endpt_name, ti);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

API int
nc_server_ch_client_endpt_set_address(const char *client_name, const char *endpt_name, const char *address)
{
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    } else if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    } else if (!address) {
        ERRARG("address");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, 0, &client);
    if (!endpt) {
        return -1;
    }

    lydict_remove(server_opts.ctx, endpt->address);
    endpt->address = lydict_insert(server_opts.ctx, address, 0);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return 0;
}

API int
nc_server_ch_client_endpt_set_port(const char *client_name, const char *endpt_name, uint16_t port)
{
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    } else if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    } else if (!port) {
        ERRARG("port");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, 0, &client);
    if (!endpt) {
        return -1;
    }

    endpt->port = port;

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return -1;
}

API int
nc_server_ch_client_endpt_enable_keepalives(const char *client_name, const char *endpt_name, int enable)
{
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    } else if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, 0, &client);
    if (!endpt) {
        return -1;
    }

    endpt->ka.enabled = (enable ? 1 : 0);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return 0;
}

API int
nc_server_ch_client_endpt_set_keepalives(const char *client_name, const char *endpt_name, int idle_time, int max_probes,
        int probe_interval)
{
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    } else if (!endpt_name) {
        ERRARG("endpt_name");
        return -1;
    }

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, 0, &client);
    if (!endpt) {
        return -1;
    }

    if (idle_time > -1) {
        endpt->ka.idle_time = idle_time;
    }
    if (max_probes > -1) {
        endpt->ka.max_probes = max_probes;
    }
    if (probe_interval > -1) {
        endpt->ka.probe_interval = probe_interval;
    }

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return 0;
}

API int
nc_server_ch_client_set_conn_type(const char *client_name, NC_CH_CONN_TYPE conn_type)
{
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    } else if (!conn_type) {
        ERRARG("conn_type");
        return -1;
    }

    /* LOCK */
    nc_server_ch_client_lock(client_name, NULL, 0, &client);
    if (!client) {
        return -1;
    }

    if (client->conn_type != conn_type) {
        client->conn_type = conn_type;

        /* set default options */
        switch (conn_type) {
        case NC_CH_PERSIST:
            /* no options */
            break;
        case NC_CH_PERIOD:
            client->conn.period.period = 60;
            client->conn.period.anchor_time = 0;
            client->conn.period.idle_timeout = 120;
            break;
        default:
            ERRINT;
            break;
        }
    }

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return 0;
}

API int
nc_server_ch_client_periodic_set_period(const char *client_name, uint16_t period)
{
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    } else if (!period) {
        ERRARG("period");
        return -1;
    }

    /* LOCK */
    nc_server_ch_client_lock(client_name, NULL, 0, &client);
    if (!client) {
        return -1;
    }

    if (client->conn_type != NC_CH_PERIOD) {
        ERR("Call Home client \"%s\" is not of periodic connection type.");
        /* UNLOCK */
        nc_server_ch_client_unlock(client);
        return -1;
    }

    client->conn.period.period = period;

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return 0;
}

API int
nc_server_ch_client_periodic_set_anchor_time(const char *client_name, time_t anchor_time)
{
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    nc_server_ch_client_lock(client_name, NULL, 0, &client);
    if (!client) {
        return -1;
    }

    if (client->conn_type != NC_CH_PERIOD) {
        ERR("Call Home client \"%s\" is not of periodic connection type.");
        /* UNLOCK */
        nc_server_ch_client_unlock(client);
        return -1;
    }

    client->conn.period.anchor_time = anchor_time;

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return 0;
}

API int
nc_server_ch_client_periodic_set_idle_timeout(const char *client_name, uint16_t idle_timeout)
{
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    nc_server_ch_client_lock(client_name, NULL, 0, &client);
    if (!client) {
        return -1;
    }

    if (client->conn_type != NC_CH_PERIOD) {
        ERR("Call Home client \"%s\" is not of periodic connection type.", client_name);
        /* UNLOCK */
        nc_server_ch_client_unlock(client);
        return -1;
    }

    client->conn.period.idle_timeout = idle_timeout;

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return 0;
}

API int
nc_server_ch_client_set_start_with(const char *client_name, NC_CH_START_WITH start_with)
{
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    }

    /* LOCK */
    nc_server_ch_client_lock(client_name, NULL, 0, &client);
    if (!client) {
        return -1;
    }

    client->start_with = start_with;

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return 0;
}

API int
nc_server_ch_client_set_max_attempts(const char *client_name, uint8_t max_attempts)
{
    struct nc_ch_client *client;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    } else if (!max_attempts) {
        ERRARG("max_attempts");
        return -1;
    }

    /* LOCK */
    nc_server_ch_client_lock(client_name, NULL, 0, &client);
    if (!client) {
        return -1;
    }

    client->max_attempts = max_attempts;

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return 0;
}

/* client lock is expected to be held */
static NC_MSG_TYPE
nc_connect_ch_endpt(struct nc_ch_endpt *endpt, struct nc_session **session)
{
    NC_MSG_TYPE msgtype;
    int sock, ret;
    struct timespec ts_cur;
    char *ip_host;

    sock = nc_sock_connect(endpt->address, endpt->port, 5, &endpt->ka, &endpt->sock_pending, &ip_host);
    if (sock < 0) {
        return NC_MSG_ERROR;
    }
    /* no need to store the socket as pending any longer */
    endpt->sock_pending = -1;

    *session = nc_new_session(NC_SERVER, 0);
    if (!(*session)) {
        ERRMEM;
        close(sock);
        free(ip_host);
        return NC_MSG_ERROR;
    }
    (*session)->status = NC_STATUS_STARTING;
    (*session)->ctx = server_opts.ctx;
    (*session)->flags = NC_SESSION_SHAREDCTX;
    (*session)->host = lydict_insert_zc(server_opts.ctx, ip_host);
    (*session)->port = endpt->port;

    /* sock gets assigned to session or closed */
#ifdef NC_ENABLED_SSH
    if (endpt->ti == NC_TI_LIBSSH) {
        (*session)->data = endpt->opts.ssh;
        ret = nc_accept_ssh_session(*session, sock, NC_TRANSPORT_TIMEOUT);
        (*session)->data = NULL;

        if (ret < 0) {
            msgtype = NC_MSG_ERROR;
            goto fail;
        } else if (!ret) {
            msgtype = NC_MSG_WOULDBLOCK;
            goto fail;
        }
    } else
#endif
#ifdef NC_ENABLED_TLS
    if (endpt->ti == NC_TI_OPENSSL) {
        (*session)->data = endpt->opts.tls;
        ret = nc_accept_tls_session(*session, sock, NC_TRANSPORT_TIMEOUT);
        (*session)->data = NULL;

        if (ret < 0) {
            msgtype = NC_MSG_ERROR;
            goto fail;
        } else if (!ret) {
            msgtype = NC_MSG_WOULDBLOCK;
            goto fail;
        }
    } else
#endif
    {
        ERRINT;
        close(sock);
        msgtype = NC_MSG_ERROR;
        goto fail;
    }

    /* assign new SID atomically */
    (*session)->id = ATOMIC_INC(&server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(*session);
    if (msgtype != NC_MSG_HELLO) {
        goto fail;
    }

    nc_gettimespec_mono(&ts_cur);
    (*session)->opts.server.last_rpc = ts_cur.tv_sec;
    nc_gettimespec_real(&ts_cur);
    (*session)->opts.server.session_start = ts_cur.tv_sec;
    (*session)->status = NC_STATUS_RUNNING;

    return msgtype;

fail:
    nc_session_free(*session, NULL);
    *session = NULL;
    return msgtype;
}

struct nc_ch_client_thread_arg {
    char *client_name;
    void (*session_clb)(const char *client_name, struct nc_session *new_session);
};

static struct nc_ch_client *
nc_server_ch_client_with_endpt_lock(const char *name)
{
    struct nc_ch_client *client;

    while (1) {
        /* LOCK */
        nc_server_ch_client_lock(name, NULL, 0, &client);
        if (!client) {
            return NULL;
        }
        if (client->ch_endpt_count) {
            return client;
        }
        /* no endpoints defined yet */

        /* UNLOCK */
        nc_server_ch_client_unlock(client);

        usleep(NC_CH_NO_ENDPT_WAIT * 1000);
    }

    return NULL;
}

static int
nc_server_ch_client_thread_session_cond_wait(struct nc_session *session, struct nc_ch_client_thread_arg *data)
{
    int ret = 0, r;
    uint32_t idle_timeout;
    struct timespec ts;
    struct nc_ch_client *client;

    /* session created, initialize condition */
    session->opts.server.ch_lock = calloc(1, sizeof *session->opts.server.ch_lock);
    session->opts.server.ch_cond = calloc(1, sizeof *session->opts.server.ch_cond);
    if (!session->opts.server.ch_lock || !session->opts.server.ch_cond) {
        ERRMEM;
        nc_session_free(session, NULL);
        return -1;
    }
    pthread_mutex_init(session->opts.server.ch_lock, NULL);
    pthread_cond_init(session->opts.server.ch_cond, NULL);

    session->flags |= NC_SESSION_CALLHOME;

    /* CH LOCK */
    pthread_mutex_lock(session->opts.server.ch_lock);

    /* give the session to the user */
    data->session_clb(data->client_name, session);

    do {
        nc_gettimespec_real(&ts);
        nc_addtimespec(&ts, NC_CH_NO_ENDPT_WAIT);

        r = pthread_cond_timedwait(session->opts.server.ch_cond, session->opts.server.ch_lock, &ts);
        if (!r) {
            /* we were woken up, something probably happened */
            if (session->status != NC_STATUS_RUNNING) {
                break;
            }
        } else if (r != ETIMEDOUT) {
            ERR("Pthread condition timedwait failed (%s).", strerror(r));
            ret = -1;
            break;
        }

        /* check whether the client was not removed */
        /* LOCK */
        nc_server_ch_client_lock(data->client_name, NULL, 0, &client);
        if (!client) {
            /* client was removed, finish thread */
            VRB("Call Home client \"%s\" removed, but an established session will not be terminated.",
                    data->client_name);
            ret = 1;
            break;
        }

        if (client->conn_type == NC_CH_PERIOD) {
            idle_timeout = client->conn.period.idle_timeout;
        } else {
            idle_timeout = 0;
        }

        nc_gettimespec_mono(&ts);
        if (!session->opts.server.ntf_status && idle_timeout && (ts.tv_sec >= session->opts.server.last_rpc + idle_timeout)) {
            VRB("Call Home client \"%s\" session %u: session idle timeout elapsed.", client->name, session->id);
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_TIMEOUT;
        }

        /* UNLOCK */
        nc_server_ch_client_unlock(client);

    } while (session->status == NC_STATUS_RUNNING);

    /* CH UNLOCK */
    pthread_mutex_unlock(session->opts.server.ch_lock);

    if (session->status == NC_STATUS_CLOSING) {
        /* signal to nc_session_free() that we registered session being freed, otherwise it matters not */
        session->flags &= ~NC_SESSION_CALLHOME;
    }

    return ret;
}

static void *
nc_ch_client_thread(void *arg)
{
    struct nc_ch_client_thread_arg *data = (struct nc_ch_client_thread_arg *)arg;
    NC_MSG_TYPE msgtype;
    uint8_t cur_attempts = 0;
    uint16_t next_endpt_index;
    char *cur_endpt_name = NULL;
    struct nc_ch_endpt *cur_endpt;
    struct nc_session *session;
    struct nc_ch_client *client;
    uint32_t client_id;
    time_t reconnect_in;

    /* LOCK */
    client = nc_server_ch_client_with_endpt_lock(data->client_name);
    if (!client) {
        goto cleanup;
    }
    client_id = client->id;

    cur_endpt = &client->ch_endpts[0];
    cur_endpt_name = strdup(cur_endpt->name);

    VRB("Call Home client \"%s\" connecting...", data->client_name);
    while (1) {
        msgtype = nc_connect_ch_endpt(cur_endpt, &session);

        if (msgtype == NC_MSG_HELLO) {
            /* UNLOCK */
            nc_server_ch_client_unlock(client);

            VRB("Call Home client \"%s\" session %u established.", data->client_name, session->id);
            if (nc_server_ch_client_thread_session_cond_wait(session, data)) {
                goto cleanup;
            }
            VRB("Call Home client \"%s\" session terminated, reconnecting...", client->name);

            /* LOCK */
            client = nc_server_ch_client_with_endpt_lock(data->client_name);
            if (!client) {
                goto cleanup;
            }
            if (client->id != client_id) {
                nc_server_ch_client_unlock(client);
                goto cleanup;
            }

            /* session changed status -> it was disconnected for whatever reason,
             * persistent connection immediately tries to reconnect, periodic connects at specific times */
            if (client->conn_type == NC_CH_PERIOD) {
                /* UNLOCK */
                nc_server_ch_client_unlock(client);

                /* sleep until we should reconnect TODO wake up sometimes to check for new notifications */
                reconnect_in = (time(NULL) - client->conn.period.anchor_time) % (client->conn.period.period * 60);
                sleep(reconnect_in);

                /* LOCK */
                client = nc_server_ch_client_with_endpt_lock(data->client_name);
                if (!client) {
                    goto cleanup;
                }
                if (client->id != client_id) {
                    nc_server_ch_client_unlock(client);
                    goto cleanup;
                }
            }

            /* set next endpoint to try */
            if (client->start_with == NC_CH_FIRST_LISTED) {
                next_endpt_index = 0;
            } else if (client->start_with == NC_CH_LAST_CONNECTED) {
                /* we keep the current one but due to unlock/lock we have to find it again */
                for (next_endpt_index = 0; next_endpt_index < client->ch_endpt_count; ++next_endpt_index) {
                    if (!strcmp(client->ch_endpts[next_endpt_index].name, cur_endpt_name)) {
                        break;
                    }
                }
                if (next_endpt_index >= client->ch_endpt_count) {
                    /* endpoint was removed, start with the first one */
                    next_endpt_index = 0;
                }
            } else {
                /* just get a random index */
                next_endpt_index = rand() % client->ch_endpt_count;
            }

        } else {
            /* UNLOCK */
            nc_server_ch_client_unlock(client);

            /* session was not created */
            usleep(NC_CH_ENDPT_FAIL_WAIT * 1000);

            /* LOCK */
            client = nc_server_ch_client_with_endpt_lock(data->client_name);
            if (!client) {
                goto cleanup;
            }
            if (client->id != client_id) {
                nc_server_ch_client_unlock(client);
                goto cleanup;
            }

            ++cur_attempts;

            /* try to find our endpoint again */
            for (next_endpt_index = 0; next_endpt_index < client->ch_endpt_count; ++next_endpt_index) {
                if (!strcmp(client->ch_endpts[next_endpt_index].name, cur_endpt_name)) {
                    break;
                }
            }

            if (next_endpt_index >= client->ch_endpt_count) {
                /* endpoint was removed, start with the first one */
                next_endpt_index = 0;
                cur_attempts = 0;
            } else if (cur_attempts == client->max_attempts) {
                /* we have tried to connect to this endpoint enough times */
                if (next_endpt_index < client->ch_endpt_count - 1) {
                    /* just go to the next endpoint */
                    ++next_endpt_index;
                } else {
                    /* cur_endpoint is the last, start with the first one */
                    next_endpt_index = 0;
                }

                cur_attempts = 0;
            } /* else we keep the current one */
        }

        cur_endpt = &client->ch_endpts[next_endpt_index];
        free(cur_endpt_name);
        cur_endpt_name = strdup(cur_endpt->name);
    }

cleanup:
    VRB("Call Home client \"%s\" thread exit.", data->client_name);
    free(cur_endpt_name);
    free(data->client_name);
    free(data);
    return NULL;
}

API int
nc_connect_ch_client_dispatch(const char *client_name, void (*session_clb)(const char *client_name,
        struct nc_session *new_session))
{
    int ret;
    pthread_t tid;
    struct nc_ch_client_thread_arg *arg;

    if (!client_name) {
        ERRARG("client_name");
        return -1;
    } else if (!session_clb) {
        ERRARG("session_clb");
        return -1;
    }

    arg = malloc(sizeof *arg);
    if (!arg) {
        ERRMEM;
        return -1;
    }
    arg->client_name = strdup(client_name);
    if (!arg->client_name) {
        ERRMEM;
        free(arg);
        return -1;
    }
    arg->session_clb = session_clb;

    ret = pthread_create(&tid, NULL, nc_ch_client_thread, arg);
    if (ret) {
        ERR("Creating a new thread failed (%s).", strerror(ret));
        free(arg->client_name);
        free(arg);
        return -1;
    }
    /* the thread now manages arg */

    pthread_detach(tid);

    return 0;
}

#endif /* NC_ENABLED_SSH || NC_ENABLED_TLS */

API time_t
nc_session_get_start_time(const struct nc_session *session)
{
    if (!session || (session->side != NC_SERVER)) {
        ERRARG("session");
        return 0;
    }

    return session->opts.server.session_start;
}

API void
nc_session_set_notif_status(struct nc_session *session, int notif_status)
{
    if (!session || (session->side != NC_SERVER)) {
        ERRARG("session");
        return;
    }

    session->opts.server.ntf_status = (notif_status ? 1 : 0);
}

API int
nc_session_get_notif_status(const struct nc_session *session)
{
    if (!session || (session->side != NC_SERVER)) {
        ERRARG("session");
        return 0;
    }

    return session->opts.server.ntf_status;
}

API int
nc_session_is_callhome(const struct nc_session *session)
{
    if (!session || (session->side != NC_SERVER)) {
        ERRARG("session");
        return 0;
    }

    if (session->flags & NC_SESSION_CALLHOME) {
        return 1;
    }

    return 0;
}
