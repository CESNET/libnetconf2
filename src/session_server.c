/**
 * @file session_server.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 server session manipulation functions
 *
 * @copyright
 * Copyright (c) 2015 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _QNX_SOURCE /* getpeereid */
#define _GNU_SOURCE /* threads, SO_PEERCRED */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "messages_p.h"
#include "messages_server.h"
#include "server_config.h"
#include "server_config_p.h"
#include "session.h"
#include "session_p.h"
#include "session_server.h"
#include "session_server_ch.h"
#include "session_wrapper.h"

#ifdef NC_ENABLED_SSH_TLS
#include <curl/curl.h>
#include <libssh/libssh.h>
#endif

struct nc_server_opts server_opts = {
    .config_lock = PTHREAD_RWLOCK_INITIALIZER,
    .ch_client_lock = PTHREAD_RWLOCK_INITIALIZER,
    .idle_timeout = 180,    /**< default idle timeout (not in config for UNIX socket) */
};

static nc_rpc_clb global_rpc_clb = NULL;

#ifdef NC_ENABLED_SSH_TLS
/**
 * @brief Lock CH client structures for reading and lock the specific client.
 *
 * @param[in] name Name of the CH client.
 * @return CH client, NULL if not found.
 */
static struct nc_ch_client *
nc_server_ch_client_lock(const char *name)
{
    uint16_t i;
    struct nc_ch_client *client = NULL;

    assert(name);

    /* READ LOCK */
    pthread_rwlock_rdlock(&server_opts.ch_client_lock);

    for (i = 0; i < server_opts.ch_client_count; ++i) {
        if (server_opts.ch_clients[i].name && !strcmp(server_opts.ch_clients[i].name, name)) {
            client = &server_opts.ch_clients[i];
            break;
        }
    }

    if (!client) {
        /* READ UNLOCK */
        pthread_rwlock_unlock(&server_opts.ch_client_lock);
    } else {
        /* CH CLIENT LOCK */
        pthread_mutex_lock(&client->lock);
    }

    return client;
}

/**
 * @brief Unlock CH client strcutures and the specific client.
 *
 * @param[in] endpt Locked CH client structure.
 */
static void
nc_server_ch_client_unlock(struct nc_ch_client *client)
{
    /* CH CLIENT UNLOCK */
    pthread_mutex_unlock(&client->lock);

    /* READ UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);
}

#endif /* NC_ENABLED_SSH_TLS */

int
nc_server_get_referenced_endpt(const char *name, struct nc_endpt **endpt)
{
    uint16_t i;

    for (i = 0; i < server_opts.endpt_count; i++) {
        if (!strcmp(name, server_opts.endpts[i].name)) {
            *endpt = &server_opts.endpts[i];
            return 0;
        }
    }

    ERR(NULL, "Referenced endpoint \"%s\" was not found.", name);
    return 1;
}

API void
nc_session_set_term_reason(struct nc_session *session, NC_SESSION_TERM_REASON reason)
{
    if (!session) {
        ERRARG(session, "session");
        return;
    } else if (!reason) {
        ERRARG(session, "reason");
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
        ERRARG(session, "session");
        return;
    } else if (!sid) {
        ERRARG(session, "sid");
        return;
    }

    session->killed_by = sid;
}

API void
nc_session_set_status(struct nc_session *session, NC_STATUS status)
{
    if (!session) {
        ERRARG(session, "session");
        return;
    } else if (!status) {
        ERRARG(session, "status");
        return;
    }

    session->status = status;
}

API int
nc_server_init_ctx(struct ly_ctx **ctx)
{
    int new_ctx = 0, i, ret = 0;
    struct lys_module *module;
    /* all features */
    const char *ietf_netconf_features[] = {"writable-running", "candidate", "rollback-on-error", "validate", "startup", "url", "xpath", "confirmed-commit", NULL};
    /* all features (module has no features) */
    const char *ietf_netconf_monitoring_features[] = {NULL};

    NC_CHECK_ARG_RET(NULL, ctx, 1);

    if (!*ctx) {
        /* context not given, create a new one */
        if (ly_ctx_new(NC_SERVER_SEARCH_DIR, 0, ctx)) {
            ERR(NULL, "Couldn't create new libyang context.\n");
            ret = 1;
            goto cleanup;
        }
        new_ctx = 1;
    }

    if (new_ctx) {
        /* new context created, implement both modules */
        if (!ly_ctx_load_module(*ctx, "ietf-netconf", NULL, ietf_netconf_features)) {
            ERR(NULL, "Loading module \"ietf-netconf\" failed.\n");
            ret = 1;
            goto cleanup;
        }

        if (!ly_ctx_load_module(*ctx, "ietf-netconf-monitoring", NULL, ietf_netconf_monitoring_features)) {
            ERR(NULL, "Loading module \"ietf-netconf-monitoring\" failed.\n");
            ret = 1;
            goto cleanup;
        }

        goto cleanup;
    }

    module = ly_ctx_get_module_implemented(*ctx, "ietf-netconf");
    if (module) {
        /* ietf-netconf module is present, check features */
        for (i = 0; ietf_netconf_features[i]; i++) {
            if (lys_feature_value(module, ietf_netconf_features[i])) {
                /* feature not found, enable all of them */
                if (!ly_ctx_load_module(*ctx, "ietf-netconf", NULL, ietf_netconf_features)) {
                    ERR(NULL, "Loading module \"ietf-netconf\" failed.\n");
                    ret = 1;
                    goto cleanup;
                }

                break;
            }
        }
    } else {
        /* ietf-netconf module not found, add it */
        if (!ly_ctx_load_module(*ctx, "ietf-netconf", NULL, ietf_netconf_features)) {
            ERR(NULL, "Loading module \"ietf-netconf\" failed.\n");
            ret = 1;
            goto cleanup;
        }
    }

    module = ly_ctx_get_module_implemented(*ctx, "ietf-netconf-monitoring");
    if (!module) {
        /* ietf-netconf-monitoring module not found, add it */
        if (!ly_ctx_load_module(*ctx, "ietf-netconf-monitoring", NULL, ietf_netconf_monitoring_features)) {
            ERR(NULL, "Loading module \"ietf-netconf-monitoring\" failed.\n");
            ret = 1;
            goto cleanup;
        }
    }

cleanup:
    if (new_ctx && ret) {
        ly_ctx_destroy(*ctx);
        *ctx = NULL;
    }
    return ret;
}

#ifdef NC_ENABLED_SSH_TLS

API void
nc_server_ch_set_dispatch_data(nc_server_ch_session_acquire_ctx_cb acquire_ctx_cb,
        nc_server_ch_session_release_ctx_cb release_ctx_cb, void *ctx_cb_data, nc_server_ch_new_session_cb new_session_cb,
        void *new_session_cb_data)
{
    NC_CHECK_ARG_RET(NULL, acquire_ctx_cb, release_ctx_cb, new_session_cb, );

    server_opts.ch_dispatch_data.acquire_ctx_cb = acquire_ctx_cb;
    server_opts.ch_dispatch_data.release_ctx_cb = release_ctx_cb;
    server_opts.ch_dispatch_data.ctx_cb_data = ctx_cb_data;
    server_opts.ch_dispatch_data.new_session_cb = new_session_cb;
    server_opts.ch_dispatch_data.new_session_cb_data = new_session_cb_data;
}

#endif

int
nc_sock_bind_inet(int sock, const char *address, uint16_t port, int is_ipv4)
{
    struct sockaddr_storage saddr;
    struct sockaddr_in *saddr4;
    struct sockaddr_in6 *saddr6;

    memset(&saddr, 0, sizeof(struct sockaddr_storage));

    if (is_ipv4) {
        saddr4 = (struct sockaddr_in *)&saddr;

        saddr4->sin_family = AF_INET;
        saddr4->sin_port = htons(port);

        /* determine the address */
        if (!address) {
            /* set the implicit default IPv4 address */
            address = "0.0.0.0";
        }
        if (inet_pton(AF_INET, address, &saddr4->sin_addr) != 1) {
            ERR(NULL, "Failed to convert IPv4 address \"%s\".", address);
            return -1;
        }

        if (bind(sock, (struct sockaddr *)saddr4, sizeof(struct sockaddr_in)) == -1) {
            ERR(NULL, "Could not bind %s:%" PRIu16 " (%s).", address, port, strerror(errno));
            return -1;
        }

    } else {
        saddr6 = (struct sockaddr_in6 *)&saddr;

        saddr6->sin6_family = AF_INET6;
        saddr6->sin6_port = htons(port);

        /* determine the address */
        if (!address) {
            /* set the implicit default IPv6 address */
            address = "::";
        }
        if (inet_pton(AF_INET6, address, &saddr6->sin6_addr) != 1) {
            ERR(NULL, "Failed to convert IPv6 address \"%s\".", address);
            return -1;
        }

        if (bind(sock, (struct sockaddr *)saddr6, sizeof(struct sockaddr_in6)) == -1) {
            ERR(NULL, "Could not bind [%s]:%" PRIu16 " (%s).", address, port, strerror(errno));
            return -1;
        }
    }

    return 0;
}

int
nc_sock_listen_inet(const char *address, uint16_t port)
{
    int opt;
    int is_ipv4, sock;

    if (!strchr(address, ':')) {
        is_ipv4 = 1;
    } else {
        is_ipv4 = 0;
    }

    sock = socket((is_ipv4 ? AF_INET : AF_INET6), SOCK_STREAM, 0);
    if (sock == -1) {
        ERR(NULL, "Failed to create socket (%s).", strerror(errno));
        goto fail;
    }

    /* these options will be inherited by accepted sockets */
    opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) == -1) {
        ERR(NULL, "Could not set SO_REUSEADDR socket option (%s).", strerror(errno));
        goto fail;
    }
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof opt) == -1) {
        ERR(NULL, "Could not set TCP_NODELAY socket option (%s).", strerror(errno));
        goto fail;
    }

    /* bind the socket */
    if (nc_sock_bind_inet(sock, address, port, is_ipv4)) {
        goto fail;
    }

    if (listen(sock, NC_REVERSE_QUEUE) == -1) {
        ERR(NULL, "Unable to start listening on \"%s\" port %d (%s).", address, port, strerror(errno));
        goto fail;
    }
    return sock;

fail:
    if (sock > -1) {
        close(sock);
    }

    return -1;
}

/**
 * @brief Create a listening socket (AF_UNIX).
 *
 * @param[in] opts The server options (unix permissions and address of the socket).
 * @return Listening socket, -1 on error.
 */
static int
nc_sock_listen_unix(const struct nc_server_unix_opts *opts)
{
    struct sockaddr_un sun;
    int sock = -1;

    if (strlen(opts->address) > sizeof(sun.sun_path) - 1) {
        ERR(NULL, "Socket path \"%s\" is longer than maximum length %d.", opts->address, (int)(sizeof(sun.sun_path) - 1));
        goto fail;
    }

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        ERR(NULL, "Failed to create socket (%s).", strerror(errno));
        goto fail;
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path) - 1, "%s", opts->address);

    unlink(sun.sun_path);
    if (bind(sock, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
        ERR(NULL, "Could not bind \"%s\" (%s).", opts->address, strerror(errno));
        goto fail;
    }

    if (opts->mode != (mode_t)-1) {
        if (chmod(sun.sun_path, opts->mode) < 0) {
            ERR(NULL, "Failed to set unix socket permissions (%s).", strerror(errno));
            goto fail;
        }
    }

    if ((opts->uid != (uid_t)-1) || (opts->gid != (gid_t)-1)) {
        if (chown(sun.sun_path, opts->uid, opts->gid) < 0) {
            ERR(NULL, "Failed to set unix socket uid/gid (%s).", strerror(errno));
            goto fail;
        }
    }

    if (listen(sock, NC_REVERSE_QUEUE) == -1) {
        ERR(NULL, "Unable to start listening on \"%s\" (%s).", opts->address, strerror(errno));
        goto fail;
    }

    return sock;

fail:
    if (sock > -1) {
        close(sock);
    }
    return -1;
}

/**
 * @brief Evaluate socket name for AF_UNIX socket.
 * @param[in] acc_sock_fd is file descriptor for the accepted socket (a nonnegative).
 * @param[out] host is pointer to char* to which the socket name will be set. It must not be NULL.
 * @return 0 in case of success. Call free function for parameter host to avoid a memory leak.
 * @return 0 if the stream socket is unnamed. Parameter host is set to NULL.
 * @return -1 in case of error. Parameter host is set to NULL.
 */
static int
sock_host_unix(int acc_sock_fd, char **host)
{
    char *sun_path;
    struct sockaddr_storage saddr;
    socklen_t addr_len;

    *host = NULL;
    saddr.ss_family = AF_UNIX;
    addr_len = sizeof(saddr);

    if (getsockname(acc_sock_fd, (struct sockaddr *)&saddr, &addr_len)) {
        ERR(NULL, "getsockname failed (%s).", strerror(errno));
        return -1;
    }

    sun_path = ((struct sockaddr_un *)&saddr)->sun_path;
    if (!sun_path) {
        /* stream socket is unnamed */
        return 0;
    }

    NC_CHECK_ERRMEM_RET(!(*host = strdup(sun_path)), -1);

    return 0;
}

/**
 * @brief Evaluate socket name and port number for AF_INET socket.
 * @param[in] addr is pointing to structure filled by accept function which was successful.
 * @param[out] host is pointer to char* to which the socket name will be set. It must not be NULL.
 * @param[out] port is pointer to uint16_t to which the port number will be set. It must not be NULL.
 * @return 0 in case of success. Call free function for parameter host to avoid a memory leak.
 * @return -1 in case of error. Parameter host is set to NULL and port is unchanged.
 */
static int
sock_host_inet(const struct sockaddr_in *addr, char **host, uint16_t *port)
{
    *host = malloc(INET_ADDRSTRLEN);
    NC_CHECK_ERRMEM_RET(!(*host), -1);

    if (!inet_ntop(AF_INET, &addr->sin_addr, *host, INET_ADDRSTRLEN)) {
        ERR(NULL, "inet_ntop failed (%s).", strerror(errno));
        free(*host);
        *host = NULL;
        return -1;
    }

    *port = ntohs(addr->sin_port);

    return 0;
}

/**
 * @brief Evaluate socket name and port number for AF_INET6 socket.
 * @param[in] addr is pointing to structure filled by accept function which was successful.
 * @param[out] host is pointer to char* to which the socket name will be set. It must not be NULL.
 * @param[out] port is pointer to uint16_t to which the port number will be set. It must not be NULL.
 * @return 0 in case of success. Call free function for parameter host to avoid a memory leak.
 * @return -1 in case of error. Parameter host is set to the NULL and port is unchanged.
 */
static int
sock_host_inet6(const struct sockaddr_in6 *addr, char **host, uint16_t *port)
{
    *host = malloc(INET6_ADDRSTRLEN);
    NC_CHECK_ERRMEM_RET(!(*host), -1);

    if (!inet_ntop(AF_INET6, &addr->sin6_addr, *host, INET6_ADDRSTRLEN)) {
        ERR(NULL, "inet_ntop failed (%s).", strerror(errno));
        free(*host);
        *host = NULL;
        return -1;
    }

    *port = ntohs(addr->sin6_port);

    return 0;
}

int
nc_sock_accept_binds(struct nc_bind *binds, uint16_t bind_count, pthread_mutex_t *bind_lock, int timeout, char **host,
        uint16_t *port, uint16_t *idx, int *sock)
{
    uint16_t i, j, pfd_count, client_port;
    char *client_address;
    struct pollfd *pfd;
    struct sockaddr_storage saddr;
    socklen_t saddr_len = sizeof(saddr);
    int ret, client_sock, server_sock = -1, flags;

    pfd = malloc(bind_count * sizeof *pfd);
    NC_CHECK_ERRMEM_RET(!pfd, -1);

    /* LOCK */
    pthread_mutex_lock(bind_lock);

    for (i = 0, pfd_count = 0; i < bind_count; ++i) {
        if (binds[i].sock < 0) {
            /* invalid socket */
            continue;
        }
        if (binds[i].pollin) {
            binds[i].pollin = 0;
            /* leftover pollin */
            server_sock = binds[i].sock;
            break;
        }
        pfd[pfd_count].fd = binds[i].sock;
        pfd[pfd_count].events = POLLIN;
        pfd[pfd_count].revents = 0;

        ++pfd_count;
    }

    if (server_sock == -1) {
        /* poll for a new connection */
        ret = nc_poll(pfd, pfd_count, timeout);
        if (ret < 1) {
            free(pfd);

            /* UNLOCK */
            pthread_mutex_unlock(bind_lock);

            return ret;
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
                    server_sock = pfd[j].fd;
                    break;
                } else {
                    /* just remember the event for next time */
                    binds[i].pollin = 1;
                }
            }
        }
    }
    free(pfd);
    if (server_sock == -1) {
        ERRINT;
        /* UNLOCK */
        pthread_mutex_unlock(bind_lock);
        return -1;
    }

    /* accept connection */
    client_sock = accept(server_sock, (struct sockaddr *)&saddr, &saddr_len);
    if (client_sock < 0) {
        ERR(NULL, "Accept failed (%s).", strerror(errno));
        /* UNLOCK */
        pthread_mutex_unlock(bind_lock);
        return -1;
    }

    /* make the socket non-blocking */
    if (((flags = fcntl(client_sock, F_GETFL)) == -1) || (fcntl(client_sock, F_SETFL, flags | O_NONBLOCK) == -1)) {
        ERR(NULL, "Fcntl failed (%s).", strerror(errno));
        goto fail;
    }

    /* learn information about the client end */
    if (saddr.ss_family == AF_UNIX) {
        if (sock_host_unix(client_sock, &client_address)) {
            goto fail;
        }
        client_port = 0;
    } else if (saddr.ss_family == AF_INET) {
        if (sock_host_inet((struct sockaddr_in *)&saddr, &client_address, &client_port)) {
            goto fail;
        }
    } else if (saddr.ss_family == AF_INET6) {
        if (sock_host_inet6((struct sockaddr_in6 *)&saddr, &client_address, &client_port)) {
            goto fail;
        }
    } else {
        ERR(NULL, "Source host of an unknown protocol family.");
        goto fail;
    }

    if (saddr.ss_family == AF_UNIX) {
        VRB(NULL, "Accepted a connection on %s.", binds[i].address);
    } else {
        VRB(NULL, "Accepted a connection on %s:%u from %s:%u.", binds[i].address, binds[i].port, client_address, client_port);
    }

    if (host) {
        *host = client_address;
    } else {
        free(client_address);
    }
    if (port) {
        *port = client_port;
    }
    if (idx) {
        *idx = i;
    }
    /* UNLOCK */
    pthread_mutex_unlock(bind_lock);

    *sock = client_sock;
    return 1;

fail:
    close(client_sock);
    /* UNLOCK */
    pthread_mutex_unlock(bind_lock);
    return -1;
}

API struct nc_server_reply *
nc_clb_default_get_schema(struct lyd_node *rpc, struct nc_session *session)
{
    const char *identifier = NULL, *revision = NULL, *format = NULL;
    char *model_data = NULL;
    struct ly_out *out;
    const struct lys_module *module = NULL, *mod;
    const struct lysp_submodule *submodule = NULL;
    struct lyd_node *child, *err, *data = NULL;
    LYS_OUTFORMAT outformat = 0;

    LY_LIST_FOR(lyd_child(rpc), child) {
        if (!strcmp(child->schema->name, "identifier")) {
            identifier = lyd_get_value(child);
        } else if (!strcmp(child->schema->name, "version")) {
            revision = lyd_get_value(child);
            if (revision && (revision[0] == '\0')) {
                revision = NULL;
            }
        } else if (!strcmp(child->schema->name, "format")) {
            format = lyd_get_value(child);
        }
    }
    VRB(session, "Module \"%s@%s\" was requested.", identifier, revision ? revision : "<any>");

    /* check revision */
    if (revision && (strlen(revision) != 10) && strcmp(revision, "1.0")) {
        err = nc_err(session->ctx, NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, "The requested version is not supported.", "en");
        return nc_server_reply_err(err);
    }

    if (revision) {
        /* get specific module */
        module = ly_ctx_get_module(session->ctx, identifier, revision);
        if (!module) {
            submodule = ly_ctx_get_submodule(session->ctx, identifier, revision);
        }
    } else {
        /* try to get implemented, then latest module */
        module = ly_ctx_get_module_implemented(session->ctx, identifier);
        if (!module) {
            module = ly_ctx_get_module_latest(session->ctx, identifier);
        }
        if (!module) {
            submodule = ly_ctx_get_submodule_latest(session->ctx, identifier);
        }
    }
    if (!module && !submodule) {
        err = nc_err(session->ctx, NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, "The requested module was not found.", "en");
        return nc_server_reply_err(err);
    }

    /* check format */
    if (!format || !strcmp(format, "ietf-netconf-monitoring:yang")) {
        outformat = LYS_OUT_YANG;
    } else if (!strcmp(format, "ietf-netconf-monitoring:yin")) {
        outformat = LYS_OUT_YIN;
    } else {
        err = nc_err(session->ctx, NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, "The requested format is not supported.", "en");
        return nc_server_reply_err(err);
    }

    /* print */
    ly_out_new_memory(&model_data, 0, &out);
    if (module) {
        lys_print_module(out, module, outformat, 0, 0);
    } else {
        lys_print_submodule(out, submodule, outformat, 0, 0);
    }
    ly_out_free(out, NULL, 0);
    if (!model_data) {
        ERRINT;
        return NULL;
    }

    /* create reply */
    mod = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf-monitoring");
    if (!mod || lyd_new_inner(NULL, mod, "get-schema", 0, &data)) {
        ERRINT;
        free(model_data);
        return NULL;
    }
    if (lyd_new_any(data, NULL, "data", model_data, LYD_ANYDATA_STRING, LYD_NEW_ANY_USE_VALUE | LYD_NEW_VAL_OUTPUT, NULL)) {
        ERRINT;
        free(model_data);
        lyd_free_tree(data);
        return NULL;
    }

    return nc_server_reply_data(data, NC_WD_EXPLICIT, NC_PARAMTYPE_FREE);
}

API struct nc_server_reply *
nc_clb_default_close_session(struct lyd_node *UNUSED(rpc), struct nc_session *session)
{
    session->term_reason = NC_SESSION_TERM_CLOSED;
    return nc_server_reply_ok();
}

/**
 * @brief Initialize a context with default RPC callbacks if none are set.
 *
 * @param[in] ctx Context to initialize.
 */
static void
nc_server_init_cb_ctx(const struct ly_ctx *ctx)
{
    struct lysc_node *rpc;

    if (global_rpc_clb) {
        /* expect it to handle these RPCs as well */
        return;
    }

    /* set default <get-schema> callback if not specified */
    rpc = NULL;
    if (ly_ctx_get_module_implemented(ctx, "ietf-netconf-monitoring")) {
        rpc = (struct lysc_node *)lys_find_path(ctx, NULL, "/ietf-netconf-monitoring:get-schema", 0);
    }
    if (rpc && !rpc->priv) {
        rpc->priv = nc_clb_default_get_schema;
    }

    /* set default <close-session> callback if not specified */
    rpc = (struct lysc_node *)lys_find_path(ctx, NULL, "/ietf-netconf:close-session", 0);
    if (rpc && !rpc->priv) {
        rpc->priv = nc_clb_default_close_session;
    }
}

API int
nc_server_init(void)
{
    pthread_rwlockattr_t *attr_p = NULL;
    int r;

    ATOMIC_STORE_RELAXED(server_opts.new_session_id, 1);
    ATOMIC_STORE_RELAXED(server_opts.new_client_id, 1);

#ifdef HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP
    pthread_rwlockattr_t attr;

    if ((r = pthread_rwlockattr_init(&attr))) {
        ERR(NULL, "%s: failed init attribute (%s).", __func__, strerror(r));
        goto error;
    }
    attr_p = &attr;
    if ((r = pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP))) {
        ERR(NULL, "%s: failed set attribute (%s).", __func__, strerror(r));
        goto error;
    }
#endif

    if ((r = pthread_rwlock_init(&server_opts.config_lock, attr_p))) {
        ERR(NULL, "%s: failed to init rwlock(%s).", __func__, strerror(r));
        goto error;
    }
    if ((r = pthread_rwlock_init(&server_opts.ch_client_lock, attr_p))) {
        ERR(NULL, "%s: failed to init rwlock(%s).", __func__, strerror(r));
        goto error;
    }

    if (attr_p) {
        pthread_rwlockattr_destroy(attr_p);
    }

#ifdef NC_ENABLED_SSH_TLS
    if (curl_global_init(CURL_GLOBAL_SSL | CURL_GLOBAL_ACK_EINTR)) {
        ERR(NULL, "%s: failed to init CURL.", __func__);
        goto error;
    }

    /* optional for dynamic library, mandatory for static */
    if (ssh_init()) {
        ERR(NULL, "%s: failed to init libssh.", __func__);
        goto error;
    }
#endif

    if ((r = pthread_mutex_init(&server_opts.bind_lock, NULL))) {
        ERR(NULL, "%s: failed to init bind lock(%s).", __func__, strerror(r));
        goto error;
    }

#ifdef NC_ENABLED_SSH_TLS
    if ((r = pthread_mutex_init(&server_opts.cert_exp_notif.lock, NULL))) {
        ERR(NULL, "%s: failed to init certificate expiration notification thread lock(%s).", __func__, strerror(r));
        goto error;
    }
    if ((r = pthread_cond_init(&server_opts.cert_exp_notif.cond, NULL))) {
        ERR(NULL, "%s: failed to init certificate expiration notification thread condition(%s).", __func__, strerror(r));
        goto error;
    }
#endif

    return 0;

error:
    if (attr_p) {
        pthread_rwlockattr_destroy(attr_p);
    }
    return -1;
}

API void
nc_server_destroy(void)
{
    uint32_t i, endpt_count;

    for (i = 0; i < server_opts.capabilities_count; i++) {
        free(server_opts.capabilities[i]);
    }
    free(server_opts.capabilities);
    server_opts.capabilities = NULL;
    server_opts.capabilities_count = 0;
    if (server_opts.content_id_data && server_opts.content_id_data_free) {
        server_opts.content_id_data_free(server_opts.content_id_data);
    }

#ifdef NC_ENABLED_SSH_TLS
    /* destroy the certificate expiration notification thread */
    nc_server_notif_cert_expiration_thread_stop(1);
    nc_server_config_ln2_netconf_server(NULL, NC_OP_DELETE);
#endif /* NC_ENABLED_SSH_TLS */

    nc_server_config_listen(NULL, NC_OP_DELETE);
    nc_server_config_ch(NULL, NC_OP_DELETE);

    endpt_count = server_opts.endpt_count;
    for (i = 0; i < endpt_count; i++) {
        if (server_opts.endpts[i].ti == NC_TI_UNIX) {
            _nc_server_del_endpt_unix_socket(&server_opts.endpts[i], &server_opts.binds[i]);
        }
    }

    pthread_mutex_destroy(&server_opts.bind_lock);

#ifdef NC_ENABLED_SSH_TLS
    free(server_opts.authkey_path_fmt);
    server_opts.authkey_path_fmt = NULL;
    free(server_opts.pam_config_name);
    server_opts.pam_config_name = NULL;
    if (server_opts.interactive_auth_data && server_opts.interactive_auth_data_free) {
        server_opts.interactive_auth_data_free(server_opts.interactive_auth_data);
    }
    server_opts.interactive_auth_data = NULL;
    server_opts.interactive_auth_data_free = NULL;

    nc_server_config_ks_keystore(NULL, NC_OP_DELETE);
    nc_server_config_ts_truststore(NULL, NC_OP_DELETE);
    curl_global_cleanup();
    ssh_finalize();
#endif /* NC_ENABLED_SSH_TLS */
}

API int
nc_server_set_capab_withdefaults(NC_WD_MODE basic_mode, int also_supported)
{
    if (!basic_mode || (basic_mode == NC_WD_ALL_TAG)) {
        ERRARG(NULL, "basic_mode");
        return -1;
    } else if (also_supported && !(also_supported & (NC_WD_ALL | NC_WD_ALL_TAG | NC_WD_TRIM | NC_WD_EXPLICIT))) {
        ERRARG(NULL, "also_supported");
        return -1;
    }

    ATOMIC_STORE_RELAXED(server_opts.wd_basic_mode, basic_mode);
    ATOMIC_STORE_RELAXED(server_opts.wd_also_supported, also_supported);
    return 0;
}

API void
nc_server_get_capab_withdefaults(NC_WD_MODE *basic_mode, int *also_supported)
{
    if (!basic_mode && !also_supported) {
        ERRARG(NULL, "basic_mode and also_supported");
        return;
    }

    if (basic_mode) {
        *basic_mode = ATOMIC_LOAD_RELAXED(server_opts.wd_basic_mode);
    }
    if (also_supported) {
        *also_supported = ATOMIC_LOAD_RELAXED(server_opts.wd_also_supported);
    }
}

API int
nc_server_set_capability(const char *value)
{
    void *mem;

    if (!value || !value[0]) {
        ERRARG(NULL, "value must not be empty");
        return EXIT_FAILURE;
    }

    mem = realloc(server_opts.capabilities, (server_opts.capabilities_count + 1) * sizeof *server_opts.capabilities);
    NC_CHECK_ERRMEM_RET(!mem, EXIT_FAILURE);
    server_opts.capabilities = mem;

    server_opts.capabilities[server_opts.capabilities_count] = strdup(value);
    server_opts.capabilities_count++;

    return EXIT_SUCCESS;
}

API void
nc_server_set_content_id_clb(char *(*content_id_clb)(void *user_data), void *user_data,
        void (*free_user_data)(void *user_data))
{
    server_opts.content_id_clb = content_id_clb;
    server_opts.content_id_data = user_data;
    server_opts.content_id_data_free = free_user_data;
}

API NC_MSG_TYPE
nc_accept_inout(int fdin, int fdout, const char *username, const struct ly_ctx *ctx, struct nc_session **session)
{
    NC_MSG_TYPE msgtype;
    struct timespec ts_cur;

    NC_CHECK_ARG_RET(NULL, ctx, username, fdin >= 0, fdout >= 0, session, NC_MSG_ERROR);

    NC_CHECK_SRV_INIT_RET(NC_MSG_ERROR);

    /* init ctx as needed */
    nc_server_init_cb_ctx(ctx);

    /* prepare session structure */
    *session = nc_new_session(NC_SERVER, 0);
    NC_CHECK_ERRMEM_RET(!(*session), NC_MSG_ERROR);
    (*session)->status = NC_STATUS_STARTING;

    /* transport specific data */
    (*session)->ti_type = NC_TI_FD;
    (*session)->ti.fd.in = fdin;
    (*session)->ti.fd.out = fdout;

    /* assign context */
    (*session)->flags = NC_SESSION_SHAREDCTX;
    (*session)->ctx = (struct ly_ctx *)ctx;

    /* assign new SID atomically */
    (*session)->id = ATOMIC_INC_RELAXED(server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(*session);
    if (msgtype != NC_MSG_HELLO) {
        nc_session_free(*session, NULL);
        *session = NULL;
        return msgtype;
    }

    nc_timeouttime_get(&ts_cur, 0);
    (*session)->opts.server.last_rpc = ts_cur.tv_sec;
    nc_realtime_get(&ts_cur);
    (*session)->opts.server.session_start = ts_cur;

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

    /* LOCK */
    ret = pthread_mutex_lock(&ps->lock);
    if (ret) {
        ERR(NULL, "%s: failed to lock a pollsession (%s).", func, strerror(ret));
        return -1;
    }

    /* check that the queue is long enough */
    if (ps->queue_len == NC_PS_QUEUE_SIZE) {
        ERR(NULL, "%s: pollsession queue size (%d) too small.", func, NC_PS_QUEUE_SIZE);
        pthread_mutex_unlock(&ps->lock);
        return -1;
    }

    /* add ourselves into the queue */
    nc_ps_queue_add_id(ps, id);
    DBL(NULL, "PS 0x%p TID %lu queue: added %u, head %u, length %u", ps, (long unsigned int)pthread_self(), *id,
            ps->queue[ps->queue_begin], ps->queue_len);

    /* is it our turn? */
    while (ps->queue[ps->queue_begin] != *id) {
        nc_timeouttime_get(&ts, NC_PS_QUEUE_TIMEOUT);

        ret = pthread_cond_clockwait(&ps->cond, &ps->lock, COMPAT_CLOCK_ID, &ts);
        if (ret) {
            /**
             * This may happen when another thread releases the lock and broadcasts the condition
             * and this thread had already timed out. When this thread is scheduled, it returns timed out error
             * but when actually this thread was ready for condition.
             */
            if ((ETIMEDOUT == ret) && (ps->queue[ps->queue_begin] == *id)) {
                break;
            }

            ERR(NULL, "%s: failed to wait for a pollsession condition (%s).", func, strerror(ret));
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

    /* LOCK */
    ret = pthread_mutex_lock(&ps->lock);
    if (ret) {
        ERR(NULL, "%s: failed to lock a pollsession (%s).", func, strerror(ret));
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
    DBL(NULL, "PS 0x%p TID %lu queue: removed %u, head %u, length %u", ps, (long unsigned int)pthread_self(), id,
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
    NC_CHECK_ERRMEM_RET(!ps, NULL);
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
        ERR(NULL, "FATAL: Freeing a pollsession structure that is currently being worked with!");
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

    NC_CHECK_ARG_RET(session, ps, session, -1);

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

    NC_CHECK_ARG_RET(session, ps, session, -1);

    /* LOCK */
    if (nc_ps_lock(ps, &q_id, __func__)) {
        return -1;
    }

    ret = _nc_ps_del_session(ps, session, -1);

    /* UNLOCK */
    ret2 = nc_ps_unlock(ps, q_id, __func__);

    return ret || ret2 ? -1 : 0;
}

API struct nc_session *
nc_ps_get_session(const struct nc_pollsession *ps, uint16_t idx)
{
    uint8_t q_id;
    struct nc_session *ret = NULL;

    NC_CHECK_ARG_RET(NULL, ps, NULL);

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

API struct nc_session *
nc_ps_find_session(const struct nc_pollsession *ps, nc_ps_session_match_cb match_cb, void *cb_data)
{
    uint8_t q_id;
    uint16_t i;
    struct nc_session *ret = NULL;

    NC_CHECK_ARG_RET(NULL, ps, NULL);

    /* LOCK */
    if (nc_ps_lock((struct nc_pollsession *)ps, &q_id, __func__)) {
        return NULL;
    }

    for (i = 0; i < ps->session_count; ++i) {
        if (match_cb(ps->sessions[i]->session, cb_data)) {
            ret = ps->sessions[i]->session;
            break;
        }
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

    NC_CHECK_ARG_RET(NULL, ps, 0);

    /* LOCK (just for memory barrier so that we read the current value) */
    if (nc_ps_lock((struct nc_pollsession *)ps, &q_id, __func__)) {
        return 0;
    }

    session_count = ps->session_count;

    /* UNLOCK */
    nc_ps_unlock((struct nc_pollsession *)ps, q_id, __func__);

    return session_count;
}

static NC_MSG_TYPE
recv_rpc_check_msgid(struct nc_session *session, const struct lyd_node *envp)
{
    struct lyd_attr *attr;

    assert(envp && !envp->schema);

    /* find the message-id attribute */
    LY_LIST_FOR(((struct lyd_node_opaq *)envp)->attr, attr) {
        if (!strcmp(attr->name.name, "message-id")) {
            break;
        }
    }

    if (!attr) {
        ERR(session, "Received an <rpc> without a message-id.");
        return NC_MSG_REPLY_ERR_MSGID;
    }

    return NC_MSG_RPC;
}

/**
 * @brief Find lysc node mentioned in schema_path.
 *
 * @param[in] ctx libyang context.
 * @param[in] ly_err last libyang error.
 * @return lysc node.
 */
static const struct lysc_node *
nc_rpc_err_find_lysc_node(const struct ly_ctx *ctx, const struct ly_err_item *ly_err)
{
    char *str, *last;
    const struct lysc_node *cn;

    if (!ly_err->schema_path) {
        return NULL;
    }

    str = strdup(ly_err->schema_path);
    if (!str) {
        return NULL;
    }
    last = strrchr(str, '/');
    if (strchr(last, '@')) {
        /* ignore attribute part */
        *last = '\0';
    }
    cn = lys_find_path(ctx, NULL, str, 0);
    free(str);

    return cn;
}

/**
 * @brief Find the nth substring delimited by quotes.
 *
 * For example: abcd"ef"ghij"kl"mn -> index 0 is "ef", index 1 is "kl".
 *
 * @param[in] msg Input string with quoted substring.
 * @param[in] index Number starting from 0 specifying the nth substring.
 * @return Copied nth substring without quotes.
 */
static char *
nc_rpc_err_get_quoted_string(const char *msg, uint32_t index)
{
    char *ret;
    const char *start = NULL, *end = NULL, *iter, *tmp;
    uint32_t quote_cnt = 0, last_quote;

    assert(msg);

    last_quote = (index + 1) * 2;
    for (iter = msg; *iter; ++iter) {
        if (*iter != '\"') {
            continue;
        }
        /* updating the start and end pointers - swap */
        tmp = end;
        end = iter;
        start = tmp;
        if (++quote_cnt == last_quote) {
            /* nth substring found */
            break;
        }
    }

    if (!start) {
        return NULL;
    }

    /* Skip first quote */
    ++start;
    /* Copy substring */
    ret = strndup(start, end - start);

    return ret;
}

/**
 * @brief Check that the @p str starts with the @p prefix.
 *
 * @param[in] prefix Required prefix.
 * @param[in] str Input string to check.
 * @return True if @p str start with @p prefix otherwise False.
 */
static ly_bool
nc_strstarts(const char *prefix, const char *str)
{
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

/**
 * @brief Prepare reply for rpc error.
 *
 * @param[in] session NETCONF session.
 * @param[in] envp NETCONF-specific RPC envelope. Can be NULL.
 * @return rpc-reply object or NULL.
 */
static struct nc_server_reply *
nc_server_prepare_rpc_err(struct nc_session *session, struct lyd_node *envp)
{
    struct lyd_node *reply = NULL;
    const struct lysc_node *cn;
    const struct ly_err_item *ly_err;
    NC_ERR_TYPE errtype;
    const char *attr;
    char *str = NULL, *errmsg = NULL, *schema_path = NULL;
    LY_ERR errcode;

    /* envelope was not parsed */
    if (!envp && (session->version != NC_VERSION_11)) {
        return NULL;
    }
    ly_err = ly_err_last(session->ctx);
    if (!envp && !strcmp("Missing XML namespace.", ly_err->msg)) {
        reply = nc_err(session->ctx, NC_ERR_MISSING_ATTR, NC_ERR_TYPE_RPC, "xmlns", "rpc");
        goto cleanup;
    } else if (!envp) {
        /* completely malformed message, NETCONF version 1.1 defines sending error reply from
         * the server (RFC 6241 sec. 3) */
        reply = nc_err(session->ctx, NC_ERR_MALFORMED_MSG);
        return nc_server_reply_err(reply);
    }
    /* at least the envelopes were parsed */
    assert(envp);

    /* store strings, to avoid overwriting ly_err */
    errmsg = strdup(ly_err->msg);
    if (!errmsg) {
        reply = nc_err(session->ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        goto cleanup;
    }
    if (ly_err->schema_path) {
        schema_path = strdup(ly_err->schema_path);
        if (!schema_path) {
            reply = nc_err(session->ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            goto cleanup;
        }
    }
    errcode = ly_err->err;

    /* find out in which layer the error occurred */
    cn = nc_rpc_err_find_lysc_node(session->ctx, ly_err);
    if (cn && ((cn->nodetype & LYS_RPC) || (cn->nodetype & LYS_INPUT))) {
        errtype = NC_ERR_TYPE_PROT;
    } else {
        errtype = NC_ERR_TYPE_APP;
    }

    /* deciding which error to prepare */
    if (cn && (nc_strstarts("Missing mandatory prefix", errmsg) ||
            nc_strstarts("Unknown XML prefix", errmsg))) {
        str = nc_rpc_err_get_quoted_string(errmsg, 1);
        reply = str ? nc_err(session->ctx, NC_ERR_UNKNOWN_ATTR, errtype, str, cn->name) :
                nc_err(session->ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
    } else if (cn && nc_strstarts("Annotation definition for attribute", errmsg)) {
        attr = strrchr(schema_path, ':') + 1;
        reply = nc_err(session->ctx, NC_ERR_UNKNOWN_ATTR, errtype, attr, cn->name);
    } else if (nc_strstarts("Invalid character sequence", errmsg)) {
        reply = nc_err(session->ctx, NC_ERR_MALFORMED_MSG);
    } else if (errcode == LY_EMEM) {
        /* <error-tag>resource-denied</error-tag> */
        reply = nc_err(session->ctx, NC_ERR_RES_DENIED, errtype);
    } else {
        /* prepare some generic error */
        reply = nc_err(session->ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
    }

cleanup:
    nc_err_set_msg(reply, errmsg, "en");

    /* clear for other errors */
    ly_err_clean(session->ctx, NULL);

    free(errmsg);
    free(schema_path);
    free(str);

    return nc_server_reply_err(reply);
}

/* should be called holding the session RPC lock! IO lock will be acquired as needed
 * returns: NC_PSPOLL_ERROR,
 *          NC_PSPOLL_TIMEOUT,
 *          NC_PSPOLL_BAD_RPC (| NC_PSPOLL_REPLY_ERROR),
 *          NC_PSPOLL_RPC
 */
static int
nc_server_recv_rpc_io(struct nc_session *session, int io_timeout, struct nc_server_rpc **rpc)
{
    struct ly_in *msg;
    struct nc_server_reply *reply = NULL;
    int r, ret = 0;

    NC_CHECK_ARG_RET(session, session, rpc, NC_PSPOLL_ERROR);

    if ((session->status != NC_STATUS_RUNNING) || (session->side != NC_SERVER)) {
        ERR(session, "Invalid session to receive RPCs.");
        return NC_PSPOLL_ERROR;
    }

    *rpc = NULL;

    /* get a message */
    r = nc_read_msg_io(session, io_timeout, &msg, 0);
    if (r == -2) {
        /* malformed message */
        reply = nc_server_reply_err(nc_err(session->ctx, NC_ERR_MALFORMED_MSG));
        goto cleanup;
    }
    if (r == -1) {
        return NC_PSPOLL_ERROR;
    } else if (!r) {
        return NC_PSPOLL_TIMEOUT;
    }

    *rpc = calloc(1, sizeof **rpc);
    NC_CHECK_ERRMEM_GOTO(!*rpc, ret = NC_PSPOLL_ERROR, cleanup);

    /* parse the RPC */
    if (!lyd_parse_op(session->ctx, NULL, msg, LYD_XML, LYD_TYPE_RPC_NETCONF, &(*rpc)->envp, &(*rpc)->rpc)) {
        /* check message-id */
        if (recv_rpc_check_msgid(session, (*rpc)->envp) == NC_MSG_RPC) {
            /* valid RPC */
            ret = NC_PSPOLL_RPC;
        } else {
            /* no message-id */
            reply = nc_server_reply_err(nc_err(session->ctx, NC_ERR_MISSING_ATTR, NC_ERR_TYPE_RPC, "message-id", "rpc"));
            ret = NC_PSPOLL_BAD_RPC;
        }
    } else {
        /* bad RPC received */
        reply = nc_server_prepare_rpc_err(session, (*rpc)->envp);
        ret = NC_PSPOLL_BAD_RPC;
    }

cleanup:
    if (reply) {
        /* send error reply */
        r = nc_write_msg_io(session, io_timeout, NC_MSG_REPLY, *rpc ? (*rpc)->envp : NULL, reply);
        nc_server_reply_free(reply);
        if (r != NC_MSG_REPLY) {
            ERR(session, "Failed to write reply (%s), terminating session.", nc_msgtype2str[r]);
            if (session->status != NC_STATUS_INVALID) {
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_OTHER;
            }
        }

        /* bad RPC and an error reply sent */
        ret |= NC_PSPOLL_REPLY_ERROR;
    }

    ly_in_free(msg, 1);
    if (ret != NC_PSPOLL_RPC) {
        nc_server_rpc_free(*rpc);
        *rpc = NULL;
    }
    return ret;
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
    if (!session || (session->side != NC_SERVER) || !nc_session_get_notif_status(session)) {
        ERRARG(NULL, "session");
        return NC_MSG_ERROR;
    } else if (!notif || !notif->ntf || !notif->eventtime) {
        ERRARG(NULL, "notif");
        return NC_MSG_ERROR;
    }

    /* we do not need RPC lock for this, IO lock will be acquired properly */
    ret = nc_write_msg_io(session, timeout, NC_MSG_NOTIF, notif);
    if (ret != NC_MSG_NOTIF) {
        ERR(session, "Failed to write notification (%s).", nc_msgtype2str[ret]);
    }

    return ret;
}

/**
 * @brief Send a reply acquiring IO lock as needed.
 * Session RPC lock must be held!
 *
 * @param[in] session Session to use.
 * @param[in] io_timeout Timeout to use for acquiring IO lock.
 * @param[in] rpc RPC to sent.
 * @return 0 on success.
 * @return Bitmask of NC_PSPOLL_ERROR (any fatal error) and NC_PSPOLL_REPLY_ERROR (reply failed to be sent).
 * @return NC_PSPOLL_ERROR on other errors.
 */
static int
nc_server_send_reply_io(struct nc_session *session, int io_timeout, const struct nc_server_rpc *rpc)
{
    nc_rpc_clb clb;
    struct nc_server_reply *reply;
    const struct lysc_node *rpc_act = NULL;
    struct lyd_node *elem;
    int ret = 0;
    NC_MSG_TYPE r;

    if (!rpc) {
        ERRINT;
        return NC_PSPOLL_ERROR;
    }

    if (rpc->rpc->schema->nodetype == LYS_RPC) {
        /* RPC */
        rpc_act = rpc->rpc->schema;
    } else {
        /* action */
        LYD_TREE_DFS_BEGIN(rpc->rpc, elem) {
            if (elem->schema->nodetype == LYS_ACTION) {
                rpc_act = elem->schema;
                break;
            }
            LYD_TREE_DFS_END(rpc->rpc, elem);
        }
        if (!rpc_act) {
            ERRINT;
            return NC_PSPOLL_ERROR;
        }
    }

    if (!rpc_act->priv) {
        if (!global_rpc_clb) {
            /* no callback, reply with a not-implemented error */
            reply = nc_server_reply_err(nc_err(session->ctx, NC_ERR_OP_NOT_SUPPORTED, NC_ERR_TYPE_PROT));
        } else {
            reply = global_rpc_clb(rpc->rpc, session);
        }
    } else {
        clb = (nc_rpc_clb)rpc_act->priv;
        reply = clb(rpc->rpc, session);
    }

    if (!reply) {
        reply = nc_server_reply_err(nc_err(session->ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP));
    }
    r = nc_write_msg_io(session, io_timeout, NC_MSG_REPLY, rpc->envp, reply);
    if (reply->type == NC_RPL_ERROR) {
        ret |= NC_PSPOLL_REPLY_ERROR;
    }
    nc_server_reply_free(reply);

    if (r != NC_MSG_REPLY) {
        ERR(session, "Failed to write reply (%s).", nc_msgtype2str[r]);
        ret |= NC_PSPOLL_ERROR;
    }

    /* special case if term_reason was set in callback, last reply was sent (needed for <close-session> if nothing else) */
    if ((session->status == NC_STATUS_RUNNING) && (session->term_reason != NC_SESSION_TERM_NONE)) {
        session->status = NC_STATUS_INVALID;
    }

    return ret;
}

/**
 * @brief Poll a session from pspoll acquiring IO lock as needed.
 * Session must be running and session RPC lock held!
 *
 * @param[in] session Session to use.
 * @param[in] io_timeout Timeout to use for acquiring IO lock.
 * @param[in] now_mono Current monotonic timestamp.
 * @param[in,out] msg Message to fill in case of an error.
 * @return NC_PSPOLL_RPC if some application data are available.
 * @return NC_PSPOLL_TIMEOUT if a timeout elapsed.
 * @return NC_PSPOLL_SSH_CHANNEL if a new SSH channel has been created.
 * @return NC_PSPOLL_SSH_MSG if just an SSH message has been processed.
 * @return NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR if session has been terminated (@p msg filled).
 * @return NC_PSPOLL_ERROR on other fatal errors (@p msg filled).
 */
static int
nc_ps_poll_session_io(struct nc_session *session, int io_timeout, time_t now_mono, char *msg)
{
    struct pollfd pfd;
    int r, ret = 0;

#ifdef NC_ENABLED_SSH_TLS
    ssh_message ssh_msg;
    struct nc_session *new;
#endif /* NC_ENABLED_SSH_TLS */

    /* check timeout first */
    if (!(session->flags & NC_SESSION_CALLHOME) && !nc_session_get_notif_status(session) && server_opts.idle_timeout &&
            (now_mono >= session->opts.server.last_rpc + (unsigned) server_opts.idle_timeout)) {
        sprintf(msg, "Session idle timeout elapsed");
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_TIMEOUT;
        return NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
    }

    r = nc_session_io_lock(session, io_timeout, __func__);
    if (r < 0) {
        sprintf(msg, "Session IO lock failed to be acquired");
        return NC_PSPOLL_ERROR;
    } else if (!r) {
        return NC_PSPOLL_TIMEOUT;
    }

    switch (session->ti_type) {
#ifdef NC_ENABLED_SSH_TLS
    case NC_TI_SSH:
        ssh_msg = ssh_message_get(session->ti.libssh.session);
        if (ssh_msg) {
            if (nc_session_ssh_msg(session, NULL, ssh_msg, NULL)) {
                ssh_message_reply_default(ssh_msg);
            }
            if (session->ti.libssh.next) {
                for (new = session->ti.libssh.next; new != session; new = new->ti.libssh.next) {
                    if ((new->status == NC_STATUS_STARTING) && new->ti.libssh.channel &&
                            (new->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
                        /* new NETCONF SSH channel */
                        ret = NC_PSPOLL_SSH_CHANNEL;
                        break;
                    }
                }
                if (new != session) {
                    ssh_message_free(ssh_msg);
                    break;
                }
            }
            if (!ret) {
                /* just some SSH message */
                ret = NC_PSPOLL_SSH_MSG;
            }
            ssh_message_free(ssh_msg);

            /* break because 1) we don't want to return anything here ORred with NC_PSPOLL_RPC
             * and 2) we don't want to delay openning a new channel by waiting for a RPC to get processed
             */
            break;
        }

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
            /* no application data received */
            ret = NC_PSPOLL_TIMEOUT;
        } else {
            /* we have some application data */
            ret = NC_PSPOLL_RPC;
        }
        break;
    case NC_TI_TLS:
        r = nc_tls_get_num_pending_bytes_wrap(session->ti.tls.session);
        if (!r) {
            /* no data pending in the SSL buffer, poll fd */
            pfd.fd = nc_tls_get_fd_wrap(session);
            if (pfd.fd < 0) {
                sprintf(msg, "Internal error (%s:%d)", __FILE__, __LINE__);
                ret = NC_PSPOLL_ERROR;
                break;
            }
            pfd.events = POLLIN;
            pfd.revents = 0;
            r = nc_poll(&pfd, 1, 0);

            if (r < 0) {
                sprintf(msg, "Poll failed (%s)", strerror(errno));
                session->status = NC_STATUS_INVALID;
                ret = NC_PSPOLL_ERROR;
            } else if (r > 0) {
                if (pfd.revents & (POLLHUP | POLLNVAL)) {
                    sprintf(msg, "Communication socket unexpectedly closed");
                    session->status = NC_STATUS_INVALID;
                    session->term_reason = NC_SESSION_TERM_DROPPED;
                    ret = NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
                } else if (pfd.revents & POLLERR) {
                    sprintf(msg, "Communication socket error");
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
#endif /* NC_ENABLED_SSH_TLS */
    case NC_TI_FD:
    case NC_TI_UNIX:
        pfd.fd = (session->ti_type == NC_TI_FD) ? session->ti.fd.in : session->ti.unixsock.sock;
        pfd.events = POLLIN;
        pfd.revents = 0;
        r = nc_poll(&pfd, 1, 0);

        if (r < 0) {
            sprintf(msg, "Poll failed (%s)", strerror(errno));
            session->status = NC_STATUS_INVALID;
            ret = NC_PSPOLL_ERROR;
        } else if (r > 0) {
            if (pfd.revents & (POLLHUP | POLLNVAL)) {
                sprintf(msg, "Communication socket unexpectedly closed");
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_DROPPED;
                ret = NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
            } else if (pfd.revents & POLLERR) {
                sprintf(msg, "Communication socket error");
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
        sprintf(msg, "Internal error (%s:%d)", __FILE__, __LINE__);
        ret = NC_PSPOLL_ERROR;
        break;
    }

    nc_session_io_unlock(session, __func__);
    return ret;
}

/**
 * @brief Poll a single pspoll session.
 *
 * @param[in] ps_session pspoll session to poll.
 * @param[in] now_mono Current monotonic timestamp.
 * @return NC_PSPOLL_RPC if some application data are available.
 * @return NC_PSPOLL_TIMEOUT if a timeout elapsed.
 * @return NC_PSPOLL_SSH_CHANNEL if a new SSH channel has been created.
 * @return NC_PSPOLL_SSH_MSG if just an SSH message has been processed.
 * @return NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR if session has been terminated.
 * @return NC_PSPOLL_ERROR on other fatal errors.
 */
static int
nc_ps_poll_sess(struct nc_ps_session *ps_session, time_t now_mono)
{
    int ret = NC_PSPOLL_ERROR;
    char msg[256];

    switch (ps_session->state) {
    case NC_PS_STATE_NONE:
        if (ps_session->session->status == NC_STATUS_RUNNING) {
            /* session is fine, work with it */
            ps_session->state = NC_PS_STATE_BUSY;

            ret = nc_ps_poll_session_io(ps_session->session, NC_SESSION_LOCK_TIMEOUT, now_mono, msg);
            switch (ret) {
            case NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR:
                ERR(ps_session->session, "%s.", msg);
                ps_session->state = NC_PS_STATE_INVALID;
                break;
            case NC_PSPOLL_ERROR:
                ERR(ps_session->session, "%s.", msg);
                ps_session->state = NC_PS_STATE_NONE;
                break;
            case NC_PSPOLL_TIMEOUT:
#ifdef NC_ENABLED_SSH_TLS
            case NC_PSPOLL_SSH_CHANNEL:
            case NC_PSPOLL_SSH_MSG:
#endif /* NC_ENABLED_SSH_TLS */
                ps_session->state = NC_PS_STATE_NONE;
                break;
            case NC_PSPOLL_RPC:
                /* let's keep the state busy, we are not done with this session */
                break;
            }
        } else {
            /* session is not fine, let the caller know */
            ret = NC_PSPOLL_SESSION_TERM;
            if (ps_session->session->term_reason != NC_SESSION_TERM_CLOSED) {
                ret |= NC_PSPOLL_SESSION_ERROR;
            }
            ps_session->state = NC_PS_STATE_INVALID;
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

    return ret;
}

API int
nc_ps_poll(struct nc_pollsession *ps, int timeout, struct nc_session **session)
{
    int ret = NC_PSPOLL_ERROR, r;
    uint8_t q_id;
    uint16_t i, j;
    struct timespec ts_timeout, ts_cur;
    struct nc_session *cur_session;
    struct nc_ps_session *cur_ps_session;
    struct nc_server_rpc *rpc = NULL;

    NC_CHECK_ARG_RET(NULL, ps, NC_PSPOLL_ERROR);

    if (session) {
        *session = NULL;
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
    nc_timeouttime_get(&ts_cur, 0);
    if (timeout > -1) {
        nc_timeouttime_get(&ts_timeout, timeout);
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
                ret = nc_ps_poll_sess(cur_ps_session, ts_timeout.tv_sec);

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

            if ((timeout > -1) && (nc_timeouttime_cur_diff(&ts_timeout) < 1)) {
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
#ifdef NC_ENABLED_SSH_TLS
    case NC_PSPOLL_SSH_CHANNEL:
    case NC_PSPOLL_SSH_MSG:
#endif /* NC_ENABLED_SSH_TLS */
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
        nc_server_rpc_free(rpc);

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
        ERRARG(NULL, "ps");
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

int
nc_server_set_address_port(struct nc_endpt *endpt, struct nc_bind *bind, const char *address, uint16_t port)
{
    int sock = -1, set_addr, ret = 0;

    assert((address && !port) || (!address && port) || (endpt->ti == NC_TI_UNIX));

    if (address) {
        set_addr = 1;
    } else {
        set_addr = 0;
    }

    if (set_addr) {
        port = bind->port;
    } else {
        address = bind->address;
    }

    /* we have all the information we need to create a listening socket */
    if ((address && port) || (endpt->ti == NC_TI_UNIX)) {
        /* create new socket, close the old one */
        if (endpt->ti == NC_TI_UNIX) {
            sock = nc_sock_listen_unix(endpt->opts.unixsock);
        } else {
            sock = nc_sock_listen_inet(address, port);
        }

        if (sock == -1) {
            ret = 1;
            goto cleanup;
        }

        if (bind->sock > -1) {
            close(bind->sock);
        }
        bind->sock = sock;
    }

    if (sock > -1) {
        switch (endpt->ti) {
        case NC_TI_UNIX:
            VRB(NULL, "Listening on %s for UNIX connections.", endpt->opts.unixsock->address);
            break;
#ifdef NC_ENABLED_SSH_TLS
        case NC_TI_SSH:
            VRB(NULL, "Listening on %s:%u for SSH connections.", address, port);
            break;
        case NC_TI_TLS:
            VRB(NULL, "Listening on %s:%u for TLS connections.", address, port);
            break;
#endif /* NC_ENABLED_SSH_TLS */
        default:
            ERRINT;
            ret = 1;
            break;
        }
    }

cleanup:
    return ret;
}

#if defined (SO_PEERCRED) || defined (HAVE_GETPEEREID)

/**
 * @brief Get UID of the owner of a socket.
 *
 * @param[in] sock Socket to analyze.
 * @param[out] uid Socket owner UID.
 * @return 0 on success,
 * @return -1 on error.
 */
static int
nc_get_uid(int sock, uid_t *uid)
{
    int r;

#ifdef SO_PEERCRED
    struct ucred ucred;
    socklen_t len;

    len = sizeof(ucred);
    r = getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &len);
    if (!r) {
        *uid = ucred.uid;
    }
#else
    r = getpeereid(sock, uid, NULL);
#endif

    if (r < 0) {
        ERR(NULL, "Failed to get owner UID of a UNIX socket (%s).", strerror(errno));
        return -1;
    }
    return 0;
}

#endif

/**
 * @brief Fully accept a session on a connected UNIX socket.
 *
 * @param[in] session Session to use.
 * @param[in] sock Connected socket.
 * @return 1 on success.
 * @return -1 on error.
 */
static int
nc_accept_unix_session(struct nc_session *session, int sock)
{
#if defined (SO_PEERCRED) || defined (HAVE_GETPEEREID)
    struct passwd *pw, pw_buf;
    char *username;
    uid_t uid = 0;
    char *buf = NULL;
    size_t buf_len = 0;

    if (nc_get_uid(sock, &uid)) {
        close(sock);
        return -1;
    }

    pw = nc_getpw(uid, NULL, &pw_buf, &buf, &buf_len);
    if (pw == NULL) {
        ERR(session, "Failed to find username for uid=%u (%s).", uid, strerror(errno));
        close(sock);
        return -1;
    }

    username = strdup(pw->pw_name);
    free(buf);
    if (username == NULL) {
        ERRMEM;
        close(sock);
        return -1;
    }

    session->username = username;
    session->ti_type = NC_TI_UNIX;
    session->ti.unixsock.sock = sock;

    return 1;
#else
    (void)session;
    (void)sock;

    ERR(session, "Unable to learn the identity of the client connected to the UNIX socket, terminating.");
    return -1;
#endif
}

API int
nc_server_add_endpt_unix_socket_listen(const char *endpt_name, const char *unix_socket_path, mode_t mode, uid_t uid, gid_t gid)
{
    int ret = 0;
    void *tmp;
    uint16_t i;

    NC_CHECK_ARG_RET(NULL, endpt_name, unix_socket_path, 1);

    /* CONFIG LOCK */
    pthread_rwlock_wrlock(&server_opts.config_lock);

    /* check name uniqueness */
    for (i = 0; i < server_opts.endpt_count; i++) {
        if (!strcmp(endpt_name, server_opts.endpts[i].name)) {
            ERR(NULL, "Endpoint \"%s\" already exists.", endpt_name);
            ret = 1;
            goto cleanup;
        }
    }

    /* alloc a new endpoint */
    tmp = nc_realloc(server_opts.endpts, (server_opts.endpt_count + 1) * sizeof *server_opts.endpts);
    NC_CHECK_ERRMEM_GOTO(!tmp, ret = 1, cleanup);
    server_opts.endpts = tmp;
    memset(&server_opts.endpts[server_opts.endpt_count], 0, sizeof *server_opts.endpts);

    /* alloc a new bind */
    tmp = nc_realloc(server_opts.binds, (server_opts.endpt_count + 1) * sizeof *server_opts.binds);
    NC_CHECK_ERRMEM_GOTO(!tmp, ret = 1, cleanup);
    server_opts.binds = tmp;
    memset(&server_opts.binds[server_opts.endpt_count], 0, sizeof *server_opts.binds);
    server_opts.binds[server_opts.endpt_count].sock = -1;
    server_opts.endpt_count++;

    /* set name and ti */
    server_opts.endpts[server_opts.endpt_count - 1].name = strdup(endpt_name);
    NC_CHECK_ERRMEM_GOTO(!server_opts.endpts[server_opts.endpt_count - 1].name, ret = 1, cleanup);
    server_opts.endpts[server_opts.endpt_count - 1].ti = NC_TI_UNIX;

    /* set the bind data */
    server_opts.binds[server_opts.endpt_count - 1].address = strdup(unix_socket_path);
    NC_CHECK_ERRMEM_GOTO(!server_opts.binds[server_opts.endpt_count - 1].address, ret = 1, cleanup);

    /* alloc unix opts */
    server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock = calloc(1, sizeof(struct nc_server_unix_opts));
    NC_CHECK_ERRMEM_GOTO(!server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock, ret = 1, cleanup);

    /* set the opts data */
    server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock->address = strdup(unix_socket_path);
    NC_CHECK_ERRMEM_GOTO(!server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock->address, ret = 1, cleanup);
    server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock->mode = (mode == (mode_t) -1) ? (mode_t) -1 : mode;
    server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock->uid = (uid == (uid_t) -1) ? (uid_t) -1 : uid;
    server_opts.endpts[server_opts.endpt_count - 1].opts.unixsock->gid = (gid == (gid_t) -1) ? (gid_t) -1 : gid;

    /* start listening */
    ret = nc_server_set_address_port(&server_opts.endpts[server_opts.endpt_count - 1],
            &server_opts.binds[server_opts.endpt_count - 1], NULL, 0);
    if (ret) {
        ERR(NULL, "Listening on UNIX socket \"%s\" failed.", unix_socket_path);
        goto cleanup;
    }

cleanup:
    /* CONFIG UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);
    return ret;
}

static void
nc_server_del_endpt_unix_socket_opts(struct nc_bind *bind, struct nc_server_unix_opts *opts)
{
    if (bind->sock > -1) {
        close(bind->sock);
    }

    unlink(bind->address);
    free(bind->address);
    free(opts->address);

    free(opts);
}

void
_nc_server_del_endpt_unix_socket(struct nc_endpt *endpt, struct nc_bind *bind)
{
    free(endpt->name);
    nc_server_del_endpt_unix_socket_opts(bind, endpt->opts.unixsock);

    server_opts.endpt_count--;
    if (!server_opts.endpt_count) {
        free(server_opts.endpts);
        free(server_opts.binds);
        server_opts.endpts = NULL;
        server_opts.binds = NULL;
    } else if (endpt != &server_opts.endpts[server_opts.endpt_count]) {
        memcpy(endpt, &server_opts.endpts[server_opts.endpt_count], sizeof *server_opts.endpts);
        memcpy(bind, &server_opts.binds[server_opts.endpt_count], sizeof *server_opts.binds);
    }
}

API void
nc_server_del_endpt_unix_socket(const char *endpt_name)
{
    uint16_t i;
    struct nc_endpt *endpt = NULL;
    struct nc_bind *bind;

    NC_CHECK_ARG_RET(NULL, endpt_name, );

    /* CONFIG LOCK */
    pthread_rwlock_wrlock(&server_opts.config_lock);

    for (i = 0; i < server_opts.endpt_count; i++) {
        if (!strcmp(server_opts.endpts[i].name, endpt_name)) {
            endpt = &server_opts.endpts[i];
            bind = &server_opts.binds[i];
            break;
        }
    }
    if (!endpt) {
        ERR(NULL, "Endpoint \"%s\" not found.", endpt_name);
        goto end;
    }
    if (endpt->ti != NC_TI_UNIX) {
        ERR(NULL, "Endpoint \"%s\" is not a UNIX socket endpoint.", endpt_name);
        goto end;
    }

    _nc_server_del_endpt_unix_socket(endpt, bind);

end:
    /* CONFIG UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);
}

API int
nc_server_endpt_count(void)
{
    return server_opts.endpt_count;
}

API NC_MSG_TYPE
nc_accept(int timeout, const struct ly_ctx *ctx, struct nc_session **session)
{
    NC_MSG_TYPE msgtype;
    int sock = -1, ret;
    char *host = NULL;
    uint16_t port, bind_idx;
    struct timespec ts_cur;

    NC_CHECK_ARG_RET(NULL, ctx, session, NC_MSG_ERROR);

    NC_CHECK_SRV_INIT_RET(NC_MSG_ERROR);

    *session = NULL;

    /* init ctx as needed */
    nc_server_init_cb_ctx(ctx);

    /* CONFIG LOCK */
    pthread_rwlock_rdlock(&server_opts.config_lock);

    if (!server_opts.endpt_count) {
        ERR(NULL, "No endpoints to accept sessions on.");
        msgtype = NC_MSG_ERROR;
        goto cleanup;
    }

    ret = nc_sock_accept_binds(server_opts.binds, server_opts.endpt_count, &server_opts.bind_lock, timeout, &host,
            &port, &bind_idx, &sock);
    if (ret < 1) {
        msgtype = (!ret ? NC_MSG_WOULDBLOCK : NC_MSG_ERROR);
        goto cleanup;
    }

    /* configure keepalives */
    if (nc_sock_configure_ka(sock, &server_opts.endpts[bind_idx].ka)) {
        msgtype = NC_MSG_ERROR;
        goto cleanup;
    }

    *session = nc_new_session(NC_SERVER, 0);
    NC_CHECK_ERRMEM_GOTO(!(*session), msgtype = NC_MSG_ERROR, cleanup);
    (*session)->status = NC_STATUS_STARTING;
    (*session)->ctx = (struct ly_ctx *)ctx;
    (*session)->flags = NC_SESSION_SHAREDCTX;
    (*session)->host = host;
    host = NULL;
    (*session)->port = port;

    /* sock gets assigned to session or closed */
#ifdef NC_ENABLED_SSH_TLS
    if (server_opts.endpts[bind_idx].ti == NC_TI_SSH) {
        ret = nc_accept_ssh_session(*session, server_opts.endpts[bind_idx].opts.ssh, sock, NC_TRANSPORT_TIMEOUT);
        sock = -1;
        if (ret < 0) {
            msgtype = NC_MSG_ERROR;
            goto cleanup;
        } else if (!ret) {
            msgtype = NC_MSG_WOULDBLOCK;
            goto cleanup;
        }
    } else if (server_opts.endpts[bind_idx].ti == NC_TI_TLS) {
        (*session)->data = server_opts.endpts[bind_idx].opts.tls;
        ret = nc_accept_tls_session(*session, server_opts.endpts[bind_idx].opts.tls, sock, NC_TRANSPORT_TIMEOUT);
        sock = -1;
        if (ret < 0) {
            msgtype = NC_MSG_ERROR;
            goto cleanup;
        } else if (!ret) {
            msgtype = NC_MSG_WOULDBLOCK;
            goto cleanup;
        }
    } else
#endif /* NC_ENABLED_SSH_TLS */
    if (server_opts.endpts[bind_idx].ti == NC_TI_UNIX) {
        (*session)->data = server_opts.endpts[bind_idx].opts.unixsock;
        ret = nc_accept_unix_session(*session, sock);
        sock = -1;
        if (ret < 0) {
            msgtype = NC_MSG_ERROR;
            goto cleanup;
        }
    } else {
        ERRINT;
        msgtype = NC_MSG_ERROR;
        goto cleanup;
    }

    (*session)->data = NULL;

    /* CONFIG UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);

    /* assign new SID atomically */
    (*session)->id = ATOMIC_INC_RELAXED(server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(*session);
    if (msgtype != NC_MSG_HELLO) {
        nc_session_free(*session, NULL);
        *session = NULL;
        return msgtype;
    }

    nc_timeouttime_get(&ts_cur, 0);
    (*session)->opts.server.last_rpc = ts_cur.tv_sec;
    nc_realtime_get(&ts_cur);
    (*session)->opts.server.session_start = ts_cur;
    (*session)->status = NC_STATUS_RUNNING;

    return msgtype;

cleanup:
    /* CONFIG UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);

    free(host);
    if (sock > -1) {
        close(sock);
    }
    nc_session_free(*session, NULL);
    *session = NULL;
    return msgtype;
}

#ifdef NC_ENABLED_SSH_TLS

API int
nc_server_ch_is_client(const char *name)
{
    uint16_t i;
    int found = 0;

    if (!name) {
        return found;
    }

    /* READ LOCK */
    pthread_rwlock_rdlock(&server_opts.ch_client_lock);

    /* check name uniqueness */
    for (i = 0; i < server_opts.ch_client_count; ++i) {
        if (!strcmp(server_opts.ch_clients[i].name, name)) {
            found = 1;
            break;
        }
    }

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);

    return found;
}

API int
nc_server_ch_client_is_endpt(const char *client_name, const char *endpt_name)
{
    uint16_t i;
    struct nc_ch_client *client = NULL;
    int found = 0;

    if (!client_name || !endpt_name) {
        return found;
    }

    /* READ LOCK */
    pthread_rwlock_rdlock(&server_opts.ch_client_lock);

    for (i = 0; i < server_opts.ch_client_count; ++i) {
        if (!strcmp(server_opts.ch_clients[i].name, client_name)) {
            client = &server_opts.ch_clients[i];
            break;
        }
    }

    if (!client) {
        goto cleanup;
    }

    for (i = 0; i < client->ch_endpt_count; ++i) {
        if (!strcmp(client->ch_endpts[i].name, endpt_name)) {
            found = 1;
            break;
        }
    }

cleanup:
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);
    return found;
}

/**
 * @brief Create a connection for an endpoint.
 *
 * Client lock is expected to be held.
 *
 * @param[in] endpt Endpoint to use.
 * @param[in] acquire_ctx_cb Callback for acquiring the libyang context.
 * @param[in] release_ctx_cb Callback for releasing the libyang context.
 * @param[in] ctx_cb_data Context callbacks data.
 * @param[out] session Created NC session.
 * @return NC_MSG values.
 */
static NC_MSG_TYPE
nc_connect_ch_endpt(struct nc_ch_endpt *endpt, nc_server_ch_session_acquire_ctx_cb acquire_ctx_cb,
        nc_server_ch_session_release_ctx_cb release_ctx_cb, void *ctx_cb_data, struct nc_session **session)
{
    NC_MSG_TYPE msgtype;
    const struct ly_ctx *ctx = NULL;
    int sock, ret;
    struct timespec ts_cur;
    char *ip_host;

    sock = nc_sock_connect(endpt->src_addr, endpt->src_port, endpt->dst_addr, endpt->dst_port,
            NC_CH_CONNECT_TIMEOUT, &endpt->ka, &endpt->sock_pending, &ip_host);
    if (sock < 0) {
        return NC_MSG_ERROR;
    }

    /* acquire context */
    ctx = acquire_ctx_cb(ctx_cb_data);
    if (!ctx) {
        ERR(NULL, "Failed to acquire context for a new Call Home session.");
        close(sock);
        free(ip_host);
        return NC_MSG_ERROR;
    }

    /* init ctx as needed */
    nc_server_init_cb_ctx(ctx);

    /* create session */
    *session = nc_new_session(NC_SERVER, 0);
    NC_CHECK_ERRMEM_GOTO(!(*session), close(sock); free(ip_host); msgtype = NC_MSG_ERROR, fail);
    (*session)->status = NC_STATUS_STARTING;
    (*session)->ctx = (struct ly_ctx *)ctx;
    (*session)->flags = NC_SESSION_SHAREDCTX | NC_SESSION_CALLHOME;
    (*session)->host = ip_host;
    (*session)->port = endpt->dst_port;

    /* sock gets assigned to session or closed */
    if (endpt->ti == NC_TI_SSH) {
        ret = nc_accept_ssh_session(*session, endpt->opts.ssh, sock, NC_TRANSPORT_TIMEOUT);
        (*session)->data = NULL;

        if (ret < 0) {
            msgtype = NC_MSG_ERROR;
            goto fail;
        } else if (!ret) {
            msgtype = NC_MSG_WOULDBLOCK;
            goto fail;
        }
    } else if (endpt->ti == NC_TI_TLS) {
        (*session)->data = endpt->opts.tls;
        ret = nc_accept_tls_session(*session, endpt->opts.tls, sock, NC_TRANSPORT_TIMEOUT);
        (*session)->data = NULL;

        if (ret < 0) {
            msgtype = NC_MSG_ERROR;
            goto fail;
        } else if (!ret) {
            msgtype = NC_MSG_WOULDBLOCK;
            goto fail;
        }
    } else {
        ERRINT;
        close(sock);
        msgtype = NC_MSG_ERROR;
        goto fail;
    }

    /* assign new SID atomically */
    (*session)->id = ATOMIC_INC_RELAXED(server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(*session);
    if (msgtype != NC_MSG_HELLO) {
        goto fail;
    }

    nc_timeouttime_get(&ts_cur, 0);
    (*session)->opts.server.last_rpc = ts_cur.tv_sec;
    nc_realtime_get(&ts_cur);
    (*session)->opts.server.session_start = ts_cur;
    (*session)->status = NC_STATUS_RUNNING;

    return msgtype;

fail:
    nc_session_free(*session, NULL);
    *session = NULL;
    if (ctx) {
        release_ctx_cb(ctx_cb_data);
    }
    return msgtype;
}

/**
 * @brief Wait for any event after a NC session was established on a CH client.
 *
 * @param[in] data CH client thread argument.
 * @param[in] session New NC session. The session is invalid upon being freed (= function exit).
 * @return 0 if session was terminated normally,
 * @return 1 if the CH client was removed,
 * @return -1 on error.
 */
static int
nc_server_ch_client_thread_session_cond_wait(struct nc_ch_client_thread_arg *data, struct nc_session *session)
{
    int rc = 0, r;
    uint32_t idle_timeout;
    struct timespec ts;
    struct nc_ch_client *client;

    /* CH LOCK */
    pthread_mutex_lock(&session->opts.server.ch_lock);

    session->flags |= NC_SESSION_CH_THREAD;

    /* give the session to the user */
    if (data->new_session_cb(data->client_name, session, data->new_session_cb_data)) {
        /* something is wrong, free the session */
        session->flags &= ~NC_SESSION_CH_THREAD;

        /* CH UNLOCK */
        pthread_mutex_unlock(&session->opts.server.ch_lock);

        /* session terminated, free it and release its context */
        nc_session_free(session, NULL);
        data->release_ctx_cb(data->ctx_cb_data);
        return 0;
    }

    do {
        nc_timeouttime_get(&ts, NC_CH_THREAD_IDLE_TIMEOUT_SLEEP);

        /* CH COND WAIT */
        r = pthread_cond_clockwait(&session->opts.server.ch_cond, &session->opts.server.ch_lock, COMPAT_CLOCK_ID, &ts);
        if (!r) {
            /* we were woken up, something probably happened */
            if (session->status != NC_STATUS_RUNNING) {
                break;
            }
        } else if (r != ETIMEDOUT) {
            ERR(session, "Pthread condition timedwait failed (%s).", strerror(r));
            rc = -1;
            break;
        }

        /* check whether the client was not removed */

        /* LOCK */
        client = nc_server_ch_client_lock(data->client_name);
        if (!client) {
            /* client was removed, finish thread */
            VRB(session, "Call Home client \"%s\" removed, but an established session will not be terminated.",
                    data->client_name);
            rc = 1;
            break;
        }

        if (client->conn_type == NC_CH_PERIOD) {
            idle_timeout = client->idle_timeout;
        } else {
            idle_timeout = 0;
        }

        nc_timeouttime_get(&ts, 0);
        if (!nc_session_get_notif_status(session) && idle_timeout && (ts.tv_sec >= session->opts.server.last_rpc + idle_timeout)) {
            VRB(session, "Call Home client \"%s\": session idle timeout elapsed.", client->name);
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_TIMEOUT;
        }

        /* UNLOCK */
        nc_server_ch_client_unlock(client);

    } while (session->status == NC_STATUS_RUNNING);

    /* signal to nc_session_free() that CH thread is terminating */
    session->flags &= ~NC_SESSION_CH_THREAD;
    pthread_cond_signal(&session->opts.server.ch_cond);

    /* CH UNLOCK */
    pthread_mutex_unlock(&session->opts.server.ch_lock);

    return rc;
}

/**
 * @brief Waits for some amount of time while reacting to signals about terminating a Call Home thread.
 *
 * @param[in] session An established session.
 * @param[in] data Call Home thread's data.
 * @param[in] cond_wait_time Time in seconds to sleep for, after which a reconnect is attempted.
 *
 * @return 0 if the thread should stop running, 1 if it should continue.
 */
static int
nc_server_ch_client_thread_is_running_wait(struct nc_session *session, struct nc_ch_client_thread_arg *data, uint64_t cond_wait_time)
{
    struct timespec ts;
    int ret = 0, thread_running;

    /* COND LOCK */
    pthread_mutex_lock(&data->cond_lock);
    /* get reconnect timeout in ms */
    nc_timeouttime_get(&ts, cond_wait_time * 1000);
    while (!ret && data->thread_running) {
        ret = pthread_cond_clockwait(&data->cond, &data->cond_lock, COMPAT_CLOCK_ID, &ts);
    }

    thread_running = data->thread_running;
    /* COND UNLOCK */
    pthread_mutex_unlock(&data->cond_lock);

    if (!thread_running) {
        /* thread is terminating */
        VRB(session, "Call Home thread signaled to exit, client \"%s\" probably removed.", data->client_name);
        ret = 0;
    } else if (ret == ETIMEDOUT) {
        /* time to reconnect */
        VRB(session, "Call Home client \"%s\" timeout of %" PRIu64 " seconds expired, reconnecting.", data->client_name, cond_wait_time);
        ret = 1;
    } else if (ret) {
        ERR(session, "Pthread condition timedwait failed (%s).", strerror(ret));
        ret = 0;
    }

    return ret;
}

/**
 * @brief Checks if a Call Home thread should terminate.
 *
 * Checks the shared boolean variable thread_running. This should be done everytime
 * before entering a critical section.
 *
 * @param[in] data Call Home thread's data.
 *
 * @return 0 if the thread should stop running, -1 if it can continue.
 */
static int
nc_server_ch_client_thread_is_running(struct nc_ch_client_thread_arg *data)
{
    int ret = -1;

    /* COND LOCK */
    pthread_mutex_lock(&data->cond_lock);
    if (!data->thread_running) {
        /* thread should stop running */
        ret = 0;
    }
    /* COND UNLOCK */
    pthread_mutex_unlock(&data->cond_lock);

    return ret;
}

/**
 * @brief Lock CH client structures for reading and lock the specific client if it has some endpoints, wait otherwise.
 *
 * @param[in] name Name of the CH client.
 * @return Pointer to the CH client.
 */
static struct nc_ch_client *
nc_server_ch_client_with_endpt_lock(const char *name)
{
    struct nc_ch_client *client;

    while (1) {
        /* LOCK */
        client = nc_server_ch_client_lock(name);
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

/**
 * @brief Call Home client management thread.
 *
 * @param[in] arg CH client thread argument.
 * @return NULL.
 */
static void *
nc_ch_client_thread(void *arg)
{
    struct nc_ch_client_thread_arg *data = arg;
    NC_MSG_TYPE msgtype;
    uint8_t cur_attempts = 0;
    uint16_t next_endpt_index, max_wait;
    char *cur_endpt_name = NULL;
    struct nc_ch_endpt *cur_endpt;
    struct nc_session *session = NULL;
    struct nc_ch_client *client;
    uint32_t reconnect_in;

    /* LOCK */
    client = nc_server_ch_client_with_endpt_lock(data->client_name);
    if (!client) {
        VRB(NULL, "Call Home client \"%s\" removed.", data->client_name);
        goto cleanup;
    }

    cur_endpt = &client->ch_endpts[0];
    cur_endpt_name = strdup(cur_endpt->name);

    while (nc_server_ch_client_thread_is_running(data)) {
        if (!cur_attempts) {
            VRB(NULL, "Call Home client \"%s\" endpoint \"%s\" connecting...", data->client_name, cur_endpt_name);
        }

        msgtype = nc_connect_ch_endpt(cur_endpt, data->acquire_ctx_cb, data->release_ctx_cb, data->ctx_cb_data, &session);
        if (msgtype == NC_MSG_HELLO) {
            /* UNLOCK */
            nc_server_ch_client_unlock(client);

            if (!nc_server_ch_client_thread_is_running(data)) {
                /* thread should stop running */
                goto cleanup;
            }

            /* run while the session is established */
            VRB(session, "Call Home client \"%s\" session %u established.", data->client_name, session->id);
            if (nc_server_ch_client_thread_session_cond_wait(data, session)) {
                goto cleanup;
            }
            session = NULL;

            VRB(NULL, "Call Home client \"%s\" session terminated.", data->client_name);
            if (!nc_server_ch_client_thread_is_running(data)) {
                /* thread should stop running */
                goto cleanup;
            }

            /* LOCK */
            client = nc_server_ch_client_with_endpt_lock(data->client_name);
            if (!client) {
                VRB(NULL, "Call Home client \"%s\" removed.", data->client_name);
                goto cleanup;
            }

            /* session changed status -> it was disconnected for whatever reason,
             * persistent connection immediately tries to reconnect, periodic connects at specific times */
            if (client->conn_type == NC_CH_PERIOD) {
                if (client->anchor_time) {
                    /* anchored */
                    reconnect_in = (time(NULL) - client->anchor_time) % (client->period * 60);
                } else {
                    /* fixed timeout */
                    reconnect_in = client->period * 60;
                }

                /* UNLOCK */
                nc_server_ch_client_unlock(client);

                /* wait for the timeout to elapse, so we can try to reconnect */
                VRB(session, "Call Home client \"%s\" reconnecting in %" PRIu32 " seconds.", data->client_name, reconnect_in);
                if (!nc_server_ch_client_thread_is_running_wait(session, data, reconnect_in)) {
                    goto cleanup;
                }

                /* LOCK */
                client = nc_server_ch_client_with_endpt_lock(data->client_name);
                assert(client);
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
            /* session was not created, wait a little bit and try again */
            max_wait = client->max_wait;

            /* UNLOCK */
            nc_server_ch_client_unlock(client);

            /* wait for max_wait seconds */
            if (!nc_server_ch_client_thread_is_running_wait(session, data, max_wait)) {
                /* thread should stop running */
                goto cleanup;
            }

            /* LOCK */
            client = nc_server_ch_client_with_endpt_lock(data->client_name);
            assert(client);

            ++cur_attempts;

            /* try to find our endpoint again */
            for (next_endpt_index = 0; next_endpt_index < client->ch_endpt_count; ++next_endpt_index) {
                if (!strcmp(client->ch_endpts[next_endpt_index].name, cur_endpt_name)) {
                    break;
                }
            }

            if (next_endpt_index >= client->ch_endpt_count) {
                /* endpoint was removed, start with the first one */
                VRB(session, "Call Home client \"%s\" endpoint \"%s\" removed.", data->client_name, cur_endpt_name);
                next_endpt_index = 0;
                cur_attempts = 0;
            } else if (cur_attempts == client->max_attempts) {
                /* we have tried to connect to this endpoint enough times */
                VRB(session, "Call Home client \"%s\" endpoint \"%s\" failed connection attempt limit %" PRIu8 " reached.",
                        data->client_name, cur_endpt_name, client->max_attempts);

                /* clear a pending socket, if any */
                cur_endpt = &client->ch_endpts[next_endpt_index];
                if (cur_endpt->sock_pending > -1) {
                    close(cur_endpt->sock_pending);
                    cur_endpt->sock_pending = -1;
                }

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

    /* UNLOCK if we break out of the loop */
    nc_server_ch_client_unlock(client);

cleanup:
    VRB(session, "Call Home client \"%s\" thread exit.", data->client_name);
    free(cur_endpt_name);
    free(data->client_name);
    pthread_mutex_lock(&data->cond_lock);
    pthread_cond_destroy(&data->cond);
    pthread_mutex_unlock(&data->cond_lock);
    pthread_mutex_destroy(&data->cond_lock);
    free(data);
    return NULL;
}

API int
nc_connect_ch_client_dispatch(const char *client_name, nc_server_ch_session_acquire_ctx_cb acquire_ctx_cb,
        nc_server_ch_session_release_ctx_cb release_ctx_cb, void *ctx_cb_data, nc_server_ch_new_session_cb new_session_cb,
        void *new_session_cb_data)
{
    int rc = 0, r;
    pthread_t tid;
    struct nc_ch_client_thread_arg *arg = NULL;
    struct nc_ch_client *ch_client;

    NC_CHECK_ARG_RET(NULL, client_name, acquire_ctx_cb, release_ctx_cb, new_session_cb, -1);

    NC_CHECK_SRV_INIT_RET(-1);

    /* LOCK */
    ch_client = nc_server_ch_client_lock(client_name);
    if (!ch_client) {
        ERR(NULL, "Client \"%s\" not found.", client_name);
        return -1;
    }

    /* create the thread argument */
    arg = calloc(1, sizeof *arg);
    NC_CHECK_ERRMEM_GOTO(!arg, rc = -1, cleanup);
    arg->client_name = strdup(client_name);
    NC_CHECK_ERRMEM_GOTO(!arg->client_name, rc = -1, cleanup);
    arg->acquire_ctx_cb = acquire_ctx_cb;
    arg->release_ctx_cb = release_ctx_cb;
    arg->ctx_cb_data = ctx_cb_data;
    arg->new_session_cb = new_session_cb;
    arg->new_session_cb_data = new_session_cb_data;
    pthread_cond_init(&arg->cond, NULL);
    pthread_mutex_init(&arg->cond_lock, NULL);

    /* creating the thread */
    arg->thread_running = 1;
    if ((r = pthread_create(&tid, NULL, nc_ch_client_thread, arg))) {
        ERR(NULL, "Creating a new thread failed (%s).", strerror(r));
        rc = -1;
        goto cleanup;
    }

    /* the thread now manages arg */
    ch_client->tid = tid;
    ch_client->thread_data = arg;
    arg = NULL;

cleanup:
    /* UNLOCK */
    nc_server_ch_client_unlock(ch_client);

    if (arg) {
        free(arg->client_name);
        free(arg);
    }
    return rc;
}

#endif /* NC_ENABLED_SSH_TLS */

API struct timespec
nc_session_get_start_time(const struct nc_session *session)
{
    struct timespec fail = {0};

    NC_CHECK_ARG_RET(session, session, fail);

    if (session->side != NC_SERVER) {
        ERRARG(session, "session");
        return fail;
    }

    return session->opts.server.session_start;
}

API void
nc_session_inc_notif_status(struct nc_session *session)
{
    if (!session || (session->side != NC_SERVER)) {
        ERRARG(session, "session");
        return;
    }

    /* NTF STATUS LOCK */
    pthread_mutex_lock(&session->opts.server.ntf_status_lock);

    ++session->opts.server.ntf_status;

    /* NTF STATUS UNLOCK */
    pthread_mutex_unlock(&session->opts.server.ntf_status_lock);
}

API void
nc_session_dec_notif_status(struct nc_session *session)
{
    if (!session || (session->side != NC_SERVER)) {
        ERRARG(session, "session");
        return;
    }

    /* NTF STATUS LOCK */
    pthread_mutex_lock(&session->opts.server.ntf_status_lock);

    if (session->opts.server.ntf_status) {
        --session->opts.server.ntf_status;
    }

    /* NTF STATUS UNLOCK */
    pthread_mutex_unlock(&session->opts.server.ntf_status_lock);
}

API int
nc_session_get_notif_status(const struct nc_session *session)
{
    uint32_t ntf_status;

    if (!session || (session->side != NC_SERVER)) {
        ERRARG(session, "session");
        return 0;
    }

    /* NTF STATUS LOCK */
    pthread_mutex_lock(&((struct nc_session *)session)->opts.server.ntf_status_lock);

    ntf_status = session->opts.server.ntf_status;

    /* NTF STATUS UNLOCK */
    pthread_mutex_unlock(&((struct nc_session *)session)->opts.server.ntf_status_lock);

    return ntf_status;
}

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Get the XPath for the certificate expiration notification.
 *
 * @param[in] cp Keys of lists for the given certificate that are needed to create the XPath.
 * @return XPath for the certificate expiration notification or NULL on error.
 */
static char *
nc_server_notif_cert_exp_xpath_get(struct nc_cert_path_aux *cp)
{
    int rc;
    char *xpath = NULL, *tmp = NULL;

    if (cp->ks_cert_name) {
        /* ietf-keystore */
        rc = asprintf(&xpath, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='%s']/certificates/"
                "certificate[name='%s']/certificate-expiration/expiration-date", cp->ks_askey_name, cp->ks_cert_name);
        NC_CHECK_ERRMEM_RET(rc == -1, NULL);
        return xpath;
    } else if (cp->ts_cert_name) {
        /* ietf-truststore */
        rc = asprintf(&xpath, "/ietf-truststore:truststore/certificate-bags/certificate-bag[name='%s']/"
                "certificate[name='%s']/certificate-expiration/expiration-date", cp->ts_cbag_name, cp->ts_cert_name);
        NC_CHECK_ERRMEM_RET(rc == -1, NULL);
        return xpath;
    }

    /* ietf-netconf-server */
    if (cp->ch_client_name) {
        /* call-home */
        rc = asprintf(&tmp, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='%s']/endpoints/"
                "endpoint[name='%s']/tls/tls-server-parameters", cp->ch_client_name, cp->endpt_name);
    } else {
        /* listen */
        rc = asprintf(&tmp, "/ietf-netconf-server:netconf-server/listen/endpoints/"
                "endpoint[name='%s']/tls/tls-server-parameters", cp->endpt_name);
    }
    NC_CHECK_ERRMEM_RET(rc == -1, NULL);

    if (cp->ee_cert_name) {
        /* end entity */
        rc = asprintf(&xpath, "%s/client-authentication/ee-certs/inline-definition/certificate[name='%s']/"
                "certificate-expiration/expiration-date", tmp, cp->ee_cert_name);
    } else if (cp->ca_cert_name) {
        /* certificate authority */
        rc = asprintf(&xpath, "%s/client-authentication/ca-certs/inline-definition/certificate[name='%s']/"
                "certificate-expiration/expiration-date", tmp, cp->ca_cert_name);
    } else {
        /* server cert */
        rc = asprintf(&xpath, "%s/server-identity/certificate/inline-definition/certificate-expiration/expiration-date", tmp);
    }
    free(tmp);
    NC_CHECK_ERRMEM_RET(rc == -1, NULL);

    return xpath;
}

/**
 * @brief Add months, weeks, days and hours to a calendar time.
 *
 * @param[in] orig_time Original calendar time.
 * @param[in] add_time Months, weeks, days and hours to add.
 * @return Calendar time of the new time or -1 on error.
 */
static time_t
nc_server_notif_cert_exp_time_add(time_t orig_time, struct nc_cert_exp_time *add_time)
{
    struct tm *tm;
    struct tm tm_aux;

    tm = localtime_r(&orig_time, &tm_aux);
    if (!tm) {
        ERR(NULL, "Failed to get localtime (%s).", strerror(errno));
        return -1;
    }

    tm->tm_mon += add_time->months;
    tm->tm_mday += 7 * add_time->weeks;
    tm->tm_mday += add_time->days;
    tm->tm_hour += add_time->hours;

    return mktime(tm);
}

/**
 * @brief Subtract months, weeks, days and hours from a calendar time.
 *
 * @param[in] orig_time Original calendar time.
 * @param[in] sub_time Months, weeks, days and hours to subtract.
 * @return Calendar time of the new time or -1 on error.
 */
static time_t
nc_server_notif_cert_exp_time_sub(time_t orig_time, struct nc_cert_exp_time *sub_time)
{
    struct tm *tm;
    struct tm tm_aux;

    tm = localtime_r(&orig_time, &tm_aux);
    if (!tm) {
        ERR(NULL, "Failed to get localtime (%s).", strerror(errno));
        return -1;
    }

    tm->tm_mon -= sub_time->months;
    tm->tm_mday -= 7 * sub_time->weeks;
    tm->tm_mday -= sub_time->days;
    tm->tm_hour -= sub_time->hours;

    return mktime(tm);
}

/**
 * @brief Get the next notification time for the certificate expiration.
 *
 * @param[in] intervals Certificate expiration time intervals.
 * @param[in] interval_count Interval count.
 * @param[in,out] exp Expiration date structure.
 * @return Calendar time of the next notification or -1 on error.
 */
static time_t
nc_server_notif_cert_exp_next_notif_time_get(struct nc_interval *intervals, int interval_count, struct nc_cert_expiration *exp)
{
    time_t new_notif_time, now;
    double diff;
    struct nc_cert_exp_time day_period = {.days = 1};

    now = time(NULL);

    /* check if the certificate already expired */
    diff = difftime(exp->expiration_time, now);
    if (diff < 0) {
        /* it did, so the next notif shall happen on the next day regardless of set intervals */
        return nc_server_notif_cert_exp_time_add(exp->notif_time, &day_period);
    }

    /* otherwise just add the current period and check for overflow into the next interval */
    new_notif_time = nc_server_notif_cert_exp_time_add(exp->notif_time, &intervals[exp->current_interval].period);
    if (new_notif_time == -1) {
        return -1;
    }

    if (exp->current_interval == (interval_count - 1)) {
        /* we are in the last interval, so we cant overflow */
        return new_notif_time;
    }

    diff = difftime(exp->starts_of_intervals[exp->current_interval + 1], new_notif_time);
    if (diff > 0) {
        /* no overflow */
        return new_notif_time;
    } else {
        /* overflowed, move to the next interval */
        ++exp->current_interval;
        return exp->starts_of_intervals[exp->current_interval];
    }
}

/**
 * @brief Initialize the start times of the intervals for the specific certificate expiration.
 *
 * @param[in] intervals Certificate expiration time intervals.
 * @param[in] interval_count Interval count.
 * @param[in,out] exp Certificate expiration structure.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_notif_cert_exp_init_intervals(struct nc_interval *intervals, int interval_count, struct nc_cert_expiration *exp)
{
    int i;

    exp->starts_of_intervals = malloc(interval_count * sizeof *exp->starts_of_intervals);
    NC_CHECK_ERRMEM_RET(!exp->starts_of_intervals, 1);

    /* find the start time of each interval */
    for (i = 0; i < interval_count; i++) {
        exp->starts_of_intervals[i] = nc_server_notif_cert_exp_time_sub(exp->expiration_time, &intervals[i].anchor);
        if (exp->starts_of_intervals[i] == -1) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Get the first notification time and the given interval for the certificate expiration.
 *
 * @param[in] intervals Certificate expiration time intervals.
 * @param[in] interval_count Interval count.
 * @param[in,out] exp Certificate expiration structure.
 * @return 0 on success.
 */
static int
nc_server_notif_cert_exp_first_notif_time_get(struct nc_interval *intervals, int interval_count, struct nc_cert_expiration *exp)
{
    int i;
    time_t now, notif_time;
    double diff;

    now = time(NULL);

    /* check if the start of the first interval is in the future, since they are sorted by calendar time (ascending) */
    diff = difftime(exp->starts_of_intervals[0], now);
    if (diff > 0) {
        /* it is, so the first notif shall happen at the start of the first interval */
        exp->notif_time = exp->starts_of_intervals[0];
        exp->current_interval = 0;
        return 0;
    }

    /* check if the certificate already expired */
    diff = difftime(exp->expiration_time, now);
    if (diff < 0) {
        /* it did, so the first notif shall happen immediately */
        exp->notif_time = now;
        exp->current_interval = interval_count - 1;
        return 0;
    }

    /* otherwise we have to find the correct interval */
    for (i = 0; i < interval_count - 1; i++) {
        if ((difftime(now, exp->starts_of_intervals[i]) >= 0) && (difftime(now, exp->starts_of_intervals[i + 1]) < 0)) {
            /* found it (now is at or after i, but before i + 1) */
            break;
        }
    }

    /* now we have to find the exact notification time based on the interval and its period */
    notif_time = exp->starts_of_intervals[i];
    while (difftime(notif_time, now) < 0) {
        /* the notif_time is still in the past, so we add the given period and check for overflow into the next interval */
        notif_time = nc_server_notif_cert_exp_time_add(notif_time, &intervals[i].period);
        if (notif_time == -1) {
            return 1;
        }

        if ((i != (interval_count - 1)) && (difftime(notif_time, exp->starts_of_intervals[i + 1]) >= 0)) {
            /* overflowed into the next interval */
            notif_time = exp->starts_of_intervals[i + 1];
            ++i;
            break;
        }
    }

    exp->notif_time = notif_time;
    exp->current_interval = i;
    return 0;
}

/**
 * @brief Initialize and append the certificate expiration date to an array.
 *
 * @param[in] cert_data Base64 encoded certificate data.
 * @param[in] cp Keys of lists required to create the XPath to the certificate expiration date.
 * @param[in] intervals Certificate expiration time intervals.
 * @param[in] interval_count Interval count.
 * @param[out] exp_dates Expiration dates.
 * @param[out] exp_date_count Expiration date count.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_notif_cert_exp_date_append(const char *cert_data, struct nc_cert_path_aux *cp,
        struct nc_interval *intervals, int interval_count, struct nc_cert_expiration **exp_dates, int *exp_date_count)
{
    int ret = 0;
    void *cert = NULL;
    time_t exp_time;

    cert = nc_base64der_to_cert(cert_data);
    if (!cert) {
        ret = 1;
        goto cleanup;
    }

    /* get expiration date */
    exp_time = nc_tls_get_cert_exp_time_wrap(cert);
    if (exp_time == -1) {
        ret = 1;
        goto cleanup;
    }

    *exp_dates = nc_realloc(*exp_dates, (*exp_date_count + 1) * sizeof **exp_dates);
    NC_CHECK_ERRMEM_GOTO(!*exp_dates, ret = 1, cleanup);

    (*exp_dates)[*exp_date_count].expiration_time = exp_time;

    /* init the time intervals for this specific cert */
    ret = nc_server_notif_cert_exp_init_intervals(intervals, interval_count, &(*exp_dates)[*exp_date_count]);
    if (ret) {
        goto cleanup;
    }

    /* get the time of the first notif */
    ret = nc_server_notif_cert_exp_first_notif_time_get(intervals, interval_count, &(*exp_dates)[*exp_date_count]);
    if (ret) {
        goto cleanup;
    }

    /* get the XPath to this specific cert */
    (*exp_dates)[*exp_date_count].xpath = nc_server_notif_cert_exp_xpath_get(cp);
    if (!(*exp_dates)[*exp_date_count].xpath) {
        ret = 1;
        goto cleanup;
    }

    ++(*exp_date_count);

cleanup:
    nc_tls_cert_destroy_wrap(cert);
    return ret;
}

/**
 * @brief Get the certificate expiration dates for all the certificates in the given endpoint.
 *
 * @param[in] ch_client_name Call Home client name.
 * @param[in] endpt_name Endpoint name.
 * @param[in] opts TLS server options.
 * @param[in] intervals Certificate expiration time intervals.
 * @param[in] interval_count Interval count.
 * @param[out] exp_dates Expiration dates.
 * @param[out] exp_date_count Expiration date count.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_notif_cert_exp_dates_endpt_get(const char *ch_client_name, const char *endpt_name, struct nc_server_tls_opts *opts,
        struct nc_interval *intervals, int interval_count, struct nc_cert_expiration **exp_dates, int *exp_date_count)
{
    int ret = 0, i;
    struct nc_certificate *certs;
    uint16_t ncerts;
    struct nc_cert_path_aux cp = {0};

    /* append server cert first */
    if (opts->store == NC_STORE_LOCAL) {
        NC_CERT_EXP_UPDATE_CERT_PATH(&cp, ch_client_name, endpt_name, NULL, NULL, NULL, NULL, NULL, NULL);
        ret = nc_server_notif_cert_exp_date_append(opts->cert_data, &cp, intervals, interval_count, exp_dates, exp_date_count);
        if (ret) {
            goto cleanup;
        }
    }

    /* append CA certs */
    if (opts->ca_certs.store == NC_STORE_LOCAL) {
        certs = opts->ca_certs.certs;
        ncerts = opts->ca_certs.cert_count;

        for (i = 0; i < ncerts; i++) {
            NC_CERT_EXP_UPDATE_CERT_PATH(&cp, ch_client_name, endpt_name, certs[i].name, NULL, NULL, NULL, NULL, NULL);
            ret = nc_server_notif_cert_exp_date_append(certs[i].data, &cp, intervals, interval_count, exp_dates, exp_date_count);
            if (ret) {
                goto cleanup;
            }
        }
    }

    /* append end entity certs */
    if (opts->ee_certs.store == NC_STORE_LOCAL) {
        certs = opts->ee_certs.certs;
        ncerts = opts->ee_certs.cert_count;

        for (i = 0; i < ncerts; i++) {
            NC_CERT_EXP_UPDATE_CERT_PATH(&cp, ch_client_name, endpt_name, NULL, certs[i].name, NULL, NULL, NULL, NULL);
            ret = nc_server_notif_cert_exp_date_append(certs[i].data, &cp, intervals, interval_count, exp_dates, exp_date_count);
            if (ret) {
                goto cleanup;
            }
        }
    }

cleanup:
    return ret;
}

/**
 * @brief Get the certificate expiration dates for all the certificates in the server configuration.
 *
 * @param[in] intervals Certificate expiration time intervals.
 * @param[in] interval_count Interval count.
 * @param[out] exp_dates Expiration dates.
 * @param[out] exp_date_count Expiration date count.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_notif_cert_exp_dates_get(struct nc_interval *intervals, int interval_count, struct nc_cert_expiration **exp_dates, int *exp_date_count)
{
    int ret = 0;
    uint16_t i, j;
    struct nc_keystore *ks = &server_opts.keystore;
    struct nc_truststore *ts = &server_opts.truststore;
    struct nc_cert_path_aux cp = {0};

    NC_CHECK_ARG_RET(NULL, intervals, interval_count, exp_dates, exp_date_count, 1);

    *exp_dates = NULL;
    *exp_date_count = 0;

    /* CONFIG LOCK */
    pthread_rwlock_rdlock(&server_opts.config_lock);

    /* first go through listen certs */
    for (i = 0; i < server_opts.endpt_count; ++i) {
        if (server_opts.endpts[i].ti == NC_TI_TLS) {
            ret = nc_server_notif_cert_exp_dates_endpt_get(NULL, server_opts.endpts[i].name,
                    server_opts.endpts[i].opts.tls, intervals, interval_count, exp_dates, exp_date_count);
            if (ret) {
                goto cleanup;
            }
        }
    }

    /* then go through all the ch clients and their endpts */
    /* CH CLIENT LOCK */
    pthread_rwlock_rdlock(&server_opts.ch_client_lock);
    for (i = 0; i < server_opts.ch_client_count; ++i) {
        /* CH LOCK */
        pthread_mutex_lock(&server_opts.ch_clients[i].lock);
        for (j = 0; j < server_opts.ch_clients[i].ch_endpt_count; ++j) {
            if (server_opts.ch_clients[i].ch_endpts[j].ti == NC_TI_TLS) {
                ret = nc_server_notif_cert_exp_dates_endpt_get(server_opts.ch_clients[i].name,
                        server_opts.ch_clients[i].ch_endpts[j].name, server_opts.ch_clients[i].ch_endpts[j].opts.tls,
                        intervals, interval_count, exp_dates, exp_date_count);
                if (ret) {
                    /* CH UNLOCK */
                    pthread_mutex_unlock(&server_opts.ch_clients[i].lock);
                    /* CH CLIENT UNLOCK */
                    pthread_rwlock_unlock(&server_opts.ch_client_lock);
                    goto cleanup;
                }
            }
        }
        /* CH UNLOCK */
        pthread_mutex_unlock(&server_opts.ch_clients[i].lock);
    }
    /* CH CLIENT UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);

    /* keystore certs */
    for (i = 0; i < ks->asym_key_count; i++) {
        for (j = 0; j < ks->asym_keys[i].cert_count; j++) {
            NC_CERT_EXP_UPDATE_CERT_PATH(&cp, NULL, NULL, NULL, NULL, ks->asym_keys[i].name, ks->asym_keys[i].certs[j].name, NULL, NULL);
            ret = nc_server_notif_cert_exp_date_append(ks->asym_keys[i].certs[j].data, &cp, intervals, interval_count, exp_dates, exp_date_count);
            if (ret) {
                goto cleanup;
            }
        }
    }

    /* truststore certs */
    for (i = 0; i < ts->cert_bag_count; i++) {
        for (j = 0; j < ts->cert_bags[i].cert_count; j++) {
            NC_CERT_EXP_UPDATE_CERT_PATH(&cp, NULL, NULL, NULL, NULL, NULL, NULL, ts->cert_bags[i].name, ts->cert_bags[i].certs[j].name);
            ret = nc_server_notif_cert_exp_date_append(ts->cert_bags[i].certs[j].data, &cp, intervals, interval_count, exp_dates, exp_date_count);
            if (ret) {
                goto cleanup;
            }
        }
    }

cleanup:
    /* CONFIG UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);
    return ret;
}

/**
 * @brief Get the time when the certificate expiration notification thread should wake up.
 *
 * @param[in] exp_dates Expiration dates.
 * @param[in] exp_date_count Expiration date count.
 * @param[out] next Certificate that the notification thread should notify about.
 * @return 0 if the thread should wake up immediately, otherwise a calendar time in the future.
 */
static time_t
nc_server_notif_cert_exp_wakeup_time_get(struct nc_cert_expiration *exp_dates, int exp_date_count, struct nc_cert_expiration **next)
{
    time_t min_time = LONG_MAX;
    int i;
    double diff;
    time_t now, wakeup_time = 0;

    *next = NULL;

    now = time(NULL);
    if (!exp_date_count) {
        /* no certificates, set a "very long timeout" for the thread, it shall wake up on the change of config */
        wakeup_time = now + 365 * 24 * 60 * 60;
        return wakeup_time;
    }

    /* find the minimum wait time */
    for (i = 0; i < exp_date_count; i++) {
        diff = difftime(exp_dates[i].notif_time, now);
        if (diff <= 0) {
            /* already expired, notify immediately */
            *next = &exp_dates[i];
            return 0;
        }

        if (diff < min_time) {
            min_time = diff;
            wakeup_time = exp_dates[i].notif_time;
            *next = &exp_dates[i];
        }
    }

    return wakeup_time;
}

/**
 * @brief Destroy the certificate expiration notification data.
 *
 * @param[in] exp_dates Expiration dates.
 * @param[in] exp_date_count Expiration date count.
 */
static void
nc_server_notif_cert_exp_dates_destroy(struct nc_cert_expiration *exp_dates, int exp_date_count)
{
    int i;

    for (i = 0; i < exp_date_count; i++) {
        free(exp_dates[i].starts_of_intervals);
        free(exp_dates[i].xpath);
    }
    free(exp_dates);
}

/**
 * @brief Check if the certificate expiration notification thread is running.
 *
 * @return 1 if the thread is running, 0 otherwise.
 */
static int
nc_server_notif_cert_exp_thread_is_running()
{
    int ret = 0;

    /* LOCK */
    pthread_mutex_lock(&server_opts.cert_exp_notif.lock);

    if (server_opts.cert_exp_notif.thread_running) {
        ret = 1;
    }

    /* UNLOCK */
    pthread_mutex_unlock(&server_opts.cert_exp_notif.lock);

    return ret;
}

/**
 * @brief Get the certificate expiration notification time intervals either from the config or the default ones.
 *
 * @param[in] default_intervals Default intervals.
 * @param[in] default_interval_count Default interval count.
 * @param[out] intervals Actual intervals to be used.
 * @param[out] interval_count Used interval count.
 */
static void
nc_server_notif_cert_exp_intervals_get(struct nc_interval *default_intervals, int default_interval_count,
        struct nc_interval **intervals, int *interval_count)
{
    /* LOCK */
    pthread_mutex_lock(&server_opts.cert_exp_notif.lock);

    if (!server_opts.cert_exp_notif.intervals) {
        /* using the default intervals */
        *intervals = default_intervals;
        *interval_count = default_interval_count;
    } else {
        /* using configured intervals */
        *intervals = server_opts.cert_exp_notif.intervals;
        *interval_count = server_opts.cert_exp_notif.interval_count;
    }

    /* UNLOCK */
    pthread_mutex_unlock(&server_opts.cert_exp_notif.lock);
}

/**
 * @brief Certificate expiration notification thread.
 *
 * @param[in] arg Thread argument.
 *
 * @return NULL.
 */
static void *
nc_server_notif_cert_exp_thread(void *arg)
{
    int r = 0, exp_date_count = 0;
    struct nc_cert_exp_notif_thread_arg *targ = arg;
    struct nc_cert_expiration *exp_dates = NULL, *curr_cert = NULL;
    struct timespec wakeup_time = {0};
    char *exp_time = NULL;
    struct nc_interval default_intervals[3] = {
        {.anchor = {.months = 3}, .period = {.months = 1}},
        {.anchor = {.weeks = 2}, .period = {.weeks = 1}},
        {.anchor = {.days = 7}, .period = {.days = 1}}
    };
    struct nc_interval *intervals;
    int interval_count;

    /* get certificate expiration time intervals */
    nc_server_notif_cert_exp_intervals_get(default_intervals, 3, &intervals, &interval_count);

    /* get the expiration dates */
    r = nc_server_notif_cert_exp_dates_get(intervals, interval_count, &exp_dates, &exp_date_count);
    if (r) {
        goto cleanup;
    }

    while (nc_server_notif_cert_exp_thread_is_running()) {
        /* get the next notification time and the cert to send it for */
        wakeup_time.tv_sec = nc_server_notif_cert_exp_wakeup_time_get(exp_dates, exp_date_count, &curr_cert);

        /* sleep until the next notification time or until the thread is woken up */
        pthread_mutex_lock(&server_opts.cert_exp_notif.lock);
        r = pthread_cond_clockwait(&server_opts.cert_exp_notif.cond,
                &server_opts.cert_exp_notif.lock, CLOCK_REALTIME, &wakeup_time);
        pthread_mutex_unlock(&server_opts.cert_exp_notif.lock);

        if (!r) {
            /* we were woken up */
            if (!nc_server_notif_cert_exp_thread_is_running()) {
                /* end the thread */
                break;
            }

            /* config changed, reload the certificates and intervals */
            nc_server_notif_cert_exp_dates_destroy(exp_dates, exp_date_count);

            nc_server_notif_cert_exp_intervals_get(default_intervals, 3, &intervals, &interval_count);

            r = nc_server_notif_cert_exp_dates_get(intervals, interval_count, &exp_dates, &exp_date_count);
            if (r) {
                break;
            }
        } else if (r == ETIMEDOUT) {
            /* time to send the notification */
            if (!curr_cert) {
                /* no certificates to notify about */
                continue;
            }

            /* convert the expiration time to string */
            r = ly_time_time2str(curr_cert->expiration_time, NULL, &exp_time);
            if (r) {
                break;
            }

            /* call the callback */
            targ->clb(exp_time, curr_cert->xpath, targ->clb_data);
            free(exp_time);

            /* update the next notification time */
            curr_cert->notif_time = nc_server_notif_cert_exp_next_notif_time_get(intervals, interval_count, curr_cert);
            if (curr_cert->notif_time == -1) {
                break;
            }
        } else {
            ERR(NULL, "Pthread condition timedwait failed (%s).", strerror(r));
            break;
        }
    }

cleanup:
    VRB(NULL, "Certificate expiration notification thread exit.");
    if (targ->clb_free_data) {
        targ->clb_free_data(targ->clb_data);
    }
    nc_server_notif_cert_exp_dates_destroy(exp_dates, exp_date_count);
    free(targ);
    return NULL;
}

API int
nc_server_notif_cert_expiration_thread_start(nc_cert_exp_notif_clb cert_exp_notif_clb,
        void *user_data, void (*free_data)(void *))
{
    int r, ret = 0;
    pthread_t tid;
    struct nc_cert_exp_notif_thread_arg *arg;

    NC_CHECK_ARG_RET(NULL, cert_exp_notif_clb, 1);

    /* set the user callback and its data */
    arg = malloc(sizeof *arg);
    NC_CHECK_ERRMEM_RET(!arg, 1);
    arg->clb = cert_exp_notif_clb;
    arg->clb_data = user_data;
    arg->clb_free_data = free_data;

    /* LOCK */
    pthread_mutex_lock(&server_opts.cert_exp_notif.lock);

    /* check if the thread is already running */
    if (server_opts.cert_exp_notif.thread_running) {
        ERR(NULL, "Certificate expiration notification thread is already running.");
        ret = 1;
        goto cleanup;
    } else {
        server_opts.cert_exp_notif.thread_running = 1;
    }

    if ((r = pthread_create(&tid, NULL, nc_server_notif_cert_exp_thread, arg))) {
        ERR(NULL, "Creating the certificate expiration notification thread failed (%s).", strerror(r));
        ret = 1;
        goto cleanup;
    }

    server_opts.cert_exp_notif.tid = tid;

cleanup:
    /* UNLOCK */
    pthread_mutex_unlock(&server_opts.cert_exp_notif.lock);
    if (ret) {
        free(arg);
    }
    return ret;
}

API void
nc_server_notif_cert_expiration_thread_stop(int wait)
{
    int r;
    pthread_t tid;

    /* LOCK */
    pthread_mutex_lock(&server_opts.cert_exp_notif.lock);
    tid = server_opts.cert_exp_notif.tid;

    if (server_opts.cert_exp_notif.thread_running) {
        /* set the tid and running flag to 0, signal the thread and unlock its mutex */
        server_opts.cert_exp_notif.thread_running = 0;
        server_opts.cert_exp_notif.tid = 0;
        pthread_cond_signal(&server_opts.cert_exp_notif.cond);

        /* UNLOCK */
        pthread_mutex_unlock(&server_opts.cert_exp_notif.lock);
        if (wait) {
            r = pthread_join(tid, NULL);
        } else {
            r = pthread_detach(tid);
        }
        if (r) {
            ERR(NULL, "Stopping the certificate expiration notification thread failed (%s).", strerror(r));
        }
    } else {
        /* thread is not running */
        /* UNLOCK */
        pthread_mutex_unlock(&server_opts.cert_exp_notif.lock);
    }
}

#endif /* NC_ENABLED_SSH_TLS */
