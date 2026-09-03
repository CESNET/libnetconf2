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
#define _GNU_SOURCE /* threads */

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
#include "session.h"
#include "session_p.h"
#include "session_server.h"
#include "session_server_ch.h"

#ifdef NC_ENABLED_SSH_TLS

#include "session_server_ssh_wrapper.h"
#include "session_wrapper.h"

#include <curl/curl.h>
#include <libssh/libssh.h>

#endif /* NC_ENABLED_SSH_TLS */

struct nc_server_opts server_opts = {
    .hello_lock = PTHREAD_RWLOCK_INITIALIZER,
    .config_lock = PTHREAD_RWLOCK_INITIALIZER,
    .config_update_lock = PTHREAD_MUTEX_INITIALIZER,
    .binds_lock = PTHREAD_MUTEX_INITIALIZER,
    .opts_lock = PTHREAD_RWLOCK_INITIALIZER,
    .ch_threads_lock = PTHREAD_MUTEX_INITIALIZER,
};

static nc_rpc_clb global_rpc_clb = NULL;

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Free a Call Home thread argument.
 *
 * @param[in] thread_arg Thread argument to free, may be NULL.
 */
static void
nc_server_ch_thread_arg_free(struct nc_server_ch_thread_arg *thread_arg)
{
    if (!thread_arg) {
        return;
    }

    free(thread_arg->client_name);
    if (thread_arg->notify_pipe[0] != -1) {
        close(thread_arg->notify_pipe[0]);
    }
    if (thread_arg->notify_pipe[1] != -1) {
        close(thread_arg->notify_pipe[1]);
    }
    free(thread_arg);
}

/**
 * @brief Remove a Call Home thread argument from the thread registry.
 *
 * The registry entry is the ownership token of the thread argument, whoever removes it becomes
 * responsible for terminating the thread and freeing the argument.
 *
 * @param[in] client_name Name of the Call Home client to unregister the thread of.
 * @param[out] thread_arg Unregistered thread argument, NULL if the client had no thread registered.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_ch_thread_reg_del(const char *client_name, struct nc_server_ch_thread_arg **thread_arg)
{
    LY_ARRAY_COUNT_TYPE u;

    *thread_arg = NULL;

    /* CH THREADS LOCK */
    if (nc_mutex_lock(&server_opts.ch_threads_lock, NC_CH_THREADS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    LY_ARRAY_FOR(server_opts.ch_threads, u) {
        if (strcmp(server_opts.ch_threads[u]->client_name, client_name)) {
            continue;
        }

        *thread_arg = server_opts.ch_threads[u];

        /* swap the last entry into the hole, the order of the registry is irrelevant */
        server_opts.ch_threads[u] = server_opts.ch_threads[LY_ARRAY_COUNT(server_opts.ch_threads) - 1];
        LY_ARRAY_DECREMENT_FREE(server_opts.ch_threads);
        break;
    }

    /* CH THREADS UNLOCK */
    nc_mutex_unlock(&server_opts.ch_threads_lock, __func__);
    return 0;
}

/**
 * @brief Unregister a Call Home thread that is terminating on its own and free its argument.
 *
 * Called by the Call Home thread itself right before it returns. Normally the thread only ever
 * terminates because ::nc_session_server_ch_client_dispatch_stop() told it to, in which case the
 * stopper has already removed the registry entry and does all the cleanup itself. If the thread
 * terminates for any other reason (an unrecoverable error), it has to take itself out of the
 * registry, otherwise every later configuration apply would believe the client is still running
 * and would never dispatch it again.
 *
 * The registry entry is the ownership token of the thread argument, so the entry removal decides
 * who cleans up and the ::nc_server_opts.ch_threads_lock makes that decision atomic.
 *
 * @param[in] thread_arg Argument of the calling thread.
 */
static void
nc_server_ch_thread_unreg_self(struct nc_server_ch_thread_arg *thread_arg)
{
    LY_ARRAY_COUNT_TYPE u;
    int found = 0;

    /* CH THREADS LOCK */
    if (nc_mutex_lock(&server_opts.ch_threads_lock, NC_CH_THREADS_LOCK_TIMEOUT, __func__) != 1) {
        return;
    }

    LY_ARRAY_FOR(server_opts.ch_threads, u) {
        if (server_opts.ch_threads[u] != thread_arg) {
            continue;
        }

        found = 1;

        /* swap the last entry into the hole, the order of the registry is irrelevant */
        server_opts.ch_threads[u] = server_opts.ch_threads[LY_ARRAY_COUNT(server_opts.ch_threads) - 1];
        LY_ARRAY_DECREMENT_FREE(server_opts.ch_threads);
        break;
    }

    /* CH THREADS UNLOCK */
    nc_mutex_unlock(&server_opts.ch_threads_lock, __func__);

    if (!found) {
        /* someone else owns us now and will join us, nothing to do */
        return;
    }

    /* nobody is going to join us anymore, so make sure our resources are reclaimed */
    pthread_detach(thread_arg->tid);
    nc_server_ch_thread_arg_free(thread_arg);
}

void
nc_server_ch_thread_names_free(char **names)
{
    LY_ARRAY_COUNT_TYPE u;

    LY_ARRAY_FOR(names, u) {
        free(names[u]);
    }
    LY_ARRAY_FREE(names);
}

int
nc_server_ch_thread_names_get(char ***names)
{
    int rc = 0;
    LY_ARRAY_COUNT_TYPE u;
    char *name;

    *names = NULL;

    /* CH THREADS LOCK */
    if (nc_mutex_lock(&server_opts.ch_threads_lock, NC_CH_THREADS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    if (LY_ARRAY_COUNT(server_opts.ch_threads)) {
        LY_ARRAY_CREATE_GOTO(NULL, *names, LY_ARRAY_COUNT(server_opts.ch_threads), rc, cleanup);
        LY_ARRAY_FOR(server_opts.ch_threads, u) {
            name = strdup(server_opts.ch_threads[u]->client_name);
            NC_CHECK_ERRMEM_GOTO(!name, rc = 1, cleanup);
            (*names)[u] = name;
            LY_ARRAY_INCREMENT(*names);
        }
    }

cleanup:
    /* CH THREADS UNLOCK */
    nc_mutex_unlock(&server_opts.ch_threads_lock, __func__);
    if (rc) {
        nc_server_ch_thread_names_free(*names);
        *names = NULL;
    }
    return rc ? 1 : 0;
}

/**
 * @brief Get a CH client with the given @p name from a pinned configuration.
 *
 * @param[in] config Pinned server configuration to search.
 * @param[in] name Name of the CH client to find.
 * @return CH client, NULL if not found.
 */
static const struct nc_ch_client *
nc_server_ch_client_get_pinned(const struct nc_server_config *config, const char *name)
{
    LY_ARRAY_COUNT_TYPE u;

    assert(name);

    LY_ARRAY_FOR(config->ch_clients, u) {
        if (!strcmp(config->ch_clients[u].name, name)) {
            return &config->ch_clients[u];
        }
    }

    return NULL;
}

#endif /* NC_ENABLED_SSH_TLS */

int
nc_server_endpt_get(const struct nc_server_config *config, const char *name, const struct nc_endpt **endpt)
{
    LY_ARRAY_COUNT_TYPE u;

    *endpt = NULL;

    if (!config) {
        return 1;
    }

    LY_ARRAY_FOR(config->endpts, u) {
        if (config->endpts[u].name && !strcmp(config->endpts[u].name, name)) {
            *endpt = &config->endpts[u];
            return 0;
        }
    }

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

    if ((reason != NC_SESSION_TERM_KILLED) && (NC_SESSION_TERM_REASON_GET(session) == NC_SESSION_TERM_KILLED)) {
        session->killed_by = 0;
    }
    NC_SESSION_TERM_REASON_SET(session, reason);
}

API void
nc_session_set_killed_by(struct nc_session *session, uint32_t sid)
{
    if (!session || (NC_SESSION_TERM_REASON_GET(session) != NC_SESSION_TERM_KILLED)) {
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

    NC_SESSION_STATUS_SET(session, status);
}

API int
nc_server_init_ctx(struct ly_ctx **ctx)
{
    int new_ctx = 0, i, ret = 0;
    struct lys_module *module;
    LY_ERR r;
    /* all features */
    const char *ietf_netconf_features[] = {"writable-running", "candidate", "rollback-on-error", "validate", "startup", "url", "xpath", "confirmed-commit", NULL};
    /* all features (module has no features) */
    const char *ietf_netconf_monitoring_features[] = {NULL};

    NC_CHECK_ARG_RET(NULL, ctx, 1);

    if (!*ctx) {
        /* context not given, create a new one */
        if (ly_ctx_new(ly_yang_module_dir(), 0, ctx)) {
            ERR(NULL, "Failed to create a new libyang context.");
            ret = 1;
            goto cleanup;
        }
        new_ctx = 1;

        r = ly_ctx_set_searchdir(*ctx, nc_yang_module_dir());
        if (r && (r != LY_EEXIST)) {
            ERR(NULL, "Failed to set searchdir for a context.");
            ret = 1;
            goto cleanup;
        }
    }

    if (new_ctx) {
        /* new context created, implement both modules */
        if (!ly_ctx_load_module(*ctx, "ietf-netconf", NULL, ietf_netconf_features)) {
            ERR(NULL, "Loading module \"ietf-netconf\" failed.");
            ret = 1;
            goto cleanup;
        }

        if (!ly_ctx_load_module(*ctx, "ietf-netconf-monitoring", NULL, ietf_netconf_monitoring_features)) {
            ERR(NULL, "Loading module \"ietf-netconf-monitoring\" failed.");
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
                    ERR(NULL, "Loading module \"ietf-netconf\" failed.");
                    ret = 1;
                    goto cleanup;
                }

                break;
            }
        }
    } else {
        /* ietf-netconf module not found, add it */
        if (!ly_ctx_load_module(*ctx, "ietf-netconf", NULL, ietf_netconf_features)) {
            ERR(NULL, "Loading module \"ietf-netconf\" failed.");
            ret = 1;
            goto cleanup;
        }
    }

    module = ly_ctx_get_module_implemented(*ctx, "ietf-netconf-monitoring");
    if (!module) {
        /* ietf-netconf-monitoring module not found, add it */
        if (!ly_ctx_load_module(*ctx, "ietf-netconf-monitoring", NULL, ietf_netconf_monitoring_features)) {
            ERR(NULL, "Loading module \"ietf-netconf-monitoring\" failed.");
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

    /* OPTS WRITE LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_WRITE, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return;
    }

    server_opts.ch_dispatch_data.acquire_ctx_cb = acquire_ctx_cb;
    server_opts.ch_dispatch_data.release_ctx_cb = release_ctx_cb;
    server_opts.ch_dispatch_data.ctx_cb_data = ctx_cb_data;
    server_opts.ch_dispatch_data.new_session_cb = new_session_cb;
    server_opts.ch_dispatch_data.new_session_cb_data = new_session_cb_data;

    /* OPTS WRITE UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
}

API void
nc_server_ch_set_new_session_fail_cb(nc_server_ch_new_session_fail_cb new_session_fail_cb,
        void *new_session_fail_cb_data)
{
    /* OPTS WRITE LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_WRITE, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return;
    }

    server_opts.ch_dispatch_data.new_session_fail_cb = new_session_fail_cb;
    server_opts.ch_dispatch_data.new_session_fail_cb_data = new_session_fail_cb_data;

    /* OPTS WRITE UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
}

#endif

int
nc_sock_bind_inet(int sock, const char *address, uint16_t port, int is_ipv4)
{
    struct sockaddr_storage saddr;
    struct sockaddr_in *saddr4;
    struct sockaddr_in6 *saddr6;

#ifdef NC_ENABLE_IP_FREEBIND
    int opt;
#endif

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

#ifdef NC_ENABLE_IP_FREEBIND
        opt = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_FREEBIND, &opt, sizeof(opt))) {
            ERR(NULL, "Could not add IP_FREEBIND option (%s).", strerror(errno));
            return -1;
        }
#endif

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

#ifdef NC_ENABLE_IP_FREEBIND
        opt = 1;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_FREEBIND, &opt, sizeof(opt))) {
            ERR(NULL, "Could not add IPV6_FREEBIND option (%s).", strerror(errno));
            return -1;
        }
#endif

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
    int opt, flags, is_ipv4, sock;

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

    /* make the socket non-blocking */
    if (((flags = fcntl(sock, F_GETFL)) == -1) || (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)) {
        ERR(NULL, "Fcntl failed (%s).", strerror(errno));
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
 * @brief Construct the full path to the UNIX socket.
 *
 * @note Resolves the paths on the filesystem, so no lock may be held.
 *
 * @param[in] dir Base directory the socket must reside in, NULL if none is set.
 * @param[in] filename Name of the socket file.
 * @param[out] path Constructed full path to the UNIX socket (must be freed by the caller).
 * @return 0 on success, 1 on error.
 */
static int
nc_session_unix_construct_socket_path(const char *dir, const char *filename, char **path)
{
    int rc = 0, is_prefix, is_subdir, is_exact;
    char *full_path = NULL, *real_base_dir = NULL, *last_slash = NULL, *sock_dir_path = NULL;
    char *real_target_dir = NULL;
    struct sockaddr_un sun;
    size_t dir_len, base_len;

    if (!dir) {
        ERR(NULL, "Cannot construct UNIX socket path \"%s\""
                " (no base directory set, see nc_server_set_unix_socket_dir()).", filename);
        return 1;
    }

    if (filename[0] == '/') {
        ERR(NULL, "Cannot construct UNIX socket path \"%s\" (absolute path not allowed).", filename);
        return 1;
    }

    /* construct the path to the UNIX socket */
    if (asprintf(&full_path, "%s/%s", dir, filename) == -1) {
        ERRMEM;
        rc = 1;
        goto cleanup;
    }

    if (strlen(full_path) > sizeof(sun.sun_path) - 1) {
        ERR(NULL, "Socket path \"%s\" is too long.", full_path);
        rc = 1;
        goto cleanup;
    }

    /* ensure the socket path is within the base directory */
    if (!(real_base_dir = realpath(dir, NULL))) {
        ERR(NULL, "realpath() failed for UNIX socket base directory \"%s\" (%s).", dir, strerror(errno));
        rc = 1;
        goto cleanup;
    }

    /* find the last slash in the constructed path */
    last_slash = strrchr(full_path, '/');
    if (last_slash) {
        /* extract the directory part of the socket path */
        dir_len = last_slash - full_path;
        sock_dir_path = strndup(full_path, dir_len);
        NC_CHECK_ERRMEM_GOTO(!sock_dir_path, rc = 1, cleanup);

        if (!(real_target_dir = realpath(sock_dir_path, NULL))) {
            ERR(NULL, "realpath() failed for UNIX socket path directory \"%s\" (%s).", sock_dir_path,
                    strerror(errno));
            rc = 1;
            goto cleanup;
        }
    } else {
        /* should not happen as we always add dir/filename */
        real_target_dir = strdup(real_base_dir);
        NC_CHECK_ERRMEM_GOTO(!real_target_dir, rc = 1, cleanup);
    }

    base_len = strlen(real_base_dir);

    /* check the relationship between both paths */
    is_prefix = (strncmp(real_base_dir, real_target_dir, base_len) == 0);

    is_exact = (real_target_dir[base_len] == '\0');

    is_subdir = (real_target_dir[base_len] == '/');

    /* special case if base is '/' */
    if ((base_len == 1) && (real_base_dir[0] == '/')) {
        is_subdir = 1;
    }

    if (!is_prefix || (!is_exact && !is_subdir)) {
        ERR(NULL, "UNIX socket path \"%s\" escapes the base directory \"%s\".", full_path, dir);
        rc = 1;
        goto cleanup;
    }

    /* transfer ownership */
    *path = full_path;
    full_path = NULL;

cleanup:
    free(real_base_dir);
    free(real_target_dir);
    free(sock_dir_path);
    free(full_path);
    return rc;
}

/**
 * @brief Get the full path of the UNIX socket of an endpoint.
 *
 * @param[in] endpt Endpoint to get the socket path for.
 * @return Socket path, NULL on error.
 */
static char *
nc_server_unix_get_socket_path(const struct nc_endpt *endpt)
{
    int rc = 0;
    LY_ARRAY_COUNT_TYPE i;
    const char *p = NULL;
    char *path = NULL, *sock_dir = NULL;

    /* OPTS READ LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_READ, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return NULL;
    }

    /* only copy what is needed out of the options, resolving the path touches the filesystem and
     * the options lock must not be held for that */
    switch (endpt->opts.unix->path_type) {
    case NC_UNIX_SOCKET_PATH_FILE:
        /* the address in the bind is relative to the base directory */
        if (server_opts.unix_socket_dir) {
            sock_dir = strdup(server_opts.unix_socket_dir);
            NC_CHECK_ERRMEM_GOTO(!sock_dir, rc = 1, cleanup);
        }
        break;
    case NC_UNIX_SOCKET_PATH_HIDDEN:
        /* search the mappings, they store the full path so there is nothing to construct */
        LY_ARRAY_FOR(server_opts.unix_paths, i) {
            if (!strcmp(server_opts.unix_paths[i].endpt_name, endpt->name)) {
                p = server_opts.unix_paths[i].path;
                break;
            }
        }
        if (!p) {
            ERR(NULL, "UNIX socket path mapping for endpoint \"%s\" not found.", endpt->name);
            rc = 1;
            goto cleanup;
        }

        path = strdup(p);
        NC_CHECK_ERRMEM_GOTO(!path, rc = 1, cleanup);
        break;
    default:
        ERRINT;
        rc = 1;
        break;
    }

cleanup:
    /* OPTS READ UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);

    if (rc) {
        free(sock_dir);
        free(path);
        return NULL;
    }
    if (path) {
        /* the hidden path is used as it is */
        return path;
    }

    /* UNIX socket endpoints always have only one bind, its address is the socket file name */
    if (nc_session_unix_construct_socket_path(sock_dir, endpt->binds[0].address, &path)) {
        path = NULL;
    }
    free(sock_dir);
    return path;
}

/**
 * @brief Create a listening socket (AF_UNIX).
 *
 * @param[in] address Path to the UNIX socket.
 * @param[in] opts The server options (unix permissions).
 * @return Listening socket, -1 on error.
 */
static int
nc_sock_listen_unix(const char *address, const struct nc_server_unix_opts *opts)
{
    struct sockaddr_un sun;
    int sock = -1, flags;

    if (!address) {
        ERR(NULL, "No socket path set.");
        goto fail;
    } else if (strlen(address) > sizeof(sun.sun_path) - 1) {
        ERR(NULL, "Socket path \"%s\" is longer than maximum length %d.", address, (int)(sizeof(sun.sun_path) - 1));
        goto fail;
    }

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        ERR(NULL, "Failed to create socket (%s).", strerror(errno));
        goto fail;
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path) - 1, "%s", address);

    unlink(sun.sun_path);
    if (bind(sock, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
        ERR(NULL, "Could not bind \"%s\" (%s).", address, strerror(errno));
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

    /* make the socket non-blocking */
    if (((flags = fcntl(sock, F_GETFL)) == -1) || (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)) {
        ERR(NULL, "Fcntl failed (%s).", strerror(errno));
        goto fail;
    }

    if (listen(sock, NC_REVERSE_QUEUE) == -1) {
        ERR(NULL, "Unable to start listening on \"%s\" (%s).", address, strerror(errno));
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
nc_sock_host_unix(int acc_sock_fd, char **host)
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
nc_sock_host_inet(const struct sockaddr_in *addr, char **host, uint16_t *port)
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
nc_sock_host_inet6(const struct sockaddr_in6 *addr, char **host, uint16_t *port)
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

/**
 * @brief Get the client's host information from the accepted socket address.
 *
 * @param[in] saddr sockaddr_storage.
 * @param[in] client_sock Socket FD of the accepted connection.
 * @param[out] client_address Hostname or IP address of the connecting client (must be freed by the caller).
 * @param[out] client_port Port number of the connecting client, if any (0 for AF_UNIX).
 * @return 0 on success, -1 on error.
 */
static int
nc_sock_host_get(const struct sockaddr_storage *saddr, int client_sock, char **client_address, uint16_t *client_port)
{
    int rc = 0;

    /* learn information about the client end */
    if (saddr->ss_family == AF_UNIX) {
        if ((rc = nc_sock_host_unix(client_sock, client_address))) {
            goto cleanup;
        }
        *client_port = 0;
    } else if (saddr->ss_family == AF_INET) {
        if ((rc = nc_sock_host_inet((struct sockaddr_in *)saddr, client_address, client_port))) {
            goto cleanup;
        }
    } else if (saddr->ss_family == AF_INET6) {
        if ((rc = nc_sock_host_inet6((struct sockaddr_in6 *)saddr, client_address, client_port))) {
            goto cleanup;
        }
    } else {
        ERR(NULL, "Source host of an unknown protocol family.");
        rc = -1;
        goto cleanup;
    }

cleanup:
    return rc;
}

/**
 * @brief Log the accepted connection.
 *
 * @param[in] saddr sockaddr_storage.
 * @param[in] address Address of the bind the connection was accepted on, the socket path for AF_UNIX.
 * @param[in] port Port of the bind the connection was accepted on.
 * @param[in] client_address Hostname or IP address of the connecting client.
 * @param[in] client_port Port number of the connecting client, if any.
 * @return 0 on success, -1 on error.
 */
static int
nc_sock_log_accepted(const struct sockaddr_storage *saddr, const char *address, uint16_t port,
        const char *client_address, uint16_t client_port)
{
    if (saddr->ss_family == AF_UNIX) {
        /* UNIX socket, the address is the full socket path */
        VRB(NULL, "Accepted a new connection on %s.", address);
    } else if (saddr->ss_family == AF_INET) {
        /* IPv4 socket */
        VRB(NULL, "Accepted a new connection on %s:%" PRIu16 " from %s:%" PRIu16 ".", address, port,
                client_address, client_port);
    } else if (saddr->ss_family == AF_INET6) {
        /* IPv6 socket */
        VRB(NULL, "Accepted a new connection on [%s]:%" PRIu16 " from [%s]:%" PRIu16 ".", address, port,
                client_address, client_port);
    } else {
        ERR(NULL, "Source host of an unknown protocol family.");
        return -1;
    }

    return 0;
}

/**
 * @brief Accept the first available connection on the given pollfds.
 *
 * @param[in] pfd Array of pollfds to check for incoming connections.
 * @param[in] pfd_count Number of pollfds in the array.
 * @param[out] client_sock Socket file descriptor of the accepted connection, -1 if no connection was accepted.
 * @param[out] saddr sockaddr_storage to store the address of the connecting client.
 * @param[out] saddr_len Length of the sockaddr_storage structure.
 * @param[out] fd_idx Index of the pollfd on which the connection was accepted, valid only if client_sock is not -1.
 * @return 0 on success, -1 on error (client_sock will be -1 on error or if no connection was accepted).
 */
static int
nc_sock_accept_first(struct pollfd *pfd, uint16_t pfd_count, int *client_sock,
        struct sockaddr_storage *saddr, socklen_t *saddr_len, uint16_t *fd_idx)
{
    int sock = -1;
    uint16_t i;

    *client_sock = -1;

    for (i = 0; i < pfd_count; i++) {
        if (pfd[i].revents & POLLIN) {
            sock = accept(pfd[i].fd, (struct sockaddr *)saddr, saddr_len);
            if (sock < 0) {
                if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                    /* another thread already accepted the connection, try another one */
                    continue;
                }
                if ((errno == EBADF) || (errno == ENOTSOCK)) {
                    /* the listening socket was closed by a configuration apply after we copied it
                     * out of the registry, which is a normal outcome here, try another one */
                    DBG(NULL, "Accept on an already closed listening socket, skipping it.");
                    continue;
                }
                ERR(NULL, "Accept failed (%s).", strerror(errno));
                return -1;
            }

            /* successfully accepted a connection! */
            break;
        }
    }

    if (sock != -1) {
        *client_sock = sock;
        *fd_idx = i;
    }

    return 0;
}

/**
 * @brief Accept a new connection on any of the given pollfds.
 *
 * Can be called by multiple threads. If there is only a single event, one thread will accept the connection,
 * others will timeout.
 *
 * @param[in] pollfds FDs to poll for new connections.
 * @param[in] pollfd_count Number of FDs in the pollfds array.
 * @param[in] addr_map Map of pollfd indices to bind addresses (used for logging).
 * @param[in] port_map Map of pollfd indices to bind ports (used for logging).
 * @param[in] timeout Timeout for accepting a connection.
 * @param[out] host Hostname or IP address of the connecting client.
 * @param[out] port Port number of the connecting client, if any.
 * @param[out] fd_idx Index of the pollfd on which the connection was accepted.
 * @param[out] sock Socket file descriptor of the accepted connection.
 * @return 1 on success, 0 on timeout, -1 on error.
 */
static int
nc_sock_accept_pollfds(struct pollfd *pollfds, uint16_t pollfd_count, const char **addr_map,
        const uint16_t *port_map, int timeout, char **host, uint16_t *port,
        uint16_t *fd_idx, int *sock)
{
    uint16_t client_port = 0, matched_pollfd_idx = 0;
    char *client_address = NULL;
    struct sockaddr_storage client_saddr;
    socklen_t saddr_len = sizeof(client_saddr);
    int client_sock = -1, ret = 1, r, flags;

    if (!pollfd_count) {
        /* no FDs to poll, treat as a timeout */
        ret = 0;
        goto cleanup;
    }

    /* poll for a new connection */
    r = nc_poll(pollfds, pollfd_count, timeout);
    if (r < 1) {
        /* either 0 (timeout) or -1 (error) */
        ret = r;
        goto cleanup;
    }

    /* try to accept the first available connection */
    if ((r = nc_sock_accept_first(pollfds, pollfd_count, &client_sock, &client_saddr, &saddr_len, &matched_pollfd_idx))) {
        ret = r;
        goto cleanup;
    }
    if (client_sock == -1) {
        /* all events were stolen by other threads, treat as a timeout */
        ret = 0;
        goto cleanup;
    }

    /* make the socket non-blocking */
    if (((flags = fcntl(client_sock, F_GETFL)) == -1) || (fcntl(client_sock, F_SETFL, flags | O_NONBLOCK) == -1)) {
        ERR(NULL, "Fcntl failed (%s).", strerror(errno));
        ret = -1;
        goto cleanup;
    }

    /* learn information about the peer */
    if ((r = nc_sock_host_get(&client_saddr, client_sock, &client_address, &client_port))) {
        ret = r;
        goto cleanup;
    }

    /* log the new accepted connection */
    if ((r = nc_sock_log_accepted(&client_saddr, addr_map[matched_pollfd_idx], port_map[matched_pollfd_idx],
            client_address, client_port))) {
        ret = r;
        goto cleanup;
    }

    if (host) {
        *host = client_address;
        client_address = NULL;
    }
    if (port) {
        *port = client_port;
    }
    if (fd_idx) {
        *fd_idx = matched_pollfd_idx;
    }
    *sock = client_sock;
    client_sock = -1;

cleanup:
    free(client_address);
    if (client_sock > -1) {
        close(client_sock);
    }
    return ret;
}

/**
 * @brief Accept a new connection on any of the registered listening sockets.
 *
 * The listening socket registry is only read to build the local poll arrays, the ::poll() itself
 * and the ::accept() run with no lock held.
 *
 * @note Only the sockets of endpoints that @p config contains are polled. A socket registered for
 * an endpoint that @p config does not know (it was registered or its endpoint renamed after
 * @p config was read) is skipped, its pending connections are left in the listen backlog for a
 * call with a newer configuration pinned. That way no connection is ever accepted just to be
 * dropped again because there is no endpoint to serve it with.
 *
 * @note Since the registry lock is not held while polling, a configuration apply may close one of
 * the sockets meanwhile. Polling and accepting a closed descriptor is handled (the socket is simply
 * skipped), but the descriptor number may also have been reused by then, in which case the
 * connection is accepted on and logged with whatever the endpoint of the new socket is.
 *
 * @param[in] config Pinned server configuration used to look the accepting endpoint up.
 * @param[in] timeout Timeout for accepting a connection.
 * @param[out] host Hostname or IP address of the connecting client.
 * @param[out] port Port number of the connecting client, if any.
 * @param[out] idx Index of the endpoint on which the connection was accepted (optional).
 * @param[out] sock Socket file descriptor of the accepted connection.
 * @return 1 on success, 0 on timeout, -1 on error.
 */
static int
nc_server_accept_binds(const struct nc_server_config *config, int timeout, char **host,
        uint16_t *port, LY_ARRAY_COUNT_TYPE *idx, int *sock)
{
    struct pollfd *pollfds = NULL;
    uint16_t pollfd_count = 0, fd_idx = 0, i, bind_count = 0;
    LY_ARRAY_COUNT_TYPE u;
    int ret = 1, binds_locked = 0;
    char **addr_map = NULL;
    uint16_t *port_map = NULL;
    LY_ARRAY_COUNT_TYPE *endpt_map = NULL;

    /* BINDS LOCK */
    if (nc_mutex_lock(&server_opts.binds_lock, NC_BINDS_LOCK_TIMEOUT, __func__) != 1) {
        return -1;
    }
    binds_locked = 1;

    bind_count = LY_ARRAY_COUNT(server_opts.binds);
    if (!bind_count) {
        /* no binds to accept on, treat as a timeout */
        ret = 0;
        goto cleanup;
    }

    /* copy the registry into local arrays, so that the lock can be released before polling */
    pollfds = malloc(bind_count * sizeof *pollfds);
    NC_CHECK_ERRMEM_GOTO(!pollfds, ret = -1, cleanup);
    addr_map = calloc(bind_count, sizeof *addr_map);
    NC_CHECK_ERRMEM_GOTO(!addr_map, ret = -1, cleanup);
    port_map = malloc(bind_count * sizeof *port_map);
    NC_CHECK_ERRMEM_GOTO(!port_map, ret = -1, cleanup);
    endpt_map = malloc(bind_count * sizeof *endpt_map);
    NC_CHECK_ERRMEM_GOTO(!endpt_map, ret = -1, cleanup);

    for (i = 0; i < bind_count; ++i) {
        /* resolve the endpoint of the bind in the pinned configuration, it is immutable so the
         * index stays valid for as long as the configuration is pinned */
        LY_ARRAY_FOR(config->endpts, u) {
            if (!strcmp(config->endpts[u].name, server_opts.binds[i].endpt_name)) {
                break;
            }
        }
        if (u == LY_ARRAY_COUNT(config->endpts)) {
            /* we would have no endpoint to serve a connection accepted here with, do not poll it */
            continue;
        }
        endpt_map[pollfd_count] = u;

        pollfds[pollfd_count].fd = server_opts.binds[i].sock;
        pollfds[pollfd_count].events = POLLIN;
        pollfds[pollfd_count].revents = 0;

        /* the registry entries may be freed once the lock is released, so copy the address */
        addr_map[pollfd_count] = strdup(server_opts.binds[i].address);
        NC_CHECK_ERRMEM_GOTO(!addr_map[pollfd_count], ret = -1, cleanup);
        port_map[pollfd_count] = server_opts.binds[i].port;

        ++pollfd_count;
    }

    /* BINDS UNLOCK */
    nc_mutex_unlock(&server_opts.binds_lock, __func__);
    binds_locked = 0;

    if (!pollfd_count) {
        /* every registered socket belongs to an endpoint the pinned configuration does not have,
         * report a timeout right away and let the caller retry with a newer configuration */
        VRB(NULL, "No listening socket of the pinned configuration to accept on.");
        ret = 0;
        goto cleanup;
    }

    /* accept a new connection on any of the sockets */
    ret = nc_sock_accept_pollfds(pollfds, pollfd_count, (const char **)addr_map, port_map, timeout, host, port,
            &fd_idx, sock);
    if ((ret > 0) && idx) {
        *idx = endpt_map[fd_idx];
    }

cleanup:
    if (binds_locked) {
        /* BINDS UNLOCK */
        nc_mutex_unlock(&server_opts.binds_lock, __func__);
    }
    if (addr_map) {
        for (i = 0; i < bind_count; ++i) {
            free(addr_map[i]);
        }
    }
    free(pollfds);
    free(addr_map);
    free(port_map);
    free(endpt_map);
    return ret;
}

int
nc_server_ch_accept_binds(const struct nc_bind *binds, const struct nc_client_ch_bind_aux *binds_aux,
        uint16_t bind_count, int timeout, char **host, uint16_t *port, uint16_t *bind_idx, int *sock)
{
    struct pollfd *pollfds = NULL;
    uint16_t pollfd_count = 0, fd_idx = 0, i;
    int ret = 1;
    const char **addr_map = NULL;
    uint16_t *port_map = NULL, *idx_map = NULL;

    if (!bind_count) {
        /* no binds to accept on, treat as a timeout */
        return 0;
    }

    /* prepare the pollfd and map parallel arrays */
    pollfds = malloc(bind_count * sizeof *pollfds);
    NC_CHECK_ERRMEM_RET(!pollfds, -1);
    addr_map = malloc(bind_count * sizeof *addr_map);
    NC_CHECK_ERRMEM_GOTO(!addr_map, ret = -1, cleanup);
    port_map = malloc(bind_count * sizeof *port_map);
    NC_CHECK_ERRMEM_GOTO(!port_map, ret = -1, cleanup);
    idx_map = malloc(bind_count * sizeof *idx_map);
    NC_CHECK_ERRMEM_GOTO(!idx_map, ret = -1, cleanup);

    /* fill the arrays */
    for (i = 0; i < bind_count; ++i) {
        if (binds_aux[i].sock < 0) {
            /* invalid socket */
            continue;
        }

        pollfds[pollfd_count].fd = binds_aux[i].sock;
        pollfds[pollfd_count].events = POLLIN;
        pollfds[pollfd_count].revents = 0;

        addr_map[pollfd_count] = binds[i].address;
        port_map[pollfd_count] = binds[i].port;
        idx_map[pollfd_count] = i;

        ++pollfd_count;
    }

    ret = nc_sock_accept_pollfds(pollfds, pollfd_count, addr_map, port_map, timeout, host, port, &fd_idx, sock);
    if (bind_idx && (ret > 0)) {
        *bind_idx = idx_map[fd_idx];
    }

cleanup:
    free(pollfds);
    free(addr_map);
    free(port_map);
    free(idx_map);
    return ret;
}

API struct nc_server_reply *
nc_clb_default_get_schema(struct lyd_node *rpc, struct nc_session *session)
{
    const char *identifier = NULL, *revision = NULL, *format = NULL;
    char *model_data = NULL;
    struct ly_out *out;
    const struct lys_module *module = NULL, *nm_mod;
    const struct lysp_submodule *submodule = NULL;
    struct lyd_node *child, *err, *data = NULL;
    LYS_OUTFORMAT outformat = 0;
    LY_ERR lyrc;

    nm_mod = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf-monitoring");
    if (!nm_mod) {
        err = nc_err(session->ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, "Module \"ietf-netconf-monitoring\" not found in the session context.", "en");
        goto error;
    }

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
        goto error;
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
        goto error;
    }

    /* check format */
    if (!format || !strcmp(format, "ietf-netconf-monitoring:yang")) {
        outformat = LYS_OUT_YANG;
    } else if (!strcmp(format, "ietf-netconf-monitoring:yin")) {
        outformat = LYS_OUT_YIN;
    } else {
        err = nc_err(session->ctx, NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, "The requested format is not supported.", "en");
        goto error;
    }

    /* print */
    ly_out_new_memory(&model_data, 0, &out);
    if (module) {
        lyrc = lys_print_module(out, module, outformat, 0, 0);
    } else {
        lyrc = lys_print_submodule(out, submodule, outformat, 0, 0);
    }
    ly_out_free(out, NULL, 0);
    if (lyrc) {
        err = nc_err(session->ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, ly_last_logmsg(), "en");
        goto error;
    }

    /* create reply */
    if (lyd_new_inner(NULL, nm_mod, "get-schema", 0, &data)) {
        err = nc_err(session->ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, ly_last_logmsg(), "en");
        goto error;
    }
    if (lyd_new_any(data, NULL, "data", NULL, model_data, 0, LYD_NEW_ANY_USE_VALUE | LYD_NEW_VAL_OUTPUT, NULL)) {
        err = nc_err(session->ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(err, ly_last_logmsg(), "en");
        goto error;
    }

    return nc_server_reply_data(data, NC_WD_EXPLICIT, NC_PARAMTYPE_FREE);

error:
    free(model_data);
    lyd_free_tree(data);
    return nc_server_reply_err(err);
}

API struct nc_server_reply *
nc_clb_default_close_session(struct lyd_node *UNUSED(rpc), struct nc_session *session)
{
    NC_SESSION_TERM_REASON_SET(session, NC_SESSION_TERM_CLOSED);
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
    uintptr_t exp;
    int result;

    if (global_rpc_clb) {
        /* expect it to handle these RPCs as well */
        return;
    }

    /* set default <get-schema> callback if not specified */
    rpc = NULL;
    if (ly_ctx_get_module_implemented(ctx, "ietf-netconf-monitoring")) {
        rpc = (struct lysc_node *)lys_find_path(ctx, NULL, "/ietf-netconf-monitoring:get-schema", 0);
    }
    if (rpc) {
        exp = 0;
        ATOMIC_PTR_COMPARE_EXCHANGE_RELAXED(rpc->priv, exp, (uintptr_t)nc_clb_default_get_schema, result);

        /* whatever */
        (void)result;
    }

    /* set default <close-session> callback if not specified */
    rpc = (struct lysc_node *)lys_find_path(ctx, NULL, "/ietf-netconf:close-session", 0);
    if (rpc) {
        exp = 0;
        ATOMIC_PTR_COMPARE_EXCHANGE_RELAXED(rpc->priv, exp, (uintptr_t)nc_clb_default_close_session, result);
        (void)result;
    }
}

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Open the keylog file for writing TLS secrets.
 */
static void
nc_server_keylog_file_open(void)
{
    char *keylog_file_name;

    keylog_file_name = getenv(NC_TLS_KEYLOGFILE_ENV);
    if (!keylog_file_name) {
        return;
    }

    server_opts.tls_keylog_file = fopen(keylog_file_name, "a");
    if (!server_opts.tls_keylog_file) {
        WRN(NULL, "Failed to open keylog file \"%s\".", keylog_file_name);
    }
}

#endif

/**
 * @brief Initialize a rwlock.
 *
 * @param[in] rwlock RW lock to initialize.
 * @return errno.
 */
static int
nc_server_init_rwlock(pthread_rwlock_t *rwlock)
{
#ifdef HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP
    int rc = 0;
    pthread_rwlockattr_t attr;

    if ((rc = pthread_rwlockattr_init(&attr))) {
        ERR(NULL, "%s: failed to init attribute (%s).", __func__, strerror(rc));
        return rc;
    }

    if ((rc = pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP))) {
        ERR(NULL, "%s: failed to set attribute (%s).", __func__, strerror(rc));
        goto cleanup;
    }

    if ((rc = pthread_rwlock_init(rwlock, &attr))) {
        ERR(NULL, "%s: failed to init rwlock (%s).", __func__, strerror(rc));
        goto cleanup;
    }

cleanup:
    pthread_rwlockattr_destroy(&attr);
    return rc;
#else
    int rc = 0;

    if ((rc = pthread_rwlock_init(rwlock, NULL))) {
        ERR(NULL, "%s: failed to init rwlock (%s).", __func__, strerror(rc));
    }

    return rc;
#endif
}

API int
nc_server_init(void)
{
#ifdef NC_ENABLED_SSH_TLS
    int r;
#endif /* NC_ENABLED_SSH_TLS */

    ATOMIC_STORE_RELAXED(server_opts.new_session_id, 1);

    if (nc_server_init_rwlock(&server_opts.config_lock)) {
        goto error;
    }

    if (nc_server_init_rwlock(&server_opts.opts_lock)) {
        goto error;
    }

    /* allocate the initial empty configuration generation, its reference belongs to server_opts.config */
    server_opts.config = calloc(1, sizeof *server_opts.config);
    if (!server_opts.config) {
        ERRMEM;
        goto error;
    }
    ATOMIC_STORE_RELAXED(server_opts.config->refcount, 1);
    ATOMIC_STORE_RELAXED(server_opts.idle_timeout, 0);

#ifdef NC_ENABLED_SSH_TLS
    if (curl_global_init(CURL_GLOBAL_SSL | CURL_GLOBAL_ACK_EINTR)) {
        ERR(NULL, "%s: failed to init CURL.", __func__);
        goto error;
    }

    if (nc_tls_backend_init_wrap()) {
        ERR(NULL, "%s: failed to init the SSL library backend.", __func__);
        goto error;
    }

    /* optional for dynamic library, mandatory for static */
    if (ssh_init()) {
        ERR(NULL, "%s: failed to init libssh.", __func__);
        goto error;
    }

    if ((r = pthread_mutex_init(&server_opts.cert_exp_notif.lock, NULL))) {
        ERR(NULL, "%s: failed to init certificate expiration notification thread lock(%s).", __func__, strerror(r));
        goto error;
    }
    if ((r = pthread_cond_init(&server_opts.cert_exp_notif.cond, NULL))) {
        ERR(NULL, "%s: failed to init certificate expiration notification thread condition(%s).", __func__, strerror(r));
        goto error;
    }

    /* try to open the keylog file for writing TLS secrets */
    nc_server_keylog_file_open();
#endif /* NC_ENABLED_SSH_TLS */

    return 0;

error:
    /* the server is not initialized, do not leave a configuration generation behind */
    nc_server_config_release(server_opts.config);
    server_opts.config = NULL;
    ATOMIC_STORE_RELAXED(server_opts.new_session_id, 0);
    return -1;
}

API int
nc_server_destroy(void)
{
    int rc = 0;
    int config_update_locked = 0, opts_locked = 0;
    struct nc_server_config *config;
    uint32_t i;

#ifdef NC_ENABLED_SSH_TLS
    void *interactive_auth_data;

    void (*interactive_auth_data_free)(void *data);
#endif /* NC_ENABLED_SSH_TLS */

    for (i = 0; i < server_opts.capabilities_count; i++) {
        free(server_opts.capabilities[i]);
    }
    free(server_opts.capabilities);
    server_opts.capabilities = NULL;
    server_opts.capabilities_count = 0;
    if (server_opts.content_id_data && server_opts.content_id_data_free) {
        server_opts.content_id_data_free(server_opts.content_id_data);
    }
    server_opts.content_id_data = NULL;
    server_opts.content_id_data_free = NULL;

#ifdef NC_ENABLED_SSH_TLS
    /* destroy the certificate expiration notification thread */
    if ((rc = nc_server_notif_cert_expiration_thread_stop(1))) {
        ERR(NULL, "%s: failed to stop certificate expiration notification thread.", __func__);
        goto cleanup;
    }
#endif /* NC_ENABLED_SSH_TLS */

    /* CONFIG UPDATE LOCK - the same timeout as the appliers use, destroying the server must not
     * fail just because a legitimate configuration apply is in progress */
    if (nc_mutex_lock(&server_opts.config_update_lock, NC_CONFIG_UPDATE_LOCK_TIMEOUT, __func__) != 1) {
        rc = 1;
        goto cleanup;
    }
    config_update_locked = 1;

#ifdef NC_ENABLED_SSH_TLS
    /* stop all dispatched CH threads, no configuration lock may be held while joining them */
    if ((rc = nc_server_ch_threads_destroy())) {
        goto cleanup;
    }
#endif /* NC_ENABLED_SSH_TLS */

    /* stop listening on all the registered sockets */
    nc_server_binds_destroy();

    /* OPTS WRITE LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_WRITE, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        rc = 1;
        goto cleanup;
    }
    opts_locked = 1;

#ifdef NC_ENABLED_SSH_TLS
    free(server_opts.authkey_path_fmt);
    server_opts.authkey_path_fmt = NULL;
    free(server_opts.pam_config_name);
    server_opts.pam_config_name = NULL;
    free(server_opts.ssh_protocol_string);
    server_opts.ssh_protocol_string = NULL;
    server_opts.interactive_auth_clb = NULL;
    interactive_auth_data = server_opts.interactive_auth_data;
    interactive_auth_data_free = server_opts.interactive_auth_data_free;
    server_opts.interactive_auth_data = NULL;
    server_opts.interactive_auth_data_free = NULL;
    server_opts.user_verify_clb = NULL;

    /* Call Home dispatch data, its callback data does not have to be valid once the server is destroyed */
    memset(&server_opts.ch_dispatch_data, 0, sizeof server_opts.ch_dispatch_data);
#endif /* NC_ENABLED_SSH_TLS */

    /* hidden UNIX socket paths */
    LY_ARRAY_FOR(server_opts.unix_paths, i) {
        free(server_opts.unix_paths[i].endpt_name);
        free(server_opts.unix_paths[i].path);
    }
    LY_ARRAY_FREE(server_opts.unix_paths);
    server_opts.unix_paths = NULL;
    free(server_opts.unix_socket_dir);
    server_opts.unix_socket_dir = NULL;

    /* OPTS WRITE UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
    opts_locked = 0;

#ifdef NC_ENABLED_SSH_TLS
    /* free the user data only once the lock is released, the callback may call back into the library */
    if (interactive_auth_data && interactive_auth_data_free) {
        interactive_auth_data_free(interactive_auth_data);
    }
#endif /* NC_ENABLED_SSH_TLS */

    /* CONFIG WR LOCK - unpublish the configuration, a concurrent acquire must not see a stale pointer */
    if (nc_rwlock_lock(&server_opts.config_lock, NC_RWLOCK_WRITE, NC_CONFIG_LOCK_TIMEOUT, __func__) != 1) {
        rc = 1;
        goto cleanup;
    }
    config = server_opts.config;
    server_opts.config = NULL;
    ATOMIC_STORE_RELAXED(server_opts.idle_timeout, 0);

    /* CONFIG UNLOCK */
    nc_rwlock_unlock(&server_opts.config_lock, __func__);

    /* the configuration is destroyed once its last reader releases it */
    nc_server_config_release(config);

#ifdef NC_ENABLED_SSH_TLS
    curl_global_cleanup();
    nc_tls_backend_destroy_wrap();
    ssh_finalize();

    /* close the TLS keylog file */
    if (server_opts.tls_keylog_file) {
        fclose(server_opts.tls_keylog_file);
        server_opts.tls_keylog_file = NULL;
    }
#endif /* NC_ENABLED_SSH_TLS */

cleanup:
    if (opts_locked) {
        nc_rwlock_unlock(&server_opts.opts_lock, __func__);
    }
    if (config_update_locked) {
        nc_mutex_unlock(&server_opts.config_update_lock, __func__);
    }
    return rc;
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

    /* HELLO LOCK */
    if (nc_rwlock_lock(&server_opts.hello_lock, NC_RWLOCK_WRITE, NC_HELLO_LOCK_TIMEOUT, __func__) != 1) {
        return -1;
    }

    server_opts.wd_basic_mode = basic_mode;
    server_opts.wd_also_supported = also_supported;

    /* HELLO UNLOCK */
    nc_rwlock_unlock(&server_opts.hello_lock, __func__);

    return 0;
}

API void
nc_server_get_capab_withdefaults(NC_WD_MODE *basic_mode, int *also_supported)
{
    if (!basic_mode && !also_supported) {
        ERRARG(NULL, "basic_mode and also_supported");
        return;
    }

    /* HELLO LOCK, nothing to do on failure */
    nc_rwlock_lock(&server_opts.hello_lock, NC_RWLOCK_WRITE, NC_HELLO_LOCK_TIMEOUT, __func__);

    if (basic_mode) {
        *basic_mode = server_opts.wd_basic_mode;
    }
    if (also_supported) {
        *also_supported = server_opts.wd_also_supported;
    }

    /* HELLO UNLOCK */
    nc_rwlock_unlock(&server_opts.hello_lock, __func__);
}

API int
nc_server_set_capability(const char *value)
{
    int rc = 0;
    void *mem;

    if (!value || !value[0]) {
        ERRARG(NULL, "value must not be empty");
        return -1;
    }

    /* HELLO LOCK */
    if (nc_rwlock_lock(&server_opts.hello_lock, NC_RWLOCK_WRITE, NC_HELLO_LOCK_TIMEOUT, __func__) != 1) {
        return -1;
    }

    mem = realloc(server_opts.capabilities, (server_opts.capabilities_count + 1) * sizeof *server_opts.capabilities);
    NC_CHECK_ERRMEM_GOTO(!mem, rc = -1, cleanup);

    server_opts.capabilities = mem;

    server_opts.capabilities[server_opts.capabilities_count] = strdup(value);
    server_opts.capabilities_count++;

cleanup:
    /* HELLO UNLOCK */
    nc_rwlock_unlock(&server_opts.hello_lock, __func__);
    return rc;
}

API void
nc_server_set_content_id_clb(char *(*content_id_clb)(void *user_data), void *user_data,
        void (*free_user_data)(void *user_data))
{
    /* HELLO LOCK, nothing to do on failure */
    nc_rwlock_lock(&server_opts.hello_lock, NC_RWLOCK_WRITE, NC_HELLO_LOCK_TIMEOUT, __func__);

    server_opts.content_id_clb = content_id_clb;
    server_opts.content_id_data = user_data;
    server_opts.content_id_data_free = free_user_data;

    /* HELLO UNLOCK */
    nc_rwlock_unlock(&server_opts.hello_lock, __func__);
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
    NC_SESSION_STATUS_SET(*session, NC_STATUS_STARTING);

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

    NC_SESSION_STATUS_SET(*session, NC_STATUS_RUNNING);

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
    int r, rc = 0;
    struct timespec ts;

    /* LOCK */
    if (nc_mutex_lock(&ps->lock, NC_PS_LOCK_TIMEOUT, func) != 1) {
        return -1;
    }

    /* check that the queue is long enough */
    if (ps->queue_len == NC_PS_QUEUE_SIZE) {
        ERR(NULL, "%s: pollsession queue size (%d) too small.", func, NC_PS_QUEUE_SIZE);
        nc_mutex_unlock(&ps->lock, func);
        return -1;
    }

    /* add ourselves into the queue */
    nc_ps_queue_add_id(ps, id);
    DBL(NULL, "PS 0x%p TID %lu queue: added %u, head %u, length %u", ps, (long unsigned int)pthread_self(), *id,
            ps->queue[ps->queue_begin], ps->queue_len);

    /* is it our turn? */
    while (ps->queue[ps->queue_begin] != *id) {
        nc_timeouttime_get(&ts, NC_PS_QUEUE_TIMEOUT);

        r = pthread_cond_clockwait(&ps->cond, &ps->lock, COMPAT_CLOCK_ID, &ts);
        if (r) {
            /**
             * This may happen when another thread releases the lock and broadcasts the condition
             * and this thread had already timed out. When this thread is scheduled, it returns timed out error
             * but when actually this thread was ready for condition.
             */
            if ((ETIMEDOUT == r) && (ps->queue[ps->queue_begin] == *id)) {
                break;
            }

            ERR(NULL, "%s: failed to wait for a pollsession condition (%s).", func, strerror(r));
            /* remove ourselves from the queue */
            nc_ps_queue_remove_id(ps, *id);
            rc = -1;
            break;
        }
    }

    /* UNLOCK */
    nc_mutex_unlock(&ps->lock, func);

    return rc;
}

int
nc_ps_unlock(struct nc_pollsession *ps, uint8_t id, const char *func)
{
    int r;

    /* LOCK, continue on error */
    r = nc_mutex_lock(&ps->lock, NC_PS_LOCK_TIMEOUT, func);

    /* we must be the first, it was our turn after all, right? */
    if (ps->queue[ps->queue_begin] != id) {
        ERRINT;
        /* UNLOCK */
        if (r == 1) {
            nc_mutex_unlock(&ps->lock, func);
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
    if (r == 1) {
        nc_mutex_unlock(&ps->lock, func);
    }

    return r == 1 ? 0 : -1;
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
    if (!envp && (session->version != NC_PROT_VERSION_11)) {
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
    struct ly_in *msg = NULL;
    struct nc_server_reply *reply = NULL;
    char *buf = NULL;
    uint32_t buf_len = 0;
    int r, ret = 0;

    NC_CHECK_ARG_RET(session, session, rpc, NC_PSPOLL_ERROR);

    if ((NC_SESSION_STATUS_GET(session) != NC_STATUS_RUNNING) || (session->side != NC_SERVER)) {
        ERR(session, "Invalid session to receive RPCs.");
        return NC_PSPOLL_ERROR;
    }

    *rpc = NULL;

    /* get a message */
    r = nc_read_msg_io(session, io_timeout, 0, &buf, &buf_len);
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

    /* create input */
    if (ly_in_new_memory(buf, &msg)) {
        free(buf);
        return NC_PSPOLL_ERROR;
    }

    *rpc = calloc(1, sizeof **rpc);
    NC_CHECK_ERRMEM_GOTO(!*rpc, ret = NC_PSPOLL_ERROR, cleanup);

    /* parse the RPC */
    if (!lyd_parse_op(session->ctx, NULL, msg, LYD_XML, LYD_TYPE_RPC_NETCONF, LYD_PARSE_STRICT, &(*rpc)->envp,
            &(*rpc)->rpc)) {
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
            if (NC_SESSION_STATUS_GET(session) != NC_STATUS_INVALID) {
                NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
                NC_SESSION_TERM_REASON_SET(session, NC_SESSION_TERM_OTHER);
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
 * @brief Send a reply to an RPC.
 *
 * The session IO lock is acquired internally, the caller must not hold it. The caller must,
 * however, hold the session RPC lock.
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
    void *priv_ptr;
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

    priv_ptr = ATOMIC_PTR_LOAD_RELAXED(rpc_act->priv);
    if (!priv_ptr) {
        if (!global_rpc_clb) {
            /* no callback, reply with a not-implemented error */
            reply = nc_server_reply_err(nc_err(session->ctx, NC_ERR_OP_NOT_SUPPORTED, NC_ERR_TYPE_PROT));
        } else {
            reply = global_rpc_clb(rpc->rpc, session);
        }
    } else {
        clb = (nc_rpc_clb)priv_ptr;
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
    if ((NC_SESSION_STATUS_GET(session) == NC_STATUS_RUNNING) && (NC_SESSION_TERM_REASON_GET(session) != NC_SESSION_TERM_NONE)) {
        NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
    }

    return ret;
}

#ifdef NC_ENABLED_SSH_TLS
/**
 * @brief Scan the session ring for a newly established NETCONF SSH channel.
 *
 * @param[in] session Session whose SSH channel ring to scan.
 * @return 1 if a new SSH channel is found, 0 otherwise.
 */
static int
nc_ps_ssh_find_new_channel(struct nc_session *session)
{
    struct nc_session *new;

    if (!session->ti.libssh.next) {
        return 0;
    }

    for (new = session->ti.libssh.next; new != session; new = new->ti.libssh.next) {
        if ((NC_SESSION_STATUS_GET(new) == NC_STATUS_STARTING) && new->ti.libssh.channel &&
                (new->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
            return 1;
        }
    }

    return 0;
}

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Poll a session from pspoll.
 *
 * The session IO lock is acquired internally, the caller must not hold it. The caller must,
 * however, hold the session RPC lock and the session must be running.
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
    uint16_t idle_timeout;

#ifdef NC_ENABLED_SSH_TLS
#if !LIBSSH_0_12
    ssh_message ssh_msg;
#endif
#endif /* NC_ENABLED_SSH_TLS */

    /* check timeout first, read the mirror so that the poll path needs no configuration at all */
    idle_timeout = (uint16_t)ATOMIC_LOAD_RELAXED(server_opts.idle_timeout);
    if (!(session->flags & NC_SESSION_CALLHOME) && !nc_session_get_notif_status(session) && idle_timeout &&
            (now_mono >= session->opts.server.last_rpc + idle_timeout)) {
        sprintf(msg, "Session idle timeout elapsed");
        NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
        NC_SESSION_TERM_REASON_SET(session, NC_SESSION_TERM_TIMEOUT);
        return NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
    }

    r = nc_mutex_lock(session->io_lock, io_timeout, __func__);
    if (r < 0) {
        return NC_PSPOLL_ERROR;
    } else if (!r) {
        return NC_PSPOLL_TIMEOUT;
    }

    switch (session->ti_type) {
#ifdef NC_ENABLED_SSH_TLS
    case NC_TI_SSH:
#if LIBSSH_0_12
        if (nc_ps_ssh_find_new_channel(session)) {
            ret = NC_PSPOLL_SSH_CHANNEL;
            break;
        }
#else
        ssh_msg = ssh_message_get(session->ti.libssh.session);
        if (ssh_msg) {
            if (nc_session_ssh_msg(session, NULL, ssh_msg, NULL)) {
                ssh_message_reply_default(ssh_msg);
            }
            if (nc_ps_ssh_find_new_channel(session)) {
                ret = NC_PSPOLL_SSH_CHANNEL;
                ssh_message_free(ssh_msg);
                break;
            }
            if (!ret) {
                /* just some SSH message */
                ret = NC_PSPOLL_SSH_MSG;
            }
            ssh_message_free(ssh_msg);
            /* break because 1) we don't want to return anything here ORred with NC_PSPOLL_RPC
             * and 2) we don't want to delay opening a new channel by waiting for a RPC to get processed
             */
            break;
        }
#endif

        r = ssh_channel_poll_timeout(session->ti.libssh.channel, 0, 0);
        if (r == SSH_EOF) {
            sprintf(msg, "SSH channel unexpected EOF");
            NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
            NC_SESSION_TERM_REASON_SET(session, NC_SESSION_TERM_DROPPED);
            ret = NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
        } else if (r == SSH_ERROR) {
            sprintf(msg, "SSH channel poll error (%s)", ssh_get_error(session->ti.libssh.session));
            NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
            NC_SESSION_TERM_REASON_SET(session, NC_SESSION_TERM_OTHER);
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
                NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
                ret = NC_PSPOLL_ERROR;
            } else if (r > 0) {
                if (pfd.revents & (POLLHUP | POLLNVAL)) {
                    sprintf(msg, "Communication socket unexpectedly closed");
                    NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
                    NC_SESSION_TERM_REASON_SET(session, NC_SESSION_TERM_DROPPED);
                    ret = NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
                } else if (pfd.revents & POLLERR) {
                    sprintf(msg, "Communication socket error");
                    NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
                    NC_SESSION_TERM_REASON_SET(session, NC_SESSION_TERM_OTHER);
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
            NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
            ret = NC_PSPOLL_ERROR;
        } else if (r > 0) {
            if (pfd.revents & (POLLHUP | POLLNVAL)) {
                sprintf(msg, "Communication socket unexpectedly closed");
                NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
                NC_SESSION_TERM_REASON_SET(session, NC_SESSION_TERM_DROPPED);
                ret = NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
            } else if (pfd.revents & POLLERR) {
                sprintf(msg, "Communication socket error");
                NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
                NC_SESSION_TERM_REASON_SET(session, NC_SESSION_TERM_OTHER);
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

    nc_mutex_unlock(session->io_lock, __func__);
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
        if (NC_SESSION_STATUS_GET(ps_session->session) == NC_STATUS_RUNNING) {
            /* session is fine, work with it, no configuration is accessed */
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
            if (NC_SESSION_TERM_REASON_GET(ps_session->session) != NC_SESSION_TERM_CLOSED) {
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
            /* error, do not send a reply */
            if (NC_SESSION_STATUS_GET(cur_session) != NC_STATUS_RUNNING) {
                ret |= NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
                cur_ps_session->state = NC_PS_STATE_INVALID;
            } else {
                cur_ps_session->state = NC_PS_STATE_NONE;
            }
        } else if (ret & NC_PSPOLL_REPLY_ERROR) {
            /* error reply has been sent */
            cur_ps_session->state = NC_PS_STATE_NONE;
        } else {
            cur_session->opts.server.last_rpc = ts_cur.tv_sec;

            /* process RPC and send a reply */
            ret |= nc_server_send_reply_io(cur_session, timeout, rpc);
            if (NC_SESSION_STATUS_GET(cur_session) != NC_STATUS_RUNNING) {
                ret |= NC_PSPOLL_SESSION_TERM;
                if ((NC_SESSION_TERM_REASON_GET(cur_session) != NC_SESSION_TERM_CLOSED) &&
                        (NC_SESSION_TERM_REASON_GET(cur_session) != NC_SESSION_TERM_KILLED)) {
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
            if (NC_SESSION_STATUS_GET(ps->sessions[i]->session) != NC_STATUS_RUNNING) {
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

/**
 * @brief Start listening on a socket of an endpoint bind.
 *
 * @param[in] endpt Endpoint the bind belongs to.
 * @param[in] address Address to listen on, the full socket path for a UNIX endpoint.
 * @param[in] port Port to listen on, 0 for a UNIX endpoint.
 * @param[out] sock Created listening socket.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_bind_and_listen(const struct nc_endpt *endpt, const char *address, uint16_t port, int *sock)
{
#ifndef NC_ENABLED_SSH_TLS
    /* only UNIX endpoints exist, which have no port */
    (void)port;
#endif

    *sock = -1;

    switch (endpt->ti) {
    case NC_TI_UNIX:
        *sock = nc_sock_listen_unix(address, endpt->opts.unix);
        NC_CHECK_RET(*sock == -1, 1);
        VRB(NULL, "Listening on %s for UNIX connections.", address);
        break;
#ifdef NC_ENABLED_SSH_TLS
    case NC_TI_SSH:
        *sock = nc_sock_listen_inet(address, port);
        NC_CHECK_RET(*sock == -1, 1);
        VRB(NULL, "Listening on %s:%" PRIu16 " for SSH connections.", address, port);
        break;
    case NC_TI_TLS:
        *sock = nc_sock_listen_inet(address, port);
        NC_CHECK_RET(*sock == -1, 1);
        VRB(NULL, "Listening on %s:%" PRIu16 " for TLS connections.", address, port);
        break;
#endif /* NC_ENABLED_SSH_TLS */
    default:
        ERRINT;
        return 1;
    }

    return 0;
}

/**
 * @brief Stop listening on a socket that was opened for a bind description.
 *
 * @param[in,out] desc Bind description to close the socket of, no-op if it has none.
 */
static void
nc_server_bind_desc_close(struct nc_bind_desc *desc)
{
    if (desc->sock == -1) {
        return;
    }

    close(desc->sock);
    desc->sock = -1;
    if (desc->endpt->ti == NC_TI_UNIX) {
        /* remove the socket file we have just created */
        unlink(desc->address);
    }
}

/**
 * @brief Stop listening on a registered socket and free the registry entry members.
 *
 * @note The bind registry lock must be held.
 *
 * @param[in] entry Bind registry entry to close.
 */
static void
nc_server_bind_entry_close(struct nc_bind_entry *entry)
{
    close(entry->sock);
    if (entry->ti == NC_TI_UNIX) {
        /* remove the socket file */
        unlink(entry->address);
        VRB(NULL, "Stopped listening on %s.", entry->address);
    } else {
        VRB(NULL, "Stopped listening on %s:%" PRIu16 ".", entry->address, entry->port);
    }

    free(entry->endpt_name);
    free(entry->address);
}

/**
 * @brief Check whether a bind registry entry refers to the same listening socket as a bind description.
 *
 * @param[in] entry Bind registry entry.
 * @param[in] desc Bind description.
 * @return 1 if they match, 0 otherwise.
 */
static int
nc_server_bind_entry_matches(const struct nc_bind_entry *entry, const struct nc_bind_desc *desc)
{
    return (entry->ti == desc->endpt->ti) && (entry->port == desc->port) && !strcmp(entry->address, desc->address);
}

/**
 * @brief Collect the listening sockets required by a server configuration.
 *
 * @param[in] config Server configuration.
 * @param[out] descs Bind descriptions (sized-array, see libyang docs).
 * @return 0 on success, 1 on error.
 */
static int
nc_server_bind_descs_get(const struct nc_server_config *config, struct nc_bind_desc **descs)
{
    int rc = 0;
    const struct nc_endpt *endpt;
    const struct nc_bind *bind;
    struct nc_bind_desc *desc;
    LY_ARRAY_COUNT_TYPE u, v;
    uint32_t count = 0;

    *descs = NULL;

    LY_ARRAY_FOR(config->endpts, u) {
        count += LY_ARRAY_COUNT(config->endpts[u].binds);
    }
    if (!count) {
        return 0;
    }
    LY_ARRAY_CREATE_GOTO(NULL, *descs, count, rc, cleanup);

    LY_ARRAY_FOR(config->endpts, u) {
        endpt = &config->endpts[u];

        LY_ARRAY_FOR(endpt->binds, v) {
            bind = &endpt->binds[v];

            desc = &(*descs)[LY_ARRAY_COUNT(*descs)];
            desc->endpt = endpt;
            desc->port = bind->port;
            desc->sock = -1;

            if (endpt->ti == NC_TI_UNIX) {
                /* the socket path is not stored in the bind, resolve it */
                desc->address = nc_server_unix_get_socket_path(endpt);
                NC_CHECK_ERR_GOTO(!desc->address, rc = 1, cleanup);
            } else {
                assert(bind->address && bind->port);
                desc->address = strdup(bind->address);
                NC_CHECK_ERRMEM_GOTO(!desc->address, rc = 1, cleanup);
            }

            LY_ARRAY_INCREMENT(*descs);
        }
    }

cleanup:
    return rc ? 1 : 0;
}

/**
 * @brief Free bind descriptions and close all the sockets they still own.
 *
 * @param[in] descs Bind descriptions to free.
 */
static void
nc_server_bind_descs_free(struct nc_bind_desc *descs)
{
    LY_ARRAY_COUNT_TYPE u;

    LY_ARRAY_FOR(descs, u) {
        nc_server_bind_desc_close(&descs[u]);
        free(descs[u].address);
        free(descs[u].rename);
    }
    LY_ARRAY_FREE(descs);
}

int
nc_server_binds_reconcile(const struct nc_server_config *config)
{
    int rc = 0, binds_locked = 0, found;
    struct nc_bind_desc *descs = NULL;
    struct nc_bind_entry *entry;
    char *endpt_name, *address;
    LY_ARRAY_COUNT_TYPE u, v, added = 0;
    uint32_t new_count = 0;

    /* collect all the listening sockets the configuration requires, no lock is needed for that */
    NC_CHECK_GOTO(rc = nc_server_bind_descs_get(config, &descs), cleanup);

    /* BINDS LOCK */
    if (nc_mutex_lock(&server_opts.binds_lock, NC_BINDS_LOCK_TIMEOUT, __func__) != 1) {
        rc = 1;
        goto cleanup;
    }
    binds_locked = 1;

    /* keep listening on the sockets that are already registered */
    LY_ARRAY_FOR(descs, u) {
        LY_ARRAY_FOR(server_opts.binds, v) {
            if (!nc_server_bind_entry_matches(&server_opts.binds[v], &descs[u])) {
                continue;
            }

            descs[u].reused = 1;
            descs[u].entry_idx = v;

            /* the socket stays open, but the endpoint owning it may have been renamed, prepare the
             * new name and store it only once nothing can fail anymore */
            if (strcmp(server_opts.binds[v].endpt_name, descs[u].endpt->name)) {
                descs[u].rename = strdup(descs[u].endpt->name);
                NC_CHECK_ERRMEM_GOTO(!descs[u].rename, rc = 1, cleanup);
            }
            break;
        }

        if (!descs[u].reused) {
            ++new_count;
        }
    }

    /* BINDS UNLOCK - creating the sockets may take a while */
    nc_mutex_unlock(&server_opts.binds_lock, __func__);
    binds_locked = 0;

    /* start listening on the sockets that are not registered yet */
    LY_ARRAY_FOR(descs, u) {
        if (descs[u].reused) {
            continue;
        }

        NC_CHECK_GOTO(rc = nc_server_bind_and_listen(descs[u].endpt, descs[u].address, descs[u].port,
                &descs[u].sock), cleanup);
    }

    /* BINDS LOCK */
    if (nc_mutex_lock(&server_opts.binds_lock, NC_BINDS_LOCK_TIMEOUT, __func__) != 1) {
        rc = 1;
        goto cleanup;
    }
    binds_locked = 1;

    /* register the new sockets, reserve the space in advance */
    if (new_count) {
        LY_ARRAY_CREATE_GOTO(NULL, server_opts.binds, new_count, rc, cleanup);
    }
    LY_ARRAY_FOR(descs, u) {
        if (descs[u].reused) {
            continue;
        }

        endpt_name = strdup(descs[u].endpt->name);
        NC_CHECK_ERRMEM_GOTO(!endpt_name, rc = 1, cleanup);
        address = strdup(descs[u].address);
        NC_CHECK_ERRMEM_GOTO(!address, free(endpt_name); rc = 1, cleanup);

        entry = &server_opts.binds[LY_ARRAY_COUNT(server_opts.binds)];
        entry->endpt_name = endpt_name;
        entry->address = address;
        entry->port = descs[u].port;
        entry->ti = descs[u].endpt->ti;
        entry->sock = descs[u].sock;

        /* the socket now belongs to the registry */
        descs[u].sock = -1;
        LY_ARRAY_INCREMENT(server_opts.binds);
        ++added;
    }

    /* the registry entries did not move, so store the new endpoint names now that nothing can fail */
    LY_ARRAY_FOR(descs, u) {
        if (!descs[u].rename) {
            continue;
        }

        entry = &server_opts.binds[descs[u].entry_idx];
        free(entry->endpt_name);
        entry->endpt_name = descs[u].rename;
        descs[u].rename = NULL;
    }

    /* stop listening on the sockets the configuration no longer contains */
    v = 0;
    while (v < LY_ARRAY_COUNT(server_opts.binds)) {
        found = 0;
        LY_ARRAY_FOR(descs, u) {
            if (nc_server_bind_entry_matches(&server_opts.binds[v], &descs[u])) {
                found = 1;
                break;
            }
        }
        if (found) {
            ++v;
            continue;
        }

        nc_server_bind_entry_close(&server_opts.binds[v]);

        /* swap the last entry into the hole, the order of the registry is irrelevant */
        server_opts.binds[v] = server_opts.binds[LY_ARRAY_COUNT(server_opts.binds) - 1];
        LY_ARRAY_DECREMENT_FREE(server_opts.binds);
    }

cleanup:
    if (rc) {
        /* unregister the sockets we have just registered, they are always the last ones */
        while (added) {
            entry = &server_opts.binds[LY_ARRAY_COUNT(server_opts.binds) - 1];
            nc_server_bind_entry_close(entry);
            LY_ARRAY_DECREMENT_FREE(server_opts.binds);
            --added;
        }
    }
    if (binds_locked) {
        /* BINDS UNLOCK */
        nc_mutex_unlock(&server_opts.binds_lock, __func__);
    }
    nc_server_bind_descs_free(descs);
    return rc ? 1 : 0;
}

void
nc_server_binds_destroy(void)
{
    LY_ARRAY_COUNT_TYPE u;

    /* BINDS LOCK */
    if (nc_mutex_lock(&server_opts.binds_lock, NC_BINDS_LOCK_TIMEOUT, __func__) != 1) {
        return;
    }

    LY_ARRAY_FOR(server_opts.binds, u) {
        nc_server_bind_entry_close(&server_opts.binds[u]);
    }
    LY_ARRAY_FREE(server_opts.binds);
    server_opts.binds = NULL;

    /* BINDS UNLOCK */
    nc_mutex_unlock(&server_opts.binds_lock, __func__);
}

/**
 * @brief Read the NETCONF user of a UNIX transport session.
 *
 * @param[in] session NETCONF session for logging.
 * @param[in] sock Socket to read from.
 * @param[out] username Read NETCONF username.
 * @return 1 on success, 0 on timeout, -1 on error.
 */
static int
nc_accept_unix_read_username(struct nc_session *session, int sock, char **username)
{
    struct timespec ts_timeout;
    size_t size = 32, rr = 0;
    ssize_t r;

    assert(sock > -1);

    /* fill timespec */
    nc_timeouttime_get(&ts_timeout, NC_TRANSPORT_MSG_TIMEOUT);

    /* prepare username */
    *username = malloc(size);
    NC_CHECK_ERRMEM_RET(!*username, -1);

    while (1) {
        /* realloc as needed */
        if (size == rr) {
            size *= 2;
            *username = nc_realloc(*username, size);
            NC_CHECK_ERRMEM_RET(!*username, -1);
        }

        /* read */
        r = read(sock, *username + rr, 1);
        if ((r < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))) {
            /* ignore */
            r = 0;
        }
        if (r < 0) {
            ERR(session, "Failed to read NETCONF username from UNIX session (%s).", strerror(errno));
            return -1;
        }

        if (!r) {
            /* sleep */
            usleep(NC_TIMEOUT_STEP);

            if (nc_timeouttime_cur_diff(&ts_timeout) < 1) {
                /* final timeout */
                ERR(session, "Failed to read NETCONF username from a UNIX session for too long, disconnecting.");
                return 0;
            }
        } else {
            if ((*username)[rr] == '\0') {
                /* whole username read */
                break;
            }

            rr += r;
        }
    }

    return 1;
}

/**
 * @brief Authenticate the requested username against the configured mappings.
 *
 * @param[in] session NETCONF session.
 * @param[in] effective_uname Effective system username of the connected peer.
 * @param[in] requested_uname Requested NETCONF username.
 * @return 0 if the requested username can be used, 1 otherwise.
 */
static int
nc_accept_unix_auth_username(struct nc_session *session, const char *effective_uname,
        const char *requested_uname)
{
    int match = 0;
    struct nc_server_unix_opts *opts = session->data;
    LY_ARRAY_COUNT_TYPE i, j;

    /* try to find a mapping entry for this system user */
    LY_ARRAY_FOR(opts->user_mappings, i) {
        if (!strcmp(opts->user_mappings[i].system_user, effective_uname)) {
            break;
        }
    }
    if (i == LY_ARRAY_COUNT(opts->user_mappings)) {
        /* matching entry not found, the user can only authenticate if its
         * requested username is the same as the effective one */
        if (strcmp(effective_uname, requested_uname)) {
            /* fail */
            return 1;
        }
    } else {
        /* found a mapping entry, check if the requested username is allowed for this system user */
        LY_ARRAY_FOR(opts->user_mappings[i].allowed_users, j) {
            if (!strcmp(opts->user_mappings[i].allowed_users[j], "*")) {
                /* special case, the user can authenticate as any username */
                match = 1;
                break;
            } else if (!strcmp(opts->user_mappings[i].allowed_users[j], requested_uname)) {
                /* match */
                match = 1;
                break;
            }
        }

        if (!match) {
            /* fail */
            return 1;
        }
    }

    /* the user can use the requested username */
    return 0;
}

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
    struct passwd *pw, pw_buf;
    char *requested_username = NULL, *buf = NULL;
    const char *pwname;
    uid_t uid = 0;
    size_t buf_len = 0;

    /* get UID of the connected peer on the socket */
    if (unsock_get_uid(sock, &uid)) {
        ERR(session, "Failed to get UID of a socket (%s).", strerror(errno));
        goto error;
    }

    /* get the connected process system user from the UID */
    pw = nc_getpw(uid, NULL, &pw_buf, &buf, &buf_len);
    if (!pw) {
        ERR(session, "Failed to find username for UID %u (%s).", uid, strerror(errno));
        goto error;
    }
    pwname = pw->pw_name;

    /* read the NETCONF username */
    if (nc_accept_unix_read_username(session, sock, &requested_username) != 1) {
        goto error;
    }

    NC_CHECK_ERR_GOTO(!requested_username || !*requested_username,
            ERR(session, "Empty username requested by a UNIX client \"%s\", "
            "but a valid NETCONF username is required, disconnecting.", pwname), error);

    /* authenticate the requested username against configured mappings, if its ok the user can directly use it */
    if (nc_accept_unix_auth_username(session, pwname, requested_username)) {
        ERR(session, "UNIX system user \"%s\" tried to authenticate as invalid user \"%s\", disconnecting.",
                pwname, requested_username);
        goto error;
    }

    VRB(session, "User \"%s\" authenticated (UNIX socket system user \"%s\").", requested_username, pwname);

    /* fill session */
    session->username = requested_username;
    session->ti_type = NC_TI_UNIX;
    session->ti.unixsock.sock = sock;

    free(buf);
    return 1;

error:
    close(sock);
    free(requested_username);
    free(buf);
    return -1;
}

API uint32_t
nc_server_endpt_count(void)
{
    const struct nc_server_config *config;
    uint32_t cnt;

    config = nc_server_config_acquire();
    if (!config) {
        return 0;
    }

    cnt = LY_ARRAY_COUNT(config->endpts);

    nc_server_config_release(config);
    return cnt;
}

API NC_MSG_TYPE
nc_accept(int timeout, const struct ly_ctx *ctx, struct nc_session **session)
{
    NC_MSG_TYPE msgtype;
    int sock = -1, ret;
    char *host = NULL;
    uint16_t port = 0;
    struct timespec ts_cur;
    LY_ARRAY_COUNT_TYPE endpt_idx;
    const struct nc_server_config *config;

    NC_CHECK_ARG_RET(NULL, ctx, session, NC_MSG_ERROR);

    NC_CHECK_SRV_INIT_RET(NC_MSG_ERROR);

    *session = NULL;

    /* init ctx as needed */
    nc_server_init_cb_ctx(ctx);

    /* pin the configuration for the whole accept, no lock is held for any of it */
    config = nc_server_config_acquire();
    if (!config) {
        return NC_MSG_ERROR;
    }

    if (!config->endpts) {
        ERR(NULL, "No endpoints to accept sessions on.");
        msgtype = NC_MSG_ERROR;
        goto cleanup;
    }

    /* try to accept a new connection on any of the listening endpoints */
    ret = nc_server_accept_binds(config, timeout, &host, &port, &endpt_idx, &sock);
    if (ret < 0) {
        msgtype = NC_MSG_ERROR;
        goto cleanup;
    } else if (!ret) {
        /* timeout, no connection established */
        msgtype = NC_MSG_WOULDBLOCK;
        goto cleanup;
    }

    /* configure keepalives */
    if (nc_sock_configure_ka(sock, &config->endpts[endpt_idx].ka)) {
        msgtype = NC_MSG_ERROR;
        goto cleanup;
    }

    *session = nc_new_session(NC_SERVER, 0);
    NC_CHECK_ERRMEM_GOTO(!(*session), msgtype = NC_MSG_ERROR, cleanup);
    NC_SESSION_STATUS_SET(*session, NC_STATUS_STARTING);
    (*session)->ctx = (struct ly_ctx *)ctx;
    (*session)->flags = NC_SESSION_SHAREDCTX;
    (*session)->host = host;
    host = NULL;
    (*session)->port = port;

    /* pin the configuration for the duration of the transport handshake, it is a borrowed pointer */
    (*session)->opts.server.config = config;

    /* sock gets assigned to session or closed */
#ifdef NC_ENABLED_SSH_TLS
    if (config->endpts[endpt_idx].ti == NC_TI_SSH) {
        ret = nc_accept_ssh_session(*session, config->endpts[endpt_idx].opts.ssh, sock);
        sock = -1;
        if (ret < 0) {
            msgtype = NC_MSG_ERROR;
            goto cleanup;
        } else if (!ret) {
            msgtype = NC_MSG_WOULDBLOCK;
            goto cleanup;
        }
    } else if (config->endpts[endpt_idx].ti == NC_TI_TLS) {
        (*session)->data = config->endpts[endpt_idx].opts.tls;
        ret = nc_accept_tls_session(*session, config->endpts[endpt_idx].opts.tls, sock);
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
    if (config->endpts[endpt_idx].ti == NC_TI_UNIX) {
        (*session)->data = config->endpts[endpt_idx].opts.unix;
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

    /* the transport handshake is over, the configuration must not be reached through the session anymore */
    (*session)->opts.server.config = NULL;

    /* the NETCONF hello needs no configuration */
    nc_server_config_release(config);
    config = NULL;

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
    NC_SESSION_STATUS_SET(*session, NC_STATUS_RUNNING);

    return msgtype;

cleanup:
    free(host);
    if (sock > -1) {
        close(sock);
    }
    if (*session) {
        (*session)->opts.server.config = NULL;
    }
    nc_session_free(*session, NULL);
    *session = NULL;
    nc_server_config_release(config);
    return msgtype;
}

#ifdef NC_ENABLED_SSH_TLS

int
nc_session_handshake_interrupted(const struct nc_session *session)
{
    ATOMIC_T *ch_thread_running = session->opts.server.ch_thread_running;

    if (!ch_thread_running) {
        /* not a Call Home handshake, there is nobody to interrupt it */
        return 0;
    }

    return !ATOMIC_LOAD_RELAXED(*ch_thread_running);
}

int32_t
nc_session_handshake_poll_timeout(const struct nc_session *session, int32_t timeout)
{
    if (!session->opts.server.ch_thread_running) {
        /* nothing can interrupt the handshake, there is no reason to wake up early */
        return timeout;
    }

    /* a negative timeout means waiting indefinitely, which must not happen if we have to notice an interrupt */
    if ((timeout < 0) || (timeout > NC_HANDSHAKE_INTERRUPT_STEP)) {
        return NC_HANDSHAKE_INTERRUPT_STEP;
    }

    return timeout;
}

API int
nc_server_ch_is_client(const char *name)
{
    const struct nc_server_config *config;
    int found = 0;

    if (!name) {
        return found;
    }

    config = nc_server_config_acquire();
    if (!config) {
        return found;
    }

    /* check name against all configured clients */
    if (nc_server_ch_client_get_pinned(config, name)) {
        found = 1;
    }

    nc_server_config_release(config);
    return found;
}

API int
nc_server_ch_client_is_endpt(const char *client_name, const char *endpt_name)
{
    const struct nc_server_config *config;
    const struct nc_ch_client *client;
    LY_ARRAY_COUNT_TYPE u;
    int found = 0;

    if (!client_name || !endpt_name) {
        return found;
    }

    config = nc_server_config_acquire();
    if (!config) {
        return found;
    }

    client = nc_server_ch_client_get_pinned(config, client_name);
    if (!client) {
        goto cleanup;
    }

    LY_ARRAY_FOR(client->ch_endpts, u) {
        if (!strcmp(client->ch_endpts[u].name, endpt_name)) {
            found = 1;
            goto cleanup;
        }
    }

cleanup:
    nc_server_config_release(config);
    return found;
}

/**
 * @brief Create a connection for an endpoint.
 *
 * @param[in] config Pinned server configuration @p endpt belongs to, pinned into the created session
 * for the duration of the transport handshake.
 * @param[in] endpt Endpoint to use.
 * @param[in] ch_thread_running Running flag of the calling Call Home thread, the transport handshake
 * is aborted as soon as it becomes 0.
 * @param[in,out] cur_sock_pending Current pending socket for the connection.
 * @param[in] acquire_ctx_cb Callback for acquiring the libyang context.
 * @param[in] release_ctx_cb Callback for releasing the libyang context.
 * @param[in] ctx_cb_data Context callbacks data.
 * @param[out] session Created NC session.
 * @return NC_MSG values.
 */
static NC_MSG_TYPE
nc_connect_ch_endpt(const struct nc_server_config *config, const struct nc_ch_endpt *endpt,
        ATOMIC_T *ch_thread_running, int *cur_sock_pending, nc_server_ch_session_acquire_ctx_cb acquire_ctx_cb,
        nc_server_ch_session_release_ctx_cb release_ctx_cb, void *ctx_cb_data, struct nc_session **session)
{
    NC_MSG_TYPE msgtype;
    const struct ly_ctx *ctx = NULL;
    int sock, ret;
    struct timespec ts_cur;
    char *ip_host = NULL;

    sock = nc_sock_connect(endpt->src_addr, endpt->src_port, endpt->dst_addr, endpt->dst_port,
            NC_CH_CONNECT_TIMEOUT, &endpt->ka, cur_sock_pending, &ip_host);
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
    NC_SESSION_STATUS_SET(*session, NC_STATUS_STARTING);
    (*session)->ctx = (struct ly_ctx *)ctx;
    (*session)->flags = NC_SESSION_SHAREDCTX | NC_SESSION_CALLHOME;
    (*session)->host = ip_host;
    (*session)->port = endpt->dst_port;

    /* pin the configuration for the duration of the transport handshake, it is a borrowed pointer */
    (*session)->opts.server.config = config;

    /* let the handshake be aborted as soon as this thread is told to stop, also a borrowed pointer */
    (*session)->opts.server.ch_thread_running = ch_thread_running;

    /* sock gets assigned to session or closed */
    if (endpt->ti == NC_TI_SSH) {
        ret = nc_accept_ssh_session(*session, endpt->opts.ssh, sock);
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
        ret = nc_accept_tls_session(*session, endpt->opts.tls, sock);
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

    /* the transport handshake is over, neither the configuration nor the running flag must be
     * reached through the session anymore */
    (*session)->opts.server.config = NULL;
    (*session)->opts.server.ch_thread_running = NULL;

    /* assign new SID atomically */
    (*session)->id = ATOMIC_INC_RELAXED(server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_ch_handshake_io(*session);
    if (msgtype != NC_MSG_HELLO) {
        goto fail;
    }

    nc_timeouttime_get(&ts_cur, 0);
    (*session)->opts.server.last_rpc = ts_cur.tv_sec;
    nc_realtime_get(&ts_cur);
    (*session)->opts.server.session_start = ts_cur;
    NC_SESSION_STATUS_SET(*session, NC_STATUS_RUNNING);

    return msgtype;

fail:
    if (*session) {
        (*session)->opts.server.config = NULL;
        (*session)->opts.server.ch_thread_running = NULL;
    }
    nc_session_free(*session, NULL);
    *session = NULL;
    if (ctx) {
        release_ctx_cb(ctx_cb_data);
    }
    return msgtype;
}

/**
 * @brief Get idle timeout for a Call Home client.
 *
 * A client that is not (yet) part of the published configuration simply has no idle timeout, the
 * lifetime of its thread is decided by ::nc_server_ch_thread_arg.thread_running only.
 *
 * @param[in] client_name Name of the Call Home client.
 * @param[out] idle_timeout Idle timeout in seconds, 0 for none.
 * @return 0 on success, -1 on error.
 */
static int
nc_server_ch_client_get_idle_timeout(const char *client_name, uint32_t *idle_timeout)
{
    const struct nc_server_config *config;
    const struct nc_ch_client *client;

    *idle_timeout = 0;

    config = nc_server_config_acquire();
    if (!config) {
        return -1;
    }

    client = nc_server_ch_client_get_pinned(config, client_name);
    if (client && (client->conn_type == NC_CH_PERIOD)) {
        *idle_timeout = client->idle_timeout;
    }

    nc_server_config_release(config);
    return 0;
}

/**
 * @brief Wait for any event after a NC session was established on a CH client.
 *
 * The session is given to the user by ::nc_server_ch_thread_arg.new_session_cb. Until that
 * succeeds the session still belongs to the Call Home thread, so it is freed here on any error.
 * Afterwards it belongs to the user and is never freed here.
 *
 * @param[in] data CH client thread argument.
 * @param[in] session New NC session. The session is invalid upon being freed (= function exit).
 * @return 0 if session was terminated normally,
 * @return 1 if the CH client was removed,
 * @return -1 on error.
 */
static int
nc_server_ch_client_thread_session_cond_wait(struct nc_server_ch_thread_arg *data, struct nc_session *session)
{
    int rc = 0, r, terminate;
    uint32_t idle_timeout;
    struct timespec ts;

    /* claim the session, ::nc_session_free() waits for this to be cleared */
    ATOMIC_STORE_RELAXED(session->opts.server.ch_thread_active, 1);

    /* give the session to the user */
    if (data->new_session_cb(data->client_name, session, data->new_session_cb_data)) {
        /* something is wrong, we are done with the session */
        ATOMIC_STORE_RELEASE(session->opts.server.ch_thread_active, 0);

        /* session terminated, free it and release its context */
        nc_session_free(session, NULL);
        data->release_ctx_cb(data->ctx_cb_data);
        return 0;
    }

    /* CH LOCK */
    if (nc_mutex_lock(&session->opts.server.ch_lock, NC_SESSION_CH_LOCK_TIMEOUT, __func__) != 1) {
        ATOMIC_STORE_RELEASE(session->opts.server.ch_thread_active, 0);
        return -1;
    }

    /* entering the loop with locked ch_lock, the status must be checked before waiting on the
     * condition, otherwise a session closed before we got the lock is missed and we sleep until
     * the wait times out, by which point ::nc_session_free() may have given up on us */
    while (NC_SESSION_STATUS_GET(session) == NC_STATUS_RUNNING) {
        nc_timeouttime_get(&ts, NC_CH_THREAD_IDLE_TIMEOUT_SLEEP);

        /* CH COND WAIT */
        r = pthread_cond_clockwait(&session->opts.server.ch_cond, &session->opts.server.ch_lock, COMPAT_CLOCK_ID, &ts);
        if (!r) {
            /* we were woken up, something probably happened */
            if (NC_SESSION_STATUS_GET(session) != NC_STATUS_RUNNING) {
                break;
            }
        } else if (r != ETIMEDOUT) {
            ERR(session, "Pthread condition timedwait failed (%s).", strerror(r));
            rc = -1;
            break;
        }

        /* CH UNLOCK */
        nc_mutex_unlock(&session->opts.server.ch_lock, __func__);

        terminate = 0;

        /* get the client's idle timeout */
        if (nc_server_ch_client_get_idle_timeout(data->client_name, &idle_timeout)) {
            rc = -1;
            terminate = 1;
        }

        /* check if the thread should terminate */
        if (!ATOMIC_LOAD_RELAXED(data->thread_running)) {
            terminate = 1;
        }

        /* CH LOCK */
        if (nc_mutex_lock(&session->opts.server.ch_lock, NC_SESSION_CH_LOCK_TIMEOUT, __func__) != 1) {
            ATOMIC_STORE_RELEASE(session->opts.server.ch_thread_active, 0);
            return -1;
        }

        if (terminate) {
            /* the purpose of this is to break only after we've acquired the ch_lock */
            break;
        }

        nc_timeouttime_get(&ts, 0);
        if (!nc_session_get_notif_status(session) && idle_timeout && (ts.tv_sec >= session->opts.server.last_rpc + idle_timeout)) {
            VRB(session, "Call Home client \"%s\": session idle timeout elapsed.", data->client_name);
            NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
            NC_SESSION_TERM_REASON_SET(session, NC_SESSION_TERM_TIMEOUT);
        }
    }
    /* left the loop, but still holding the ch_lock */

    if (NC_SESSION_STATUS_GET(session) == NC_STATUS_RUNNING) {
        /* thread is terminating but the session is still running, so just log it */
        VRB(session, "Call Home client \"%s\" removed, but an established session will not be terminated.",
                data->client_name);
    }

    /* CH UNLOCK */
    nc_mutex_unlock(&session->opts.server.ch_lock, __func__);

    /* release the session, ::nc_session_free() may tear it down as soon as this is observed */
    ATOMIC_STORE_RELEASE(session->opts.server.ch_thread_active, 0);

    return rc;
}

/**
 * @brief Waits for some amount of time while reacting to signals about terminating a Call Home thread
 * and optionally monitoring a pending socket for connection establishment.
 *
 * Uses a self-pipe (data->notify_pipe) for the stop signal and poll(2) to wait on both the pipe and
 * the pending socket simultaneously.
 *
 * @param[in] session An established session.
 * @param[in] data Call Home thread's data.
 * @param[in] wait_time Time in seconds to wait for, after which a reconnect is attempted.
 * @param[in,out] cur_sock_pending Pointer to the current pending socket. May be NULL, in which case
 * only the notify pipe is polled. If non-NULL and the socket connects, it is kept; if the peer closes
 * or an error occurs, it is closed and set to -1.
 * @return -1 if the thread should stop running (pipe was signaled or poll failed).
 * @return 0 if the timeout elapsed (caller should close the pending socket and retry with a new one).
 * @return 1 if the pending socket became writable (connection established, proceed to handshake).
 */
static int
nc_server_ch_client_thread_wait(struct nc_session *session, struct nc_server_ch_thread_arg *data,
        uint32_t wait_time, int *cur_sock_pending)
{
    struct pollfd pfd[2] = {0};
    uint16_t pfd_count = 1;
    int r, timeout_ms;
    char buf[16];

    /* always poll the notify pipe (for stop signal) */
    pfd[0].fd = data->notify_pipe[0];
    pfd[0].events = POLLIN;

    /* if we have a pending socket, poll it for writability (connection established) */
    if (cur_sock_pending && (*cur_sock_pending != -1)) {
        pfd[1].fd = *cur_sock_pending;
        pfd[1].events = POLLOUT;
        pfd_count = 2;
    }

    /* convert seconds to ms, avoid int overflow (negative poll timeout = infinite) */
    if (wait_time > (uint32_t)INT32_MAX / 1000) {
        timeout_ms = INT32_MAX;
    } else {
        timeout_ms = (int)(wait_time * 1000);
    }

    r = nc_poll(pfd, pfd_count, timeout_ms);
    if (r == -1) {
        /* poll failed, nc_poll already logged the error */
        return -1;
    } else if (r == 0) {
        /* timeout */
        VRB(session, "Call Home client \"%s\" timeout of %" PRIu32 " seconds expired, reconnecting.",
                data->client_name, wait_time);
        return 0;
    }

    /* check if the thread was signaled to stop */
    if (!ATOMIC_LOAD_RELAXED(data->thread_running)) {
        return -1;
    }

    /* drain the pipe if it was signaled */
    if (pfd[0].revents & POLLIN) {
        while (read(data->notify_pipe[0], buf, sizeof buf) > 0) {}
    }

    /* check if the pending socket became writable or had an error */
    if (pfd_count == 2) {
        if (pfd[1].revents & (POLLHUP | POLLERR)) {
            /* socket connected but peer already closed, or error.
             * treat as timeout, will create a new socket */
            VRB(session, "Call Home client \"%s\" pending socket connected but peer closed.", data->client_name);
            close(*cur_sock_pending);
            *cur_sock_pending = -1;
            return 0;
        }
        if (pfd[1].revents & POLLOUT) {
            return 1;
        }
    }

    /* only the pipe was signaled but thread_running is still 1 — shouldn't happen, treat as timeout */
    return 0;
}

/**
 * @brief Acquire a configuration in which the Call Home client has at least one endpoint defined.
 *
 * A client that is missing from the published configuration is waited for the same way as a client
 * with no endpoints - it may simply not have been published yet, so the thread is normally only
 * ever stopped by clearing ::nc_server_ch_thread_arg.thread_running. A configuration that cannot be
 * acquired at all is retried a few times as well, but not forever - it means either a wedged
 * configuration lock or a server destroyed without stopping this thread first.
 *
 * @param[in] data Call Home client thread argument.
 * @param[out] client Found Call Home client of the returned configuration.
 * @return Pinned server configuration, the caller must release it.
 * @return NULL if the thread should stop running.
 */
static const struct nc_server_config *
nc_server_ch_client_acquire_with_endpt(struct nc_server_ch_thread_arg *data, const struct nc_ch_client **client)
{
    const struct nc_server_config *config;
    uint32_t failed_attempts = 0;

    *client = NULL;

    while (ATOMIC_LOAD_RELAXED(data->thread_running)) {
        config = nc_server_config_acquire();
        if (config) {
            failed_attempts = 0;

            *client = nc_server_ch_client_get_pinned(config, data->client_name);
            if (*client && (*client)->ch_endpts) {
                /* the client is configured and has at least one endpoint */
                return config;
            }

            /* not configured (yet) or no endpoints defined yet */
            nc_server_config_release(config);
            *client = NULL;
        } else if (++failed_attempts == NC_CH_CONFIG_ACQUIRE_ATTEMPTS) {
            ERR(NULL, "Call Home client \"%s\" failed to acquire the server configuration %d times, "
                    "terminating its thread.", data->client_name, NC_CH_CONFIG_ACQUIRE_ATTEMPTS);
            return NULL;
        }

        /* the configuration is not usable (yet), wait a little bit and try again */
        usleep(NC_CH_NO_ENDPT_WAIT * 1000);
    }

    /* thread is not running */
    return NULL;
}

/**
 * @brief Call Home client management thread.
 *
 * Runs until ::nc_server_ch_thread_arg.thread_running is cleared or an unrecoverable error occurs.
 * In the latter case it unregisters itself, see ::nc_server_ch_thread_unreg_self().
 *
 * @param[in] arg CH client thread argument.
 * @return NULL.
 */
static void *
nc_ch_client_thread(void *arg)
{
    struct nc_server_ch_thread_arg *data = arg;
    NC_MSG_TYPE msgtype;
    int cur_sock_pending = -1, r;
    uint8_t cur_attempts = 0, max_attempts = 0;
    uint16_t next_endpt_index, max_wait = 0, period = 0;
    char *cur_endpt_name = NULL;
    const struct nc_server_config *config = NULL;
    const struct nc_ch_client *client;
    const struct nc_ch_endpt *cur_endpt;
    struct nc_session *session = NULL;
    uint32_t reconnect_in;
    NC_CH_CONN_TYPE conn_type;
    NC_CH_START_WITH start_with;
    time_t anchor_time;

    /* get the client once it is configured with at least one endpoint */
    config = nc_server_ch_client_acquire_with_endpt(data, &client);
    if (!config) {
        goto cleanup;
    }

    /* the client has at least 1 endpoint, so select the first one */
    cur_endpt = &client->ch_endpts[0];
    cur_endpt_name = strdup(cur_endpt->name);
    NC_CHECK_ERRMEM_GOTO(!cur_endpt_name, , cleanup);

    while (ATOMIC_LOAD_RELAXED(data->thread_running)) {
        if (!cur_attempts) {
            VRB(NULL, "Call Home client \"%s\" endpoint \"%s\" connecting...", data->client_name, cur_endpt_name);
        }

        /* try to connect to the endpoint, the configuration stays pinned for the whole handshake */
        msgtype = nc_connect_ch_endpt(config, cur_endpt, &data->thread_running, &cur_sock_pending,
                data->acquire_ctx_cb, data->release_ctx_cb, data->ctx_cb_data, &session);
        if (msgtype == NC_MSG_HELLO) {
            /* session established, the configuration is not needed anymore */
            nc_server_config_release(config);
            config = NULL;
            client = NULL;
            cur_endpt = NULL;

            if (!ATOMIC_LOAD_RELAXED(data->thread_running)) {
                /* thread should stop running, the session has not been given to the user yet,
                 * so it is still ours to free */
                nc_session_free(session, NULL);
                session = NULL;
                data->release_ctx_cb(data->ctx_cb_data);
                goto cleanup;
            }

            /* run while the session is established */
            VRB(session, "Call Home client \"%s\" session %u established.", data->client_name, session->id);
            if (nc_server_ch_client_thread_session_cond_wait(data, session)) {
                goto cleanup;
            }
            session = NULL;

            VRB(NULL, "Call Home client \"%s\" session terminated.", data->client_name);
            if (!ATOMIC_LOAD_RELAXED(data->thread_running)) {
                /* thread should stop running */
                goto cleanup;
            }

            /* get the client again, it may have been changed */
            config = nc_server_ch_client_acquire_with_endpt(data, &client);
            if (!config) {
                goto cleanup;
            }

            /* session changed status -> it was disconnected for whatever reason,
             * persistent connection immediately tries to reconnect, periodic connects at specific times */
            conn_type = client->conn_type;
            period = client->period;
            anchor_time = client->anchor_time;
            if (conn_type == NC_CH_PERIOD) {
                if (anchor_time) {
                    /* anchored */
                    reconnect_in = (time(NULL) - anchor_time) % (period * 60);
                } else {
                    /* fixed timeout */
                    reconnect_in = period * 60;
                }

                /* the configuration is not needed while waiting */
                nc_server_config_release(config);
                config = NULL;
                client = NULL;

                /* wait for the timeout to elapse, so we can try to reconnect */
                VRB(NULL, "Call Home client \"%s\" reconnecting in %" PRIu32 " seconds.", data->client_name, reconnect_in);
                r = nc_server_ch_client_thread_wait(NULL, data, reconnect_in, NULL);
                if (r == -1) {
                    goto cleanup;
                }

                config = nc_server_ch_client_acquire_with_endpt(data, &client);
                if (!config) {
                    goto cleanup;
                }
            }

            /* set next endpoint to try */
            start_with = client->start_with;
            if (start_with == NC_CH_FIRST_LISTED) {
                next_endpt_index = 0;
            } else if (start_with == NC_CH_LAST_CONNECTED) {
                /* we keep the current one but due to the release/acquire we have to find it again */
                LY_ARRAY_FOR(client->ch_endpts, next_endpt_index) {
                    if (!strcmp(client->ch_endpts[next_endpt_index].name, cur_endpt_name)) {
                        break;
                    }
                }
                if (next_endpt_index >= LY_ARRAY_COUNT(client->ch_endpts)) {
                    /* endpoint was removed, start with the first one */
                    next_endpt_index = 0;
                }
            } else {
                /* just get a random index */
                next_endpt_index = rand() % LY_ARRAY_COUNT(client->ch_endpts);
            }
            cur_attempts = 0;
        } else {
            if (!ATOMIC_LOAD_RELAXED(data->thread_running)) {
                /* the handshake was interrupted because this thread should stop, do not count it as
                 * a failed attempt and do not bother the user with it */
                goto cleanup;
            }

            /* session was not created, wait a little bit and try again */
            ++cur_attempts;

            /* copy what is needed after the configuration is released, the user callback and the
             * wait must not run with a generation pinned */
            max_wait = client->max_wait;
            max_attempts = client->max_attempts;

            /* the configuration is not needed while waiting */
            nc_server_config_release(config);
            config = NULL;
            client = NULL;
            cur_endpt = NULL;

            /* failed connection attempt */
            if (data->new_session_fail_cb) {
                data->new_session_fail_cb(data->client_name, cur_endpt_name, max_attempts, cur_attempts,
                        data->new_session_fail_cb_data);
            }

            /* wait for max_wait seconds */
            r = nc_server_ch_client_thread_wait(NULL, data, max_wait, &cur_sock_pending);
            if (r == -1) {
                /* thread should stop running */
                goto cleanup;
            } else if (r == 0) {
                /* timeout or peer closed - close pending socket, will create a new one next iteration */
                if (cur_sock_pending != -1) {
                    close(cur_sock_pending);
                    cur_sock_pending = -1;
                }
            }
            /* if r == 1, socket is connected, keep cur_sock_pending for nc_connect_ch_endpt */

            /* get the client */
            config = nc_server_ch_client_acquire_with_endpt(data, &client);
            if (!config) {
                goto cleanup;
            }

            /* try to find our endpoint again */
            LY_ARRAY_FOR(client->ch_endpts, next_endpt_index) {
                if (!strcmp(client->ch_endpts[next_endpt_index].name, cur_endpt_name)) {
                    break;
                }
            }

            if (next_endpt_index >= LY_ARRAY_COUNT(client->ch_endpts)) {
                /* endpoint was removed, start with the first one */
                VRB(NULL, "Call Home client \"%s\" endpoint \"%s\" removed.", data->client_name, cur_endpt_name);

                /* close pending socket to the removed endpoint, if any */
                if (cur_sock_pending != -1) {
                    close(cur_sock_pending);
                    cur_sock_pending = -1;
                }

                next_endpt_index = 0;
                cur_attempts = 0;
            } else if (cur_attempts == client->max_attempts) {
                /* we have tried to connect to this endpoint enough times */
                VRB(NULL, "Call Home client \"%s\" endpoint \"%s\" failed connection attempt limit %" PRIu8 " reached.",
                        data->client_name, cur_endpt_name, client->max_attempts);

                /* close pending socket, switching to a different endpoint */
                if (cur_sock_pending != -1) {
                    close(cur_sock_pending);
                    cur_sock_pending = -1;
                }

                if (next_endpt_index < LY_ARRAY_COUNT(client->ch_endpts) - 1) {
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
        NC_CHECK_ERRMEM_GOTO(!cur_endpt_name, , cleanup);
    }

cleanup:
    /* the session, if there still is one, belongs to the user and may have been freed already,
     * so it must not be logged through */
    VRB(NULL, "Call Home client \"%s\" thread exit.", data->client_name);
    nc_server_config_release(config);
    free(cur_endpt_name);
    if (cur_sock_pending != -1) {
        close(cur_sock_pending);
    }

    /* if we are terminating on our own, take ourselves out of the registry so that the client can
     * be dispatched again, otherwise this is a no-op and whoever stopped us cleans up after us */
    nc_server_ch_thread_unreg_self(data);

    return NULL;
}

int
nc_session_server_ch_client_dispatch_stop(const char *client_name)
{
    int r;
    struct nc_server_ch_thread_arg *thread_arg;

    /* unregister the thread first, so that no other caller can find and join the same one */
    if (nc_server_ch_thread_reg_del(client_name, &thread_arg)) {
        return 1;
    }
    if (!thread_arg) {
        /* no thread is running for this client */
        return 0;
    }

    /* notify the thread to stop */
    ATOMIC_STORE_RELAXED(thread_arg->thread_running, 0);

    /* wake up the thread if it's in thread_wait */
    if (write(thread_arg->notify_pipe[1], "x", 1) == -1) {
        if (errno != EAGAIN) {
            ERR(NULL, "Writing to the notify pipe failed (%s).", strerror(errno));
        }
        /* EAGAIN is fine: pipe buffer is full, meaning it's already been signaled */
    }

    /* wait for the thread to end, no lock is held so a stalled handshake blocks nothing else */
    r = pthread_join(thread_arg->tid, NULL);
    if (r) {
        ERR(NULL, "Joining Call Home client \"%s\" thread failed (%s), its data will be leaked.",
                client_name, strerror(r));
        return 1;
    }

    /* the registry entry was ours, so is the cleanup */
    nc_server_ch_thread_arg_free(thread_arg);

    return 0;
}

int
nc_server_ch_threads_destroy(void)
{
    int rc = 0;
    char **names = NULL;
    LY_ARRAY_COUNT_TYPE u;

    if (nc_server_ch_thread_names_get(&names)) {
        return 1;
    }

    LY_ARRAY_FOR(names, u) {
        if (nc_session_server_ch_client_dispatch_stop(names[u])) {
            rc = 1;
        }
    }
    nc_server_ch_thread_names_free(names);

    /* CH THREADS LOCK */
    if (nc_mutex_lock(&server_opts.ch_threads_lock, NC_CH_THREADS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }
    if (LY_ARRAY_COUNT(server_opts.ch_threads)) {
        ERRINT;
        rc = 1;
    }
    LY_ARRAY_FREE(server_opts.ch_threads);
    server_opts.ch_threads = NULL;
    /* CH THREADS UNLOCK */
    nc_mutex_unlock(&server_opts.ch_threads_lock, __func__);

    return rc;
}

int
_nc_connect_ch_client_dispatch(const char *client_name, nc_server_ch_session_acquire_ctx_cb acquire_ctx_cb,
        nc_server_ch_session_release_ctx_cb release_ctx_cb, void *ctx_cb_data, nc_server_ch_new_session_cb new_session_cb,
        void *new_session_cb_data)
{
    int rc = 0, r;
    int flags;
    LY_ERR lyrc = LY_SUCCESS;
    struct nc_server_ch_thread_arg *arg = NULL, **item;
    LY_ARRAY_COUNT_TYPE u;

    /* create the thread argument */
    arg = calloc(1, sizeof *arg);
    NC_CHECK_ERRMEM_GOTO(!arg, rc = -1, cleanup);
    arg->notify_pipe[0] = -1;
    arg->notify_pipe[1] = -1;
    arg->client_name = strdup(client_name);
    NC_CHECK_ERRMEM_GOTO(!arg->client_name, rc = -1, cleanup);
    arg->acquire_ctx_cb = acquire_ctx_cb;
    arg->release_ctx_cb = release_ctx_cb;
    arg->ctx_cb_data = ctx_cb_data;
    arg->new_session_cb = new_session_cb;
    arg->new_session_cb_data = new_session_cb_data;

    /* OPTS READ LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_READ, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        rc = -1;
        goto cleanup;
    }
    arg->new_session_fail_cb = server_opts.ch_dispatch_data.new_session_fail_cb;
    arg->new_session_fail_cb_data = server_opts.ch_dispatch_data.new_session_fail_cb_data;
    /* OPTS READ UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);

    /* create the self-pipe for signaling the thread to terminate */
    if (pipe(arg->notify_pipe) == -1) {
        ERR(NULL, "pipe() failed (%s).", strerror(errno));
        rc = -1;
        goto cleanup;
    }

    /* set both ends non-blocking */
    if (((flags = fcntl(arg->notify_pipe[0], F_GETFL)) == -1) ||
            (fcntl(arg->notify_pipe[0], F_SETFL, flags | O_NONBLOCK) == -1) ||
            ((flags = fcntl(arg->notify_pipe[1], F_GETFL)) == -1) ||
            (fcntl(arg->notify_pipe[1], F_SETFL, flags | O_NONBLOCK) == -1)) {
        ERR(NULL, "fcntl() failed (%s).", strerror(errno));
        rc = -1;
        goto cleanup;
    }

    /* mark the thread as running before it is created, so that it can be stopped right away */
    ATOMIC_STORE_RELAXED(arg->thread_running, 1);

    /* CH THREADS LOCK - the registration and the thread creation must be atomic, the registry entry
     * is what makes the thread findable and joinable, so it must exist before the thread does but
     * it must never refer to a thread that was not created yet */
    if (nc_mutex_lock(&server_opts.ch_threads_lock, NC_CH_THREADS_LOCK_TIMEOUT, __func__) != 1) {
        rc = -1;
        goto cleanup;
    }

    /* there must never be two threads dispatched for a single Call Home client */
    LY_ARRAY_FOR(server_opts.ch_threads, u) {
        if (!strcmp(server_opts.ch_threads[u]->client_name, client_name)) {
            rc = 1;
            goto unlock;
        }
    }

    /* register the thread first, the array cannot fail to grow once the thread is running */
    LY_ARRAY_NEW_GOTO(NULL, server_opts.ch_threads, item, lyrc, unlock);
    *item = arg;

    /* create the CH thread */
    if ((r = pthread_create(&arg->tid, NULL, nc_ch_client_thread, arg))) {
        ERR(NULL, "Creating a new thread failed (%s).", strerror(r));
        LY_ARRAY_DECREMENT_FREE(server_opts.ch_threads);
        rc = -1;
        goto unlock;
    }

    /* arg is now owned by the thread and the registry */
    arg = NULL;

unlock:
    /* CH THREADS UNLOCK */
    nc_mutex_unlock(&server_opts.ch_threads_lock, __func__);
    if (lyrc) {
        rc = -1;
    }

cleanup:
    nc_server_ch_thread_arg_free(arg);
    return rc;
}

API int
nc_connect_ch_client_dispatch(const char *client_name, nc_server_ch_session_acquire_ctx_cb acquire_ctx_cb,
        nc_server_ch_session_release_ctx_cb release_ctx_cb, void *ctx_cb_data, nc_server_ch_new_session_cb new_session_cb,
        void *new_session_cb_data)
{
    int rc = 0;
    const struct nc_server_config *config;

    NC_CHECK_ARG_RET(NULL, client_name, acquire_ctx_cb, release_ctx_cb, new_session_cb, -1);

    NC_CHECK_SRV_INIT_RET(-1);

    config = nc_server_config_acquire();
    if (!config) {
        return -1;
    }

    /* check ch client existence */
    if (!nc_server_ch_client_get_pinned(config, client_name)) {
        ERR(NULL, "Call Home client \"%s\" not found.", client_name);
        rc = -1;
        goto cleanup;
    }

    rc = _nc_connect_ch_client_dispatch(client_name, acquire_ctx_cb, release_ctx_cb, ctx_cb_data,
            new_session_cb, new_session_cb_data);
    if (rc == 1) {
        /* a thread is already running for this client, do not silently ignore that */
        ERR(NULL, "Call Home client \"%s\" is already being dispatched.", client_name);
        rc = -1;
    }

cleanup:
    nc_server_config_release(config);
    return rc;
}

/**
 * @brief Check whether a Call Home client name is present in an array of names.
 *
 * @param[in] names Array of names (sized-array, see libyang docs).
 * @param[in] name Name to look for.
 * @return 1 if @p name is present, 0 otherwise.
 */
static int
nc_server_ch_name_found(char **names, const char *name)
{
    LY_ARRAY_COUNT_TYPE u;

    LY_ARRAY_FOR(names, u) {
        if (!strcmp(names[u], name)) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Check whether a server configuration contains a Call Home client of the given name.
 *
 * @param[in] config Server configuration.
 * @param[in] name Name of the Call Home client to look for.
 * @return 1 if the client is configured, 0 otherwise.
 */
static int
nc_server_ch_client_configured(const struct nc_server_config *config, const char *name)
{
    LY_ARRAY_COUNT_TYPE u;

    LY_ARRAY_FOR(config->ch_clients, u) {
        if (!strcmp(config->ch_clients[u].name, name)) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief Check if the new configuration contains a Call Home client that has no thread running.
 *
 * @param[in] config New server configuration currently being applied.
 * @param[in] running Names of the Call Home clients with a running thread (sized-array, see libyang docs).
 * @return 1 if there are new CH clients, 0 otherwise.
 */
static int
nc_server_ch_new_clients_created(const struct nc_server_config *config, char **running)
{
    LY_ARRAY_COUNT_TYPE u;

    LY_ARRAY_FOR(config->ch_clients, u) {
        if (!nc_server_ch_name_found(running, config->ch_clients[u].name)) {
            return 1;
        }
    }

    /* no differences found */
    return 0;
}

int
nc_server_ch_clients_reconcile(const struct nc_server_config *config)
{
    int rc = 0;
    LY_ARRAY_COUNT_TYPE u;
    char **running = NULL, **started = NULL, **started_name, *name = NULL;
    struct nc_server_ch_dispatch_data dispatch_data;
    int dispatch_new_clients = 1;

    /* OPTS READ LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_READ, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }
    dispatch_data = server_opts.ch_dispatch_data;
    /* OPTS READ UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);

    /* learn which clients are running right now */
    NC_CHECK_GOTO(rc = nc_server_ch_thread_names_get(&running), cleanup);

    if (!dispatch_data.acquire_ctx_cb || !dispatch_data.release_ctx_cb || !dispatch_data.new_session_cb) {
        /* Call Home dispatch callbacks not set, we can't dispatch new clients, but we can still stop deleted ones */
        if (nc_server_ch_new_clients_created(config, running)) {
            WRN(NULL, "New Call Home clients were created but Call Home dispatch callbacks are not set - "
                    "new clients will not be dispatched automatically.");
        }
        dispatch_new_clients = 0;
    }

    /*
     * == PHASE 1: START NEW CLIENTS ==
     * Start clients present in config that are not already running.
     * Track successfully started threads for potential rollback.
     */
    if (dispatch_new_clients) {
        /* only dispatch if all required CBs are set */
        LY_ARRAY_FOR(config->ch_clients, u) {
            if (nc_server_ch_name_found(running, config->ch_clients[u].name)) {
                /* already running */
                continue;
            }

            /* this is a new Call Home client, dispatch it */
            rc = _nc_connect_ch_client_dispatch(config->ch_clients[u].name, dispatch_data.acquire_ctx_cb,
                    dispatch_data.release_ctx_cb, dispatch_data.ctx_cb_data,
                    dispatch_data.new_session_cb, dispatch_data.new_session_cb_data);
            if (rc == 1) {
                /* the client was dispatched through the API right after we learned the running ones,
                 * which is exactly the state we wanted, so leave the thread to its dispatcher */
                VRB(NULL, "Call Home client \"%s\" already has a running thread, skipping its dispatch.",
                        config->ch_clients[u].name);
                rc = 0;
                continue;
            } else if (rc) {
                /* FAILURE! trigger rollback */
                goto rollback;
            }

            /* successfully started, track the client for a potential rollback, the name must be
             * ready before the array grows so that the rollback never sees a NULL entry */
            name = strdup(config->ch_clients[u].name);
            NC_CHECK_ERRMEM_GOTO(!name, rc = 1, rollback);
            LY_ARRAY_NEW_GOTO(NULL, started, started_name, rc, rollback);
            *started_name = name;
            name = NULL;
        }
    }

    /*
     * == PHASE 2: STOP DELETED CLIENTS (COMMIT) ==
     * All new clients started successfully. Now stop the running clients
     * that are not present in the new configuration.
     */
    LY_ARRAY_FOR(running, u) {
        if (nc_server_ch_client_configured(config, running[u])) {
            continue;
        }

        /* this Call Home client was deleted, notify it to stop */
        if ((rc = nc_session_server_ch_client_dispatch_stop(running[u]))) {
            ERR(NULL, "Failed to dispatch stop for Call Home client \"%s\".", running[u]);
            goto rollback;
        }
    }

    /* success */
    rc = 0;
    goto cleanup;

rollback:
    /*
     * == ROLLBACK LOGIC ==
     * An error occurred during PHASE 1. Stop any new threads we *just* started
     * to return to the pre-call state.
     */
    LY_ARRAY_FOR(started, u) {
        nc_session_server_ch_client_dispatch_stop(started[u]);
    }
    /* rc is already set to non-zero from the failure point */

cleanup:
    free(name);
    nc_server_ch_thread_names_free(running);
    nc_server_ch_thread_names_free(started);
    return rc ? 1 : 0;
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

    /* NTF STATUS LOCK, continue on error */
    nc_mutex_lock(&session->opts.server.ntf_status_lock, NC_SESSION_NTF_STATUS_LOCK_TIMEOUT, __func__);

    ++session->opts.server.ntf_status;

    /* NTF STATUS UNLOCK */
    nc_mutex_unlock(&session->opts.server.ntf_status_lock, __func__);
}

API void
nc_session_dec_notif_status(struct nc_session *session)
{
    if (!session || (session->side != NC_SERVER)) {
        ERRARG(session, "session");
        return;
    }

    /* NTF STATUS LOCK, continue on error */
    nc_mutex_lock(&session->opts.server.ntf_status_lock, NC_SESSION_NTF_STATUS_LOCK_TIMEOUT, __func__);

    if (session->opts.server.ntf_status) {
        --session->opts.server.ntf_status;
    }

    /* NTF STATUS UNLOCK */
    nc_mutex_unlock(&session->opts.server.ntf_status_lock, __func__);
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
    if (nc_mutex_lock(&((struct nc_session *)session)->opts.server.ntf_status_lock, NC_SESSION_NTF_STATUS_LOCK_TIMEOUT,
            __func__) != 1) {
        return 0;
    }

    ntf_status = session->opts.server.ntf_status;

    /* NTF STATUS UNLOCK */
    nc_mutex_unlock(&((struct nc_session *)session)->opts.server.ntf_status_lock, __func__);

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
nc_server_notif_cert_exp_next_notif_time_get(struct nc_cert_exp_time_interval *intervals, int interval_count,
        struct nc_cert_expiration *exp)
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
nc_server_notif_cert_exp_init_intervals(struct nc_cert_exp_time_interval *intervals, int interval_count,
        struct nc_cert_expiration *exp)
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
nc_server_notif_cert_exp_first_notif_time_get(struct nc_cert_exp_time_interval *intervals, int interval_count,
        struct nc_cert_expiration *exp)
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
        struct nc_cert_exp_time_interval *intervals, uint32_t interval_count,
        struct nc_cert_expiration **exp_dates, uint32_t *exp_date_count)
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
        struct nc_cert_exp_time_interval *intervals, uint32_t interval_count,
        struct nc_cert_expiration **exp_dates, uint32_t *exp_date_count)
{
    int ret = 0;
    LY_ARRAY_COUNT_TYPE i;
    struct nc_certificate *certs;
    struct nc_cert_path_aux cp = {0};

    /* append server cert first */
    if (opts->cert_store == NC_STORE_LOCAL) {
        NC_CERT_EXP_UPDATE_CERT_PATH(&cp, ch_client_name, endpt_name, NULL, NULL, NULL, NULL, NULL, NULL);
        ret = nc_server_notif_cert_exp_date_append(opts->local.cert.data, &cp, intervals, interval_count, exp_dates, exp_date_count);
        if (ret) {
            goto cleanup;
        }
    }

    /* append CA certs */
    if (opts->client_auth.ca_certs_store == NC_STORE_LOCAL) {
        certs = opts->client_auth.ca_certs;

        LY_ARRAY_FOR(certs, i) {
            NC_CERT_EXP_UPDATE_CERT_PATH(&cp, ch_client_name, endpt_name, certs[i].name, NULL, NULL, NULL, NULL, NULL);
            ret = nc_server_notif_cert_exp_date_append(certs[i].data, &cp, intervals, interval_count, exp_dates, exp_date_count);
            if (ret) {
                goto cleanup;
            }
        }
    }

    /* append end entity certs */
    if (opts->client_auth.ee_certs_store == NC_STORE_LOCAL) {
        certs = opts->client_auth.ee_certs;

        LY_ARRAY_FOR(certs, i) {
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
nc_server_notif_cert_exp_dates_get(struct nc_cert_exp_time_interval *intervals, uint32_t interval_count,
        struct nc_cert_expiration **exp_dates, uint32_t *exp_date_count)
{
    int ret = 0;
    const struct nc_server_config *config;
    const struct nc_endpt *endpt;
    const struct nc_ch_client *ch_client;
    const struct nc_ch_endpt *ch_endpt;
    struct nc_certificate *cert;
    const struct nc_keystore *ks;
    const struct nc_truststore *ts;
    struct nc_cert_path_aux cp = {0};
    LY_ARRAY_COUNT_TYPE i, u, v;

    NC_CHECK_ARG_RET(NULL, intervals, interval_count, exp_dates, exp_date_count, 1);

    *exp_dates = NULL;
    *exp_date_count = 0;

    config = nc_server_config_acquire();
    if (!config) {
        return 1;
    }

    /* the aliases must only be taken from the pinned configuration */
    ks = &config->keystore;
    ts = &config->truststore;

    /* first go through listen certs */
    LY_ARRAY_FOR(config->endpts, u) {
        endpt = &config->endpts[u];
        if (endpt->ti == NC_TI_TLS) {
            ret = nc_server_notif_cert_exp_dates_endpt_get(NULL, endpt->name, endpt->opts.tls,
                    intervals, interval_count, exp_dates, exp_date_count);
            if (ret) {
                goto cleanup;
            }
        }
    }

    /* then go through all the ch clients and their endpts */
    LY_ARRAY_FOR(config->ch_clients, u) {
        ch_client = &config->ch_clients[u];
        LY_ARRAY_FOR(ch_client->ch_endpts, v) {
            ch_endpt = &ch_client->ch_endpts[v];
            if (ch_endpt->ti == NC_TI_TLS) {
                ret = nc_server_notif_cert_exp_dates_endpt_get(ch_client->name, ch_endpt->name, ch_endpt->opts.tls,
                        intervals, interval_count, exp_dates, exp_date_count);
                if (ret) {
                    goto cleanup;
                }
            }
        }
    }

    /* keystore certs */
    LY_ARRAY_FOR(ks->entries, i) {
        LY_ARRAY_FOR(ks->entries[i].certs, struct nc_certificate, cert) {
            NC_CERT_EXP_UPDATE_CERT_PATH(&cp, NULL, NULL, NULL, NULL, ks->entries[i].asym_key.name, cert->name, NULL, NULL);
            ret = nc_server_notif_cert_exp_date_append(cert->data, &cp, intervals, interval_count, exp_dates, exp_date_count);
            if (ret) {
                goto cleanup;
            }
        }
    }

    /* truststore certs */
    LY_ARRAY_FOR(ts->cert_bags, i) {
        LY_ARRAY_FOR(ts->cert_bags[i].certs, struct nc_certificate, cert) {
            NC_CERT_EXP_UPDATE_CERT_PATH(&cp, NULL, NULL, NULL, NULL, NULL, NULL, ts->cert_bags[i].name, cert->name);
            ret = nc_server_notif_cert_exp_date_append(cert->data, &cp, intervals, interval_count, exp_dates, exp_date_count);
            if (ret) {
                goto cleanup;
            }
        }
    }

cleanup:
    nc_server_config_release(config);
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
 * @param[in] intervals Time intervals to destroy.
 */
static void
nc_server_notif_cert_exp_data_destroy(struct nc_cert_expiration *exp_dates, int exp_date_count,
        struct nc_cert_exp_time_interval *intervals)
{
    int i;

    for (i = 0; i < exp_date_count; i++) {
        free(exp_dates[i].starts_of_intervals);
        free(exp_dates[i].xpath);
    }
    free(exp_dates);

    free(intervals);
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
    if (nc_mutex_lock(&server_opts.cert_exp_notif.lock, NC_CERT_EXP_LOCK_TIMEOUT, __func__) != 1) {
        return 0;
    }

    if (server_opts.cert_exp_notif.thread_running) {
        ret = 1;
    }

    /* UNLOCK */
    nc_mutex_unlock(&server_opts.cert_exp_notif.lock, __func__);

    return ret;
}

/**
 * @brief Get the certificate expiration notification time intervals either from the config or the default ones.
 *
 * @note The caller is responsible for freeing the allocated intervals.
 *
 * @param[in] default_intervals Default intervals.
 * @param[in] default_interval_count Default interval count.
 * @param[out] intervals Actual intervals to be used.
 * @param[out] interval_count Used interval count.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_notif_cert_exp_intervals_get(struct nc_cert_exp_time_interval *default_intervals, uint32_t default_interval_count,
        struct nc_cert_exp_time_interval **intervals, uint32_t *interval_count)
{
    int rc = 0;
    const struct nc_server_config *config;

    *intervals = NULL;
    *interval_count = 0;

    config = nc_server_config_acquire();
    if (!config) {
        return 1;
    }

    if (!config->cert_exp_notif_intervals) {
        /* dup the default intervals */
        *intervals = malloc(default_interval_count * sizeof **intervals);
        NC_CHECK_ERRMEM_GOTO(!*intervals, rc = 1, cleanup);
        memcpy(*intervals, default_intervals, default_interval_count * sizeof **intervals);
        *interval_count = default_interval_count;
    } else {
        /* dup the configured intervals */
        *intervals = malloc(LY_ARRAY_COUNT(config->cert_exp_notif_intervals) * sizeof **intervals);
        NC_CHECK_ERRMEM_GOTO(!*intervals, rc = 1, cleanup);
        memcpy(*intervals, config->cert_exp_notif_intervals,
                LY_ARRAY_COUNT(config->cert_exp_notif_intervals) * sizeof **intervals);
        *interval_count = LY_ARRAY_COUNT(config->cert_exp_notif_intervals);
    }

cleanup:
    nc_server_config_release(config);
    return rc;
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
    int r = 0;
    struct nc_cert_exp_notif_thread_arg *targ = arg;
    struct nc_cert_expiration *exp_dates = NULL, *curr_cert = NULL;
    struct timespec wakeup_time = {0};
    char *exp_time = NULL;
    struct nc_cert_exp_time_interval default_intervals[3] = {
        {.anchor = {.months = 3}, .period = {.months = 1}},
        {.anchor = {.weeks = 2}, .period = {.weeks = 1}},
        {.anchor = {.days = 7}, .period = {.days = 1}}
    };
    struct nc_cert_exp_time_interval *intervals;
    uint32_t interval_count = 0, exp_date_count = 0;

    /* get certificate expiration time intervals */
    r = nc_server_notif_cert_exp_intervals_get(default_intervals,
            sizeof(default_intervals) / sizeof(default_intervals[0]), &intervals, &interval_count);
    if (r) {
        goto cleanup;
    }

    /* get the expiration dates */
    r = nc_server_notif_cert_exp_dates_get(intervals, interval_count, &exp_dates, &exp_date_count);
    if (r) {
        goto cleanup;
    }

    while (nc_server_notif_cert_exp_thread_is_running()) {
        /* get the next notification time and the cert to send it for */
        wakeup_time.tv_sec = nc_server_notif_cert_exp_wakeup_time_get(exp_dates, exp_date_count, &curr_cert);

        /* sleep until the next notification time or until the thread is woken up */
        if (nc_mutex_lock(&server_opts.cert_exp_notif.lock, NC_CERT_EXP_LOCK_TIMEOUT, __func__) != 1) {
            break;
        }
        r = pthread_cond_clockwait(&server_opts.cert_exp_notif.cond,
                &server_opts.cert_exp_notif.lock, CLOCK_REALTIME, &wakeup_time);
        nc_mutex_unlock(&server_opts.cert_exp_notif.lock, __func__);

        if (!r) {
            /* we were woken up */
            if (!nc_server_notif_cert_exp_thread_is_running()) {
                /* end the thread */
                break;
            }

            /* config changed, reload the certificates and intervals */
            nc_server_notif_cert_exp_data_destroy(exp_dates, exp_date_count, intervals);

            r = nc_server_notif_cert_exp_intervals_get(default_intervals, 3, &intervals, &interval_count);
            if (r) {
                break;
            }

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
    nc_server_notif_cert_exp_data_destroy(exp_dates, exp_date_count, intervals);
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
    if (nc_mutex_lock(&server_opts.cert_exp_notif.lock, NC_CERT_EXP_LOCK_TIMEOUT, __func__) != 1) {
        ret = 1;
        goto cleanup;
    }

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
    nc_mutex_unlock(&server_opts.cert_exp_notif.lock, __func__);
    if (ret) {
        free(arg);
    }
    return ret;
}

API int
nc_server_notif_cert_expiration_thread_stop(int wait)
{
    int r;
    pthread_t tid;

    /* LOCK */
    if (nc_mutex_lock(&server_opts.cert_exp_notif.lock, NC_CERT_EXP_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }
    tid = server_opts.cert_exp_notif.tid;

    if (server_opts.cert_exp_notif.thread_running) {
        /* set the tid and running flag to 0, signal the thread and unlock its mutex */
        server_opts.cert_exp_notif.thread_running = 0;
        server_opts.cert_exp_notif.tid = 0;
        pthread_cond_signal(&server_opts.cert_exp_notif.cond);

        /* UNLOCK */
        nc_mutex_unlock(&server_opts.cert_exp_notif.lock, __func__);
        if (wait) {
            r = pthread_join(tid, NULL);
        } else {
            r = pthread_detach(tid);
        }
        if (r) {
            ERR(NULL, "Stopping the certificate expiration notification thread failed (%s).", strerror(r));
            return 1;
        }
    } else {
        /* thread is not running */
        /* UNLOCK */
        nc_mutex_unlock(&server_opts.cert_exp_notif.lock, __func__);
    }
    return 0;
}

#endif /* NC_ENABLED_SSH_TLS */

int
nc_server_is_mod_ignored(const struct nc_server_config *config, const char *mod_name)
{
    LY_ARRAY_COUNT_TYPE u;

    if (!config) {
        return 0;
    }

    LY_ARRAY_FOR(config->ignored_modules, u) {
        if (!strcmp(config->ignored_modules[u], mod_name)) {
            return 1;
        }
    }

    return 0;
}

API int
nc_server_set_unix_socket_path(const char *endpoint_name, const char *socket_path)
{
    int rc = 0;
    LY_ARRAY_COUNT_TYPE i;
    struct nc_server_unix_path_entry *pentry = NULL;

    NC_CHECK_ARG_RET(NULL, endpoint_name, socket_path, 1);

    /* OPTS WRITE LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_WRITE, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    /* try to see if the path for this endpoint already exists */
    LY_ARRAY_FOR(server_opts.unix_paths, i) {
        if (!strcmp(server_opts.unix_paths[i].endpt_name, endpoint_name)) {
            pentry = &server_opts.unix_paths[i];
            break;
        }
    }
    if (!pentry) {
        /* create a new entry */
        LY_ARRAY_NEW_GOTO(NULL, server_opts.unix_paths, pentry, rc, cleanup);
        pentry->endpt_name = strdup(endpoint_name);
        NC_CHECK_ERRMEM_GOTO(!pentry->endpt_name, rc = 1, cleanup);
    } else {
        /* free the old path */
        free(pentry->path);
    }

    pentry->path = strdup(socket_path);
    NC_CHECK_ERRMEM_GOTO(!pentry->path, rc = 1, cleanup);

cleanup:
    /* OPTS WRITE UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
    return rc;
}

API int
nc_server_get_unix_socket_path(const char *endpoint_name, char **socket_path)
{
    int rc = 0;
    char *p = NULL;
    LY_ARRAY_COUNT_TYPE i;

    NC_CHECK_ARG_RET(NULL, endpoint_name, socket_path, 1);

    *socket_path = NULL;

    /* OPTS READ LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_READ, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    /* try to find the path for this endpoint */
    LY_ARRAY_FOR(server_opts.unix_paths, i) {
        if (!strcmp(server_opts.unix_paths[i].endpt_name, endpoint_name)) {
            p = server_opts.unix_paths[i].path;
            break;
        }
    }

    if (!p) {
        goto cleanup;
    }

    *socket_path = strdup(p);
    NC_CHECK_ERRMEM_GOTO(!*socket_path, rc = 1, cleanup);

cleanup:
    /* OPTS READ UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
    return rc;
}

API int
nc_server_set_unix_socket_dir(const char *dir)
{
    int rc = 0;

    NC_CHECK_ARG_RET(NULL, dir, 1);

    /* OPTS WRITE LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_WRITE, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    free(server_opts.unix_socket_dir);
    server_opts.unix_socket_dir = strdup(dir);
    NC_CHECK_ERRMEM_GOTO(!server_opts.unix_socket_dir, rc = 1, cleanup);

cleanup:
    /* OPTS WRITE UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
    return rc;
}

API int
nc_server_get_unix_socket_dir(char **dir)
{
    int rc = 0;

    NC_CHECK_ARG_RET(NULL, dir, 1);

    *dir = NULL;

    /* OPTS READ LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_READ, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    if (server_opts.unix_socket_dir) {
        *dir = strdup(server_opts.unix_socket_dir);
        NC_CHECK_ERRMEM_GOTO(!*dir, rc = 1, cleanup);
    }

cleanup:
    /* OPTS READ UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
    return rc;
}
