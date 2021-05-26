/**
 * \file session.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 - general session functions
 *
 * Copyright (c) 2015 - 2018 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _DEFAULT_SOURCE

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <libyang/libyang.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "compat.h"
#include "libnetconf.h"
#include "session.h"
#include "session_server.h"

#ifdef NC_ENABLED_SSH

#   include <libssh/libssh.h>

#endif /* NC_ENABLED_SSH */

#if defined (NC_ENABLED_SSH) || defined (NC_ENABLED_TLS)

#   include <openssl/conf.h>
#   include <openssl/err.h>

#endif /* NC_ENABLED_SSH || NC_ENABLED_TLS */

/* in seconds */
#define NC_CLIENT_HELLO_TIMEOUT 60
#define NC_SERVER_HELLO_TIMEOUT 60

/* in milliseconds */
#define NC_CLOSE_REPLY_TIMEOUT 200

extern struct nc_server_opts server_opts;

int
nc_gettimespec_mono(struct timespec *ts)
{
#ifdef CLOCK_MONOTONIC_RAW
    return clock_gettime(CLOCK_MONOTONIC_RAW, ts);
#elif defined (CLOCK_MONOTONIC)
    return clock_gettime(CLOCK_MONOTONIC, ts);
#else
    /* no monotonic clock available, return realtime */
    return nc_gettimespec_real(ts);
#endif
}

int
nc_gettimespec_real(struct timespec *ts)
{
#ifdef CLOCK_REALTIME
    return clock_gettime(CLOCK_REALTIME, ts);
#else
    int rc;
    struct timeval tv;

    rc = gettimeofday(&tv, NULL);
    if (!rc) {
        ts->tv_sec = (time_t)tv.tv_sec;
        ts->tv_nsec = 1000L * (long)tv.tv_usec;
    }
    return rc;
#endif
}

/* ts1 < ts2 -> +, ts1 > ts2 -> -, returns milliseconds */
int32_t
nc_difftimespec(const struct timespec *ts1, const struct timespec *ts2)
{
    int64_t nsec_diff = 0;

    nsec_diff += (((int64_t)ts2->tv_sec) - ((int64_t)ts1->tv_sec)) * 1000000000L;
    nsec_diff += ((int64_t)ts2->tv_nsec) - ((int64_t)ts1->tv_nsec);

    return nsec_diff ? nsec_diff / 1000000L : 0;
}

void
nc_addtimespec(struct timespec *ts, uint32_t msec)
{
    assert((ts->tv_nsec >= 0) && (ts->tv_nsec < 1000000000L));

    ts->tv_sec += msec / 1000;
    ts->tv_nsec += (msec % 1000) * 1000000L;

    if (ts->tv_nsec >= 1000000000L) {
        ++ts->tv_sec;
        ts->tv_nsec -= 1000000000L;
    } else if (ts->tv_nsec < 0) {
        --ts->tv_sec;
        ts->tv_nsec += 1000000000L;
    }

    assert((ts->tv_nsec >= 0) && (ts->tv_nsec < 1000000000L));
}

const char *
nc_keytype2str(NC_SSH_KEY_TYPE type)
{
    switch (type) {
    case NC_SSH_KEY_DSA:
        return "DSA";
    case NC_SSH_KEY_RSA:
        return "RSA";
    case NC_SSH_KEY_ECDSA:
        return "EC";
    default:
        break;
    }

    return NULL;
}

int
nc_sock_enable_keepalive(int sock, struct nc_keepalives *ka)
{
    int opt;

    opt = ka->enabled;
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof opt) == -1) {
        ERR("Could not set SO_KEEPALIVE option (%s).", strerror(errno));
        return -1;
    }
    if (!ka->enabled) {
        return 0;
    }

#ifdef TCP_KEEPIDLE
    opt = ka->idle_time;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof opt) == -1) {
        ERR("Setsockopt failed (%s).", strerror(errno));
        return -1;
    }
#endif

#ifdef TCP_KEEPCNT
    opt = ka->max_probes;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof opt) == -1) {
        ERR("Setsockopt failed (%s).", strerror(errno));
        return -1;
    }
#endif

#ifdef TCP_KEEPINTVL
    opt = ka->probe_interval;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof opt) == -1) {
        ERR("Setsockopt failed (%s).", strerror(errno));
        return -1;
    }
#endif

    return 0;
}

struct nc_session *
nc_new_session(NC_SIDE side, int shared_ti)
{
    struct nc_session *sess;

    sess = calloc(1, sizeof *sess);
    if (!sess) {
        return NULL;
    }

    sess->side = side;

    if (side == NC_SERVER) {
        pthread_mutex_init(&sess->opts.server.rpc_lock, NULL);
        pthread_cond_init(&sess->opts.server.rpc_cond, NULL);
        sess->opts.server.rpc_inuse = 0;

        pthread_mutex_init(&sess->opts.server.ch_lock, NULL);
        pthread_cond_init(&sess->opts.server.ch_cond, NULL);
    }

    if (!shared_ti) {
        sess->io_lock = malloc(sizeof *sess->io_lock);
        if (!sess->io_lock) {
            goto error;
        }
        pthread_mutex_init(sess->io_lock, NULL);
    }

    return sess;

error:
    free(sess);
    return NULL;
}

/*
 * @return 1 - success
 *         0 - timeout
 *        -1 - error
 */
int
nc_session_rpc_lock(struct nc_session *session, int timeout, const char *func)
{
    int ret;
    struct timespec ts_timeout;

    if (session->side != NC_SERVER) {
        ERRINT;
        return -1;
    }

    if (timeout > 0) {
        nc_gettimespec_real(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);

        /* LOCK */
        ret = pthread_mutex_timedlock(&session->opts.server.rpc_lock, &ts_timeout);
        if (!ret) {
            while (session->opts.server.rpc_inuse) {
                ret = pthread_cond_timedwait(&session->opts.server.rpc_cond, &session->opts.server.rpc_lock, &ts_timeout);
                if (ret) {
                    pthread_mutex_unlock(&session->opts.server.rpc_lock);
                    break;
                }
            }
        }
    } else if (!timeout) {
        /* LOCK */
        ret = pthread_mutex_trylock(&session->opts.server.rpc_lock);
        if (!ret) {
            if (session->opts.server.rpc_inuse) {
                pthread_mutex_unlock(&session->opts.server.rpc_lock);
                return 0;
            }
        }
    } else { /* timeout == -1 */
        /* LOCK */
        ret = pthread_mutex_lock(&session->opts.server.rpc_lock);
        if (!ret) {
            while (session->opts.server.rpc_inuse) {
                ret = pthread_cond_wait(&session->opts.server.rpc_cond, &session->opts.server.rpc_lock);
                if (ret) {
                    pthread_mutex_unlock(&session->opts.server.rpc_lock);
                    break;
                }
            }
        }
    }

    if (ret) {
        if ((ret == EBUSY) || (ret == ETIMEDOUT)) {
            /* timeout */
            return 0;
        }

        /* error */
        ERR("%s: failed to RPC lock a session (%s).", func, strerror(ret));
        return -1;
    }

    /* ok */
    assert(session->opts.server.rpc_inuse == 0);
    session->opts.server.rpc_inuse = 1;

    /* UNLOCK */
    ret = pthread_mutex_unlock(&session->opts.server.rpc_lock);
    if (ret) {
        /* error */
        ERR("%s: faile to RPC unlock a session (%s).", func, strerror(ret));
        return -1;
    }

    return 1;
}

int
nc_session_rpc_unlock(struct nc_session *session, int timeout, const char *func)
{
    int ret;
    struct timespec ts_timeout;

    if (session->side != NC_SERVER) {
        ERRINT;
        return -1;
    }

    assert(session->opts.server.rpc_inuse);

    if (timeout > 0) {
        nc_gettimespec_real(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);

        /* LOCK */
        ret = pthread_mutex_timedlock(&session->opts.server.rpc_lock, &ts_timeout);
    } else if (!timeout) {
        /* LOCK */
        ret = pthread_mutex_trylock(&session->opts.server.rpc_lock);
    } else { /* timeout == -1 */
        /* LOCK */
        ret = pthread_mutex_lock(&session->opts.server.rpc_lock);
    }

    if (ret && (ret != EBUSY) && (ret != ETIMEDOUT)) {
        /* error */
        ERR("%s: failed to RPC lock a session (%s).", func, strerror(ret));
        return -1;
    } else if (ret) {
        WRN("%s: session RPC lock timeout, should not happen.");
    }

    session->opts.server.rpc_inuse = 0;
    pthread_cond_signal(&session->opts.server.rpc_cond);

    if (!ret) {
        /* UNLOCK */
        ret = pthread_mutex_unlock(&session->opts.server.rpc_lock);
        if (ret) {
            /* error */
            ERR("%s: failed to RPC unlock a session (%s).", func, strerror(ret));
            return -1;
        }
    }

    return 1;
}

/*
 * @return 1 - success
 *         0 - timeout
 *        -1 - error
 */
int
nc_session_io_lock(struct nc_session *session, int timeout, const char *func)
{
    int ret;
    struct timespec ts_timeout;

    if (timeout > 0) {
        nc_gettimespec_real(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);

        ret = pthread_mutex_timedlock(session->io_lock, &ts_timeout);
    } else if (!timeout) {
        ret = pthread_mutex_trylock(session->io_lock);
    } else { /* timeout == -1 */
        ret = pthread_mutex_lock(session->io_lock);
    }

    if (ret) {
        if ((ret == EBUSY) || (ret == ETIMEDOUT)) {
            /* timeout */
            return 0;
        }

        /* error */
        ERR("%s: failed to IO lock a session (%s).", func, strerror(ret));
        return -1;
    }

    return 1;
}

int
nc_session_io_unlock(struct nc_session *session, const char *func)
{
    int ret;

    ret = pthread_mutex_unlock(session->io_lock);
    if (ret) {
        /* error */
        ERR("%s: failed to IO unlock a session (%s).", func, strerror(ret));
        return -1;
    }

    return 1;
}

API NC_STATUS
nc_session_get_status(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return NC_STATUS_ERR;
    }

    return session->status;
}

API NC_SESSION_TERM_REASON
nc_session_get_term_reason(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return NC_SESSION_TERM_ERR;
    }

    return session->term_reason;
}

API uint32_t
nc_session_get_killed_by(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return 0;
    }

    return session->killed_by;
}

API uint32_t
nc_session_get_id(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return 0;
    }

    return session->id;
}

API int
nc_session_get_version(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return -1;
    }

    return session->version == NC_VERSION_10 ? 0 : 1;
}

API NC_TRANSPORT_IMPL
nc_session_get_ti(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return 0;
    }

    return session->ti_type;
}

API const char *
nc_session_get_username(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return NULL;
    }

    return session->username;
}

API const char *
nc_session_get_host(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return NULL;
    }

    return session->host;
}

API const char *
nc_session_get_path(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return NULL;
    }
    if (session->ti_type != NC_TI_UNIX) {
        return NULL;
    }

    return session->path;
}

API uint16_t
nc_session_get_port(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return 0;
    }

    return session->port;
}

API struct ly_ctx *
nc_session_get_ctx(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return NULL;
    }

    return session->ctx;
}

API void
nc_session_set_data(struct nc_session *session, void *data)
{
    if (!session) {
        ERRARG("session");
        return;
    }

    session->data = data;
}

API void *
nc_session_get_data(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return NULL;
    }

    return session->data;
}

NC_MSG_TYPE
nc_send_msg_io(struct nc_session *session, int io_timeout, struct lyd_node *op)
{
    if (session->ctx != op->schema->module->ctx) {
        ERR("Session %u: RPC \"%s\" was created in different context than that of the session.",
                session->id, op->schema->name);
        return NC_MSG_ERROR;
    }

    return nc_write_msg_io(session, io_timeout, NC_MSG_RPC, op, NULL);
}

API void
nc_session_free(struct nc_session *session, void (*data_free)(void *))
{
    int r, i, rpc_locked = 0, sock = -1;
    int connected; /* flag to indicate whether the transport socket is still connected */
    int multisession = 0; /* flag for more NETCONF sessions on a single SSH session */
    struct nc_session *siter;
    struct nc_msg_cont *contiter;
    struct ly_in *msg;
    struct lyd_node *close_rpc, *envp;
    const struct lys_module *ietfnc;
    struct timespec ts;
    void *p;

    if (!session || (session->status == NC_STATUS_CLOSING)) {
        return;
    }

    /* stop notifications loop if any */
    if ((session->side == NC_CLIENT) && ATOMIC_LOAD(session->opts.client.ntf_tid)) {
        ATOMIC_STORE(session->opts.client.ntf_tid, (uintptr_t)NULL);
        /* the thread now knows it should quit */
    }

    if (session->side == NC_SERVER) {
        r = nc_session_rpc_lock(session, NC_SESSION_FREE_LOCK_TIMEOUT, __func__);
        if (r == -1) {
            return;
        } else if (r) {
            rpc_locked = 1;
        } else {
            /* else failed to lock it, too bad */
            ERR("Session %u: freeing a session while an RPC is being processed.", session->id);
        }
    }

    if (session->side == NC_CLIENT) {
        /* cleanup message queues */
        /* notifications */
        for (contiter = session->opts.client.notifs; contiter; ) {
            ly_in_free(contiter->msg, 1);

            p = contiter;
            contiter = contiter->next;
            free(p);
        }

        /* rpc replies */
        for (contiter = session->opts.client.replies; contiter; ) {
            ly_in_free(contiter->msg, 1);

            p = contiter;
            contiter = contiter->next;
            free(p);
        }

        if (session->status == NC_STATUS_RUNNING) {
            /* send closing info to the other side */
            ietfnc = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf");
            if (!ietfnc) {
                WRN("Session %u: missing ietf-netconf schema in context, unable to send <close-session>.", session->id);
            } else {
                lyd_new_inner(NULL, ietfnc, "close-session", 0, &close_rpc);
                nc_send_msg_io(session, NC_SESSION_FREE_LOCK_TIMEOUT, close_rpc);
                switch (nc_read_msg_poll_io(session, NC_CLOSE_REPLY_TIMEOUT, &msg)) {
                case 1:
                    if (lyd_parse_op(session->ctx, close_rpc, msg, LYD_XML, LYD_TYPE_REPLY_NETCONF, &envp, NULL)) {
                        WRN("Session %u: failed to parse <close-session> reply.", session->id);
                    } else if (!lyd_child(envp) || strcmp(LYD_NAME(lyd_child(envp)), "ok")) {
                        WRN("Session %u: the reply to <close-session> was not <ok> as expected.", session->id);
                    }
                    lyd_free_tree(envp);
                    ly_in_free(msg, 1);
                    break;
                case 0:
                    WRN("Session %u: timeout for receiving a reply to <close-session> elapsed.", session->id);
                    break;
                case -1:
                    ERR("Session %u: failed to receive a reply to <close-session>.", session->id);
                    break;
                default:
                    /* cannot happen */
                    break;
                }
                lyd_free_tree(close_rpc);
            }
        }

        /* list of server's capabilities */
        if (session->opts.client.cpblts) {
            for (i = 0; session->opts.client.cpblts[i]; i++) {
                free(session->opts.client.cpblts[i]);
            }
            free(session->opts.client.cpblts);
        }
    }

    if (session->data && data_free) {
        data_free(session->data);
    }

    if ((session->side == NC_SERVER) && (session->flags & NC_SESSION_CALLHOME)) {
        /* CH LOCK */
        pthread_mutex_lock(&session->opts.server.ch_lock);
    }

    /* mark session for closing */
    session->status = NC_STATUS_CLOSING;

    if ((session->side == NC_SERVER) && (session->flags & NC_SESSION_CALLHOME)) {
        pthread_cond_signal(&session->opts.server.ch_cond);

        nc_gettimespec_real(&ts);
        nc_addtimespec(&ts, NC_SESSION_FREE_LOCK_TIMEOUT);

        /* wait for CH thread to actually wake up and terminate */
        r = 0;
        while (!r && (session->flags & NC_SESSION_CALLHOME)) {
            r = pthread_cond_timedwait(&session->opts.server.ch_cond, &session->opts.server.ch_lock, &ts);
        }

        /* CH UNLOCK */
        pthread_mutex_unlock(&session->opts.server.ch_lock);

        if (r) {
            ERR("Session %u: waiting for Call Home thread failed (%s).", session->id, strerror(r));
        }
    }

    connected = nc_session_is_connected(session);

    /* transport implementation cleanup */
    switch (session->ti_type) {
    case NC_TI_FD:
        /* nothing needed - file descriptors were provided by caller,
         * so it is up to the caller to close them correctly
         * TODO use callbacks
         */
        /* just to avoid compiler warning */
        (void)connected;
        (void)siter;
        break;

    case NC_TI_UNIX:
        sock = session->ti.unixsock.sock;
        (void)connected;
        (void)siter;
        break;

#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
        if (connected) {
            ssh_channel_free(session->ti.libssh.channel);
        }
        /* There can be multiple NETCONF sessions on the same SSH session (NETCONF session maps to
         * SSH channel). So destroy the SSH session only if there is no other NETCONF session using
         * it. Also, avoid concurrent free by multiple threads of sessions that share the SSH session.
         */
        /* SESSION IO LOCK */
        r = nc_session_io_lock(session, NC_SESSION_FREE_LOCK_TIMEOUT, __func__);

        multisession = 0;
        if (session->ti.libssh.next) {
            for (siter = session->ti.libssh.next; siter != session; siter = siter->ti.libssh.next) {
                if (siter->status != NC_STATUS_STARTING) {
                    multisession = 1;
                    break;
                }
            }
        }

        if (!multisession) {
            /* it's not multisession yet, but we still need to free the starting sessions */
            if (session->ti.libssh.next) {
                do {
                    siter = session->ti.libssh.next;
                    session->ti.libssh.next = siter->ti.libssh.next;

                    /* free starting SSH NETCONF session (channel will be freed in ssh_free()) */
                    lydict_remove(session->ctx, session->username);
                    lydict_remove(session->ctx, session->host);
                    if (!(session->flags & NC_SESSION_SHAREDCTX)) {
                        ly_ctx_destroy(session->ctx);
                    }

                    free(siter);
                } while (session->ti.libssh.next != session);
            }
            /* remember sock so we can close it */
            sock = ssh_get_fd(session->ti.libssh.session);
            if (connected) {
                ssh_disconnect(session->ti.libssh.session);
                sock = -1;
            }
            ssh_free(session->ti.libssh.session);
        } else {
            /* remove the session from the list */
            for (siter = session->ti.libssh.next; siter->ti.libssh.next != session; siter = siter->ti.libssh.next) {}
            if (session->ti.libssh.next == siter) {
                /* there will be only one session */
                siter->ti.libssh.next = NULL;
            } else {
                /* there are still multiple sessions, keep the ring list */
                siter->ti.libssh.next = session->ti.libssh.next;
            }
            /* change nc_sshcb_msg() argument, we need a RUNNING session and this one will be freed */
            if (session->flags & NC_SESSION_SSH_MSG_CB) {
                siter = session->ti.libssh.next;
                while (siter && siter->status != NC_STATUS_RUNNING) {
                    if (siter->ti.libssh.next == session) {
                        ERRINT;
                        break;
                    }
                    siter = siter->ti.libssh.next;
                }
                /* siter may be NULL in case all the sessions terminated at the same time (socket was disconnected),
                 * we set session to NULL because we do not expect any new message to arrive */
                ssh_set_message_callback(session->ti.libssh.session, nc_sshcb_msg, siter);
                if (siter) {
                    siter->flags |= NC_SESSION_SSH_MSG_CB;
                }
            }
        }

        /* SESSION IO UNLOCK */
        if (r == 1) {
            nc_session_io_unlock(session, __func__);
        }
        break;
#endif

#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
        /* remember sock so we can close it */
        sock = SSL_get_fd(session->ti.tls);

        if (connected) {
            SSL_shutdown(session->ti.tls);
        }
        SSL_free(session->ti.tls);

        if (session->side == NC_SERVER) {
            X509_free(session->opts.server.client_cert);
        }
        break;
#endif
    case NC_TI_NONE:
        break;
    }

    /* close socket separately */
    if (sock > -1) {
        close(sock);
    }

    lydict_remove(session->ctx, session->username);
    lydict_remove(session->ctx, session->host);
    lydict_remove(session->ctx, session->path);

    /* final cleanup */
    if (session->side == NC_SERVER) {
        if (rpc_locked) {
            nc_session_rpc_unlock(session, NC_SESSION_LOCK_TIMEOUT, __func__);
        }
        pthread_mutex_destroy(&session->opts.server.rpc_lock);
        pthread_cond_destroy(&session->opts.server.rpc_cond);
    }

    if (session->io_lock && !multisession) {
        pthread_mutex_destroy(session->io_lock);
        free(session->io_lock);
    }

    if (!(session->flags & NC_SESSION_SHAREDCTX)) {
        ly_ctx_destroy(session->ctx);
    }

    if (session->side == NC_SERVER) {
        /* free CH synchronization structures */
        pthread_cond_destroy(&session->opts.server.ch_cond);
        pthread_mutex_destroy(&session->opts.server.ch_lock);
    }

    free(session);
}

static void
add_cpblt(struct ly_ctx *ctx, const char *capab, const char ***cpblts, int *size, int *count)
{
    size_t len;
    int i;
    char *p;

    if (capab) {
        /*  check if already present */
        p = strchr(capab, '?');
        if (p) {
            len = p - capab;
        } else {
            len = strlen(capab);
        }
        for (i = 0; i < *count; i++) {
            if (!strncmp((*cpblts)[i], capab, len) && (((*cpblts)[i][len] == '\0') || ((*cpblts)[i][len] == '?'))) {
                /* already present, do not duplicate it */
                return;
            }
        }
    }

    /* add another capability */
    if (*count == *size) {
        *size += 5;
        *cpblts = nc_realloc(*cpblts, *size * sizeof **cpblts);
        if (!(*cpblts)) {
            ERRMEM;
            return;
        }
    }

    if (capab) {
        lydict_insert(ctx, capab, 0, &(*cpblts)[*count]);
    } else {
        (*cpblts)[*count] = NULL;
    }
    ++(*count);
}

API const char **
nc_server_get_cpblts_version(struct ly_ctx *ctx, LYS_VERSION version)
{
    const char **cpblts;
    const struct lys_module *mod;
    struct lysp_feature *feat;
    int size = 10, count, features_count = 0, dev_count = 0, str_len, len;
    uint32_t i, u;
    LY_ARRAY_COUNT_TYPE v;
    char *yl_content_id;

#define NC_CPBLT_BUF_LEN 4096
    char str[NC_CPBLT_BUF_LEN];

    if (!ctx) {
        ERRARG("ctx");
        return NULL;
    }

    cpblts = malloc(size * sizeof *cpblts);
    if (!cpblts) {
        ERRMEM;
        goto error;
    }
    lydict_insert(ctx, "urn:ietf:params:netconf:base:1.0", 0, &cpblts[0]);
    lydict_insert(ctx, "urn:ietf:params:netconf:base:1.1", 0, &cpblts[1]);
    count = 2;

    /* capabilities */

    mod = ly_ctx_get_module_implemented(ctx, "ietf-netconf");
    if (mod) {
        if (lys_feature_value(mod, "writable-running") == LY_SUCCESS) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:writable-running:1.0", &cpblts, &size, &count);
        }
        if (lys_feature_value(mod, "candidate") == LY_SUCCESS) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:candidate:1.0", &cpblts, &size, &count);
            if (lys_feature_value(mod, "confirmed-commit") == LY_SUCCESS) {
                add_cpblt(ctx, "urn:ietf:params:netconf:capability:confirmed-commit:1.1", &cpblts, &size, &count);
            }
        }
        if (lys_feature_value(mod, "rollback-on-error") == LY_SUCCESS) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:rollback-on-error:1.0", &cpblts, &size, &count);
        }
        if (lys_feature_value(mod, "validate") == LY_SUCCESS) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:validate:1.1", &cpblts, &size, &count);
        }
        if (lys_feature_value(mod, "startup") == LY_SUCCESS) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:startup:1.0", &cpblts, &size, &count);
        }

        /* The URL capability must be set manually using nc_server_set_capability()
         * because of the need for supported protocols to be included.
         * https://tools.ietf.org/html/rfc6241#section-8.8.3
         */
        // if (lys_feature_value(mod, "url") == LY_SUCCESS) {
        // add_cpblt(ctx, "urn:ietf:params:netconf:capability:url:1.0", &cpblts, &size, &count);
        // }

        if (lys_feature_value(mod, "xpath") == LY_SUCCESS) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:xpath:1.0", &cpblts, &size, &count);
        }
    }

    mod = ly_ctx_get_module_implemented(ctx, "ietf-netconf-with-defaults");
    if (mod) {
        if (!server_opts.wd_basic_mode) {
            VRB("with-defaults capability will not be advertised even though \"ietf-netconf-with-defaults\" model is present, unknown basic-mode.");
        } else {
            strcpy(str, "urn:ietf:params:netconf:capability:with-defaults:1.0");
            switch (server_opts.wd_basic_mode) {
            case NC_WD_ALL:
                strcat(str, "?basic-mode=report-all");
                break;
            case NC_WD_TRIM:
                strcat(str, "?basic-mode=trim");
                break;
            case NC_WD_EXPLICIT:
                strcat(str, "?basic-mode=explicit");
                break;
            default:
                ERRINT;
                break;
            }

            if (server_opts.wd_also_supported) {
                strcat(str, "&also-supported=");
                if (server_opts.wd_also_supported & NC_WD_ALL) {
                    strcat(str, "report-all,");
                }
                if (server_opts.wd_also_supported & NC_WD_ALL_TAG) {
                    strcat(str, "report-all-tagged,");
                }
                if (server_opts.wd_also_supported & NC_WD_TRIM) {
                    strcat(str, "trim,");
                }
                if (server_opts.wd_also_supported & NC_WD_EXPLICIT) {
                    strcat(str, "explicit,");
                }
                str[strlen(str) - 1] = '\0';

                add_cpblt(ctx, str, &cpblts, &size, &count);
            }
        }
    }

    /* other capabilities */
    for (u = 0; u < server_opts.capabilities_count; u++) {
        add_cpblt(ctx, server_opts.capabilities[u], &cpblts, &size, &count);
    }

    /* models */
    u = 0;
    while ((mod = ly_ctx_get_module_iter(ctx, &u))) {
        if (!strcmp(mod->name, "ietf-yang-library")) {
            if (!mod->revision || (strcmp(mod->revision, "2016-06-21") && strcmp(mod->revision, "2019-01-04"))) {
                ERR("Unknown \"ietf-yang-library\" revision, only 2016-06-21 and 2019-01-04 are supported.");
                goto error;
            }

            /* get content-id */
            if (server_opts.content_id_clb) {
                yl_content_id = server_opts.content_id_clb(server_opts.content_id_data);
                if (!yl_content_id) {
                    ERRMEM;
                    goto error;
                }
            } else {
                yl_content_id = malloc(11);
                if (!yl_content_id) {
                    ERRMEM;
                    goto error;
                }
                sprintf(yl_content_id, "%u", ly_ctx_get_change_count(ctx));
            }

            if (!strcmp(mod->revision, "2019-01-04")) {
                /* new one (capab defined in RFC 8526 section 2) */
                sprintf(str, "urn:ietf:params:netconf:capability:yang-library:1.1?revision=%s&content-id=%s",
                        mod->revision, yl_content_id);
                add_cpblt(ctx, str, &cpblts, &size, &count);
            } else {
                /* old one (capab defined in RFC 7950 section 5.6.4) */
                sprintf(str, "urn:ietf:params:netconf:capability:yang-library:1.0?revision=%s&module-set-id=%s",
                        mod->revision, yl_content_id);
                add_cpblt(ctx, str, &cpblts, &size, &count);
            }
            free(yl_content_id);
            continue;
        } else if ((version == LYS_VERSION_1_0) && (mod->parsed->version > version)) {
            /* skip YANG 1.1 schemas */
            continue;
        } else if ((version == LYS_VERSION_1_1) && (mod->parsed->version != version)) {
            /* skip YANG 1.0 schemas */
            continue;
        }

        str_len = sprintf(str, "%s?module=%s%s%s", mod->ns, mod->name, mod->revision ? "&revision=" : "",
                mod->revision ? mod->revision : "");

        features_count = 0;
        i = 0;
        feat = NULL;
        while ((feat = lysp_feature_next(feat, mod->parsed, &i))) {
            if (!(feat->flags & LYS_FENABLED)) {
                continue;
            }
            if (!features_count) {
                strcat(str, "&features=");
                str_len += 10;
            }
            len = strlen(feat->name);
            if (str_len + 1 + len >= NC_CPBLT_BUF_LEN) {
                ERRINT;
                break;
            }
            if (features_count) {
                strcat(str, ",");
                ++str_len;
            }
            strcat(str, feat->name);
            str_len += len;
            features_count++;
        }

        if (mod->deviated_by) {
            strcat(str, "&deviations=");
            str_len += 12;
            dev_count = 0;
            LY_ARRAY_FOR(mod->deviated_by, v) {
                len = strlen(mod->deviated_by[v]->name);
                if (str_len + 1 + len >= NC_CPBLT_BUF_LEN) {
                    ERRINT;
                    break;
                }
                if (dev_count) {
                    strcat(str, ",");
                    ++str_len;
                }
                strcat(str, mod->deviated_by[v]->name);
                str_len += len;
                dev_count++;
            }
        }

        add_cpblt(ctx, str, &cpblts, &size, &count);
    }

    /* ending NULL capability */
    add_cpblt(ctx, NULL, &cpblts, &size, &count);

    return cpblts;

error:
    free(cpblts);
    return NULL;
}

API const char **
nc_server_get_cpblts(struct ly_ctx *ctx)
{
    return nc_server_get_cpblts_version(ctx, LYS_VERSION_UNDEF);
}

static int
parse_cpblts(struct lyd_node *capabilities, char ***list)
{
    struct lyd_node *iter;
    struct lyd_node_opaq *cpblt;
    int ver = -1, i = 0;
    const char *cpb_start, *cpb_end;

    if (list) {
        /* get the storage for server's capabilities */
        LY_LIST_FOR(lyd_child(capabilities), iter) {
            i++;
        }
        /* last item remains NULL */
        *list = calloc(i + 1, sizeof **list);
        if (!*list) {
            ERRMEM;
            return -1;
        }
        i = 0;
    }

    LY_LIST_FOR(lyd_child(capabilities), iter) {
        cpblt = (struct lyd_node_opaq *)iter;

        if (strcmp(cpblt->name.name, "capability") || !cpblt->name.module_ns || strcmp(cpblt->name.module_ns, NC_NS_BASE)) {
            ERR("Unexpected <%s> element in client's <hello>.", cpblt->name.name);
            return -1;
        }

        /* skip leading/trailing whitespaces */
        for (cpb_start = cpblt->value; isspace(cpb_start[0]); ++cpb_start) {}
        for (cpb_end = cpblt->value + strlen(cpblt->value); (cpb_end > cpblt->value) && isspace(cpb_end[-1]); --cpb_end) {}
        if (!cpb_start[0] || (cpb_end == cpblt->value)) {
            ERR("Empty capability \"%s\" received.", cpblt->value);
            return -1;
        }

        /* detect NETCONF version */
        if ((ver < 0) && !strncmp(cpb_start, "urn:ietf:params:netconf:base:1.0", cpb_end - cpb_start)) {
            ver = 0;
        } else if ((ver < 1) && !strncmp(cpb_start, "urn:ietf:params:netconf:base:1.1", cpb_end - cpb_start)) {
            ver = 1;
        }

        /* store capabilities */
        if (list) {
            (*list)[i] = strndup(cpb_start, cpb_end - cpb_start);
            if (!(*list)[i]) {
                ERRMEM;
                return -1;
            }
            i++;
        }
    }

    if (ver == -1) {
        ERR("Peer does not support a compatible NETCONF version.");
    }

    return ver;
}

static NC_MSG_TYPE
nc_send_hello_io(struct nc_session *session)
{
    NC_MSG_TYPE ret;
    int i, io_timeout;
    const char **cpblts;
    uint32_t *sid;

    if (session->side == NC_CLIENT) {
        /* client side hello - send only NETCONF base capabilities */
        cpblts = malloc(3 * sizeof *cpblts);
        if (!cpblts) {
            ERRMEM;
            return NC_MSG_ERROR;
        }
        lydict_insert(session->ctx, "urn:ietf:params:netconf:base:1.0", 0, &cpblts[0]);
        lydict_insert(session->ctx, "urn:ietf:params:netconf:base:1.1", 0, &cpblts[1]);
        cpblts[2] = NULL;

        io_timeout = NC_CLIENT_HELLO_TIMEOUT * 1000;
        sid = NULL;
    } else {
        cpblts = nc_server_get_cpblts_version(session->ctx, LYS_VERSION_1_0);
        if (!cpblts) {
            return NC_MSG_ERROR;
        }

        io_timeout = NC_SERVER_HELLO_TIMEOUT * 1000;
        sid = &session->id;
    }

    ret = nc_write_msg_io(session, io_timeout, NC_MSG_HELLO, cpblts, sid);

    for (i = 0; cpblts[i]; ++i) {
        lydict_remove(session->ctx, cpblts[i]);
    }
    free(cpblts);

    return ret;
}

static NC_MSG_TYPE
nc_recv_client_hello_io(struct nc_session *session)
{
    struct ly_in *msg;
    struct lyd_node *hello = NULL, *iter;
    struct lyd_node_opaq *node;
    int r, ver = -1, flag = 0;
    char *str;
    long long int id;
    NC_MSG_TYPE rc = NC_MSG_HELLO;

    r = nc_read_msg_poll_io(session, NC_CLIENT_HELLO_TIMEOUT * 1000, &msg);
    switch (r) {
    case 1:
        /* parse <hello> data */
        if (lyd_parse_data(session->ctx, NULL, msg, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_OPAQ, 0, &hello)) {
            ERR("Failed to parse server <hello>.");
            rc = NC_MSG_ERROR;
            goto cleanup;
        }

        LY_LIST_FOR(lyd_child(hello), iter) {
            node = (struct lyd_node_opaq *)iter;

            if (!node->name.module_ns || strcmp(node->name.module_ns, NC_NS_BASE)) {
                continue;
            } else if (!strcmp(node->name.name, "session-id")) {
                if (!node->value || !strlen(node->value)) {
                    ERR("No value of <session-id> element in server <hello>.");
                    rc = NC_MSG_ERROR;
                    goto cleanup;
                }
                str = NULL;
                id = strtoll(node->value, &str, 10);
                if (*str || (id < 1) || (id > UINT32_MAX)) {
                    ERR("Invalid value of <session-id> element in server <hello>.");
                    rc = NC_MSG_ERROR;
                    goto cleanup;
                }
                session->id = (uint32_t)id;
                continue;
            } else if (strcmp(node->name.name, "capabilities")) {
                ERR("Unexpected <%s> element in server <hello>.", node->name.name);
                rc = NC_MSG_ERROR;
                goto cleanup;
            }

            if (flag) {
                /* multiple capabilities elements */
                ERR("Invalid <hello> message (multiple <capabilities> elements).");
                rc = NC_MSG_ERROR;
                goto cleanup;
            }
            flag = 1;

            if ((ver = parse_cpblts(&node->node, &session->opts.client.cpblts)) < 0) {
                rc = NC_MSG_ERROR;
                goto cleanup;
            }
            session->version = ver;
        }

        if (!session->id) {
            ERR("Missing <session-id> in server <hello>.");
            rc = NC_MSG_ERROR;
            goto cleanup;
        }
        break;
    case 0:
        ERR("Server <hello> timeout elapsed.");
        rc = NC_MSG_WOULDBLOCK;
        break;
    default:
        rc = NC_MSG_ERROR;
        break;
    }

cleanup:
    ly_in_free(msg, 1);
    lyd_free_tree(hello);
    return rc;
}

static NC_MSG_TYPE
nc_recv_server_hello_io(struct nc_session *session)
{
    struct ly_in *msg;
    struct lyd_node *hello = NULL, *iter;
    struct lyd_node_opaq *node;
    NC_MSG_TYPE rc = NC_MSG_HELLO;
    int r, ver = -1, flag = 0, timeout_io;

    timeout_io = server_opts.hello_timeout ? server_opts.hello_timeout * 1000 : NC_SERVER_HELLO_TIMEOUT * 1000;
    r = nc_read_msg_poll_io(session, timeout_io, &msg);
    switch (r) {
    case 1:
        /* parse <hello> data */
        if (lyd_parse_data(session->ctx, NULL, msg, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_OPAQ, 0, &hello)) {
            ERR("Failed to parse client <hello>.");
            rc = NC_MSG_ERROR;
            goto cleanup;
        }

        /* learn NETCONF version */
        LY_LIST_FOR(lyd_child(hello), iter) {
            node = (struct lyd_node_opaq *)iter;

            if (!node->name.module_ns || strcmp(node->name.module_ns, NC_NS_BASE)) {
                continue;
            } else if (strcmp(node->name.name, "capabilities")) {
                ERR("Unexpected <%s> element in client <hello>.", node->name.name);
                rc = NC_MSG_BAD_HELLO;
                goto cleanup;
            }

            if (flag) {
                /* multiple capabilities elements */
                ERR("Invalid <hello> message (multiple <capabilities> elements).");
                rc = NC_MSG_BAD_HELLO;
                goto cleanup;
            }
            flag = 1;

            if ((ver = parse_cpblts(&node->node, NULL)) < 0) {
                rc = NC_MSG_BAD_HELLO;
                goto cleanup;
            }
            session->version = ver;
        }
        break;
    case 0:
        ERR("Client <hello> timeout elapsed.");
        rc = NC_MSG_WOULDBLOCK;
        break;
    default:
        rc = NC_MSG_ERROR;
        break;
    }

cleanup:
    ly_in_free(msg, 1);
    lyd_free_tree(hello);
    return rc;
}

NC_MSG_TYPE
nc_handshake_io(struct nc_session *session)
{
    NC_MSG_TYPE type;

    type = nc_send_hello_io(session);
    if (type != NC_MSG_HELLO) {
        return type;
    }

    if (session->side == NC_CLIENT) {
        type = nc_recv_client_hello_io(session);
    } else {
        type = nc_recv_server_hello_io(session);
    }

    return type;
}

#ifdef NC_ENABLED_SSH

static void
nc_ssh_init(void)
{
#if (LIBSSH_VERSION_INT < SSH_VERSION_INT(0, 8, 0))
    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    ssh_init();
#endif
}

static void
nc_ssh_destroy(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    FIPS_mode_set(0);
    CONF_modules_unload(1);
    nc_thread_destroy();
#endif

#if (LIBSSH_VERSION_INT < SSH_VERSION_INT(0, 8, 0))
    ssh_finalize();
#endif
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0

struct CRYPTO_dynlock_value {
    pthread_mutex_t lock;
};

static struct CRYPTO_dynlock_value *
tls_dyn_create_func(const char *UNUSED(file), int UNUSED(line))
{
    struct CRYPTO_dynlock_value *value;

    value = malloc(sizeof *value);
    if (!value) {
        ERRMEM;
        return NULL;
    }
    pthread_mutex_init(&value->lock, NULL);

    return value;
}

static void
tls_dyn_lock_func(int mode, struct CRYPTO_dynlock_value *l, const char *UNUSED(file), int UNUSED(line))
{
    /* mode can also be CRYPTO_READ or CRYPTO_WRITE, but all the examples
     * I found ignored this fact, what do I know... */
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&l->lock);
    } else {
        pthread_mutex_unlock(&l->lock);
    }
}

static void
tls_dyn_destroy_func(struct CRYPTO_dynlock_value *l, const char *UNUSED(file), int UNUSED(line))
{
    pthread_mutex_destroy(&l->lock);
    free(l);
}

#endif

#endif /* NC_ENABLED_TLS */

#if defined (NC_ENABLED_TLS) && !defined (NC_ENABLED_SSH)

#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
static pthread_mutex_t *tls_locks;

static void
tls_thread_locking_func(int mode, int n, const char *UNUSED(file), int UNUSED(line))
{
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(tls_locks + n);
    } else {
        pthread_mutex_unlock(tls_locks + n);
    }
}

static void
tls_thread_id_func(CRYPTO_THREADID *tid)
{
    CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

#endif

static void
nc_tls_init(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    SSL_library_init();

    int i;

    tls_locks = malloc(CRYPTO_num_locks() * sizeof *tls_locks);
    if (!tls_locks) {
        ERRMEM;
        return;
    }
    for (i = 0; i < CRYPTO_num_locks(); ++i) {
        pthread_mutex_init(tls_locks + i, NULL);
    }

    CRYPTO_THREADID_set_callback(tls_thread_id_func);
    CRYPTO_set_locking_callback(tls_thread_locking_func);

    CRYPTO_set_dynlock_create_callback(tls_dyn_create_func);
    CRYPTO_set_dynlock_lock_callback(tls_dyn_lock_func);
    CRYPTO_set_dynlock_destroy_callback(tls_dyn_destroy_func);
#endif
}

static void
nc_tls_destroy(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    FIPS_mode_set(0);
    CRYPTO_cleanup_all_ex_data();
    nc_thread_destroy();
    EVP_cleanup();
    ERR_free_strings();
#if OPENSSL_VERSION_NUMBER < 0x10002000L // < 1.0.2
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
#elif OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    SSL_COMP_free_compression_methods();
#endif

    int i;

    CRYPTO_THREADID_set_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); ++i) {
        pthread_mutex_destroy(tls_locks + i);
    }
    free(tls_locks);

    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);
#endif
}

#endif /* NC_ENABLED_TLS && !NC_ENABLED_SSH */

#if defined (NC_ENABLED_SSH) && defined (NC_ENABLED_TLS)

static void
nc_ssh_tls_init(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    SSL_library_init();
#endif

    nc_ssh_init();

#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    CRYPTO_set_dynlock_create_callback(tls_dyn_create_func);
    CRYPTO_set_dynlock_lock_callback(tls_dyn_lock_func);
    CRYPTO_set_dynlock_destroy_callback(tls_dyn_destroy_func);
#endif
}

static void
nc_ssh_tls_destroy(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    ERR_free_strings();
# if OPENSSL_VERSION_NUMBER < 0x10002000L // < 1.0.2
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
# elif OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    SSL_COMP_free_compression_methods();
# endif
#endif

    nc_ssh_destroy();

#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);
#endif
}

#endif /* NC_ENABLED_SSH && NC_ENABLED_TLS */

#if defined (NC_ENABLED_SSH) || defined (NC_ENABLED_TLS)

API void
nc_thread_destroy(void)
{
    /* caused data-races and seems not neccessary for avoiding valgrind reachable memory */
    // CRYPTO_cleanup_all_ex_data();

#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    CRYPTO_THREADID crypto_tid;

    CRYPTO_THREADID_current(&crypto_tid);
    ERR_remove_thread_state(&crypto_tid);
#endif
}

#endif /* NC_ENABLED_SSH || NC_ENABLED_TLS */

void
nc_init(void)
{
#if defined (NC_ENABLED_SSH) && defined (NC_ENABLED_TLS)
    nc_ssh_tls_init();
#elif defined (NC_ENABLED_SSH)
    nc_ssh_init();
#elif defined (NC_ENABLED_TLS)
    nc_tls_init();
#endif
}

void
nc_destroy(void)
{
#if defined (NC_ENABLED_SSH) && defined (NC_ENABLED_TLS)
    nc_ssh_tls_destroy();
#elif defined (NC_ENABLED_SSH)
    nc_ssh_destroy();
#elif defined (NC_ENABLED_TLS)
    nc_tls_destroy();
#endif
}
