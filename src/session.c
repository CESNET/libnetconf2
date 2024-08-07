/**
 * @file session.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 - general session functions
 *
 * @copyright
 * Copyright (c) 2015 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

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
#include "config.h"
#include "log_p.h"
#include "netconf.h"
#include "session_p.h"

#ifdef NC_ENABLED_SSH_TLS

#include <curl/curl.h>
#include <libssh/libssh.h>
#include "session_wrapper.h"

#endif /* NC_ENABLED_SSH_TLS */

/* in seconds */
#define NC_CLIENT_HELLO_TIMEOUT 60
#define NC_SERVER_CH_HELLO_TIMEOUT 180

/* in milliseconds */
#define NC_CLOSE_REPLY_TIMEOUT 200

extern struct nc_server_opts server_opts;

void
nc_timeouttime_get(struct timespec *ts, uint32_t add_ms)
{
    if (clock_gettime(COMPAT_CLOCK_ID, ts) == -1) {
        ERR(NULL, "clock_gettime() failed (%s).", strerror(errno));
        return;
    }

    if (!add_ms) {
        return;
    }

    assert((ts->tv_nsec >= 0) && (ts->tv_nsec < 1000000000L));

    ts->tv_sec += add_ms / 1000;
    ts->tv_nsec += (add_ms % 1000) * 1000000L;

    if (ts->tv_nsec >= 1000000000L) {
        ++ts->tv_sec;
        ts->tv_nsec -= 1000000000L;
    } else if (ts->tv_nsec < 0) {
        --ts->tv_sec;
        ts->tv_nsec += 1000000000L;
    }

    assert((ts->tv_nsec >= 0) && (ts->tv_nsec < 1000000000L));
}

int32_t
nc_timeouttime_cur_diff(const struct timespec *ts)
{
    struct timespec cur;
    int64_t nsec_diff = 0;

    nc_timeouttime_get(&cur, 0);

    nsec_diff += (((int64_t)ts->tv_sec) - ((int64_t)cur.tv_sec)) * 1000000000L;
    nsec_diff += ((int64_t)ts->tv_nsec) - ((int64_t)cur.tv_nsec);

    return nsec_diff / 1000000L;
}

void
nc_realtime_get(struct timespec *ts)
{
    if (clock_gettime(CLOCK_REALTIME, ts)) {
        ERR(NULL, "clock_gettime() failed (%s).", strerror(errno));
        return;
    }
}

int
nc_poll(struct pollfd *pfd, uint16_t pfd_count, int timeout_ms)
{
    int rc;
    struct timespec start_ts;

    if (timeout_ms > 0) {
        /* get current time */
        nc_timeouttime_get(&start_ts, 0);
    }

    do {
        /* poll */
        rc = poll(pfd, pfd_count, timeout_ms);

        if (timeout_ms > 0) {
            /* adjust the timeout by subtracting the elapsed time (relevant in case of EINTR) */
            timeout_ms += nc_timeouttime_cur_diff(&start_ts);
            if (timeout_ms < 0) {
                /* manual timeout */
                rc = 0;
                errno = 0;
                break;
            }
        }
    } while ((rc == -1) && (errno == EINTR));

    if (rc == -1) {
        ERR(NULL, "Poll failed (%s).", strerror(errno));
    }
    return rc;
}

#ifdef NC_ENABLED_SSH_TLS

void *
nc_base64der_to_cert(const char *data)
{
    char *buf = NULL;
    void *cert;

    NC_CHECK_ARG_RET(NULL, data, NULL);

    if (asprintf(&buf, "%s%s%s", "-----BEGIN CERTIFICATE-----\n", data, "\n-----END CERTIFICATE-----") == -1) {
        ERRMEM;
        return NULL;
    }

    cert = nc_tls_pem_to_cert_wrap(buf);
    free(buf);
    return cert;
}

const char *
nc_privkey_format_to_str(NC_PRIVKEY_FORMAT format)
{
    switch (format) {
    case NC_PRIVKEY_FORMAT_RSA:
        return " RSA ";
    case NC_PRIVKEY_FORMAT_EC:
        return " EC ";
    case NC_PRIVKEY_FORMAT_X509:
        return " ";
    case NC_PRIVKEY_FORMAT_OPENSSH:
        return " OPENSSH ";
    default:
        return NULL;
    }
}

int
nc_is_pk_subject_public_key_info(const char *b64)
{
    int ret = 0;
    long len;
    unsigned char *bin = NULL, *tmp;

    /* decode base64 */
    len = nc_base64_decode_wrap(b64, &bin);
    if (len == -1) {
        ret = -1;
        goto cleanup;
    }

    /* for deallocation later */
    tmp = bin;

    /* try to parse the supposed SubjectPublicKeyInfo binary data */
    if (nc_tls_is_der_subpubkey_wrap(tmp, len)) {
        /* success, it's most likely SubjectPublicKeyInfo */
        ret = 1;
    } else {
        /* it's most likely not SubjectPublicKeyInfo */
        ret = 0;
    }

cleanup:
    free(bin);
    return ret;
}

#endif /* NC_ENABLED_SSH_TLS */

int
nc_sock_configure_ka(int sock, const struct nc_keepalives *ka)
{
    int opt;

    opt = ka->enabled;
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof opt) == -1) {
        ERR(NULL, "Failed to set SO_KEEPALIVE (%s).", strerror(errno));
        return -1;
    }

    if (!ka->enabled) {
        return 0;
    }

#ifdef TCP_KEEPIDLE
    opt = ka->idle_time;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof opt) == -1) {
        ERR(NULL, "Failed to set TCP_KEEPIDLE (%s).", strerror(errno));
        return -1;
    }
#endif

#ifdef TCP_KEEPCNT
    opt = ka->max_probes;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof opt) == -1) {
        ERR(NULL, "Failed to set TCP_KEEPCNT (%s).", strerror(errno));
        return -1;
    }
#endif

#ifdef TCP_KEEPINTVL
    opt = ka->probe_interval;
    if (setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof opt) == -1) {
        ERR(NULL, "Failed to set TCP_KEEPINTVL (%s).", strerror(errno));
        return -1;
    }
#endif

    return 0;
}

struct nc_session *
nc_new_session(NC_SIDE side, int shared_ti)
{
    struct nc_session *sess;
    struct timespec ts_cur;

    sess = calloc(1, sizeof *sess);
    if (!sess) {
        return NULL;
    }

    sess->side = side;

    if (side == NC_SERVER) {
        pthread_mutex_init(&sess->opts.server.ntf_status_lock, NULL);
        pthread_mutex_init(&sess->opts.server.rpc_lock, NULL);
        pthread_cond_init(&sess->opts.server.rpc_cond, NULL);

        pthread_mutex_init(&sess->opts.server.ch_lock, NULL);
        pthread_cond_init(&sess->opts.server.ch_cond, NULL);

        /* initialize last_rpc for idle_timeout */
        nc_timeouttime_get(&ts_cur, 0);
        sess->opts.server.last_rpc = ts_cur.tv_sec;
    } else {
        pthread_mutex_init(&sess->opts.client.msgs_lock, NULL);
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
        nc_timeouttime_get(&ts_timeout, timeout);

        /* LOCK */
        ret = pthread_mutex_clocklock(&session->opts.server.rpc_lock, COMPAT_CLOCK_ID, &ts_timeout);
        if (!ret) {
            while (session->opts.server.rpc_inuse) {
                ret = pthread_cond_clockwait(&session->opts.server.rpc_cond, &session->opts.server.rpc_lock,
                        COMPAT_CLOCK_ID, &ts_timeout);
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
        ERR(session, "%s: failed to RPC lock a session (%s).", func, strerror(ret));
        return -1;
    }

    /* ok */
    assert(session->opts.server.rpc_inuse == 0);
    session->opts.server.rpc_inuse = 1;

    /* UNLOCK */
    ret = pthread_mutex_unlock(&session->opts.server.rpc_lock);
    if (ret) {
        /* error */
        ERR(session, "%s: failed to RPC unlock a session (%s).", func, strerror(ret));
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
        nc_timeouttime_get(&ts_timeout, timeout);

        /* LOCK */
        ret = pthread_mutex_clocklock(&session->opts.server.rpc_lock, COMPAT_CLOCK_ID, &ts_timeout);
    } else if (!timeout) {
        /* LOCK */
        ret = pthread_mutex_trylock(&session->opts.server.rpc_lock);
    } else { /* timeout == -1 */
        /* LOCK */
        ret = pthread_mutex_lock(&session->opts.server.rpc_lock);
    }

    if (ret && (ret != EBUSY) && (ret != ETIMEDOUT)) {
        /* error */
        ERR(session, "%s: failed to RPC lock a session (%s).", func, strerror(ret));
        return -1;
    } else if (ret) {
        WRN(session, "%s: session RPC lock timeout, should not happen.", func);
    }

    session->opts.server.rpc_inuse = 0;
    pthread_cond_signal(&session->opts.server.rpc_cond);

    if (!ret) {
        /* UNLOCK */
        ret = pthread_mutex_unlock(&session->opts.server.rpc_lock);
        if (ret) {
            /* error */
            ERR(session, "%s: failed to RPC unlock a session (%s).", func, strerror(ret));
            return -1;
        }
    }

    return 1;
}

int
nc_session_io_lock(struct nc_session *session, int timeout, const char *func)
{
    int ret;
    struct timespec ts_timeout;

    if (timeout > 0) {
        nc_timeouttime_get(&ts_timeout, timeout);

        ret = pthread_mutex_clocklock(session->io_lock, COMPAT_CLOCK_ID, &ts_timeout);
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
        ERR(session, "%s: failed to IO lock a session (%s).", func, strerror(ret));
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
        ERR(session, "%s: failed to IO unlock a session (%s).", func, strerror(ret));
        return -1;
    }

    return 1;
}

int
nc_session_client_msgs_lock(struct nc_session *session, int *timeout, const char *func)
{
    int ret;
    int32_t diff_msec;
    struct timespec ts_timeout, ts_start;

    assert(session->side == NC_CLIENT);

    if (*timeout > 0) {
        /* get current time */
        nc_timeouttime_get(&ts_start, 0);

        nc_timeouttime_get(&ts_timeout, *timeout);

        ret = pthread_mutex_clocklock(&session->opts.client.msgs_lock, COMPAT_CLOCK_ID, &ts_timeout);
        if (!ret) {
            /* update timeout based on what was elapsed */
            diff_msec = nc_timeouttime_cur_diff(&ts_start);
            *timeout -= diff_msec;
        }
    } else if (!*timeout) {
        ret = pthread_mutex_trylock(&session->opts.client.msgs_lock);
    } else { /* timeout == -1 */
        ret = pthread_mutex_lock(&session->opts.client.msgs_lock);
    }

    if (ret) {
        if ((ret == EBUSY) || (ret == ETIMEDOUT)) {
            /* timeout */
            return 0;
        }

        /* error */
        ERR(session, "%s: failed to MSGS lock a session (%s).", func, strerror(ret));
        return -1;
    }

    return 1;
}

int
nc_session_client_msgs_unlock(struct nc_session *session, const char *func)
{
    int ret;

    assert(session->side == NC_CLIENT);

    ret = pthread_mutex_unlock(&session->opts.client.msgs_lock);
    if (ret) {
        /* error */
        ERR(session, "%s: failed to MSGS unlock a session (%s).", func, strerror(ret));
        return -1;
    }

    return 1;
}

API NC_STATUS
nc_session_get_status(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, NC_STATUS_ERR);

    return session->status;
}

API NC_SESSION_TERM_REASON
nc_session_get_term_reason(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, NC_SESSION_TERM_ERR);

    return session->term_reason;
}

API uint32_t
nc_session_get_killed_by(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, 0);

    return session->killed_by;
}

API uint32_t
nc_session_get_id(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, 0);

    return session->id;
}

API int
nc_session_get_version(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, -1);

    return session->version == NC_VERSION_10 ? 0 : 1;
}

API NC_TRANSPORT_IMPL
nc_session_get_ti(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, 0);

    return session->ti_type;
}

API const char *
nc_session_get_username(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, NULL);

    return session->username;
}

API const char *
nc_session_get_host(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, NULL);

    return session->host;
}

API const char *
nc_session_get_path(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, NULL);

    if (session->ti_type != NC_TI_UNIX) {
        return NULL;
    }

    return session->path;
}

API uint16_t
nc_session_get_port(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, 0);

    return session->port;
}

API const struct ly_ctx *
nc_session_get_ctx(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, NULL);

    return session->ctx;
}

API void
nc_session_set_data(struct nc_session *session, void *data)
{
    if (!session) {
        ERRARG(NULL, "session");
        return;
    }

    session->data = data;
}

API void *
nc_session_get_data(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, NULL);

    return session->data;
}

API int
nc_session_is_callhome(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, 0);

    if (session->flags & NC_SESSION_CALLHOME) {
        return 1;
    }

    return 0;
}

NC_MSG_TYPE
nc_send_msg_io(struct nc_session *session, int io_timeout, struct lyd_node *op)
{
    if (session->ctx != LYD_CTX(op)) {
        ERR(session, "RPC \"%s\" was created in different context than that of the session.", LYD_NAME(op));
        return NC_MSG_ERROR;
    }

    return nc_write_msg_io(session, io_timeout, NC_MSG_RPC, op, NULL);
}

/**
 * @brief Send \<close-session\> and read the reply on a session.
 *
 * @param[in] session Closing NETCONF session.
 */
static void
nc_session_free_close_session(struct nc_session *session)
{
    struct ly_in *msg;
    struct lyd_node *close_rpc, *envp;
    const struct lys_module *ietfnc;

    ietfnc = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf");
    if (!ietfnc) {
        WRN(session, "Missing ietf-netconf module in context, unable to send <close-session>.");
        return;
    }
    if (lyd_new_inner(NULL, ietfnc, "close-session", 0, &close_rpc)) {
        WRN(session, "Failed to create <close-session> RPC.");
        return;
    }

    /* send the RPC */
    nc_send_msg_io(session, NC_SESSION_FREE_LOCK_TIMEOUT, close_rpc);

read_msg:
    switch (nc_read_msg_poll_io(session, NC_CLOSE_REPLY_TIMEOUT, &msg)) {
    case 1:
        if (!strncmp(ly_in_memory(msg, NULL), "<notification", 13)) {
            /* ignore */
            ly_in_free(msg, 1);
            goto read_msg;
        }
        if (lyd_parse_op(session->ctx, close_rpc, msg, LYD_XML, LYD_TYPE_REPLY_NETCONF, &envp, NULL)) {
            WRN(session, "Failed to parse <close-session> reply.");
        } else if (!lyd_child(envp) || strcmp(LYD_NAME(lyd_child(envp)), "ok")) {
            WRN(session, "Reply to <close-session> was not <ok> as expected.");
        }
        lyd_free_tree(envp);
        ly_in_free(msg, 1);
        break;
    case 0:
        WRN(session, "Timeout for receiving a reply to <close-session> elapsed.");
        break;
    case -1:
        ERR(session, "Failed to receive a reply to <close-session>.");
        break;
    default:
        /* cannot happen */
        break;
    }
    lyd_free_tree(close_rpc);
}

/**
 * @brief Free transport implementation members of a session.
 *
 * @param[in] session Session to free.
 * @param[out] multisession Whether there are other NC sessions on the same SSH sessions.
 */
static void
nc_session_free_transport(struct nc_session *session, int *multisession)
{
    int connected; /* flag to indicate whether the transport socket is still connected */
    int sock = -1;
    struct nc_session *siter;

    *multisession = 0;
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

#ifdef NC_ENABLED_SSH_TLS
    case NC_TI_SSH: {
        int r;

        if (connected) {
            ssh_channel_send_eof(session->ti.libssh.channel);
            ssh_channel_free(session->ti.libssh.channel);
        }
        /* There can be multiple NETCONF sessions on the same SSH session (NETCONF session maps to
         * SSH channel). So destroy the SSH session only if there is no other NETCONF session using
         * it. Also, avoid concurrent free by multiple threads of sessions that share the SSH session.
         */
        /* SESSION IO LOCK */
        r = nc_session_io_lock(session, NC_SESSION_FREE_LOCK_TIMEOUT, __func__);

        if (session->ti.libssh.next) {
            for (siter = session->ti.libssh.next; siter != session; siter = siter->ti.libssh.next) {
                if (siter->status != NC_STATUS_STARTING) {
                    *multisession = 1;
                    break;
                }
            }
        }

        if (!*multisession) {
            /* it's not multisession yet, but we still need to free the starting sessions */
            if (session->ti.libssh.next) {
                do {
                    siter = session->ti.libssh.next;
                    session->ti.libssh.next = siter->ti.libssh.next;

                    /* free starting SSH NETCONF session (channel will be freed in ssh_free()) */
                    free(siter->username);
                    free(siter->host);
                    if (!(siter->flags & NC_SESSION_SHAREDCTX)) {
                        ly_ctx_destroy((struct ly_ctx *)siter->ctx);
                    }

                    free(siter);
                } while (session->ti.libssh.next != session);
            }
            /* remember sock so we can close it */
            sock = ssh_get_fd(session->ti.libssh.session);
            if (connected) {
                /* does not close sock */
                ssh_disconnect(session->ti.libssh.session);
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
        }

        /* SESSION IO UNLOCK */
        if (r == 1) {
            nc_session_io_unlock(session, __func__);
        }
        break;
    }
    case NC_TI_TLS:
        sock = nc_tls_get_fd_wrap(session);

        if (connected) {
            /* notify the peer that we're shutting down */
            nc_tls_close_notify_wrap(session->ti.tls.session);
        }

        nc_tls_ctx_destroy_wrap(&session->ti.tls.ctx);
        memset(&session->ti.tls.ctx, 0, sizeof session->ti.tls.ctx);
        nc_tls_session_destroy_wrap(session->ti.tls.session);
        session->ti.tls.session = NULL;
        nc_tls_config_destroy_wrap(session->ti.tls.config);
        session->ti.tls.config = NULL;

        if (session->side == NC_SERVER) {
            nc_tls_cert_destroy_wrap(session->opts.server.client_cert);
        }

        break;
#endif /* NC_ENABLED_SSH_TLS */
    case NC_TI_NONE:
        break;
    }

    /* close socket separately */
    if (sock > -1) {
        close(sock);
    }
}

API void
nc_session_free(struct nc_session *session, void (*data_free)(void *))
{
    int r, i, rpc_locked = 0, msgs_locked = 0, timeout;
    int multisession = 0; /* flag for more NETCONF sessions on a single SSH session */
    struct nc_msg_cont *contiter;
    struct ly_in *msg;
    struct timespec ts;
    void *p;

    if (!session || (session->status == NC_STATUS_CLOSING)) {
        return;
    }

    /* stop notification threads if any */
    if ((session->side == NC_CLIENT) && ATOMIC_LOAD_RELAXED(session->opts.client.ntf_thread_running)) {
        /* let the threads know they should quit */
        ATOMIC_STORE_RELAXED(session->opts.client.ntf_thread_running, 0);

        /* wait for them */
        nc_timeouttime_get(&ts, NC_SESSION_FREE_LOCK_TIMEOUT);
        while (ATOMIC_LOAD_RELAXED(session->opts.client.ntf_thread_count)) {
            usleep(NC_TIMEOUT_STEP);
            if (nc_timeouttime_cur_diff(&ts) < 1) {
                ERR(session, "Waiting for notification thread exit failed (timed out).");
                break;
            }
        }
    }

    if (session->side == NC_SERVER) {
        r = nc_session_rpc_lock(session, NC_SESSION_FREE_LOCK_TIMEOUT, __func__);
        if (r == -1) {
            return;
        } else if (r) {
            rpc_locked = 1;
        } else {
            /* else failed to lock it, too bad */
            ERR(session, "Freeing a session while an RPC is being processed.");
        }
    }

    if (session->side == NC_CLIENT) {
        timeout = NC_SESSION_FREE_LOCK_TIMEOUT;

        /* MSGS LOCK */
        r = nc_session_client_msgs_lock(session, &timeout, __func__);
        if (r == -1) {
            return;
        } else if (r) {
            msgs_locked = 1;
        } else {
            /* else failed to lock it, too bad */
            ERR(session, "Freeing a session while messages are being received.");
        }

        /* cleanup message queue */
        for (contiter = session->opts.client.msgs; contiter; ) {
            ly_in_free(contiter->msg, 1);

            p = contiter;
            contiter = contiter->next;
            free(p);
        }

        if (msgs_locked) {
            /* MSGS UNLOCK */
            nc_session_client_msgs_unlock(session, __func__);
        }

        if (session->status == NC_STATUS_RUNNING) {
            /* receive any leftover messages */
            while (nc_read_msg_poll_io(session, 0, &msg) == 1) {
                ly_in_free(msg, 1);
            }

            /* send closing info to the other side */
            nc_session_free_close_session(session);
        }

        /* list of server's capabilities */
        if (session->opts.client.cpblts) {
            for (i = 0; session->opts.client.cpblts[i]; i++) {
                free(session->opts.client.cpblts[i]);
            }
            free(session->opts.client.cpblts);
        }

        /* LY ext data */
#ifdef NC_ENABLED_SSH_TLS
        struct nc_session *siter;

        if ((session->flags & NC_SESSION_SHAREDCTX) && (session->ti_type == NC_TI_SSH) && session->ti.libssh.next) {
            for (siter = session->ti.libssh.next; siter != session; siter = siter->ti.libssh.next) {
                if (siter->status != NC_STATUS_STARTING) {
                    /* move LY ext data to this session */
                    assert(!siter->opts.client.ext_data);
                    siter->opts.client.ext_data = session->opts.client.ext_data;
                    session->opts.client.ext_data = NULL;
                    break;
                }
            }
        } else
#endif /* NC_ENABLED_SSH_TLS */
        {
            lyd_free_siblings(session->opts.client.ext_data);
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

    if ((session->side == NC_SERVER) && (session->flags & NC_SESSION_CH_THREAD)) {
        pthread_cond_signal(&session->opts.server.ch_cond);

        nc_timeouttime_get(&ts, NC_SESSION_FREE_LOCK_TIMEOUT);

        /* wait for CH thread to actually wake up and terminate */
        r = 0;
        while (!r && (session->flags & NC_SESSION_CH_THREAD)) {
            r = pthread_cond_clockwait(&session->opts.server.ch_cond, &session->opts.server.ch_lock, COMPAT_CLOCK_ID, &ts);
        }
        if (r) {
            ERR(session, "Waiting for Call Home thread failed (%s).", strerror(r));
        }
    }

    if ((session->side == NC_SERVER) && (session->flags & NC_SESSION_CALLHOME)) {
        /* CH UNLOCK */
        pthread_mutex_unlock(&session->opts.server.ch_lock);
    }

    /* transport implementation cleanup */
    nc_session_free_transport(session, &multisession);

    /* final cleanup */
    free(session->username);
    free(session->host);
    free(session->path);

    if (session->side == NC_SERVER) {
        pthread_mutex_destroy(&session->opts.server.ntf_status_lock);
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
        ly_ctx_destroy((struct ly_ctx *)session->ctx);
    }

    if (session->side == NC_SERVER) {
        /* free CH synchronization structures */
        pthread_cond_destroy(&session->opts.server.ch_cond);
        pthread_mutex_destroy(&session->opts.server.ch_lock);
    } else {
        pthread_mutex_destroy(&session->opts.client.msgs_lock);
    }

    free(session);
}

static void
add_cpblt(const char *capab, char ***cpblts, int *size, int *count)
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

    (*cpblts)[*count] = capab ? strdup(capab) : NULL;
    ++(*count);
}

API char **
nc_server_get_cpblts_version(const struct ly_ctx *ctx, LYS_VERSION version)
{
    char **cpblts;
    const struct lys_module *mod;
    struct lysp_feature *feat;
    int size = 10, count, features_count = 0, dev_count = 0, str_len, len;
    uint32_t i, u;
    LY_ARRAY_COUNT_TYPE v;
    char *yl_content_id;
    uint32_t wd_also_supported;
    uint32_t wd_basic_mode;

#define NC_CPBLT_BUF_LEN 4096
    char str[NC_CPBLT_BUF_LEN];

    NC_CHECK_ARG_RET(NULL, ctx, NULL);

    cpblts = malloc(size * sizeof *cpblts);
    NC_CHECK_ERRMEM_GOTO(!cpblts, , error);
    cpblts[0] = strdup("urn:ietf:params:netconf:base:1.0");
    cpblts[1] = strdup("urn:ietf:params:netconf:base:1.1");
    count = 2;

    /* capabilities */

    mod = ly_ctx_get_module_implemented(ctx, "ietf-netconf");
    if (mod) {
        if (lys_feature_value(mod, "writable-running") == LY_SUCCESS) {
            add_cpblt("urn:ietf:params:netconf:capability:writable-running:1.0", &cpblts, &size, &count);
        }
        if (lys_feature_value(mod, "candidate") == LY_SUCCESS) {
            add_cpblt("urn:ietf:params:netconf:capability:candidate:1.0", &cpblts, &size, &count);
            if (lys_feature_value(mod, "confirmed-commit") == LY_SUCCESS) {
                add_cpblt("urn:ietf:params:netconf:capability:confirmed-commit:1.1", &cpblts, &size, &count);
            }
        }
        if (lys_feature_value(mod, "rollback-on-error") == LY_SUCCESS) {
            add_cpblt("urn:ietf:params:netconf:capability:rollback-on-error:1.0", &cpblts, &size, &count);
        }
        if (lys_feature_value(mod, "validate") == LY_SUCCESS) {
            add_cpblt("urn:ietf:params:netconf:capability:validate:1.1", &cpblts, &size, &count);
        }
        if (lys_feature_value(mod, "startup") == LY_SUCCESS) {
            add_cpblt("urn:ietf:params:netconf:capability:startup:1.0", &cpblts, &size, &count);
        }

        /* The URL capability must be set manually using nc_server_set_capability()
         * because of the need for supported protocols to be included.
         * https://tools.ietf.org/html/rfc6241#section-8.8.3
         */
        // if (lys_feature_value(mod, "url") == LY_SUCCESS) {
        // add_cpblt("urn:ietf:params:netconf:capability:url:1.0", &cpblts, &size, &count);
        // }

        if (lys_feature_value(mod, "xpath") == LY_SUCCESS) {
            add_cpblt("urn:ietf:params:netconf:capability:xpath:1.0", &cpblts, &size, &count);
        }
    }

    mod = ly_ctx_get_module_implemented(ctx, "ietf-netconf-with-defaults");
    if (mod) {
        wd_basic_mode = ATOMIC_LOAD_RELAXED(server_opts.wd_basic_mode);
        if (!wd_basic_mode) {
            VRB(NULL, "with-defaults capability will not be advertised even though \"ietf-netconf-with-defaults\" model is present, unknown basic-mode.");
        } else {
            strcpy(str, "urn:ietf:params:netconf:capability:with-defaults:1.0");
            switch (wd_basic_mode) {
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

            wd_also_supported = ATOMIC_LOAD_RELAXED(server_opts.wd_also_supported);
            if (wd_also_supported) {
                strcat(str, "&also-supported=");
                if (wd_also_supported & NC_WD_ALL) {
                    strcat(str, "report-all,");
                }
                if (wd_also_supported & NC_WD_ALL_TAG) {
                    strcat(str, "report-all-tagged,");
                }
                if (wd_also_supported & NC_WD_TRIM) {
                    strcat(str, "trim,");
                }
                if (wd_also_supported & NC_WD_EXPLICIT) {
                    strcat(str, "explicit,");
                }
                str[strlen(str) - 1] = '\0';

                add_cpblt(str, &cpblts, &size, &count);
            }
        }
    }

    /* other capabilities */
    for (u = 0; u < server_opts.capabilities_count; u++) {
        add_cpblt(server_opts.capabilities[u], &cpblts, &size, &count);
    }

    /* models */
    u = 0;
    while ((mod = ly_ctx_get_module_iter(ctx, &u))) {
        if (!strcmp(mod->name, "ietf-yang-library")) {
            if (!mod->revision || (strcmp(mod->revision, "2016-06-21") && strcmp(mod->revision, "2019-01-04"))) {
                ERR(NULL, "Unknown \"ietf-yang-library\" revision, only 2016-06-21 and 2019-01-04 are supported.");
                goto error;
            }

            /* get content-id */
            if (server_opts.content_id_clb) {
                yl_content_id = server_opts.content_id_clb(server_opts.content_id_data);
                NC_CHECK_ERRMEM_GOTO(!yl_content_id, , error);
            } else {
                yl_content_id = malloc(11);
                NC_CHECK_ERRMEM_GOTO(!yl_content_id, , error);
                sprintf(yl_content_id, "%u", ly_ctx_get_change_count(ctx));
            }

            if (!strcmp(mod->revision, "2019-01-04")) {
                /* new one (capab defined in RFC 8526 section 2) */
                sprintf(str, "urn:ietf:params:netconf:capability:yang-library:1.1?revision=%s&content-id=%s",
                        mod->revision, yl_content_id);
                add_cpblt(str, &cpblts, &size, &count);
            } else {
                /* old one (capab defined in RFC 7950 section 5.6.4) */
                sprintf(str, "urn:ietf:params:netconf:capability:yang-library:1.0?revision=%s&module-set-id=%s",
                        mod->revision, yl_content_id);
                add_cpblt(str, &cpblts, &size, &count);
            }
            free(yl_content_id);
            continue;
        } else if ((version == LYS_VERSION_1_0) && (mod->parsed->version > version)) {
            /* skip YANG 1.1 modules */
            continue;
        } else if ((version == LYS_VERSION_1_1) && (mod->parsed->version != version)) {
            /* skip YANG 1.0 modules */
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

        add_cpblt(str, &cpblts, &size, &count);
    }

    /* ending NULL capability */
    add_cpblt(NULL, &cpblts, &size, &count);

    return cpblts;

error:
    free(cpblts);
    return NULL;
}

API char **
nc_server_get_cpblts(const struct ly_ctx *ctx)
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
        NC_CHECK_ERRMEM_RET(!*list, -1);
        i = 0;
    }

    LY_LIST_FOR(lyd_child(capabilities), iter) {
        cpblt = (struct lyd_node_opaq *)iter;

        if (strcmp(cpblt->name.name, "capability") || !cpblt->name.module_ns || strcmp(cpblt->name.module_ns, NC_NS_BASE)) {
            ERR(NULL, "Unexpected <%s> element in client's <hello>.", cpblt->name.name);
            return -1;
        }

        /* skip leading/trailing whitespaces */
        for (cpb_start = cpblt->value; isspace(cpb_start[0]); ++cpb_start) {}
        for (cpb_end = cpblt->value + strlen(cpblt->value); (cpb_end > cpblt->value) && isspace(cpb_end[-1]); --cpb_end) {}
        if (!cpb_start[0] || (cpb_end == cpblt->value)) {
            ERR(NULL, "Empty capability \"%s\" received.", cpblt->value);
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
            NC_CHECK_ERRMEM_RET(!(*list)[i], -1);
            i++;
        }
    }

    if (ver == -1) {
        ERR(NULL, "Peer does not support a compatible NETCONF version.");
    }

    return ver;
}

static NC_MSG_TYPE
nc_send_hello_io(struct nc_session *session)
{
    NC_MSG_TYPE ret;
    int i, timeout_io;
    char **cpblts;
    uint32_t *sid;

    if (session->side == NC_CLIENT) {
        /* client side hello - send only NETCONF base capabilities */
        cpblts = malloc(3 * sizeof *cpblts);
        NC_CHECK_ERRMEM_RET(!cpblts, NC_MSG_ERROR);
        cpblts[0] = strdup("urn:ietf:params:netconf:base:1.0");
        cpblts[1] = strdup("urn:ietf:params:netconf:base:1.1");
        cpblts[2] = NULL;

        timeout_io = NC_CLIENT_HELLO_TIMEOUT * 1000;
        sid = NULL;
    } else {
        cpblts = nc_server_get_cpblts_version(session->ctx, LYS_VERSION_1_0);
        if (!cpblts) {
            return NC_MSG_ERROR;
        }

        if (session->flags & NC_SESSION_CALLHOME) {
            timeout_io = NC_SERVER_CH_HELLO_TIMEOUT * 1000;
        } else {
            timeout_io = server_opts.idle_timeout ? server_opts.idle_timeout * 1000 : -1;
        }
        sid = &session->id;
    }

    ret = nc_write_msg_io(session, timeout_io, NC_MSG_HELLO, cpblts, sid);

    for (i = 0; cpblts[i]; ++i) {
        free(cpblts[i]);
    }
    free(cpblts);

    return ret;
}

/**
 * @brief Receive server hello message on the client.
 *
 * @param[in] session Client session to use.
 * @return Received message type.
 */
static NC_MSG_TYPE
nc_client_recv_hello_io(struct nc_session *session)
{
    struct ly_in *msg;
    struct lyd_node *hello = NULL, *iter;
    struct lyd_node_opaq *node;
    int r, ver = -1, flag = 0;
    char *str;
    long long id;
    NC_MSG_TYPE rc = NC_MSG_HELLO;

    r = nc_read_msg_poll_io(session, NC_CLIENT_HELLO_TIMEOUT * 1000, &msg);
    switch (r) {
    case 1:
        /* parse <hello> data */
        if (lyd_parse_data(session->ctx, NULL, msg, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_OPAQ, 0, &hello)) {
            ERR(session, "Failed to parse server <hello>.");
            rc = NC_MSG_ERROR;
            goto cleanup;
        }

        LY_LIST_FOR(lyd_child(hello), iter) {
            node = (struct lyd_node_opaq *)iter;

            if (!node->name.module_ns || strcmp(node->name.module_ns, NC_NS_BASE)) {
                continue;
            } else if (!strcmp(node->name.name, "session-id")) {
                if (!node->value || !strlen(node->value)) {
                    ERR(session, "No value of <session-id> element in server <hello>.");
                    rc = NC_MSG_ERROR;
                    goto cleanup;
                }
                str = NULL;
                id = strtoll(node->value, &str, 10);
                if (*str || (id < 1) || (id > UINT32_MAX)) {
                    ERR(session, "Invalid value of <session-id> element in server <hello>.");
                    rc = NC_MSG_ERROR;
                    goto cleanup;
                }
                session->id = (uint32_t)id;
                continue;
            } else if (strcmp(node->name.name, "capabilities")) {
                ERR(session, "Unexpected <%s> element in server <hello>.", node->name.name);
                rc = NC_MSG_ERROR;
                goto cleanup;
            }

            if (flag) {
                /* multiple capabilities elements */
                ERR(session, "Invalid <hello> message (multiple <capabilities> elements).");
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
            ERR(session, "Missing <session-id> in server <hello>.");
            rc = NC_MSG_ERROR;
            goto cleanup;
        }
        break;
    case 0:
        ERR(session, "Server <hello> timeout elapsed.");
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

/**
 * @brief Receive client hello message on the server.
 *
 * @param[in] session Server session to use.
 * @return Received message type.
 */
static NC_MSG_TYPE
nc_server_recv_hello_io(struct nc_session *session)
{
    struct ly_in *msg;
    struct lyd_node *hello = NULL, *iter;
    struct lyd_node_opaq *node;
    NC_MSG_TYPE rc = NC_MSG_HELLO;
    int r, ver = -1, flag = 0, timeout_io;

    if (session->flags & NC_SESSION_CALLHOME) {
        timeout_io = NC_SERVER_CH_HELLO_TIMEOUT * 1000;
    } else {
        timeout_io = server_opts.idle_timeout ? server_opts.idle_timeout * 1000 : -1;
    }

    r = nc_read_msg_poll_io(session, timeout_io, &msg);
    switch (r) {
    case 1:
        /* parse <hello> data */
        if (lyd_parse_data(session->ctx, NULL, msg, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_OPAQ, 0, &hello)) {
            ERR(session, "Failed to parse client <hello>.");
            rc = NC_MSG_ERROR;
            goto cleanup;
        }

        /* learn NETCONF version */
        LY_LIST_FOR(lyd_child(hello), iter) {
            node = (struct lyd_node_opaq *)iter;

            if (!node->name.module_ns || strcmp(node->name.module_ns, NC_NS_BASE)) {
                continue;
            } else if (strcmp(node->name.name, "capabilities")) {
                ERR(session, "Unexpected <%s> element in client <hello>.", node->name.name);
                rc = NC_MSG_BAD_HELLO;
                goto cleanup;
            }

            if (flag) {
                /* multiple capabilities elements */
                ERR(session, "Invalid <hello> message (multiple <capabilities> elements).");
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
        ERR(session, "Client <hello> timeout elapsed.");
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
        type = nc_client_recv_hello_io(session);
    } else {
        type = nc_server_recv_hello_io(session);
    }

    return type;
}

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief CURL callback for downloading data.
 *
 * @param[in] ptr Downloaded data.
 * @param[in] size Size of one element.
 * @param[in] nmemb Number of elements.
 * @param[in,out] userdata Storage the downloaded data.
 * @return Number of bytes processed.
 */
static size_t
nc_session_curl_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct nc_curl_data *data;

    size = nmemb;

    data = (struct nc_curl_data *)userdata;

    data->data = nc_realloc(data->data, data->size + size);
    NC_CHECK_ERRMEM_RET(!data->data, 0);

    memcpy(&data->data[data->size], ptr, size);
    data->size += size;

    return size;
}

/**
 * @brief Download data using CURL.
 *
 * @param[in] handle CURL handle.
 * @param[in] url URL to download the data from.
 * @return 0 on success, 1 on failure.
 */
static int
nc_session_curl_fetch(CURL *handle, const char *url)
{
    char err_buf[CURL_ERROR_SIZE];

    /* set uri */
    if (curl_easy_setopt(handle, CURLOPT_URL, url)) {
        ERR(NULL, "Setting URI \"%s\" to download CRL from failed.", url);
        return 1;
    }

    /* set err buf */
    if (curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, err_buf)) {
        ERR(NULL, "Setting CURL error buffer option failed.");
        return 1;
    }

    /* download */
    if (curl_easy_perform(handle)) {
        ERR(NULL, "Downloading CRL from \"%s\" failed (%s).", url, err_buf);
        return 1;
    }

    return 0;
}

/**
 * @brief Initialize CURL handle for downloading CRL.
 *
 * @param[out] handle CURL handle.
 * @param[out] data Stores the downloaded data.
 * @return 0 on success, 1 on failure.
 */
static int
nc_session_curl_init(CURL **handle, struct nc_curl_data *data)
{
    NC_CHECK_ARG_RET(NULL, handle, data, -1);

    *handle = NULL;

    *handle = curl_easy_init();
    if (!*handle) {
        ERR(NULL, "Initializing CURL failed.");
        return 1;
    }

    if (curl_easy_setopt(*handle, CURLOPT_WRITEFUNCTION, nc_session_curl_cb)) {
        ERR(NULL, "Setting curl callback failed.");
        return 1;
    }

    if (curl_easy_setopt(*handle, CURLOPT_WRITEDATA, data)) {
        ERR(NULL, "Setting curl callback data failed.");
        return 1;
    }

    return 0;
}

int
nc_session_tls_crl_from_cert_ext_fetch(void *leaf_cert, void *cert_store, void **crl_store)
{
    int ret = 0, uri_count = 0, i;
    CURL *handle = NULL;
    struct nc_curl_data downloaded = {0};
    char **uris = NULL;
    void *crl_store_aux = NULL;

    *crl_store = NULL;

    crl_store_aux = nc_tls_crl_store_new_wrap();
    if (!crl_store_aux) {
        goto cleanup;
    }

    /* init curl */
    ret = nc_session_curl_init(&handle, &downloaded);
    if (ret) {
        goto cleanup;
    }

    /* get all the uris we can, even though some may point to the same CRL */
    ret = nc_server_tls_get_crl_distpoint_uris_wrap(leaf_cert, cert_store, &uris, &uri_count);
    if (ret) {
        goto cleanup;
    }

    if (!uri_count) {
        /* no CRL distribution points, nothing to download */
        goto cleanup;
    }

    for (i = 0; i < uri_count; i++) {
        VRB(NULL, "Downloading CRL from \"%s\".", uris[i]);
        ret = nc_session_curl_fetch(handle, uris[i]);
        if (ret) {
            /* failed to download the CRL from this entry, try the next entry */
            WRN(NULL, "Failed to fetch CRL from \"%s\".", uris[i]);
            continue;
        }

        /* convert the downloaded data to CRL and add it to the store */
        ret = nc_server_tls_add_crl_to_store_wrap(downloaded.data, downloaded.size, crl_store_aux);

        /* free the downloaded data */
        free(downloaded.data);
        downloaded.data = NULL;
        downloaded.size = 0;

        if (ret) {
            goto cleanup;
        }
    }

    *crl_store = crl_store_aux;
    crl_store_aux = NULL;

cleanup:
    for (i = 0; i < uri_count; i++) {
        free(uris[i]);
    }
    free(uris);
    curl_easy_cleanup(handle);
    nc_tls_crl_store_destroy_wrap(crl_store_aux);
    return ret;
}

#endif
