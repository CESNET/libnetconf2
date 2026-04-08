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

#include "session_wrapper.h"

#include <curl/curl.h>
#include <libssh/libssh.h>

#endif /* NC_ENABLED_SSH_TLS */

/* in seconds */
#define NC_CLIENT_HELLO_TIMEOUT 60
#define NC_SERVER_CH_HELLO_TIMEOUT 180

/* in milliseconds */
#define NC_CLOSE_REPLY_TIMEOUT 200

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
nc_time_diff(const struct timespec *ts1, const struct timespec *ts2)
{
    int64_t nsec_diff = 0;

    nsec_diff += (((int64_t)ts1->tv_sec) - ((int64_t)ts2->tv_sec)) * 1000000000L;
    nsec_diff += ((int64_t)ts1->tv_nsec) - ((int64_t)ts2->tv_nsec);

    return nsec_diff / 1000000L;
}

int32_t
nc_timeouttime_cur_diff(const struct timespec *ts)
{
    struct timespec cur;

    nc_timeouttime_get(&cur, 0);

    return nc_time_diff(ts, &cur);
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
nc_privkey_format_to_str(enum nc_privkey_format format)
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
nc_rwlock_lock(pthread_rwlock_t *rwlock, enum nc_rwlock_mode mode, int timeout, const char *func_name)
{
    int ret;
    struct timespec ts_timeout;

    if (!rwlock || (mode == NC_RWLOCK_NONE)) {
        ERRINT;
        return -1;
    }

    if (timeout > 0) {
        /* get absolute time for timeout */
        nc_timeouttime_get(&ts_timeout, timeout);

        /* acquire lock with timeout based on mode */
        if (mode == NC_RWLOCK_READ) {
            ret = pthread_rwlock_clockrdlock(rwlock, COMPAT_CLOCK_ID, &ts_timeout);
        } else {
            ret = pthread_rwlock_clockwrlock(rwlock, COMPAT_CLOCK_ID, &ts_timeout);
        }
    } else if (!timeout) {
        /* try to acquire lock without waiting */
        if (mode == NC_RWLOCK_READ) {
            ret = pthread_rwlock_tryrdlock(rwlock);
        } else {
            ret = pthread_rwlock_trywrlock(rwlock);
        }
    } else {
        /* acquire lock without timeout */
        if (mode == NC_RWLOCK_READ) {
            ret = pthread_rwlock_rdlock(rwlock);
        } else {
            ret = pthread_rwlock_wrlock(rwlock);
        }
    }

    if (ret) {
        if ((ret == EBUSY) || (ret == ETIMEDOUT)) {
            /* timeout */
            return 0;
        }

        ERR(NULL, "%s: failed to lock rwlock in %s mode (%s).", func_name,
                mode == NC_RWLOCK_READ ? "read" : "write", strerror(ret));
        return -1;
    }

    return 1;
}

void
nc_rwlock_unlock(pthread_rwlock_t *rwlock, const char *func_name)
{
    int r;

    if (!rwlock) {
        ERRINT;
        return;
    }

    r = pthread_rwlock_unlock(rwlock);
    if (r) {
        ERR(NULL, "%s: failed to unlock rwlock (%s).", func_name, strerror(r));
    }
}

int
nc_mutex_lock(pthread_mutex_t *mutex, int timeout, const char *func_name)
{
    int ret;
    struct timespec ts_timeout;

    if (!mutex) {
        ERRINT;
        return -1;
    }

    if (timeout > 0) {
        /* get absolute time for timeout */
        nc_timeouttime_get(&ts_timeout, timeout);

        /* acquire lock with timeout */
        ret = pthread_mutex_clocklock(mutex, COMPAT_CLOCK_ID, &ts_timeout);
    } else if (!timeout) {
        /* try to acquire lock without waiting */
        ret = pthread_mutex_trylock(mutex);
    } else {
        /* acquire lock without timeout */
        ret = pthread_mutex_lock(mutex);
    }

    if (ret) {
        if ((ret == EBUSY) || (ret == ETIMEDOUT)) {
            /* timeout */
            return 0;
        }

        ERR(NULL, "%s: failed to lock mutex (%s).", func_name, strerror(ret));
        return -1;
    }

    return 1;
}

void
nc_mutex_unlock(pthread_mutex_t *mutex, const char *func_name)
{
    int r;

    if (!mutex) {
        ERRINT;
        return;
    }

    r = pthread_mutex_unlock(mutex);
    if (r) {
        ERR(NULL, "%s: failed to unlock mutex (%s).", func_name, strerror(r));
    }
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

    return session->version == NC_PROT_VERSION_10 ? 0 : 1;
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

#ifdef NC_ENABLED_SSH_TLS

API const char *
nc_session_ssh_get_banner(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(NULL, session, NULL);

    if (session->ti_type != NC_TI_SSH) {
        ERR(NULL, "Cannot get the SSH banner of a non-SSH session.");
        return NULL;
    }

    if (session->side == NC_SERVER) {
        /* get the banner sent by the client */
        return ssh_get_clientbanner(session->ti.libssh.session);
    } else {
        /* get the banner received from the server */
        return ssh_get_serverbanner(session->ti.libssh.session);
    }
}

#endif

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

/**
 * @brief Send a transport shutdown indication to the peer.
 *
 * Depending on the transport type, this may involve sending transport-specific
 * shutdown signaling so the peer can detect no more outgoing data are expected.
 *
 * @param[in] session Closing NETCONF session.
 */
static void
nc_session_free_send_transport_shutdown(struct nc_session *session)
{
    switch (session->ti_type) {
    case NC_TI_FD:
    case NC_TI_UNIX:
        /* nothing needed - the transport will be closed by caller */
        break;
#ifdef NC_ENABLED_SSH_TLS
    case NC_TI_SSH:
        if (session->ti.libssh.channel) {
            if (session->side == NC_SERVER) {
                /* send SSH channel close - we will not be reading nor writing anymore */
                ssh_channel_close(session->ti.libssh.channel);
            } else if (session->side == NC_CLIENT) {
                /* send SSH channel EOF - we can still receive data from the server, but not send.
                 * we will close the channel later, after receiving the server acknowledges our EOF,
                 * since we are the one initiating it */
                ssh_channel_send_eof(session->ti.libssh.channel);
            }
        }
        break;
    case NC_TI_TLS:
        /* send TLS close_notify alert - we can still receive data from the peer, but not send */
        if (session->ti.tls.session) {
            nc_tls_close_notify_wrap(session->ti.tls.session);
        }
        break;
#endif
    default:
        break;
    }
}

/**
 * @brief Send \<close-session\> to the peer.
 *
 * @param[in] session Closing NETCONF session.
 * @param[out] close_rpc The sent \<close-session\> RPC, caller must free.
 * @return 0 on success, 1 on failure (RPC not sent).
 */
static int
nc_session_free_send_close_session(struct nc_session *session, struct lyd_node **close_rpc)
{
    struct lys_module *ietfnc;
    struct lyd_node *rpc = NULL;
    NC_MSG_TYPE msg_type;

    *close_rpc = NULL;

    ietfnc = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf");
    if (!ietfnc) {
        WRN(session, "Missing ietf-netconf module in context, unable to send <close-session>.");
        return 1;
    }
    if (lyd_new_inner(NULL, ietfnc, "close-session", 0, &rpc)) {
        WRN(session, "Failed to create <close-session> RPC.");
        return 1;
    }

    /* send the RPC */
    msg_type = nc_write_msg_io(session, NC_SESSION_FREE_LOCK_TIMEOUT, NC_MSG_RPC, rpc, NULL);
    if (msg_type != NC_MSG_RPC) {
        WRN(session, "Failed to send <close-session> RPC.");
        lyd_free_tree(rpc);
        return 1;
    } else {
        *close_rpc = rpc;
        return 0;
    }
}

/**
 * @brief Wait for the \<close-session\> reply from the server and process it.
 *
 * @note Waits for at most ::NC_CLOSE_REPLY_TIMEOUT ms.
 *
 * @param[in] session Closing NETCONF session.
 * @param[in] close_rpc The sent \<close-session\> RPC.
 */
static void
nc_session_free_wait_close_session_reply(struct nc_session *session, struct lyd_node *close_rpc)
{
    int32_t timeout;
    struct timespec ts_end;
    struct ly_in *msg = NULL;
    struct lyd_node *envp = NULL;

    nc_timeouttime_get(&ts_end, NC_CLOSE_REPLY_TIMEOUT);

read_msg:
    timeout = nc_timeouttime_cur_diff(&ts_end);
    if (timeout <= 0) {
        /* avoid waiting for the reply for long in case of notification flooding */
        WRN(session, "Timeout for receiving a reply to <close-session> elapsed.");
        return;
    }

    switch (nc_read_msg_poll_io(session, timeout, &msg)) {
    case 1:
        if (!strncmp(ly_in_memory(msg, NULL), "<notification", 13)) {
            /* ignore */
            ly_in_free(msg, 1);
            msg = NULL;
            goto read_msg;
        }
        if (lyd_parse_op(session->ctx, close_rpc, msg, LYD_XML, LYD_TYPE_REPLY_NETCONF, LYD_PARSE_STRICT, &envp, NULL)) {
            WRN(session, "Failed to parse <close-session> reply.");
        } else if (!lyd_child(envp) || strcmp(LYD_NAME(lyd_child(envp)), "ok")) {
            WRN(session, "Reply to <close-session> was not <ok> as expected.");
        }
        lyd_free_tree(envp);
        envp = NULL;
        ly_in_free(msg, 1);
        msg = NULL;
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
}

/**
 * @brief Gracefully close a client session on NETCONF and transport levels.
 *
 * Sends the \<close-session\> RPC to close the NETCONF layer and then sends
 * a transport shutdown indication.
 *
 * @param[in] session Closing NETCONF session.
 */
static void
nc_session_free_client_close_graceful(struct nc_session *session)
{
    int r;
    struct ly_in *msg;
    struct lyd_node *close_rpc = NULL;

    /* receive any leftover messages */
    while (nc_read_msg_poll_io(session, 0, &msg) == 1) {
        ly_in_free(msg, 1);
    }

    /* send the <close-session> RPC */
    r = nc_session_free_send_close_session(session, &close_rpc);

    /* regardless of RPC-send result, send transport shutdown indication */
    nc_session_free_send_transport_shutdown(session);

    if (!r) {
        /* if we sent the RPC successfully, wait for the server reply */
        nc_session_free_wait_close_session_reply(session, close_rpc);
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
    int sock = -1;

    *multisession = 0;

    /* transport implementation cleanup */
    switch (session->ti_type) {
    case NC_TI_FD:
        /* nothing needed - file descriptors were provided by caller,
         * so it is up to the caller to close them correctly
         * TODO use callbacks
         */
        break;

    case NC_TI_UNIX:
        sock = session->ti.unixsock.sock;
        break;

#ifdef NC_ENABLED_SSH_TLS
    case NC_TI_SSH: {
        int r;
        struct nc_session *siter;

        /* There can be multiple NETCONF sessions on the same SSH session (NETCONF session maps to
         * SSH channel). So destroy the SSH session only if there is no other NETCONF session using
         * it. Also, avoid concurrent free by multiple threads of sessions that share the SSH session.
         */
        /* SESSION IO LOCK */
        r = nc_mutex_lock(session->io_lock, NC_SESSION_FREE_LOCK_TIMEOUT, __func__);

        if (session->ti.libssh.channel) {
            if ((session->side == NC_CLIENT) ||
                    ((session->side == NC_SERVER) && (session->term_reason == NC_SESSION_TERM_CLOSED))) {
                /* NC_SERVER: session was properly closed by the client, so he should have sent SSH channel EOF.
                 * Polling here should properly set libssh internal state and avoid libssh WRN log about writing
                 * to a closed channel in ssh_channel_free().
                 * NC_CLIENT: we are waiting for the server to acknowledge our SSH channel EOF
                 * by sending us its own SSH channel EOF. */
                if (ssh_channel_poll_timeout(session->ti.libssh.channel, NC_SESSION_FREE_SSH_POLL_EOF_TIMEOUT, 0) != SSH_EOF) {
                    WRN(session, "Timeout for receiving SSH channel EOF from the peer elapsed.");
                }
            }
            ssh_channel_free(session->ti.libssh.channel);
        }

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

            /* clears sock but does not close it if passed via options (libssh >= 0.10) */
            ssh_disconnect(session->ti.libssh.session);
#if (LIBSSH_VERSION_MAJOR == 0 && LIBSSH_VERSION_MINOR < 10)
            sock = -1;
#endif

            /* closes sock if set */
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
            nc_mutex_unlock(session->io_lock, __func__);
        }
        break;
    }
    case NC_TI_TLS:
        sock = nc_tls_get_fd_wrap(session);

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
    int r, i, rpc_locked = 0;
    int multisession = 0; /* flag for more NETCONF sessions on a single SSH session */
    struct timespec ts;
    NC_STATUS status;

    if (!session) {
        return;
    }

    if ((session->side == NC_SERVER) && (session->flags & NC_SESSION_CALLHOME)) {
        /* CH LOCK, continue on error */
        r = nc_mutex_lock(&session->opts.server.ch_lock, NC_SESSION_CH_LOCK_TIMEOUT, __func__);
    }

    /* store status, so we can check if this session is already closing */
    status = session->status;

    if ((session->side == NC_SERVER) && (session->flags & NC_SESSION_CALLHOME)) {
        /* CH UNLOCK */
        if (r == 1) {
            /* only if we locked it */
            nc_mutex_unlock(&session->opts.server.ch_lock, __func__);
        }
    }

    if (status == NC_STATUS_CLOSING) {
        return;
    }

    if (session->side == NC_CLIENT) {
        if (session->flags & NC_SESSION_CLIENT_MONITORED) {
            /* remove the session from the monitored list */
            nc_client_monitoring_session_stop(session, 1);
        }

        if (ATOMIC_LOAD_RELAXED(session->opts.client.ntf_thread_running)) {
            /* stop notification threads if any */
            nc_client_notification_threads_stop(session);
        }
    }

    if (session->side == NC_SERVER) {
        /* RPC LOCK, not to receive new RPCs while we're freeing the session, continue on error */
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
        /* free queued messages */
        nc_client_msgs_free(session);
    }

    if (session->status == NC_STATUS_RUNNING) {
        /* notify the peer that we're closing the session */
        if (session->side == NC_CLIENT) {
            /* graceful close: <close-session> + transport shutdown indication */
            nc_session_free_client_close_graceful(session);
        } else if (session->side == NC_SERVER) {
            /* only send transport shutdown indication to the peer */
            nc_session_free_send_transport_shutdown(session);
        }
    }

    if ((session->side == NC_SERVER) && (session->flags & NC_SESSION_CALLHOME)) {
        /* CH LOCK */
        nc_mutex_lock(&session->opts.server.ch_lock, NC_SESSION_CH_LOCK_TIMEOUT, __func__);
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
        nc_mutex_unlock(&session->opts.server.ch_lock, __func__);
    }

    /* transport implementation cleanup */
    nc_session_free_transport(session, &multisession);

    /* final cleanup */
    free(session->username);
    free(session->host);
    free(session->path);

    if (session->side == NC_CLIENT) {
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

/**
 * @brief Add a capability into an array.
 *
 * @param[in] capab Capability to add.
 * @param[in,out] cpblts Array of capabilities to add to, terminated with NULL.
 * @param[in,out] count Count of @p cpblts.
 * @return 0 on success;
 * @return -1 on error.
 */
static int
nc_add_cpblt(const char *capab, char ***cpblts, uint32_t *count)
{
    uint32_t i, len;
    char *p;

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
            return 0;
        }
    }

    /* add another capability */
    *cpblts = nc_realloc(*cpblts, (*count + 2) * sizeof **cpblts);
    if (!(*cpblts)) {
        ERRMEM;
        return -1;
    }

    (*cpblts)[*count] = strdup(capab);
    ++(*count);

    /* terminating NULL */
    (*cpblts)[*count] = NULL;

    return 0;
}

/**
 * @brief Get the server capabilities.
 *
 * @param[in] ctx libyang context.
 * @param[in] version YANG version of the schemas to be included in result.
 * @param[in] config_locked Whether the configuration lock is already held or should be acquired.
 * @return Array of capabilities terminated with NULL, NULL on error.
 */
static char **
_nc_server_get_cpblts_version(const struct ly_ctx *ctx, LYS_VERSION version, int config_locked)
{
    char **cpblts;
    const struct lys_module *mod;
    const char *feat;
    int features_count = 0, dev_count = 0, str_len, len;
    uint32_t i, count;
    LY_ARRAY_COUNT_TYPE v;
    char *yl_content_id = NULL;
    uint32_t wd_also_supported, wd_basic_mode;

#define NC_CPBLT_BUF_LEN 4096
    char str[NC_CPBLT_BUF_LEN];

    NC_CHECK_ARG_RET(NULL, ctx, NULL);

    cpblts = malloc(3 * sizeof *cpblts);
    NC_CHECK_ERRMEM_GOTO(!cpblts, , error);
    cpblts[0] = strdup("urn:ietf:params:netconf:base:1.0");
    cpblts[1] = strdup("urn:ietf:params:netconf:base:1.1");
    cpblts[2] = NULL;
    count = 2;

    mod = ly_ctx_get_module_implemented(ctx, "ietf-netconf");
    if (mod) {
        if (lys_feature_value(mod, "writable-running") == LY_SUCCESS) {
            NC_CHECK_GOTO(nc_add_cpblt("urn:ietf:params:netconf:capability:writable-running:1.0", &cpblts, &count), error);
        }
        if (lys_feature_value(mod, "candidate") == LY_SUCCESS) {
            NC_CHECK_GOTO(nc_add_cpblt("urn:ietf:params:netconf:capability:candidate:1.0", &cpblts, &count), error);
            if (lys_feature_value(mod, "confirmed-commit") == LY_SUCCESS) {
                NC_CHECK_GOTO(nc_add_cpblt("urn:ietf:params:netconf:capability:confirmed-commit:1.1", &cpblts, &count), error);
            }
        }
        if (lys_feature_value(mod, "rollback-on-error") == LY_SUCCESS) {
            NC_CHECK_GOTO(nc_add_cpblt("urn:ietf:params:netconf:capability:rollback-on-error:1.0", &cpblts, &count), error);
        }
        if (lys_feature_value(mod, "validate") == LY_SUCCESS) {
            NC_CHECK_GOTO(nc_add_cpblt("urn:ietf:params:netconf:capability:validate:1.1", &cpblts, &count), error);
        }
        if (lys_feature_value(mod, "startup") == LY_SUCCESS) {
            NC_CHECK_GOTO(nc_add_cpblt("urn:ietf:params:netconf:capability:startup:1.0", &cpblts, &count), error);
        }

        /* The URL capability must be set manually using nc_server_set_capability()
         * because of the need for supported protocols to be included.
         * https://tools.ietf.org/html/rfc6241#section-8.8.3
         */
        // if (lys_feature_value(mod, "url") == LY_SUCCESS) {
        // NC_CHECK_GOTO(nc_add_cpblt("urn:ietf:params:netconf:capability:url:1.0", &cpblts, &count), error);
        // }

        if (lys_feature_value(mod, "xpath") == LY_SUCCESS) {
            NC_CHECK_GOTO(nc_add_cpblt("urn:ietf:params:netconf:capability:xpath:1.0", &cpblts, &count), error);
        }
    }

    /* HELLO LOCK */
    if (nc_rwlock_lock(&server_opts.hello_lock, NC_RWLOCK_READ, NC_HELLO_LOCK_TIMEOUT, __func__) != 1) {
        goto error;
    }

    mod = ly_ctx_get_module_implemented(ctx, "ietf-netconf-with-defaults");
    if (mod) {
        wd_basic_mode = server_opts.wd_basic_mode;
        if (!wd_basic_mode) {
            VRB(NULL, "with-defaults capability will not be advertised even though \"ietf-netconf-with-defaults\" "
                    "model is present, unknown basic-mode.");
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
                goto unlock_error;
            }

            wd_also_supported = server_opts.wd_also_supported;
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

                NC_CHECK_GOTO(nc_add_cpblt(str, &cpblts, &count), error);
            }
        }
    }

    /* other capabilities */
    for (i = 0; i < server_opts.capabilities_count; i++) {
        NC_CHECK_GOTO(nc_add_cpblt(server_opts.capabilities[i], &cpblts, &count), error);
    }

    /* models */
    i = 0;
    while ((mod = ly_ctx_get_module_iter(ctx, &i))) {
        if (nc_server_is_mod_ignored(mod->name, config_locked)) {
            /* ignored, not part of the cababilities */
            continue;
        }

        if (!strcmp(mod->name, "ietf-yang-library")) {
            if (!mod->revision || (strcmp(mod->revision, "2016-06-21") && strcmp(mod->revision, "2019-01-04"))) {
                ERR(NULL, "Unknown \"ietf-yang-library\" revision, only 2016-06-21 and 2019-01-04 are supported.");
                goto unlock_error;
            }

            /* get content-id */
            if (server_opts.content_id_clb) {
                yl_content_id = server_opts.content_id_clb(server_opts.content_id_data);
                NC_CHECK_ERRMEM_GOTO(!yl_content_id, , unlock_error);
            } else {
                yl_content_id = malloc(11);
                NC_CHECK_ERRMEM_GOTO(!yl_content_id, , unlock_error);
                sprintf(yl_content_id, "%" PRIu32, ly_ctx_get_change_count(ctx));
            }

            if (!strcmp(mod->revision, "2019-01-04")) {
                /* new one (capab defined in RFC 8526 section 2) */
                sprintf(str, "urn:ietf:params:netconf:capability:yang-library:1.1?revision=%s&content-id=%s",
                        mod->revision, yl_content_id);
                NC_CHECK_GOTO(nc_add_cpblt(str, &cpblts, &count), error);
            } else {
                /* old one (capab defined in RFC 7950 section 5.6.4) */
                sprintf(str, "urn:ietf:params:netconf:capability:yang-library:1.0?revision=%s&module-set-id=%s",
                        mod->revision, yl_content_id);
                NC_CHECK_GOTO(nc_add_cpblt(str, &cpblts, &count), error);
            }
            free(yl_content_id);
            yl_content_id = NULL;
            continue;
        } else if (mod->version != version) {
            /* skip YANG 1.0 or 1.1 modules */
            continue;
        }

        str_len = sprintf(str, "%s?module=%s%s%s", mod->ns, mod->name, mod->revision ? "&revision=" : "",
                mod->revision ? mod->revision : "");

        if (mod->compiled) {
            features_count = 0;
            LY_ARRAY_FOR(mod->compiled->features, v) {
                feat = mod->compiled->features[v];
                if (!features_count) {
                    strcat(str, "&features=");
                    str_len += 10;
                }
                len = strlen(feat);
                if (str_len + 1 + len >= NC_CPBLT_BUF_LEN) {
                    ERRINT;
                    break;
                }
                if (features_count) {
                    strcat(str, ",");
                    ++str_len;
                }
                strcat(str, feat);
                str_len += len;
                features_count++;
            }
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

        NC_CHECK_GOTO(nc_add_cpblt(str, &cpblts, &count), error);
    }

    /* HELLO UNLOCK */
    nc_rwlock_unlock(&server_opts.hello_lock, __func__);

    return cpblts;

unlock_error:
    /* HELLO UNLOCK */
    nc_rwlock_unlock(&server_opts.hello_lock, __func__);

error:
    if (cpblts) {
        for (i = 0; cpblts[i]; ++i) {
            free(cpblts[i]);
        }
        free(cpblts);
    }
    free(yl_content_id);
    return NULL;
}

API char **
nc_server_get_cpblts_version(const struct ly_ctx *ctx, LYS_VERSION version)
{
    return _nc_server_get_cpblts_version(ctx, version, 0);
}

API char **
nc_server_get_cpblts(const struct ly_ctx *ctx)
{
    return _nc_server_get_cpblts_version(ctx, LYS_VERSION_UNDEF, 0);
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

/**
 * @brief Get client-side capabilities.
 *
 * @return Array of capabilities terminated with NULL, NULL on error.
 */
static char **
nc_client_get_cpblts(void)
{
    char **cpblts = NULL;
    uint32_t i, count;

    cpblts = malloc(3 * sizeof *cpblts);
    NC_CHECK_ERRMEM_GOTO(!cpblts, , error);

    cpblts[0] = strdup("urn:ietf:params:netconf:base:1.0");
    NC_CHECK_ERRMEM_GOTO(!cpblts[0], , error);
    cpblts[1] = strdup("urn:ietf:params:netconf:base:1.1");
    NC_CHECK_ERRMEM_GOTO(!cpblts[1], , error);
    cpblts[2] = NULL;
    count = 3;

    /* custom capabilities */
    for (i = 0; i < client_opts.capabilities_count; ++i) {
        NC_CHECK_GOTO(nc_add_cpblt(client_opts.capabilities[i], &cpblts, &count), error);
    }

    return cpblts;

error:
    if (cpblts) {
        for (i = 0; cpblts[i]; ++i) {
            free(cpblts[i]);
        }
        free(cpblts);
    }
    return NULL;
}

/**
 * @brief Send NETCONF hello message on a session.
 *
 * @param[in] session Session to send the message on.
 * @param[in] config_locked Whether the configuration READ lock is already held (only relevant for server side).
 * @return Sent message type.
 */
static NC_MSG_TYPE
nc_send_hello_io(struct nc_session *session, int config_locked)
{
    NC_MSG_TYPE ret;
    int i, timeout_io;
    char **cpblts;
    uint32_t *sid;

    if (session->side == NC_CLIENT) {
        /* client side hello - send only NETCONF base capabilities */
        cpblts = nc_client_get_cpblts();
        if (!cpblts) {
            return NC_MSG_ERROR;
        }

        timeout_io = NC_CLIENT_HELLO_TIMEOUT * 1000;
        sid = NULL;
    } else {
        cpblts = _nc_server_get_cpblts_version(session->ctx, LYS_VERSION_1_0, config_locked);
        if (!cpblts) {
            return NC_MSG_ERROR;
        }

        if (session->flags & NC_SESSION_CALLHOME) {
            timeout_io = NC_SERVER_CH_HELLO_TIMEOUT * 1000;
        } else {
            timeout_io = server_opts.config.idle_timeout ? server_opts.config.idle_timeout * 1000 : -1;
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
        timeout_io = server_opts.config.idle_timeout ? server_opts.config.idle_timeout * 1000 : -1;
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

    type = nc_send_hello_io(session, 0);
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

NC_MSG_TYPE
nc_ch_handshake_io(struct nc_session *session)
{
    NC_MSG_TYPE type;

    if ((session->side != NC_SERVER) || !(session->flags & NC_SESSION_CALLHOME)) {
        ERR(session, "Call Home handshake can only be performed on a server session with Call Home flag set.");
        return NC_MSG_ERROR;
    }

    type = nc_send_hello_io(session, 1);
    if (type != NC_MSG_HELLO) {
        return type;
    }

    type = nc_server_recv_hello_io(session);

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
