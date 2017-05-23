/**
 * \file session.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 - general session functions
 *
 * Copyright (c) 2015 - 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <libyang/libyang.h>

#include "session.h"
#include "libnetconf.h"
#include "session_server.h"

#ifdef NC_ENABLED_SSH

#   include <libssh/libssh.h>

#endif /* NC_ENABLED_SSH */

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)

#   include <openssl/engine.h>
#   include <openssl/conf.h>
#   include <openssl/err.h>

#endif /* NC_ENABLED_SSH || NC_ENABLED_TLS */

/* in seconds */
#define NC_CLIENT_HELLO_TIMEOUT 60

/* in milliseconds */
#define NC_CLOSE_REPLY_TIMEOUT 200

extern struct nc_server_opts server_opts;

int
nc_gettimespec(struct timespec *ts)
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
nc_difftimespec(struct timespec *ts1, struct timespec *ts2)
{
    int64_t nsec_diff = 0;

    nsec_diff += (((int64_t)ts2->tv_sec) - ((int64_t)ts1->tv_sec)) * 1000000000L;
    nsec_diff += ((int64_t)ts2->tv_nsec) - ((int64_t)ts1->tv_nsec);

    return (nsec_diff ? nsec_diff / 1000000L : 0);
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

#ifndef HAVE_PTHREAD_MUTEX_TIMEDLOCK
int
pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abstime)
{
    int32_t diff;
    int rc;
    struct timespec cur, dur;

    /* Try to acquire the lock and, if we fail, sleep for 5ms. */
    while ((rc = pthread_mutex_trylock(mutex)) == EBUSY) {
        nc_gettimespec(&cur);

        if ((diff = nc_difftimespec(&cur, abstime)) < 1) {
            /* timeout */
            break;
        } else if (diff < 5) {
            /* sleep until timeout */
            dur = *abstime;
        } else {
            /* sleep 5 ms */
            dur.tv_sec = 0;
            dur.tv_nsec = 5000000;
        }

        nanosleep(&dur, NULL);
    }

    return rc;
}
#endif

struct nc_session *
nc_new_session(int not_allocate_ti)
{
    struct nc_session *sess;

    sess = calloc(1, sizeof *sess);
    if (!sess) {
        return NULL;
    }

    if (!not_allocate_ti) {
        sess->ti_lock = malloc(sizeof *sess->ti_lock);
        sess->ti_cond = malloc(sizeof *sess->ti_cond);
        sess->ti_inuse = malloc(sizeof *sess->ti_inuse);
        if (!sess->ti_lock || !sess->ti_cond || !sess->ti_inuse) {
            free(sess->ti_lock);
            free(sess->ti_cond);
            free((int *)sess->ti_inuse);
            free(sess);
            return NULL;
        }
    }

    return sess;
}

/*
 * @return 1 - success
 *         0 - timeout
 *        -1 - error
 */
int
nc_session_lock(struct nc_session *session, int timeout, const char *func)
{
    int ret;
    struct timespec ts_timeout;

    if (timeout > 0) {
        nc_gettimespec(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);

        /* LOCK */
        ret = pthread_mutex_timedlock(session->ti_lock, &ts_timeout);
        if (!ret) {
            while (*session->ti_inuse) {
                ret = pthread_cond_timedwait(session->ti_cond, session->ti_lock, &ts_timeout);
                if (ret) {
                    pthread_mutex_unlock(session->ti_lock);
                    break;
                }
            }
        }
    } else if (!timeout) {
        if (*session->ti_inuse) {
            /* immediate timeout */
            return 0;
        }

        /* LOCK */
        ret = pthread_mutex_trylock(session->ti_lock);
        if (!ret) {
            /* be extra careful, someone could have been faster */
            if (*session->ti_inuse) {
                pthread_mutex_unlock(session->ti_lock);
                return 0;
            }
        }
    } else { /* timeout == -1 */
        /* LOCK */
        ret = pthread_mutex_lock(session->ti_lock);
        if (!ret) {
            while (*session->ti_inuse) {
                ret = pthread_cond_wait(session->ti_cond, session->ti_lock);
                if (ret) {
                    pthread_mutex_unlock(session->ti_lock);
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
        ERR("%s: failed to lock a session (%s).", func, strerror(ret));
        return -1;
    }

    /* ok */
    assert(*session->ti_inuse == 0);
    *session->ti_inuse = 1;

    /* UNLOCK */
    ret = pthread_mutex_unlock(session->ti_lock);
    if (ret) {
        /* error */
        ERR("%s: faile to unlock a session (%s).", func, strerror(ret));
        return -1;
    }

    return 1;
}

int
nc_session_unlock(struct nc_session *session, int timeout, const char *func)
{
    int ret;
    struct timespec ts_timeout;

    assert(*session->ti_inuse);

    if (timeout > 0) {
        nc_gettimespec(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);

        /* LOCK */
        ret = pthread_mutex_timedlock(session->ti_lock, &ts_timeout);
    } else if (!timeout) {
        /* LOCK */
        ret = pthread_mutex_trylock(session->ti_lock);
    } else { /* timeout == -1 */
        /* LOCK */
        ret = pthread_mutex_lock(session->ti_lock);
    }

    if (ret && (ret != EBUSY) && (ret != ETIMEDOUT)) {
        /* error */
        ERR("%s: failed to lock a session (%s).", func, strerror(ret));
        return -1;
    } else if (ret) {
        WRN("%s: session lock timeout, should not happen.");
    }

    *session->ti_inuse = 0;
    pthread_cond_signal(session->ti_cond);

    if (!ret) {
        /* UNLOCK */
        ret = pthread_mutex_unlock(session->ti_lock);
        if (ret) {
            /* error */
            ERR("%s: failed to unlock a session (%s).", func, strerror(ret));
            return -1;
        }
    }

    return 1;
}

API NC_STATUS
nc_session_get_status(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return 0;
    }

    return session->status;
}

API NC_SESSION_TERM_REASON
nc_session_get_termreason(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return 0;
    }

    return session->term_reason;
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

    return (session->version == NC_VERSION_10 ? 0 : 1);
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
nc_send_msg(struct nc_session *session, struct lyd_node *op)
{
    int r;

    if (session->ctx != op->schema->module->ctx) {
        ERR("Session %u: RPC \"%s\" was created in different context than that of the session.",
            session->id, op->schema->name);
        return NC_MSG_ERROR;
    }

    r = nc_write_msg(session, NC_MSG_RPC, op, NULL);

    if (r) {
        return NC_MSG_ERROR;
    }

    return NC_MSG_RPC;
}

API void
nc_session_free(struct nc_session *session, void (*data_free)(void *))
{
    int r, i, locked;
    int connected; /* flag to indicate whether the transport socket is still connected */
    int multisession = 0; /* flag for more NETCONF sessions on a single SSH session */
    pthread_t tid;
    struct nc_session *siter;
    struct nc_msg_cont *contiter;
    struct lyxml_elem *rpl, *child;
    struct lyd_node *close_rpc;
    const struct lys_module *ietfnc;
    void *p;

    if (!session || (session->status == NC_STATUS_CLOSING)) {
        return;
    }

    /* stop notifications loop if any */
    if ((session->side == NC_CLIENT) && session->opts.client.ntf_tid) {
        tid = *session->opts.client.ntf_tid;
        free((pthread_t *)session->opts.client.ntf_tid);
        session->opts.client.ntf_tid = NULL;
        /* the thread now knows it should quit */

        pthread_join(tid, NULL);
    }

    if (session->ti_lock) {
        r = nc_session_lock(session, NC_SESSION_FREE_LOCK_TIMEOUT, __func__);
        if (r == -1) {
            return;
        } else if (!r) {
            /* we failed to lock it, too bad */
            locked = 0;
        } else {
            locked = 1;
        }
    } else {
        ERRINT;
        return;
    }

    if ((session->side == NC_CLIENT) && (session->status == NC_STATUS_RUNNING) && locked) {
        /* cleanup message queues */
        /* notifications */
        for (contiter = session->opts.client.notifs; contiter; ) {
            lyxml_free(session->ctx, contiter->msg);

            p = contiter;
            contiter = contiter->next;
            free(p);
        }

        /* rpc replies */
        for (contiter = session->opts.client.replies; contiter; ) {
            lyxml_free(session->ctx, contiter->msg);

            p = contiter;
            contiter = contiter->next;
            free(p);
        }

        /* send closing info to the other side */
        ietfnc = ly_ctx_get_module(session->ctx, "ietf-netconf", NULL);
        if (!ietfnc) {
            WRN("Session %u: missing ietf-netconf schema in context, unable to send <close-session>.", session->id);
        } else {
            close_rpc = lyd_new(NULL, ietfnc, "close-session");
            nc_send_msg(session, close_rpc);
            lyd_free(close_rpc);
            switch (nc_read_msg_poll(session, NC_CLOSE_REPLY_TIMEOUT, &rpl)) {
            case NC_MSG_REPLY:
                LY_TREE_FOR(rpl->child, child) {
                    if (!strcmp(child->name, "ok") && child->ns && !strcmp(child->ns->value, NC_NS_BASE)) {
                        break;
                    }
                }
                if (!child) {
                    WRN("Session %u: the reply to <close-session> was not <ok> as expected.", session->id);
                }
                lyxml_free(session->ctx, rpl);
                break;
            case NC_MSG_WOULDBLOCK:
                WRN("Session %u: timeout for receiving a reply to <close-session> elapsed.", session->id);
                break;
            case NC_MSG_ERROR:
                ERR("Session %u: failed to receive a reply to <close-session>.", session->id);
                break;
            default:
                /* cannot happen */
                break;
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
        pthread_mutex_lock(session->opts.server.ch_lock);
    }

    /* mark session for closing */
    session->status = NC_STATUS_CLOSING;

    if ((session->side == NC_SERVER) && (session->flags & NC_SESSION_CALLHOME)) {
        pthread_cond_signal(session->opts.server.ch_cond);

        /* CH UNLOCK */
        pthread_mutex_unlock(session->opts.server.ch_lock);
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

#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
        if (connected) {
            ssh_channel_free(session->ti.libssh.channel);
        }
        /* There can be multiple NETCONF sessions on the same SSH session (NETCONF session maps to
         * SSH channel). So destroy the SSH session only if there is no other NETCONF session using
         * it.
         */
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
                        ly_ctx_destroy(session->ctx, NULL);
                    }

                    free(siter);
                } while (session->ti.libssh.next != session);
            }
            if (connected) {
                ssh_disconnect(session->ti.libssh.session);
            }
            ssh_free(session->ti.libssh.session);
        } else {
            /* remove the session from the list */
            for (siter = session->ti.libssh.next; siter->ti.libssh.next != session; siter = siter->ti.libssh.next);
            if (session->ti.libssh.next == siter) {
                /* there will be only one session */
                siter->ti.libssh.next = NULL;
            } else {
                /* there are still multiple sessions, keep the ring list */
                siter->ti.libssh.next = session->ti.libssh.next;
            }
            /* change nc_sshcb_msg() argument, we need a RUNNING session and this one will be freed */
            if (session->flags & NC_SESSION_SSH_MSG_CB) {
                for (siter = session->ti.libssh.next; siter->status != NC_STATUS_RUNNING; siter = siter->ti.libssh.next) {
                    if (siter->ti.libssh.next == session) {
                        ERRINT;
                        break;
                    }
                }
                ssh_set_message_callback(session->ti.libssh.session, nc_sshcb_msg, siter);
                siter->flags |= NC_SESSION_SSH_MSG_CB;
            }
        }
        break;
#endif

#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
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
        ERRINT;
        break;
    }

    lydict_remove(session->ctx, session->username);
    lydict_remove(session->ctx, session->host);

    /* final cleanup */
    if (session->ti_lock) {
        if (locked) {
            nc_session_unlock(session, NC_SESSION_LOCK_TIMEOUT, __func__);
        }
        if (!multisession) {
            pthread_mutex_destroy(session->ti_lock);
            pthread_cond_destroy(session->ti_cond);
            free(session->ti_lock);
            free(session->ti_cond);
            free((int *)session->ti_inuse);
        }
    }

    if (!(session->flags & NC_SESSION_SHAREDCTX)) {
        ly_ctx_destroy(session->ctx, NULL);
    }

    if (session->side == NC_SERVER) {
        if (session->opts.server.ch_cond) {
            pthread_cond_destroy(session->opts.server.ch_cond);
            free(session->opts.server.ch_cond);
        }
        if (session->opts.server.ch_lock) {
            pthread_mutex_destroy(session->opts.server.ch_lock);
            free(session->opts.server.ch_lock);
        }
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
            if (!strncmp((*cpblts)[i], capab, len) && ((*cpblts)[i][len] == '\0' || (*cpblts)[i][len] == '?')) {
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
        (*cpblts)[*count] = lydict_insert(ctx, capab, 0);
    } else {
        (*cpblts)[*count] = NULL;
    }
    ++(*count);
}

API const char **
nc_server_get_cpblts(struct ly_ctx *ctx)
{
    struct lyd_node *child, *child2, *yanglib;
    struct lyd_node_leaf_list **features = NULL, **deviations = NULL, *ns = NULL, *rev = NULL, *name = NULL, *module_set_id = NULL;
    const char **cpblts;
    const struct lys_module *mod;
    int size = 10, count, feat_count = 0, dev_count = 0, i, str_len;
    unsigned int u;
#define NC_CPBLT_BUF_LEN 512
    char str[NC_CPBLT_BUF_LEN];

    if (!ctx) {
        ERRARG("ctx");
        return NULL;
    }

    yanglib = ly_ctx_info(ctx);
    if (!yanglib) {
        ERR("Failed to get ietf-yang-library data from the context.");
        return NULL;
    }

    cpblts = malloc(size * sizeof *cpblts);
    if (!cpblts) {
        ERRMEM;
        return NULL;
    }
    cpblts[0] = lydict_insert(ctx, "urn:ietf:params:netconf:base:1.0", 0);
    cpblts[1] = lydict_insert(ctx, "urn:ietf:params:netconf:base:1.1", 0);
    count = 2;

    /* capabilities */

    mod = ly_ctx_get_module(ctx, "ietf-netconf", NULL);
    if (mod) {
        if (lys_features_state(mod, "writable-running") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:writable-running:1.0", &cpblts, &size, &count);
        }
        if (lys_features_state(mod, "candidate") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:candidate:1.0", &cpblts, &size, &count);
            if (lys_features_state(mod, "confirmed-commit") == 1) {
                add_cpblt(ctx, "urn:ietf:params:netconf:capability:confirmed-commit:1.1", &cpblts, &size, &count);
            }
        }
        if (lys_features_state(mod, "rollback-on-error") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:rollback-on-error:1.0", &cpblts, &size, &count);
        }
        if (lys_features_state(mod, "validate") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:validate:1.1", &cpblts, &size, &count);
        }
        if (lys_features_state(mod, "startup") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:startup:1.0", &cpblts, &size, &count);
        }
        if (lys_features_state(mod, "url") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:url:1.0", &cpblts, &size, &count);
        }
        if (lys_features_state(mod, "xpath") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:capability:xpath:1.0", &cpblts, &size, &count);
        }
    }

    mod = ly_ctx_get_module(ctx, "ietf-netconf-with-defaults", NULL);
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
    LY_TREE_FOR(yanglib->child, child) {
        if (!module_set_id) {
            if (strcmp(child->prev->schema->name, "module-set-id")) {
                ERRINT;
                free(cpblts);
                free(deviations);
                return NULL;
            }
            module_set_id = (struct lyd_node_leaf_list *)child->prev;
        }
        if (!strcmp(child->schema->name, "module")) {
            LY_TREE_FOR(child->child, child2) {
                if (!strcmp(child2->schema->name, "namespace")) {
                    ns = (struct lyd_node_leaf_list *)child2;
                } else if (!strcmp(child2->schema->name, "name")) {
                    name = (struct lyd_node_leaf_list *)child2;
                } else if (!strcmp(child2->schema->name, "revision")) {
                    rev = (struct lyd_node_leaf_list *)child2;
                } else if (!strcmp(child2->schema->name, "feature")) {
                    features = nc_realloc(features, ++feat_count * sizeof *features);
                    if (!features) {
                        ERRMEM;
                        free(cpblts);
                        free(deviations);
                        return NULL;
                    }
                    features[feat_count - 1] = (struct lyd_node_leaf_list *)child2;
                } else if (!strcmp(child2->schema->name, "deviation")) {
                    deviations = nc_realloc(deviations, ++dev_count * sizeof *deviations);
                    if (!deviations) {
                        ERRMEM;
                        free(cpblts);
                        free(features);
                        return NULL;
                    }
                }
            }

            if (!ns || !name || !rev) {
                ERRINT;
                continue;
            }

            str_len = sprintf(str, "%s?module=%s%s%s", ns->value_str, name->value_str,
                              rev->value_str[0] ? "&revision=" : "", rev->value_str);
            if (feat_count) {
                strcat(str, "&features=");
                str_len += 10;
                for (i = 0; i < feat_count; ++i) {
                    if (str_len + 1 + strlen(features[i]->value_str) >= NC_CPBLT_BUF_LEN) {
                        ERRINT;
                        break;
                    }
                    if (i) {
                        strcat(str, ",");
                        ++str_len;
                    }
                    strcat(str, features[i]->value_str);
                    str_len += strlen(features[i]->value_str);
                }
            }
            if (dev_count) {
                strcat(str, "&deviations=");
                str_len += 12;
                for (i = 0; i < dev_count; ++i) {
                    if (str_len + 1 + strlen(deviations[i]->value_str) >= NC_CPBLT_BUF_LEN) {
                        ERRINT;
                        break;
                    }
                    if (i) {
                        strcat(str, ",");
                        ++str_len;
                    }
                    strcat(str, deviations[i]->value_str);
                    str_len += strlen(deviations[i]->value_str);
                }
            }
            if (!strcmp(name->value_str, "ietf-yang-library")) {
                sprintf(str + str_len, "&module-set-id=%s", module_set_id->value_str);
            }

            add_cpblt(ctx, str, &cpblts, &size, &count);

            ns = NULL;
            name = NULL;
            rev = NULL;
            if (features || feat_count) {
                free(features);
                features = NULL;
                feat_count = 0;
            }
            if (deviations || dev_count) {
                free(deviations);
                deviations = NULL;
                dev_count = 0;
            }
        }
    }

    lyd_free(yanglib);

    /* ending NULL capability */
    add_cpblt(ctx, NULL, &cpblts, &size, &count);

    return cpblts;
}

static int
parse_cpblts(struct lyxml_elem *xml, char ***list)
{
    struct lyxml_elem *cpblt;
    int ver = -1, i = 0;
    const char *cpb_start, *cpb_end;

    if (list) {
        /* get the storage for server's capabilities */
        LY_TREE_FOR(xml->child, cpblt) {
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

    LY_TREE_FOR(xml->child, cpblt) {
        if (strcmp(cpblt->name, "capability") && cpblt->ns && cpblt->ns->value &&
                    !strcmp(cpblt->ns->value, NC_NS_BASE)) {
            ERR("Unexpected <%s> element in client's <hello>.", cpblt->name);
            return -1;
        } else if (!cpblt->ns || !cpblt->ns->value || strcmp(cpblt->ns->value, NC_NS_BASE)) {
            continue;
        }

        /* skip leading/trailing whitespaces */
        for (cpb_start = cpblt->content; isspace(cpb_start[0]); ++cpb_start);
        for (cpb_end = cpblt->content + strlen(cpblt->content); (cpb_end > cpblt->content) && isspace(cpb_end[-1]); --cpb_end);
        if (!cpb_start[0] || (cpb_end == cpblt->content)) {
            ERR("Empty capability \"%s\" received.", cpblt->content);
            return -1;
        }

        /* detect NETCONF version */
        if (ver < 0 && !strncmp(cpb_start, "urn:ietf:params:netconf:base:1.0", cpb_end - cpb_start)) {
            ver = 0;
        } else if (ver < 1 && !strncmp(cpb_start, "urn:ietf:params:netconf:base:1.1", cpb_end - cpb_start)) {
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
nc_send_client_hello(struct nc_session *session)
{
    int r, i;
    const char **cpblts;

    /* client side hello - send only NETCONF base capabilities */
    cpblts = malloc(3 * sizeof *cpblts);
    if (!cpblts) {
        ERRMEM;
        return NC_MSG_ERROR;
    }
    cpblts[0] = lydict_insert(session->ctx, "urn:ietf:params:netconf:base:1.0", 0);
    cpblts[1] = lydict_insert(session->ctx, "urn:ietf:params:netconf:base:1.1", 0);
    cpblts[2] = NULL;

    r = nc_write_msg(session, NC_MSG_HELLO, cpblts, NULL);

    for (i = 0; cpblts[i]; ++i) {
        lydict_remove(session->ctx, cpblts[i]);
    }
    free(cpblts);

    if (r) {
        return NC_MSG_ERROR;
    }

    return NC_MSG_HELLO;
}

static NC_MSG_TYPE
nc_send_server_hello(struct nc_session *session)
{
    int r, i;
    const char **cpblts;

    cpblts = nc_server_get_cpblts(session->ctx);

    r = nc_write_msg(session, NC_MSG_HELLO, cpblts, &session->id);

    for (i = 0; cpblts[i]; ++i) {
        lydict_remove(session->ctx, cpblts[i]);
    }
    free(cpblts);

    if (r) {
        return NC_MSG_ERROR;
    }

    return NC_MSG_HELLO;
}

static NC_MSG_TYPE
nc_recv_client_hello(struct nc_session *session)
{
    struct lyxml_elem *xml = NULL, *node;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */
    int ver = -1;
    char *str;
    long long int id;
    int flag = 0;

    msgtype = nc_read_msg_poll(session, NC_CLIENT_HELLO_TIMEOUT * 1000, &xml);

    switch(msgtype) {
    case NC_MSG_HELLO:
        /* parse <hello> data */
        LY_TREE_FOR(xml->child, node) {
            if (!node->ns || !node->ns->value || strcmp(node->ns->value, NC_NS_BASE)) {
                continue;
            } else if (!strcmp(node->name, "session-id")) {
                if (!node->content || !strlen(node->content)) {
                    ERR("No value of <session-id> element in server's <hello>.");
                    goto error;
                }
                str = NULL;
                id = strtoll(node->content, &str, 10);
                if (*str || id < 1 || id > UINT32_MAX) {
                    ERR("Invalid value of <session-id> element in server's <hello>.");
                    goto error;
                }
                session->id = (uint32_t)id;
                continue;
            } else if (strcmp(node->name, "capabilities")) {
                ERR("Unexpected <%s> element in client's <hello>.", node->name);
                goto error;
            }

            if (flag) {
                /* multiple capabilities elements */
                ERR("Invalid <hello> message (multiple <capabilities> elements).");
                goto error;
            }
            flag = 1;

            if ((ver = parse_cpblts(node, &session->opts.client.cpblts)) < 0) {
                goto error;
            }
            session->version = ver;
        }

        if (!session->id) {
            ERR("Missing <session-id> in server's <hello>.");
            goto error;
        }
        break;
    case NC_MSG_WOULDBLOCK:
        ERR("Server's <hello> timeout elapsed.");
        break;
    case NC_MSG_ERROR:
        /* nothing special, just pass it out */
        break;
    default:
        ERR("Unexpected message received instead of <hello>.");
        msgtype = NC_MSG_ERROR;
        break;
    }

    /* cleanup */
    lyxml_free(session->ctx, xml);

    return msgtype;

error:
    /* cleanup */
    lyxml_free(session->ctx, xml);

    return NC_MSG_ERROR;
}

static NC_MSG_TYPE
nc_recv_server_hello(struct nc_session *session)
{
    struct lyxml_elem *xml = NULL, *node;
    NC_MSG_TYPE msgtype;
    int ver = -1;
    int flag = 0;

    msgtype = nc_read_msg_poll(session, (server_opts.hello_timeout ? server_opts.hello_timeout * 1000 : -1), &xml);

    switch (msgtype) {
    case NC_MSG_HELLO:
        /* get know NETCONF version */
        LY_TREE_FOR(xml->child, node) {
            if (!node->ns || !node->ns->value || strcmp(node->ns->value, NC_NS_BASE)) {
                continue;
            } else if (strcmp(node->name, "capabilities")) {
                ERR("Unexpected <%s> element in client's <hello>.", node->name);
                msgtype = NC_MSG_BAD_HELLO;
                goto cleanup;
            }

            if (flag) {
                /* multiple capabilities elements */
                ERR("Invalid <hello> message (multiple <capabilities> elements).");
                msgtype = NC_MSG_BAD_HELLO;
                goto cleanup;
            }
            flag = 1;

            if ((ver = parse_cpblts(node, NULL)) < 0) {
                msgtype = NC_MSG_BAD_HELLO;
                goto cleanup;
            }
            session->version = ver;
        }
        break;
    case NC_MSG_ERROR:
        /* nothing special, just pass it out */
        break;
    case NC_MSG_WOULDBLOCK:
        ERR("Client's <hello> timeout elapsed.");
        break;
    default:
        ERR("Unexpected message received instead of <hello>.");
        msgtype = NC_MSG_ERROR;
        break;
    }

cleanup:
    lyxml_free(session->ctx, xml);

    return msgtype;
}

NC_MSG_TYPE
nc_handshake(struct nc_session *session)
{
    NC_MSG_TYPE type;

    if (session->side == NC_CLIENT) {
        type = nc_send_client_hello(session);
    } else {
        type = nc_send_server_hello(session);
    }

    if (type != NC_MSG_HELLO) {
        return type;
    }

    if (session->side == NC_CLIENT) {
        type = nc_recv_client_hello(session);
    } else {
        type = nc_recv_server_hello(session);
    }

    return type;
}

#ifdef NC_ENABLED_SSH

static void
nc_ssh_init(void)
{
    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    ssh_init();
}

static void
nc_ssh_destroy(void)
{
    FIPS_mode_set(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    nc_thread_destroy();
    ssh_finalize();
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

#if defined(NC_ENABLED_TLS) && !defined(NC_ENABLED_SSH)

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
    int i;

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    SSL_library_init();

#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
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
    int i;

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

#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
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

#if defined(NC_ENABLED_SSH) && defined(NC_ENABLED_TLS)

static void
nc_ssh_tls_init(void)
{
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    SSL_library_init();

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
    ERR_free_strings();
#if OPENSSL_VERSION_NUMBER < 0x10002000L // < 1.0.2
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
#elif OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    SSL_COMP_free_compression_methods();
#endif

    nc_ssh_destroy();

#if OPENSSL_VERSION_NUMBER < 0x10100000L // < 1.1.0
    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);
#endif
}

#endif /* NC_ENABLED_SSH && NC_ENABLED_TLS */

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)

API void
nc_thread_destroy(void)
{
    /* caused data-races and seems not neccessary for avoiding valgrind reachable memory */
    //CRYPTO_cleanup_all_ex_data();

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
#if defined(NC_ENABLED_SSH) && defined(NC_ENABLED_TLS)
    nc_ssh_tls_init();
#elif defined(NC_ENABLED_SSH)
    nc_ssh_init();
#elif defined(NC_ENABLED_TLS)
    nc_tls_init();
#endif
}

void
nc_destroy(void)
{
#if defined(NC_ENABLED_SSH) && defined(NC_ENABLED_TLS)
    nc_ssh_tls_destroy();
#elif defined(NC_ENABLED_SSH)
    nc_ssh_destroy();
#elif defined(NC_ENABLED_TLS)
    nc_tls_destroy();
#endif
}
