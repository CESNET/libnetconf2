/**
 * \file session.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 - general session functions
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

#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <libyang/libyang.h>

#include "libnetconf.h"
#include "session_server.h"

#ifdef ENABLE_SSH

#   include <libssh/libssh.h>

#endif /* ENABLE_SSH */

#ifdef ENABLE_TLS

#   include <openssl/err.h>

#endif /* ENABLE_TLS */

/* in seconds */
#define NC_CLIENT_HELLO_TIMEOUT 60

/* in milliseconds */
#define NC_CLOSE_REPLY_TIMEOUT 200

extern struct nc_server_opts server_opts;

/*
 * @return 1 - success
 *         0 - timeout
 *        -1 - error
 */
int
nc_timedlock(pthread_mutex_t *lock, int timeout, int *elapsed)
{
    int ret;
    struct timespec ts_timeout, ts_old, ts_new;

    if (timeout > 0) {
        clock_gettime(CLOCK_REALTIME, &ts_timeout);

        if (elapsed) {
            ts_old = ts_timeout;
        }

        ts_timeout.tv_sec += timeout / 1000;
        ts_timeout.tv_nsec += (timeout % 1000) * 1000000;

        ret = pthread_mutex_timedlock(lock, &ts_timeout);

        if (elapsed) {
            clock_gettime(CLOCK_REALTIME, &ts_new);

            *elapsed += (ts_new.tv_sec - ts_old.tv_sec) * 1000;
            *elapsed += (ts_new.tv_nsec - ts_old.tv_nsec) / 1000000;
        }
    } else if (!timeout) {
        ret = pthread_mutex_trylock(lock);
    } else { /* timeout == -1 */
        ret = pthread_mutex_lock(lock);
    }

    if (ret == ETIMEDOUT) {
        /* timeout */
        return 0;
    } else if (ret) {
        /* error */
        ERR("Mutex lock failed (%s).", strerror(errno));
        return -1;
    }

    /* ok */
    return 1;
}

void
nc_subtract_elapsed(int *timeout, struct timespec *old_ts)
{
    struct timespec new_ts;

    clock_gettime(CLOCK_MONOTONIC_RAW, &new_ts);

    *timeout -= (new_ts.tv_sec - old_ts->tv_sec) * 1000;
    *timeout -= (new_ts.tv_nsec - old_ts->tv_nsec) / 1000000;

    *old_ts = new_ts;
}

API NC_STATUS
nc_session_get_status(const struct nc_session *session)
{
    if (!session) {
        ERRARG;
        return 0;
    }

    return session->status;
}

API uint32_t
nc_session_get_id(const struct nc_session *session)
{
    if (!session) {
        ERRARG;
        return 0;
    }

    return session->id;
}

API NC_TRANSPORT_IMPL
nc_session_get_ti(const struct nc_session *session)
{
    if (!session) {
        ERRARG;
        return 0;
    }

    return session->ti_type;
}

API const char *
nc_session_get_username(const struct nc_session *session)
{
    if (!session) {
        ERRARG;
        return NULL;
    }

    return session->username;
}

API const char *
nc_session_get_host(const struct nc_session *session)
{
    if (!session) {
        ERRARG;
        return NULL;
    }

    return session->host;
}

API uint16_t
nc_session_get_port(const struct nc_session *session)
{
    if (!session) {
        ERRARG;
        return 0;
    }

    return session->port;
}

API const char **
nc_session_get_cpblts(const struct nc_session *session)
{
    if (!session) {
        ERRARG;
        return NULL;
    }

    return session->cpblts;
}

API const char *
nc_session_cpblt(const struct nc_session *session, const char *capab)
{
    int i, len;

    if (!session || !capab) {
        ERRARG;
        return NULL;
    }

    len = strlen(capab);
    for (i = 0; session->cpblts[i]; ++i) {
        if (!strncmp(session->cpblts[i], capab, len)) {
            return session->cpblts[i];
        }
    }

    return NULL;
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
nc_session_free(struct nc_session *session)
{
    int r, i;
    int connected; /* flag to indicate whether the transport socket is still connected */
    int multisession = 0; /* flag for more NETCONF sessions on a single SSH session */
    struct nc_session *siter;
    struct nc_msg_cont *contiter;
    struct lyxml_elem *rpl, *child;
    struct lyd_node *close_rpc;
    const struct lys_module *ietfnc;
    void *p;

    if (!session || (session->status == NC_STATUS_CLOSING)) {
        return;
    }

    /* mark session for closing */
    if (session->ti_lock) {
        do {
            r = nc_timedlock(session->ti_lock, 0, NULL);
        } while (!r);
        if (r == -1) {
            return;
        }
    }

    /* stop notifications loop if any */
    if (session->notif) {
        pthread_cancel(*session->notif);
        pthread_join(*session->notif, NULL);
    }

    if ((session->side == NC_CLIENT) && (session->status == NC_STATUS_RUNNING)) {
        /* cleanup message queues */
        /* notifications */
        for (contiter = session->notifs; contiter; ) {
            lyxml_free(session->ctx, contiter->msg);

            p = contiter;
            contiter = contiter->next;
            free(p);
        }

        /* rpc replies */
        for (contiter = session->replies; contiter; ) {
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
        if (session->cpblts) {
            for (i = 0; session->cpblts[i]; i++) {
                lydict_remove(session->ctx, session->cpblts[i]);
            }
            free(session->cpblts);
        }
    }

    session->status = NC_STATUS_CLOSING;
    connected = nc_session_is_connected(session);

    /* transport implementation cleanup */
    switch (session->ti_type) {
    case NC_TI_FD:
        /* nothing needed - file descriptors were provided by caller,
         * so it is up to the caller to close them correctly
         * TODO use callbacks
         */
        break;

#ifdef ENABLE_SSH
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
                    if (session->side == NC_SERVER) {
                        nc_ctx_lock(-1, NULL);
                    }
                    lydict_remove(session->ctx, session->username);
                    lydict_remove(session->ctx, session->host);
                    if (session->side == NC_SERVER) {
                        nc_ctx_unlock();
                    }
                    if (!(session->flags & NC_SESSION_SHAREDCTX)) {
                        ly_ctx_destroy(session->ctx);
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

#ifdef ENABLE_TLS
    case NC_TI_OPENSSL:
        if (connected) {
            SSL_shutdown(session->ti.tls);
        }
        SSL_free(session->ti.tls);

        X509_free(session->tls_cert);
        break;
#endif
    case NC_TI_NONE:
        ERRINT;
        break;
    }

    if (session->side == NC_SERVER) {
        nc_ctx_lock(-1, NULL);
    }
    lydict_remove(session->ctx, session->username);
    lydict_remove(session->ctx, session->host);
    if (session->side == NC_SERVER) {
        nc_ctx_unlock();
    }

    /* final cleanup */
    if (session->ti_lock) {
        pthread_mutex_unlock(session->ti_lock);
        if (!multisession) {
            pthread_mutex_destroy(session->ti_lock);
            free(session->ti_lock);
        }
    }

    if (!(session->flags & NC_SESSION_SHAREDCTX)) {
        ly_ctx_destroy(session->ctx);
    }

    free(session);
}

static void
add_cpblt(struct ly_ctx *ctx, const char *capab, const char ***cpblts, int *size, int *count)
{
    if (*count == *size) {
        *size += 5;
        *cpblts = realloc(*cpblts, *size * sizeof **cpblts);
    }

    if (capab) {
        (*cpblts)[*count] = lydict_insert(ctx, capab, 0);
    } else {
        (*cpblts)[*count] = NULL;
    }
    ++(*count);
}

static const char **
create_cpblts(struct ly_ctx *ctx)
{
    struct lyd_node *child, *child2, *yanglib;
    struct lyd_node_leaf_list **features = NULL, *ns = NULL, *rev = NULL, *name = NULL;
    const char **cpblts;
    const struct lys_module *mod;
    int size = 10, count, feat_count = 0, i, str_len;
    char str[512];

    nc_ctx_lock(-1, NULL);

    yanglib = ly_ctx_info(ctx);
    if (!yanglib) {
        nc_ctx_unlock();
        return NULL;
    }

    cpblts = malloc(size * sizeof *cpblts);
    cpblts[0] = lydict_insert(ctx, "urn:ietf:params:netconf:base:1.0", 0);
    cpblts[1] = lydict_insert(ctx, "urn:ietf:params:netconf:base:1.1", 0);
    count = 2;

    /* capabilities */

    mod = ly_ctx_get_module(ctx, "ietf-netconf", NULL);
    if (mod) {
        if (lys_features_state(mod, "writable-running") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:writable-running:1.0", &cpblts, &size, &count);
        }
        if (lys_features_state(mod, "candidate") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:candidate:1.0", &cpblts, &size, &count);
            if (lys_features_state(mod, "confirmed-commit") == 1) {
                add_cpblt(ctx, "urn:ietf:params:netconf:confirmed-commit:1.1", &cpblts, &size, &count);
            }
        }
        if (lys_features_state(mod, "rollback-on-error") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:rollback-on-error:1.0", &cpblts, &size, &count);
        }
        if (lys_features_state(mod, "validate") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:validate:1.1", &cpblts, &size, &count);
        }
        if (lys_features_state(mod, "startup") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:startup:1.0", &cpblts, &size, &count);
        }
        if (lys_features_state(mod, "url") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:url:1.0", &cpblts, &size, &count);
        }
        if (lys_features_state(mod, "xpath") == 1) {
            add_cpblt(ctx, "urn:ietf:params:netconf:xpath:1.0", &cpblts, &size, &count);
        }
    }

    mod = ly_ctx_get_module(ctx, "ietf-netconf-with-defaults", NULL);
    if (mod) {
        if (!server_opts.wd_basic_mode) {
            VRB("with-defaults capability will not be advertised even though \"ietf-netconf-with-defaults\" model is present, unknown basic-mode.");
        } else {
            strcpy(str, "urn:ietf:params:netconf:with-defaults:1.0");
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
                strcat(str, "&amp;also-supported=");
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

    mod = ly_ctx_get_module(ctx, "nc-notifications", NULL);
    if (mod) {
        add_cpblt(ctx, "urn:ietf:params:netconf:notification:1.0", &cpblts, &size, &count);
        if (server_opts.interleave_capab) {
            add_cpblt(ctx, "urn:ietf:params:netconf:interleave:1.0", &cpblts, &size, &count);
        }
    }

    /* models */

    LY_TREE_FOR(yanglib->child, child) {
        if (!strcmp(child->schema->name, "module")) {
            LY_TREE_FOR(child->child, child2) {
                if (!strcmp(child2->schema->name, "namespace")) {
                    ns = (struct lyd_node_leaf_list *)child2;
                } else if (!strcmp(child2->schema->name, "name")) {
                    name = (struct lyd_node_leaf_list *)child2;
                } else if (!strcmp(child2->schema->name, "revision")) {
                    rev = (struct lyd_node_leaf_list *)child2;
                } else if (!strcmp(child2->schema->name, "feature")) {
                    features = realloc(features, feat_count++ * sizeof *features);
                    features[feat_count - 1] = (struct lyd_node_leaf_list *)child2;
                }
            }

            if (!ns || !name || !rev) {
                ERRINT;
                continue;
            }

            str_len = sprintf(str, "%s?module=%s&amp;revision=%s", ns->value_str, name->value_str, rev->value_str);
            if (feat_count) {
                strcat(str, "&amp;features=");
                str_len += 14;
                for (i = 0; i < feat_count; ++i) {
                    if (str_len + 1 + strlen(features[i]->value_str) >= 512) {
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

            add_cpblt(ctx, str, &cpblts, &size, &count);

            ns = NULL;
            name = NULL;
            rev = NULL;
            free(features);
            features = NULL;
            feat_count = 0;
        }
    }

    lyd_free(yanglib);

    nc_ctx_unlock();

    /* ending NULL capability */
    add_cpblt(ctx, NULL, &cpblts, &size, &count);

    return cpblts;
}

static int
parse_cpblts(struct lyxml_elem *xml, const char ***list)
{
    struct lyxml_elem *cpblt;
    int ver = -1;
    int i = 0;

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

        /* detect NETCONF version */
        if (ver < 0 && !strcmp(cpblt->content, "urn:ietf:params:netconf:base:1.0")) {
            ver = 0;
        } else if (ver < 1 && !strcmp(cpblt->content, "urn:ietf:params:netconf:base:1.1")) {
            ver = 1;
        }

        /* store capabilities */
        if (list) {
            (*list)[i] = cpblt->content;
            cpblt->content = NULL;
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

    cpblts = create_cpblts(session->ctx);

    r = nc_write_msg(session, NC_MSG_HELLO, cpblts, &session->id);

    nc_ctx_lock(-1, NULL);
    for (i = 0; cpblts[i]; ++i) {
        lydict_remove(session->ctx, cpblts[i]);
    }
    nc_ctx_unlock();
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

            if ((ver = parse_cpblts(node, &session->cpblts)) < 0) {
                goto error;
            }
            session->version = ver;
        }

        if (!session->id) {
            ERR("Missing <session-id> in server's <hello>.");
            goto error;
        }
        break;
    case NC_MSG_ERROR:
        /* nothing special, just pass it out */
        break;
    default:
        ERR("Unexpected message received instead of <hello>.");
        msgtype = NC_MSG_ERROR;
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
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */
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
                msgtype = NC_MSG_ERROR;
                goto cleanup;
            }

            if (flag) {
                /* multiple capabilities elements */
                ERR("Invalid <hello> message (multiple <capabilities> elements).");
                msgtype = NC_MSG_ERROR;
                goto cleanup;
            }
            flag = 1;

            if ((ver = parse_cpblts(node, NULL)) < 0) {
                msgtype = NC_MSG_ERROR;
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
        msgtype = NC_MSG_ERROR;
        break;
    default:
        ERR("Unexpected message received instead of <hello>.");
        msgtype = NC_MSG_ERROR;
    }

cleanup:
    nc_ctx_lock(-1, NULL);
    lyxml_free(session->ctx, xml);
    nc_ctx_unlock();

    return msgtype;
}

int
nc_handshake(struct nc_session *session)
{
    NC_MSG_TYPE type;

    if (session->side == NC_CLIENT) {
        type = nc_send_client_hello(session);
    } else {
        type = nc_send_server_hello(session);
    }

    if (type != NC_MSG_HELLO) {
        return 1;
    }

    if (session->side == NC_CLIENT) {
        type = nc_recv_client_hello(session);
    } else {
        type = nc_recv_server_hello(session);
    }

    if (type != NC_MSG_HELLO) {
        return 1;
    }

    return 0;
}

#ifdef ENABLE_SSH

API void
nc_ssh_init(void)
{
    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    ssh_init();
    ssh_set_log_level(verbose_level);
}

API void
nc_ssh_destroy(void)
{
    ssh_finalize();
}

#endif /* ENABLE_SSH */

#ifdef ENABLE_TLS

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

static unsigned long
tls_thread_id_func(void)
{
    return (unsigned long)pthread_self();
}

API void
nc_tls_init(void)
{
    int i;

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    SSL_library_init();

    tls_locks = malloc(CRYPTO_num_locks() * sizeof *tls_locks);
    for (i = 0; i < CRYPTO_num_locks(); ++i) {
        pthread_mutex_init(tls_locks + i, NULL);
    }

    CRYPTO_set_id_callback(tls_thread_id_func);
    CRYPTO_set_locking_callback(tls_thread_locking_func);
}

API void
nc_tls_destroy(void)
{
    int i;

    CRYPTO_THREADID crypto_tid;

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
    CRYPTO_THREADID_current(&crypto_tid);
    ERR_remove_thread_state(&crypto_tid);

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); ++i) {
        pthread_mutex_destroy(tls_locks + i);
    }
    free(tls_locks);
}

#endif /* ENABLE_TLS */
