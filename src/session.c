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
#include <libyang/libyang.h>

#ifdef ENABLE_SSH

#   include <libssh/libssh.h>

#endif /* ENABLE_SSH */

#ifdef ENABLE_TLS

#   include <openssl/err.h>

#endif /* ENABLE_TLS */

#include "config.h"
#include "log_p.h"
#include "session.h"
#include "session_p.h"

/* in seconds */
#define NC_CLIENT_HELLO_TIMEOUT 60

/* in milliseconds */
#define NC_CLOSE_REPLY_TIMEOUT 200

extern struct nc_server_opts server_opts;

NC_MSG_TYPE
nc_send_msg(struct nc_session *session, struct lyd_node *op)
{
    int r;

    if (session->ctx != op->schema->module->ctx) {
        ERR("RPC \"%s\" was created in different context than that of \"%s\" session %u.",
            op->schema->name, session->username, session->id);
        return NC_MSG_ERROR;
    }

    r = nc_write_msg(session, NC_MSG_RPC, op, NULL);

    if (r) {
        return NC_MSG_ERROR;
    }

    return NC_MSG_RPC;
}

/*
 * @return 0 - success
 *        -1 - timeout
 *        >0 - error
 */
int
session_ti_lock(struct nc_session *session, int32_t timeout)
{
    int r;

    if (timeout >= 0) {
        /* limited waiting for lock */
        do {
            r = pthread_mutex_trylock(session->ti_lock);
            if (r == EBUSY) {
                /* try later until timeout passes */
                usleep(NC_TIMEOUT_STEP);
                timeout = timeout - NC_TIMEOUT_STEP;
                continue;
            } else if (r) {
                /* error */
                ERR("Acquiring session (%u) TI lock failed (%s).", session->id, strerror(r));
                return r;
            } else {
                /* lock acquired */
                return 0;
            }
        } while (timeout > 0);

        /* timeout has passed */
        return -1;
    } else {
        /* infinite waiting for lock */
        return pthread_mutex_lock(session->ti_lock);
    }
}

int
session_ti_unlock(struct nc_session *session)
{
    return pthread_mutex_unlock(session->ti_lock);
}

API void
nc_session_free(struct nc_session *session)
{
    int r, i;
    int connected; /* flag to indicate whether the transport socket is still connected */
    int multisession = 0; /* flag for more NETCONF session on a single SSH session */
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
            r = session_ti_lock(session, 0);
        } while (r < 0);
        if (r) {
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
                ERR("%s: session %u: failed to receive a reply to <close-session>.", __func__, session->id);
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
        if (!session->ti.libssh.next) {
            if (connected) {
                ssh_disconnect(session->ti.libssh.session);
            }
            ssh_free(session->ti.libssh.session);
        } else {
            /* multiple NETCONF sessions on a single SSH session */
            multisession = 1;
            /* remove the session from the list */
            for (siter = session->ti.libssh.next; siter->ti.libssh.next != session; siter = siter->ti.libssh.next);
            if (session->ti.libssh.next == siter) {
                /* there will be only one session */
                siter->ti.libssh.next = NULL;
            } else {
                /* there are still multiple sessions, keep the ring list */
                siter->ti.libssh.next = session->ti.libssh.next;
            }
        }
        break;
#endif

#ifdef ENABLE_TLS
    case NC_TI_OPENSSL:
        X509_free(session->cert);

        if (connected) {
            SSL_shutdown(session->ti.tls);
        }
        SSL_free(session->ti.tls);
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
        if (multisession) {
            session_ti_unlock(session);
        } else {
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
    int size = 10, count, feat_count = 0, i;
    char str[512];

    yanglib = ly_ctx_info(ctx);
    if (!yanglib) {
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

    mod = ly_ctx_get_module(ctx, "ietf-netconf-notifications", NULL);
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

            sprintf(str, "%s?module=%s&amp;revision=%s", ns->value_str, name->value_str, rev->value_str);
            if (feat_count) {
                strcat(str, "&amp;features=");
                for (i = 0; i < feat_count; ++i) {
                    if (i) {
                        strcat(str, ",");
                    }
                    strcat(str, features[i]->value_str);
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
        ERR("Peer does not support compatible NETCONF version.");
    }

    return ver;
}

static NC_MSG_TYPE
nc_send_hello(struct nc_session *session)
{
    int r, i;
    const char **cpblts;

    if (session->side == NC_CLIENT) {
        /* client side hello - send only NETCONF base capabilities */
        cpblts = malloc(3 * sizeof *cpblts);
        cpblts[0] = lydict_insert(session->ctx, "urn:ietf:params:netconf:base:1.0", 0);
        cpblts[1] = lydict_insert(session->ctx, "urn:ietf:params:netconf:base:1.1", 0);
        cpblts[2] = NULL;

        r = nc_write_msg(session, NC_MSG_HELLO, cpblts, NULL);
    } else {
        cpblts = create_cpblts(session->ctx);

        r = nc_write_msg(session, NC_MSG_HELLO, cpblts, &session->id);
    }

    for (i = 0; cpblts[i]; ++i) {
        lydict_remove(session->ctx, cpblts[i]);
    }
    free(cpblts);

    if (r) {
        return NC_MSG_ERROR;
    } else {
        return NC_MSG_HELLO;
    }
}

static NC_MSG_TYPE
nc_recv_hello(struct nc_session *session)
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
        if (session->side == NC_SERVER) {
            /* get know NETCONF version */
            LY_TREE_FOR(xml->child, node) {
                if (!node->ns || !node->ns->value || strcmp(node->ns->value, NC_NS_BASE)) {
                    continue;
                } else if (strcmp(node->name, "capabilities")) {
                    ERR("Unexpected <%s> element in client's <hello>.", node->name);
                    goto error;
                }

                if (flag) {
                    /* multiple capabilities elements */
                    ERR("Invalid <hello> message (multiple <capabilities> elements)");
                    goto error;
                }
                flag = 1;

                if ((ver = parse_cpblts(node, NULL)) < 0) {
                    goto error;
                }
                session->version = ver;
            }
        } else { /* NC_CLIENT */
            LY_TREE_FOR(xml->child, node) {
                if (!node->ns || !node->ns->value || strcmp(node->ns->value, NC_NS_BASE)) {
                    continue;
                } else if (!strcmp(node->name, "session-id")) {
                    if (!node->content || !strlen(node->content)) {
                        ERR("No value of <session-id> element in server's <hello>");
                        goto error;
                    }
                    str = NULL;
                    id = strtoll(node->content, &str, 10);
                    if (*str || id < 1 || id > UINT32_MAX) {
                        ERR("Invalid value of <session-id> element in server's <hello>");
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
                    ERR("Invalid <hello> message (multiple <capabilities> elements)");
                    goto error;
                }
                flag = 1;

                if ((ver = parse_cpblts(node, &session->cpblts)) < 0) {
                    goto error;
                }
                session->version = ver;
            }

            if (!session->id) {
                ERR("Missing <session-id> in server's <hello>");
                goto error;
            }
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

int
nc_handshake(struct nc_session *session)
{
    NC_MSG_TYPE type;

    type = nc_send_hello(session);
    if (type != NC_MSG_HELLO) {
        return 1;
    }

    type = nc_recv_hello(session);
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
tls_thread_locking_func(int mode, int n, const char *file, int line)
{
    (void)file;
    (void)line;

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
