/**
 * \file session.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 - input/output functions
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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "libnetconf.h"

#define TIMEOUT_STEP 50

static NC_MSG_TYPE nc_send_hello_(struct nc_session *session);
static NC_MSG_TYPE nc_recv_hello(struct nc_session *session);
static NC_MSG_TYPE nc_send_rpc_(struct nc_session *session, struct lyd_node *op);

static char *schema_searchpath = NULL;

/* session configuration */
static struct {
    uint16_t hello_timeout; /**< hello-timeout in seconds, default is 600 */
} cfg = {600};

API int
nc_schema_searchpath(const char *path)
{
    if (schema_searchpath) {
        free(schema_searchpath);
    }
    schema_searchpath = strdup(path);

    return schema_searchpath ? 0 : 1;
}

/*
 * @return 0 - success
 *        -1 - timeout
 *        >0 - error
 */
static int
session_ti_lock(struct nc_session *session, int timeout)
{
    int r;

    if (timeout >= 0) {
        /* limited waiting for lock */
        do {
            r = pthread_mutex_trylock(session->ti_lock);
            if (r == EBUSY) {
                /* try later until timeout passes */
                usleep(TIMEOUT_STEP);
                timeout = timeout - TIMEOUT_STEP;
                continue;
            } else if (r) {
                /* error */
                ERR("Acquiring session (%u) TI lock failed (%s).", session->id, strerror(r));
                return r;
            } else {
                /* lock acquired */
                return 0;
            }
        } while(timeout > 0);

        /* timeout has passed */
        return -1;
    } else {
        /* infinite waiting for lock */
        return pthread_mutex_lock(session->ti_lock);
    }
}

static int
session_ti_unlock(struct nc_session *session)
{
    return pthread_mutex_unlock(session->ti_lock);
}

int
handshake(struct nc_session *session)
{
    NC_MSG_TYPE type;

    type = nc_send_hello_(session);
    if (type != NC_MSG_HELLO) {
        return 1;
    }

    type = nc_recv_hello(session);
    if (type != NC_MSG_HELLO) {
        return 1;
    }

    return 0;
}

static int
connect_load_schemas(struct ly_ctx *ctx)
{
    int fd;
    struct lys_module *ietfnc;

    fd = open(SCHEMAS_DIR"ietf-netconf.yin", O_RDONLY);
    if (fd < 0) {
        ERR("Loading base NETCONF schema (%s) failed (%s).", SCHEMAS_DIR"ietf-netconf", strerror(errno));
        return 1;
    }
    if (!(ietfnc = lys_read(ctx, fd, LYS_IN_YIN))) {
        ERR("Loading base NETCONF schema (%s) failed.", SCHEMAS_DIR"ietf-netconf");
        return 1;
    }
    close(fd);

    /* set supported capabilities from ietf-netconf */
    lys_features_enable(ietfnc, "writable-running");
    lys_features_enable(ietfnc, "candidate");
    //lys_features_enable(ietfnc, "confirmed-commit");
    lys_features_enable(ietfnc, "rollback-on-error");
    lys_features_enable(ietfnc, "validate");
    lys_features_enable(ietfnc, "startup");
    lys_features_enable(ietfnc, "url");
    lys_features_enable(ietfnc, "xpath");

    return 0;
}

struct nc_session *
connect_init(struct ly_ctx *ctx)
{
    struct nc_session *session = NULL;
    const char *str;
    int r;

    /* prepare session structure */
    session = calloc(1, sizeof *session);
    if (!session) {
        ERRMEM;
        return NULL;
    }
    session->status = NC_STATUS_STARTING;
    session->side = NC_CLIENT;

    /* YANG context for the session */
    if (ctx) {
        session->flags |= NC_SESSION_SHAREDCTX;
        session->ctx = ctx;

        /* check presence of the required schemas */
        if (!ly_ctx_get_module(session->ctx, "ietf-netconf", NULL)) {
            str = ly_ctx_get_searchdir(session->ctx);
            ly_ctx_set_searchdir(session->ctx, SCHEMAS_DIR);
            r = connect_load_schemas(session->ctx);
            ly_ctx_set_searchdir(session->ctx, str);

            if (r) {
                nc_session_free(session);
                return NULL;
            }
        }
    } else {
        session->ctx = ly_ctx_new(SCHEMAS_DIR);

        /* load basic NETCONF schemas required for libnetconf work */
        if (connect_load_schemas(session->ctx)) {
            nc_session_free(session);
            return NULL;
        }

        ly_ctx_set_searchdir(session->ctx, schema_searchpath);
    }

    return session;
}

API struct nc_session *
nc_connect_inout(int fdin, int fdout, struct ly_ctx *ctx)
{
    struct nc_session *session = NULL;

    if (fdin < 0 || fdout < 0) {
        ERR("%s: Invalid parameter", __func__);
        return NULL;
    }

    /* prepare session structure */
    session = connect_init(ctx);
    if (!session) {
        return NULL;
    }

    /* transport specific data */
    session->ti_type = NC_TI_FD;
    session->ti.fd.in = fdin;
    session->ti.fd.out = fdout;

    /* NETCONF handshake */
    if (handshake(session)) {
        goto error;
    }

    session->status = NC_STATUS_RUNNING;
    return session;

error:
    nc_session_free(session);
    return NULL;
}

int
connect_getsocket(const char* host, unsigned short port)
{
    int sock = -1;
    int i;
    struct addrinfo hints, *res_list, *res;
    char port_s[6]; /* length of string representation of short int */

    snprintf(port_s, 6, "%u", port);

    /* Connect to a server */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    i = getaddrinfo(host, port_s, &hints, &res_list);
    if (i != 0) {
        ERR("Unable to translate the host address (%s).", gai_strerror(i));
        return -1;
    }

    for (i = 0, res = res_list; res != NULL; res = res->ai_next) {
        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock == -1) {
            /* socket was not created, try another resource */
            i = errno;
            goto errloop;
        }

        if (connect(sock, res->ai_addr, res->ai_addrlen) == -1) {
            /* network connection failed, try another resource */
            i = errno;
            close(sock);
            sock = -1;
            goto errloop;
        }

        /* we're done, network connection established */
        break;
errloop:
        VRB("Unable to connect to %s:%s over %s (%s).", host, port_s,
            (res->ai_family == AF_INET6) ? "IPv6" : "IPv4", strerror(i));
        continue;
    }

    if (sock == -1) {
        ERR("Unable to connect to %s:%s.", host, port_s);
    } else {
        VRB("Successfully connected to %s:%s over %s", host, port_s, (res->ai_family == AF_INET6) ? "IPv6" : "IPv4");
    }
    freeaddrinfo(res_list);

    return sock;
}

API void
nc_session_free(struct nc_session *session)
{
    int r, i;
    int multisession = 0; /* flag for more NETCONF session on a single SSH session */
    struct nc_session *siter;
    struct nc_notif_cont *ntfiter;
    struct nc_reply_cont *rpliter;
    struct lyxml_elem *rpl, *child;
    struct lyd_node *close_rpc;
    struct lys_module *ietfnc;
    void *p;

    if (!session || session->status == NC_STATUS_CLOSING) {
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

    if (session->side == NC_CLIENT && session->status == NC_STATUS_RUNNING) {
        /* cleanup message queues */
        /* notifications */
        for (ntfiter = session->notifs; ntfiter; ) {
            nc_notif_free(ntfiter->msg);

            p = ntfiter;
            ntfiter = ntfiter->next;
            free(p);
        }

        /* rpc replies */
        for (rpliter = session->replies; rpliter; ) {
            nc_reply_free(rpliter->msg);

            p = rpliter;
            rpliter = rpliter->next;
            free(p);
        }

        /* send closing info to the other side */
        ietfnc = ly_ctx_get_module(session->ctx, "ietf-netconf", NULL);
        if (!ietfnc) {
            WRN("%s: Missing ietf-netconf schema in context (session %u), unable to send <close-session\\>", session->id);
        } else {
            close_rpc = lyd_new(NULL, ietfnc, "close-session");
            nc_send_rpc_(session, close_rpc);
            lyd_free(close_rpc);
            switch (nc_read_msg(session, 200, &rpl)) {
            case NC_MSG_REPLY:
                LY_TREE_FOR(rpl->child, child) {
                    if (!strcmp(child->name, "ok") && child->ns && !strcmp(child->ns->value, NC_NS_BASE)) {
                        break;
                    }
                }
                if (!child) {
                    WRN("The reply to <close-session\\> was not <ok\\> as expected.");
                }
                lyxml_free_elem(session->ctx, rpl);
                break;
            case NC_MSG_WOULDBLOCK:
                WRN("Timeout for receiving a reply to <close-session\\> elapsed.");
                break;
            case NC_MSG_ERROR:
                ERR("Failed to receive a reply to <close-session\\>.");
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
        ssh_channel_free(session->ti.libssh.channel);
        /* There can be multiple NETCONF sessions on the same SSH session (NETCONF session maps to
         * SSH channel). So destroy the SSH session only if there is no other NETCONF session using
         * it.
         */
        if (!session->ti.libssh.next) {
            ssh_disconnect(session->ti.libssh.session);
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
        SSL_shutdown(session->ti.tls);
        SSL_free(session->ti.tls);
        break;
#endif
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
        *list = calloc(i, sizeof **list);
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
nc_recv_hello(struct nc_session *session)
{
    struct lyxml_elem *xml = NULL, *node;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */
    int ver = -1;
    char *str;
    long long int id;
    int flag = 0;

    msgtype = nc_read_msg(session, cfg.hello_timeout * 1000, &xml);

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

                if ((ver = parse_cpblts(node, NULL)) < 0) {
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
    lyxml_free_elem(session->ctx, xml);

    return msgtype;

error:
    /* cleanup */
    lyxml_free_elem(session->ctx, xml);

    return NC_MSG_ERROR;
}

API NC_MSG_TYPE
nc_recv_rpc(struct nc_session *session, int timeout, struct nc_rpc_server **rpc)
{
    int r;
    struct lyxml_elem *xml = NULL;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */

    if (!session || !rpc) {
        ERR("%s: Invalid parameter", __func__);
        return NC_MSG_ERROR;
    } else if (session->status != NC_STATUS_RUNNING || session->side != NC_SERVER) {
        ERR("%s: invalid session to receive RPCs.", __func__);
        return NC_MSG_ERROR;
    }

    r = session_ti_lock(session, timeout);
    if (r > 0) {
        /* error */
        return NC_MSG_ERROR;
    } else if (r < 0) {
        /* timeout */
        return NC_MSG_WOULDBLOCK;
    }

    msgtype = nc_read_msg(session, timeout, &xml);
    session_ti_unlock(session);

    switch(msgtype) {
    case NC_MSG_RPC:
        *rpc = malloc(sizeof **rpc);
        (*rpc)->type = NC_RPC_SERVER;
        (*rpc)->ctx = session->ctx;
        (*rpc)->tree = lyd_parse_xml(session->ctx, xml, LYD_OPT_DESTRUCT);
        (*rpc)->root = xml;
        break;
    case NC_MSG_HELLO:
        ERR("SESSION %u: Received another <hello> message.", session->id);
        goto error;
    case NC_MSG_REPLY:
        ERR("SESSION %u: Received <rpc-reply> from NETCONF client.", session->id);
        goto error;
    case NC_MSG_NOTIF:
        ERR("SESSION %u: Received <notification> from NETCONF client.", session->id);
        goto error;
    default:
        /* NC_MSG_WOULDBLOCK and NC_MSG_ERROR - pass it out;
         * NC_MSG_NONE is not returned by nc_read_msg()
         */
        break;
    }

    return msgtype;

error:

    /* cleanup */
    lyxml_free_elem(session->ctx, xml);

    return NC_MSG_ERROR;
}

static struct nc_reply *
parse_reply(struct ly_ctx *ctx, struct lyxml_elem *xml)
{
    struct lyxml_elem *iter;
    struct nc_reply *reply = NULL;

    LY_TREE_FOR(xml->child, iter) {
        if (!iter->ns || strcmp(iter->ns->value, NC_NS_BASE)) {
            continue;
        }

        if (!strcmp(iter->name, "ok")) {
            if (reply) {
                ERR("Unexpected content of the <rpc-reply>.");
                goto error;
            }
            reply = malloc(sizeof(struct nc_reply));
            reply->type = NC_REPLY_OK;
            reply->ctx = ctx;
            reply->root = xml;
        } else if (!strcmp(iter->name, "data")) {
            if (reply) {
                ERR("Unexpected content of the <rpc-reply>.");
                goto error;
            }
            reply = malloc(sizeof(struct nc_reply_data));
            reply->type = NC_REPLY_DATA;
            reply->ctx = ctx;
            reply->root = xml;
            ((struct nc_reply_data *)reply)->data = lyd_parse_xml(ctx, iter, LYD_OPT_DESTRUCT);
        } else if (!strcmp(iter->name, "rpc-error")) {
            if (reply && reply->type != NC_REPLY_ERROR) {
                ERR("<rpc-reply> content mismatch.");
                goto error;
            }
            reply = malloc(sizeof(struct nc_reply_error));
            reply->type = NC_REPLY_ERROR;
            reply->ctx = ctx;
            reply->root = xml;
        }
    }

    if (!reply) {
        ERR("Invalid content of the <rpc-reply>.");
    }
    return reply;

error:
    if (reply) {
        reply->root = NULL;
        nc_reply_free(reply);
    }
    return NULL;
}

API NC_MSG_TYPE
nc_recv_reply(struct nc_session *session, int timeout, struct nc_reply **reply)
{
    int r;
    struct lyxml_elem *xml;
    struct nc_reply_cont *cont_r;
    struct nc_notif_cont **cont_n;
    struct nc_notif *notif;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */

    if (!session || !reply) {
        ERR("%s: Invalid parameter", __func__);
        return NC_MSG_ERROR;
    } else if (session->status != NC_STATUS_RUNNING || session->side != NC_CLIENT) {
        ERR("%s: invalid session to receive RPC replies.", __func__);
        return NC_MSG_ERROR;
    }
    *reply = NULL;

    do {
        if (msgtype && session->notif) {
            /* second run, wait and give a chance to nc_recv_notif() */
            usleep(TIMEOUT_STEP);
            timeout = timeout - (TIMEOUT_STEP);
        }
        r = session_ti_lock(session, timeout);
        if (r > 0) {
            /* error */
            return NC_MSG_ERROR;
        } else if (r < 0) {
            /* timeout */
            return NC_MSG_WOULDBLOCK;
        }

        /* try to get message from the session's queue */
        if (session->notifs) {
            cont_r = session->replies;
            session->replies = cont_r->next;

            session_ti_unlock(session);

            *reply = cont_r->msg;
            free(cont_r);

            return NC_MSG_REPLY;
        }

        /* read message from wire */
        msgtype = nc_read_msg(session, timeout, &xml);
        if (msgtype == NC_MSG_NOTIF) {
            if (!session->notif) {
                session_ti_unlock(session);
                ERR("SESSION %u: Received Notification but session is not subscribed.", session->id);
                goto error;
            }

            /* create notification object */
            notif = malloc(sizeof *notif);
            notif->ctx = session->ctx;
            notif->tree = lyd_parse_xml(session->ctx, xml, LYD_OPT_DESTRUCT);
            notif->root = xml;

            /* store the message for nc_recv_notif() */
            cont_n = &session->notifs;
            while(*cont_n) {
                cont_n = &((*cont_n)->next);
            }
            *cont_n = malloc(sizeof **cont_n);
            (*cont_n)->msg = notif;
            (*cont_n)->next = NULL;
        }

        session_ti_unlock(session);

        switch(msgtype) {
        case NC_MSG_REPLY:
            /* distinguish between data / ok / error reply */
            *reply = parse_reply(session->ctx, xml);
            if (!(*reply)) {
                goto error;
            }
            break;
        case NC_MSG_HELLO:
            ERR("SESSION %u: Received another <hello> message.", session->id);
            goto error;
        case NC_MSG_RPC:
            ERR("SESSION %u: Received <rpc> from NETCONF server.", session->id);
            goto error;
        default:
            /* NC_MSG_WOULDBLOCK and NC_MSG_ERROR - pass it out;
             * NC_MSG_NOTIF already handled before the switch;
             * NC_MSG_NONE is not returned by nc_read_msg()
             */
            break;
        }

    } while(msgtype == NC_MSG_NOTIF);

    return msgtype;

error:

    /* cleanup */
    lyxml_free_elem(session->ctx, xml);

    return NC_MSG_ERROR;
}

API NC_MSG_TYPE
nc_recv_notif(struct nc_session *session, int timeout, struct nc_notif **notif)
{
    int r;
    struct lyxml_elem *xml;
    struct nc_notif_cont *cont_n;
    struct nc_reply_cont **cont_r;
    struct nc_reply *reply;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */

    if (!session || !notif) {
        ERR("%s: Invalid parameter", __func__);
        return NC_MSG_ERROR;
    } else if (session->status != NC_STATUS_RUNNING || session->side != NC_CLIENT) {
        ERR("%s: invalid session to receive Notifications.", __func__);
        return NC_MSG_ERROR;
    }

    do {
        if (msgtype) {
            /* second run, wait and give a chance to nc_recv_reply() */
            usleep(TIMEOUT_STEP);
            timeout = timeout - (TIMEOUT_STEP);
        }
        r = session_ti_lock(session, timeout);
        if (r > 0) {
            /* error */
            return NC_MSG_ERROR;
        } else if (r < 0) {
            /* timeout */
            return NC_MSG_WOULDBLOCK;
        }

        /* try to get message from the session's queue */
        if (session->notifs) {
            cont_n = session->notifs;
            session->notifs = cont_n->next;

            session_ti_unlock(session);

            *notif = cont_n->msg;
            free(cont_n);

            return NC_MSG_NOTIF;
        }

        /* read message from wire */
        msgtype = nc_read_msg(session, timeout, &xml);
        if (msgtype == NC_MSG_REPLY) {
            /* distinguish between data / ok / error reply */
            reply = parse_reply(session->ctx, xml);
            if (!reply) {
                goto error;
            }

            /* store the message for nc_recv_reply() */
            cont_r = &session->replies;
            while(*cont_r) {
                cont_r = &((*cont_r)->next);
            }
            *cont_r = malloc(sizeof **cont_r);
            (*cont_r)->msg = reply;
            (*cont_r)->next = NULL;
        }

        session_ti_unlock(session);

        switch(msgtype) {
        case NC_MSG_NOTIF:
            *notif = malloc(sizeof **notif);
            (*notif)->ctx = session->ctx;
            (*notif)->tree = lyd_parse_xml(session->ctx, xml, LYD_OPT_DESTRUCT);
            (*notif)->root = xml;
            break;
        case NC_MSG_HELLO:
            ERR("SESSION %u: Received another <hello> message.", session->id);
            goto error;
        case NC_MSG_RPC:
            ERR("SESSION %u: Received <rpc> from NETCONF server.", session->id);
            goto error;
        default:
            /* NC_MSG_WOULDBLOCK and NC_MSG_ERROR - pass it out;
             * NC_MSG_REPLY already handled before the switch;
             * NC_MSG_NONE is not returned by nc_read_msg()
             */
            break;
        }

    } while(msgtype == NC_MSG_NOTIF);

    return msgtype;

error:

    /* cleanup */
    lyxml_free_elem(session->ctx, xml);

    return NC_MSG_ERROR;
}

static NC_MSG_TYPE
nc_send_hello_(struct nc_session *session)
{
    int r;
    char **cpblts;

    if (session->side == NC_CLIENT) {
        /* client side hello - send only NETCONF base capabilities */
        cpblts = malloc(3 * sizeof *cpblts);
        cpblts[0] = "urn:ietf:params:netconf:base:1.0";
        cpblts[1] = "urn:ietf:params:netconf:base:1.1";
        cpblts[2] = NULL;

        r = nc_write_msg(session, NC_MSG_HELLO, cpblts, NULL);
        free(cpblts);
    }


    if (r) {
        return NC_MSG_ERROR;
    } else {
        return NC_MSG_HELLO;
    }
}

static NC_MSG_TYPE
nc_send_rpc_(struct nc_session *session, struct lyd_node *op)
{
    int r;

    r = nc_write_msg(session, NC_MSG_RPC, op, NULL);

    if (r) {
        return NC_MSG_ERROR;
    } else {
        return NC_MSG_RPC;
    }
}

API NC_MSG_TYPE
nc_send_rpc(struct nc_session *session, struct nc_rpc *rpc)
{
    NC_MSG_TYPE r;
    struct nc_rpc_lock *rpc_lock;
    struct nc_rpc_getconfig *rpc_gc;
    struct nc_rpc_get *rpc_g;
    struct lyd_node *data, *node;
    struct lys_module *ietfnc;

    if (!session || !rpc || rpc->type == NC_RPC_SERVER) {
        ERR("%s: Invalid parameter", __func__);
        return NC_MSG_ERROR;
    } else if (session->status != NC_STATUS_RUNNING || session->side != NC_CLIENT) {
        ERR("%s: invalid session to send RPCs.", __func__);
        return NC_MSG_ERROR;
    }

    ietfnc = ly_ctx_get_module(session->ctx, "ietf-netconf", NULL);
    if (!ietfnc) {
        ERR("%s: Missing ietf-netconf schema in context (session %u)", session->id);
        return NC_MSG_ERROR;
    }

    switch(rpc->type) {
    case NC_RPC_GET:
        rpc_g = (struct nc_rpc_get *)rpc;

        data = lyd_new(NULL, ietfnc, "get");
        if (rpc_g->filter) {
            if (rpc_g->filter->type == NC_FILTER_SUBTREE) {
                node = lyd_new_anyxml(data, ietfnc, "filter", rpc_g->filter->data);
                lyd_insert_attr(node, "type", "subtree");
            } else if (rpc_g->filter->type == NC_FILTER_XPATH) {
                node = lyd_new_anyxml(data, ietfnc, "filter", NULL);
                /* TODO - handle namespaces from XPATH query */
                lyd_insert_attr(node, "type", "xpath");
                lyd_insert_attr(node, "select", rpc_g->filter->data);
            }
        }
        break;
    case NC_RPC_GETCONFIG:
        rpc_gc = (struct nc_rpc_getconfig *)rpc;

        data = lyd_new(NULL, ietfnc, "get-config");
        node = lyd_new(data, ietfnc, "source");
        node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_gc->source], NULL);
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        if (rpc_gc->filter) {
            if (rpc_gc->filter->type == NC_FILTER_SUBTREE) {
                node = lyd_new_anyxml(data, ietfnc, "filter", rpc_gc->filter->data);
                lyd_insert_attr(node, "type", "subtree");
            } else if (rpc_gc->filter->type == NC_FILTER_XPATH) {
                node = lyd_new_anyxml(data, ietfnc, "filter", NULL);
                /* TODO - handle namespaces from XPATH query */
                lyd_insert_attr(node, "type", "xpath");
                lyd_insert_attr(node, "select", rpc_gc->filter->data);
            }
        }
        break;
    case NC_RPC_LOCK:
        rpc_lock = (struct nc_rpc_lock *)rpc;

        data = lyd_new(NULL, ietfnc, "lock");
        node = lyd_new(data, ietfnc, "target");
        node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_lock->target], NULL);
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        break;
    case NC_RPC_UNLOCK:
        rpc_lock = (struct nc_rpc_lock *)rpc;

        data = lyd_new(NULL, ietfnc, "unlock");
        node = lyd_new(data, ietfnc, "target");
        node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_lock->target], NULL);
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        break;
    }

    r = session_ti_lock(session, 0);
    if (r != 0) {
        /* error or blocking */
        r = NC_MSG_WOULDBLOCK;
    } else {
        /* send RPC */
        r = nc_send_rpc_(session, data);
    }
    session_ti_unlock(session);

    lyd_free(data);
    return r;
}
