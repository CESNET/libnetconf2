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
#include <arpa/inet.h>
#include <poll.h>

#include <libyang/libyang.h>

#include "libnetconf.h"
#include "messages_p.h"

#define TIMEOUT_STEP 50

static NC_MSG_TYPE nc_send_hello_(struct nc_session *session);
static NC_MSG_TYPE nc_recv_hello(struct nc_session *session);
static NC_MSG_TYPE nc_send_msg(struct nc_session *session, struct lyd_node *op);

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

API NC_STATUS
nc_session_get_status(const struct nc_session *session)
{
    return session->status;
}

API uint32_t
nc_session_get_id(const struct nc_session *session)
{
    return session->id;
}

API NC_TRANSPORT_IMPL
nc_session_get_ti(const struct nc_session *session)
{
    return session->ti_type;
}

API const char *
nc_session_get_username(const struct nc_session *session)
{
    return session->username;
}

API const char *
nc_session_get_host(const struct nc_session *session)
{
    return session->host;
}

API uint16_t
nc_session_get_port(const struct nc_session *session)
{
    return session->port;
}

API const char **
nc_session_get_cpblts(const struct nc_session *session)
{
    return session->cpblts;
}

API const char *
nc_session_cpblt(const struct nc_session *session, const char *capab)
{
    int i, len;

    len = strlen(capab);
    for (i = 0; session->cpblts[i]; ++i) {
        if (!strncmp(session->cpblts[i], capab, len)) {
            return session->cpblts[i];
        }
    }

    return NULL;
}

/*
 * @return 0 - success
 *        -1 - timeout
 *        >0 - error
 */
static int
session_ti_lock(struct nc_session *session, int32_t timeout)
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
nc_handshake(struct nc_session *session)
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

/* SCHEMAS_DIR not used */
static int
ctx_check_and_load_model(struct nc_session *session, const char *cpblt)
{
    const struct lys_module *module;
    char *ptr, *ptr2;
    char *model_name, *revision = NULL, *features = NULL;

    /* parse module */
    ptr = strstr(cpblt, "module=");
    if (!ptr) {
        WRN("Unknown capability \"%s\" could not be parsed.", cpblt);
        return 1;
    }
    ptr += 7;
    ptr2 = strchr(ptr, '&');
    if (!ptr2) {
        ptr2 = ptr + strlen(ptr);
    }
    model_name = strndup(ptr, ptr2 - ptr);

    /* parse revision */
    ptr = strstr(cpblt, "revision=");
    if (ptr) {
        ptr += 9;
        ptr2 = strchr(ptr, '&');
        if (!ptr2) {
            ptr2 = ptr + strlen(ptr);
        }
        revision = strndup(ptr, ptr2 - ptr);
    }

    /* load module if needed */
    module = ly_ctx_get_module(session->ctx, model_name, revision);
    if (!module) {
        module = ly_ctx_load_module(session->ctx, model_name, revision);
    }

    free(model_name);
    free(revision);
    if (!module) {
        return 1;
    }

    /* parse features */
    ptr = strstr(cpblt, "features=");
    if (ptr) {
        ptr += 9;
        ptr2 = strchr(ptr, '&');
        if (!ptr2) {
            ptr2 = ptr + strlen(ptr);
        }
        features = strndup(ptr, ptr2 - ptr);
    }

    /* enable features */
    if (features) {
        /* basically manual strtok_r (to avoid macro) */
        ptr2 = features;
        for (ptr = features; *ptr; ++ptr) {
            if (*ptr == ',') {
                *ptr = '\0';
                /* remember last feature */
                ptr2 = ptr + 1;
            }
        }

        ptr = features;
        lys_features_enable(module, ptr);
        while (ptr != ptr2) {
            ptr += strlen(ptr) + 1;
            lys_features_enable(module, ptr);
        }

        free(features);
    }

    return 0;
}

/* SCHEMAS_DIR used */
static int
ctx_check_and_load_ietf_netconf(struct ly_ctx *ctx, const char **cpblts, int from_file)
{
    int i;
    const struct lys_module *ietfnc;

    ietfnc = ly_ctx_get_module(ctx, "ietf-netconf", NULL);
    if (!ietfnc) {
        if (from_file) {
            ietfnc = lys_parse_path(ctx, SCHEMAS_DIR"/ietf-netconf.yin", LYS_IN_YIN);
        } else {
            ietfnc = ly_ctx_load_module(ctx, "ietf-netconf", NULL);
        }
    }
    if (!ietfnc) {
        ERR("Loading base NETCONF schema failed.");
        return 1;
    }

    /* set supported capabilities from ietf-netconf */
    for (i = 0; cpblts[i]; ++i) {
        if (!strncmp(cpblts[i], "urn:ietf:params:netconf:capability:", 35)) {
            if (!strncmp(cpblts[i] + 35, "writable-running", 16)) {
                lys_features_enable(ietfnc, "writable-running");
            } else if (!strncmp(cpblts[i] + 35, "candidate", 9)) {
                lys_features_enable(ietfnc, "candidate");
            } else if (!strcmp(cpblts[i] + 35, "confirmed-commit:1.1")) {
                lys_features_enable(ietfnc, "confirmed-commit");
            } else if (!strncmp(cpblts[i] + 35, "rollback-on-error", 17)) {
                lys_features_enable(ietfnc, "rollback-on-error");
            } else if (!strcmp(cpblts[i] + 35, "validate:1.1")) {
                lys_features_enable(ietfnc, "validate");
            } else if (!strncmp(cpblts[i] + 35, "startup", 7)) {
                lys_features_enable(ietfnc, "startup");
            } else if (!strncmp(cpblts[i] + 35, "url", 3)) {
                lys_features_enable(ietfnc, "url");
            } else if (!strncmp(cpblts[i] + 35, "xpath", 5)) {
                lys_features_enable(ietfnc, "xpath");
            }
        }
    }

    return 0;
}

static char *
libyang_module_clb(const char *name, const char *revision, void *user_data, LYS_INFORMAT *format,
                   void (**free_model_data)(char *model_data))
{
    struct nc_session *session = (struct nc_session *)user_data;
    struct nc_rpc *rpc;
    struct nc_reply *reply;
    struct nc_reply_data *data_rpl;
    NC_MSG_TYPE msg;
    char *model_data, *ptr, *ptr2, *anyxml;
    uint64_t msgid;

    /* TODO later replace with yang to reduce model size? */
    rpc = nc_rpc_getschema(name, revision, "yin", NC_RPC_PARAMTYPE_CONST);
    *format = LYS_IN_YIN;

    while ((msg = nc_send_rpc(session, rpc, 0, &msgid)) == NC_MSG_WOULDBLOCK) {
        usleep(1000);
    }
    if (msg == NC_MSG_ERROR) {
        ERR("Failed to send the <get-schema> RPC.");
        nc_rpc_free(rpc);
        return NULL;
    }

    msg = nc_recv_reply(session, rpc, msgid, 250, &reply);
    nc_rpc_free(rpc);
    if (msg == NC_MSG_WOULDBLOCK) {
        ERR("Timeout for receiving reply to a <get-schema> expired.");
        return NULL;
    } else if (msg == NC_MSG_ERROR) {
        ERR("Failed to receive a reply to <get-schema>.");
        return NULL;
    }

    data_rpl = (struct nc_reply_data *)reply;
    anyxml = lyxml_serialize(((struct lyd_node_anyxml *)data_rpl->data)->value);
    nc_reply_free(reply);
    *free_model_data = NULL;

    /* it's with the data root node, remove it */
    if (anyxml) {
        ptr = strchr(anyxml, '>');
        ++ptr;

        ptr2 = strrchr(anyxml, '<');

        model_data = strndup(ptr, strlen(ptr) - strlen(ptr2));
        free(anyxml);
    }

    return model_data;
}

int
nc_ctx_check_and_fill(struct nc_session *session)
{
    int i, get_schema_support = 0;
    ly_module_clb old_clb = NULL;
    void *old_data = NULL;

    assert(session->cpblts && session->ctx);

    /* check if get-schema is supported */
    for (i = 0; session->cpblts[i]; ++i) {
        if (!strncmp(session->cpblts[i], "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring", 51)) {
            get_schema_support = 1;
            break;
        }
    }

    /* get-schema is supported, load local ietf-netconf-monitoring so we can create <get-schema> RPCs */
    if (get_schema_support && !ly_ctx_get_module(session->ctx, "ietf-netconf-monitoring", NULL)) {
        if (lys_parse_path(session->ctx, SCHEMAS_DIR"/ietf-netconf-monitoring.yin", LYS_IN_YIN)) {
            /* set module retrieval using <get-schema> */
            old_clb = ly_ctx_get_module_clb(session->ctx, &old_data);
            ly_ctx_set_module_clb(session->ctx, &libyang_module_clb, session);
        } else {
            WRN("Loading NETCONF monitoring schema failed, cannot use <get-schema>.");
        }
    }

    /* load base model disregarding whether it's in capabilities (but NETCONF capabilities are used to enable features) */
    if (ctx_check_and_load_ietf_netconf(session->ctx, session->cpblts, !get_schema_support)) {
        if (old_clb) {
            ly_ctx_set_module_clb(session->ctx, old_clb, old_data);
        }
        return 1;
    }

    /* load all other models */
    for (i = 0; session->cpblts[i]; ++i) {
        if (!strncmp(session->cpblts[i], "urn:ietf:params:netconf:capability", 34)
                || !strncmp(session->cpblts[i], "urn:ietf:params:netconf:base", 28)) {
            continue;
        }

        ctx_check_and_load_model(session, session->cpblts[i]);
    }

    if (old_clb) {
        ly_ctx_set_module_clb(session->ctx, old_clb, old_data);
    }
    return 0;
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
    session = calloc(1, sizeof *session);
    if (!session) {
        ERRMEM;
        return NULL;
    }
    session->status = NC_STATUS_STARTING;
    session->side = NC_CLIENT;

    /* transport specific data */
    session->ti_type = NC_TI_FD;
    session->ti.fd.in = fdin;
    session->ti.fd.out = fdout;

    /* assign context (dicionary needed for handshake) */
    if (!ctx) {
        ctx = ly_ctx_new(SCHEMAS_DIR);
    } else {
        session->flags |= NC_SESSION_SHAREDCTX;
    }
    session->ctx = ctx;

    /* NETCONF handshake */
    if (nc_handshake(session)) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    if (nc_ctx_check_and_fill(session)) {
        goto fail;
    }

    return session;

fail:
    nc_session_free(session);
    return NULL;
}

int
nc_connect_getsocket(const char* host, uint16_t port)
{
    int i, sock = -1;
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
    struct nc_msg_cont *contiter;
    struct lyxml_elem *rpl, *child;
    struct lyd_node *close_rpc;
    const struct lys_module *ietfnc;
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
            WRN("%s: Missing ietf-netconf schema in context (session %u), unable to send <close-session\\>", __func__, session->id);
        } else {
            close_rpc = lyd_new(NULL, ietfnc, "close-session");
            nc_send_msg(session, close_rpc);
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
                lyxml_free(session->ctx, rpl);
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
    case NC_TI_NONE:
        break;

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

                if ((ver = parse_cpblts(node, &session->cpblts)) < 0) {
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

NC_MSG_TYPE
nc_recv_rpc(struct nc_session *session, int32_t timeout, struct nc_server_rpc **rpc)
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
        (*rpc)->tree = lyd_parse_xml(session->ctx, xml, LYD_OPT_DESTRUCT);
        lyxml_free(session->ctx, xml);
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
    lyxml_free(session->ctx, xml);

    return NC_MSG_ERROR;
}

static NC_MSG_TYPE
get_msg(struct nc_session *session, int32_t timeout, uint64_t msgid, struct lyxml_elem **msg)
{
    int r;
    char *ptr;
    const char *str_msgid;
    uint64_t cur_msgid;
    struct lyxml_elem *xml;
    struct nc_msg_cont *cont, *prev_cont, **cont_ptr;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */

next_message:
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

    /* try to get notification from the session's queue */
    if (!msgid && session->notifs) {
        cont = session->notifs;
        session->notifs = cont->next;

        session_ti_unlock(session);

        *msg = cont->msg;
        free(cont);

        return NC_MSG_NOTIF;
    }

    /* try to get rpc-reply from the session's queue */
    if (msgid && session->replies) {
        prev_cont = NULL;
        for (cont = session->replies; cont; cont = cont->next) {
            /* errors checked in the condition below */
            str_msgid = lyxml_get_attr(cont->msg, "message-id", NULL);
            cur_msgid = strtoul(str_msgid, &ptr, 10);

            if (cur_msgid == msgid) {
                if (!prev_cont) {
                    session->replies = cont->next;
                } else {
                    prev_cont->next = cont->next;
                }
                session_ti_unlock(session);

                *msg = cont->msg;
                free(cont);

                return NC_MSG_REPLY;
            }

            prev_cont = cont;
        }
    }

    /* read message from wire */
    msgtype = nc_read_msg(session, timeout, &xml);

    /* we read rpc-reply, want a notif */
    if (!msgid && (msgtype == NC_MSG_REPLY)) {
        /* just check that message-id is fine */
        str_msgid = lyxml_get_attr(xml, "message-id", NULL);
        if (!str_msgid) {
            session_ti_unlock(session);
            ERR("SESSION %u: Received a <rpc-reply> with no message-id, discarding.", session->id);
            lyxml_free(session->ctx, xml);
            goto next_message;
        }
        cur_msgid = strtoul(str_msgid, &ptr, 10);
        if (ptr[0]) {
            session_ti_unlock(session);
            ERR("SESSION %u: Received a <rpc-reply> with an invalid message-id (\"%s\"), discarding.", session->id, str_msgid);
            lyxml_free(session->ctx, xml);
            goto next_message;
        }

        cont_ptr = &session->replies;
        while (*cont_ptr) {
            cont_ptr = &((*cont_ptr)->next);
        }
        *cont_ptr = malloc(sizeof **cont_ptr);
        (*cont_ptr)->msg = xml;
        (*cont_ptr)->next = NULL;
    }

    /* we read notif, want a rpc-reply */
    if (msgid && (msgtype == NC_MSG_NOTIF)) {
        if (!session->notif) {
            session_ti_unlock(session);
            ERR("SESSION %u: Received a <notification> but session is not subscribed.", session->id);
            lyxml_free(session->ctx, xml);
            goto next_message;
        }

        cont_ptr = &session->notifs;
        while (*cont_ptr) {
            cont_ptr = &((*cont_ptr)->next);
        }
        *cont_ptr = malloc(sizeof **cont_ptr);
        (*cont_ptr)->msg = xml;
        (*cont_ptr)->next = NULL;
    }

    session_ti_unlock(session);

    switch (msgtype) {
    case NC_MSG_NOTIF:
        /* we want a rpc-reply */
        if (msgid) {
            goto next_message;
        }
        *msg = xml;
        break;

    case NC_MSG_REPLY:
        /* we want a notif */
        if (!msgid) {
            goto next_message;
        }
        *msg = xml;
        break;

    case NC_MSG_HELLO:
        ERR("SESSION %u: Received another <hello> message.", session->id);
        lyxml_free(session->ctx, xml);
        goto next_message;

    case NC_MSG_RPC:
        ERR("SESSION %u: Received <rpc> from NETCONF server.", session->id);
        lyxml_free(session->ctx, xml);
        goto next_message;

    default:
        /* NC_MSG_WOULDBLOCK and NC_MSG_ERROR - pass it out;
         * NC_MSG_NONE is not returned by nc_read_msg()
         */
        break;
    }

    return msgtype;
}

/* cannot strictly fail, but does not need to fill any error parameter at all */
static void
parse_rpc_error(struct ly_ctx *ctx, struct lyxml_elem *xml, struct nc_err *err)
{
    struct lyxml_elem *iter, *next, *info;

    LY_TREE_FOR(xml->child, iter) {
        if (!iter->ns) {
            if (iter->content) {
                WRN("<rpc-error> child \"%s\" with value \"%s\" without namespace.", iter->name, iter->content);
            } else {
                WRN("<rpc-error> child \"%s\" without namespace.", iter->name);
            }
            continue;
        } else if (strcmp(iter->ns->value, NC_NS_BASE)) {
            if (iter->content) {
                WRN("<rpc-error> child \"%s\" with value \"%s\" in an unknown namespace \"%s\".",
                    iter->name, iter->content, iter->ns->value);
            } else {
                WRN("<rpc-error> child \"%s\" in an unknown namespace \"%s\".", iter->name, iter->ns->value);
            }
            continue;
        }

        if (!strcmp(iter->name, "error-type")) {
            if (!iter->content || (strcmp(iter->content, "transport") && strcmp(iter->content, "rpc")
                    && strcmp(iter->content, "protocol") && strcmp(iter->content, "application"))) {
                WRN("<rpc-error> <error-type> unknown value \"%s\".", (iter->content ? iter->content : ""));
            } else if (err->type) {
                WRN("<rpc-error> <error-type> duplicated.");
            } else {
                err->type = lydict_insert(ctx, iter->content, 0);
            }
        } else if (!strcmp(iter->name, "error-tag")) {
            if (!iter->content || (strcmp(iter->content, "in-use") && strcmp(iter->content, "invalid-value")
                    && strcmp(iter->content, "too-big") && strcmp(iter->content, "missing-attribute")
                    && strcmp(iter->content, "bad-attribute") && strcmp(iter->content, "unknown-attribute")
                    && strcmp(iter->content, "missing-element") && strcmp(iter->content, "bad-element")
                    && strcmp(iter->content, "unknown-element") && strcmp(iter->content, "unknown-namespace")
                    && strcmp(iter->content, "access-denied") && strcmp(iter->content, "lock-denied")
                    && strcmp(iter->content, "resource-denied") && strcmp(iter->content, "rollback-failed")
                    && strcmp(iter->content, "data-exists") && strcmp(iter->content, "data-missing")
                    && strcmp(iter->content, "operation-not-supported") && strcmp(iter->content, "operation-failed")
                    && strcmp(iter->content, "malformed-message"))) {
                WRN("<rpc-error> <error-tag> unknown value \"%s\".", (iter->content ? iter->content : ""));
            } else if (err->tag) {
                WRN("<rpc-error> <error-tag> duplicated.");
            } else {
                err->tag = lydict_insert(ctx, iter->content, 0);
            }
        } else if (!strcmp(iter->name, "error-severity")) {
            if (!iter->content || (strcmp(iter->content, "error") && strcmp(iter->content, "warning"))) {
                WRN("<rpc-error> <error-severity> unknown value \"%s\".", (iter->content ? iter->content : ""));
            } else if (err->severity) {
                WRN("<rpc-error> <error-severity> duplicated.");
            } else {
                err->severity = lydict_insert(ctx, iter->content, 0);
            }
        } else if (!strcmp(iter->name, "error-app-tag")) {
            if (err->apptag) {
                WRN("<rpc-error> <error-app-tag> duplicated.");
            } else {
                err->apptag = lydict_insert(ctx, (iter->content ? iter->content : ""), 0);
            }
        } else if (!strcmp(iter->name, "error-path")) {
            if (err->path) {
                WRN("<rpc-error> <error-path> duplicated.");
            } else {
                err->path = lydict_insert(ctx, (iter->content ? iter->content : ""), 0);
            }
        } else if (!strcmp(iter->name, "error-message")) {
            if (err->message) {
                WRN("<rpc-error> <error-message> duplicated.");
            } else {
                err->message_lang = lyxml_get_attr(iter, "xml:lang", NULL);
                if (!err->message_lang) {
                    VRB("<rpc-error> <error-message> without the recommended \"xml:lang\" attribute.");
                }
                err->message = lydict_insert(ctx, (iter->content ? iter->content : ""), 0);
            }
        } else if (!strcmp(iter->name, "error-info")) {
            LY_TREE_FOR_SAFE(iter->child, next, info) {
                if (info->ns && !strcmp(info->ns->value, NC_NS_BASE)) {
                    if (!strcmp(info->name, "session-id")) {
                        if (err->sid) {
                            WRN("<rpc-error> <error-info> <session-id> duplicated.");
                        } else {
                            err->sid = lydict_insert(ctx, (info->content ? info->content : ""), 0);
                        }
                    } else if (!strcmp(info->name, "bad-attr")) {
                        ++err->attr_count;
                        err->attr = realloc(err->attr, err->attr_count * sizeof *err->attr);
                        err->attr[err->attr_count - 1] = lydict_insert(ctx, (info->content ? info->content : ""), 0);
                    } else if (!strcmp(info->name, "bad-element")) {
                        ++err->elem_count;
                        err->elem = realloc(err->elem, err->elem_count * sizeof *err->elem);
                        err->elem[err->elem_count - 1] = lydict_insert(ctx, (info->content ? info->content : ""), 0);
                    } else if (!strcmp(info->name, "bad-namespace")) {
                        ++err->ns_count;
                        err->ns = realloc(err->ns, err->ns_count * sizeof *err->ns);
                        err->ns[err->ns_count - 1] = lydict_insert(ctx, (info->content ? info->content : ""), 0);
                    } else {
                        if (info->content) {
                            WRN("<rpc-error> <error-info> unknown child \"%s\" with value \"%s\".",
                                info->name, info->content);
                        } else {
                            WRN("<rpc-error> <error-info> unknown child \"%s\".", info->name);
                        }
                    }
                } else {
                    lyxml_unlink(ctx, info);
                    ++err->other_count;
                    err->other = realloc(err->other, err->other_count * sizeof *err->other);
                    err->other[err->other_count - 1] = info;
                }
            }
        } else {
            if (iter->content) {
                WRN("<rpc-error> unknown child \"%s\" with value \"%s\".", iter->name, iter->content);
            } else {
                WRN("<rpc-error> unknown child \"%s\".", iter->name);
            }
        }
    }
}

static struct nc_reply *
parse_reply(struct ly_ctx *ctx, struct lyxml_elem *xml, struct nc_rpc *rpc)
{
    struct lyxml_elem *iter;
    const struct lys_node *schema;
    struct lyd_node *data = NULL;
    struct nc_reply_error *error_rpl;
    struct nc_reply_data *data_rpl;
    struct nc_reply *reply = NULL;
    struct nc_rpc_generic *rpc_gen;
    int i;

    if (!xml->child) {
        ERR("An empty <rpc-reply>.");
        return NULL;
    }

    /* rpc-error */
    if (!strcmp(xml->child->name, "rpc-error") && xml->child->ns && !strcmp(xml->child->ns->value, NC_NS_BASE)) {
        /* count and check elements */
        i = 0;
        LY_TREE_FOR(xml->child, iter) {
            if (strcmp(iter->name, "rpc-error")) {
                ERR("<rpc-reply> content mismatch (<rpc-error> and <%s>).", iter->name);
                return NULL;
            } else if (!iter->ns) {
                ERR("<rpc-reply> content mismatch (<rpc-error> without namespace).");
                return NULL;
            } else if (strcmp(iter->ns->value, NC_NS_BASE)) {
                ERR("<rpc-reply> content mismatch (<rpc-error> with NS \"%s\").", iter->ns->value);
                return NULL;
            }
            ++i;
        }

        error_rpl = malloc(sizeof *error_rpl);
        error_rpl->type = NC_REPLY_ERROR;
        error_rpl->ctx = ctx;
        error_rpl->err = calloc(i, sizeof *error_rpl->err);
        error_rpl->err_count = i;
        reply = (struct nc_reply *)error_rpl;

        i = 0;
        LY_TREE_FOR(xml->child, iter) {
            parse_rpc_error(ctx, iter, error_rpl->err + i);
            ++i;
        }

    /* ok */
    } else if (!strcmp(xml->child->name, "ok") && xml->child->ns && !strcmp(xml->child->ns->value, NC_NS_BASE)) {
        if (xml->child->next) {
            ERR("<rpc-reply> content mismatch (<ok> and <%s>).", xml->child->next->name);
            return NULL;
        }
        reply = malloc(sizeof *reply);
        reply->type = NC_REPLY_OK;

    /* some RPC output */
    } else {
        switch (rpc->type) {
        case NC_RPC_GENERIC:
            rpc_gen = (struct nc_rpc_generic *)rpc;

            if (rpc_gen->has_data) {
                schema = rpc_gen->content.data->schema;
            } else {
                data = lyd_parse_data(ctx, rpc_gen->content.xml_str, LYD_XML, 0);
                if (!data) {
                    ERR("Failed to parse a generic RPC XML.");
                    return NULL;
                }
                schema = data->schema;
                lyd_free(data);
                data = NULL;
            }
            if (!schema) {
                ERR("%s: internal error (%s:%d).", __func__, __FILE__, __LINE__);
                return NULL;
            }
            break;

        case NC_RPC_GETCONFIG:
        case NC_RPC_GET:
            /* special treatment */
            data = lyd_parse_xml(ctx, xml->child, LYD_OPT_DESTRUCT
                                 | (rpc->type == NC_RPC_GETCONFIG ? LYD_OPT_GETCONFIG : LYD_OPT_GET));
            if (!data) {
                ERR("Failed to parse <%s> reply.", (rpc->type == NC_RPC_GETCONFIG ? "get-config" : "get"));
                return NULL;
            }
            break;

        case NC_RPC_GETSCHEMA:
            schema = ly_ctx_get_node(ctx, "/ietf-netconf-monitoring:get-schema");
            if (!schema) {
                ERR("%s: internal error (%s:%d).", __func__, __FILE__, __LINE__);
                return NULL;
            }
            break;

        case NC_RPC_EDIT:
        case NC_RPC_COPY:
        case NC_RPC_DELETE:
        case NC_RPC_LOCK:
        case NC_RPC_UNLOCK:
        case NC_RPC_KILL:
        case NC_RPC_COMMIT:
        case NC_RPC_DISCARD:
        case NC_RPC_CANCEL:
        case NC_RPC_VALIDATE:
        case NC_RPC_SUBSCRIBE:
            /* there is no output defined */
            ERR("Unexpected data reply (root elem \"%s\").", xml->child->name);
            return NULL;
        }

        data_rpl = malloc(sizeof *data_rpl);
        data_rpl->type = NC_REPLY_DATA;
        if (!data) {
            data_rpl->data = lyd_parse_output_xml(schema, xml, LYD_OPT_DESTRUCT);
        } else {
            /* <get>, <get-config> */
            data_rpl->data = data;
        }
        if (!data_rpl->data) {
            ERR("Failed to parse <rpc-reply>.");
            free(data_rpl);
            return NULL;
        }
        reply = (struct nc_reply *)data_rpl;
    }

    return reply;
}

API NC_MSG_TYPE
nc_recv_reply(struct nc_session *session, struct nc_rpc *rpc, uint64_t msgid, int32_t timeout, struct nc_reply **reply)
{
    struct lyxml_elem *xml;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */

    if (!session || !reply) {
        ERR("%s: Invalid parameter", __func__);
        return NC_MSG_ERROR;
    } else if (session->status != NC_STATUS_RUNNING || session->side != NC_CLIENT) {
        ERR("%s: invalid session to receive RPC replies.", __func__);
        return NC_MSG_ERROR;
    }
    *reply = NULL;

    msgtype = get_msg(session, timeout, msgid, &xml);
    if (msgtype == NC_MSG_WOULDBLOCK) {
        return NC_MSG_WOULDBLOCK;
    }

    if (msgtype == NC_MSG_REPLY) {
        *reply = parse_reply(session->ctx, xml, rpc);
        lyxml_free(session->ctx, xml);
        if (!(*reply)) {
            return NC_MSG_ERROR;
        }
    }

    return msgtype;
}

API NC_MSG_TYPE
nc_recv_notif(struct nc_session *session, int timeout, struct nc_notif **notif)
{
    struct lyxml_elem *xml, *ev_time;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */

    if (!session || !notif) {
        ERR("%s: Invalid parameter", __func__);
        return NC_MSG_ERROR;
    } else if (session->status != NC_STATUS_RUNNING || session->side != NC_CLIENT) {
        ERR("%s: Invalid session to receive Notifications.", __func__);
        return NC_MSG_ERROR;
    }

    msgtype = get_msg(session, timeout, 0, &xml);

    if (msgtype == NC_MSG_NOTIF) {
        *notif = calloc(1, sizeof **notif);

        /* eventTime */
        LY_TREE_FOR(xml->child, ev_time) {
            if (!strcmp(ev_time->name, "eventTime")) {
                (*notif)->datetime = lydict_insert(session->ctx, ev_time->content, 0);
                /* lyd_parse does not know this element */
                lyxml_free(session->ctx, ev_time);
                break;
            }
        }
        if (!(*notif)->datetime) {
            ERR("%s: Notification is missing the \"eventTime\" element.", __func__);
            goto fail;
        }

        /* notification body */
        (*notif)->tree = lyd_parse_xml(session->ctx, xml, LYD_OPT_DESTRUCT);
        lyxml_free(session->ctx, xml);
        xml = NULL;
        if (!(*notif)->tree) {
            ERR("%s: Failed to parse a new notification.", __func__);
            goto fail;
        }
    }

    return msgtype;

fail:
    lydict_remove(session->ctx, (*notif)->datetime);
    lyd_free((*notif)->tree);
    free(*notif);
    *notif = NULL;
    lyxml_free(session->ctx, xml);

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

API NC_MSG_TYPE
nc_send_rpc(struct nc_session *session, struct nc_rpc *rpc, int32_t timeout, uint64_t *msgid)
{
    NC_MSG_TYPE r;
    struct nc_rpc_generic *rpc_gen;
    struct nc_rpc_getconfig *rpc_gc;
    struct nc_rpc_edit *rpc_e;
    struct nc_rpc_copy *rpc_cp;
    struct nc_rpc_delete *rpc_del;
    struct nc_rpc_lock *rpc_lock;
    struct nc_rpc_get *rpc_g;
    struct nc_rpc_kill *rpc_k;
    struct nc_rpc_commit *rpc_com;
    struct nc_rpc_cancel *rpc_can;
    struct nc_rpc_validate *rpc_val;
    struct nc_rpc_getschema *rpc_gs;
    struct nc_rpc_subscribe *rpc_sub;
    struct lyd_node *data, *node;
    const struct lys_module *ietfnc, *ietfncmon, *notifs, *ietfncwd = NULL;
    char str[11];
    uint64_t cur_msgid;

    if (!session || !rpc) {
        ERR("%s: Invalid parameter", __func__);
        return NC_MSG_ERROR;
    } else if (session->status != NC_STATUS_RUNNING || session->side != NC_CLIENT) {
        ERR("%s: invalid session to send RPCs.", __func__);
        return NC_MSG_ERROR;
    }

    if ((rpc->type != NC_RPC_GETSCHEMA) && (rpc->type != NC_RPC_GENERIC) && (rpc->type != NC_RPC_SUBSCRIBE)) {
        ietfnc = ly_ctx_get_module(session->ctx, "ietf-netconf", NULL);
        if (!ietfnc) {
            ERR("%s: Missing ietf-netconf schema in context (session %u).", __func__, session->id);
            return NC_MSG_ERROR;
        }
    }

    switch (rpc->type) {
    case NC_RPC_GENERIC:
        rpc_gen = (struct nc_rpc_generic *)rpc;

        if (rpc_gen->has_data) {
            data = rpc_gen->content.data;
        } else {
            data = lyd_parse_data(session->ctx, rpc_gen->content.xml_str, LYD_XML, LYD_OPT_STRICT);
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
            if (rpc_gc->filter[0] == '<') {
                node = lyd_new_anyxml(data, ietfnc, "filter", rpc_gc->filter);
                lyd_insert_attr(node, "type", "subtree");
            } else {
                node = lyd_new_anyxml(data, ietfnc, "filter", NULL);
                lyd_insert_attr(node, "type", "xpath");
                lyd_insert_attr(node, "select", rpc_gc->filter);
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_gc->wd_mode) {
            if (!ietfncwd) {
                ietfncwd = ly_ctx_get_module(session->ctx, "ietf-netconf-with-defaults", NULL);
                if (!ietfncwd) {
                    ERR("%s: Missing ietf-netconf-with-defaults schema in context (session %u).", __func__, session->id);
                    return NC_MSG_ERROR;
                }
            }
            switch (rpc_gc->wd_mode) {
            case NC_WD_UNKNOWN:
                /* cannot get here */
                break;
            case NC_WD_ALL:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all");
                break;
            case NC_WD_ALL_TAG:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all-tagged");
                break;
            case NC_WD_TRIM:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "trim");
                break;
            case NC_WD_EXPLICIT:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "explicit");
                break;
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_EDIT:
        rpc_e = (struct nc_rpc_edit *)rpc;

        data = lyd_new(NULL, ietfnc, "edit-config");
        node = lyd_new(data, ietfnc, "target");
        node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_e->target], NULL);
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }

        if (rpc_e->default_op) {
            node = lyd_new_leaf(data, ietfnc, "default-operation", rpcedit_dfltop2str[rpc_e->default_op]);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_e->test_opt) {
            node = lyd_new_leaf(data, ietfnc, "test-option", rpcedit_testopt2str[rpc_e->test_opt]);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_e->error_opt) {
            node = lyd_new_leaf(data, ietfnc, "error-option", rpcedit_erropt2str[rpc_e->error_opt]);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_e->edit_cont[0] == '<') {
            node = lyd_new_anyxml(data, ietfnc, "config", rpc_e->edit_cont);
        } else {
            node = lyd_new_leaf(data, ietfnc, "url", rpc_e->edit_cont);
        }
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        break;

    case NC_RPC_COPY:
        rpc_cp = (struct nc_rpc_copy *)rpc;

        data = lyd_new(NULL, ietfnc, "copy-config");
        node = lyd_new(data, ietfnc, "target");
        if (rpc_cp->url_trg) {
            node = lyd_new_leaf(node, ietfnc, "url", rpc_cp->url_trg);
        } else {
            node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_cp->target], NULL);
        }
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }

        node = lyd_new(data, ietfnc, "source");
        if (rpc_cp->url_config_src) {
            if (rpc_cp->url_config_src[0] == '<') {
                node = lyd_new_anyxml(node, ietfnc, "config", rpc_cp->url_config_src);
            } else {
                node = lyd_new_leaf(node, ietfnc, "url", rpc_cp->url_config_src);
            }
        } else {
            node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_cp->source], NULL);
        }
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }

        if (rpc_cp->wd_mode) {
            if (!ietfncwd) {
                ietfncwd = ly_ctx_get_module(session->ctx, "ietf-netconf-with-defaults", NULL);
                if (!ietfncwd) {
                    ERR("%s: Missing ietf-netconf-with-defaults schema in context (session %u).", __func__, session->id);
                    return NC_MSG_ERROR;
                }
            }
            switch (rpc_cp->wd_mode) {
            case NC_WD_UNKNOWN:
                /* cannot get here */
                break;
            case NC_WD_ALL:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all");
                break;
            case NC_WD_ALL_TAG:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all-tagged");
                break;
            case NC_WD_TRIM:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "trim");
                break;
            case NC_WD_EXPLICIT:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "explicit");
                break;
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_DELETE:
        rpc_del = (struct nc_rpc_delete *)rpc;

        data = lyd_new(NULL, ietfnc, "delete-config");
        node = lyd_new(data, ietfnc, "target");
        if (rpc_del->url) {
            node = lyd_new_leaf(node, ietfnc, "url", rpc_del->url);
        } else {
            node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_del->target], NULL);
        }
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
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

    case NC_RPC_GET:
        rpc_g = (struct nc_rpc_get *)rpc;

        data = lyd_new(NULL, ietfnc, "get");
        if (rpc_g->filter) {
            if (rpc_g->filter[0] == '<') {
                node = lyd_new_anyxml(data, ietfnc, "filter", rpc_g->filter);
                lyd_insert_attr(node, "type", "subtree");
            } else {
                node = lyd_new_anyxml(data, ietfnc, "filter", NULL);
                lyd_insert_attr(node, "type", "xpath");
                lyd_insert_attr(node, "select", rpc_g->filter);
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_g->wd_mode) {
            if (!ietfncwd) {
                ietfncwd = ly_ctx_get_module(session->ctx, "ietf-netconf-with-defaults", NULL);
                if (!ietfncwd) {
                    ERR("%s: Missing ietf-netconf-with-defaults schema in context (session %u).", __func__, session->id);
                    return NC_MSG_ERROR;
                }
            }
            switch (rpc_g->wd_mode) {
            case NC_WD_UNKNOWN:
                /* cannot get here */
                break;
            case NC_WD_ALL:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all");
                break;
            case NC_WD_ALL_TAG:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all-tagged");
                break;
            case NC_WD_TRIM:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "trim");
                break;
            case NC_WD_EXPLICIT:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "explicit");
                break;
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_KILL:
        rpc_k = (struct nc_rpc_kill *)rpc;

        data = lyd_new(NULL, ietfnc, "kill-session");
        sprintf(str, "%u", rpc_k->sid);
        lyd_new_leaf(data, ietfnc, "session-id", str);
        break;

    case NC_RPC_COMMIT:
        rpc_com = (struct nc_rpc_commit *)rpc;

        data = lyd_new(NULL, ietfnc, "commit");
        if (rpc_com->confirmed) {
            lyd_new_leaf(data, ietfnc, "confirmed", NULL);
        }

        if (rpc_com->confirm_timeout) {
            sprintf(str, "%u", rpc_com->confirm_timeout);
            lyd_new_leaf(data, ietfnc, "confirm-timeout", str);
        }

        if (rpc_com->persist) {
            node = lyd_new_leaf(data, ietfnc, "persist", rpc_com->persist);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_com->persist_id) {
            node = lyd_new_leaf(data, ietfnc, "persist-id", rpc_com->persist_id);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_DISCARD:
        data = lyd_new(NULL, ietfnc, "discard-changes");
        break;

    case NC_RPC_CANCEL:
        rpc_can = (struct nc_rpc_cancel *)rpc;

        data = lyd_new(NULL, ietfnc, "cancel-commit");
        if (rpc_can->persist_id) {
            node = lyd_new_leaf(data, ietfnc, "persist-id", rpc_can->persist_id);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_VALIDATE:
        rpc_val = (struct nc_rpc_validate *)rpc;

        data = lyd_new(NULL, ietfnc, "validate");
        if (rpc_val->url_config_src) {
            if (rpc_val->url_config_src[0] == '<') {
                node = lyd_new_anyxml(data, ietfnc, "config", rpc_val->url_config_src);
            } else {
                node = lyd_new_leaf(data, ietfnc, "url", rpc_val->url_config_src);
            }
        } else {
            node = lyd_new_leaf(data, ietfnc, ncds2str[rpc_val->source], NULL);
        }
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        break;

    case NC_RPC_GETSCHEMA:
        ietfncmon = ly_ctx_get_module(session->ctx, "ietf-netconf-monitoring", NULL);
        if (!ietfncmon) {
            ERR("%s: Missing ietf-netconf-monitoring schema in context (session %u)", session->id);
            return NC_MSG_ERROR;
        }

        rpc_gs = (struct nc_rpc_getschema *)rpc;

        data = lyd_new(NULL, ietfncmon, "get-schema");
        node = lyd_new_leaf(data, ietfncmon, "identifier", rpc_gs->identifier);
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        if (rpc_gs->version) {
            node = lyd_new_leaf(data, ietfncmon, "version", rpc_gs->version);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        if (rpc_gs->format) {
            node = lyd_new_leaf(data, ietfncmon, "format", rpc_gs->format);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_SUBSCRIBE:
        notifs = ly_ctx_get_module(session->ctx, "notifications", NULL);
        if (!notifs) {
            ERR("%s: Missing notifications schema in context (session %u)", session->id);
            return NC_MSG_ERROR;
        }

        rpc_sub = (struct nc_rpc_subscribe *)rpc;

        data = lyd_new(NULL, notifs, "create-subscription");
        if (rpc_sub->stream) {
            node = lyd_new_leaf(data, notifs, "stream", rpc_sub->stream);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_sub->filter) {
            if (rpc_sub->filter[0] == '<') {
                node = lyd_new_anyxml(data, notifs, "filter", rpc_sub->filter);
                lyd_insert_attr(node, "type", "subtree");
            } else {
                node = lyd_new_anyxml(data, notifs, "filter", NULL);
                lyd_insert_attr(node, "type", "xpath");
                lyd_insert_attr(node, "select", rpc_sub->filter);
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_sub->start) {
            node = lyd_new_leaf(data, notifs, "startTime", rpc_sub->start);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_sub->stop) {
            node = lyd_new_leaf(data, notifs, "stopTime", rpc_sub->stop);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;
    }

    if (lyd_validate(data, LYD_OPT_STRICT)) {
        lyd_free(data);
        return NC_MSG_ERROR;
    }

    r = session_ti_lock(session, timeout);
    if (r != 0) {
        /* error or blocking */
        r = NC_MSG_WOULDBLOCK;
    } else {
        /* send RPC, store its message ID */
        r = nc_send_msg(session, data);
        cur_msgid = session->msgid;
    }
    session_ti_unlock(session);

    lyd_free(data);

    if (r != NC_MSG_RPC) {
        return r;
    }

    *msgid = cur_msgid;
    return NC_MSG_RPC;
}

/* CALL HOME */

static int
get_listen_socket(const char *address, uint16_t port)
{
    int sock;
    const int optVal = 1;
    const socklen_t optLen = sizeof(optVal);
    char is_ipv4;
    struct sockaddr_storage saddr;

    struct sockaddr_in* saddr4;
    struct sockaddr_in6* saddr6;

    if (!address || !port) {
        return -1;
    }

    if (strchr(address, ':') == NULL) {
        is_ipv4 = 1;
    } else {
        is_ipv4 = 0;
    }

    sock = socket((is_ipv4 ? AF_INET : AF_INET6), SOCK_STREAM, 0);
    if (sock == -1) {
        ERR("Could not create socket (%s)", strerror(errno));
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&optVal, optLen)) {
        ERR("Could not set socket SO_REUSEADDR option (%s)", strerror(errno));
        close(sock);
        return -1;
    }

    /* TODO may be needed
    if (fcntl(sock, F_SETFD, FD_CLOEXEC) != 0) {
        nc_verb_error("%s: fcntl failed (%s)", __func__, strerror(errno));
        continue;
    }*/

    bzero(&saddr, sizeof(struct sockaddr_storage));
    if (is_ipv4) {
        saddr4 = (struct sockaddr_in *)&saddr;

        saddr4->sin_family = AF_INET;
        saddr4->sin_port = htons(port);

        if (inet_pton(AF_INET, address, &saddr4->sin_addr) != 1) {
            ERR("Failed to convert \"%s\" to IPv4 address.", address);
            close(sock);
            return -1;
        }

        if (bind(sock, (struct sockaddr*)saddr4, sizeof(struct sockaddr_in)) == -1) {
            ERR("Could not bind \"%s\" port %d (%s).", address, port, strerror(errno));
            close(sock);
            return -1;
        }

    } else {
        saddr6 = (struct sockaddr_in6 *)&saddr;

        saddr6->sin6_family = AF_INET6;
        saddr6->sin6_port = htons(port);

        if (inet_pton(AF_INET6, address, &saddr6->sin6_addr) != 1) {
            ERR("Failed to convert \"%s\" to IPv6 address.", address);
            close(sock);
            return -1;
        }

        if (bind(sock, (struct sockaddr*)saddr6, sizeof(struct sockaddr_in6)) == -1) {
            ERR("Could not bind \"%s\" port %d (%s)", __func__, address, port, strerror(errno));
            close(sock);
            return -1;
        }
    }

    if (listen(sock, NC_REVERSE_QUEUE)) {
        ERR("Unable to start listening on \"%s\" port %d (%s)", __func__, address, port, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

int
nc_callhome_accept_connection(uint16_t port, int32_t timeout, uint16_t *server_port, char **server_host)
{
    struct pollfd reverse_listen_socket = {-1, POLLIN, 0};
    int sock;
    struct sockaddr_storage remote;
    socklen_t addr_size = sizeof(remote);
    int status;

    reverse_listen_socket.fd = get_listen_socket("::0", port);
    if (reverse_listen_socket.fd == -1) {
        goto fail;
    }

    reverse_listen_socket.revents = 0;
    while (1) {
        DBG("Waiting %ums for incoming Call Home connections.", timeout);
        status = poll(&reverse_listen_socket, 1, timeout);

        if (status == 0) {
            /* timeout */
            ERR("Timeout for Call Home listen expired.");
            goto fail;
        } else if ((status == -1) && (errno == EINTR)) {
            /* poll was interrupted - try it again */
            continue;
        } else if (status < 0) {
            /* poll failed - something wrong happened */
            ERR("Call Home poll failed (%s).", strerror(errno));
            goto fail;
        } else if (status > 0) {
            if (reverse_listen_socket.revents & (POLLHUP | POLLERR)) {
                /* close pipe/fd - other side already did it */
                ERR("Call Home listening socket was closed.");
                goto fail;
            } else if (reverse_listen_socket.revents & POLLIN) {
                /* accept call home */
                sock = accept(reverse_listen_socket.fd, (struct sockaddr *)&remote, &addr_size);
                break;
            }
        }
    }

    /* we accepted a connection, that's it */
    close(reverse_listen_socket.fd);

    /* fill some server info, if interested */
    if (remote.ss_family == AF_INET) {
        struct sockaddr_in *remote_in = (struct sockaddr_in *)&remote;
        if (server_port) {
            *server_port = ntohs(remote_in->sin_port);
        }
        if (server_host) {
            *server_host = malloc(INET6_ADDRSTRLEN);
            inet_ntop(AF_INET, &(remote_in->sin_addr), *server_host, INET6_ADDRSTRLEN);
        }
    } else if (remote.ss_family == AF_INET6) {
        struct sockaddr_in6 *remote_in = (struct sockaddr_in6 *)&remote;
        if (server_port) {
            *server_port = ntohs(remote_in->sin6_port);
        }
        if (server_host) {
            *server_host = malloc(INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(remote_in->sin6_addr), *server_host, INET6_ADDRSTRLEN);
        }
    }

    return sock;

fail:
    if (reverse_listen_socket.fd != -1) {
        close(reverse_listen_socket.fd);
    }

    return -1;
}
