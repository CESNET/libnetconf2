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
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "config.h"
#include "libnetconf.h"
#include "messages_p.h"
#include "session_p.h"

#define TIMEOUT_STEP 50

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
            r = pthread_mutex_trylock(&session->ti_lock);
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
        return pthread_mutex_lock(&session->ti_lock);
    }
}

static int
session_ti_unlock(struct nc_session *session)
{
    return pthread_mutex_unlock(&session->ti_lock);
}

API NC_MSG_TYPE
nc_recv_rpc(struct nc_session *session, int timeout, struct nc_rpc **rpc)
{
    int r;
    struct lyxml_elem *xml = NULL;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */

    if (!session || !rpc) {
        ERR("%s: Invalid parameter", __func__);
        return NC_MSG_ERROR;
    } else if (session->side != NC_SIDE_SERVER) {
        ERR("%s: only servers are allowed to receive RPCs.", __func__);
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
        *rpc = calloc(1, sizeof **rpc);
        (*rpc)->tree = lyd_parse_xml(session->ctx, xml, 0);
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

API NC_MSG_TYPE
nc_recv_reply(struct nc_session* session, int timeout, struct nc_reply **reply)
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
    } else if (session->side != NC_SIDE_CLIENT) {
        ERR("%s: only clients are allowed to receive RPC replies.", __func__);
        return NC_MSG_ERROR;
    }

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
            notif = calloc(1, sizeof *notif);
            notif->tree = lyd_parse_xml(session->ctx, xml, 0);
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
            *reply = calloc(1, sizeof **reply);
            (*reply)->tree = lyd_parse_xml(session->ctx, xml, 0);
            (*reply)->root = xml;
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
nc_recv_notif(struct nc_session* session, int timeout, struct nc_notif **notif)
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
    } else if (session->side != NC_SIDE_CLIENT) {
        ERR("%s: only clients are allowed to receive Notifications.", __func__);
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
            /* create reply object */
            reply = calloc(1, sizeof *reply);
            reply->tree = lyd_parse_xml(session->ctx, xml, 0);
            reply->root = xml;

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
            *notif = calloc(1, sizeof **notif);
            (*notif)->tree = lyd_parse_xml(session->ctx, xml, 0);
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

    } while(msgtype == NC_MSG_REPLY);

    return msgtype;

error:

    /* cleanup */
    lyxml_free_elem(session->ctx, xml);

    return NC_MSG_ERROR;
}

API NC_MSG_TYPE
nc_send_rpc(struct nc_session* session, struct lyd_node *op, const char *attrs)
{
    int r;

    if (!session || !op) {
        ERR("%s: Invalid parameter", __func__);
        return NC_MSG_ERROR;
    } else if (session->side != NC_SIDE_CLIENT) {
        ERR("%s: only clients are allowed to send RPCs.", __func__);
        return NC_MSG_ERROR;
    }

    r = session_ti_lock(session, 0);
    if (r != 0) {
        /* error or blocking */
        return NC_MSG_WOULDBLOCK;
    }

    r = nc_write_msg(session, NC_MSG_RPC, op, attrs);

    session_ti_unlock(session);

    if (r) {
        return NC_MSG_ERROR;
    } else {
        return NC_MSG_RPC;
    }
}

