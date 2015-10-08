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

API NC_MSG_TYPE
nc_recv_rpc(struct nc_session* session, int timeout, struct nc_rpc **rpc)
{
    int r;
    struct lyxml_elem *xml;
    NC_MSG_TYPE msgtype;

    assert(session);
    assert(rpc);

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
                return NC_MSG_ERROR;
            } else {
                /* lock acquired */
                break;
            }
        } while(timeout > 0);

        if (timeout <= 0) {
            /* timeout has passed */
            return NC_MSG_WOULDBLOCK;
        }
    } else {
        /* infinite waiting for lock */
        r = pthread_mutex_lock(&session->ti_lock);
    }

    msgtype = nc_read_msg(session, timeout, &xml);

    pthread_mutex_unlock(&session->ti_lock);

    *rpc = calloc(1, sizeof **rpc);
    (*rpc)->tree = lyd_parse_xml(session->ctx, xml, 0);
    (*rpc)->root = xml;

    return msgtype;
}
