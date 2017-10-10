/**
 * @file ssh.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief SSH parameters management
 *
 * Copyright (c) 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

/* Python API header */
#include <Python.h>

/* standard headers */
#include <string.h>

#include <libyang/libyang.h>
#include <libyang/swigpyrun.h>

#include "netconf.h"
#include "session.h"

#define TIMEOUT_SEND 1000  /* 1 second */
#define TIMEOUT_RECV 10000 /* 10 second */

extern PyObject *libnetconf2Error;

static struct nc_reply *
rpc_send_recv(struct nc_session *session, struct nc_rpc *rpc)
{
    uint64_t msgid;
    NC_MSG_TYPE msgtype;
    struct nc_reply *reply;

    msgtype = nc_send_rpc(session, rpc, TIMEOUT_SEND, &msgid);
    if (msgtype == NC_MSG_ERROR) {
        PyErr_SetString(PyExc_ConnectionError, "Failed to send a request.");
        return NULL;
    } else if (msgtype == NC_MSG_WOULDBLOCK) {
        PyErr_SetString(PyExc_ConnectionError, "Sending a request timeouted.");
        return NULL;
    }

recv_reply:
    msgtype = nc_recv_reply(session, rpc, msgid, TIMEOUT_RECV, LYD_OPT_DESTRUCT | LYD_OPT_NOSIBLINGS, &reply);
    if (msgtype == NC_MSG_ERROR) {
        PyErr_SetString(PyExc_ConnectionError, "Failed to receive a reply.");
        return NULL;
    } else if (msgtype == NC_MSG_WOULDBLOCK) {
        PyErr_SetString(PyExc_ConnectionError, "Receiving a reply timeouted.");
        return NULL;
    } else if (msgtype == NC_MSG_NOTIF) {
        /* read again */
        goto recv_reply;
    } else if (msgtype == NC_MSG_REPLY_ERR_MSGID) {
        /* unexpected message, try reading again to get the correct reply */
        nc_reply_free(reply);
        goto recv_reply;
    }

    return reply;
}

static PyObject *
process_reply_data(struct nc_reply *reply)
{
    struct lyd_node *data;
    PyObject *result;

    /* check the type of the received reply message */
    if (reply->type != NC_RPL_DATA) {
        if (reply->type == NC_RPL_ERROR) {
            PyErr_SetString(libnetconf2Error, ((struct nc_reply_error*)reply)->err->message);
        } else {
            PyErr_SetString(libnetconf2Error, "Unexpected reply received.");
        }
        nc_reply_free(reply);
        return NULL;
    }

    /* process the received data */
    data = ((struct nc_reply_data*)reply)->data;
    ((struct nc_reply_data*)reply)->data = NULL;
    nc_reply_free(reply);

    lyd_print_file(stdout, data, LYD_XML, LYP_FORMAT);

    result = SWIG_NewPointerObj(data, SWIG_Python_TypeQuery("std::shared_ptr<Data_Node>*"), SWIG_POINTER_DISOWN);
    if (!result) {
        PyErr_SetString(libnetconf2Error, "Building Python object from lyd_node* failed");
    }

    return result;
}

PyObject *
ncRPCGet(ncSessionObject *self, PyObject *args, PyObject *keywords)
{
    const char *xml = NULL, *xpath = NULL;
    static char *kwlist[] = {"subtree", "xpath", NULL};
    struct nc_rpc *rpc;
    struct nc_reply *reply;

    if (!PyArg_ParseTupleAndKeywords(args, keywords, "|ss:ncRPCGet", kwlist, &xml, &xpath)) {
        return NULL;
    }

    rpc = nc_rpc_get(xml ? xml : xpath, NC_WD_UNKNOWN, NC_PARAMTYPE_CONST);
    if (!rpc) {
        return NULL;
    }

    reply = rpc_send_recv(self->session, rpc);
    nc_rpc_free(rpc);
    if (!reply) {
        return NULL;
    }

    return process_reply_data(reply);
}

PyObject *
ncRPCGetConfig(ncSessionObject *self, PyObject *args, PyObject *keywords)
{
    const char *xml = NULL, *xpath = NULL;
    static char *kwlist[] = {"datastore", "subtree", "xpath", NULL};
    struct nc_rpc *rpc;
    struct nc_reply *reply;
    NC_DATASTORE datastore;

    if (!PyArg_ParseTupleAndKeywords(args, keywords, "i|ss:ncRPCGetConfig", kwlist, &datastore, &xml, &xpath)) {
        return NULL;
    }

    rpc = nc_rpc_getconfig(datastore, xml ? xml : xpath, NC_WD_UNKNOWN, NC_PARAMTYPE_CONST);
    if (!rpc) {
        return NULL;
    }

    reply = rpc_send_recv(self->session, rpc);
    nc_rpc_free(rpc);
    if (!reply) {
        return NULL;
    }

    return process_reply_data(reply);
}
