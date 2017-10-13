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

#include "netconf.h"
#include "session.h"
#include "messages_p.h"

#define TIMEOUT_SEND 1000  /* 1 second */
#define TIMEOUT_RECV 10000 /* 10 second */

extern PyObject *libnetconf2Error;
extern PyObject *libnetconf2ReplyError;

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
err_reply_converter(struct nc_client_reply_error *reply)
{
    ncErrObject *result;

    result = PyObject_New(ncErrObject, &ncErrType);
    result->ctx = reply->ctx;
    result->err = reply->err;
    reply->err = NULL;

    return (PyObject*)result;
}

#define RAISE_REPLY_ERROR(reply) PyErr_SetObject(libnetconf2ReplyError,err_reply_converter((struct nc_client_reply_error *)reply))

static PyObject *
process_reply_data(struct nc_reply *reply)
{
    struct lyd_node *data;
    //PyObject *result;

    /* check the type of the received reply message */
    if (reply->type != NC_RPL_DATA) {
        if (reply->type == NC_RPL_ERROR) {
            RAISE_REPLY_ERROR(reply);
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

    Py_RETURN_NONE;
    //return result;
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
