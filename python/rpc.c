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

#include "../src/messages_p.h"
#include "netconf.h"
#include "session.h"

#define TIMEOUT_SEND 1000  /* 1 second */
#define TIMEOUT_RECV 10000 /* 10 second */

extern PyObject *libnetconf2Error;
extern PyObject *libnetconf2ReplyError;

static const char *ncds2str[] = {NULL, "config", "url", "running", "startup", "candidate"};
const char *rpcedit_dfltop2str[] = {NULL, "merge", "replace", "none"};
const char *rpcedit_testopt2str[] = {NULL, "test-then-set", "set", "test-only"};
const char *rpcedit_erropt2str[] = {NULL, "stop-on-error", "continue-on-error", "rollback-on-error"};

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
    uint32_t i = 0;
    ncErrObject *e;
    PyObject *result;

    result = PyList_New(reply->count);
    for (i = 0; i < reply->count; i++) {
        e = PyObject_New(ncErrObject, &ncErrType);
        e->ctx = reply->ctx;
        e->err = malloc(sizeof *e->err);
        memcpy(e->err, &reply->err[i], sizeof *e->err);
        PyList_SET_ITEM(result, i, (PyObject*)e);
    }
    free(reply->err); /* pointers to the data were moved, so we are freeing just a container for the data */
    reply->err = NULL;

    return (PyObject*)result;
}

#define RAISE_REPLY_ERROR(reply) PyErr_SetObject(libnetconf2ReplyError,err_reply_converter((struct nc_client_reply_error *)reply))

static PyObject *
process_reply_data(struct nc_reply *reply)
{
    PyObject *result, *data = NULL, *module;

    /* check the type of the received reply message */
    if (reply->type != NC_RPL_DATA) {
        if (reply->type == NC_RPL_ERROR) {
            RAISE_REPLY_ERROR(reply);
        } else {
            PyErr_SetString(libnetconf2Error, "Unexpected reply received.");
        }
        goto error;
    }

    //lyd_print_file(stdout, ((struct nc_reply_data*)reply)->data, LYD_XML, LYP_FORMAT);

    /* process the received data */
    data = SWIG_NewPointerObj(((struct nc_reply_data*)reply)->data, SWIG_Python_TypeQuery("lyd_node*"), 0);
    if (!data) {
        PyErr_SetString(libnetconf2Error, "Building Python object from data reply failed.");
        goto error;
    }
    ((struct nc_reply_data*)reply)->data = NULL;

    module = PyImport_ImportModule("yang");
    if (module == NULL) {
        PyErr_SetString(libnetconf2Error, "Could not import libyang python module");
        goto error;
    }

    result = PyObject_CallMethod(module, "create_new_Data_Node", "(O)", data);
    Py_DECREF(module);
    Py_DECREF(data);
    if (result == NULL) {
        PyErr_SetString(libnetconf2Error, "Could not create Data_Node object.");
        goto error;
    }

    nc_reply_free(reply);
    return result;

error:
    Py_XDECREF(data);
    nc_reply_free(reply);
    return NULL;
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

PyObject *
ncRPCEditConfig(ncSessionObject *self, PyObject *args, PyObject *keywords)
{
    static char *kwlist[] = {"datastore", "data", "defop", "testopt", "erropt", NULL};
    struct lyd_node *data = NULL, *node, *content_tree = NULL;
    char *content_str = NULL;
    const struct lys_module *ietfnc;
    NC_DATASTORE datastore;
    NC_RPC_EDIT_DFLTOP defop = 0;
    NC_RPC_EDIT_TESTOPT testopt = 0;
    NC_RPC_EDIT_ERROPT erropt = 0;
    PyObject *content_o = NULL, *py_lyd_node;
    struct nc_rpc *rpc;
    struct nc_reply *reply;

    ietfnc = ly_ctx_get_module(self->ctx, "ietf-netconf", NULL, 1);
    if (!ietfnc) {
        PyErr_SetString(libnetconf2Error, "Missing \"ietf-netconf\" schema in the context.");
        return NULL;
    }

    if (!PyArg_ParseTupleAndKeywords(args, keywords, "iO|iii:ncRPCEditConfig", kwlist, &datastore, &content_o, &defop, &testopt, &erropt)) {
        return NULL;
    }

    if (PyUnicode_Check(content_o)) {
            content_str = PyUnicode_AsUTF8(content_o);
    } else if (SWIG_Python_GetSwigThis(content_o)) {
        py_lyd_node = PyObject_CallMethod(content_o, "C_lyd_node", NULL);
        if (!SWIG_IsOK(SWIG_Python_ConvertPtr(py_lyd_node, (void**)&content_tree, SWIG_Python_TypeQuery("lyd_node *"), SWIG_POINTER_DISOWN))) {
            PyErr_SetString(PyExc_TypeError, "Invalid object representing <edit-config> content. Data_Node is accepted.");
            goto error;
        }
    } else if (content_o != Py_None) {
        PyErr_SetString(PyExc_TypeError, "Invalid object representing <edit-config> content. String or Data_Node is accepted.");
        goto error;
    }

    data = lyd_new(NULL, ietfnc, "edit-config");
    node = lyd_new(data, ietfnc, "target");
    node = lyd_new_leaf(node, ietfnc, ncds2str[datastore], NULL);
    if (!node) {
        goto error;
    }

    if (defop) {
        node = lyd_new_leaf(data, ietfnc, "default-operation", rpcedit_dfltop2str[defop]);
        if (!node) {
            goto error;
        }
    }

    if (testopt) {
        node = lyd_new_leaf(data, ietfnc, "test-option", rpcedit_testopt2str[testopt]);
        if (!node) {
            goto error;
        }
    }

    if (erropt) {
        node = lyd_new_leaf(data, ietfnc, "error-option", rpcedit_erropt2str[erropt]);
        if (!node) {
            goto error;
        }
    }

    if (content_str) {
        if (!content_str[0] || (content_str[0] == '<')) {
            node = lyd_new_anydata(data, ietfnc, "config", content_str, LYD_ANYDATA_SXML);
        } else {
            node = lyd_new_leaf(data, ietfnc, "url", content_str);
        }
    } else if (content_tree) {
        node = lyd_new_anydata(data, ietfnc, "config", content_tree, LYD_ANYDATA_DATATREE);
    }
    if (!node) {
        goto error;
    }

    rpc = nc_rpc_act_generic(data, NC_PARAMTYPE_FREE);
    data = NULL;
    if (!rpc) {
        goto error;
    }

    reply = rpc_send_recv(self->session, rpc);
    nc_rpc_free(rpc);
    if (!reply) {
        goto error;
    }
    if (reply->type != NC_RPL_OK) {
        if (reply->type == NC_RPL_ERROR) {
            RAISE_REPLY_ERROR(reply);
        } else {
            PyErr_SetString(libnetconf2Error, "Unexpected reply received.");
        }
        goto error;
    }

    Py_RETURN_NONE;

error:
    lyd_free(data);
    return NULL;
}
