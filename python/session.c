/**
 * @file session.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief NETCONF session management in Python3 bindings for libnetconf2 (client-side)
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
#include <structmember.h>

/* standard headers */
#include <string.h>
#include <libyang/libyang.h>

#include "netconf.h"

typedef struct {
    PyObject_HEAD
    struct ly_ctx *ctx;
    struct nc_session *session;
} ncSessionObject;

char *
auth_password_clb(const char *UNUSED(username), const char *UNUSED(hostname), void *priv)
{
    /* password is provided as priv when setting up the callback */
    return strdup((char *)priv);
}
char *
auth_interactive_clb(const char *UNUSED(auth_name), const char *UNUSED(instruction), const char *UNUSED(prompt),
                     int UNUSED(echo), void *priv)
{
    /* password is provided as priv when setting up the callback */
    return strdup((char *)priv);
}

char *
auth_privkey_passphrase_clb(const char *privkey_path, void *priv)
{
    /* password is provided as priv when setting up the callback */
    return strdup((char *)priv);
}

static void
ncSessionFree(ncSessionObject *self)
{
    PyObject *err_type, *err_value, *err_traceback;

    /* save the current exception state */
    PyErr_Fetch(&err_type, &err_value, &err_traceback);

    nc_session_free(self->session, NULL);
    ly_ctx_destroy(self->ctx, NULL);

    /* restore the saved exception state */
    PyErr_Restore(err_type, err_value, err_traceback);

    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
ncSessionNew(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    ncSessionObject *self;

    self = (ncSessionObject *)type->tp_alloc(type, 0);
    if (self != NULL) {
        /* NULL initiation */
        self->session = NULL;

        /* prepare libyang context or use the one already present in the session */
        self->ctx = ly_ctx_new(SCHEMAS_DIR);
        if (!self->ctx) {
            Py_DECREF(self);
            return NULL;
        }
    }

    return (PyObject *)self;
}

static int
ncSessionInit(ncSessionObject *self, PyObject *args, PyObject *kwds)
{
    const char *host = NULL;
    PyObject *transport = NULL;
    unsigned short port = 0;
    struct nc_session *session;

    char *kwlist[] = {"host", "port", "transport", NULL};

    /* Get input parameters */
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|zHO", kwlist, &host, &port, &transport)) {
        return -1;
    }

    /* connect */
    if (transport && PyObject_TypeCheck(transport, &ncTLSType)) {
        session = nc_connect_tls(host, port, self->ctx);
    } else {
        if (transport) {
            /* set SSH parameters */
            if (((ncSSHObject*)transport)->username) {
                nc_client_ssh_set_username(PyUnicode_AsUTF8(((ncSSHObject*)transport)->username));
            }
            if (((ncSSHObject*)transport)->password) {
                nc_client_ssh_set_auth_password_clb(&auth_password_clb,
                                                    (void *)PyUnicode_AsUTF8(((ncSSHObject*)transport)->password));
                nc_client_ssh_set_auth_interactive_clb(&auth_interactive_clb,
                                                       (void *)PyUnicode_AsUTF8(((ncSSHObject*)transport)->password));
                nc_client_ssh_set_auth_privkey_passphrase_clb(&auth_privkey_passphrase_clb,
                                                              (void *)PyUnicode_AsUTF8(((ncSSHObject*)transport)->password));
            }
        }

        /* create connection */
        session = nc_connect_ssh(host, port, self->ctx);

        /* cleanup */
        if (transport) {
            if (((ncSSHObject*)transport)->username) {
                nc_client_ssh_set_username(NULL);
            }
            if (((ncSSHObject*)transport)->password) {
                nc_client_ssh_set_auth_password_clb(NULL, NULL);
                nc_client_ssh_set_auth_interactive_clb(NULL, NULL);
                nc_client_ssh_set_auth_privkey_passphrase_clb(NULL, NULL);
            }
        }
    }

    /* check the result */
    if (!session) {
        return -1;
    }

    /* replace the previous (if any) data in the session object */
    nc_session_free(self->session, NULL);
    self->session = session;

    return 0;
}

static PyObject *
ncSessionStr(ncSessionObject *self)
{
    return PyUnicode_FromFormat("NETCONF Session %u to %s:%u (%lu references)", nc_session_get_id(self->session),
                                nc_session_get_host(self->session), nc_session_get_port(self->session),
                                ((PyObject*)(self))->ob_refcnt);
}

/*
 * tp_methods callbacks held by ncSessionMethods[]
 */

/*
 * tp_getset callbacs held by ncSessionGetSetters[]
 */
#if 0
static PyObject *
ncSessionGetSTatus(ncSessionObject *self, void *closure)
{
    NC_STATUS s;

    s = nc_session_get_status(self->session);
    switch(s) {
    case NC_STATUS_ERR:
        /* exception */
        return NULL;
    }
    return PyUnicode_FromFormat("%u", nc_session_get_id(self->session));
}
#endif

static PyObject *
ncSessionGetId(ncSessionObject *self, void *closure)
{
    return PyUnicode_FromFormat("%u", nc_session_get_id(self->session));
}

static PyObject *
ncSessionGetHost(ncSessionObject *self, void *closure)
{
    return PyUnicode_FromString(nc_session_get_host(self->session));
}

static PyObject *
ncSessionGetPort(ncSessionObject *self, void *closure)
{
    return PyUnicode_FromFormat("%u", nc_session_get_port(self->session));
}

static PyObject *
ncSessionGetUser(ncSessionObject *self, void *closure)
{
    return PyUnicode_FromString(nc_session_get_username(self->session));
}

static PyObject *
ncSessionGetTransport(ncSessionObject *self, void *closure)
{
    NC_TRANSPORT_IMPL ti = nc_session_get_ti(self->session);
    switch (ti) {
    case NC_TI_LIBSSH:
        return PyUnicode_FromString("SSH");
    case NC_TI_OPENSSL:
        return PyUnicode_FromString("TLS");
    default:
        return PyUnicode_FromString("unknown");
    }
}

static PyObject *
ncSessionGetCapabilities(ncSessionObject *self, void *closure)
{
    PyObject *list;
    const char * const *cpblts;
    ssize_t pos;

    cpblts = nc_session_get_cpblts(self->session);
    if (cpblts == NULL) {
        return (NULL);
    }

    list = PyList_New(0);
    for(pos = 0; cpblts[pos]; ++pos) {
        PyList_Append(list, PyUnicode_FromString(cpblts[pos]));
    }

    return list;
}

static PyObject *
ncSessionGetVersion(ncSessionObject *self, void *closure)
{
    if (nc_session_get_version(self->session)) {
        return PyUnicode_FromString("1.1");
    } else {
        return PyUnicode_FromString("1.0");
    }
}

/*
 * Callback structures
 */

static PyGetSetDef ncSessionGetSetters[] = {
    {"id", (getter)ncSessionGetId, NULL, "NETCONF Session id.", NULL},
    {"host", (getter)ncSessionGetHost, NULL, "Host where the NETCONF Session is connected.", NULL},
    {"port", (getter)ncSessionGetPort, NULL, "Port number where the NETCONF Session is connected.", NULL},
    {"user", (getter)ncSessionGetUser, NULL, "Username of the user connected with the NETCONF Session.", NULL},
    {"transport", (getter)ncSessionGetTransport, NULL, "Transport protocol used for the NETCONF Session.", NULL},
    {"version", (getter)ncSessionGetVersion, NULL, "NETCONF Protocol version used for the NETCONF Session.", NULL},
    {"capabilities", (getter)ncSessionGetCapabilities, NULL, "Capabilities of the NETCONF Session.", NULL},
    {NULL} /* Sentinel */
};

static PyMemberDef ncSessionMembers[] = {
    {NULL} /* Sentinel */
};

static PyMethodDef ncSessionMethods[] = {
    {NULL}  /* Sentinel */
};

PyDoc_STRVAR(sessionDoc,
             "Create the NETCONF Session\n"
             "netconf2.Session([host, port, transport]) -> connect to the NETCONF server\n"
             "Arguments:\n"
             "\thost         - address of the server (default localhost)\n"
             "\tport         - port where to connect to (default 830)\n"
             "\ttransport    - NETCONF transport protocol (default SSH), supported SSH or TLS\n");

PyTypeObject ncSessionType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "netconf2.Session",        /* tp_name */
    sizeof(ncSessionObject),   /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)ncSessionFree, /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    (reprfunc)ncSessionStr,    /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    (reprfunc)ncSessionStr,    /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    sessionDoc,                /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    ncSessionMethods,          /* tp_methods */
    ncSessionMembers,          /* tp_members */
    ncSessionGetSetters,       /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)ncSessionInit,   /* tp_init */
    0,                         /* tp_alloc */
    ncSessionNew,              /* tp_new */
};

