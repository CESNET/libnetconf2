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
#include <libssh/libssh.h>
#include <libyang/libyang.h>
#include <libyang/swigpyrun.h>

#include "../src/config.h"
#include "netconf.h"
#include "session.h"
#include "rpc.h"

extern PyObject *libnetconf2Error;

int
auth_hostkey_check_pyclb(const char *hostname, ssh_session session, void *priv)
{
    PyObject *arglist, *result;
    ncSSHObject *ssh = (ncSSHObject*)priv;
    int ret = EXIT_FAILURE, rc, state;
    unsigned char *hash_sha1 = NULL;
    char *hexa;
    const char *keytype = NULL;
    ssh_key srv_pubkey;
    size_t hlen;

    state = ssh_is_server_known(session);
    if (state == SSH_SERVER_KNOWN_OK) {
        /* known host */
        return EXIT_SUCCESS;
    } else if (!ssh->clb_hostcheck) {
        /* no callback, hostkey check failed */
        return EXIT_FAILURE;
    }

    /* use the callback set by Python application */
    rc = ssh_get_publickey(session, &srv_pubkey);
    if (rc < 0) {
        PyErr_SetString(PyExc_RuntimeError, "Unable to get server public key.");
        return -1;
    }

    keytype = ssh_key_type_to_char(ssh_key_type(srv_pubkey));
    rc = ssh_get_publickey_hash(srv_pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash_sha1, &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to calculate SHA1 hash of the server public key.");
        return -1;
    }

    hexa = ssh_get_hexa(hash_sha1, hlen);
    arglist = Py_BuildValue("(sissO)", hostname, state, keytype, hexa, ssh->clb_hostcheck_data ? ssh->clb_hostcheck_data : Py_None);
    if (!arglist) {
        PyErr_Print();
        ssh_string_free_char(hexa);
        ssh_clean_pubkey_hash(&hash_sha1);
        return -1;
    }
    result = PyObject_CallObject(ssh->clb_hostcheck, arglist);
    Py_DECREF(arglist);
    ssh_string_free_char(hexa);
    ssh_clean_pubkey_hash(&hash_sha1);

    if (result) {
        if (!PyBool_Check(result)) {
            PyErr_SetString(PyExc_TypeError, "Invalid hostkey check callback result.");
        } else if (result == Py_True) {
            ret = EXIT_SUCCESS;
        } else if (result != Py_False) {
            PyErr_SetString(PyExc_TypeError, "Invalid hostkey check callback result.");
        }
        Py_DECREF(result);
    }

    return ret;
}

char *
auth_password_clb(const char *UNUSED(username), const char *UNUSED(hostname), void *priv)
{
    /* password is provided as priv when setting up the callback */
    return strdup((char *)priv);
}

char *
auth_password_pyclb(const char *username, const char *hostname, void *priv)
{
    PyObject *arglist, *result;
    ncSSHObject *ssh = (ncSSHObject*)priv;
    char *password = NULL;

    arglist = Py_BuildValue("(ssO)", username, hostname, ssh->clb_password_data ? ssh->clb_password_data : Py_None);
    if (!arglist) {
        PyErr_Print();
        return NULL;
    }
    result = PyObject_CallObject(ssh->clb_password, arglist);
    Py_DECREF(arglist);

    if (result) {
        if (!PyUnicode_Check(result)) {
            PyErr_SetString(PyExc_TypeError, "Invalid password authentication callback result.");
        } else {
            password = strdup(PyUnicode_AsUTF8(result));
            Py_DECREF(result);
        }
    }

    return password;
}

char *
auth_interactive_clb(const char *UNUSED(auth_name), const char *UNUSED(instruction), const char *UNUSED(prompt),
                     int UNUSED(echo), void *priv)
{
    /* password is provided as priv when setting up the callback */
    return strdup((char *)priv);
}

char *
auth_interactive_pyclb(const char *auth_name, const char *instruction, const char *prompt, int UNUSED(echo), void *priv)
{
    PyObject *arglist, *result;
    ncSSHObject *ssh = (ncSSHObject*)priv;
    char *password = NULL;

    arglist = Py_BuildValue("(sssO)", auth_name, instruction, prompt, ssh->clb_password_data ? ssh->clb_password_data : Py_None);
    if (!arglist) {
        PyErr_Print();
        return NULL;
    }
    result = PyObject_CallObject(ssh->clb_interactive, arglist);
    Py_DECREF(arglist);

    if (result) {
        if (!PyUnicode_Check(result)) {
            PyErr_SetString(PyExc_TypeError, "Invalid password authentication callback result.");
        } else {
            password = strdup(PyUnicode_AsUTF8(result));
            Py_DECREF(result);
        }
    }

    return password;
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

    (*self->ctx_counter)--;
    if (!(*self->ctx_counter)) {
        ly_ctx_destroy(self->ctx, NULL);
        free(self->ctx_counter);
    }

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
        self->ctx = NULL;
        self->ctx_counter = calloc(1, sizeof *self->ctx_counter);
    }

    return (PyObject *)self;
}

static int
ncSessionInit(ncSessionObject *self, PyObject *args, PyObject *kwds)
{
    const char *host = NULL;
    PyObject *transport = NULL;
    unsigned short port = 0;
    struct nc_session *session = NULL;

    char *kwlist[] = {"host", "port", "transport", NULL};

    /* Get input parameters */
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|zHO", kwlist, &host, &port, &transport)) {
        return -1;
    }

    /* connect */
#ifdef NC_ENABLED_TLS
    if (transport && PyObject_TypeCheck(transport, &ncTLSType)) {
        session = nc_connect_tls(host, port, NULL);
    } else {
#else /* !NC_ENABLED_TLS */
    {
#endif
#ifdef NC_ENABLED_SSH
        if (transport) {
            /* set SSH parameters */
            if (((ncSSHObject*)transport)->username) {
                nc_client_ssh_set_username(PyUnicode_AsUTF8(((ncSSHObject*)transport)->username));
            }

            nc_client_ssh_set_auth_hostkey_check_clb(&auth_hostkey_check_pyclb, (void *)transport);

            if (((ncSSHObject*)transport)->password) {
                nc_client_ssh_set_auth_password_clb(&auth_password_clb,
                                                    (void *)PyUnicode_AsUTF8(((ncSSHObject*)transport)->password));
                nc_client_ssh_set_auth_interactive_clb(&auth_interactive_clb,
                                                       (void *)PyUnicode_AsUTF8(((ncSSHObject*)transport)->password));
                nc_client_ssh_set_auth_privkey_passphrase_clb(&auth_privkey_passphrase_clb,
                                                              (void *)PyUnicode_AsUTF8(((ncSSHObject*)transport)->password));
            } else {
                if (((ncSSHObject *)transport)->clb_password) {
                    nc_client_ssh_set_auth_password_clb(&auth_password_pyclb, (void *)transport);
                }
                if (((ncSSHObject *)transport)->clb_interactive) {
                    nc_client_ssh_set_auth_interactive_clb(&auth_interactive_pyclb, (void *)transport);
                }
            }
        }

        /* create connection */
        session = nc_connect_ssh(host, port, NULL);
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
#endif /* NC_ENABLED_SSH */
    }

    /* check the result */
    if (!session) {
        return -1;
    }

    if (PyErr_Occurred()) {
        PyErr_PrintEx(0);
    }

    /* get the internally created context for this session */
    self->ctx = nc_session_get_ctx(session);

    /* replace the previous (if any) data in the session object */
    nc_session_free(self->session, NULL);
    self->session = session;

    return 0;
}

#ifdef NC_ENABLED_SSH

static PyObject *
newChannel(PyObject *self)
{
    ncSessionObject *new;

    if (nc_session_get_ti(((ncSessionObject *)self)->session) != NC_TI_LIBSSH) {
        PyErr_SetString(PyExc_TypeError, "The session must be on SSH.");
        return NULL;
    }

    new = (ncSessionObject *)self->ob_type->tp_alloc(self->ob_type, 0);
    if (!new) {
        return NULL;
    }

    new->ctx = ((ncSessionObject *)self)->ctx;
    new->session = nc_connect_ssh_channel(((ncSessionObject *)self)->session, new->ctx);
    if (!new->session) {
        Py_DECREF(new);
        return NULL;
    }

    new->ctx_counter = ((ncSessionObject *)self)->ctx_counter;
    (*new->ctx_counter)++;
    return (PyObject*)new;
}

#endif /* NC_ENABLED_SSH */

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
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
        return PyUnicode_FromString("SSH");
#endif /* NC_ENABLED_SSH */
#ifdef NC_ENABLEd_TLS
    case NC_TI_OPENSSL:
        return PyUnicode_FromString("TLS");
#endif /* NC_ENABLED_TLS */
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

static PyObject *
ncSessionGetContext(ncSessionObject *self, void *closure)
{
    PyObject *context, *result, *module;


    /* process the received data */
    context = SWIG_NewPointerObj(self->ctx, SWIG_Python_TypeQuery("ly_ctx*"), 0);
    if (!context) {
        PyErr_SetString(libnetconf2Error, "Building Python object from context structure failed.");
        goto error;
    }

    module = PyImport_ImportModule("yang");
    if (module == NULL) {
        PyErr_SetString(libnetconf2Error, "Could not import libyang python module");
        goto error;
    }

    result = PyObject_CallMethod(module, "create_new_Context", "(O)", context, NULL);
    Py_DECREF(module);
    Py_DECREF(context);
    if (!result) {
        PyErr_SetString(libnetconf2Error, "Could not create Context object.");
        goto error;
    }

    return result;

error:
    Py_XDECREF(context);
    return NULL;
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
    {"context", (getter)ncSessionGetContext, NULL, "libyang context of the NETCONF Session.", NULL},
    {NULL} /* Sentinel */
};

static PyMemberDef ncSessionMembers[] = {
    {NULL} /* Sentinel */
};

static PyMethodDef ncSessionMethods[] = {
#ifdef NC_ENABLED_SSH
    {"newChannel", (PyCFunction)newChannel, METH_NOARGS,
     "newChannel()\n--\n\n"
     "Create another NETCONF session on existing SSH session using separated SSH channel\n\n"
     ":returns: New netconf2.Session instance.\n"},
#endif /* NC_ENABLED_SSH */
    /* RPCs */
    {"rpcGet", (PyCFunction)ncRPCGet, METH_VARARGS | METH_KEYWORDS,
     "Send NETCONF <get> operation on the Session.\n\n"
     "ncRPCGet(subtree=None, xpath=None)\n"
     ":returns: Reply from the server.\n"},
    {"rpcGetConfig", (PyCFunction)ncRPCGetConfig, METH_VARARGS | METH_KEYWORDS,
     "Send NETCONF <get-config> operation on the Session.\n\n"
     "ncRPCGetConfig(datastore, subtree=None, xpath=None)\n"
     ":returns: Reply from the server.\n"},
    {"rpcEditConfig", (PyCFunction)ncRPCEditConfig, METH_VARARGS | METH_KEYWORDS,
     "Send NETCONF <edit-config> operation on the Session.\n\n"
     "ncRPCEditConfig(datastore, data, defop=None, testopt=None, erropt=None)\n"
     ":returns: None\n"},
    {NULL}  /* Sentinel */
};

PyDoc_STRVAR(sessionDoc,
             "The NETCONF Session object.\n\n"
             "Arguments: (host='localhost', port=830, transport=None)\n");

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

