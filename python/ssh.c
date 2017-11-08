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
#include <structmember.h>

/* standard headers */
#include <string.h>

#include "netconf.h"

static void
ncSSHFree(ncSSHObject *self)
{
    Py_XDECREF(self->username); /* PyUnicode */
    Py_XDECREF(self->password); /* PyUnicode */
    Py_XDECREF(self->pubkeys);  /* PyList */
    Py_XDECREF(self->privkeys); /* PyList */

    Py_XDECREF(self->clb_hostcheck);
    Py_XDECREF(self->clb_hostcheck_data);
    Py_XDECREF(self->clb_password);
    Py_XDECREF(self->clb_password_data);
    Py_XDECREF(self->clb_interactive);
    Py_XDECREF(self->clb_interactive_data);

    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
ncSSHInit(ncSSHObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *user = NULL, *password = NULL;
    PyObject *pubkey_path = NULL, *pubkey = NULL;
    PyObject *privkey_path = NULL, *privkey = NULL;

    char *kwlist[] = {"username", "password", "pubkey", "pubkey_file", "privkey", "privkey_file", NULL};

    /* Get input parameters */
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|UUUUUU", kwlist,
                                     &user, &password,
                                     &pubkey, &pubkey_path,
                                     &privkey, &privkey_path)) {
        return -1;
    }

    if ((pubkey || pubkey_path) != (privkey || privkey_path)) {
        PyErr_SetString(PyExc_TypeError, "Both public and private keys must be set.");
        goto error;
    }

    /* username and password */
    Py_XDECREF(self->username);
    Py_XDECREF(self->password);

    if (user) {
        Py_XDECREF(self->username);
        Py_INCREF(user);
        self->username = user;
    } else {
        self->username = NULL;
    }
    if (password) {
        Py_XDECREF(self->password);
        Py_INCREF(password);
        self->password = password;
    } else {
        self->password = NULL;
    }

    /* keys */
    Py_XDECREF(self->pubkeys);
    Py_XDECREF(self->privkeys);

    if (pubkey || pubkey_path) {
        self->pubkeys = PyList_New(0);
        self->privkeys = PyList_New(0);

        if (!self->pubkeys || self->privkeys) {
            PyErr_SetString(PyExc_MemoryError, "Unable to allocate memory for keys list.");
            goto error;
        }
    } else {
        self->pubkeys = NULL;
        self->privkeys = NULL;
    }

    if (pubkey) {
        PyList_Append(self->pubkeys, pubkey);
    }
    if (pubkey_path) {
        /* process keys in the file */
    }

    if (privkey) {
        PyList_Append(self->privkeys, privkey);
    }
    if (privkey_path) {
        /* process keys in the file */
    }

    /* check that the keys pairs together */

    /* forget callbacks */
    Py_CLEAR(self->clb_hostcheck);
    Py_CLEAR(self->clb_hostcheck_data);
    Py_CLEAR(self->clb_password);
    Py_CLEAR(self->clb_password_data);
    Py_CLEAR(self->clb_interactive);
    Py_CLEAR(self->clb_interactive_data);

    return 0;

error:

    Py_CLEAR(self->username);
    Py_CLEAR(self->password);
    Py_CLEAR(self->pubkeys);
    Py_CLEAR(self->privkeys);
    Py_CLEAR(self->clb_hostcheck);
    Py_CLEAR(self->clb_hostcheck_data);
    Py_CLEAR(self->clb_password);
    Py_CLEAR(self->clb_password_data);
    Py_CLEAR(self->clb_interactive);
    Py_CLEAR(self->clb_interactive_data);

    return -1;
}

static PyObject *
ncSSHStr(ncSSHObject *self)
{
    if (self->privkeys) {
        if (self->username && self->password) {
            return PyUnicode_FromFormat("SSH Settings with %d keys and password for user %U",
                                        PyList_Size(self->privkeys), self->username);
        } else if (self->password) {
            return PyUnicode_FromFormat("SSH Settings with %d keys and password for default user.",
                                        PyList_Size(self->privkeys));
        } else {
            return PyUnicode_FromFormat("SSH Settings with %d keys", PyList_Size(self->privkeys));
        }
    } else if (self->password) {
        if (self->username) {
            return PyUnicode_FromFormat("SSH Settings with password authentication for user %U.", self->username);
        } else {
            return PyUnicode_FromString("SSH Settings with password authentication for default user.");
        }
    } else if (self->username) {
        return PyUnicode_FromFormat("SSH Settings for user %U.", self->username);
    } else {
        return PyUnicode_FromString("Default SSH Settings.");
    }
}

/*
 * tp_methods callbacks held by ncSessionMethods[]
 */

/*
 * tp_getset callbacs held by ncSessionGetSetters[]
 */
static int
ncSSHSetUser(ncSSHObject *self, PyObject *value, void *closure)
{
    if (!value) {
        Py_XDECREF(self->username);
    } else if (!PyUnicode_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "The attribute value must be a string.");
        return -1;
    } else {
        Py_XDECREF(self->username);
        Py_INCREF(value);
    }
    self->username = value;

    return 0;
}

static PyObject *
ncSSHGetUser(ncSSHObject *self, void *closure)
{
    Py_XINCREF(self->username);
    return self->username;
}

static int
ncSSHSetPassword(ncSSHObject *self, PyObject *value, void *closure)
{
    if (!value) {
        Py_XDECREF(self->password);
    } else if (!PyUnicode_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "The value must be a string.");
        return -1;
    } else {
        Py_XDECREF(self->password);
        Py_INCREF(value);
    }
    self->password = value;

    return 0;
}

static PyObject *
ncSSHSetAuthHostkeyCheckClb(ncSSHObject *self, PyObject *args, PyObject *keywords)
{
    PyObject *clb, *data = NULL;
    static char *kwlist[] = {"func", "priv", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywords, "O|O:ncSSHSetAuthHostkeyCheckClb", kwlist, &clb, &data)) {
        return NULL;
    }

    if (!clb) {
        Py_XDECREF(self->clb_hostcheck);
        Py_XDECREF(self->clb_hostcheck_data);
        data = NULL;
    } else if (!PyCallable_Check(clb)) {
        PyErr_SetString(PyExc_TypeError, "The callback must be a function.");
        return NULL;
    } else {
        Py_XDECREF(self->clb_hostcheck);
        Py_XDECREF(self->clb_hostcheck_data);

        Py_INCREF(clb);
        if (data) {
            Py_INCREF(data);
        }
    }
    self->clb_hostcheck = clb;
    self->clb_hostcheck_data = data;

    Py_RETURN_NONE;
}


static PyObject *
ncSSHSetAuthPasswordClb(ncSSHObject *self, PyObject *args, PyObject *keywords)
{
    PyObject *clb, *data = NULL;
    static char *kwlist[] = {"func", "priv", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywords, "O|O:ncSSHSetAuthPasswordClb", kwlist, &clb, &data)) {
        return NULL;
    }

    if (!clb) {
        Py_XDECREF(self->clb_password);
        Py_XDECREF(self->clb_password_data);
        data = NULL;
    } else if (!PyCallable_Check(clb)) {
        PyErr_SetString(PyExc_TypeError, "The callback must be a function.");
        return NULL;
    } else {
        Py_XDECREF(self->clb_password);
        Py_XDECREF(self->clb_password_data);

        Py_INCREF(clb);
        if (data) {
            Py_INCREF(data);
        }
    }
    self->clb_password = clb;
    self->clb_password_data = data;

    Py_RETURN_NONE;
}

static PyObject *
ncSSHSetAuthInteractiveClb(ncSSHObject *self, PyObject *args, PyObject *keywords)
{
    PyObject *clb, *data = NULL;
    static char *kwlist[] = {"func", "priv", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywords, "O|O:ncSSHSetAuthInteractiveClb", kwlist, &clb, &data)) {
        return NULL;
    }

    if (!clb) {
        Py_XDECREF(self->clb_interactive);
        Py_XDECREF(self->clb_interactive_data);
        data = NULL;
    } else if (!PyCallable_Check(clb)) {
        PyErr_SetString(PyExc_TypeError, "The callback must be a function.");
        return NULL;
    } else {
        Py_XDECREF(self->clb_interactive);
        Py_XDECREF(self->clb_interactive_data);

        Py_INCREF(clb);
        if (data) {
            Py_INCREF(data);
        }
    }
    self->clb_interactive = clb;
    self->clb_interactive_data = data;

    Py_RETURN_NONE;
}

/*
 * Callback structures
 */

static PyGetSetDef ncSSHGetSetters[] = {
    {"username", (getter)ncSSHGetUser, (setter)ncSSHSetUser, "SSH username.", NULL},
    {"password", NULL, (setter)ncSSHSetPassword, "SSH password (or key passphrase).", NULL},
    {NULL} /* Sentinel */
};

static PyMethodDef ncSSHMethods[] = {
    {"setAuthHostkeyCheckClb", (PyCFunction)ncSSHSetAuthHostkeyCheckClb, METH_VARARGS | METH_KEYWORDS,
     "SSH Hostkey (fingerprint) check callback.\n\n"
     "setAuthHostkeyCheckClb(func, priv=None)\n"
     "with func(str hostname, int state, str keytype, str hexa, priv)\n"
     "state is SERVER_ERROR (-1), SERVER_NOT_KNOWN (0), SERVER_CHANGED (2), SERVER_FOUND_OTHER (3), SERVER_FILE_NOT_FOUND (4)\n"
     "callback returns True in case of valid hostkey.\n"},
    {"setAuthPasswordClb", (PyCFunction)ncSSHSetAuthPasswordClb, METH_VARARGS | METH_KEYWORDS,
     "SSH password authentication callback.\n\n"
     "setAuthPasswordClb(func, priv=None)\n"},
    {"setAuthInteractiveClb", (PyCFunction)ncSSHSetAuthInteractiveClb, METH_VARARGS | METH_KEYWORDS,
     "setAuthInteractiveClb(func, priv=None)\n--\n\n"
     "SSH keyboard-interactive authentication callback.\n\n"},
    {NULL, NULL, 0, NULL}
};

PyDoc_STRVAR(ncSSHDoc,
             "Settings for SSH authentication.\n\n"
             "Arguments: (user=None, password=None)\n");

PyTypeObject ncSSHType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "netconf2.SSH",            /* tp_name */
    sizeof(ncSSHObject),       /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)ncSSHFree,     /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    (reprfunc)ncSSHStr,        /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    (reprfunc)ncSSHStr,        /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    ncSSHDoc,                  /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    ncSSHMethods,              /* tp_methods */
    0,                         /* tp_members */
    ncSSHGetSetters,           /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)ncSSHInit,       /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

