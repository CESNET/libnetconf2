/**
 * @file tls.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief TLS parameters management
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "netconf.h"

static void
ncTLSFree(ncTLSObject *self)
{
    Py_XDECREF(self->cert_file);
    Py_XDECREF(self->key_file);
    Py_XDECREF(self->ca_file);
    Py_XDECREF(self->ca_dir);
    Py_XDECREF(self->crl_file);
    Py_XDECREF(self->crl_dir);

    Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
ncTLSInit(ncTLSObject *self, PyObject *args, PyObject *kwds)
{
    char *kwlist[] = {"cert_file", "key_file", "ca_file", "ca_dir", "crl_file", "crl_dir", NULL};

    /* Get input parameters */
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "UU|UUUU", kwlist,
                                     &self->cert_file, &self->key_file,
                                     &self->ca_file, &self->ca_dir,
                                     &self->crl_file, &self->crl_dir)) {
        return -1;
    }

    return 0;
}

static PyObject *
ncTLSStr(ncTLSObject *self)
{
    return PyUnicode_FromFormat("TLS Settings with certificate \"%U\" and the key \"%U\".",
                                self->cert_file, self->key_file);
}

/*
 * tp_getset callbacs held by ncTLSGetSetters[]
 */
static int
ncTLSSetCert(ncTLSObject *self, PyObject *value, void *closure)
{
    char *path;
    struct stat st;

    if (!value) {
        PyErr_SetString(PyExc_TypeError, "Client certificate path cannot be unset.");
        return -1;
    } else if (!PyUnicode_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "The certificate path value must be a string.");
        return -1;
    }

    path = PyUnicode_AsUTF8(value);
    if (!path) {
        return -1;
    }

    if (stat(path, &st)) {
        PyErr_SetFromErrno(PyExc_SystemError);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        PyErr_SetString(PyExc_FileNotFoundError, "Certificate file cannot be used.");
        return -1;
    }

    Py_XDECREF(self->cert_file);
    Py_INCREF(value);
    self->cert_file = value;

    return 0;
}

static PyObject *
ncTLSGetCert(ncTLSObject *self, void *closure)
{
    Py_XINCREF(self->cert_file);
    return self->cert_file;
}

static int
ncTLSSetKey(ncTLSObject *self, PyObject *value, void *closure)
{
    char *path;
    struct stat st;

    if (!value) {
        PyErr_SetString(PyExc_TypeError, "Client certificate key path cannot be unset.");
        return -1;
    } else if (!PyUnicode_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "The certificate key path value must be a string.");
        return -1;
    }

    path = PyUnicode_AsUTF8(value);
    if (!path) {
        return -1;
    }

    if (stat(path, &st)) {
        PyErr_SetFromErrno(PyExc_SystemError);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        PyErr_SetString(PyExc_FileNotFoundError, "Certificate key file cannot be used.");
        return -1;
    }

    Py_XDECREF(self->key_file);
    Py_INCREF(value);
    self->key_file = value;

    return 0;
}

static PyObject *
ncTLSGetKey(ncTLSObject *self, void *closure)
{
    Py_XINCREF(self->key_file);
    return self->key_file;
}

/*
 * Callback structures
 */

static PyGetSetDef ncTLSGetSetters[] = {
    {"cert", (getter)ncTLSGetCert, (setter)ncTLSSetCert, "Client certificate filepath.", NULL},
    {"key", (getter)ncTLSGetKey, (setter)ncTLSSetKey, "Client certificate private key filepath.", NULL},
    {NULL} /* Sentinel */
};

PyDoc_STRVAR(ncTLSDoc,
             "Settings for TLS authentication\n\n"
             "Arguments: (cert=None, key=None, ca_file=None, ca_dir=None, crl_file=None, crl_dir=None)\n");

PyTypeObject ncTLSType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "netconf2.TLS",            /* tp_name */
    sizeof(ncTLSObject),       /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)ncTLSFree,     /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    (reprfunc)ncTLSStr,        /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    (reprfunc)ncTLSStr,        /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,   /* tp_flags */
    ncTLSDoc,                  /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    0,                         /* tp_methods */
    0,                         /* tp_members */
    ncTLSGetSetters,           /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)ncTLSInit,       /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

