/**
 * @file err.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief NETCONF reply errors
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
#include "messages_p.h"

static void
ncErrFree(ncErrObject *self)
{
    nc_client_err_clean(self->err, self->ctx);

    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
ncErrStr(ncErrObject *self)
{
    return PyUnicode_FromFormat("NETCONF error-reply: %s", self->err->message);
}

/*
 * tp_getset callbacs held by ncErrGetSetters[]
 */

static PyObject *
ncErrGetType(ncErrObject *self, void *closure)
{
    if (!self->err->type) {
        Py_RETURN_NONE;
    }
    return PyUnicode_FromString(self->err->type);
}

static PyObject *
ncErrGetTag(ncErrObject *self, void *closure)
{
    if (!self->err->tag) {
        Py_RETURN_NONE;
    }
    return PyUnicode_FromString(self->err->tag);
}

static PyObject *
ncErrGetMessage(ncErrObject *self, void *closure)
{
    if (!self->err->message) {
        Py_RETURN_NONE;
    }
    return PyUnicode_FromString(self->err->message);
}

/*
 * Callback structures
 */

static PyGetSetDef ncErrGetSetters[] = {
    {"type", (getter)ncErrGetType, NULL, "<error-type>", NULL},
    {"tag", (getter)ncErrGetTag, NULL, "<error-tag>", NULL},
    {"message", (getter)ncErrGetMessage, NULL, "<error-message>", NULL},
    {NULL} /* Sentinel */
};

PyDoc_STRVAR(ncErrDoc,
             "NETCONF Error Reply information.\n\n");

PyTypeObject ncErrType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "netconf2.Err",            /* tp_name */
    sizeof(ncErrObject),       /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)ncErrFree,     /* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    (reprfunc)ncErrStr,        /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    (reprfunc)ncErrStr,        /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,       /* tp_flags */
    ncErrDoc,                  /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    0,                         /* tp_methods */
    0,                         /* tp_members */
    ncErrGetSetters,           /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,                         /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};

