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
#include "../src/messages_p.h"

static void
ncErrFree(ncErrObject *self)
{
    nc_client_err_clean(self->err, self->ctx);

    Py_TYPE(self)->tp_free((PyObject*)self);
}

static char *
escape_quotes(char *strbuf, size_t strbuf_size, const char *text)
{
    size_t i, o;
    for (i = o = 0; i < strbuf_size; i++) {
        if (text[i] == '"') {
            strbuf[o++] = '\\';
        }
        strbuf[o++] = text[i];
        if (!text[i]) {
            /* end of the text */
            break;
        }
    }
    return strbuf;
}

static PyObject *
ncErrStr(ncErrObject *self)
{
    uint16_t u, f = 0;
    char *str = NULL;
#define BUFSIZE 4096
    char buf[BUFSIZE];

    if (self->err->type) {
        asprintf(&str, "\"type\":\"%s\"", self->err->type);
    }
    if (self->err->tag) {
        asprintf(&str, "%s%s\"tag\":\"%s\"", str ? str : "", str ? "," : "", self->err->tag);
    }
    if (self->err->severity) {
        asprintf(&str, "%s%s\"severity\":\"%s\"", str ? str : "", str ? "," : "", self->err->severity);
    }
    if (self->err->apptag) {
        asprintf(&str, "%s%s\"app-tag\":\"%s\"", str ? str : "", str ? "," : "", escape_quotes(buf, BUFSIZE, self->err->apptag));
    }
    if (self->err->path) {
        asprintf(&str, "%s%s\"path\":\"%s\"", str ? str : "", str ? "," : "", escape_quotes(buf, BUFSIZE, self->err->path));
    }
    if (self->err->message) {
        asprintf(&str, "%s%s\"message\":\"%s", str ? str : "", str ? "," : "", escape_quotes(buf, BUFSIZE, self->err->message));
        if (self->err->message_lang) {
            asprintf(&str, "%s (%s)\"", str, self->err->message_lang);
        } else {
            asprintf(&str, "%s\"", str);
        }
    }
    if (self->err->sid || self->err->attr || self->err->elem || self->err->ns || self->err->other) {
        asprintf(&str, "%s%s\"info\":{", str ? str : "", str ? "," : "");

        if (self->err->sid) {
            asprintf(&str, "%s%s\"session-id\":\"%s\"", str, f ? "," : "", self->err->sid);
            f = 1;
        }
        if (self->err->attr_count) {
            asprintf(&str, "%s%s\"bad-attr\":[", str, f ? "," : "");
            for (u = 0; u < self->err->attr_count; u++) {
                asprintf(&str, "%s%s\"%s\"", str, u ? "," : "", self->err->attr[u]);
            }
            asprintf(&str, "%s]", str);
            f = 1;
        }
        if (self->err->elem_count) {
            asprintf(&str, "%s%s\"bad-element\":[", str, f ? "," : "");
            for (u = 0; u < self->err->elem_count; u++) {
                asprintf(&str, "%s%s\"%s\"", str, u ? "," : "", self->err->elem[u]);
            }
            asprintf(&str, "%s]", str);
            f = 1;
        }
        if (self->err->ns_count) {
            asprintf(&str, "%s%s\"bad-namespace\":[", str, f ? "," : "");
            for (u = 0; u < self->err->ns_count; u++) {
                asprintf(&str, "%s%s\"%s\"", str, u ? "," : "", self->err->ns[u]);
            }
            asprintf(&str, "%s]", str);
            f = 1;
        }
        if (self->err->other_count) {
            for (u = 0; u < self->err->other_count; u++) {
                asprintf(&str, "%s%s\"%s\":\"%s\"", str, f ? "," : "", self->err->other[u]->name,
                         escape_quotes(buf, BUFSIZE, self->err->other[u]->content));
            }
            f = 1;
        }

        asprintf(&str, "%s}", str);
    }
    return PyUnicode_FromFormat("{%s}", str);
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
ncErrGetSeverity(ncErrObject *self, void *closure)
{
    if (!self->err->severity) {
        Py_RETURN_NONE;
    }
    return PyUnicode_FromString(self->err->severity);
}

static PyObject *
ncErrGetAppTag(ncErrObject *self, void *closure)
{
    if (!self->err->apptag) {
        Py_RETURN_NONE;
    }
    return PyUnicode_FromString(self->err->apptag);
}

static PyObject *
ncErrGetPath(ncErrObject *self, void *closure)
{
    if (!self->err->path) {
        Py_RETURN_NONE;
    }
    return PyUnicode_FromString(self->err->path);
}

static PyObject *
ncErrGetMessage(ncErrObject *self, void *closure)
{
    if (!self->err->message) {
        Py_RETURN_NONE;
    }
    return PyUnicode_FromString(self->err->message);
}

static PyObject *
ncErrGetMessageLang(ncErrObject *self, void *closure)
{
    if (!self->err->message_lang) {
        Py_RETURN_NONE;
    }
    return PyUnicode_FromString(self->err->message_lang);
}

static PyObject *
ncErrGetSID(ncErrObject *self, void *closure)
{
    if (!self->err->sid) {
        Py_RETURN_NONE;
    }
    return PyUnicode_FromString(self->err->sid);
}

static PyObject *
ncErrGetBadAttr(ncErrObject *self, void *closure)
{
    PyObject *list;
    uint16_t u;

    if (!self->err->attr_count) {
        Py_RETURN_NONE;
    }

    list = PyList_New(self->err->attr_count);
    if (!list) {
        return NULL;
    }
    for (u = 0; u < self->err->attr_count; u++) {
        PyList_SET_ITEM(list, u, PyUnicode_FromString(self->err->attr[u]));
    }

    return list;
}

static PyObject *
ncErrGetBadElem(ncErrObject *self, void *closure)
{
    PyObject *list;
    uint16_t u;

    if (!self->err->elem_count) {
        Py_RETURN_NONE;
    }

    list = PyList_New(self->err->elem_count);
    if (!list) {
        return NULL;
    }
    for (u = 0; u < self->err->elem_count; u++) {
        PyList_SET_ITEM(list, u, PyUnicode_FromString(self->err->elem[u]));
    }

    return list;
}

static PyObject *
ncErrGetBadNS(ncErrObject *self, void *closure)
{
    PyObject *list;
    uint16_t u;

    if (!self->err->ns_count) {
        Py_RETURN_NONE;
    }

    list = PyList_New(self->err->ns_count);
    if (!list) {
        return NULL;
    }
    for (u = 0; u < self->err->ns_count; u++) {
        PyList_SET_ITEM(list, u, PyUnicode_FromString(self->err->ns[u]));
    }

    return list;
}

/*
 * Callback structures
 */

static PyGetSetDef ncErrGetSetters[] = {
    {"type", (getter)ncErrGetType, NULL, "<error-type>", NULL},
    {"tag", (getter)ncErrGetTag, NULL, "<error-tag>", NULL},
    {"severity", (getter)ncErrGetSeverity, NULL, "<error-severity>", NULL},
    {"app-tag", (getter)ncErrGetAppTag, NULL, "<error-app-tag>", NULL},
    {"path", (getter)ncErrGetPath, NULL, "<error-path>", NULL},
    {"message", (getter)ncErrGetMessage, NULL, "<error-message>", NULL},
    {"lang", (getter)ncErrGetMessageLang, NULL, "<error-message xml:lang=\" \">", NULL},
    {"session-id", (getter)ncErrGetSID, NULL, "<error-info><session-id/></error-info>", NULL},
    {"bad-attr", (getter)ncErrGetBadAttr, NULL, "<error-info><bad-attr/></error-info>", NULL},
    {"bad-elem", (getter)ncErrGetBadElem, NULL, "<error-info><bad-element/></error-info>", NULL},
    {"bad-namespace", (getter)ncErrGetBadNS, NULL, "<error-info><bad-namespace/></error-info>", NULL},
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

