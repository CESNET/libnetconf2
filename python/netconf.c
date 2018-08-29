/**
 * @file netconf.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief Python3 bindings for libnetconf2 (client-side)
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
#include <syslog.h>

#include "netconf.h"

PyObject *libnetconf2Error;
PyObject *libnetconf2Warning;
PyObject *libnetconf2ReplyError;

/* syslog usage flag */
static int syslogEnabled = 0;

/* libyang schema callback */
static PyObject *schemaCallback = NULL;
static void *schemaCallbackData = NULL;

static void
clb_print(NC_VERB_LEVEL level, const char* msg)
{
    switch (level) {
    case NC_VERB_ERROR:
        PyErr_SetString(libnetconf2Error, msg);
        if (syslogEnabled) {
            syslog(LOG_ERR, "%s", msg);
        }
        break;
    case NC_VERB_WARNING:
        if (syslogEnabled) {
            syslog(LOG_WARNING, "%s", msg);
        }
        PyErr_WarnEx(libnetconf2Warning, msg, 1);
        break;
    case NC_VERB_VERBOSE:
        if (syslogEnabled) {
            syslog(LOG_INFO, "%s", msg);
        }
        break;
    case NC_VERB_DEBUG:
        if (syslogEnabled) {
            syslog(LOG_DEBUG, "%s", msg);
        }
        break;
    }
}

static PyObject *
setSyslog(PyObject *self, PyObject *args, PyObject *keywds)
{
    char* name = NULL;
    static char* logname = NULL;
    static int option = LOG_PID;
    static int facility = LOG_USER;

    static char *kwlist[] = {"enabled", "name", "option", "facility", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "p|sii", kwlist, &syslogEnabled, &name, &option, &facility)) {
        return NULL;
    }

    if (name) {
        free(logname);
        logname = strdup(name);
    } else {
        free(logname);
        logname = NULL;
    }
    closelog();
    openlog(logname, option, facility);

    Py_RETURN_NONE;
}

static PyObject *
setVerbosity(PyObject *self, PyObject *args, PyObject *keywds)
{
    int level = NC_VERB_ERROR; /* 0 */

    static char *kwlist[] = {"level", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "i", kwlist, &level)) {
        return NULL;
    }

    /* normalize level value if not from the enum */
    if (level < NC_VERB_ERROR) {
        nc_verbosity(NC_VERB_ERROR);
    } else if (level > NC_VERB_DEBUG) {
        nc_verbosity(NC_VERB_DEBUG);
    } else {
        nc_verbosity(level);
    }

    Py_RETURN_NONE;
}

static PyObject *
setSearchpath(PyObject *self, PyObject *args, PyObject *keywds)
{
    char *path;
    static char *kwlist[] = {"path", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &path)) {
        return NULL;
    }

    if (nc_client_set_schema_searchpath(path)) {
        return NULL;
    }

    Py_RETURN_NONE;
}

char *
schemaCallbackWrapper(const char *mod_name, const char *mod_rev, const char *submod_name, const char *sub_rev,
                      void *user_data, LYS_INFORMAT *format, void (**free_module_data)(void *model_data))
{
    PyObject *arglist, *result, *data = NULL;
    char *str = NULL;

    arglist = Py_BuildValue("(ssssO)", mod_name, mod_rev, submod_name, sub_rev, schemaCallbackData ? schemaCallbackData : Py_None);
    if (!arglist) {
        PyErr_Print();
        return NULL;
    }
    result = PyObject_CallObject(schemaCallback, arglist);
    Py_DECREF(arglist);

    if (result) {
        if (!PyArg_ParseTuple(result, "iU", format, &data)) {
            Py_DECREF(result);
            return NULL;
        }
        Py_DECREF(result);
        *free_module_data = free;
        str = strdup(PyUnicode_AsUTF8(data));
        Py_DECREF(data);
    }

    return str;
}

static PyObject *
setSchemaCallback(PyObject *self, PyObject *args, PyObject *keywds)
{
    PyObject *clb = NULL, *data = NULL;
    static char *kwlist[] = {"func", "priv", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "O|O:setSchemaCallback", kwlist, &clb, &data)) {
        return NULL;
    }

    if (!clb || clb == Py_None) {
        Py_XDECREF(schemaCallback);
        Py_XDECREF(schemaCallbackData);
        data = NULL;
    } else if (!PyCallable_Check(clb)) {
        PyErr_SetString(PyExc_TypeError, "The callback must be a function.");
        return NULL;
    } else {
        Py_XDECREF(schemaCallback);
        Py_XDECREF(schemaCallbackData);

        Py_INCREF(clb);
        if (data) {
            Py_INCREF(data);
        }
    }
    nc_client_set_schema_callback(schemaCallbackWrapper, NULL);
    schemaCallback = clb;
    schemaCallbackData = data;

    Py_RETURN_NONE;
}

static PyMethodDef netconf2Methods[] = {
    {"setVerbosity", (PyCFunction)setVerbosity, METH_VARARGS | METH_KEYWORDS,
     "setVerbosity(level)\n--\n\n"
     "Set verbose level\n\n"
     ":param level: Verbosity level (0 - errors, 1 - warnings, 2 - verbose, 3 - debug)\n"
     ":type level: int\n"
     ":returns: None\n"},
    {"setSyslog", (PyCFunction)setSyslog, METH_VARARGS | METH_KEYWORDS,
     "setSyslog(enabled[, name=None][, option=LOG_PID][, facility=LOG_USER])\n--\n\n"
     "Set application settings for syslog.\n\n"
     ":param enabled: Flag to enable/disable logging into syslog.\n"
     ":type enabled: bool\n"
     ":param name: Identifier (program name is set by default).\n"
     ":type name: string\n"
     ":param option: ORed value of syslog options (LOG_PID by default).\n"
     ":type option: int\n"
     ":param facility: Type of the program logging the message (LOG_USER by default).\n"
     ":type facility: int\n"
     ":returns: None\n\n"
     ".. seealso:: syslog.openlog\n"},
    {"setSearchpath", (PyCFunction)setSearchpath, METH_VARARGS | METH_KEYWORDS,
     "setSearchpath(path)\n--\n\n"
     "Set location where YANG/YIN schemas are searched and where the schemas\n"
     "retrieved via <get-schema> opration are stored.\n\n"
     ":param path: Search directory.\n"
     ":type path: string\n"
     ":returns: None\n"},
    {"setSchemaCallback", (PyCFunction)setSchemaCallback, METH_VARARGS | METH_KEYWORDS,
     "Set schema search callaback.\n\n"
     "setSchemaCallback(func, priv=None)\n"
     "with func(str mod_name, str mod_rev, str submod_name, str submod_rev, priv)\n"
     "callback returns tuple of format (e.g. LYS_IN_YANG) and string of the schema content.\n"},
    {NULL, NULL, 0, NULL}
};

static char netconf2Docs[] =
    "NETCONF Protocol client-side implementation using libnetconf2\n"
    "\n"
    "netconf2 is a wrapper around libnetconf2 functions designed for NETCONF\n"
    "clients. it provides a higher level API than the original libnetconf2 to\n"
    "better fit the usage in Python.\n";

static struct PyModuleDef ncModule = {
    PyModuleDef_HEAD_INIT,
    "netconf2",
    netconf2Docs,
    -1,
    netconf2Methods,
};

/* module initializer */
PyMODINIT_FUNC
PyInit_netconf2(void)
{
    void* clb;
    PyObject *nc;

    /* import libyang Python module to have it available */
    if (!PyImport_ImportModule("yang")) {
        return NULL;
    }

    /* initiate libnetconf2 client part */
    nc_client_init();

    /* set schema searchpath
     * nc_client_set_schema_searchpath()
     */

    /* set print callback */
    clb = ly_get_log_clb();
    nc_set_print_clb(clb_print);
    ly_set_log_clb(clb, 1);

    if (PyType_Ready(&ncSessionType) == -1) {
        return NULL;
    }

    ncSSHType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ncSSHType) == -1) {
        return NULL;
    }
/*
    ncTLSType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ncTLSType) == -1) {
        return NULL;
    }
*/
    ncErrType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ncErrType) == -1) {
        return NULL;
    }

    /* create netconf as the Python module */
    nc = PyModule_Create(&ncModule);
    if (nc == NULL) {
        return NULL;
    }

    Py_INCREF(&ncSSHType);
    PyModule_AddObject(nc, "SSH", (PyObject *)&ncSSHType);
/*
    Py_INCREF(&ncTLSType);
    PyModule_AddObject(nc, "TLS", (PyObject *)&ncTLSType);
*/
    Py_INCREF(&ncErrType);
    PyModule_AddObject(nc, "ReplyErrorInfo", (PyObject *)&ncErrType);

    Py_INCREF(&ncSessionType);
    PyModule_AddObject(nc, "Session", (PyObject *)&ncSessionType);

/*
    Py_INCREF(&ncTLSType);
    PyModule_AddObject(nc, "TLS", (PyObject *)&ncTLSType);
*/
/*
    PyModule_AddStringConstant(nc, "NETCONFv1_0", NETCONF_CAP_BASE10);
    PyModule_AddStringConstant(nc, "NETCONFv1_1", NETCONF_CAP_BASE11);
    PyModule_AddStringConstant(nc, "TRANSPORT_SSH", NETCONF_TRANSPORT_SSH);
    PyModule_AddStringConstant(nc, "TRANSPORT_TLS", NETCONF_TRANSPORT_TLS);
*/
    PyModule_AddIntConstant(nc, "DATASTORE_RUNNING", NC_DATASTORE_RUNNING);
    PyModule_AddIntConstant(nc, "DATASTORE_STARTUP", NC_DATASTORE_STARTUP);
    PyModule_AddIntConstant(nc, "DATASTORE_CANDIDATE", NC_DATASTORE_CANDIDATE);

    PyModule_AddIntConstant(nc, "RPC_EDIT_ERROPT_STOP", NC_RPC_EDIT_ERROPT_STOP);
    PyModule_AddIntConstant(nc, "RPC_EDIT_ERROPT_CONTINUE", NC_RPC_EDIT_ERROPT_CONTINUE);
    PyModule_AddIntConstant(nc, "RPC_EDIT_ERROPT_ROLLBACK", NC_RPC_EDIT_ERROPT_ROLLBACK);

    PyModule_AddIntConstant(nc, "RPC_EDIT_TESTOPT_TESTSET", NC_RPC_EDIT_TESTOPT_TESTSET);
    PyModule_AddIntConstant(nc, "RPC_EDIT_TESTOPT_SET", NC_RPC_EDIT_TESTOPT_SET);
    PyModule_AddIntConstant(nc, "RPC_EDIT_TESTOPT_TEST", NC_RPC_EDIT_TESTOPT_TEST);

    PyModule_AddIntConstant(nc, "RPC_EDIT_DFLTOP_MERGE", NC_RPC_EDIT_DFLTOP_MERGE);
    PyModule_AddIntConstant(nc, "RPC_EDIT_DFLTOP_REPLACE", NC_RPC_EDIT_DFLTOP_REPLACE);
    PyModule_AddIntConstant(nc, "RPC_EDIT_DFLTOP_NONE", NC_RPC_EDIT_DFLTOP_NONE);

    /* init libnetconf exceptions for use in clb_print() */
    libnetconf2Error = PyErr_NewExceptionWithDoc("netconf2.Error",
                    "Error passed from the underlying libnetconf2 library.",
                    NULL, NULL);
    Py_INCREF(libnetconf2Error);
    PyModule_AddObject(nc, "Error", libnetconf2Error);

    libnetconf2Warning = PyErr_NewExceptionWithDoc("netconf2.Warning",
                    "Warning passed from the underlying libnetconf2 library.",
                    PyExc_Warning, NULL);
    Py_INCREF(libnetconf2Warning);
    PyModule_AddObject(nc, "Warning", libnetconf2Warning);

    libnetconf2ReplyError = PyErr_NewExceptionWithDoc("netconf2.ReplyError",
                    "NETCONF error returned from the server.",
                    NULL, NULL);
    Py_INCREF(libnetconf2ReplyError);
    PyModule_AddObject(nc, "ReplyError", libnetconf2ReplyError);

    return nc;
}
