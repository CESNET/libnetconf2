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
#include <nc_client.h>
#include <syslog.h>

#include "netconf.h"

PyObject *libnetconf2Error;
PyObject *libnetconf2Warning;

/* syslog usage flag */
static int syslogEnabled = 0;

static void
clb_print(NC_VERB_LEVEL level, const char* msg)
{
	switch (level) {
	case NC_VERB_ERROR:
		PyErr_SetString(libnetconf2Error, msg);
		if (syslogEnabled) {syslog(LOG_ERR, "%s", msg);}
		break;
	case NC_VERB_WARNING:
		if (syslogEnabled) {syslog(LOG_WARNING, "%s", msg);}
		PyErr_WarnEx(libnetconf2Warning, msg, 1);
		break;
	case NC_VERB_VERBOSE:
		if (syslogEnabled) {syslog(LOG_INFO, "%s", msg);}
		break;
	case NC_VERB_DEBUG:
		if (syslogEnabled) {syslog(LOG_DEBUG, "%s", msg);}
		break;
	}
}

static PyObject *
setSyslog(PyObject *self, PyObject *args, PyObject *keywds)
{
	char* name = NULL;
	static char* logname = NULL;
	static int option = LOG_PID;
	static int facility = LOG_DAEMON;

	static char *kwlist[] = {"enabled", "name", "option", "facility", NULL};

	if (! PyArg_ParseTupleAndKeywords(args, keywds, "p|sii", kwlist, &syslogEnabled, &name, &option, &facility)) {
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

	if (! PyArg_ParseTupleAndKeywords(args, keywds, "i", kwlist, &level)) {
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

static PyMethodDef netconf2Methods[] = {
		{"setVerbosity", (PyCFunction)setVerbosity, METH_VARARGS | METH_KEYWORDS, "Set verbose level (0-3)."},
		{"setSyslog", (PyCFunction)setSyslog, METH_VARARGS | METH_KEYWORDS, "Set application settings for syslog."},
		{NULL, NULL, 0, NULL}
};

static struct PyModuleDef ncModule = {
		PyModuleDef_HEAD_INIT,
		"netconf2",
		"NETCONF Protocol implementation using libnetconf2",
		-1,
		netconf2Methods,
};

/* module initializer */
PyMODINIT_FUNC
PyInit_netconf2(void)
{
	PyObject *nc;

	/* initiate libnetconf2 client part */
	nc_client_init();

	/* set schema searchpath
	 * nc_client_set_schema_searchpath()
	 */

	/* set print callback */
	nc_set_print_clb(clb_print);

    if (PyType_Ready(&ncSessionType) == -1) {
        return NULL;
    }

    ncSSHType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ncSSHType) == -1) {
        return NULL;
    }

    ncTLSType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&ncTLSType) == -1) {
        return NULL;
    }

	/* create netconf as the Python module */
	nc = PyModule_Create(&ncModule);
	if (nc == NULL) {
		return NULL;
	}

    Py_INCREF(&ncSSHType);
    PyModule_AddObject(nc, "SSH", (PyObject *)&ncSSHType);

    Py_INCREF(&ncTLSType);
    PyModule_AddObject(nc, "TLS", (PyObject *)&ncTLSType);

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

	/* init libnetconf exceptions for use in clb_print() */
	libnetconf2Error = PyErr_NewExceptionWithDoc("netconf.Error",
	                                             "Error passed from the underlying libnetconf2 library.",
	                                             NULL, NULL);
	Py_INCREF(libnetconf2Error);
	PyModule_AddObject(nc, "Error", libnetconf2Error);

	libnetconf2Warning = PyErr_NewExceptionWithDoc("netconf.Warning",
	                                               "Warning passed from the underlying libnetconf2 library.",
	                                               PyExc_Warning, NULL);
	Py_INCREF(libnetconf2Warning);
	PyModule_AddObject(nc, "Warning", libnetconf2Warning);

	return nc;
}
