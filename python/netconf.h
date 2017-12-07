/**
 * @file netconf.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief Main header of Python3 bindings for libnetconf2 (client-side)
 *
 * Copyright (c) 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef PYNETCONF_H_
#define PYNETCONF_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "../src/netconf.h"
#include "../src/log.h"
#include "../src/messages_client.h"
#include "../src/session_client.h"
#include "../src/session_client_ch.h"

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#elif defined(__cplusplus)
# define UNUSED(x)
#else
# define UNUSED(x) x
#endif

typedef struct {
    PyObject_HEAD
    PyObject *username;  /* username */
    PyObject *password;  /* plaintext password for authentication or unlocking a private key */
    PyObject *pubkeys;   /* public keys for the key authentication, both pubkey and privkey must be set */
    PyObject *privkeys;  /* private key for the key authentication, both pubkey and privkey must be set */

    PyObject *clb_hostcheck;         /* callback to check host key (fingerprint) */
    PyObject *clb_hostcheck_data;    /* private data for the host key check callback */
    PyObject *clb_password;          /* callback for SSH password authentication */
    PyObject *clb_password_data;     /* private data for the SSH password authentication callback */
    PyObject *clb_interactive;       /* callback for SSH keyboard-interactive authentication */
    PyObject *clb_interactive_data;  /* private data for the SSH keyboard-interactive authentication callback */
} ncSSHObject;

typedef struct {
    PyObject_HEAD
    PyObject *cert_file;  /* path to the client certificate file */
    PyObject *key_file;   /* path to the file with the private key for the client certificate */
    PyObject *ca_file;    /* path to the file with the CA certificate(s) used to verify the server certificate */
    PyObject *ca_dir;     /* path to the directory with the CA certificate(s) used to verify the server certificate */
    PyObject *crl_file;   /* path to the file with the CRL certificate(s) used to check for revocated server certificates */
    PyObject *crl_dir;    /* path to the directory with the CRL certificate(s) used to check for revocated server certificates */
} ncTLSObject;

typedef struct {
    PyObject_HEAD
    struct nc_err *err;
    struct ly_ctx *ctx;
} ncErrObject;

extern PyTypeObject ncSSHType;
extern PyTypeObject ncTLSType;
extern PyTypeObject ncSessionType;
extern PyTypeObject ncErrType;

#ifdef __cplusplus
}
#endif

#endif /* PYNETCONF_H_ */
