/**
 * @file rpc.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief RPC functions for the Session object
 *
 * Copyright (c) 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef PYRPC_H_
#define PYRPC_H_

#ifdef __cplusplus
extern "C" {
#endif

PyObject *ncRPCGet(ncSSHObject *self, PyObject *args, PyObject *keywords);
PyObject *ncRPCGetConfig(ncSSHObject *self, PyObject *args, PyObject *keywords);
PyObject *ncRPCEditConfig(ncSSHObject *self, PyObject *args, PyObject *keywords);

#ifdef __cplusplus
}
#endif

#endif /* PYRPC_H_ */
