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

#ifndef PYSESSION_H_
#define PYSESSION_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    PyObject_HEAD
    struct ly_ctx *ctx;
    unsigned int *ctx_counter;
    struct nc_session *session;
} ncSessionObject;

#ifdef __cplusplus
}
#endif

#endif /* PYSESSION_H_ */
