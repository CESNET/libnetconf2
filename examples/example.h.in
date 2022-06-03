/**
 * @file example.h
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 example header
 *
 * @copyright
 * Copyright (c) 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _EXAMPLE_H_
#define _EXAMPLE_H_

#include <stdio.h>

/* directory with library YANG modules */
#define MODULES_DIR "@CMAKE_SOURCE_DIR@/modules"

/* SSH listening IP address */
#define SSH_ADDRESS "127.0.0.1"

/* SSH listening port */
#define SSH_PORT 830

/* SSH 'password' authentication exptected username and password */
#define SSH_USERNAME "admin"
#define SSH_PASSWORD "admin"

/* time in microseconds to sleep for if there are no new RPCs and no new sessions */
#define BACKOFF_TIMEOUT_USECS 100

#define ERR_MSG_CLEANUP(msg) \
        rc = 1; \
        fprintf(stderr, "%s", msg); \
        goto cleanup

/* supported server transport protocol */
enum server_transport {
    NONE = 0,
    UNIX,
    SSH
};

#endif
