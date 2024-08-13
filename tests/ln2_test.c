/**
 * @file ln2_test.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief base source for libnetconf2 testing
 *
 * @copyright
 * Copyright (c) 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ln2_test.h"

int
ln2_glob_test_get_ports(int port_count, ...)
{
    va_list ap;
    int i, ret = 0;
    int *port_ptr;
    const char **port_str_ptr, *env;
    char *env_name = NULL;

    va_start(ap, port_count);

    for (i = 0; i < port_count; i++) {
        port_ptr = va_arg(ap, int *);
        port_str_ptr = va_arg(ap, const char **);

        if (asprintf(&env_name, "TEST_PORT_%d", i) == -1) {
            ret = 1;
            goto cleanup;
        }

        /* try to get the env variable, which is set by CTest */
        env = getenv(env_name);
        free(env_name);
        if (!env) {
            continue;
        }

        *port_ptr = atoi(env);
        *port_str_ptr = env;
    }

cleanup:
    va_end(ap);
    return ret;
}
