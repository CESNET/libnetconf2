/**
 * \file test_client_thread.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 tests - threads functions in client
 *
 * Copyright (c) 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "ln2_test.h"

#define nc_assert(cond) if (!(cond)) { fprintf(stderr, "assert failed (%s:%d)\n", __FILE__, __LINE__); exit(1); }

static void *
thread(void *arg)
{
    /* default search path is NULL */
    nc_assert(nc_client_get_schema_searchpath() == NULL);

    /* use the context shared from the main thread */
    nc_client_set_thread_context(arg);

    /* check that we have now the search path set in main thread */
    nc_assert(strcmp(nc_client_get_schema_searchpath(), "/tmp") == 0);
    /* and change it to check it later in main thread */
    nc_assert(nc_client_set_schema_searchpath("/etc") == 0)

    return NULL;
}

int
main(void)
{
    void *arg;
    pthread_t t;
    int r;

    /*
     * TEST sharing the thread context
     */
    nc_assert(nc_client_set_schema_searchpath("/tmp") == 0)

    /* get the context for sharing */
    arg = nc_client_get_thread_context();

    /* create new thread and provide the context */
    r = pthread_create(&t, NULL, &thread, arg);
    nc_assert(r == 0);

    pthread_join(t, NULL);

    /* check the changed search path value from the thread */
    nc_assert(strcmp(nc_client_get_schema_searchpath(), "/etc") == 0);

    /* cleanup */
    nc_client_destroy();

    return EXIT_SUCCESS;
}
