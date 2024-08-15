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

#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ln2_test.h"

int
ln2_glob_test_get_ports(int port_count, ...)
{
    va_list ap;
    int i, ret = 0, *port_ptr;
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
            /* the default value will be used instead */
            continue;
        }

        *port_ptr = atoi(env);
        *port_str_ptr = env;
    }

cleanup:
    va_end(ap);
    return ret;
}

void *
ln2_glob_test_server_thread(void *arg)
{
    int ret;
    NC_MSG_TYPE msgtype;
    struct nc_session *session = NULL;
    struct nc_pollsession *ps = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    ps = nc_ps_new();
    assert(ps);

    /* wait for the client to be ready to connect */
    pthread_barrier_wait(&test_ctx->barrier);

    /* accept a session and add it to the poll session structure */
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, test_ctx->ctx, &session);
    if (msgtype != NC_MSG_HELLO) {
        SETUP_FAIL_LOG;
        nc_ps_free(ps);
        return NULL;
    }

    ret = nc_ps_add_session(ps, session);
    assert(!ret);

    /* poll until the session is terminated by the client */
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
        assert(ret & NC_PSPOLL_RPC);
    } while (!(ret & NC_PSPOLL_SESSION_TERM));

    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);
    return NULL;
}

int
ln2_glob_test_setup(struct ln2_test_ctx **test_ctx)
{
    int ret;

    *test_ctx = calloc(1, sizeof **test_ctx);
    if (!*test_ctx) {
        SETUP_FAIL_LOG;
        ret = 1;
        goto cleanup;
    }

    /* set verbosity */
    nc_verbosity(NC_VERB_VERBOSE);

    /* initialize server */
    ret = nc_server_init();
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }

    /* initialize client */
    ret = nc_client_init();
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }

    /* init barrier */
    ret = pthread_barrier_init(&(*test_ctx)->barrier, NULL, 2);
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }

    /* create libyang context */
    ret = ly_ctx_new(MODULES_DIR, 0, &(*test_ctx)->ctx);
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }

    /* load default yang modules */
    ret = nc_server_init_ctx(&(*test_ctx)->ctx);
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }
    ret = nc_server_config_load_modules(&(*test_ctx)->ctx);
    if (ret) {
        SETUP_FAIL_LOG;
        goto cleanup;
    }

cleanup:
    return ret;
}

int
ln2_glob_test_teardown(void **state)
{
    struct ln2_test_ctx *test_ctx = *state;

    nc_client_destroy();
    nc_server_destroy();

    if (test_ctx->free_test_data) {
        test_ctx->free_test_data(test_ctx->test_data);
    }

    pthread_barrier_destroy(&test_ctx->barrier);
    ly_ctx_destroy(test_ctx->ctx);
    free(test_ctx);

    return 0;
}

void
ln2_glob_test_free_test_data(void *test_data)
{
    free(test_data);
}
