/**
 * @file log.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief libnetconf2 - log functions
 *
 * @copyright
 * Copyright (c) 2015 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE /* pthread_rwlock_t */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <libyang/libyang.h>

#ifdef NC_ENABLED_SSH_TLS
    #include <libssh/libssh.h>
#endif /* NC_ENABLED_SSH_TLS */

#include "compat.h"
#include "config.h"
#include "log.h"
#include "session_p.h"

/**
 * @brief libnetconf verbose level variable
 */
ATOMIC_T verbose_level = 0;

void (*print_clb)(const struct nc_session *session, NC_VERB_LEVEL level, const char *msg);

API void
nc_verbosity(NC_VERB_LEVEL level)
{
    ATOMIC_STORE_RELAXED(verbose_level, level);
    ly_log_level((LY_LOG_LEVEL)level);
}

struct {
    NC_VERB_LEVEL level;
    const char *label;
} verb[] = {
    {NC_VERB_ERROR, "[ERR]"},
    {NC_VERB_WARNING, "[WRN]"},
    {NC_VERB_VERBOSE, "[INF]"},
    {NC_VERB_DEBUG, "[DBG]"},
    {NC_VERB_DEBUG_LOWLVL, "[DBL]"}
};

#ifdef NC_ENABLED_SSH_TLS

API void
nc_libssh_thread_verbosity(int level)
{
    ssh_set_log_level(level);
}

#endif /* NC_ENABLED_SSH_TLS */

static void
prv_vprintf(const struct nc_session *session, NC_VERB_LEVEL level, const char *format, va_list args)
{
#define PRV_MSG_INIT_SIZE 256
    va_list args2;
    char *prv_msg;
    void *mem;
    int req_len;

    prv_msg = malloc(PRV_MSG_INIT_SIZE);
    if (!prv_msg) {
        return;
    }

    va_copy(args2, args);

    req_len = vsnprintf(prv_msg, PRV_MSG_INIT_SIZE - 1, format, args);
    if (req_len == -1) {
        goto cleanup;
    } else if (req_len >= PRV_MSG_INIT_SIZE - 1) {
        /* the length is not enough */
        ++req_len;
        mem = realloc(prv_msg, req_len);
        if (!mem) {
            goto cleanup;
        }
        prv_msg = mem;

        /* now print the full message */
        req_len = vsnprintf(prv_msg, req_len, format, args2);
        if (req_len == -1) {
            goto cleanup;
        }
    }

    if (print_clb) {
        print_clb(session, level, prv_msg);
    } else if (session && session->id) {
        fprintf(stderr, "Session %" PRIu32 " %s: %s\n", session->id, verb[level].label, prv_msg);
    } else {
        fprintf(stderr, "%s: %s\n", verb[level].label, prv_msg);
    }

cleanup:
    free(prv_msg);
#undef PRV_MSG_INIT_SIZE
}

void
prv_printf(const struct nc_session *session, NC_VERB_LEVEL level, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    prv_vprintf(session, level, format, ap);
    va_end(ap);
}

API void
nc_set_print_clb_session(void (*clb)(const struct nc_session *, NC_VERB_LEVEL, const char *))
{
    print_clb = clb;
}
