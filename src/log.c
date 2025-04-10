/**
 * @file log.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 - log functions
 *
 * @copyright
 * Copyright (c) 2015 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE /* pthread_rwlock_t */

#include "log_p.h"

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

#define NC_MSG_SIZE 256

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

static void
nc_libssh_log_cb(int priority, const char *UNUSED(function), const char *buffer, void *UNUSED(userdata))
{
    static char last_msg[NC_MSG_SIZE] = {0};
    static struct timespec last_print = {0}, cur_time;

    /* check for repeated messages and do not print them */
    if (!strncmp(last_msg, buffer, NC_MSG_SIZE - 1)) {
        nc_realtime_get(&cur_time);
        if (last_print.tv_sec && (nc_time_diff(&cur_time, &last_print) < 1000)) {
            /* print another repeated message only after 1s */
            return;
        }

        last_print = cur_time;
    } else {
        /* store the last message */
        strncpy(last_msg, buffer, NC_MSG_SIZE - 1);
        memset(&last_print, 0, sizeof last_print);
    }

    /* print the message */
    nc_log_printf(NULL, priority, "SSH: %s", buffer);
}

API void
nc_libssh_thread_verbosity(int level)
{
    ssh_set_log_callback(nc_libssh_log_cb);
    ssh_set_log_level(level);
}

#endif /* NC_ENABLED_SSH_TLS */

void
nc_log_vprintf(const struct nc_session *session, NC_VERB_LEVEL level, const char *format, va_list args)
{
    va_list args2;
    char *msg;
    void *mem;
    int req_len;

    msg = malloc(NC_MSG_SIZE);
    if (!msg) {
        return;
    }

    va_copy(args2, args);

    req_len = vsnprintf(msg, NC_MSG_SIZE - 1, format, args);
    if (req_len == -1) {
        goto cleanup;
    } else if (req_len >= NC_MSG_SIZE - 1) {
        /* the length is not enough */
        ++req_len;
        mem = realloc(msg, req_len);
        if (!mem) {
            goto cleanup;
        }
        msg = mem;

        /* now print the full message */
        req_len = vsnprintf(msg, req_len, format, args2);
        if (req_len == -1) {
            goto cleanup;
        }
    }

    if (print_clb) {
        print_clb(session, level, msg);
    } else if (session && session->id) {
        fprintf(stderr, "Session %" PRIu32 " %s: %s\n", session->id, verb[level].label, msg);
    } else {
        fprintf(stderr, "%s: %s\n", verb[level].label, msg);
    }

cleanup:
    free(msg);
}

void
nc_log_printf(const struct nc_session *session, NC_VERB_LEVEL level, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    nc_log_vprintf(session, level, format, ap);
    va_end(ap);
}

API void
nc_set_print_clb_session(void (*clb)(const struct nc_session *, NC_VERB_LEVEL, const char *))
{
    print_clb = clb;
}
