/**
 * \file log.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 - log functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include <libyang/libyang.h>

#ifdef NC_ENABLED_SSH
    #include <libssh/libssh.h>
#endif

#include "libnetconf.h"
#include "log.h"

/**
 * @brief libnetconf verbose level variable
 */
volatile uint8_t verbose_level = 0;

void (*print_clb)(NC_VERB_LEVEL level, const char *msg);

API void
nc_verbosity(NC_VERB_LEVEL level)
{
    verbose_level = level;
    ly_verb((LY_LOG_LEVEL)level);
}

struct {
    NC_VERB_LEVEL level;
    const char *label;
} verb[] = {
    {NC_VERB_ERROR, "[ERR]"},
    {NC_VERB_WARNING, "[WRN]"},
    {NC_VERB_VERBOSE, "[INF]"},
    {NC_VERB_DEBUG, "[DBG]"}
};

#ifdef NC_ENABLED_SSH

API void
nc_libssh_thread_verbosity(int level)
{
    ssh_set_log_level(level);
}

#endif

static void
prv_vprintf(NC_VERB_LEVEL level, const char *format, va_list args)
{
#define PRV_MSG_SIZE 4096
    char prv_msg[PRV_MSG_SIZE];

    vsnprintf(prv_msg, PRV_MSG_SIZE - 1, format, args);
    prv_msg[PRV_MSG_SIZE - 1] = '\0';

    if (print_clb) {
        print_clb(level, prv_msg);
    } else {
        fprintf(stderr, "%s: %s\n", verb[level].label, prv_msg);
    }

#undef PRV_MSG_SIZE
}

void
prv_printf(NC_VERB_LEVEL level, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    prv_vprintf(level, format, ap);
    va_end(ap);
}

static void
nc_ly_log_clb(LY_LOG_LEVEL lvl, const char *msg, const char *UNUSED(path))
{
    print_clb((NC_VERB_LEVEL)lvl, msg);
}

API void
nc_set_print_clb(void (*clb)(NC_VERB_LEVEL, const char *))
{
    print_clb = clb;
    ly_set_log_clb(nc_ly_log_clb, 0);
}
