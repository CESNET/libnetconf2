/**
 * \file log.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 - log functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 */

#include <stdarg.h>
#include <stdio.h>

#include <libyang/libyang.h>

#include "libnetconf.h"

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
    {NC_VERB_ERROR, "ERROR"},
    {NC_VERB_WARNING, "WARNING"},
    {NC_VERB_VERBOSE, "VERBOSE"},
    {NC_VERB_DEBUG, "DEBUG"}
};

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

API void
nc_set_print_clb(void (*clb)(NC_VERB_LEVEL, const char *))
{
    print_clb = clb;
    ly_set_log_clb((void (*)(LY_LOG_LEVEL, const char *))clb);
}
