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

#include "config.h"
#include "log_p.h"

/**
 * @brief libnetconf verbose level variable
 */
volatile uint8_t verbose_level = 0;

API void
nc_verbosity(NC_VERB_LEVEL level)
{
    verbose_level = level;
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

    /* TODO: allow to set printer via callbacks */
    fprintf(stderr, "%s: %s\n", verb[level].label, prv_msg);

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
nc_verb_verbose(const char *format, ...)
{
    va_list argptr;
    if (verbose_level >= NC_VERB_VERBOSE) {
        va_start(argptr, format);
        prv_vprintf(NC_VERB_VERBOSE, format, argptr);
        va_end(argptr);
    }
}

API void
nc_verb_warning(const char *format, ...)
{
    va_list argptr;

    if (verbose_level >= NC_VERB_WARNING) {
        va_start(argptr, format);
        prv_vprintf(NC_VERB_WARNING, format, argptr);
        va_end(argptr);
    }
}

API void
nc_verb_error(const char *format, ...)
{
    va_list argptr;

    va_start(argptr, format);
    prv_vprintf(NC_VERB_ERROR, format, argptr);
    va_end(argptr);
}
