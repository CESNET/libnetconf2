/**
 * \file log.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 logger
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_LOG_PRIVATE_H_
#define NC_LOG_PRIVATE_H_

#include <stdint.h>

#include "log.h"

/*
 * libnetconf's message printing
 */

/**
 * @brief internal printing function
 * @param[in] level Verbose level
 * @param[in] format Formatting string
 */
void prv_printf(NC_VERB_LEVEL level, const char *format, ...);

/**
 * @brief Verbose level variable
 */
extern volatile uint8_t verbose_level;

/*
 * Verbose printing macros
 */
#define ERR(format,args...) prv_printf(NC_VERB_ERROR,format,##args)
#define WRN(format,args...) if(verbose_level>=NC_VERB_WARNING){prv_printf(NC_VERB_WARNING,format,##args);}
#define VRB(format,args...) if(verbose_level>=NC_VERB_VERBOSE){prv_printf(NC_VERB_VERBOSE,format,##args);}
#define DBG(format,args...) if(verbose_level>=NC_VERB_DEBUG){prv_printf(NC_VERB_DEBUG,format,##args);}

#define ERRMEM ERR("%s: memory reallocation failed (%s:%d).", __func__, __FILE__, __LINE__)
#define ERRARG(arg) ERR("%s: invalid argument (%s).", __func__, arg)
#define ERRINIT ERR("%s: libnetconf2 not initialized.", __func__)
#define ERRINT ERR("%s: internal error (%s:%d).", __func__, __FILE__, __LINE__)

#endif /* NC_LOG_PRIVATE_H_ */
