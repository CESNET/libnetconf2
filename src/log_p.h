/**
 * \file log.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 logger
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
#define ERRARG ERR("%s: invalid arguments.", __func__)
#define ERRINT ERR("%s: internal error (%s:%d).", __func__, __FILE__, __LINE__)

#endif /* NC_LOG_PRIVATE_H_ */
