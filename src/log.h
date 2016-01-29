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

#ifndef NC_LOG_H_
#define NC_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Verbosity levels.
 */
typedef enum NC_VERB_LEVEL {
    NC_VERB_ERROR = 0,   /**< Print only error messages. */
    NC_VERB_WARNING = 1, /**< Print error and warning messages. */
    NC_VERB_VERBOSE = 2, /**< Besides errors and warnings, print some other verbose messages. */
    NC_VERB_DEBUG = 3    /**< Print all messages including some development debug messages. */
} NC_VERB_LEVEL;

/**
 * @brief Set libnetconf's verbosity level.
 *
 * This level is set for libnetconf2 and alo libyang that is used internally. libyang
 * verbose level can be set explicitly, but must be done so after calling this function.
 *
 * @param[in] level Enabled verbosity level (includes all the levels with higher priority).
 */
void nc_verbosity(NC_VERB_LEVEL level);

/**
 * @brief Set libnetconf's print callback.
 *
 * This callback is set for libnetconf2 and also libyang that is used internally. libyang
 * callback can be set explicitly, but must be done so after calling this function.
 *
 * @param[in] clb Callback that is called for every message.
 */
void nc_set_print_clb(void (*clb)(NC_VERB_LEVEL, const char *));

#ifdef __cplusplus
}
#endif

#endif /* NC_LOG_H_ */
