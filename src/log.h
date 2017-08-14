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

#ifndef NC_LOG_H_
#define NC_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup misc
 * @{
 */

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
 * However, if debug verbosity is used, selecting displayed libyang debug message groups
 * must be done explicitly.
 *
 * @param[in] level Enabled verbosity level (includes all the levels with higher priority).
 */
void nc_verbosity(NC_VERB_LEVEL level);

#ifdef NC_ENABLED_SSH

/**
 * @brief Set libssh verbosity level.
 *
 * libssh verbosity is set separately because it defines more verbose levels than libnetconf2.
 * Also, you need to set this for every thread unlike libnetconf verbosity.
 *
 * Values:
 * - 0 - no logging,
 * - 1 - rare conditions or warnings,
 * - 2 - API-accessible entrypoints,
 * - 3 - packet id and size,
 * - 4 - functions entering and leaving.
 *
 * @param[in] level libssh verbosity level.
 */
void nc_libssh_thread_verbosity(int level);

#endif

/**
 * @brief Set libnetconf's print callback.
 *
 * This callback is set for libnetconf2 and also libyang that is used internally. libyang
 * callback can be set explicitly, but must be done so after calling this function.
 *
 * @param[in] clb Callback that is called for every message.
 */
void nc_set_print_clb(void (*clb)(NC_VERB_LEVEL, const char *));

/**@} Miscellaneous */

#ifdef __cplusplus
}
#endif

#endif /* NC_LOG_H_ */
