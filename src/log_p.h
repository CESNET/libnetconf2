/**
 * @file log.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief libnetconf2 logger
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

#ifndef NC_LOG_PRIVATE_H_
#define NC_LOG_PRIVATE_H_

#include <stdarg.h>

#include "compat.h"
#include "log.h"

/*
 * libnetconf's message printing
 */

/**
 * @brief Internal printing function
 *
 * @param[in] session Optional NETCONF session that generated the message
 * @param[in] level Verbose level
 * @param[in] format Formatting string
 */
void prv_printf(const struct nc_session *session, NC_VERB_LEVEL level, const char *format, ...);

/**
 * @brief Verbose level variable
 */
extern ATOMIC_T verbose_level;

/*
 * Verbose printing macros
 */
#define ERR(session, ...) prv_printf(session, NC_VERB_ERROR, __VA_ARGS__)
#define WRN(session, ...) if(ATOMIC_LOAD_RELAXED(verbose_level)>=NC_VERB_WARNING){prv_printf(session, NC_VERB_WARNING, __VA_ARGS__);}
#define VRB(session, ...) if(ATOMIC_LOAD_RELAXED(verbose_level)>=NC_VERB_VERBOSE){prv_printf(session, NC_VERB_VERBOSE, __VA_ARGS__);}
#define DBG(session, ...) if(ATOMIC_LOAD_RELAXED(verbose_level)>=NC_VERB_DEBUG){prv_printf(session, NC_VERB_DEBUG, __VA_ARGS__);}
#define DBL(session, ...) if(ATOMIC_LOAD_RELAXED(verbose_level)>=NC_VERB_DEBUG_LOWLVL){prv_printf(session, NC_VERB_DEBUG_LOWLVL, __VA_ARGS__);}

#define ERRMEM ERR(NULL, "%s: memory reallocation failed (%s:%d).", __func__, __FILE__, __LINE__)
#define ERRINITSRV ERR(NULL, "%s: server not initialized.", __func__)
#define ERRINT ERR(NULL, "%s: internal error (%s:%d).", __func__, __FILE__, __LINE__)
#define ERRARG(session, ARG) ERR(session, "Invalid argument %s (%s()).", #ARG, __func__)

#define NC_CHECK_SRV_INIT_RET(RET) if (!ATOMIC_LOAD_RELAXED(server_opts.new_session_id)) {ERRINITSRV; return (RET);}
#define NC_CHECK_ERRMEM_RET(COND, RET) if ((COND)) {ERRMEM; return (RET);}
#define NC_CHECK_ERRMEM_GOTO(COND, RET, GOTO) if ((COND)) {ERRMEM; RET; goto GOTO;}

#define GETMACRO1(_1, NAME, ...) NAME
#define GETMACRO2(_1, _2, NAME, ...) NAME
#define GETMACRO3(_1, _2, _3, NAME, ...) NAME
#define GETMACRO4(_1, _2, _3, _4, NAME, ...) NAME
#define GETMACRO5(_1, _2, _3, _4, _5, NAME, ...) NAME
#define GETMACRO6(_1, _2, _3, _4, _5, _6, NAME, ...) NAME
#define GETMACRO7(_1, _2, _3, _4, _5, _6, _7, NAME, ...) NAME
#define GETMACRO8(_1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME

#define NC_CHECK_ARG_RET1(session, ARG, RETVAL) if (!(ARG)) {ERRARG(session, ARG);return RETVAL;}
#define NC_CHECK_ARG_RET2(session, ARG1, ARG2, RETVAL)\
    NC_CHECK_ARG_RET1(session, ARG1, RETVAL);\
    NC_CHECK_ARG_RET1(session, ARG2, RETVAL)
#define NC_CHECK_ARG_RET3(session, ARG1, ARG2, ARG3, RETVAL)\
    NC_CHECK_ARG_RET2(session, ARG1, ARG2, RETVAL);\
    NC_CHECK_ARG_RET1(session, ARG3, RETVAL)
#define NC_CHECK_ARG_RET4(session, ARG1, ARG2, ARG3, ARG4, RETVAL)\
    NC_CHECK_ARG_RET3(session, ARG1, ARG2, ARG3, RETVAL);\
    NC_CHECK_ARG_RET1(session, ARG4, RETVAL)
#define NC_CHECK_ARG_RET5(session, ARG1, ARG2, ARG3, ARG4, ARG5, RETVAL)\
    NC_CHECK_ARG_RET4(session, ARG1, ARG2, ARG3, ARG4, RETVAL);\
    NC_CHECK_ARG_RET1(session, ARG5, RETVAL)
#define NC_CHECK_ARG_RET6(session, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6, RETVAL)\
    NC_CHECK_ARG_RET5(session, ARG1, ARG2, ARG3, ARG4, ARG5, RETVAL);\
    NC_CHECK_ARG_RET1(session, ARG6, RETVAL)
#define NC_CHECK_ARG_RET7(session, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6, ARG7, RETVAL)\
    NC_CHECK_ARG_RET6(session, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6, RETVAL);\
    NC_CHECK_ARG_RET1(session, ARG7, RETVAL)

/**
 * @brief Function's parameters checking macro
 *
 * @param session Session that is logged.
 * @param ... Parameters of the function to check. The last parameter is the value that is returned on error.
 */
#define NC_CHECK_ARG_RET(session, ...) GETMACRO8(__VA_ARGS__, NC_CHECK_ARG_RET7, NC_CHECK_ARG_RET6, NC_CHECK_ARG_RET5,\
    NC_CHECK_ARG_RET4, NC_CHECK_ARG_RET3, NC_CHECK_ARG_RET2, NC_CHECK_ARG_RET1, DUMMY) (session, __VA_ARGS__)

#endif /* NC_LOG_PRIVATE_H_ */
