/**
 * \file libnetconf.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 main internal header.
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_LIBNETCONF_H_
#define NC_LIBNETCONF_H_

#include "config.h"
#include "netconf.h"
#include "log_p.h"
#include "session_p.h"
#include "messages_p.h"

/* Tests whether string is empty or non-empty. */
#define strisempty(str) ((str)[0] == '\0')
#define strnonempty(str) ((str)[0] != '\0')

#endif /* NC_LIBNETCONF_H_ */
