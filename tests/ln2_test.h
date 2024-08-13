/**
 * @file ln2_test.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief base header for libnetconf2 testing
 *
 * @copyright
 * Copyright (c) 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _LN2_TEST_H_
#define _LN2_TEST_H_

#include <stdarg.h>

#include "tests/config.h"

int ln2_glob_test_get_ports(int port_count, ...);

#endif
