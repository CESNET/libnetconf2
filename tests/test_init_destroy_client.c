/**
 * \file test_init_destroy_client.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 tests - init/destroy client
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "tests/config.h"
#include <session_client.h>

static int
setup_client(void **state)
{
    (void)state;

    nc_client_init();

    return 0;
}

static int
teardown_client(void **state)
{
    (void)state;

    nc_client_destroy();

    return 0;
}

static void
test_dummy(void **state)
{
    (void)state;
}

int
main(void)
{
    const struct CMUnitTest init_destroy[] = {
        cmocka_unit_test_setup_teardown(test_dummy, setup_client, teardown_client)
    };

    return cmocka_run_group_tests(init_destroy, NULL, NULL);
}

