/**
 * \file test_init_destroy_ssh.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 tests - libssh init/destroy
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

#include "config.h"
#include <netconf.h>

static int
setup_ssh(void **state)
{
    (void)state;

    nc_ssh_init();

    return 0;
}

static int
teardown_ssh(void **state)
{
    (void)state;

    nc_ssh_destroy();

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
        cmocka_unit_test_setup_teardown(test_dummy, setup_ssh, teardown_ssh)
    };

    return cmocka_run_group_tests(init_destroy, NULL, NULL);
}

