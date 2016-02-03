/**
 * \file test_init_destroy_ssh.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 tests - libssh init/destroy
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

