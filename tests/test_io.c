/**
 * \file test_io.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 tests - input/output functions
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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include <session_p.h>
#include <messages_p.h>
#include "config.h"

struct nc_session session = {0};
struct nc_rpc *rpc = NULL;

static int
setup_f(void **state)
{
    (void) state; /* unused */
    int fd;

    session.ctx = ly_ctx_new(TESTS_DIR"/models");
    pthread_mutex_init(&session.ti_lock, NULL);

    /* ietf-netconf */
    fd = open(TESTS_DIR"/models/ietf-netconf.yin", O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    lys_read(session.ctx, fd, LYS_IN_YIN);
    close(fd);

    return 0;
}

static int
teardown_f(void **state)
{
    (void) state; /* unused */

    if (rpc) {
        lyxml_free_elem(session.ctx, rpc->root);
        lyd_free(rpc->tree);
        free(rpc);
        rpc = NULL;
    }

    ly_ctx_destroy(session.ctx);

    return 0;
}

static void
test_read_rpc(void **state)
{
    (void) state; /* unused */
    NC_MSG_TYPE type;

    /* test IO with standard file descriptors */
    session.ti_type = NC_TI_FD;
    session.ti.fd.c = 0;
    session.side = NC_SIDE_SERVER;
    session.version = NC_VERSION_11;

    session.ti.fd.in = open(TESTS_DIR"/data/nc11/rpc-lock", O_RDONLY);
    if (session.ti.fd.in == -1) {
        fail_msg(" Openning \"%s\" failed (%s)", TESTS_DIR"/data/nc10/rpc-lock", strerror(errno));
    }

    type = nc_recv_rpc(&session, 1000, &rpc);
    assert_int_equal(type, NC_MSG_RPC);
    assert_non_null(rpc);

}

static void
test_write_rpc(void **state)
{
    (void) state; /* unused */
    NC_MSG_TYPE type;

    session.side = NC_SIDE_CLIENT;
    session.ti.fd.out = STDOUT_FILENO;

    do {
        type = nc_send_rpc(&session, rpc->tree, NULL);
    } while(type == NC_MSG_WOULDBLOCK);

    assert_int_equal(type, NC_MSG_RPC);

    write( session.ti.fd.out, "\n", 1);
}

int main(void)
{
    const struct CMUnitTest io[] = {
        cmocka_unit_test_setup(test_read_rpc, setup_f),
        cmocka_unit_test_teardown(test_write_rpc, teardown_f)};

    return cmocka_run_group_tests(io, NULL, NULL);
}
