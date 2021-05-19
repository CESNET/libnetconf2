/**
 * \file test_time.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 tests - time functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>

#include <libnetconf.h>

#include "tests/config.h"

static void
test_2timespec(void **state)
{
    (void) state; /* unused */
    const char *date1 = "2010-02-28T12:34:56Z";      /* 1267360496 */
    const char *date2 = "2010-02-28T22:34:56+10:00"; /* 1267360496 */
    const char *date3 = "2010-02-28T02:34:56-10:00"; /* 1267360496 */
    const char *date4 = "2010-02-28T12:34:56+00:00"; /* 1267360496 */
    const char *date5 = "2010-02-28T12:34:56-00:00"; /* 1267360496 */
    const char *date6 = "2010-02-28T12:34:56.789Z";  /* 1267360496 */
    struct timespec ts;

    ts = nc_datetime2timespec(date1);
    assert_int_equal(ts.tv_sec, 1267360496);

    ts = nc_datetime2timespec(date2);
    assert_int_equal(ts.tv_sec, 1267360496);

    ts = nc_datetime2timespec(date3);
    assert_int_equal(ts.tv_sec, 1267360496);

    ts = nc_datetime2timespec(date4);
    assert_int_equal(ts.tv_sec, 1267360496);

    ts = nc_datetime2timespec(date5);
    assert_int_equal(ts.tv_sec, 1267360496);

    ts = nc_datetime2timespec(date6);
    assert_int_equal(ts.tv_sec, 1267360496);

    ts = nc_datetime2timespec(NULL);
    assert_int_equal(ts.tv_sec, 0);
}

static void
test_2datetime(void **state)
{
    (void) state; /* unused */
    struct timespec ts = {.tv_sec = 1267360496, .tv_nsec = 0};
    char buf[30];

    assert_ptr_not_equal(NULL, nc_timespec2datetime(ts, NULL, buf));
    assert_string_equal(buf, "2010-02-28T12:34:56Z");

    assert_ptr_not_equal(NULL, nc_timespec2datetime(ts, "Pacific/Honolulu", buf));
    assert_string_equal(buf, "2010-02-28T02:34:56-10:00");

    assert_ptr_not_equal(NULL, nc_timespec2datetime(ts, "Asia/Vladivostok", buf));
    assert_string_equal(buf, "2010-02-28T22:34:56+10:00");

    assert_ptr_not_equal(NULL, nc_timespec2datetime(ts, "CET", buf));
    assert_string_equal(buf, "2010-02-28T13:34:56+01:00");

    /* unknown timezone -> UTC */
    assert_ptr_not_equal(NULL, nc_timespec2datetime(ts, "xxx", buf));
    assert_string_equal(buf, "2010-02-28T12:34:56Z");

#if __WORDSIZE == 64
    /* negative years are prohibited */
    ts.tv_sec = -69999999999;
    assert_ptr_equal(NULL, nc_timespec2datetime(ts, NULL, buf));
#endif
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_2timespec),
        cmocka_unit_test(test_2datetime),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
