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
test_2time(void **state)
{
    (void) state; /* unused */
    const char *date1 = "2010-02-28T12:34:56Z";      /* 1267360496 */
    const char *date2 = "2010-02-28T22:34:56+10:00"; /* 1267360496 */
    const char *date3 = "2010-02-28T02:34:56-10:00"; /* 1267360496 */
    const char *date4 = "2010-02-28T12:34:56+00:00"; /* 1267360496 */
    const char *date5 = "2010-02-28T12:34:56-00:00"; /* 1267360496 */
    const char *date6 = "2010-02-28T12:34:56.789Z";  /* 1267360496 */
    time_t t;

    t = nc_datetime2time(date1);
    assert_int_equal(t, 1267360496);

    t = nc_datetime2time(date2);
    assert_int_equal(t, 1267360496);

    t = nc_datetime2time(date3);
    assert_int_equal(t, 1267360496);

    t = nc_datetime2time(date4);
    assert_int_equal(t, 1267360496);

    t = nc_datetime2time(date5);
    assert_int_equal(t, 1267360496);

    t = nc_datetime2time(date6);
    assert_int_equal(t, 1267360496);

    t = nc_datetime2time(NULL);
    assert_int_equal(t, -1);
}

static void
test_2datetime(void **state)
{
    (void) state; /* unused */
    time_t t = 1267360496;
    char buf[30];

    assert_ptr_not_equal(NULL, nc_time2datetime(t, NULL, buf));
    assert_string_equal(buf, "2010-02-28T12:34:56Z");

    assert_ptr_not_equal(NULL, nc_time2datetime(t, "Pacific/Honolulu", buf));
    assert_string_equal(buf, "2010-02-28T02:34:56-10:00");

    assert_ptr_not_equal(NULL, nc_time2datetime(t, "Asia/Vladivostok", buf));
    assert_string_equal(buf, "2010-02-28T22:34:56+10:00");

    assert_ptr_not_equal(NULL, nc_time2datetime(t, "CET", buf));
    assert_string_equal(buf, "2010-02-28T13:34:56+01:00");

#if __WORDSIZE == 64
    /* negative years are prohibited */
    assert_ptr_equal(NULL, nc_time2datetime(-69999999999, NULL, buf));
#endif

    /* unknown timezone -> UTC */
    assert_ptr_not_equal(NULL, nc_time2datetime(t, "xxx", buf));
    assert_string_equal(buf, "2010-02-28T12:34:56Z");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_2time),
        cmocka_unit_test(test_2datetime),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
