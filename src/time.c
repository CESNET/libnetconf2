/**
 * \file time.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 - time handling functions
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

#define _GNU_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libnetconf.h"

API time_t
nc_datetime2time(const char *datetime)
{
    struct tm time;
    char *dt;
    int i;
    long int shift, shift_m;
    time_t retval;

    if (datetime == NULL) {
        return (-1);
    } else {
        dt = strdup(datetime);
    }

    if (strlen(dt) < 20 || dt[4] != '-' || dt[7] != '-' || dt[13] != ':' || dt[16] != ':') {
        ERR("Wrong date time format not compliant to RFC 3339.");
        free(dt);
        return (-1);
    }

    memset(&time, 0, sizeof(struct tm));
    time.tm_year = atoi(&dt[0]) - 1900;
    time.tm_mon = atoi(&dt[5]) - 1;
    time.tm_mday = atoi(&dt[8]);
    time.tm_hour = atoi(&dt[11]);
    time.tm_min = atoi(&dt[14]);
    time.tm_sec = atoi(&dt[17]);

    retval = timegm(&time);

    /* apply offset */
    i = 19;
    if (dt[i] == '.') { /* we have fractions to skip */
        for (i++; isdigit(dt[i]); i++)
            ;
    }
    if (dt[i] == 'Z' || dt[i] == 'z') {
        /* zero shift */
        shift = 0;
    } else if (dt[i + 3] != ':') {
        /* wrong format */
        ERR("Wrong date time shift format not compliant to RFC 3339.");
        free(dt);
        return (-1);
    } else {
        shift = strtol(&dt[i], NULL, 10);
        shift = shift * 60 * 60; /* convert from hours to seconds */
        shift_m = strtol(&dt[i + 4], NULL, 10) * 60; /* includes conversion from minutes to seconds */
        /* correct sign */
        if (shift < 0) {
            shift_m *= -1;
        }
        /* connect hours and minutes of the shift */
        shift = shift + shift_m;
    }
    /* we have to shift to the opposite way to correct the time */
    retval -= shift;

    free(dt);
    return (retval);
}

API char *
nc_time2datetime(time_t time, const char *tz)
{
    char *date = NULL;
    char *zoneshift = NULL;
    int zonediff, zonediff_h, zonediff_m;
    struct tm tm, *tm_ret;
    char *tz_origin;

    if (tz) {
        tz_origin = getenv("TZ");
        setenv("TZ", tz, 1);
        tm_ret = localtime_r(&time, &tm);
        setenv("TZ", tz_origin, 1);

        if (tm_ret == NULL) {
            return (NULL);
        }
    } else {
        if (gmtime_r(&time, &tm) == NULL) {
            return (NULL);
        }
    }

    if (tm.tm_isdst < 0) {
        zoneshift = NULL;
    } else {
        if (tm.tm_gmtoff == 0) {
            /* time is Zulu (UTC) */
            if (asprintf(&zoneshift, "Z") == -1) {
                ERR("asprintf() failed (%s:%d).", __FILE__, __LINE__);
                return (NULL);
            }
        } else {
            zonediff = tm.tm_gmtoff;
            zonediff_h = zonediff / 60 / 60;
            zonediff_m = zonediff / 60 % 60;
            if (asprintf(&zoneshift, "%s%02d:%02d", (zonediff < 0) ? "-" : "+", zonediff_h, zonediff_m) == -1) {
                ERR("asprintf() failed (%s:%d).", __FILE__, __LINE__);
                return (NULL);
            }
        }
    }
    if (asprintf(&date, "%04d-%02d-%02dT%02d:%02d:%02d%s",
                 tm.tm_year + 1900,
                 tm.tm_mon + 1,
                 tm.tm_mday,
                 tm.tm_hour,
                 tm.tm_min,
                 tm.tm_sec,
                 (zoneshift == NULL) ? "" : zoneshift) == -1) {
        free(zoneshift);
        ERR("asprintf() failed (%s:%d).", __FILE__, __LINE__);
        return (NULL);
    }
    free(zoneshift);

    return (date);
}
