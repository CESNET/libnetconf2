/**
 * @file proxy_unix.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 UNIX proxy functions
 *
 * @copyright
 * Copyright (c) 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include "proxy_unix.h"

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "session_p.h"

API int
nc_proxy_unix_connect(const char *address, const char *username)
{
    struct sockaddr_un sun;
    struct passwd *pw, pw_buf;
    int sock = -1;
    char *buf = NULL;
    size_t buf_size = 0;

    /* connect to the UNIX socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        ERR(NULL, "Failed to create socket (%s).", strerror(errno));
        goto error;
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", address);

    if (connect(sock, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
        ERR(NULL, "Cannot connect to sock server %s (%s)", address, strerror(errno));
        goto error;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
        ERR(NULL, "fcntl failed (%s).", strerror(errno));
        goto error;
    }

    /* NETCONF username */
    if (!username) {
        pw = nc_getpw(geteuid(), NULL, &pw_buf, &buf, &buf_size);
        if (!pw) {
            ERR(NULL, "Failed to find username for UID %u.", (unsigned int)geteuid());
            goto error;
        }
        username = pw->pw_name;
    }

    /* connect UNIX session */
    if (nc_connect_unix_session(NULL, sock, username) != 1) {
        goto error;
    }

    free(buf);
    return sock;

error:
    if (sock > -1) {
        close(sock);
    }
    free(buf);
    return -1;
}

API int
nc_proxy_read_msg(int fd, NC_PROT_VERSION version, int timeout_ms, char **buf, uint32_t *buf_len)
{
    int r;
    struct pollfd fds;
    struct nc_session sess = {0};

    /* poll */
    fds.fd = fd;
    fds.events = POLLIN;
    fds.revents = 0;

    r = nc_poll(&fds, 1, timeout_ms);
    if (r < 0) {
        /* error */
        ERR(NULL, "poll error (%s).", strerror(errno));
        return -1;
    } else if (r == 0) {
        /* timeout */
        return 0;
    } else {
        /* socket error */
        if (fds.revents & POLLERR) {
            ERR(NULL, "Communication channel error.");
            return -1;
        }

        /* some poll() implementations may return POLLHUP|POLLIN when the other
         * side has closed but there is data left to read in the buffer */
        if ((fds.revents & POLLHUP) && !(fds.revents & POLLIN)) {
            ERR(NULL, "Communication channel unexpectedly closed.");
            return -1;
        }
    }

    /* fill dummy session (id 0 causes session not to be included in log messages) */
    NC_SESSION_STATUS_SET(&sess, NC_STATUS_RUNNING);
    sess.version = version;
    sess.ti_type = NC_TI_UNIX;
    sess.ti.unixsock.sock = fd;

    /* read a message */
    r = nc_read_msg_io(&sess, 0, 1, buf, buf_len);
    switch (r) {
    case -2:
        ERR(NULL, "Malformed message received.");
        return -1;
    case -1:
        /* error printed */
        return -1;
    case 0:
        /* timeout */
        return 0;
    default:
        /* success */
        break;
    }

    return r;
}

API int
nc_proxy_write_msg(int fd, NC_PROT_VERSION version, const char *buf, uint32_t buf_len)
{
    struct nc_session sess = {0};
    struct nc_wclb_arg warg = {.session = &sess};

    /* fill dummy session (id 0 causes session not to be included in log messages) */
    NC_SESSION_STATUS_SET(&sess, NC_STATUS_RUNNING);
    sess.version = version;
    sess.ti_type = NC_TI_UNIX;
    sess.ti.unixsock.sock = fd;

    /* write the whole message */
    if (nc_write_clb(&warg, buf, buf_len, 0) == -1) {
        return -1;
    }

    /* flush buffer writing the final end tag */
    if (nc_write_clb(&warg, NULL, 0, 0) == -1) {
        return -1;
    }

    return buf_len;
}

API int
nc_proxy_unix_close(int fd)
{
    if (fd < 0) {
        return 0;
    }

    /* just close the socket */
    return close(fd);
}
