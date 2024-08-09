/**
 * @file io.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 - input/output functions
 *
 * @copyright
 * Copyright (c) 2015 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE /* asprintf, signals */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "messages_p.h"
#include "netconf.h"
#include "session.h"
#include "session_p.h"
#include "session_wrapper.h"

const char *nc_msgtype2str[] = {
    "error",
    "would block",
    "no message",
    "hello message",
    "bad hello message",
    "RPC message",
    "rpc-reply message",
    "rpc-reply message with wrong ID",
    "notification message",
};

#define BUFFERSIZE 512

static ssize_t
nc_read(struct nc_session *session, char *buf, uint32_t count, uint32_t inact_timeout, struct timespec *ts_act_timeout)
{
    uint32_t readd = 0;
    ssize_t r = -1;
    int fd, interrupted;
    struct timespec ts_inact_timeout;

    assert(session);
    assert(buf);

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        return -1;
    }

    if (!count) {
        return 0;
    }

    nc_timeouttime_get(&ts_inact_timeout, inact_timeout);
    do {
        interrupted = 0;
        switch (session->ti_type) {
        case NC_TI_NONE:
            return 0;

        case NC_TI_FD:
        case NC_TI_UNIX:
            fd = (session->ti_type == NC_TI_FD) ? session->ti.fd.in : session->ti.unixsock.sock;
            /* read via standard file descriptor */
            r = read(fd, buf + readd, count - readd);
            if (r < 0) {
                if (errno == EAGAIN) {
                    r = 0;
                    break;
                } else if (errno == EINTR) {
                    r = 0;
                    interrupted = 1;
                    break;
                } else {
                    ERR(session, "Reading from file descriptor (%d) failed (%s).", fd, strerror(errno));
                    session->status = NC_STATUS_INVALID;
                    session->term_reason = NC_SESSION_TERM_OTHER;
                    return -1;
                }
            } else if (r == 0) {
                ERR(session, "Communication file descriptor (%d) unexpectedly closed.", fd);
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_DROPPED;
                return -1;
            }
            break;

#ifdef NC_ENABLED_SSH_TLS
        case NC_TI_SSH:
            /* read via libssh */
            r = ssh_channel_read(session->ti.libssh.channel, buf + readd, count - readd, 0);
            if (r == SSH_AGAIN) {
                r = 0;
                break;
            } else if (r == SSH_ERROR) {
                ERR(session, "Reading from the SSH channel failed (%s).", ssh_get_error(session->ti.libssh.session));
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_OTHER;
                return -1;
            } else if (r == 0) {
                if (ssh_channel_is_eof(session->ti.libssh.channel)) {
                    ERR(session, "SSH channel unexpected EOF.");
                    session->status = NC_STATUS_INVALID;
                    session->term_reason = NC_SESSION_TERM_DROPPED;
                    return -1;
                }
                break;
            }
            break;

        case NC_TI_TLS:
            r = nc_tls_read_wrap(session, (unsigned char *)buf + readd, count - readd);
            if (r < 0) {
                /* non-recoverable error */
                return r;
            }
            break;
#endif /* NC_ENABLED_SSH_TLS */
        }

        if (r == 0) {
            /* nothing read */
            if (!interrupted) {
                usleep(NC_TIMEOUT_STEP);
            }
            if ((nc_timeouttime_cur_diff(&ts_inact_timeout) < 1) || (nc_timeouttime_cur_diff(ts_act_timeout) < 1)) {
                if (nc_timeouttime_cur_diff(&ts_inact_timeout) < 1) {
                    ERR(session, "Inactive read timeout elapsed.");
                } else {
                    ERR(session, "Active read timeout elapsed.");
                }
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_OTHER;
                return -1;
            }
        } else {
            /* something read */
            readd += r;

            /* reset inactive timeout */
            nc_timeouttime_get(&ts_inact_timeout, inact_timeout);
        }

    } while (readd < count);
    buf[count] = '\0';

    return (ssize_t)readd;
}

static ssize_t
nc_read_chunk(struct nc_session *session, size_t len, uint32_t inact_timeout, struct timespec *ts_act_timeout, char **chunk)
{
    ssize_t r;

    assert(session);
    assert(chunk);

    if (!len) {
        return 0;
    }

    *chunk = malloc((len + 1) * sizeof **chunk);
    NC_CHECK_ERRMEM_RET(!*chunk, -1);

    r = nc_read(session, *chunk, len, inact_timeout, ts_act_timeout);
    if (r <= 0) {
        free(*chunk);
        return -1;
    }

    /* terminating null byte */
    (*chunk)[r] = 0;

    return r;
}

static ssize_t
nc_read_until(struct nc_session *session, const char *endtag, size_t limit, uint32_t inact_timeout,
        struct timespec *ts_act_timeout, char **result)
{
    char *chunk = NULL;
    size_t size, count = 0, r, len, i, matched = 0;

    assert(session);
    assert(endtag);

    if (limit && (limit < BUFFERSIZE)) {
        size = limit;
    } else {
        size = BUFFERSIZE;
    }
    chunk = malloc((size + 1) * sizeof *chunk);
    NC_CHECK_ERRMEM_RET(!chunk, -1);

    len = strlen(endtag);
    while (1) {
        if (limit && (count == limit)) {
            free(chunk);
            WRN(session, "Reading limit (%d) reached.", limit);
            ERR(session, "Invalid input data (missing \"%s\" sequence).", endtag);
            return -1;
        }

        /* resize buffer if needed */
        if ((count + (len - matched)) >= size) {
            /* get more memory */
            size = size + BUFFERSIZE;
            chunk = nc_realloc(chunk, (size + 1) * sizeof *chunk);
            NC_CHECK_ERRMEM_RET(!chunk, -1);
        }

        /* get another character */
        r = nc_read(session, &(chunk[count]), len - matched, inact_timeout, ts_act_timeout);
        if (r != len - matched) {
            free(chunk);
            return -1;
        }

        count += len - matched;

        for (i = len - matched; i > 0; i--) {
            if (!strncmp(&endtag[matched], &(chunk[count - i]), i)) {
                /*part of endtag found */
                matched += i;
                break;
            } else {
                matched = 0;
            }
        }

        /* whole endtag found */
        if (matched == len) {
            break;
        }
    }

    /* terminating null byte */
    chunk[count] = 0;

    if (result) {
        *result = chunk;
    } else {
        free(chunk);
    }
    return count;
}

int
nc_read_msg_io(struct nc_session *session, int io_timeout, struct ly_in **msg, int passing_io_lock)
{
    int ret = 1, r, io_locked = passing_io_lock;
    char *data = NULL, *chunk;
    uint64_t chunk_len, len = 0;
    /* use timeout in milliseconds instead seconds */
    uint32_t inact_timeout = NC_READ_INACT_TIMEOUT * 1000;
    struct timespec ts_act_timeout;

    assert(session && msg);
    *msg = NULL;

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR(session, "Invalid session to read from.");
        ret = -1;
        goto cleanup;
    }

    nc_timeouttime_get(&ts_act_timeout, NC_READ_ACT_TIMEOUT * 1000);

    if (!io_locked) {
        /* SESSION IO LOCK */
        ret = nc_session_io_lock(session, io_timeout, __func__);
        if (ret < 1) {
            goto cleanup;
        }
        io_locked = 1;
    }

    /* read the message */
    switch (session->version) {
    case NC_VERSION_10:
        r = nc_read_until(session, NC_VERSION_10_ENDTAG, 0, inact_timeout, &ts_act_timeout, &data);
        if (r == -1) {
            ret = r;
            goto cleanup;
        }

        /* cut off the end tag */
        data[r - NC_VERSION_10_ENDTAG_LEN] = '\0';
        break;
    case NC_VERSION_11:
        while (1) {
            r = nc_read_until(session, "\n#", 0, inact_timeout, &ts_act_timeout, NULL);
            if (r == -1) {
                ret = r;
                goto cleanup;
            }
            r = nc_read_until(session, "\n", 0, inact_timeout, &ts_act_timeout, &chunk);
            if (r == -1) {
                ret = r;
                goto cleanup;
            }

            if (!strcmp(chunk, "#\n")) {
                /* end of chunked framing message */
                free(chunk);
                if (!data) {
                    ERR(session, "Invalid frame chunk delimiters.");
                    ret = -2;
                    goto cleanup;
                }
                break;
            }

            /* convert string to the size of the following chunk */
            chunk_len = strtoul(chunk, (char **)NULL, 10);
            free(chunk);
            if (!chunk_len) {
                ERR(session, "Invalid frame chunk size detected, fatal error.");
                ret = -2;
                goto cleanup;
            }

            /* now we have size of next chunk, so read the chunk */
            r = nc_read_chunk(session, chunk_len, inact_timeout, &ts_act_timeout, &chunk);
            if (r == -1) {
                ret = r;
                goto cleanup;
            }

            /* realloc message buffer, remember to count terminating null byte */
            data = nc_realloc(data, len + chunk_len + 1);
            NC_CHECK_ERRMEM_GOTO(!data, ret = -1, cleanup);
            memcpy(data + len, chunk, chunk_len);
            len += chunk_len;
            data[len] = '\0';
            free(chunk);
        }

        break;
    }

    /* SESSION IO UNLOCK */
    assert(io_locked);
    nc_session_io_unlock(session, __func__);
    io_locked = 0;

    DBG(session, "Received message:\n%s\n", data);

    /* build an input structure, eats data */
    if (ly_in_new_memory(data, msg)) {
        ret = -1;
        goto cleanup;
    }
    data = NULL;

cleanup:
    if (io_locked) {
        /* SESSION IO UNLOCK */
        nc_session_io_unlock(session, __func__);
    }
    free(data);
    return ret;
}

/* return -1 means either poll error or that session was invalidated (socket error), EINTR is handled inside */
static int
nc_read_poll(struct nc_session *session, int io_timeout)
{
    int ret = -2;
    struct pollfd fds;

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR(session, "Invalid session to poll.");
        return -1;
    }

    switch (session->ti_type) {
#ifdef NC_ENABLED_SSH_TLS
    case NC_TI_SSH:
        if (io_timeout == -1) {
            /* BUG libssh 0.11.0 replaces timeout -1 with 0 for non-blocking sessions */
            io_timeout = INT_MAX;
        }

        /* EINTR is handled, it resumes waiting */
        ret = ssh_channel_poll_timeout(session->ti.libssh.channel, io_timeout, 0);
        if (ret == SSH_ERROR) {
            ERR(session, "SSH channel poll error (%s).", ssh_get_error(session->ti.libssh.session));
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_OTHER;
            return -1;
        } else if (ret == SSH_EOF) {
            ERR(session, "SSH channel unexpected EOF.");
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_DROPPED;
            return -1;
        } else if (ret > 0) {
            /* fake it */
            ret = 1;
            fds.revents = POLLIN;
        } else { /* ret == 0 */
            fds.revents = 0;
        }
        break;
    case NC_TI_TLS:
        ret = nc_tls_get_num_pending_bytes_wrap(session->ti.tls.session);
        if (ret) {
            /* some buffered TLS data available */
            ret = 1;
            fds.revents = POLLIN;
            break;
        }

        fds.fd = nc_tls_get_fd_wrap(session);
#endif /* NC_ENABLED_SSH_TLS */
    /* fallthrough */
    case NC_TI_FD:
    case NC_TI_UNIX:
        if (session->ti_type == NC_TI_FD) {
            fds.fd = session->ti.fd.in;
        } else if (session->ti_type == NC_TI_UNIX) {
            fds.fd = session->ti.unixsock.sock;
        }

        fds.events = POLLIN;
        fds.revents = 0;

        ret = nc_poll(&fds, 1, io_timeout);
        break;

    default:
        ERRINT;
        return -1;
    }

    /* process the poll result, unified ret meaning for poll and ssh_channel poll */
    if (ret < 0) {
        /* poll failed - something really bad happened, close the session */
        ERR(session, "poll error (%s).", strerror(errno));
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_OTHER;
        return -1;
    } else { /* status > 0 */
        /* in case of standard (non-libssh) poll, there still can be an error */
        if (fds.revents & POLLERR) {
            ERR(session, "Communication channel error.");
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_OTHER;
            return -1;
        }
        /* Some poll() implementations may return POLLHUP|POLLIN when the other
         * side has closed but there is data left to read in the buffer. */
        if ((fds.revents & POLLHUP) && !(fds.revents & POLLIN)) {
            ERR(session, "Communication channel unexpectedly closed.");
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_DROPPED;
            return -1;
        }
    }

    return ret;
}

int
nc_read_msg_poll_io(struct nc_session *session, int io_timeout, struct ly_in **msg)
{
    int ret;

    assert(msg);
    *msg = NULL;

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR(session, "Invalid session to read from.");
        return -1;
    }

    /* SESSION IO LOCK */
    ret = nc_session_io_lock(session, io_timeout, __func__);
    if (ret < 1) {
        return ret;
    }

    ret = nc_read_poll(session, io_timeout);
    if (ret < 1) {
        /* timed out or error */

        /* SESSION IO UNLOCK */
        nc_session_io_unlock(session, __func__);
        return ret;
    }

    /* SESSION IO LOCK passed down */
    return nc_read_msg_io(session, io_timeout, msg, 1);
}

/* does not really log, only fatal errors */
int
nc_session_is_connected(const struct nc_session *session)
{
    int ret;
    struct pollfd fds;

    switch (session->ti_type) {
    case NC_TI_FD:
        fds.fd = session->ti.fd.in;
        break;
    case NC_TI_UNIX:
        fds.fd = session->ti.unixsock.sock;
        break;
#ifdef NC_ENABLED_SSH_TLS
    case NC_TI_SSH:
        return ssh_is_connected(session->ti.libssh.session);
    case NC_TI_TLS:
        fds.fd = nc_tls_get_fd_wrap(session);
        break;
#endif /* NC_ENABLED_SSH_TLS */
    default:
        return 0;
    }

    if (fds.fd == -1) {
        return 0;
    }

    fds.events = POLLIN;
    fds.revents = 0;

    ret = nc_poll(&fds, 1, 0);
    if (ret == -1) {
        return 0;
    } else if ((ret > 0) && (fds.revents & (POLLHUP | POLLERR))) {
        return 0;
    }

    return 1;
}

#define WRITE_BUFSIZE (2 * BUFFERSIZE)
struct nc_wclb_arg {
    struct nc_session *session;
    char buf[WRITE_BUFSIZE];
    uint32_t len;
};

/**
 * @brief Write to a NETCONF session.
 *
 * @param[in] session Session to write to.
 * @param[in] buf Buffer to write.
 * @param[in] count Count of bytes from @p buf to write.
 * @return Number of bytes written.
 * @return -1 on error.
 */
static int
nc_write(struct nc_session *session, const void *buf, uint32_t count)
{
    int c, fd, interrupted;
    uint32_t written = 0;

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        return -1;
    }

    /* prevent SIGPIPE this way */
    if (!nc_session_is_connected(session)) {
        ERR(session, "Communication socket unexpectedly closed.");
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_DROPPED;
        return -1;
    }

    DBG(session, "Sending message:\n%.*s\n", (int)count, buf);

    do {
        interrupted = 0;
        switch (session->ti_type) {
        case NC_TI_FD:
        case NC_TI_UNIX:
            fd = session->ti_type == NC_TI_FD ? session->ti.fd.out : session->ti.unixsock.sock;
            c = write(fd, (char *)(buf + written), count - written);
            if ((c < 0) && (errno == EAGAIN)) {
                c = 0;
            } else if ((c < 0) && (errno == EINTR)) {
                c = 0;
                interrupted = 1;
            } else if (c < 0) {
                ERR(session, "Socket error (%s).", strerror(errno));
                return -1;
            }
            break;

#ifdef NC_ENABLED_SSH_TLS
        case NC_TI_SSH:
            if (ssh_channel_is_closed(session->ti.libssh.channel) || ssh_channel_is_eof(session->ti.libssh.channel)) {
                if (ssh_channel_is_closed(session->ti.libssh.channel)) {
                    ERR(session, "SSH channel unexpectedly closed.");
                } else {
                    ERR(session, "SSH channel unexpected EOF.");
                }
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_DROPPED;
                return -1;
            }
            c = ssh_channel_write(session->ti.libssh.channel, (char *)(buf + written), count - written);
            if ((c == SSH_ERROR) || (c == -1)) {
                ERR(session, "SSH channel write failed.");
                return -1;
            }
            break;
        case NC_TI_TLS:
            c = nc_tls_write_wrap(session, (const unsigned char *)(buf + written), count - written);
            if (c < 0) {
                /* possible client dc, or some socket/TLS communication error */
                return -1;
            }
            break;
#endif /* NC_ENABLED_SSH_TLS */
        default:
            ERRINT;
            return -1;
        }

        if ((c == 0) && !interrupted) {
            /* we must wait */
            usleep(NC_TIMEOUT_STEP);
        }

        written += c;
    } while (written < count);

    return written;
}

/**
 * @brief Write the start tag and the message part of a chunked-framing NETCONF message.
 *
 * @param[in] session Session to write to.
 * @param[in] buf Message buffer to write.
 * @param[in] count Count of bytes from @p buf to write.
 * @return Number of bytes written.
 * @return -1 on error.
 */
static int
nc_write_starttag_and_msg(struct nc_session *session, const void *buf, uint32_t count)
{
    int ret = 0, r;
    char chunksize[24];

    if (session->version == NC_VERSION_11) {
        r = sprintf(chunksize, "\n#%" PRIu32 "\n", count);

        r = nc_write(session, chunksize, r);
        if (r == -1) {
            return -1;
        }
        ret += r;
    }

    r = nc_write(session, buf, count);
    if (r == -1) {
        return -1;
    }
    ret += r;

    return ret;
}

/**
 * @brief Write the end tag part of a chunked-framing NETCONF message.
 *
 * @param[in] session Session to write to.
 * @return Number of bytes written.
 * @return -1 on error.
 */
static int
nc_write_endtag(struct nc_session *session)
{
    int ret;

    if (session->version == NC_VERSION_11) {
        ret = nc_write(session, "\n##\n", 4);
    } else {
        ret = nc_write(session, "]]>]]>", 6);
    }

    return ret;
}

/**
 * @brief Flush all the data buffered for writing.
 *
 * @param[in] warg Write callback structure to flush.
 * @return Number of written bytes.
 * @return -1 on error.
 */
static int
nc_write_clb_flush(struct nc_wclb_arg *warg)
{
    int ret = 0;

    /* flush current buffer */
    if (warg->len) {
        ret = nc_write_starttag_and_msg(warg->session, warg->buf, warg->len);
        warg->len = 0;
    }

    return ret;
}

/**
 * @brief Write callback buffering the data in a write structure.
 *
 * @param[in] arg Write structure used for buffering.
 * @param[in] buf Buffer to write.
 * @param[in] count Count of bytes to write from @p buf.
 * @param[in] xmlcontent Whether the data are actually printed as part of an XML in which case they need to be encoded.
 * @return Number of written bytes.
 * @return -1 on error.
 */
static ssize_t
nc_write_clb(void *arg, const void *buf, uint32_t count, int xmlcontent)
{
    ssize_t ret = 0, c;
    uint32_t l;
    struct nc_wclb_arg *warg = arg;

    if (!buf) {
        c = nc_write_clb_flush(warg);
        if (c == -1) {
            return -1;
        }
        ret += c;

        /* endtag */
        c = nc_write_endtag(warg->session);
        if (c == -1) {
            return -1;
        }
        ret += c;

        return ret;
    }

    if (warg->len && (warg->len + count > WRITE_BUFSIZE)) {
        /* dump current buffer */
        c = nc_write_clb_flush(warg);
        if (c == -1) {
            return -1;
        }
        ret += c;
    }

    if (!xmlcontent && (count > WRITE_BUFSIZE)) {
        /* write directly */
        c = nc_write_starttag_and_msg(warg->session, buf, count);
        if (c == -1) {
            return -1;
        }
        ret += c;
    } else {
        /* keep in buffer and write later */
        if (xmlcontent) {
            for (l = 0; l < count; l++) {
                if (warg->len + 5 >= WRITE_BUFSIZE) {
                    /* buffer is full */
                    c = nc_write_clb_flush(warg);
                    if (c == -1) {
                        return -1;
                    }
                }

                switch (((char *)buf)[l]) {
                case '&':
                    ret += 5;
                    memcpy(&warg->buf[warg->len], "&amp;", 5);
                    warg->len += 5;
                    break;
                case '<':
                    ret += 4;
                    memcpy(&warg->buf[warg->len], "&lt;", 4);
                    warg->len += 4;
                    break;
                case '>':
                    /* not needed, just for readability */
                    ret += 4;
                    memcpy(&warg->buf[warg->len], "&gt;", 4);
                    warg->len += 4;
                    break;
                default:
                    ret++;
                    memcpy(&warg->buf[warg->len], &((char *)buf)[l], 1);
                    warg->len++;
                }
            }
        } else {
            memcpy(&warg->buf[warg->len], buf, count);
            warg->len += count; /* is <= WRITE_BUFSIZE */
            ret += count;
        }
    }

    return ret;
}

/**
 * @brief Write print callback used by libyang.
 */
static ssize_t
nc_write_xmlclb(void *arg, const void *buf, size_t count)
{
    ssize_t r;

    r = nc_write_clb(arg, buf, count, 0);
    if (r == -1) {
        return -1;
    }

    /* always return what libyang expects, simply that all the characters were printed */
    return count;
}

/* return NC_MSG_ERROR can change session status, acquires IO lock as needed */
NC_MSG_TYPE
nc_write_msg_io(struct nc_session *session, int io_timeout, int type, ...)
{
    va_list ap;
    int count, ret;
    const char *attrs, *str;
    struct lyd_node *op, *reply_envp, *node, *next;
    struct lyd_node_opaq *rpc_envp;
    struct nc_server_notif *notif;
    struct nc_server_reply *reply;
    char *buf;
    struct nc_wclb_arg arg;
    const char **capabilities;
    uint32_t *sid = NULL, i, wd = 0;
    LY_ERR lyrc;

    assert(session);

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR(session, "Invalid session to write to.");
        return NC_MSG_ERROR;
    }

    arg.session = session;
    arg.len = 0;

    /* SESSION IO LOCK */
    ret = nc_session_io_lock(session, io_timeout, __func__);
    if (ret < 0) {
        return NC_MSG_ERROR;
    } else if (!ret) {
        return NC_MSG_WOULDBLOCK;
    }

    va_start(ap, type);

    switch (type) {
    case NC_MSG_RPC:
        op = va_arg(ap, struct lyd_node *);
        attrs = va_arg(ap, const char *);

        /* <rpc> open */
        count = asprintf(&buf, "<rpc xmlns=\"%s\" message-id=\"%" PRIu64 "\"%s>",
                NC_NS_BASE, session->opts.client.msgid + 1, attrs ? attrs : "");
        NC_CHECK_ERRMEM_GOTO(count == -1, ret = NC_MSG_ERROR, cleanup);
        nc_write_clb((void *)&arg, buf, count, 0);
        free(buf);

        if (op->schema && (op->schema->nodetype & (LYS_CONTAINER | LYS_LIST))) {
            /* <action> open */
            str = "<action xmlns=\"urn:ietf:params:xml:ns:yang:1\">";
            nc_write_clb((void *)&arg, str, strlen(str), 0);
        }

        /* rpc data */
        if (lyd_print_clb(nc_write_xmlclb, (void *)&arg, op, LYD_XML, LYD_PRINT_SHRINK | LYD_PRINT_KEEPEMPTYCONT)) {
            ret = NC_MSG_ERROR;
            goto cleanup;
        }

        if (op->schema && (op->schema->nodetype & (LYS_CONTAINER | LYS_LIST))) {
            /* <action> close */
            str = "</action>";
            nc_write_clb((void *)&arg, str, strlen(str), 0);
        }

        /* <rpc> close */
        str = "</rpc>";
        nc_write_clb((void *)&arg, str, strlen(str), 0);

        session->opts.client.msgid++;
        break;

    case NC_MSG_REPLY:
        rpc_envp = va_arg(ap, struct lyd_node_opaq *);
        reply = va_arg(ap, struct nc_server_reply *);

        /* build a rpc-reply opaque node that can be simply printed */
        if (rpc_envp) {
            if (lyd_new_opaq2(NULL, session->ctx, "rpc-reply", NULL, rpc_envp->name.prefix, rpc_envp->name.module_ns,
                    &reply_envp)) {
                ERRINT;
                ret = NC_MSG_ERROR;
                goto cleanup;
            }
        } else {
            if (lyd_new_opaq2(NULL, session->ctx, "rpc-reply", NULL, NULL, NC_NS_BASE,
                    &reply_envp)) {
                ERRINT;
                ret = NC_MSG_ERROR;
                goto cleanup;
            }
        }

        switch (reply->type) {
        case NC_RPL_OK:
            if (lyd_new_opaq2(reply_envp, NULL, "ok", NULL, rpc_envp->name.prefix, rpc_envp->name.module_ns, NULL)) {
                lyd_free_tree(reply_envp);

                ERRINT;
                ret = NC_MSG_ERROR;
                goto cleanup;
            }
            break;
        case NC_RPL_DATA:
            switch (((struct nc_server_reply_data *)reply)->wd) {
            case NC_WD_UNKNOWN:
            case NC_WD_EXPLICIT:
                wd = LYD_PRINT_WD_EXPLICIT;
                break;
            case NC_WD_TRIM:
                wd = LYD_PRINT_WD_TRIM;
                break;
            case NC_WD_ALL:
                wd = LYD_PRINT_WD_ALL;
                break;
            case NC_WD_ALL_TAG:
                wd = LYD_PRINT_WD_ALL_TAG;
                break;
            }

            node = ((struct nc_server_reply_data *)reply)->data;
            assert(node->schema->nodetype & (LYS_RPC | LYS_ACTION));
            LY_LIST_FOR_SAFE(lyd_child(node), next, node) {
                /* temporary */
                lyd_insert_child(reply_envp, node);
            }
            break;
        case NC_RPL_ERROR:
            /* temporary */
            lyd_insert_child(reply_envp, ((struct nc_server_reply_error *)reply)->err);
            break;
        default:
            ERRINT;
            nc_write_clb((void *)&arg, NULL, 0, 0);
            ret = NC_MSG_ERROR;
            goto cleanup;
        }

        /* temporary */
        if (rpc_envp) {
            ((struct lyd_node_opaq *)reply_envp)->attr = rpc_envp->attr;
        }

        /* print */
        lyrc = lyd_print_clb(nc_write_xmlclb, (void *)&arg, reply_envp, LYD_XML, LYD_PRINT_SHRINK | wd);
        ((struct lyd_node_opaq *)reply_envp)->attr = NULL;

        /* cleanup */
        switch (reply->type) {
        case NC_RPL_OK:
            /* just free everything */
            lyd_free_tree(reply_envp);
            break;
        case NC_RPL_DATA:
            LY_LIST_FOR_SAFE(lyd_child(reply_envp), next, node) {
                /* connect back to the reply structure */
                lyd_insert_child(((struct nc_server_reply_data *)reply)->data, node);
            }
            lyd_free_tree(reply_envp);
            break;
        case NC_RPL_ERROR:
            /* unlink from the data reply */
            lyd_unlink_tree(lyd_child(reply_envp));
            lyd_free_tree(reply_envp);
            break;
        default:
            break;
        }

        if (lyrc) {
            ret = NC_MSG_ERROR;
            goto cleanup;
        }
        break;

    case NC_MSG_NOTIF:
        notif = va_arg(ap, struct nc_server_notif *);

        nc_write_clb((void *)&arg, "<notification xmlns=\""NC_NS_NOTIF "\">", 21 + 47 + 2, 0);
        nc_write_clb((void *)&arg, "<eventTime>", 11, 0);
        nc_write_clb((void *)&arg, notif->eventtime, strlen(notif->eventtime), 0);
        nc_write_clb((void *)&arg, "</eventTime>", 12, 0);
        if (lyd_print_clb(nc_write_xmlclb, (void *)&arg, notif->ntf, LYD_XML, LYD_PRINT_SHRINK)) {
            ret = NC_MSG_ERROR;
            goto cleanup;
        }
        nc_write_clb((void *)&arg, "</notification>", 15, 0);
        break;

    case NC_MSG_HELLO:
        if (session->version != NC_VERSION_10) {
            ret = NC_MSG_ERROR;
            goto cleanup;
        }
        capabilities = va_arg(ap, const char **);
        sid = va_arg(ap, uint32_t *);

        count = asprintf(&buf, "<hello xmlns=\"%s\"><capabilities>", NC_NS_BASE);
        NC_CHECK_ERRMEM_GOTO(count == -1, ret = NC_MSG_ERROR, cleanup);
        nc_write_clb((void *)&arg, buf, count, 0);
        free(buf);
        for (i = 0; capabilities[i]; i++) {
            nc_write_clb((void *)&arg, "<capability>", 12, 0);
            nc_write_clb((void *)&arg, capabilities[i], strlen(capabilities[i]), 1);
            nc_write_clb((void *)&arg, "</capability>", 13, 0);
        }
        if (sid) {
            count = asprintf(&buf, "</capabilities><session-id>%" PRIu32 "</session-id></hello>", *sid);
            NC_CHECK_ERRMEM_GOTO(count == -1, ret = NC_MSG_ERROR, cleanup);
            nc_write_clb((void *)&arg, buf, count, 0);
            free(buf);
        } else {
            nc_write_clb((void *)&arg, "</capabilities></hello>", 23, 0);
        }
        break;

    default:
        ret = NC_MSG_ERROR;
        goto cleanup;
    }

    /* flush message */
    nc_write_clb((void *)&arg, NULL, 0, 0);

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        /* error was already written */
        ret = NC_MSG_ERROR;
    } else {
        /* specific message successfully sent */
        ret = type;
    }

cleanup:
    va_end(ap);
    nc_session_io_unlock(session, __func__);
    return ret;
}

void *
nc_realloc(void *ptr, size_t size)
{
    void *ret;

    ret = realloc(ptr, size);
    if (!ret) {
        free(ptr);
    }

    return ret;
}

struct passwd *
nc_getpw(uid_t uid, const char *username, struct passwd *pwd_buf, char **buf, size_t *buf_size)
{
    struct passwd *pwd = NULL;
    long sys_size;
    int ret;

    do {
        if (!*buf_size) {
            /* learn suitable buffer size */
            sys_size = sysconf(_SC_GETPW_R_SIZE_MAX);
            *buf_size = (sys_size == -1) ? 2048 : sys_size;
        } else {
            /* enlarge buffer */
            *buf_size += 2048;
        }

        /* allocate some buffer */
        *buf = nc_realloc(*buf, *buf_size);
        NC_CHECK_ERRMEM_RET(!*buf, NULL);

        if (username) {
            ret = getpwnam_r(username, pwd_buf, *buf, *buf_size, &pwd);
        } else {
            ret = getpwuid_r(uid, pwd_buf, *buf, *buf_size, &pwd);
        }
    } while (ret && (ret == ERANGE));

    if (ret) {
        if (username) {
            ERR(NULL, "Retrieving username \"%s\" passwd entry failed (%s).", username, strerror(ret));
        } else {
            ERR(NULL, "Retrieving UID \"%lu\" passwd entry failed (%s).", (unsigned long)uid, strerror(ret));
        }
    }
    return pwd;
}
