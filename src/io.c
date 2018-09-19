/**
 * \file io.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 - input/output functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
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
#include <poll.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#ifdef NC_ENABLED_TLS
#   include <openssl/err.h>
#endif

#include <libyang/libyang.h>

#include "libnetconf.h"

#define BUFFERSIZE 512

static ssize_t
nc_read(struct nc_session *session, char *buf, size_t count, uint32_t inact_timeout, struct timespec *ts_act_timeout)
{
    size_t readd = 0;
    ssize_t r = -1;
    struct timespec ts_cur, ts_inact_timeout;

    assert(session);
    assert(buf);

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        return -1;
    }

    if (!count) {
        return 0;
    }

    nc_gettimespec_mono(&ts_inact_timeout);
    nc_addtimespec(&ts_inact_timeout, inact_timeout);
    do {
        switch (session->ti_type) {
        case NC_TI_NONE:
            return 0;

        case NC_TI_FD:
            /* read via standard file descriptor */
            r = read(session->ti.fd.in, buf + readd, count - readd);
            if (r < 0) {
                if ((errno == EAGAIN) || (errno == EINTR)) {
                    r = 0;
                    break;
                } else {
                    ERR("Session %u: reading from file descriptor (%d) failed (%s).",
                        session->id, session->ti.fd.in, strerror(errno));
                    session->status = NC_STATUS_INVALID;
                    session->term_reason = NC_SESSION_TERM_OTHER;
                    return -1;
                }
            } else if (r == 0) {
                ERR("Session %u: communication file descriptor (%d) unexpectedly closed.",
                    session->id, session->ti.fd.in);
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_DROPPED;
                return -1;
            }
            break;

#ifdef NC_ENABLED_SSH
        case NC_TI_LIBSSH:
            /* read via libssh */
            r = ssh_channel_read(session->ti.libssh.channel, buf + readd, count - readd, 0);
            if (r == SSH_AGAIN) {
                r = 0;
                break;
            } else if (r == SSH_ERROR) {
                ERR("Session %u: reading from the SSH channel failed (%s).", session->id,
                    ssh_get_error(session->ti.libssh.session));
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_OTHER;
                return -1;
            } else if (r == 0) {
                if (ssh_channel_is_eof(session->ti.libssh.channel)) {
                    ERR("Session %u: SSH channel unexpected EOF.", session->id);
                    session->status = NC_STATUS_INVALID;
                    session->term_reason = NC_SESSION_TERM_DROPPED;
                    return -1;
                }
                break;
            }
            break;
#endif

#ifdef NC_ENABLED_TLS
        case NC_TI_OPENSSL:
            /* read via OpenSSL */
            r = SSL_read(session->ti.tls, buf + readd, count - readd);
            if (r <= 0) {
                int x;
                switch (x = SSL_get_error(session->ti.tls, r)) {
                case SSL_ERROR_WANT_READ:
                    r = 0;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    ERR("Session %u: communication socket unexpectedly closed (OpenSSL).", session->id);
                    session->status = NC_STATUS_INVALID;
                    session->term_reason = NC_SESSION_TERM_DROPPED;
                    return -1;
                default:
                    ERR("Session %u: reading from the TLS session failed (SSL code %d).", session->id, x);
                    session->status = NC_STATUS_INVALID;
                    session->term_reason = NC_SESSION_TERM_OTHER;
                    return -1;
                }
            }
            break;
#endif
        }

        if (r == 0) {
            /* nothing read */
            usleep(NC_TIMEOUT_STEP);
            nc_gettimespec_mono(&ts_cur);
            if ((nc_difftimespec(&ts_cur, &ts_inact_timeout) < 1) || (nc_difftimespec(&ts_cur, ts_act_timeout) < 1)) {
                if (nc_difftimespec(&ts_cur, &ts_inact_timeout) < 1) {
                    ERR("Session %u: inactive read timeout elapsed.", session->id);
                } else {
                    ERR("Session %u: active read timeout elapsed.", session->id);
                }
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_OTHER;
                return -1;
            }
        } else {
            /* something read */
            readd += r;

            /* reset inactive timeout */
            nc_gettimespec_mono(&ts_inact_timeout);
            nc_addtimespec(&ts_inact_timeout, inact_timeout);
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
    if (!*chunk) {
        ERRMEM;
        return -1;
    }

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

    if (limit && limit < BUFFERSIZE) {
        size = limit;
    } else {
        size = BUFFERSIZE;
    }
    chunk = malloc((size + 1) * sizeof *chunk);
    if (!chunk) {
        ERRMEM;
        return -1;
    }

    len = strlen(endtag);
    while (1) {
        if (limit && count == limit) {
            free(chunk);
            WRN("Session %u: reading limit (%d) reached.", session->id, limit);
            ERR("Session %u: invalid input data (missing \"%s\" sequence).", session->id, endtag);
            return -1;
        }

        /* resize buffer if needed */
        if ((count + (len - matched)) >= size) {
            /* get more memory */
            size = size + BUFFERSIZE;
            chunk = nc_realloc(chunk, (size + 1) * sizeof *chunk);
            if (!chunk) {
                ERRMEM;
                return -1;
            }
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

/* return NC_MSG_ERROR can change session status, acquires IO lock as needed */
NC_MSG_TYPE
nc_read_msg_io(struct nc_session *session, int io_timeout, struct lyxml_elem **data, int passing_io_lock)
{
    int ret, io_locked = passing_io_lock;
    char *msg = NULL, *chunk;
    uint64_t chunk_len, len = 0;
    /* use timeout in milliseconds instead seconds */
    uint32_t inact_timeout = NC_READ_INACT_TIMEOUT * 1000;
    struct timespec ts_act_timeout;
    struct nc_server_reply *reply;

    assert(session && data);
    *data = NULL;

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR("Session %u: invalid session to read from.", session->id);
        ret = NC_MSG_ERROR;
        goto cleanup;
    }

    nc_gettimespec_mono(&ts_act_timeout);
    nc_addtimespec(&ts_act_timeout, NC_READ_ACT_TIMEOUT * 1000);

    if (!io_locked) {
        /* SESSION IO LOCK */
        ret = nc_session_io_lock(session, io_timeout, __func__);
        if (ret < 0) {
            ret = NC_MSG_ERROR;
            goto cleanup;
        } else if (!ret) {
            ret = NC_MSG_WOULDBLOCK;
            goto cleanup;
        }
        io_locked = 1;
    }

    /* read the message */
    switch (session->version) {
    case NC_VERSION_10:
        ret = nc_read_until(session, NC_VERSION_10_ENDTAG, 0, inact_timeout, &ts_act_timeout, &msg);
        if (ret == -1) {
            ret = NC_MSG_ERROR;
            goto cleanup;
        }

        /* cut off the end tag */
        msg[ret - NC_VERSION_10_ENDTAG_LEN] = '\0';
        break;
    case NC_VERSION_11:
        while (1) {
            ret = nc_read_until(session, "\n#", 0, inact_timeout, &ts_act_timeout, NULL);
            if (ret == -1) {
                ret = NC_MSG_ERROR;
                goto cleanup;
            }
            ret = nc_read_until(session, "\n", 0, inact_timeout, &ts_act_timeout, &chunk);
            if (ret == -1) {
                ret = NC_MSG_ERROR;
                goto cleanup;
            }

            if (!strcmp(chunk, "#\n")) {
                /* end of chunked framing message */
                free(chunk);
                if (!msg) {
                    ERR("Session %u: invalid frame chunk delimiters.", session->id);
                    goto malformed_msg;
                }
                break;
            }

            /* convert string to the size of the following chunk */
            chunk_len = strtoul(chunk, (char **)NULL, 10);
            free(chunk);
            if (!chunk_len) {
                ERR("Session %u: invalid frame chunk size detected, fatal error.", session->id);
                goto malformed_msg;
            }

            /* now we have size of next chunk, so read the chunk */
            ret = nc_read_chunk(session, chunk_len, inact_timeout, &ts_act_timeout, &chunk);
            if (ret == -1) {
                ret = NC_MSG_ERROR;
                goto cleanup;
            }

            /* realloc message buffer, remember to count terminating null byte */
            msg = nc_realloc(msg, len + chunk_len + 1);
            if (!msg) {
                ERRMEM;
                ret = NC_MSG_ERROR;
                goto cleanup;
            }
            memcpy(msg + len, chunk, chunk_len);
            len += chunk_len;
            msg[len] = '\0';
            free(chunk);
        }

        break;
    }

    /* SESSION IO UNLOCK */
    assert(io_locked);
    nc_session_io_unlock(session, __func__);
    io_locked = 0;

    DBG("Session %u: received message:\n%s\n", session->id, msg);

    /* build XML tree */
    *data = lyxml_parse_mem(session->ctx, msg, 0);
    if (!*data) {
        goto malformed_msg;
    } else if (!(*data)->ns) {
        ERR("Session %u: invalid message root element (invalid namespace).", session->id);
        goto malformed_msg;
    }
    free(msg);
    msg = NULL;

    /* get and return message type */
    if (!strcmp((*data)->ns->value, NC_NS_BASE)) {
        if (!strcmp((*data)->name, "rpc")) {
            return NC_MSG_RPC;
        } else if (!strcmp((*data)->name, "rpc-reply")) {
            return NC_MSG_REPLY;
        } else if (!strcmp((*data)->name, "hello")) {
            return NC_MSG_HELLO;
        } else {
            ERR("Session %u: invalid message root element (invalid name \"%s\").", session->id, (*data)->name);
            goto malformed_msg;
        }
    } else if (!strcmp((*data)->ns->value, NC_NS_NOTIF)) {
        if (!strcmp((*data)->name, "notification")) {
            return NC_MSG_NOTIF;
        } else {
            ERR("Session %u: invalid message root element (invalid name \"%s\").", session->id, (*data)->name);
            goto malformed_msg;
        }
    } else {
        ERR("Session %u: invalid message root element (invalid namespace \"%s\").", session->id, (*data)->ns->value);
        goto malformed_msg;
    }

malformed_msg:
    ERR("Session %u: malformed message received.", session->id);
    if ((session->side == NC_SERVER) && (session->version == NC_VERSION_11)) {
        /* NETCONF version 1.1 defines sending error reply from the server (RFC 6241 sec. 3) */
        reply = nc_server_reply_err(nc_err(NC_ERR_MALFORMED_MSG));

        if (io_locked) {
            /* nc_write_msg_io locks and unlocks the lock by itself */
            nc_session_io_unlock(session, __func__);
            io_locked = 0;
        }

        if (nc_write_msg_io(session, io_timeout, NC_MSG_REPLY, NULL, reply) != NC_MSG_REPLY) {
            ERR("Session %u: unable to send a \"Malformed message\" error reply, terminating session.", session->id);
            if (session->status != NC_STATUS_INVALID) {
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_OTHER;
            }
        }
        nc_server_reply_free(reply);
    }
    ret = NC_MSG_ERROR;

cleanup:
    if (io_locked) {
        nc_session_io_unlock(session, __func__);
    }
    free(msg);
    free(*data);
    *data = NULL;

    return ret;
}

/* return -1 means either poll error or that session was invalidated (socket error), EINTR is handled inside */
static int
nc_read_poll(struct nc_session *session, int io_timeout)
{
    sigset_t sigmask, origmask;
    int ret = -2;
    struct pollfd fds;

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR("Session %u: invalid session to poll.", session->id);
        return -1;
    }

    switch (session->ti_type) {
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
        /* EINTR is handled, it resumes waiting */
        ret = ssh_channel_poll_timeout(session->ti.libssh.channel, io_timeout, 0);
        if (ret == SSH_ERROR) {
            ERR("Session %u: SSH channel poll error (%s).", session->id,
                ssh_get_error(session->ti.libssh.session));
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_OTHER;
            return -1;
        } else if (ret == SSH_EOF) {
            ERR("Session %u: SSH channel unexpected EOF.", session->id);
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
#endif
#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
        ret = SSL_pending(session->ti.tls);
        if (ret) {
            /* some buffered TLS data available */
            ret = 1;
            fds.revents = POLLIN;
            break;
        }

        fds.fd = SSL_get_fd(session->ti.tls);
#endif
        /* fallthrough */
    case NC_TI_FD:
        if (session->ti_type == NC_TI_FD) {
            fds.fd = session->ti.fd.in;
        }

        fds.events = POLLIN;
        fds.revents = 0;

        sigfillset(&sigmask);
        pthread_sigmask(SIG_SETMASK, &sigmask, &origmask);
        ret = poll(&fds, 1, io_timeout);
        pthread_sigmask(SIG_SETMASK, &origmask, NULL);

        break;

    default:
        ERRINT;
        return -1;
    }

    /* process the poll result, unified ret meaning for poll and ssh_channel poll */
    if (ret < 0) {
        /* poll failed - something really bad happened, close the session */
        ERR("Session %u: poll error (%s).", session->id, strerror(errno));
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_OTHER;
        return -1;
    } else { /* status > 0 */
        /* in case of standard (non-libssh) poll, there still can be an error */
        if (fds.revents & POLLHUP) {
            ERR("Session %u: communication channel unexpectedly closed.", session->id);
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_DROPPED;
            return -1;
        }
        if (fds.revents & POLLERR) {
            ERR("Session %u: communication channel error.", session->id);
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_OTHER;
            return -1;
        }
    }

    return ret;
}

/* return NC_MSG_ERROR can change session status, acquires IO lock as needed */
NC_MSG_TYPE
nc_read_msg_poll_io(struct nc_session *session, int io_timeout, struct lyxml_elem **data)
{
    int ret;

    assert(data);
    *data = NULL;

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR("Session %u: invalid session to read from.", session->id);
        return NC_MSG_ERROR;
    }

    /* SESSION IO LOCK */
    ret = nc_session_io_lock(session, io_timeout, __func__);
    if (ret < 0) {
        return NC_MSG_ERROR;
    } else if (!ret) {
        return NC_MSG_WOULDBLOCK;
    }

    ret = nc_read_poll(session, io_timeout);
    if (ret == 0) {
        /* timed out */

        /* SESSION IO UNLOCK */
        nc_session_io_unlock(session, __func__);
        return NC_MSG_WOULDBLOCK;
    } else if (ret < 0) {
        /* poll error, error written */

        /* SESSION IO UNLOCK */
        nc_session_io_unlock(session, __func__);
        return NC_MSG_ERROR;
    }

    /* SESSION IO LOCK passed down */
    return nc_read_msg_io(session, io_timeout, data, 1);
}

/* does not really log, only fatal errors */
int
nc_session_is_connected(struct nc_session *session)
{
    int ret;
    struct pollfd fds;

    switch (session->ti_type) {
    case NC_TI_FD:
        fds.fd = session->ti.fd.in;
        break;
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
        return ssh_is_connected(session->ti.libssh.session);
#endif
#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
        fds.fd = SSL_get_fd(session->ti.tls);
        break;
#endif
    default:
        return 0;
    }

    if (fds.fd == -1) {
        return 0;
    }

    fds.events = POLLIN;
    fds.revents = 0;

    errno = 0;
    while (((ret = poll(&fds, 1, 0)) == -1) && (errno == EINTR));

    if (ret == -1) {
        ERR("Session %u: poll failed (%s).", session->id, strerror(errno));
        return 0;
    } else if ((ret > 0) && (fds.revents & (POLLHUP | POLLERR))) {
        return 0;
    }

    return 1;
}

#define WRITE_BUFSIZE (2 * BUFFERSIZE)
struct wclb_arg {
    struct nc_session *session;
    char buf[WRITE_BUFSIZE];
    size_t len;
};

static int
nc_write(struct nc_session *session, const void *buf, size_t count)
{
    int c;
    size_t written = 0;
#ifdef NC_ENABLED_TLS
    unsigned long e;
#endif

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        return -1;
    }

    /* prevent SIGPIPE this way */
    if (!nc_session_is_connected(session)) {
        ERR("Session %u: communication socket unexpectedly closed.", session->id);
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_DROPPED;
        return -1;
    }

    DBG("Session %u: sending message:\n%.*s\n", session->id, count, buf);

    do {
        switch (session->ti_type) {
        case NC_TI_FD:
            c = write(session->ti.fd.out, (char *)(buf + written), count - written);
            if (c < 0) {
                ERR("Session %u: socket error (%s).", session->id, strerror(errno));
                return -1;
            }
            break;

#ifdef NC_ENABLED_SSH
        case NC_TI_LIBSSH:
            if (ssh_channel_is_closed(session->ti.libssh.channel) || ssh_channel_is_eof(session->ti.libssh.channel)) {
                if (ssh_channel_is_closed(session->ti.libssh.channel)) {
                    ERR("Session %u: SSH channel unexpectedly closed.", session->id);
                } else {
                    ERR("Session %u: SSH channel unexpected EOF.", session->id);
                }
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_DROPPED;
                return -1;
            }
            c = ssh_channel_write(session->ti.libssh.channel, (char *)(buf + written), count - written);
            if ((c == SSH_ERROR) || (c == -1)) {
                ERR("Session %u: SSH channel write failed.", session->id);
                return -1;
            }
            break;
#endif
#ifdef NC_ENABLED_TLS
        case NC_TI_OPENSSL:
            c = SSL_write(session->ti.tls, (char *)(buf + written), count - written);
            if (c < 1) {
                switch ((e = SSL_get_error(session->ti.tls, c))) {
                case SSL_ERROR_ZERO_RETURN:
                    ERR("Session %u: SSL connection was properly closed.", session->id);
                    return -1;
                case SSL_ERROR_WANT_WRITE:
                    c = 0;
                    break;
                case SSL_ERROR_SYSCALL:
                    ERR("Session %u: SSL socket error (%s).", session->id, strerror(errno));
                    return -1;
                case SSL_ERROR_SSL:
                    ERR("Session %u: SSL error (%s).", session->id, ERR_reason_error_string(e));
                    return -1;
                default:
                    ERR("Session %u: unknown SSL error occured.", session->id);
                    return -1;
                }
            }
            break;
#endif
        default:
            ERRINT;
            return -1;
        }

        if (c == 0) {
            /* we must wait */
            usleep(NC_TIMEOUT_STEP);
        }

        written += c;
    } while (written < count);

    return written;
}

static int
nc_write_starttag_and_msg(struct nc_session *session, const void *buf, size_t count)
{
    int ret = 0, c;
    char chunksize[20];

    if (session->version == NC_VERSION_11) {
        sprintf(chunksize, "\n#%zu\n", count);
        ret = nc_write(session, chunksize, strlen(chunksize));
        if (ret == -1) {
            return -1;
        }
    }

    c = nc_write(session, buf, count);
    if (c == -1) {
        return -1;
    }
    ret += c;

    return ret;
}

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

static int
nc_write_clb_flush(struct wclb_arg *warg)
{
    int ret = 0;

    /* flush current buffer */
    if (warg->len) {
        ret = nc_write_starttag_and_msg(warg->session, warg->buf, warg->len);
        warg->len = 0;
    }

    return ret;
}

static ssize_t
nc_write_clb(void *arg, const void *buf, size_t count, int xmlcontent)
{
    int ret = 0, c;
    size_t l;
    struct wclb_arg *warg = (struct wclb_arg *)arg;

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

    if (!xmlcontent && count > WRITE_BUFSIZE) {
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

static ssize_t
nc_write_xmlclb(void *arg, const void *buf, size_t count)
{
    return nc_write_clb(arg, buf, count, 0);
}

static void
nc_write_error_elem(struct wclb_arg *arg, const char *name, uint16_t nam_len, const char *prefix, uint16_t pref_len,
                    int open, int no_attr)
{
    if (open) {
        nc_write_clb((void *)arg, "<", 1, 0);
    } else {
        nc_write_clb((void *)arg, "</", 2, 0);
    }

    if (prefix) {
        nc_write_clb((void *)arg, prefix, pref_len, 0);
        nc_write_clb((void *)arg, ":", 1, 0);
    }

    nc_write_clb((void *)arg, name, nam_len, 0);
    if (!open || !no_attr) {
        nc_write_clb((void *)arg, ">", 1, 0);
    }
}

static void
nc_write_error(struct wclb_arg *arg, struct nc_server_error *err, const char *prefix)
{
    uint16_t i, pref_len = 0;
    char str_sid[11];

    if (prefix) {
        pref_len = strlen(prefix);
    }

    nc_write_error_elem(arg, "rpc-error", 9, prefix, pref_len, 1, 0);

    nc_write_error_elem(arg, "error-type", 10, prefix, pref_len, 1, 0);
    switch (err->type) {
    case NC_ERR_TYPE_TRAN:
        nc_write_clb((void *)arg, "transport", 9, 0);
        break;
    case NC_ERR_TYPE_RPC:
        nc_write_clb((void *)arg, "rpc", 3, 0);
        break;
    case NC_ERR_TYPE_PROT:
        nc_write_clb((void *)arg, "protocol", 8, 0);
        break;
    case NC_ERR_TYPE_APP:
        nc_write_clb((void *)arg, "application", 11, 0);
        break;
    default:
        ERRINT;
        return;
    }

    nc_write_error_elem(arg, "error-type", 10, prefix, pref_len, 0, 0);

    nc_write_error_elem(arg, "error-tag", 9, prefix, pref_len, 1, 0);
    switch (err->tag) {
    case NC_ERR_IN_USE:
        nc_write_clb((void *)arg, "in-use", 6, 0);
        break;
    case NC_ERR_INVALID_VALUE:
        nc_write_clb((void *)arg, "invalid-value", 13, 0);
        break;
    case NC_ERR_TOO_BIG:
        nc_write_clb((void *)arg, "too-big", 7, 0);
        break;
    case NC_ERR_MISSING_ATTR:
        nc_write_clb((void *)arg, "missing-attribute", 17, 0);
        break;
    case NC_ERR_BAD_ATTR:
        nc_write_clb((void *)arg, "bad-attribute", 13, 0);
        break;
    case NC_ERR_UNKNOWN_ATTR:
        nc_write_clb((void *)arg, "unknown-attribute", 17, 0);
        break;
    case NC_ERR_MISSING_ELEM:
        nc_write_clb((void *)arg, "missing-element", 15, 0);
        break;
    case NC_ERR_BAD_ELEM:
        nc_write_clb((void *)arg, "bad-element", 11, 0);
        break;
    case NC_ERR_UNKNOWN_ELEM:
        nc_write_clb((void *)arg, "unknown-element", 15, 0);
        break;
    case NC_ERR_UNKNOWN_NS:
        nc_write_clb((void *)arg, "unknown-namespace", 17, 0);
        break;
    case NC_ERR_ACCESS_DENIED:
        nc_write_clb((void *)arg, "access-denied", 13, 0);
        break;
    case NC_ERR_LOCK_DENIED:
        nc_write_clb((void *)arg, "lock-denied", 11, 0);
        break;
    case NC_ERR_RES_DENIED:
        nc_write_clb((void *)arg, "resource-denied", 15, 0);
        break;
    case NC_ERR_ROLLBACK_FAILED:
        nc_write_clb((void *)arg, "rollback-failed", 15, 0);
        break;
    case NC_ERR_DATA_EXISTS:
        nc_write_clb((void *)arg, "data-exists", 11, 0);
        break;
    case NC_ERR_DATA_MISSING:
        nc_write_clb((void *)arg, "data-missing", 12, 0);
        break;
    case NC_ERR_OP_NOT_SUPPORTED:
        nc_write_clb((void *)arg, "operation-not-supported", 23, 0);
        break;
    case NC_ERR_OP_FAILED:
        nc_write_clb((void *)arg, "operation-failed", 16, 0);
        break;
    case NC_ERR_MALFORMED_MSG:
        nc_write_clb((void *)arg, "malformed-message", 17, 0);
        break;
    default:
        ERRINT;
        return;
    }
    nc_write_error_elem(arg, "error-tag", 9, prefix, pref_len, 0, 0);

    nc_write_error_elem(arg, "error-severity", 14, prefix, pref_len, 1, 0);
    nc_write_clb((void *)arg, "error", 5, 0);
    nc_write_error_elem(arg, "error-severity", 14, prefix, pref_len, 0, 0);

    if (err->apptag) {
        nc_write_error_elem(arg, "error-app-tag", 13, prefix, pref_len, 1, 0);
        nc_write_clb((void *)arg, err->apptag, strlen(err->apptag), 1);
        nc_write_error_elem(arg, "error-app-tag", 13, prefix, pref_len, 0, 0);
    }

    if (err->path) {
        nc_write_error_elem(arg, "error-path", 10, prefix, pref_len, 1, 0);
        nc_write_clb((void *)arg, err->path, strlen(err->path), 1);
        nc_write_error_elem(arg, "error-path", 10, prefix, pref_len, 0, 0);
    }

    if (err->message) {
        nc_write_error_elem(arg, "error-message", 13, prefix, pref_len, 1, 1);
        if (err->message_lang) {
            nc_write_clb((void *)arg, " xml:lang=\"", 11, 0);
            nc_write_clb((void *)arg, err->message_lang, strlen(err->message_lang), 1);
            nc_write_clb((void *)arg, "\"", 1, 0);
        }
        nc_write_clb((void *)arg, ">", 1, 0);
        nc_write_clb((void *)arg, err->message, strlen(err->message), 1);
        nc_write_error_elem(arg, "error-message", 13, prefix, pref_len, 0, 0);
    }

    if ((err->sid > -1) || err->attr_count || err->elem_count || err->ns_count || err->other_count) {
        nc_write_error_elem(arg, "error-info", 10, prefix, pref_len, 1, 0);

        if (err->sid > -1) {
            nc_write_error_elem(arg, "session-id", 10, prefix, pref_len, 1, 0);
            sprintf(str_sid, "%u", (uint32_t)err->sid);
            nc_write_clb((void *)arg, str_sid, strlen(str_sid), 0);
            nc_write_error_elem(arg, "session-id", 10, prefix, pref_len, 0, 0);
        }

        for (i = 0; i < err->attr_count; ++i) {
            nc_write_error_elem(arg, "bad-attribute", 13, prefix, pref_len, 1, 0);
            nc_write_clb((void *)arg, err->attr[i], strlen(err->attr[i]), 1);
            nc_write_error_elem(arg, "bad-attribute", 13, prefix, pref_len, 0, 0);
        }

        for (i = 0; i < err->elem_count; ++i) {
            nc_write_error_elem(arg, "bad-element", 11, prefix, pref_len, 1, 0);
            nc_write_clb((void *)arg, err->elem[i], strlen(err->elem[i]), 1);
            nc_write_error_elem(arg, "bad-element", 11, prefix, pref_len, 0, 0);
        }

        for (i = 0; i < err->ns_count; ++i) {
            nc_write_error_elem(arg, "bad-namespace", 13, prefix, pref_len, 1, 0);
            nc_write_clb((void *)arg, err->ns[i], strlen(err->ns[i]), 1);
            nc_write_error_elem(arg, "bad-namespace", 13, prefix, pref_len, 0, 0);
        }

        for (i = 0; i < err->other_count; ++i) {
            lyxml_print_clb(nc_write_xmlclb, (void *)arg, err->other[i], 0);
        }

        nc_write_error_elem(arg, "error-info", 10, prefix, pref_len, 0, 0);
    }

    nc_write_error_elem(arg, "rpc-error", 9, prefix, pref_len, 0, 0);
}

/* return NC_MSG_ERROR can change session status, acquires IO lock as needed */
NC_MSG_TYPE
nc_write_msg_io(struct nc_session *session, int io_timeout, int type, ...)
{
    va_list ap;
    int count, ret;
    const char *attrs, *base_prefix;
    struct lyd_node *content;
    struct lyxml_elem *rpc_elem;
    struct nc_server_notif *notif;
    struct nc_server_reply *reply;
    struct nc_server_reply_error *error_rpl;
    char *buf = NULL;
    struct wclb_arg arg;
    const char **capabilities;
    uint32_t *sid = NULL, i;
    int wd = 0;

    assert(session);

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR("Session %u: invalid session to write to.", session->id);
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
        content = va_arg(ap, struct lyd_node *);
        attrs = va_arg(ap, const char *);

        count = asprintf(&buf, "<rpc xmlns=\"%s\" message-id=\"%"PRIu64"\"%s>",
                         NC_NS_BASE, session->opts.client.msgid + 1, attrs ? attrs : "");
        if (count == -1) {
            ERRMEM;
            ret = NC_MSG_ERROR;
            goto cleanup;
        }
        nc_write_clb((void *)&arg, buf, count, 0);
        free(buf);

        if (lyd_print_clb(nc_write_xmlclb, (void *)&arg, content, LYD_XML, LYP_WITHSIBLINGS | LYP_NETCONF)) {
            ret = NC_MSG_ERROR;
            goto cleanup;
        }
        nc_write_clb((void *)&arg, "</rpc>", 6, 0);

        session->opts.client.msgid++;
        break;

    case NC_MSG_REPLY:
        rpc_elem = va_arg(ap, struct lyxml_elem *);
        reply = va_arg(ap, struct nc_server_reply *);

        if (rpc_elem && rpc_elem->ns && rpc_elem->ns->prefix) {
            nc_write_clb((void *)&arg, "<", 1, 0);
            nc_write_clb((void *)&arg, rpc_elem->ns->prefix, strlen(rpc_elem->ns->prefix), 0);
            nc_write_clb((void *)&arg, ":rpc-reply", 10, 0);
            base_prefix = rpc_elem->ns->prefix;
        }
        else {
            nc_write_clb((void *)&arg, "<rpc-reply", 10, 0);
            base_prefix = NULL;
        }

        /* can be NULL if replying with a malformed-message error */
        if (rpc_elem) {
            lyxml_print_clb(nc_write_xmlclb, (void *)&arg, rpc_elem, LYXML_PRINT_ATTRS);
            nc_write_clb((void *)&arg, ">", 1, 0);
        } else {
            /* but put there at least the correct namespace */
            nc_write_clb((void *)&arg, " xmlns=\""NC_NS_BASE"\">", 49, 0);
        }
        switch (reply->type) {
        case NC_RPL_OK:
            nc_write_clb((void *)&arg, "<", 1, 0);
            if (base_prefix) {
                nc_write_clb((void *)&arg, base_prefix, strlen(base_prefix), 0);
                nc_write_clb((void *)&arg, ":", 1, 0);
            }
            nc_write_clb((void *)&arg, "ok/>", 4, 0);
            break;
        case NC_RPL_DATA:
            switch(((struct nc_server_reply_data *)reply)->wd) {
            case NC_WD_UNKNOWN:
            case NC_WD_EXPLICIT:
                wd = LYP_WD_EXPLICIT;
                break;
            case NC_WD_TRIM:
                wd = LYP_WD_TRIM;
                break;
            case NC_WD_ALL:
                wd = LYP_WD_ALL;
                break;
            case NC_WD_ALL_TAG:
                wd = LYP_WD_ALL_TAG;
                break;
            }
            if (lyd_print_clb(nc_write_xmlclb, (void *)&arg, ((struct nc_reply_data *)reply)->data, LYD_XML,
                              LYP_WITHSIBLINGS | LYP_NETCONF | wd)) {
                ret = NC_MSG_ERROR;
                goto cleanup;
            }
            break;
        case NC_RPL_ERROR:
            error_rpl = (struct nc_server_reply_error *)reply;
            for (i = 0; i < error_rpl->count; ++i) {
                nc_write_error(&arg, error_rpl->err[i], base_prefix);
            }
            break;
        default:
            ERRINT;
            nc_write_clb((void *)&arg, NULL, 0, 0);
            ret = NC_MSG_ERROR;
            goto cleanup;
        }
        if (rpc_elem && rpc_elem->ns && rpc_elem->ns->prefix) {
            nc_write_clb((void *)&arg, "</", 2, 0);
            nc_write_clb((void *)&arg, rpc_elem->ns->prefix, strlen(rpc_elem->ns->prefix), 0);
            nc_write_clb((void *)&arg, ":rpc-reply>", 11, 0);
        }
        else {
            nc_write_clb((void *)&arg, "</rpc-reply>", 12, 0);
        }
        break;

    case NC_MSG_NOTIF:
        notif = va_arg(ap, struct nc_server_notif *);

        nc_write_clb((void *)&arg, "<notification xmlns=\""NC_NS_NOTIF"\">", 21 + 47 + 2, 0);
        nc_write_clb((void *)&arg, "<eventTime>", 11, 0);
        nc_write_clb((void *)&arg, notif->eventtime, strlen(notif->eventtime), 0);
        nc_write_clb((void *)&arg, "</eventTime>", 12, 0);
        if (lyd_print_clb(nc_write_xmlclb, (void *)&arg, notif->tree, LYD_XML, 0)) {
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
        sid = va_arg(ap, uint32_t*);

        count = asprintf(&buf, "<hello xmlns=\"%s\"><capabilities>", NC_NS_BASE);
        if (count == -1) {
            ERRMEM;
            ret = NC_MSG_ERROR;
            goto cleanup;
        }
        nc_write_clb((void *)&arg, buf, count, 0);
        free(buf);
        for (i = 0; capabilities[i]; i++) {
            nc_write_clb((void *)&arg, "<capability>", 12, 0);
            nc_write_clb((void *)&arg, capabilities[i], strlen(capabilities[i]), 1);
            nc_write_clb((void *)&arg, "</capability>", 13, 0);
        }
        if (sid) {
            count = asprintf(&buf, "</capabilities><session-id>%u</session-id></hello>", *sid);
            if (count == -1) {
                ERRMEM;
                ret = NC_MSG_ERROR;
                goto cleanup;
            }
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

