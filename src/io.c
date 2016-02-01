/**
 * \file io.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 - input/output functions
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

#define _GNU_SOURCE /* asprintf, ppoll */
#define _POSIX_SOUCE /* signals */
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <libyang/libyang.h>

#include "libnetconf.h"

#define BUFFERSIZE 512

static ssize_t
nc_read(struct nc_session *session, char *buf, size_t count)
{
    size_t size = 0;
    ssize_t r;

    assert(session);
    assert(buf);

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        return -1;
    }

    if (!count) {
        return 0;
    }

    switch (session->ti_type) {
    case NC_TI_NONE:
        return 0;

    case NC_TI_FD:
        /* read via standard file descriptor */
        while (count) {
            r = read(session->ti.fd.in, &(buf[size]), count);
            if (r < 0) {
                if ((errno == EAGAIN) || (errno == EINTR)) {
                    usleep(NC_READ_SLEEP);
                    continue;
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

            size = size + r;
            count = count - r;
        }
        break;

#ifdef ENABLE_SSH
    case NC_TI_LIBSSH:
        /* read via libssh */
        while (count) {
            r = ssh_channel_read(session->ti.libssh.channel, &(buf[size]), count, 0);
            if (r == SSH_AGAIN) {
                usleep(NC_READ_SLEEP);
                continue;
            } else if (r == SSH_ERROR) {
                ERR("Session %u: reading from the SSH channel failed (%zd: %s).", session->id,
                    ssh_get_error_code(session->ti.libssh.session), ssh_get_error(session->ti.libssh.session));
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
                usleep(NC_READ_SLEEP);
                continue;
            }

            size = size + r;
            count = count - r;
        }
        break;
#endif

#ifdef ENABLE_TLS
    case NC_TI_OPENSSL:
        /* read via OpenSSL */
        while (count) {
            r = SSL_read(session->ti.tls, &(buf[size]), count);
            if (r <= 0) {
                int x;
                switch (x = SSL_get_error(session->ti.tls, r)) {
                case SSL_ERROR_WANT_READ:
                    usleep(NC_READ_SLEEP);
                    continue;
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
            size = size + r;
            count = count - r;
        }
        break;
#endif
    }

    return (ssize_t)size;
}

static ssize_t
nc_read_chunk(struct nc_session *session, size_t len, char **chunk)
{
    ssize_t r;

    assert(session);
    assert(chunk);

    if (!len) {
        return 0;
    }

    *chunk = malloc ((len + 1) * sizeof **chunk);
    if (!*chunk) {
        ERRMEM;
        return -1;
    }

    r = nc_read(session, *chunk, len);
    if (r <= 0) {
        free(*chunk);
        return -1;
    }

    /* terminating null byte */
    (*chunk)[r] = 0;

    return r;
}

static ssize_t
nc_read_until(struct nc_session *session, const char *endtag, size_t limit, char **result)
{
    char *chunk = NULL;
    size_t size, count = 0, r, len;

    assert(session);
    assert(endtag);

    if (limit && limit < BUFFERSIZE) {
        size = limit;
    } else {
        size = BUFFERSIZE;
    }
    chunk = malloc ((size + 1) * sizeof *chunk);
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
        if (count == size) {
            /* get more memory */
            size = size + BUFFERSIZE;
            char *tmp = realloc (chunk, (size + 1) * sizeof *tmp);
            if (!tmp) {
                ERRMEM;
                free(chunk);
                return -1;
            }
            chunk = tmp;
        }

        /* get another character */
        r = nc_read(session, &(chunk[count]), 1);
        if (r != 1) {
            free(chunk);
            return -1;
        }

        count++;

        /* check endtag */
        if (count >= len) {
            if (!strncmp(endtag, &(chunk[count - len]), len)) {
                /* endtag found */
                break;
            }
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

/* return NC_MSG_ERROR can change session status */
NC_MSG_TYPE
nc_read_msg(struct nc_session *session, struct lyxml_elem **data)
{
    int ret;
    char *msg = NULL, *chunk, *aux;
    uint64_t chunk_len, len = 0;
    struct nc_server_reply *reply;

    assert(session && data);
    *data = NULL;

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR("Session %u: invalid session to read from.", session->id);
        return NC_MSG_ERROR;
    }

    /* read the message */
    switch (session->version) {
    case NC_VERSION_10:
        ret = nc_read_until(session, NC_VERSION_10_ENDTAG, 0, &msg);
        if (ret == -1) {
            goto error;
        }

        /* cut off the end tag */
        msg[ret - NC_VERSION_10_ENDTAG_LEN] = '\0';
        break;
    case NC_VERSION_11:
        while (1) {
            ret = nc_read_until(session, "\n#", 0, NULL);
            if (ret == -1) {
                goto error;
            }
            ret = nc_read_until(session, "\n", 0, &chunk);
            if (ret == -1) {
                goto error;
            }

            if (!strcmp(chunk, "#\n")) {
                /* end of chunked framing message */
                free(chunk);
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
            ret = nc_read_chunk(session, chunk_len, &chunk);
            if (ret == -1) {
                goto error;
            }

            /* realloc message buffer, remember to count terminating null byte */
            aux = realloc(msg, len + chunk_len + 1);
            if (!aux) {
                ERRMEM;
                goto error;
            }
            msg = aux;
            memcpy(msg + len, chunk, chunk_len);
            len += chunk_len;
            msg[len] = '\0';
            free(chunk);
        }

        break;
    }
    DBG("Session %u: received message:\n%s", session->id, msg);

    /* build XML tree */
    *data = lyxml_read_data(session->ctx, msg, 0);
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

        if (nc_write_msg(session, NC_MSG_REPLY, NULL, reply) == -1) {
            ERR("Session %u: unable to send a \"Malformed message\" error reply, terminating session.", session->id);
            if (session->status != NC_STATUS_INVALID) {
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_OTHER;
            }
        }
        nc_server_reply_free(reply);
    }

error:
    /* cleanup */
    free(msg);
    free(*data);
    *data = NULL;

    return NC_MSG_ERROR;
}

/* return -1 means either poll error or that session was invalidated (socket error), EINTR is handled inside */
static int
nc_read_poll(struct nc_session *session, int timeout)
{
    sigset_t sigmask;
    int ret = -2;
    struct pollfd fds;
    struct timespec ts_timeout;

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR("Session %u: invalid session to poll.", session->id);
        return -1;
    }

    switch (session->ti_type) {
#ifdef ENABLE_SSH
    case NC_TI_LIBSSH:
        /* EINTR is handled, it resumes waiting */
        ret = ssh_channel_poll_timeout(session->ti.libssh.channel, timeout, 0);
        if (ret == SSH_ERROR) {
            ERR("Session %u: SSH channel error (%s).", session->id, ssh_get_error(session->ti.libssh.session));
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_OTHER;
            return -1;
        } else if (ret == SSH_EOF) {
            ERR("Session %u: communication channel unexpectedly closed (libssh).", session->id);
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_DROPPED;
            return -1;
        } else if (ret > 0) {
            /* fake it */
            ret = 1;
            fds.revents = POLLIN;
        }
        /* fallthrough */
#endif
#ifdef ENABLE_TLS
    case NC_TI_OPENSSL:
        if (session->ti_type == NC_TI_OPENSSL) {
            fds.fd = SSL_get_fd(session->ti.tls);
        }
        /* fallthrough */
#endif
    case NC_TI_FD:
        if (session->ti_type == NC_TI_FD) {
            fds.fd = session->ti.fd.in;
        }

        /* poll only if it is not an SSH session */
        if (ret == -2) {
            fds.events = POLLIN;
            fds.revents = 0;

            if (timeout > -1) {
                if (!timeout) {
                    ts_timeout.tv_sec = 0;
                    ts_timeout.tv_nsec = 0;
                } else if (timeout > 0) {
                    ts_timeout.tv_sec = timeout / 1000;
                    ts_timeout.tv_nsec = (timeout % 1000) * 1000000;
                }
            }
            sigfillset(&sigmask);
            ret = ppoll(&fds, 1, (timeout == -1 ? NULL : &ts_timeout), &sigmask);
        }

        break;

    default:
        ERRINT;
        return -1;
    }

    /* process the poll result, unified ret meaning for poll and ssh_channel poll */
    if (ret < 0) {
        /* poll failed - something really bad happened, close the session */
        ERR("Session %u: ppoll error (%s).", session->id, strerror(errno));
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

/* return NC_MSG_ERROR can change session status */
NC_MSG_TYPE
nc_read_msg_poll(struct nc_session *session, int timeout, struct lyxml_elem **data)
{
    int ret;

    assert(data);
    *data = NULL;

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR("Session %u: invalid session to read from.", session->id);
        return NC_MSG_ERROR;
    }

    ret = nc_read_poll(session, timeout);
    if (ret == 0) {
        /* timed out */
        return NC_MSG_WOULDBLOCK;
    } else if (ret < 0) {
        /* poll error, error written */
        return NC_MSG_ERROR;
    }

    return nc_read_msg(session, data);
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
#ifdef ENABLE_SSH
    case NC_TI_LIBSSH:
        fds.fd = ssh_get_fd(session->ti.libssh.session);
        break;
#endif
#ifdef ENABLE_TLS
    case NC_TI_OPENSSL:
        fds.fd = SSL_get_fd(session->ti.tls);
        break;
#endif
    case NC_TI_NONE:
        ERRINT;
        return 0;
    }

    fds.events = POLLIN;

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

static ssize_t
nc_write(struct nc_session *session, const void *buf, size_t count)
{
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

    switch (session->ti_type) {
    case NC_TI_NONE:
        return -1;

    case NC_TI_FD:
        return write(session->ti.fd.out, buf, count);

#ifdef ENABLE_SSH
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
        return ssh_channel_write(session->ti.libssh.channel, buf, count);
#endif
#ifdef ENABLE_TLS
    case NC_TI_OPENSSL:
        return SSL_write(session->ti.tls, buf, count);
#endif
    }

    return -1;
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
nc_write_clb(void *arg, const void *buf, size_t count)
{
    int ret = 0, c;
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

    if (count > WRITE_BUFSIZE) {
        /* write directly */
        c = nc_write_starttag_and_msg(warg->session, buf, count);
        if (c == -1) {
            return -1;
        }
        ret += c;
    } else {
        /* keep in buffer and write later */
        memcpy(&warg->buf[warg->len], buf, count);
        warg->len += count; /* is <= WRITE_BUFSIZE */
        ret += count;
    }

    return ret;
}

static void
nc_write_error(struct wclb_arg *arg, struct nc_server_error *err)
{
    uint16_t i;
    char str_sid[11];

    nc_write_clb((void *)arg, "<rpc-error>", 11);

    nc_write_clb((void *)arg, "<error-type>", 12);
    switch (err->type) {
    case NC_ERR_TYPE_TRAN:
        nc_write_clb((void *)arg, "transport", 9);
        break;
    case NC_ERR_TYPE_RPC:
        nc_write_clb((void *)arg, "rpc", 3);
        break;
    case NC_ERR_TYPE_PROT:
        nc_write_clb((void *)arg, "protocol", 8);
        break;
    case NC_ERR_TYPE_APP:
        nc_write_clb((void *)arg, "application", 11);
        break;
    default:
        ERRINT;
        return;
    }
    nc_write_clb((void *)arg, "</error-type>", 13);

    nc_write_clb((void *)arg, "<error-tag>", 11);
    switch (err->tag) {
    case NC_ERR_IN_USE:
        nc_write_clb((void *)arg, "in-use", 6);
        break;
    case NC_ERR_INVALID_VALUE:
        nc_write_clb((void *)arg, "invalid-value", 13);
        break;
    case NC_ERR_TOO_BIG:
        nc_write_clb((void *)arg, "too-big", 7);
        break;
    case NC_ERR_MISSING_ATTR:
        nc_write_clb((void *)arg, "missing-attribute", 17);
        break;
    case NC_ERR_BAD_ATTR:
        nc_write_clb((void *)arg, "bad-attribute", 13);
        break;
    case NC_ERR_UNKNOWN_ATTR:
        nc_write_clb((void *)arg, "unknown-attribute", 17);
        break;
    case NC_ERR_MISSING_ELEM:
        nc_write_clb((void *)arg, "missing-element", 15);
        break;
    case NC_ERR_BAD_ELEM:
        nc_write_clb((void *)arg, "bad-element", 11);
        break;
    case NC_ERR_UNKNOWN_ELEM:
        nc_write_clb((void *)arg, "unknown-element", 15);
        break;
    case NC_ERR_UNKNOWN_NS:
        nc_write_clb((void *)arg, "unknown-namespace", 17);
        break;
    case NC_ERR_ACCESS_DENIED:
        nc_write_clb((void *)arg, "access-denied", 13);
        break;
    case NC_ERR_LOCK_DENIED:
        nc_write_clb((void *)arg, "lock-denied", 11);
        break;
    case NC_ERR_RES_DENIED:
        nc_write_clb((void *)arg, "resource-denied", 15);
        break;
    case NC_ERR_ROLLBACK_FAILED:
        nc_write_clb((void *)arg, "rollback-failed", 15);
        break;
    case NC_ERR_DATA_EXISTS:
        nc_write_clb((void *)arg, "data-exists", 11);
        break;
    case NC_ERR_DATA_MISSING:
        nc_write_clb((void *)arg, "data-missing", 12);
        break;
    case NC_ERR_OP_NOT_SUPPORTED:
        nc_write_clb((void *)arg, "operation-not-supported", 23);
        break;
    case NC_ERR_OP_FAILED:
        nc_write_clb((void *)arg, "operation-failed", 16);
        break;
    case NC_ERR_MALFORMED_MSG:
        nc_write_clb((void *)arg, "malformed-message", 17);
        break;
    default:
        ERRINT;
        return;
    }
    nc_write_clb((void *)arg, "</error-tag>", 12);

    nc_write_clb((void *)arg, "<error-severity>error</error-severity>", 38);

    if (err->apptag) {
        nc_write_clb((void *)arg, "<error-app-tag>", 15);
        nc_write_clb((void *)arg, err->apptag, strlen(err->apptag));
        nc_write_clb((void *)arg, "</error-app-tag>", 16);
    }

    if (err->path) {
        nc_write_clb((void *)arg, "<error-path>", 12);
        nc_write_clb((void *)arg, err->path, strlen(err->path));
        nc_write_clb((void *)arg, "</error-path>", 13);
    }

    if (err->message) {
        nc_write_clb((void *)arg, "<error-message", 14);
        if (err->message_lang) {
            nc_write_clb((void *)arg, " xml:lang=\"", 11);
            nc_write_clb((void *)arg, err->message_lang, strlen(err->message_lang));
            nc_write_clb((void *)arg, "\"", 1);
        }
        nc_write_clb((void *)arg, ">", 1);
        nc_write_clb((void *)arg, err->message, strlen(err->message));
        nc_write_clb((void *)arg, "</error-message>", 16);
    }

    if (err->sid || err->attr_count || err->elem_count || err->ns_count || err->other_count) {
        nc_write_clb((void *)arg, "<error-info>", 12);

        if (err->sid) {
            nc_write_clb((void *)arg, "<session-id>", 12);
            sprintf(str_sid, "%u", err->sid);
            nc_write_clb((void *)arg, str_sid, strlen(str_sid));
            nc_write_clb((void *)arg, "</session-id>", 13);
        }

        for (i = 0; i < err->attr_count; ++i) {
            nc_write_clb((void *)arg, "<bad-attribute>", 15);
            nc_write_clb((void *)arg, err->attr[i], strlen(err->attr[i]));
            nc_write_clb((void *)arg, "</bad-attribute>", 16);
        }

        for (i = 0; i < err->elem_count; ++i) {
            nc_write_clb((void *)arg, "<bad-element>", 13);
            nc_write_clb((void *)arg, err->elem[i], strlen(err->elem[i]));
            nc_write_clb((void *)arg, "</bad-element>", 14);
        }

        for (i = 0; i < err->ns_count; ++i) {
            nc_write_clb((void *)arg, "<bad-namespace>", 15);
            nc_write_clb((void *)arg, err->ns[i], strlen(err->ns[i]));
            nc_write_clb((void *)arg, "</bad-namespace>", 16);
        }

        for (i = 0; i < err->other_count; ++i) {
            lyxml_dump_clb(nc_write_clb, (void *)arg, err->other[i], 0);
        }

        nc_write_clb((void *)arg, "</error-info>", 13);
    }

    nc_write_clb((void *)arg, "</rpc-error>", 12);
}

/* return -1 can change session status */
int
nc_write_msg(struct nc_session *session, NC_MSG_TYPE type, ...)
{
    va_list ap;
    int count;
    const char *attrs;
    struct lyd_node *content;
    struct lyxml_elem *rpc_elem;
    struct nc_server_reply *reply;
    struct nc_server_reply_error *error_rpl;
    char *buf = NULL;
    struct wclb_arg arg;
    const char **capabilities;
    uint32_t *sid = NULL, i;

    assert(session);

    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        ERR("Session %u: invalid session to write to.", session->id);
        return -1;
    }

    va_start(ap, type);

    arg.session = session;
    arg.len = 0;

    switch (type) {
    case NC_MSG_RPC:
        content = va_arg(ap, struct lyd_node *);
        attrs = va_arg(ap, const char *);

        count = asprintf(&buf, "<rpc xmlns=\"%s\" message-id=\"%"PRIu64"\"%s>",
                         NC_NS_BASE, session->msgid + 1, attrs ? attrs : "");
        nc_write_clb((void *)&arg, buf, count);
        free(buf);
        lyd_print_clb(nc_write_clb, (void *)&arg, content, LYD_XML, 0);
        nc_write_clb((void *)&arg, "</rpc>", 6);

        session->msgid++;
        break;

    case NC_MSG_REPLY:
        rpc_elem = va_arg(ap, struct lyxml_elem *);
        reply = va_arg(ap, struct nc_server_reply *);

        nc_write_clb((void *)&arg, "<rpc-reply", 10);
        /* can be NULL if replying with a malformed-message error */
        if (rpc_elem) {
            lyxml_dump_clb(nc_write_clb, (void *)&arg, rpc_elem, LYXML_DUMP_ATTRS);
        }
        nc_write_clb((void *)&arg, ">", 1);
        switch (reply->type) {
        case NC_RPL_OK:
            nc_write_clb((void *)&arg, "<ok/>", 5);
            break;
        case NC_RPL_DATA:
            nc_write_clb((void *)&arg, "<data>", 6);
            lyd_print_clb(nc_write_clb, (void *)&arg, ((struct nc_reply_data *)reply)->data, LYD_XML, 0);
            nc_write_clb((void *)&arg, "</data>", 7);
            break;
        case NC_RPL_ERROR:
            error_rpl = (struct nc_server_reply_error *)reply;
            for (i = 0; i < error_rpl->count; ++i) {
                nc_write_error(&arg, error_rpl->err[i]);
            }
            break;
        default:
            ERRINT;
            nc_write_clb((void *)&arg, NULL, 0);
            va_end(ap);
            return -1;
        }
        nc_write_clb((void *)&arg, "</rpc-reply>", 12);
        break;

    case NC_MSG_NOTIF:
        nc_write_clb((void *)&arg, "<notification xmlns=\""NC_NS_NOTIF"\"/>", 21 + 47 + 3);
        /* TODO content */
        nc_write_clb((void *)&arg, "</notification>", 12);
        break;

    case NC_MSG_HELLO:
        if (session->version != NC_VERSION_10) {
            va_end(ap);
            return -1;
        }
        capabilities = va_arg(ap, const char **);
        sid = va_arg(ap, uint32_t*);

        count = asprintf(&buf, "<hello xmlns=\"%s\"><capabilities>", NC_NS_BASE);
        nc_write_clb((void *)&arg, buf, count);
        free(buf);
        for (i = 0; capabilities[i]; i++) {
            count = asprintf(&buf, "<capability>%s</capability>", capabilities[i]);
            nc_write_clb((void *)&arg, buf, count);
            free(buf);
        }
        if (sid) {
            count = asprintf(&buf, "</capabilities><session-id>%u</session-id></hello>", *sid);
            nc_write_clb((void *)&arg, buf, count);
            free(buf);
        } else {
            nc_write_clb((void *)&arg, "</capabilities></hello>", 23);
        }
        break;

    default:
        va_end(ap);
        return -1;
    }

    /* flush message */
    nc_write_clb((void *)&arg, NULL, 0);

    va_end(ap);
    if ((session->status != NC_STATUS_RUNNING) && (session->status != NC_STATUS_STARTING)) {
        /* error was already written */
        return -1;
    }

    return 0;
}
