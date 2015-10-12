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

#define _GNU_SOURCE /* asprintf */
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "config.h"
#include "libnetconf.h"
#include "session_p.h"
#include "messages_p.h"

#define BUFFERSIZE 512

static ssize_t
nc_read(struct nc_session *session, char *buf, size_t count)
{
    size_t size = 0;
    ssize_t r;

    assert(session);
    assert(buf);

    if (!count) {
        return 0;
    }

    switch(session->ti_type) {
    case NC_TI_FD:
        /* read via standard file descriptor */
        if (session->ti.fd.c) {
            /* get character from buffer (ungetc() simulation) */
            buf[size++] = session->ti.fd.c;
            session->ti.fd.c = 0;

            count--;
        }
        /* read data from file descriptor */
        while(count) {
            r = read(session->ti.fd.in, &(buf[size]), count);
            if (r < 0) {
                if (errno == EAGAIN) {
                    usleep(NC_READ_SLEEP);
                    continue;
                } else {
                    ERR("Reading from file descriptor (%d) failed (%s).", session->ti.fd.in, strerror(errno));
                    return -1;
                }
            } else if (r == 0) {
                ERR("Communication file descriptor (%d) unexpectedly closed.", session->ti.fd.in);
                return -1;
            }

            size = size + r;
            count = count - r;
        }
        break;

#ifdef ENABLE_LIBSSH
    case NC_TI_LIBSSH:
        /* read via libssh */
        while(count) {
            r = ssh_channel_read(session->ti.libssh.channel, &(buf[size]), count, 0);
            if (r == SSH_AGAIN) {
                usleep (NC_READ_SLEEP);
                continue;
            } else if (r == SSH_ERROR) {
                ERR("Reading from the SSH channel failed (%zd: %s)",
                    ssh_get_error_code(session->ti.libssh.session), ssh_get_error(session->ti.libssh.session));
                return -1;
            } else if (r == 0) {
                if (ssh_channel_is_eof(session->ti.libssh.channel)) {
                    ERR("Communication socket unexpectedly closed (libssh).");
                    return -1;
                }
                usleep (NC_READ_SLEEP);
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
        while(count) {
            r = SSL_read(session->ti.tls, &(buf[size]), count);
            if (r <= 0) {
                int x;
                switch (x = SSL_get_error(session->ti.tls, r)) {
                case SSL_ERROR_WANT_READ:
                    usleep(NC_READ_SLEEP);
                    continue;
                case SSL_ERROR_ZERO_RETURN:
                    ERR("Communication socket unexpectedly closed (OpenSSL).");
                    return -1;
                default:
                    ERR("Reading from the TLS session failed (SSL code %d)", x);
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
    while(1) {
        if (limit && count == limit) {
            free(chunk);
            WRN("%s: reading limit (%d) reached.", __func__, limit);
            ERR("Invalid input data (missing \"%s\" sequence).", endtag);
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

NC_MSG_TYPE
nc_read_msg(struct nc_session* session, int timeout, struct lyxml_elem **data)
{
    int status;
    int revents;
    struct pollfd fds;
    const char *emsg = NULL;
    char *msg = NULL, *chunk, *aux;
    unsigned long int chunk_len, len = 0;

    assert(data);
    *data = NULL;

    /* fill fds structure for poll */
    if (session->ti_type == NC_TI_FD) {
        fds.fd = session->ti.fd.in;
#ifdef ENABLE_TLS
    } else if (session->ti_type == NC_TI_OPENSSL) {
        fds.fd = SSL_get_fd(session->ti.tls);
#endif
    }

    while(1) {
        /* poll loop */

        switch(session->ti_type) {
#ifdef ENABLE_LIBSSH
        case NC_TI_LIBSSH:
            /* we are getting data from libssh's channel */
            status = ssh_channel_poll_timeout(session->ti.libssh.channel, timeout, 0);
            if (status > 0) {
                revents = POLLIN;
            } else if (status == SSH_AGAIN) {
                /* try again */
                continue;
            } else if (status == SSH_EOF) {
                emsg = "SSH channel closed";
            } else {
                if (!session->ti.libssh.channel) {
                    emsg = strerror(errno);
                } else if (session->ti.libssh.session) {
                    emsg = ssh_get_error(session->ti.libssh.session);
                } else {
                    emsg = "description not available";
                }
            }
            break;
#endif

#ifdef ENABLE_TLS
        case NC_TI_OPENSSL:
            /* no break - same processing as in case of standard file descriptors */
#endif
        case NC_TI_FD:
            fds.events = POLLIN;
            fds.revents = 0;
            status = poll(&fds, 1, timeout);
            revents = (unsigned long int) fds.revents;
            break;
        }

        /* process the poll result */
        if (status == 0) {
            /* timed out */
            return NC_MSG_WOULDBLOCK;
        } else if ((status == -1) && (errno == EINTR)) {
            /* poll was interrupted */
            continue;
        } else if (status < 0) {
            /* poll failed - something really bad happened, close the session */
            ERR("Input channel error (%s).", emsg ? emsg : strerror(errno));

            /* TODO - destroy the session */

            return NC_MSG_ERROR;
        } else { /* status > 0 */
            /* in case of standard (non-libssh) poll, there still can be an error */
            if ((revents & POLLHUP) || (revents & POLLERR)) {
                /* close client's socket (it's probably already closed by peer */
                ERR("Input channel closed.");

                /* TODO - destroy the session */

                return NC_MSG_ERROR;
            }

            /* we have something to read, so get out of the loop */
            break;
        }
    }

    /* read the message */
    switch (session->version) {
    case NC_VERSION_10:
        status = nc_read_until(session, NC_VERSION_10_ENDTAG, 0, &msg);
        if (status == -1) {
            goto error;
        }

        /* cut off the end tag */
        msg[status - NC_VERSION_10_ENDTAG_LEN] = '\0';
        break;
    case NC_VERSION_11:
        while(1) {
            status = nc_read_until(session, "\n#", 0, NULL);
            if (status == -1) {
                goto error;
            }
            status = nc_read_until(session, "\n", 0, &chunk);
            if (status == -1) {
                goto error;
            }

            if (!strcmp(chunk, "#\n")) {
                /* end of chunked framing message */
                free(chunk);
                break;
            }

            /* convert string to the size of the following chunk */
            chunk_len = strtoul(chunk, (char **) NULL, 10);
            free (chunk);
            if (!chunk_len) {
                ERR("Invalid frame chunk size detected, fatal error.");
                goto error;
            }

            /* now we have size of next chunk, so read the chunk */
            status = nc_read_chunk(session, chunk_len, &chunk);
            if (status == -1) {
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
    DBG("Received message (session %s): %s", session->id, msg);

    /* build XML tree */
    *data = lyxml_read(session->ctx, msg, 0);
    if (!*data) {
        goto error;
    } else if (!(*data)->ns) {
        ERR("Invalid message root element (invalid namespace)");
        goto error;
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
            ERR("Invalid message root element (invalid name \"%s\")", (*data)->name);
            goto error;
        }
    } else if (!strcmp((*data)->ns->value, NC_NS_NOTIF)) {
        if (!strcmp((*data)->name, "notification")) {
            return NC_MSG_NOTIF;
        } else {
            ERR("Invalid message root element (invalid name \"%s\")", (*data)->name);
            goto error;
        }
    } else {
        ERR("Invalid message root element (invalid namespace \"%s\")", (*data)->ns->value);
        goto error;
    }

error:
    /* cleanup */
    free(msg);
    free(*data);
    *data = NULL;

    if (session->side == NC_SIDE_SERVER && session->version == NC_VERSION_11) {
        /* NETCONF version 1.1 define sending error reply from the server */
        /* TODO
        reply = nc_reply_error(nc_err_new(NC_ERR_MALFORMED_MSG));
        if (reply == NULL) {
            ERROR("Unable to create the \'Malformed message\' reply");
            nc_session_close(session, NC_SESSION_TERM_OTHER);
            return (NC_MSG_UNKNOWN);
        }

        if (nc_session_send_reply(session, NULL, reply) == 0) {
            ERROR("Unable to send the \'Malformed message\' reply");
            nc_session_close(session, NC_SESSION_TERM_OTHER);
            return (NC_MSG_UNKNOWN);
        }
        nc_reply_free(reply);
        */
    }

    ERR("Malformed message received, closing the session %u.", session->id);
    /* TODO - destroy the session */

    return NC_MSG_ERROR;
}

#define WRITE_BUFSIZE (2 * BUFFERSIZE)
struct wclb_arg {
    struct nc_session *session;
    char buf[WRITE_BUFSIZE];
    size_t len;
};

static ssize_t
write_(struct nc_session *session, const void *buf, size_t count)
{
    int c = 0;
    char chunksize[20];

    switch (session->ti_type) {
    case NC_TI_FD:
        if (session->version == NC_VERSION_11) {
            c = dprintf(session->ti.fd.out, "\n#%zu\n", count);
        }
        return write(session->ti.fd.out, buf, count) + c;

#ifdef ENABLE_LIBSSH
    case NC_TI_LIBSSH:
        if (session->version == NC_VERSION_11) {
            c = snprintf(chunksize, 20, "\n#%zu\n", count);
            ssh_channel_write(session->ti.libssh.channel, chunksize, c);
        }
        return ssh_channel_write(session->ti.libssh.channel, buf, count) + c;
#endif

#ifdef ENABLE_TLS
    case NC_TI_OPENSSL:
        if (session->version == NC_VERSION_11) {
            c = snprintf(chunksize, "\n#%zu\n", count);
            SSL_write(session->ti.tls, chunksize, c);
        }
        return SSL_write(session->ti.tls, buf, count) + c;
#endif
    }

    return -1;
}

static int
write_endtag(struct nc_session *session)
{
    switch(session->ti_type) {
    case NC_TI_FD:
        if (session->version == NC_VERSION_11) {
            write(session->ti.fd.out, "\n##\n", 4);
        } else {
            write(session->ti.fd.out, "]]>]]>", 6);
        }
        break;

#ifdef ENABLE_LIBSSH
    case NC_TI_LIBSSH:
        if (session->version == NC_VERSION_11) {
            ssh_channel_write(session->ti.libssh.channel, "\n##\n", 4);
        } else {
            ssh_channel_write(session->ti.libssh.channel, "]]>]]>", 6);
        }
        break;
#endif

#ifdef ENABLE_TLS
    case NC_TI_OPENSSL:
        if (session->version == NC_VERSION_11) {
            SSL_write(session->ti.tls, "\n##\n", 4);
        } else {
            SSL_write(session->ti.tls, "]]>]]>", 6);
        }
        break;
#endif
    }

    return 0;
}

static void
write_clb_flush(struct wclb_arg *warg)
{
    /* flush current buffer */
    if (warg->len) {
        write_(warg->session, warg->buf, warg->len);
        warg->len = 0;
    }
}

static ssize_t
write_clb(void *arg, const void *buf, size_t count)
{
    struct wclb_arg *warg = (struct wclb_arg *)arg;

    if (!buf) {
        write_clb_flush(warg);

        /* endtag */
        write_endtag(warg->session);
        return 0;
    }

    if (warg->len && (warg->len + count > WRITE_BUFSIZE)) {
        /* dump current buffer */
        write_clb_flush(warg);
    }
    if (count > WRITE_BUFSIZE) {
        /* write directly */
        write_(warg->session, buf, count);
    } else {
        /* keep in buffer and write later */
        memcpy(&warg->buf[warg->len], buf, count);
        warg->len += count; /* is <= WRITE_BUFSIZE */
    }

    return (ssize_t)count;
}

/*
 * NETCONF 1.0 format
 */
static int
write_msg_10(struct nc_session *session, NC_MSG_TYPE type, va_list ap)
{
    int count;
    const char *attrs;
    struct lyd_node *content;
    struct nc_rpc *rpc;
    struct lyxml_elem *capabilities;
    char *buf = NULL;
    struct wclb_arg arg;

    arg.session = session;
    arg.len = 0;

    switch (type) {
    case NC_MSG_RPC:
        content = va_arg(ap, struct lyd_node *);
        attrs = va_arg(ap, const char *);
        switch (session->ti_type) {
        case NC_TI_FD:
            dprintf(session->ti.fd.out, "<rpc xmlns=\"%s\" message-id=\"%"PRIu64"\"%s>",
                    NC_NS_BASE, session->msgid + 1, attrs ? attrs : "");
            lyd_print_fd(session->ti.fd.out, content, LYD_XML);
            write(session->ti.fd.out, "</rpc>]]>]]>", 12);
            break;

#ifdef ENABLE_LIBSSH
        case NC_TI_LIBSSH:
#endif
#ifdef ENABLE_TLS
        case NC_TI_OPENSSL:
#endif
#if defined(ENABLE_LIBSSH) || defined(ENABLE_TLS)
            count = asprintf(&buf, "<rpc xmlns=\"%s\" message-id=\"%"PRIu64"\"%s>",
                             NC_NS_BASE, session->msgid + 1, attrs ? attrs : "");
            write_clb((void *)&arg, buf, count);
            free(buf);
            lyd_print_clb(write_clb, (void *)&arg, content, LYD_XML);
            write_clb((void *)&arg, "</rpc>", 6);

            /* flush message */
            write_clb((void *)&arg, NULL, 0);
            break;
#endif
        }

        session->msgid++;
        break;

    case NC_MSG_REPLY:
        rpc = va_arg(ap, struct nc_rpc *);
        switch (session->ti_type) {
        case NC_TI_FD:
            write(session->ti.fd.out, "<rpc-reply", 10);
            lyxml_dump_fd(session->ti.fd.out, rpc->root, LYXML_DUMP_ATTRS);
            write(session->ti.fd.out, ">", 1);

            /* TODO content */

            write(session->ti.fd.out, "</rpc-reply>]]>]]>", 18);
            break;

#ifdef ENABLE_LIBSSH
        case NC_TI_LIBSSH:
#endif
#ifdef ENABLE_TLS
        case NC_TI_OPENSSL:
#endif
#if defined(ENABLE_LIBSSH) || defined(ENABLE_TLS)
            write_clb((void *)&arg, "<rpc-reply", 10);
            lyxml_dump_clb(write_clb, (void *)&arg, rpc->root, LYXML_DUMP_ATTRS);

            /* TODO content */

            write_clb((void *)&arg, "</rpc-reply>", 12);

            /* flush message */
            write_clb((void *)&arg, NULL, 0);
            break;
#endif
        }
        break;

    case NC_MSG_NOTIF:
        switch (session->ti_type) {
        case NC_TI_FD:
            write(session->ti.fd.out, "<notification xmlns=\""NC_NS_NOTIF"\"/>", 21 + 47 + 3);

            /* TODO content */

            write(session->ti.fd.out, "</notification>]]>]]>", 18);
            break;

#ifdef ENABLE_LIBSSH
        case NC_TI_LIBSSH:
#endif
#ifdef ENABLE_TLS
        case NC_TI_OPENSSL:
#endif
#if defined(ENABLE_LIBSSH) || defined(ENABLE_TLS)
            write_clb((void *)&arg, "<notification xmlns=\""NC_NS_NOTIF"\"/>", 21 + 47 + 3);

            /* TODO content */

            write_clb((void *)&arg, "</notification>", 12);

            /* flush message */
            write_clb((void *)&arg, NULL, 0);
            break;
#endif
        }
        break;

    case NC_MSG_HELLO:
        capabilities = va_arg(ap, struct lyxml_elem *);
        switch (session->ti_type) {
        case NC_TI_FD:
            dprintf(session->ti.fd.out, "<hello xmlns=\"%s\">", NC_NS_BASE);
            lyxml_dump_fd(session->ti.fd.out, capabilities, 0);
            write(session->ti.fd.out, "</hello>]]>]]>", 11);
            break;

#ifdef ENABLE_LIBSSH
        case NC_TI_LIBSSH:
#endif
#ifdef ENABLE_TLS
        case NC_TI_OPENSSL:
#endif
#if defined(ENABLE_LIBSSH) || defined(ENABLE_TLS)
            count = asprintf(&buf, "<hello xmlns=\"%s\">", NC_NS_BASE);
            write_clb((void *)&arg, buf, count);
            free(buf);
            lyxml_dump_clb(write_clb, (void *)&arg, capabilities, 0);
            write_clb((void *)&arg, "</hello>", 8);

            /* flush message */
            write_clb((void *)&arg, NULL, 0);
            break;
#endif
        }
        break;

    default:
        return -1;
    }

    return 0;
}

/*
 * NETCONF 1.1 format
 */
static int
write_msg_11(struct nc_session *session, NC_MSG_TYPE type, va_list ap)
{
    int count;
    const char *attrs;
    struct lyd_node *content;
    struct nc_rpc *rpc;
    char *buf = NULL;
    struct wclb_arg arg;

    arg.session = session;
    arg.len = 0;

    switch (type) {
    case NC_MSG_RPC:
        content = va_arg(ap, struct lyd_node *);
        attrs = va_arg(ap, const char *);
        count = asprintf(&buf, "<rpc xmlns=\"%s\" message-id=\"%"PRIu64"\"%s>",
                         NC_NS_BASE, session->msgid + 1, attrs ? attrs : "");
        write_clb((void *)&arg, buf, count);
        free(buf);
        lyd_print_clb(write_clb, (void *)&arg, content, LYD_XML);
        write_clb((void *)&arg, "</rpc>", 6);

        session->msgid++;
        break;
    case NC_MSG_REPLY:
        rpc = va_arg(ap, struct nc_rpc *);
        write_clb((void *)&arg, "<rpc-reply", 10);
        lyxml_dump_clb(write_clb, (void *)&arg, rpc->root, LYXML_DUMP_ATTRS);
        write_clb((void *)&arg, ">", 1);
        /* TODO content */
        write_clb((void *)&arg, "</rpc-reply>", 12);
        break;
    case NC_MSG_NOTIF:
        write_clb((void *)&arg, "<notification xmlns=\""NC_NS_NOTIF"\"/>", 21 + 47 + 3);
        /* TODO content */
        write_clb((void *)&arg, "</notification>", 12);
        break;
    default:
        /* just to make compiler quiet */
        return -1;
    }

    /* flush message */
    write_clb((void *)&arg, NULL, 0);
    return 0;
}

int
nc_write_msg(struct nc_session *session, NC_MSG_TYPE type, ...)
{
    va_list ap;
    int r;

    va_start(ap, type);

    if (session->version == NC_VERSION_10) {
        r = write_msg_10(session, type, ap);
    } else {
        r = write_msg_11(session, type, ap);
    }

    va_end(ap);

    return r;
}
