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

    switch (session->ti_type) {
    case NC_TI_NONE:
        return 0;

    case NC_TI_FD:
        /* read via standard file descriptor */
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

#ifdef ENABLE_SSH
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
nc_read_msg(struct nc_session *session, struct lyxml_elem **data)
{
    int ret;
    char *msg = NULL, *chunk, *aux;
    uint64_t chunk_len, len = 0;

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
                ERR("Invalid frame chunk size detected, fatal error.");
                goto error;
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
    DBG("Received message (session %u):\n%s", session->id, msg);

    /* build XML tree */
    *data = lyxml_read_data(session->ctx, msg, 0);
    if (!*data) {
        goto error;
    } else if (!(*data)->ns) {
        ERR("Invalid message root element (invalid namespace).");
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
            ERR("Invalid message root element (invalid name \"%s\").", (*data)->name);
            goto error;
        }
    } else if (!strcmp((*data)->ns->value, NC_NS_NOTIF)) {
        if (!strcmp((*data)->name, "notification")) {
            return NC_MSG_NOTIF;
        } else {
            ERR("Invalid message root element (invalid name \"%s\").", (*data)->name);
            goto error;
        }
    } else {
        ERR("Invalid message root element (invalid namespace \"%s\").", (*data)->ns->value);
        goto error;
    }

error:
    /* cleanup */
    free(msg);
    free(*data);
    *data = NULL;

    if (session->side == NC_SERVER && session->version == NC_VERSION_11) {
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

    ERR("Malformed message received.");
    /* TODO - destroy the session */

    return NC_MSG_ERROR;
}

NC_MSG_TYPE
nc_read_msg_poll(struct nc_session *session, int timeout, struct lyxml_elem **data)
{
    int status;
    int revents;
    struct pollfd fds;
    const char *emsg = NULL;

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

    while (1) {
        /* poll loop */

        switch (session->ti_type) {
        case NC_TI_NONE:
            return NC_MSG_ERROR;

#ifdef ENABLE_SSH
        case NC_TI_LIBSSH:
            /* we are getting data from libssh's channel */
            status = ssh_channel_poll_timeout(session->ti.libssh.channel, timeout, 0);
            if (status > 0) {
                revents = POLLIN;
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

    return nc_read_msg(session, data);
}

#define WRITE_BUFSIZE (2 * BUFFERSIZE)
struct wclb_arg {
    struct nc_session *session;
    char buf[WRITE_BUFSIZE];
    size_t len;
};

static ssize_t
write_text_(struct nc_session *session, const void *buf, size_t count)
{
    switch (session->ti_type) {
    case NC_TI_NONE:
        return -1;

    case NC_TI_FD:
        return write(session->ti.fd.out, buf, count);

#ifdef ENABLE_SSH
    case NC_TI_LIBSSH:
        return ssh_channel_write(session->ti.libssh.channel, buf, count);
#endif
#ifdef ENABLE_TLS
    case NC_TI_OPENSSL:
        return SSL_write(session->ti.tls, buf, count);
#endif
    }

    return -1;
}

static ssize_t
write_starttag_and_msg(struct nc_session *session, const void *buf, size_t count)
{
    int c = 0;
    char chunksize[20];

    if (session->version == NC_VERSION_11) {
        sprintf(chunksize, "\n#%zu\n", count);
        c = write_text_(session, chunksize, strlen(chunksize));
    }
    return write_text_(session, buf, count) + c;
}

static int
write_endtag(struct nc_session *session)
{
    switch(session->ti_type) {
    case NC_TI_NONE:
        return 0;

    case NC_TI_FD:
        if (session->version == NC_VERSION_11) {
            write(session->ti.fd.out, "\n##\n", 4);
        } else {
            write(session->ti.fd.out, "]]>]]>", 6);
        }
        break;

#ifdef ENABLE_SSH
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
        write_starttag_and_msg(warg->session, warg->buf, warg->len);
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
        write_starttag_and_msg(warg->session, buf, count);
    } else {
        /* keep in buffer and write later */
        memcpy(&warg->buf[warg->len], buf, count);
        warg->len += count; /* is <= WRITE_BUFSIZE */
    }

    return (ssize_t)count;
}

static void
write_error(struct wclb_arg *arg, struct nc_server_error *err)
{
    uint16_t i;
    char str_sid[11];

    write_clb((void *)arg, "<rpc-error>", 11);

    write_clb((void *)arg, "<error-type>", 12);
    switch (err->type) {
    case NC_ERR_TYPE_TRAN:
        write_clb((void *)arg, "transport", 9);
        break;
    case NC_ERR_TYPE_RPC:
        write_clb((void *)arg, "rpc", 3);
        break;
    case NC_ERR_TYPE_PROT:
        write_clb((void *)arg, "protocol", 8);
        break;
    case NC_ERR_TYPE_APP:
        write_clb((void *)arg, "application", 11);
        break;
    default:
        ERRINT;
        return;
    }
    write_clb((void *)arg, "</error-type>", 13);

    write_clb((void *)arg, "<error-tag>", 11);
    switch (err->tag) {
    case NC_ERR_IN_USE:
        write_clb((void *)arg, "in-use", 6);
        break;
    case NC_ERR_INVALID_VALUE:
        write_clb((void *)arg, "invalid-value", 13);
        break;
    case NC_ERR_TOO_BIG:
        write_clb((void *)arg, "too-big", 7);
        break;
    case NC_ERR_MISSING_ATTR:
        write_clb((void *)arg, "missing-attribute", 17);
        break;
    case NC_ERR_BAD_ATTR:
        write_clb((void *)arg, "bad-attribute", 13);
        break;
    case NC_ERR_UNKNOWN_ATTR:
        write_clb((void *)arg, "unknown-attribute", 17);
        break;
    case NC_ERR_MISSING_ELEM:
        write_clb((void *)arg, "missing-element", 15);
        break;
    case NC_ERR_BAD_ELEM:
        write_clb((void *)arg, "bad-element", 11);
        break;
    case NC_ERR_UNKNOWN_ELEM:
        write_clb((void *)arg, "unknown-element", 15);
        break;
    case NC_ERR_UNKNOWN_NS:
        write_clb((void *)arg, "unknown-namespace", 17);
        break;
    case NC_ERR_ACCESS_DENIED:
        write_clb((void *)arg, "access-denied", 13);
        break;
    case NC_ERR_LOCK_DENIED:
        write_clb((void *)arg, "lock-denied", 11);
        break;
    case NC_ERR_RES_DENIED:
        write_clb((void *)arg, "resource-denied", 15);
        break;
    case NC_ERR_ROLLBACK_FAILED:
        write_clb((void *)arg, "rollback-failed", 15);
        break;
    case NC_ERR_DATA_EXISTS:
        write_clb((void *)arg, "data-exists", 11);
        break;
    case NC_ERR_DATA_MISSING:
        write_clb((void *)arg, "data-missing", 12);
        break;
    case NC_ERR_OP_NOT_SUPPORTED:
        write_clb((void *)arg, "operation-not-supported", 23);
        break;
    case NC_ERR_OP_FAILED:
        write_clb((void *)arg, "operation-failed", 16);
        break;
    case NC_ERR_MALFORMED_MSG:
        write_clb((void *)arg, "malformed-message", 17);
        break;
    default:
        ERRINT;
        return;
    }
    write_clb((void *)arg, "</error-tag>", 12);

    write_clb((void *)arg, "<error-severity>error</error-severity>", 38);

    if (err->apptag) {
        write_clb((void *)arg, "<error-app-tag>", 15);
        write_clb((void *)arg, err->apptag, strlen(err->apptag));
        write_clb((void *)arg, "</error-app-tag>", 16);
    }

    if (err->path) {
        write_clb((void *)arg, "<error-path>", 12);
        write_clb((void *)arg, err->path, strlen(err->path));
        write_clb((void *)arg, "</error-path>", 13);
    }

    if (err->message) {
        write_clb((void *)arg, "<error-message", 14);
        if (err->message_lang) {
            write_clb((void *)arg, " xml:lang=\"", 11);
            write_clb((void *)arg, err->message_lang, strlen(err->message_lang));
            write_clb((void *)arg, "\"", 1);
        }
        write_clb((void *)arg, ">", 1);
        write_clb((void *)arg, err->message, strlen(err->message));
        write_clb((void *)arg, "</error-message>", 16);
    }

    if (err->sid || err->attr || err->elem || err->ns || err->other) {
        write_clb((void *)arg, "<error-info>", 12);

        if (err->sid) {
            write_clb((void *)arg, "<session-id>", 12);
            sprintf(str_sid, "%u", err->sid);
            write_clb((void *)arg, str_sid, strlen(str_sid));
            write_clb((void *)arg, "</session-id>", 13);
        }

        for (i = 0; i < err->attr_count; ++i) {
            write_clb((void *)arg, "<bad-attribute>", 15);
            write_clb((void *)arg, err->attr[i], strlen(err->attr[i]));
            write_clb((void *)arg, "</bad-attribute>", 16);
        }

        for (i = 0; i < err->elem_count; ++i) {
            write_clb((void *)arg, "<bad-element>", 13);
            write_clb((void *)arg, err->elem[i], strlen(err->elem[i]));
            write_clb((void *)arg, "</bad-element>", 14);
        }

        for (i = 0; i < err->ns_count; ++i) {
            write_clb((void *)arg, "<bad-namespace>", 15);
            write_clb((void *)arg, err->ns[i], strlen(err->ns[i]));
            write_clb((void *)arg, "</bad-namespace>", 16);
        }

        for (i = 0; i < err->other_count; ++i) {
            lyxml_dump_clb(write_clb, (void *)arg, err->other[i], 0);
        }

        write_clb((void *)arg, "</error-info>", 13);
    }

    write_clb((void *)arg, "</rpc-error>", 12);
}

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

    va_start(ap, type);

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
        rpc_elem = va_arg(ap, struct lyxml_elem *);
        reply = va_arg(ap, struct nc_server_reply *);

        write_clb((void *)&arg, "<rpc-reply", 10);
        lyxml_dump_clb(write_clb, (void *)&arg, rpc_elem, LYXML_DUMP_ATTRS);
        write_clb((void *)&arg, ">", 1);
        switch (reply->type) {
        case NC_RPL_OK:
            write_clb((void *)&arg, "<ok/>", 5);
            break;
        case NC_RPL_DATA:
            write_clb((void *)&arg, "<data>", 6);
            lyd_print_clb(write_clb, (void *)&arg, ((struct nc_reply_data *)reply)->data, LYD_XML);
            write_clb((void *)&arg, "<data/>", 7);
            break;
        case NC_RPL_ERROR:
            error_rpl = (struct nc_server_reply_error *)reply;
            for (i = 0; i < error_rpl->count; ++i) {
                write_error(&arg, error_rpl->err[i]);
            }
            break;
        default:
            ERRINT;
            write_clb((void *)&arg, NULL, 0);
            va_end(ap);
            return -1;
        }
        write_clb((void *)&arg, "</rpc-reply>", 12);
        break;

    case NC_MSG_NOTIF:
        write_clb((void *)&arg, "<notification xmlns=\""NC_NS_NOTIF"\"/>", 21 + 47 + 3);
        /* TODO content */
        write_clb((void *)&arg, "</notification>", 12);
        break;

    case NC_MSG_HELLO:
        if (session->version != NC_VERSION_10) {
            va_end(ap);
            return -1;
        }
        capabilities = va_arg(ap, const char **);
        sid = va_arg(ap, uint32_t*);

        count = asprintf(&buf, "<hello xmlns=\"%s\"><capabilities>", NC_NS_BASE);
        write_clb((void *)&arg, buf, count);
        free(buf);
        for (i = 0; capabilities[i]; i++) {
            count = asprintf(&buf, "<capability>%s</capability>", capabilities[i]);
            write_clb((void *)&arg, buf, count);
            free(buf);
        }
        if (sid) {
            count = asprintf(&buf, "</capabilities><session-id>%u</session-id></hello>", *sid);
            write_clb((void *)&arg, buf, count);
            free(buf);
        } else {
            write_clb((void *)&arg, "</capabilities></hello>", 23);
        }
        break;

    default:
        va_end(ap);
        return -1;
    }

    /* flush message */
    write_clb((void *)&arg, NULL, 0);

    va_end(ap);
    return 0;
}
