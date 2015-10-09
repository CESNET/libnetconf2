/**
 * \file session_p.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 session manipulation
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

#ifndef NC_SESSION_PRIVATE_H_
#define NC_SESSION_PRIVATE_H_

#include <pthread.h>

#ifdef ENABLE_LIBSSH
#   include <libssh/libssh.h>
#   include <libssh/callbacks.h>
#endif

#ifdef ENABLE_TLS
#   include <openssl/bio.h>
#   include <openssl/ssl.h>
#endif

#include <libyang/libyang.h>

#include "libnetconf.h"
#include "session.h"

/**
 * Sleep time in microseconds to wait between unsuccessful reading due to EAGAIN or EWOULDBLOCK
 */
#define NC_READ_SLEEP 100

/**
 * @brief Enumeration of transport implementations (ways how libnetconf implements NETCONF transport protocol)
 */
typedef enum {
    NC_TI_FD,         /**< file descriptors - use standard input/output, transport protocol is implemented
                           outside the current application (only for NETCONF over SSH transport) */
#ifdef ENABLE_LIBSSH
    NC_TI_LIBSSH,     /**< libssh - use libssh library, only for NETCONF over SSH transport */
#endif
#ifdef ENABLE_TLS
    NC_TI_OPENSSL     /**< OpenSSL - use OpenSSK library, only for NETCONF over TLS transport */
#endif
} NC_TRANSPORT_IMPL;

/**
 * @brief Enumeration of possible session types (communication sides)
 */
typedef enum {
    NC_SIDE_SERVER,   /**< server side */
    NC_SIDE_CLIENT    /**< client side */
} NC_SIDE;

/**
 * @brief Enumeration of the supported NETCONF protocol versions
 */
typedef enum {
    NC_VERSION_10 = 0,  /**< NETCONV 1.0 - RFC 4741, 4742 */
    NC_VERSION_11 = 1   /**< NETCONF 1.1 - RFC 6241, 6242 */
} NC_VERSION;

#define NC_VERSION_10_ENDTAG "]]>]]>"
#define NC_VERSION_10_ENDTAG_LEN 6

/**
 * @brief Container to serialize RPC reply objects
 */
struct nc_reply_cont {
    struct nc_reply *msg;
    struct nc_reply_cont *next;
};

/**
 * @brief Container to serialize Notification objects
 */
struct nc_notif_cont {
    struct nc_notif *msg;
    struct nc_notif_cont *next;
};

/**
 * @brief NETCONF session structure
 */
struct nc_session {
    NC_SIDE side;                /**< type of the session: client or server */

    /* NETCONF data */
    uint32_t id;                 /**< NETCONF session ID (session-id-type) */
    NC_VERSION version;          /**< NETCONF protocol version */
    pthread_t *notif;              /**< running notifications thread */

    /* Transport implementation */
    NC_TRANSPORT_IMPL ti_type;   /**< transport implementation type to select items from ti union */
    pthread_mutex_t ti_lock;     /**< lock to access ti */
    union {
        struct {
            int in;              /**< input file descriptor */
            int out;             /**< output file descriptor */
            char c;              /**< internal buffer (ungetc() simulation */
        } fd;                    /**< NC_TI_FD transport implementation structure */
#ifdef ENABLE_LIBSSH
        struct {
            ssh_session session;
            ssh_channel channel;
        } libssh;
#endif
#ifdef ENABLE_TLS
        SSL *tls;
#endif
    } ti;                          /**< transport implementation data */

    /* other */
    struct ly_ctx *ctx;            /**< libyang context of the session */

    /* client side only data */
    struct nc_reply_cont *replies; /**< queue for RPC replies received instead of notifications */
    struct nc_notif_cont *notifs;  /**< queue for notifications received instead of RPC reply */
};

/**
 * Functions
 * - io.c
 */

/**
 * @brief Read message from the wire.
 *
 * Accepts hello, rpc, rpc-reply and notification. Received string is transformed into
 * libyang XML tree and the message type is detected from the top level element.
 *
 * @param[in] session NETCONF session from which the message is being read.
 * @param[in] timeout Timeout in milliseconds. Negative value means infinite timeout,
 *            zero value causes to return immediately.
 * @param[out] data XML tree built from the read data.
 * @return Type of the read message. #NC_MSG_WOULDBLOCK is returned if timeout is positive
 * (or zero) value and it passed out without any data on the wire. #NC_MSG_ERROR is
 * returned on error and #NC_MSG_NONE is never returned by this function.
 */
NC_MSG_TYPE nc_read_msg(struct nc_session* session, int timeout, struct lyxml_elem **data);

#endif /* NC_SESSION_PRIVATE_H_ */
