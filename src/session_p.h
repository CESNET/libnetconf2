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

#include <stdint.h>
#include <pthread.h>

#include <libyang/libyang.h>
#include "libnetconf.h"
#include "session.h"

#ifdef ENABLE_SSH

#   include <libssh/libssh.h>
#   include <libssh/callbacks.h>

/* seconds */
#   define SSH_TIMEOUT 10
#   define SSH_AUTH_COUNT 3

struct nc_ssh_auth_opts {
    /* SSH authentication method preferences */
    struct {
        NC_SSH_AUTH_TYPE type;
        short int value;
    } auth_pref[SSH_AUTH_COUNT];

    /* SSH key pairs */
    struct {
        char *pubkey_path;
        char *privkey_path;
        int privkey_crypt;
    } *keys;
    int key_count;
};

#endif /* ENABLE_SSH */

#ifdef ENABLE_TLS

#include <openssl/bio.h>
#include <openssl/ssl.h>

struct nc_tls_auth_opts {
    SSL_CTX *tls_ctx;
    X509_STORE *tls_store;
};

#endif /* ENABLE_TLS */

/**
 * Sleep time in microseconds to wait between unsuccessful reading due to EAGAIN or EWOULDBLOCK
 */
#define NC_READ_SLEEP 100

/**
 * @brief type of the session
 */
typedef enum {
    NC_CLIENT,        /**< client side */
    NC_SERVER         /**< server side */
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
 * @brief Container to serialize PRC messages
 */
struct nc_msg_cont {
    struct lyxml_elem *msg;
    struct nc_msg_cont *next;
};

/**
 * @brief NETCONF session structure
 */
struct nc_session {
    NC_STATUS status;            /**< status of the session */
    NC_SIDE side;                /**< side of the session: client or server */

    /* NETCONF data */
    uint32_t id;                 /**< NETCONF session ID (session-id-type) */
    NC_VERSION version;          /**< NETCONF protocol version */
    pthread_t *notif;            /**< running notifications thread - TODO server-side only? */

    /* Transport implementation */
    NC_TRANSPORT_IMPL ti_type;   /**< transport implementation type to select items from ti union */
    pthread_mutex_t *ti_lock;    /**< lock to access ti. Note that in case of libssh TI, it can be shared with other
                                      NETCONF sessions on the same SSH session (but different SSH channel) */
    union {
        struct {
            int in;              /**< input file descriptor */
            int out;             /**< output file descriptor */
        } fd;                    /**< NC_TI_FD transport implementation structure */
#ifdef ENABLE_SSH
        struct {
            ssh_channel channel;
            ssh_session session;
            struct nc_session *next; /**< pointer to the next NETCONF session on the same
                                          SSH session, but different SSH channel. If no such session exists, it is NULL.
                                          otherwise there is a ring list of the NETCONF sessions */
        } libssh;
#endif
#ifdef ENABLE_TLS
        SSL *tls;
#endif
    } ti;                          /**< transport implementation data */
    const char *username;
    const char *host;
    uint16_t port;

    /* other */
    struct ly_ctx *ctx;            /**< libyang context of the session */
    uint8_t flags;                 /**< various flags of the session - TODO combine with status and/or side */
#define NC_SESSION_SHAREDCTX 0x1

    /* client side only data */
    uint64_t msgid;
    const char **cpblts;           /**< list of server's capabilities on client side */
    struct nc_msg_cont *replies;   /**< queue for RPC replies received instead of notifications */
    struct nc_msg_cont *notifs;    /**< queue for notifications received instead of RPC reply */
};

/**
 * @brief Fill libyang context in \p session. Context models are based on the stored session
 *        capabilities. If the server does not support \<get-schema\>, the models are searched
 *        for in the directory set using nc_schema_searchpath().
 *
 * @param[in] session Session to create the context for.
 * @return 0 on success, non-zero on failure.
 */
int nc_ctx_fill(struct nc_session *session);

/**
 * @brief Check whether the libyang context in \p session is suitable for NETCONF use
 *        meaning whether the ietf-netconf model is loaded.
 *
 * @param[in] session Session with the capabilities to be supported if loading ietf-netconf
 *                    explicitly.
 * @return 0 on success, non-zero on failure.
 */
int nc_ctx_check(struct nc_session *session);

/**
 * @brief Create and connect a socket.
 *
 * @param[in] host Hostname to connect to.
 * @param[in] port Port to connect on.
 * @return Connected socket or -1 on error.
 */
int nc_connect_getsocket(const char *host, unsigned short port);

/**
 * @brief Perform NETCONF handshake on \p session.
 *
 * @param[in] session NETCONF session to use.
 * @return 0 on success, non-zero on failure.
 */
int nc_handshake(struct nc_session *session);

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

/**
 * @brief Write message into wire.
 *
 * @param[in] session NETCONF session to which the message will be written.
 * @param[in] type Type of the message to write. According to the type, the
 * specific additional parameters are required or accepted:
 * - #NC_MSG_RPC
 *   - `struct lyd_node *op;` - operation (content of the \<rpc/\> to be sent. Required parameter.
 *   - `const char *attrs;` - additional attributes to be added into the \<rpc/\> element.
 *     `message-id` attribute is added automatically and default namespace is set to
 *     #NC_NS_BASE. Optional parameter.
 * - #NC_MSG_REPLY
 *   - `struct nc_rpc *rpc;` - RPC object to reply. Required parameter.
 *   - TODO: content
 * - #NC_MSG_NOTIF
 *   - TODO: content
 * @return 0 on success
 */
int nc_write_msg(struct nc_session *session, NC_MSG_TYPE type, ...);

#endif /* NC_SESSION_PRIVATE_H_ */
