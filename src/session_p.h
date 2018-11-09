/**
 * \file session_p.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 session manipulation
 *
 * Copyright (c) 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_SESSION_PRIVATE_H_
#define NC_SESSION_PRIVATE_H_

#include <stdint.h>
#include <pthread.h>

#include <libyang/libyang.h>

#include "libnetconf.h"
#include "netconf.h"
#include "session.h"
#include "messages_client.h"

#ifdef NC_ENABLED_SSH

#   include <libssh/libssh.h>
#   include <libssh/callbacks.h>
#   include <libssh/server.h>

/* seconds */
#   define NC_SSH_TIMEOUT 10
/* number of all supported authentication methods */
#   define NC_SSH_AUTH_COUNT 3

/* ACCESS unlocked */
struct nc_client_ssh_opts {
    /* SSH authentication method preferences */
    struct {
        NC_SSH_AUTH_TYPE type;
        int16_t value;
    } auth_pref[NC_SSH_AUTH_COUNT];

    /* SSH key pairs */
    struct {
        char *pubkey_path;
        char *privkey_path;
        int8_t privkey_crypt;
    } *keys;
    uint16_t key_count;

    /* SSH authentication callbacks */
    int (*auth_hostkey_check)(const char *, ssh_session, void *);
    char *(*auth_password)(const char *, const char *, void *);
    char *(*auth_interactive)(const char *, const char *, const char *, int, void *);
    char *(*auth_privkey_passphrase)(const char *, void *);

    /* private data for the callbacks */
    void *auth_hostkey_check_priv;
    void *auth_password_priv;
    void *auth_interactive_priv;
    void *auth_privkey_passphrase_priv;

    char *username;
};

/* ACCESS locked, separate locks */
struct nc_server_ssh_opts {
    /* SSH bind options */
    const char **hostkeys;
    uint8_t hostkey_count;

    int auth_methods;
    uint16_t auth_attempts;
    uint16_t auth_timeout;
};

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

#   include <openssl/bio.h>
#   include <openssl/ssl.h>

/* ACCESS unlocked */
struct nc_client_tls_opts {
    char *cert_path;
    char *key_path;
    char *ca_file;
    char *ca_dir;
    int8_t tls_ctx_change;
    SSL_CTX *tls_ctx;

    char *crl_file;
    char *crl_dir;
    int8_t crl_store_change;
    X509_STORE *crl_store;
};

/* ACCESS locked, separate locks */
struct nc_server_tls_opts {
    const char *server_cert;
    const char **trusted_cert_lists;
    uint16_t trusted_cert_list_count;
    const char *trusted_ca_file;
    const char *trusted_ca_dir;
    X509_STORE *crl_store;

    struct nc_ctn {
        uint32_t id;
        const char *fingerprint;
        NC_TLS_CTN_MAPTYPE map_type;
        const char *name;
        struct nc_ctn *next;
    } *ctn;
};

#endif /* NC_ENABLED_TLS */

/* ACCESS unlocked */
struct nc_client_opts {
    char *schema_searchpath;
    ly_module_imp_clb schema_clb;
    void *schema_clb_data;

    struct nc_bind {
        const char *address;
        uint16_t port;
        int sock;
        int pollin;
    } *ch_binds;
    NC_TRANSPORT_IMPL *ch_bind_ti;
    uint16_t ch_bind_count;
};

/* ACCESS unlocked */
struct nc_client_context {
    unsigned int refcount;
    struct nc_client_opts opts;
#ifdef NC_ENABLED_SSH
    struct nc_client_ssh_opts ssh_opts;
    struct nc_client_ssh_opts ssh_ch_opts;
#endif /* NC_ENABLED_SSH */
#ifdef NC_ENABLED_TLS
    struct nc_client_tls_opts tls_opts;
    struct nc_client_tls_opts tls_ch_opts;
#endif /* NC_ENABLED_TLS */
};

struct nc_server_opts {
    /* ACCESS unlocked (dictionary locked internally in libyang) */
    struct ly_ctx *ctx;

    /* ACCESS unlocked */
    NC_WD_MODE wd_basic_mode;
    int wd_also_supported;
    unsigned int capabilities_count;
    const char **capabilities;

    /* ACCESS unlocked */
    uint16_t hello_timeout;
    uint16_t idle_timeout;
#ifdef NC_ENABLED_SSH
    int (*passwd_auth_clb)(const struct nc_session *session, const char *password, void *user_data);
    void *passwd_auth_data;
    void (*passwd_auth_data_free)(void *data);

    int (*pubkey_auth_clb)(const struct nc_session *session, ssh_key key, void *user_data);
    void *pubkey_auth_data;
    void (*pubkey_auth_data_free)(void *data);

    int (*interactive_auth_clb)(const struct nc_session *session, ssh_message msg, void *user_data);
    void *interactive_auth_data;
    void (*interactive_auth_data_free)(void *data);
#endif
#ifdef NC_ENABLED_TLS
    int (*user_verify_clb)(const struct nc_session *session);

    int (*server_cert_clb)(const char *name, void *user_data, char **cert_path, char **cert_data,char **privkey_path,
                           char **privkey_data, int *privkey_data_rsa);
    void *server_cert_data;
    void (*server_cert_data_free)(void *data);

    int (*server_cert_chain_clb)(const char *name, void *user_data, char ***cert_paths, int *cert_path_count,
                                 char ***cert_data, int *cert_data_count);
    void *server_cert_chain_data;
    void (*server_cert_chain_data_free)(void *data);

    int (*trusted_cert_list_clb)(const char *name, void *user_data, char ***cert_paths, int *cert_path_count,
                                 char ***cert_data, int *cert_data_count);
    void *trusted_cert_list_data;
    void (*trusted_cert_list_data_free)(void *data);
#endif

#ifdef NC_ENABLED_SSH
    /* ACCESS locked with authkey_lock */
    struct {
        const char *path;
        const char *base64;
        NC_SSH_KEY_TYPE type;
        const char *username;
    } *authkeys;
    uint16_t authkey_count;
    pthread_mutex_t authkey_lock;

    int (*hostkey_clb)(const char *name, void *user_data, char **privkey_path, char **privkey_data, int *privkey_data_rsa);
    void *hostkey_data;
    void (*hostkey_data_free)(void *data);
#endif

    /* ACCESS locked, add/remove endpts/binds - bind_lock + WRITE endpt_lock (strict order!)
     *                modify endpts - WRITE endpt_lock
     *                access endpts - READ endpt_lock
     *                modify/poll binds - bind_lock */
    struct nc_bind *binds;
    pthread_mutex_t bind_lock;
    struct nc_endpt {
        const char *name;
        NC_TRANSPORT_IMPL ti;
        union {
#ifdef NC_ENABLED_SSH
            struct nc_server_ssh_opts *ssh;
#endif
#ifdef NC_ENABLED_TLS
            struct nc_server_tls_opts *tls;
#endif
        } opts;
    } *endpts;
    uint16_t endpt_count;
    pthread_rwlock_t endpt_lock;

    /* ACCESS locked, add/remove CH clients - WRITE lock ch_client_lock
     *                modify CH clients - READ lock ch_client_lock + ch_client_lock */
    struct nc_ch_client {
        const char *name;
        NC_TRANSPORT_IMPL ti;
        struct nc_ch_endpt {
            const char *name;
            const char *address;
            uint16_t port;
            int sock_pending;
        } *ch_endpts;
        uint16_t ch_endpt_count;
        union {
#ifdef NC_ENABLED_SSH
            struct nc_server_ssh_opts *ssh;
#endif
#ifdef NC_ENABLED_TLS
            struct nc_server_tls_opts *tls;
#endif
        } opts;
        NC_CH_CONN_TYPE conn_type;
        union {
            struct {
                uint32_t idle_timeout;
                uint16_t ka_max_wait;
                uint8_t ka_max_attempts;
            } persist;
            struct {
                uint16_t idle_timeout;
                uint16_t reconnect_timeout;
            } period;
        } conn;
        NC_CH_START_WITH start_with;
        uint8_t max_attempts;
        uint32_t id;
        pthread_mutex_t lock;
    } *ch_clients;
    uint16_t ch_client_count;
    pthread_rwlock_t ch_client_lock;

    /* Atomic IDs */
    ATOMIC_UINT32_T new_session_id;
    ATOMIC_UINT32_T new_client_id;
};

/**
 * Sleep time in msec to wait between nc_recv_notif() calls.
 */
#define NC_CLIENT_NOTIF_THREAD_SLEEP 10000

/**
 * Timeout in msec for transport-related data to arrive (ssh_handle_key_exchange(), SSL_accept(), SSL_connect()).
 * It can be quite a lot on slow machines (waiting for TLS cert-to-name resolution, ...).
 */
#define NC_TRANSPORT_TIMEOUT 10000

/**
 * Timeout in msec for acquiring a lock of a session (used with a condition, so higher numbers could be required
 * only in case of extreme concurrency).
 */
#define NC_SESSION_LOCK_TIMEOUT 500

/**
 * Timeout in msec for acquiring a lock of a session that is supposed to be freed.
 */
#define NC_SESSION_FREE_LOCK_TIMEOUT 1000

/**
 * Timeout in msec for acquiring a lock of a pollsession structure.
 */
#define NC_PS_LOCK_TIMEOUT 200

/**
 * Timeout in msec for a thread to wait for its turn to work with a pollsession structure.
 *
 */
#define NC_PS_QUEUE_TIMEOUT 1000

/**
 * Time slept in msec if no endpoint was created for a running Call Home client.
 */
#define NC_CH_NO_ENDPT_WAIT 1000

/**
 * Time slept in msec after a failed Call Home endpoint session creation.
 */
#define NC_CH_ENDPT_FAIL_WAIT 1000

/**
 * Number of sockets kept waiting to be accepted.
 */
#define NC_REVERSE_QUEUE 5

/**
 * @brief Type of the session
 */
typedef enum {
    NC_CLIENT,        /**< client side */
    NC_SERVER         /**< server side */
} NC_SIDE;

/**
 * @brief Enumeration of the supported NETCONF protocol versions
 */
typedef enum {
    NC_VERSION_10 = 0,  /**< NETCONF 1.0 - RFC 4741, 4742 */
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
    NC_SESSION_TERM_REASON term_reason; /**< reason of termination, if status is NC_STATUS_INVALID */
    uint32_t killed_by;          /**< session responsible for termination, if term_reason is NC_SESSION_TERM_KILLED */
    NC_SIDE side;                /**< side of the session: client or server */

    /* NETCONF data */
    uint32_t id;                 /**< NETCONF session ID (session-id-type) */
    NC_VERSION version;          /**< NETCONF protocol version */

    /* Transport implementation */
    NC_TRANSPORT_IMPL ti_type;   /**< transport implementation type to select items from ti union */
    pthread_mutex_t *io_lock;    /**< input/output lock, note that in case of libssh TI, it will be shared
                                      with other NETCONF sessions on the same SSH session (but different SSH channel) */

    union {
        struct {
            int in;              /**< input file descriptor */
            int out;             /**< output file descriptor */
        } fd;                    /**< NC_TI_FD transport implementation structure */
#ifdef NC_ENABLED_SSH
        struct {
            ssh_channel channel;
            ssh_session session;
            struct nc_session *next; /**< pointer to the next NETCONF session on the same
                                          SSH session, but different SSH channel. If no such session exists, it is NULL.
                                          otherwise there is a ring list of the NETCONF sessions */
        } libssh;
#endif
#ifdef NC_ENABLED_TLS
        SSL *tls;
#endif
    } ti;                          /**< transport implementation data */
    const char *username;
    const char *host;
    uint16_t port;

    /* other */
    struct ly_ctx *ctx;            /**< libyang context of the session */
    void *data;                    /**< arbitrary user data */
    uint8_t flags;                 /**< various flags of the session - TODO combine with status and/or side */
#define NC_SESSION_SHAREDCTX 0x01
#define NC_SESSION_CALLHOME 0x02

    union {
        struct {
            /* client side only data */
            uint64_t msgid;
            char **cpblts;                 /**< list of server's capabilities on client side */
            struct nc_msg_cont *replies;   /**< queue for RPC replies received instead of notifications */
            struct nc_msg_cont *notifs;    /**< queue for notifications received instead of RPC reply */
            volatile pthread_t *ntf_tid;   /**< running notifications receiving thread */

            /* client flags */
            /* some server modules failed to load so the data from them will be ignored - not use strict flag for parsing */
#           define NC_SESSION_CLIENT_NOT_STRICT 0x40
        } client;
        struct {
            /* server side only data */
            time_t session_start;          /**< real time the session was created */
            time_t last_rpc;               /**< monotonic time (seconds) the last RPC was received on this session */
            int ntf_status;                /**< flag whether the session is subscribed to any stream */

            pthread_mutex_t *rpc_lock;   /**< lock indicating RPC processing, this lock is always locked before io_lock!! */
            pthread_cond_t *rpc_cond;    /**< RPC condition (tied with rpc_lock and rpc_inuse) */
            volatile int *rpc_inuse;     /**< variable indicating whether there is RPC being processed or not (tied with
                                              rpc_cond and rpc_lock) */

            pthread_mutex_t *ch_lock;      /**< Call Home thread lock */
            pthread_cond_t *ch_cond;       /**< Call Home thread condition */

            /* server flags */
#ifdef NC_ENABLED_SSH
            /* SSH session authenticated */
#           define NC_SESSION_SSH_AUTHENTICATED 0x04
            /* netconf subsystem requested */
#           define NC_SESSION_SSH_SUBSYS_NETCONF 0x08
            /* new SSH message arrived */
#           define NC_SESSION_SSH_NEW_MSG 0x10
            /* this session is passed to nc_sshcb_msg() */
#           define NC_SESSION_SSH_MSG_CB 0x20

            uint16_t ssh_auth_attempts;    /**< number of failed SSH authentication attempts */
#endif
#ifdef NC_ENABLED_TLS
            X509 *client_cert;                /**< TLS client certificate if used for authentication */
#endif
        } server;
    } opts;
};

enum nc_ps_session_state {
    NC_PS_STATE_NONE = 0,      /**< session is not being worked with */
    NC_PS_STATE_BUSY,          /**< session is being polled or communicated on (and locked) */
    NC_PS_STATE_INVALID        /**< session is invalid and was already returned by another poll */
};

struct nc_ps_session {
    struct nc_session *session;
    enum nc_ps_session_state state;
};

/* ACCESS locked */
struct nc_pollsession {
    struct nc_ps_session **sessions;
    uint16_t session_count;
    uint16_t last_event_session;

    pthread_cond_t cond;
    pthread_mutex_t lock;
    uint8_t queue[NC_PS_QUEUE_SIZE]; /**< round buffer, queue is empty when queue_len == 0 */
    uint8_t queue_begin;             /**< queue starts on queue[queue_begin] */
    uint8_t queue_len;               /**< queue ends on queue[(queue_begin + queue_len - 1) % NC_PS_QUEUE_SIZE] */
};

struct nc_ntf_thread_arg {
    struct nc_session *session;
    void (*notif_clb)(struct nc_session *session, const struct nc_notif *notif);
};

void *nc_realloc(void *ptr, size_t size);

NC_MSG_TYPE nc_send_msg_io(struct nc_session *session, int io_timeout, struct lyd_node *op);

#ifndef HAVE_PTHREAD_MUTEX_TIMEDLOCK
int pthread_mutex_timedlock(pthread_mutex_t *mutex, const struct timespec *abstime);
#endif

int nc_gettimespec_mono(struct timespec *ts);

int nc_gettimespec_real(struct timespec *ts);

int32_t nc_difftimespec(const struct timespec *ts1, const struct timespec *ts2);

void nc_addtimespec(struct timespec *ts, uint32_t msec);

int nc_sock_enable_keepalive(int sock);

struct nc_session *nc_new_session(NC_SIDE side, int shared_ti);

int nc_session_rpc_lock(struct nc_session *session, int timeout, const char *func);

int nc_session_rpc_unlock(struct nc_session *session, int timeout, const char *func);

int nc_session_io_lock(struct nc_session *session, int timeout, const char *func);

int nc_session_io_unlock(struct nc_session *session, const char *func);

int nc_ps_lock(struct nc_pollsession *ps, uint8_t *id, const char *func);

int nc_ps_unlock(struct nc_pollsession *ps, uint8_t id, const char *func);

/**
 * @brief Fill libyang context in \p session. Context models are based on the stored session
 *        capabilities. If the server does not support \<get-schema\>, the models are searched
 *        for in the directory set using nc_client_schema_searchpath().
 *
 * @param[in] session Session to create the context for.
 * @return 0 on success, 1 on some missing schemas, -1 on error.
 */
int nc_ctx_check_and_fill(struct nc_session *session);

/**
 * @brief Perform NETCONF handshake on \p session.
 *
 * @param[in] session NETCONF session to use.
 * @return NC_MSG_HELLO on success, NC_MSG_BAD_HELLO on client \<hello\> message parsing fail
 * (server-side only), NC_MSG_WOULDBLOCK on timeout, NC_MSG_ERROR on other error.
 */
NC_MSG_TYPE nc_handshake_io(struct nc_session *session);

/**
 * @brief Create a socket connection.
 *
 * @param[in] host Hostname to connect to.
 * @param[in] port Port to connect on.
 * @param[in] timeout for blocking the connect+select call (-1 for infinite).
 * @param[in] sock_pending for exchanging the pending socket, if the blocking timeout was != -1
 * @return Connected socket or -1 on error.
 */
int nc_sock_connect(const char *host, uint16_t port, int timeout, int* sock_pending);

/**
 * @brief Accept a new socket connection.
 *
 * @param[in] sock Listening socket.
 * @param[in] timeout Timeout in milliseconds.
 * @param[out] peer_host Host the new connection was initiated from. Can be NULL.
 * @param[out] peer_port Port the new connection is connected on. Can be NULL.
 * @return Connected socket with the new connection, -1 on error.
 */
int nc_sock_accept(int sock, int timeout, char **peer_host, uint16_t *peer_port);

/**
 * @brief Create a listening socket.
 *
 * @param[in] address IP address to listen on.
 * @param[in] port Port to listen on.
 * @return Listening socket, -1 on error.
 */
int nc_sock_listen(const char *address, uint16_t port);

/**
 * @brief Accept a new connection on a listening socket.
 *
 * @param[in] binds Structure with the listening sockets.
 * @param[in] bind_count Number of \p binds.
 * @param[in] timeout Timeout for accepting.
 * @param[out] host Host of the remote peer. Can be NULL.
 * @param[out] port Port of the new connection. Can be NULL.
 * @param[out] idx Index of the bind that was accepted. Can be NULL.
 * @return Accepted socket of the new connection, -1 on error.
 */
int nc_sock_accept_binds(struct nc_bind *binds, uint16_t bind_count, int timeout, char **host, uint16_t *port, uint16_t *idx);

/**
 * @brief Lock endpoint structures for reading and the specific endpoint.
 *
 * @param[in] name Name of the endpoint.
 * @param[in] ti Expected transport.
 * @param[out] idx Index of the endpoint. Optional.
 * @return Endpoint structure.
 */
struct nc_endpt *nc_server_endpt_lock_get(const char *name, NC_TRANSPORT_IMPL ti, uint16_t *idx);

/**
 * @brief Lock CH client structures for reading and the specific client.
 *
 * @param[in] name Name of the CH client.
 * @param[in] ti Expected transport.
 * @param[out] idx Index of the client. Optional.
 * @return CH client structure.
 */
struct nc_ch_client *nc_server_ch_client_lock(const char *name, NC_TRANSPORT_IMPL ti, uint16_t *idx);

/**
 * @brief Unlock CH client strcutures and the specific client.
 *
 * @param[in] endpt Locked CH client structure.
 */
void nc_server_ch_client_unlock(struct nc_ch_client *client);

/**
 * @brief Add a client Call Home bind, listen on it.
 *
 * @param[in] address Address to bind to.
 * @param[in] port Port to bind to.
 * @param[in] ti Transport to use.
 * @return 0 on success, -1 on error.
 */
int nc_client_ch_add_bind_listen(const char *address, uint16_t port, NC_TRANSPORT_IMPL ti);

/**
 * @brief Remove a client Call Home bind, stop listening on it.
 *
 * @param[in] address Address of the bind. NULL matches any address.
 * @param[in] port Port of the bind. 0 matches all ports.
 * @param[in] ti Transport of the bind. 0 matches all transports.
 * @return 0 on success, -1 on no matches found.
 */
int nc_client_ch_del_bind(const char *address, uint16_t port, NC_TRANSPORT_IMPL ti);

/**
 * @brief Connect to a listening NETCONF client using Call Home.
 *
 * @param[in] host Hostname to connect to.
 * @param[in] port Port to connect to.
 * @param[in] ti Transport fo the connection.
 * @param[out] session New Call Home session.
 * @return NC_MSG_HELLO on success, NC_MSG_BAD_HELLO on client \<hello\> message
 *         parsing fail, NC_MSG_WOULDBLOCK on timeout, NC_MSG_ERROR on other errors.
 */
NC_MSG_TYPE nc_connect_callhome(const char *host, uint16_t port, NC_TRANSPORT_IMPL ti, struct nc_session **session);

void nc_init(void);

void nc_destroy(void);

#ifdef NC_ENABLED_SSH

/**
 * @brief Accept a server Call Home connection on a socket.
 *
 * @param[in] sock Socket with a new connection.
 * @param[in] host Hostname of the server.
 * @param[in] port Port of the server.
 * @param[in] ctx Context for the session. Can be NULL.
 * @param[in] timeout Transport operations timeout in msec.
 * @return New session, NULL on error.
 */
struct nc_session *nc_accept_callhome_ssh_sock(int sock, const char *host, uint16_t port, struct ly_ctx *ctx, int timeout);

/**
 * @brief Establish SSH transport on a socket.
 *
 * @param[in] session Session structure of the new connection.
 * @param[in] sock Socket of the new connection.
 * @param[in] timeout Transport operations timeout in msec (not SSH authentication one).
 * @return 1 on success, 0 on timeout, -1 on error.
 */
int nc_accept_ssh_session(struct nc_session *session, int sock, int timeout);

/**
 * @brief Callback called when a new SSH message is received.
 *
 * @param[in] sshsession SSH session the message arrived on.
 * @param[in] msg SSH message itself.
 * @param[in] data NETCONF session running on \p sshsession.
 * @return 0 if the message was handled, 1 if it is left up to libssh.
 */
int nc_sshcb_msg(ssh_session sshsession, ssh_message msg, void *data);

void nc_server_ssh_clear_opts(struct nc_server_ssh_opts *opts);

void nc_client_ssh_destroy_opts(void);

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

struct nc_session *nc_accept_callhome_tls_sock(int sock, const char *host, uint16_t port, struct ly_ctx *ctx, int timeout);

/**
 * @brief Establish TLS transport on a socket.
 *
 * @param[in] session Session structure of the new connection.
 * @param[in] sock Socket of the new connection.
 * @param[in] timeout Transport operations timeout in msec.
 * @return 1 on success, 0 on timeout, -1 on error.
 */
int nc_accept_tls_session(struct nc_session *session, int sock, int timeout);

void nc_server_tls_clear_opts(struct nc_server_tls_opts *opts);

void nc_client_tls_destroy_opts(void);

#endif /* NC_ENABLED_TLS */

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
 * @param[in] io_timeout Timeout in milliseconds. Negative value means infinite timeout,
 *            zero value causes to return immediately.
 * @param[out] data XML tree built from the read data.
 * @return Type of the read message. #NC_MSG_WOULDBLOCK is returned if timeout is positive
 * (or zero) value and it passed out without any data on the wire. #NC_MSG_ERROR is
 * returned on error and #NC_MSG_NONE is never returned by this function.
 */
NC_MSG_TYPE nc_read_msg_poll_io(struct nc_session* session, int io_timeout, struct lyxml_elem **data);

/**
 * @brief Read message from the wire.
 *
 * Accepts hello, rpc, rpc-reply and notification. Received string is transformed into
 * libyang XML tree and the message type is detected from the top level element.
 *
 * @param[in] session NETCONF session from which the message is being read.
 * @param[in] io_timeout Timeout in milliseconds. Negative value means infinite timeout,
 *            zero value causes to return immediately.
 * @param[out] data XML tree built from the read data.
 * @param[in] passing_io_lock True if \p session IO lock is already held. This function always unlocks
 *            it before returning!
 * @return Type of the read message. #NC_MSG_WOULDBLOCK is returned if timeout is positive
 * (or zero) value and it passed out without any data on the wire. #NC_MSG_ERROR is
 * returned on error and #NC_MSG_NONE is never returned by this function.
 */
NC_MSG_TYPE nc_read_msg_io(struct nc_session* session, int io_timeout, struct lyxml_elem **data, int passing_io_lock);

/**
 * @brief Write message into wire.
 *
 * @param[in] session NETCONF session to which the message will be written.
 * @param[in] io_timeout Timeout in milliseconds. Negative value means infinite timeout,
 *            zero value causes to return immediately.
 * @param[in] type The type of the message to write, specified as #NC_MSG_TYPE value. According to the type, the
 * specific additional parameters are required or accepted:
 * - #NC_MSG_RPC
 *   - `struct lyd_node *op;` - operation (content of the \<rpc/\> to be sent. Required parameter.
 *   - `const char *attrs;` - additional attributes to be added into the \<rpc/\> element.
 *     Required parameter.
 *     `message-id` attribute is added automatically and default namespace is set to #NC_NS_BASE.
 *     Optional parameter.
 * - #NC_MSG_REPLY
 *   - `struct lyxml_node *rpc_elem;` - root of the RPC object to reply to. Required parameter.
 *   - `struct nc_server_reply *reply;` - RPC reply. Required parameter.
 * - #NC_MSG_NOTIF
 *   - `struct nc_server_notif *notif;` - notification object. Required parameter.
 * - #NC_MSG_HELLO
 *   - `const char **capabs;` - capabilities array ended with NULL. Required parameter.
 *   - `uint32_t *sid;` - session ID to be included in the hello message. Optional parameter.
 *
 * @return Type of the written message. #NC_MSG_WOULDBLOCK is returned if timeout is positive
 * (or zero) value and IO lock could not be acquired in that time. #NC_MSG_ERROR is
 * returned on error and #NC_MSG_NONE is never returned by this function.
 */
NC_MSG_TYPE nc_write_msg_io(struct nc_session *session, int io_timeout, int type, ...);

/**
 * @brief Check whether a session is still connected (on transport layer).
 *
 * @param[in] session Session to check.
 * @return 1 if connected, 0 if not.
 */
int nc_session_is_connected(struct nc_session *session);

#endif /* NC_SESSION_PRIVATE_H_ */
