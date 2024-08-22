/**
 * @file session_p.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 session manipulation
 *
 * @copyright
 * Copyright (c) 2017 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_SESSION_PRIVATE_H_
#define NC_SESSION_PRIVATE_H_

#define _GNU_SOURCE

#include <poll.h>
#include <pthread.h>
#include <stdint.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "session_client.h"
#include "session_server.h"
#include "session_server_ch.h"
#include "session_wrapper.h"

/**
 * Enumeration of diff operation types.
 */
typedef enum {
    NC_OP_UNKNOWN = 0,
    NC_OP_NONE,
    NC_OP_CREATE,
    NC_OP_DELETE,
    NC_OP_REPLACE
} NC_OPERATION;

/**
 * Enumeration of key or certificate store type.
 */
typedef enum {
    NC_STORE_LOCAL,     /**< key/certificate is stored locally in the ietf-netconf-server YANG data */
    NC_STORE_KEYSTORE,  /**< key/certificate is stored externally in a keystore module YANG data */
    NC_STORE_TRUSTSTORE, /**< key/certificate is stored externally in a truststore module YANG data */
    NC_STORE_SYSTEM     /**< key/certificate is managed by the system */
} NC_STORE_TYPE;

#ifdef NC_ENABLED_SSH_TLS

#include <curl/curl.h>
#include <libssh/libssh.h>

/* seconds */
#define NC_SSH_TIMEOUT 10

/* number of all supported authentication methods */
#define NC_SSH_AUTH_COUNT 3

/**
 * Enumeration of SSH public key formats.
 */
typedef enum {
    NC_PUBKEY_FORMAT_SSH, /**< see RFC 4253, section 6.6 */
    NC_PUBKEY_FORMAT_X509 /**< see RFC 5280 sec. 4.1.2.7 */
} NC_PUBKEY_FORMAT;

/**
 * Enumeration of private key file formats.
 */
typedef enum {
    NC_PRIVKEY_FORMAT_RSA,      /**< PKCS1 RSA format */
    NC_PRIVKEY_FORMAT_EC,       /**< SEC1 EC format */
    NC_PRIVKEY_FORMAT_X509,     /**< X509 (PKCS8) format */
    NC_PRIVKEY_FORMAT_OPENSSH,  /**< OpenSSH format */
    NC_PRIVKEY_FORMAT_UNKNOWN   /**< Unknown format */
} NC_PRIVKEY_FORMAT;

/**
 * @brief A basic certificate.
 */
struct nc_certificate {
    char *name; /**< Arbitrary name of the certificate. */
    char *data; /**< Base-64 encoded certificate. */
};

struct nc_certificate_bag {
    char *name;
    struct nc_certificate *certs;
    uint16_t cert_count;
};

/**
 * @brief An asymmetric key.
 */
struct nc_asymmetric_key {
    char *name;                     /**< Arbitrary name of the key. */

    NC_PUBKEY_FORMAT pubkey_type;   /**< Type of the public key. */
    char *pubkey_data;              /**< Base-64 encoded public key. */
    NC_PRIVKEY_FORMAT privkey_type; /**< Type of the private key. */
    char *privkey_data;             /**< Base-64 encoded private key. */

    struct nc_certificate *certs;   /**< The certificates associated with this key. */
    uint16_t cert_count;            /**< Number of certificates associated with this key. */
};

/**
 * @brief A symmetric key.
 */
struct nc_symmetric_key {
    char *name; /**< Arbitrary name of the key. */
    char *data; /**< Base-64 encoded key. */
};

/**
 * @brief A public key.
 */
struct nc_public_key {
    char *name;             /**< Arbitrary name of the public key. */
    NC_PUBKEY_FORMAT type;  /**< Type of the public key. */
    char *data;             /**< Base-64 encoded public key. */
};

struct nc_public_key_bag {
    char *name;
    struct nc_public_key *pubkeys;
    uint16_t pubkey_count;
};

struct nc_truststore {
    struct nc_certificate_bag *cert_bags;
    uint16_t cert_bag_count;

    struct nc_public_key_bag *pub_bags;
    uint16_t pub_bag_count;
};

/**
 * @brief Keystore YANG module representation.
 */
struct nc_keystore {
    struct nc_asymmetric_key *asym_keys;    /**< Stored asymmetric keys. */
    uint16_t asym_key_count;                /**< Count of stored asymmetric keys. */

    struct nc_symmetric_key *sym_keys;      /**< Stored symmetric keys. */
    uint16_t sym_key_count;                 /**< Count of stored symmetric keys. */
};

/**
 * @brief Tracks the state of a client's authentication.
 */
struct nc_auth_state {
    int methods;            /**< Bit field of authentication methods that the user supports. */
    int method_count;       /**< Number of authentication methods that the user supports. */
    int success_methods;    /**< Bit field of authentication methods that the user successfully authenticated with. */
    int success_count;      /**< Number of authentication methods that the user successfully authenticated with. */
};

/**
 * @brief A server's authorized client.
 */
struct nc_auth_client {
    char *username;                         /**< Arbitrary username. */

    NC_STORE_TYPE store;                    /**< Specifies how/where the client's public key is stored. */
    union {
        struct {
            struct nc_public_key *pubkeys;  /**< The client's public keys. */
            uint16_t pubkey_count;          /**< The number of client's public keys. */
        };
        char *ts_ref;                       /**< Name of the referenced truststore key. */
    };

    char *password;                         /**< Client's password */
    int kb_int_enabled;                     /**< Indicates that the client supports keyboard-interactive authentication. */
    int none_enabled;                       /**< Implies that the client supports the none authentication method. */
};

/**
 * @brief The server's hostkey.
 */
struct nc_hostkey {
    char *name;                         /**<  Arbitrary name of the host key. */

    NC_STORE_TYPE store;                /**< Specifies how/where the key is stored. */
    union {
        struct nc_asymmetric_key key;   /**< The server's hostkey. */
        char *ks_ref;                   /**< Name of the referenced key. */
    };
};

/**
 * @brief Server options for configuring the SSH transport protocol.
 */
struct nc_server_ssh_opts {
    struct nc_hostkey *hostkeys;            /**< Server's hostkeys. */
    uint16_t hostkey_count;                 /**< Number of server's hostkeys. */

    struct nc_auth_client *auth_clients;    /**< Server's authorized clients. */
    uint16_t client_count;                  /**< Number of server's authorized clients. */

    char *referenced_endpt_name;            /**< Reference to another endpoint (used for client authentication). */

    char *hostkey_algs;                     /**< Hostkey algorithms supported by the server. */
    char *encryption_algs;                  /**< Encryption algorithms supported by the server. */
    char *kex_algs;                         /**< Key exchange algorithms supported by the server. */
    char *mac_algs;                         /**< MAC algorithms supported by the server. */

    uint16_t auth_timeout;                  /**< Authentication timeout. */
};

/**
 * @brief Certificate grouping (either local-definition or truststore reference).
 */
struct nc_cert_grouping {
    NC_STORE_TYPE store;                    /**< Specifies how/where the certificates are stored. */
    union {
        struct {
            struct nc_certificate *certs;   /**< Local-defined certificates. */
            uint16_t cert_count;            /**< Certificate count. */
        };
        char *ts_ref;                       /**< Name of the referenced truststore certificate bag. */
    };
};

/**
 * @brief Storing downloaded data via CURL.
 */
struct nc_curl_data {
    unsigned char *data;    /**< Downloaded data */
    size_t size;            /**< Size of downloaded data */
};

/**
 * @brief Cert-to-name entries.
 */
struct nc_ctn {
    uint32_t id;                        /**< ID of the entry, the lower the higher priority */
    char *fingerprint;                  /**< Fingerprint of the entry */
    NC_TLS_CTN_MAPTYPE map_type;        /**< Specifies how to get the username from the certificate */
    char *name;                         /**< Username for this entry */
    struct nc_ctn *next;                /**< Linked-list reference to the next entry */
};

/**
 * @brief Server options for configuring the TLS transport protocol.
 */
struct nc_server_tls_opts {
    NC_STORE_TYPE store;                        /**< Specifies how/where the server identity is stored. */
    union {
        struct {
            NC_PUBKEY_FORMAT pubkey_type;       /**< Server public key type */
            char *pubkey_data;                  /**< Server's public key */

            NC_PRIVKEY_FORMAT privkey_type;     /**< Server private key type */
            char *privkey_data;                 /**< Server's private key */

            char *cert_data;                    /**< Server's certificate */
        };

        struct {
            char *key_ref;                      /**< Reference to the server's key */
            char *cert_ref;                     /**< Reference to the concrete server's certificate */
        };
    };

    struct nc_cert_grouping ca_certs;           /**< Client certificate authorities */
    struct nc_cert_grouping ee_certs;           /**< Client end-entity certificates */

    char *referenced_endpt_name;                /**< Reference to another endpoint (used for client authentication). */

    unsigned int tls_versions;                  /**< TLS versions */
    void *ciphers;                              /**< TLS ciphers */
    uint16_t cipher_count;                      /**< Number of TLS ciphers */

    struct nc_ctn *ctn;                         /**< Cert-to-name entries */
};

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Keepalives configuration data.
 */
struct nc_keepalives {
    int enabled;                /**< Indicates that keepalives are enabled. */
    uint16_t idle_time;         /**< Idle timeout. */
    uint16_t max_probes;        /**< Maximum number of probes. */
    uint16_t probe_interval;    /**< Probe interval. */
};

/**
 * @brief UNIX socket connection configuration.
 */
struct nc_server_unix_opts {
    char *address;  /**< Address of the socket. */
    mode_t mode;    /**< Socket's mode. */
    uid_t uid;      /**< Socket's uid. */
    gid_t gid;      /**< Socket's gid. */
};

/**
 * @brief Stores information about a bind.
 */
struct nc_bind {
    char *address;  /**< Bind's address. */
    uint16_t port;  /**< Bind's port. */
    int sock;       /**< Bind's socket. */
    int pollin;     /**< Specifies, which sockets to poll on. */
};

#ifdef NC_ENABLED_SSH_TLS

struct nc_client_ssh_opts {
    char *knownhosts_path;  /**< path to known_hosts file */
    NC_SSH_KNOWNHOSTS_MODE knownhosts_mode; /**< implies whether to check known_hosts or not */

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
    char *(*auth_password)(const char *, const char *, void *);
    char *(*auth_interactive)(const char *, const char *, const char *, int, void *);
    char *(*auth_privkey_passphrase)(const char *, void *);

    /* private data for the callbacks */
    void *auth_password_priv;
    void *auth_interactive_priv;
    void *auth_privkey_passphrase_priv;

    char *username;
};

struct nc_client_tls_opts {
    char *cert_path;
    char *key_path;

    char *ca_file;
    char *ca_dir;
};

#endif /* NC_ENABLED_SSH_TLS */

/* ACCESS unlocked */
struct nc_client_opts {
    char *schema_searchpath;
    int auto_context_fill_disabled;
    ly_module_imp_clb schema_clb;
    void *schema_clb_data;
    struct nc_keepalives ka;

    struct nc_bind *ch_binds;
    pthread_mutex_t ch_bind_lock;   /**< To avoid concurrent calls of poll and accept on the bound sockets **/

    struct {
        NC_TRANSPORT_IMPL ti;
        char *hostname;
    } *ch_binds_aux;
    uint16_t ch_bind_count;
};

/* ACCESS unlocked */
struct nc_client_context {
    unsigned int refcount;
    struct nc_client_opts opts;

#ifdef NC_ENABLED_SSH_TLS
    struct nc_client_ssh_opts ssh_opts;
    struct nc_client_ssh_opts ssh_ch_opts;

    struct nc_client_tls_opts tls_opts;
    struct nc_client_tls_opts tls_ch_opts;
#endif /* NC_ENABLED_SSH_TLS */
};

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Stores time information used for creating certificate expiration intervals.
 */
struct nc_cert_exp_time {
    int months;
    int weeks;
    int days;
    int hours;
};

/**
 * @brief Stores information about a certificate expiration notification.
 */
struct nc_cert_expiration {
    time_t *starts_of_intervals;    /**< Array of the starting times of the certificate expiration notification intervals. */
    int current_interval;           /**< Index of the current interval. */

    time_t expiration_time;         /**< Time of the certificate expiration. */
    time_t notif_time;              /**< Time of the next notification. */

    char *xpath;                    /**< XPath to the certificate. */
};

/**
 * @brief Certificate expiration notification thread data.
 */
struct nc_cert_exp_notif_thread_arg {
    nc_cert_exp_notif_clb clb;      /**< Callback called when a certificate expiration notification is ready to be sent. */
    void *clb_data;                 /**< Data passed to the callback. */
    void (*clb_free_data)(void *);  /**< Callback to free the user data. */
};

/**
 * @brief Auxiliary structure used for creating the XPaths to the certificates.
 */
struct nc_cert_path_aux {
    const char *ch_client_name;
    const char *endpt_name;
    const char *ca_cert_name;
    const char *ee_cert_name;
    const char *ks_askey_name;
    const char *ks_cert_name;
    const char *ts_cbag_name;
    const char *ts_cert_name;
};

/**
 * @brief Update the values of the nc_cert_path_aux members.
 */
#define NC_CERT_EXP_UPDATE_CERT_PATH(cp, ch_client, endpt, ca_cert, \
                ee_cert, ks_askey, ks_cert, ts_cbag, ts_cert) \
    (cp)->ch_client_name = (ch_client); \
    (cp)->endpt_name = (endpt); \
    (cp)->ca_cert_name = (ca_cert); \
    (cp)->ee_cert_name = (ee_cert); \
    (cp)->ks_askey_name = (ks_askey); \
    (cp)->ks_cert_name = (ks_cert); \
    (cp)->ts_cbag_name = (ts_cbag); \
    (cp)->ts_cert_name = (ts_cert)

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Call Home client thread data.
 */
struct nc_ch_client_thread_arg {
    char *client_name;

    const struct ly_ctx *(*acquire_ctx_cb)(void *cb_data);  /**< acquiring libyang context cb */
    void (*release_ctx_cb)(void *cb_data);                  /**< releasing libyang context cb */
    void *ctx_cb_data;                                      /**< acq/rel cb data */
    int (*new_session_cb)(const char *client_name, struct nc_session *new_session, void *user_data);    /**< creating new session cb */
    void *new_session_cb_data;                              /**< new session cb data */

    int thread_running;         /**< A boolean value that is truthy while the underlying Call Home thread is running */
    pthread_mutex_t cond_lock;  /**< Condition's lock used for signalling the thread to terminate */
    pthread_cond_t cond;        /**< Condition used for signalling the thread to terminate */
};

struct nc_server_opts {
    /* ACCESS unlocked */
    ATOMIC_T wd_basic_mode;
    ATOMIC_T wd_also_supported;
    uint32_t capabilities_count;
    char **capabilities;

    char *(*content_id_clb)(void *user_data);
    void *content_id_data;

    void (*content_id_data_free)(void *data);

    uint16_t idle_timeout;

#ifdef NC_ENABLED_SSH_TLS
    char *authkey_path_fmt;             /**< Path to users' public keys that may contain tokens with special meaning. */
    char *pam_config_name;              /**< PAM configuration file name. */
    int (*interactive_auth_clb)(const struct nc_session *session, ssh_session ssh_sess, ssh_message msg, void *user_data);
    void *interactive_auth_data;
    void (*interactive_auth_data_free)(void *data);

    int (*user_verify_clb)(const struct nc_session *session);
#endif /* NC_ENABLED_SSH_TLS */

    pthread_rwlock_t config_lock;

#ifdef NC_ENABLED_SSH_TLS
    struct nc_keystore keystore;        /**< store for server's keys/certificates */
    struct nc_truststore truststore;    /**< store for server client's keys/certificates */
#endif /* NC_ENABLED_SSH_TLS */

    struct nc_bind *binds;
    pthread_mutex_t bind_lock;          /**< To avoid concurrent calls of poll and accept on the bound sockets **/
    struct nc_endpt {
        char *name;
#ifdef NC_ENABLED_SSH_TLS
        char *referenced_endpt_name;
#endif /* NC_ENABLED_SSH_TLS */
        NC_TRANSPORT_IMPL ti;
        struct nc_keepalives ka;

        union {
#ifdef NC_ENABLED_SSH_TLS
            struct nc_server_ssh_opts *ssh;

            struct nc_server_tls_opts *tls;
#endif /* NC_ENABLED_SSH_TLS */
            struct nc_server_unix_opts *unixsock;
        } opts;
    } *endpts;
    uint16_t endpt_count;

    /* ACCESS locked, add/remove CH clients - WRITE lock ch_client_lock
     *                modify CH clients - READ lock ch_client_lock + ch_client_lock */
    struct nc_ch_client {
        char *name;
        pthread_t tid;                                  /**< Call Home client's thread ID */
        struct nc_ch_client_thread_arg *thread_data;    /**< Data of the Call Home client's thread */

        struct nc_ch_endpt {
            char *name;
#ifdef NC_ENABLED_SSH_TLS
            char *referenced_endpt_name;
#endif /* NC_ENABLED_SSH_TLS */
            NC_TRANSPORT_IMPL ti;

            char *src_addr;                             /**< IP address to bind to when connecting to a Call Home client. */
            uint16_t src_port;                          /**< Port to bind to when connecting to a Call Home client. */
            char *dst_addr;                             /**< IP address of the Call Home client. */
            uint16_t dst_port;                          /**< Port of the Call Home client. */

            int sock_pending;
            struct nc_keepalives ka;

            union {
#ifdef NC_ENABLED_SSH_TLS
                struct nc_server_ssh_opts *ssh;

                struct nc_server_tls_opts *tls;
#endif /* NC_ENABLED_SSH_TLS */
            } opts;
        } *ch_endpts;
        uint16_t ch_endpt_count;

        NC_CH_CONN_TYPE conn_type;
        struct {
            uint16_t period;
            time_t anchor_time;
            uint16_t idle_timeout;
        };

        NC_CH_START_WITH start_with;
        uint8_t max_attempts;
        uint16_t max_wait;
        uint32_t id;
        pthread_mutex_t lock;
    } *ch_clients;
    uint16_t ch_client_count;
    pthread_rwlock_t ch_client_lock;

#ifdef NC_ENABLED_SSH_TLS
    struct nc_ch_dispatch_data {
        nc_server_ch_session_acquire_ctx_cb acquire_ctx_cb;
        nc_server_ch_session_release_ctx_cb release_ctx_cb;
        void *ctx_cb_data;
        nc_server_ch_new_session_cb new_session_cb;
        void *new_session_cb_data;
    } ch_dispatch_data;
#endif /* NC_ENABLED_SSH_TLS */

    /* Atomic IDs */
    ATOMIC_T new_session_id;
    ATOMIC_T new_client_id;

#ifdef NC_ENABLED_SSH_TLS
    struct {
        pthread_t tid;                      /**< Thread ID of the certificate expiration notification thread. */
        int thread_running;                 /**< Flag representing the runningness of the cert exp notification thread. */
        pthread_mutex_t lock;               /**< Certificate expiration notification thread's data and cond lock. */
        pthread_cond_t cond;                /**< Condition for the certificate expiration notification thread. */

        /**
         * @brief Intervals for certificate expiration notifications.
         */
        struct nc_interval {
            struct nc_cert_exp_time anchor; /**< Lower bound of the given interval. */
            struct nc_cert_exp_time period; /**< Period of the given interval. */
        } *intervals;
        int interval_count;                 /**< Number of intervals. */
    } cert_exp_notif;
#endif
};

/**
 * Sleep time in usec to wait between nc_recv_notif() calls.
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
 * Timeout in msec for a thread to wait for its turn to work with a pollsession structure.
 */
#define NC_PS_QUEUE_TIMEOUT 5000

/**
 * Time slept in msec if no endpoint was created for a running Call Home client.
 */
#define NC_CH_NO_ENDPT_WAIT 1000

/**
 * Time slept in msec between Call Home thread session idle timeout checks.
 */
#define NC_CH_THREAD_IDLE_TIMEOUT_SLEEP 1000

/**
 * Timeout in msec for a Call Home socket to establish its connection.
 */
#define NC_CH_CONNECT_TIMEOUT 500

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
 * @brief Container to serialize RPC messages
 */
struct nc_msg_cont {
    struct ly_in *msg;
    NC_MSG_TYPE type;         /**< can be either NC_MSG_REPLY or NC_MSG_NOTIF */
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
    pthread_mutex_t *io_lock;    /**< input/output lock, note that in case of libssh TI, it will be shared with
                                      other NETCONF sessions on the same SSH session (but different SSH channel) */

    union {
        struct {
            int in;              /**< input file descriptor */
            int out;             /**< output file descriptor */
        } fd;                    /**< NC_TI_FD transport implementation structure */
        struct {
            int sock;            /**< socket file descriptor */
        } unixsock;              /**< NC_TI_UNIX transport implementation structure */
#ifdef NC_ENABLED_SSH_TLS
        struct {
            ssh_channel channel;
            ssh_session session;
            struct nc_session *next; /**< pointer to the next NETCONF session on the same
                                          SSH session, but different SSH channel. If no such session exists, it is NULL.
                                          otherwise there is a ring list of the NETCONF sessions */
        } libssh;

        struct {
            void *session;
            void *config;
            struct nc_tls_ctx ctx;
        } tls;
#endif /* NC_ENABLED_SSH_TLS */
    } ti;                          /**< transport implementation data */
    char *username;
    char *host;
    uint16_t port;
    char *path;                    /**< socket path in case of unix socket */

    /* other */
    struct ly_ctx *ctx;            /**< libyang context of the session */
    void *data;                    /**< arbitrary user data */
    uint8_t flags;                 /**< various flags of the session */
#define NC_SESSION_SHAREDCTX 0x01
#define NC_SESSION_CALLHOME 0x02    /**< session is Call Home and ch_lock is initialized */
#define NC_SESSION_CH_THREAD 0x04   /**< protected by ch_lock */

    union {
        struct {
            /* client side only data */
            uint64_t msgid;
            char **cpblts;                 /**< list of server's capabilities on client side */
            pthread_mutex_t msgs_lock;     /**< lock for the msgs buffer */
            struct nc_msg_cont *msgs;      /**< queue for messages received of different type than expected */
            ATOMIC_T ntf_thread_count;     /**< number of running notification threads */
            ATOMIC_T ntf_thread_running;   /**< flag whether there are notification threads for this session running or not */
            struct lyd_node *ext_data;     /**< LY ext data used in the context callback */

            /* client flags */
            /* some server modules failed to load so the data from them will be ignored - not use strict flag for parsing */
#           define NC_SESSION_CLIENT_NOT_STRICT 0x08
        } client;
        struct {
            /* server side only data */
            struct timespec session_start;  /**< real time the session was created */
            time_t last_rpc;                /**< monotonic time (seconds) the last RPC was received on this session */

            pthread_mutex_t ntf_status_lock;    /**< lock for ntf_status */
            uint32_t ntf_status;                /**< flag (count) whether the session is subscribed to notifications */

            pthread_mutex_t rpc_lock;    /**< lock indicating RPC processing, this lock is always locked before io_lock!! */
            pthread_cond_t rpc_cond;     /**< RPC condition (tied with rpc_lock and rpc_inuse) */
            int rpc_inuse;               /**< variable indicating whether there is RPC being processed or not (tied with
                                              rpc_cond and rpc_lock) */

            pthread_mutex_t ch_lock;       /**< Call Home thread lock */
            pthread_cond_t ch_cond;        /**< Call Home thread condition */

            /* server flags */
#ifdef NC_ENABLED_SSH_TLS
            /* SSH session authenticated */
#           define NC_SESSION_SSH_AUTHENTICATED 0x10
            /* netconf subsystem requested */
#           define NC_SESSION_SSH_SUBSYS_NETCONF 0x20
            uint16_t ssh_auth_attempts;    /**< number of failed SSH authentication attempts */

            void *client_cert;                /**< TLS client certificate if used for authentication */
#endif /* NC_ENABLED_SSH_TLS */
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
    nc_notif_dispatch_clb notif_clb;
    void *user_data;

    void (*free_data)(void *);
};

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief PAM callback arguments.
 */
struct nc_pam_thread_arg {
    ssh_message msg;                /**< libssh message */
    struct nc_session *session;     /**< NETCONF session */
};

/**
 * @brief Converts private key format to a string.
 * This string is the same, as in a PKCS#1 Private key format, meaning
 * ---- BEGIN (string) PRIVATE KEY ----. The string can be empty for some types.
 *
 * @param[in] format Private key format.
 * @return String representing the private key or NULL.
 */
const char *nc_privkey_format_to_str(NC_PRIVKEY_FORMAT format);

/**
 * @brief Checks if the given base64 belongs to a public key in the SubjectPublicKeyInfo format.
 *
 * @param[in] b64 Base64 encoded data.
 *
 * @return -1 on error, 0 if it is not SPKI public key, 1 if it is a public key in the SPKI format.
 */
int nc_is_pk_subject_public_key_info(const char *b64);

/**
 * @brief Import a Base64 DER encoded certificate data.
 *
 * @param[in] data Base64 DER encoded certificate data.
 * @return Imported certificate on success, NULL on error.
 */
void * nc_base64der_to_cert(const char *data);

#endif /* NC_ENABLED_SSH_TLS */

void *nc_realloc(void *ptr, size_t size);

/**
 * @brief Set the andress and port of an endpoint.
 *
 * @param[in] endpt Endpoint to set the address/port for.
 * @param[in] bind Bind to set the address/port for.
 * @param[in] address Address to set, can be a path to a UNIX socket.
 * @param[in] port Port to set, invalid for UNIX socket endpoint.
 * @return 0 on success, 1 on error.
 */
int nc_server_set_address_port(struct nc_endpt *endpt, struct nc_bind *bind, const char *address, uint16_t port);

/**
 * @brief Frees memory allocated by a UNIX socket endpoint.
 *
 * @param[in] endpt UNIX socket endpoint.
 * @param[in] bind UNIX socket bind.
 */
void _nc_server_del_endpt_unix_socket(struct nc_endpt *endpt, struct nc_bind *bind);

struct passwd *nc_getpw(uid_t uid, const char *username, struct passwd *pwd_buf, char **buf, size_t *buf_size);

NC_MSG_TYPE nc_send_msg_io(struct nc_session *session, int io_timeout, struct lyd_node *op);

/**
 * @brief Get current clock (uses COMPAT_CLOCK_ID) time with an offset.
 *
 * @param[out] ts Current time offset by @p add_ms.
 * @param[in] add_ms Number of milliseconds to add.
 */
void nc_timeouttime_get(struct timespec *ts, uint32_t add_ms);

/**
 * @brief Get time difference based on the current time (uses COMPAT_CLOCK_ID).
 *
 * @param[in] ts Timespec structure holding real time from which the current time is going to be subtracted.
 * @return Time difference in milliseconds.
 */
int32_t nc_timeouttime_cur_diff(const struct timespec *ts);

/**
 * @brief Get current CLOCK_REALTIME time.
 *
 * @param[out] ts Current real time.
 */
void nc_realtime_get(struct timespec *ts);

/**
 * @brief Perform poll(2) with signal support and timeout adjustment.
 *
 * @param[in] pfd Poll structure to use.
 * @param[in] pfd_count Count of FD in @p pfd.
 * @param[in] timeout_ms Timeout to use.
 * @return poll(2) return.
 */
int nc_poll(struct pollfd *pfd, uint16_t pfd_count, int timeout);

/**
 * @brief Enables/disables TCP keepalives.
 *
 * @param[in] sock Socket to set this option for.
 * @param[in] ka Keepalives to set.
 * @return 0 on success, -1 on fail.
 */
int nc_sock_configure_ka(int sock, const struct nc_keepalives *ka);

struct nc_session *nc_new_session(NC_SIDE side, int shared_ti);

int nc_session_rpc_lock(struct nc_session *session, int timeout, const char *func);

int nc_session_rpc_unlock(struct nc_session *session, int timeout, const char *func);

/**
 * @brief Lock IO lock on a session.
 *
 * @param[in] session Session to lock.
 * @param[in] timeout Timeout in msec to use.
 * @param[in] func Caller function for logging.
 * @return 1 on success;
 * @return 0 on timeout;
 * @return -1 on error.
 */
int nc_session_io_lock(struct nc_session *session, int timeout, const char *func);

/**
 * @brief Unlock IO lock on a session.
 *
 * @param[in] session Session to unlock.
 * @param[in] func Caller function for logging.
 * @return 1 on success;
 * @return -1 on error.
 */
int nc_session_io_unlock(struct nc_session *session, const char *func);

/**
 * @brief Lock MSGS lock on a session.
 *
 * @param[in] session Session to lock.
 * @param[in,out] timeout Timeout in msec to use. If positive and on successful lock, is updated based on what was elapsed.
 * @param[in] func Caller function for logging.
 * @return 1 on success;
 * @return 0 on timeout;
 * @return -1 on error.
 */
int nc_session_client_msgs_lock(struct nc_session *session, int *timeout, const char *func);

/**
 * @brief Unlock MSGS lock on a session.
 *
 * @param[in] session Session to unlock.
 * @param[in] func Caller function for logging.
 * @return 1 on success;
 * @return -1 on error.
 */
int nc_session_client_msgs_unlock(struct nc_session *session, const char *func);

int nc_ps_lock(struct nc_pollsession *ps, uint8_t *id, const char *func);

int nc_ps_unlock(struct nc_pollsession *ps, uint8_t id, const char *func);

int nc_client_session_new_ctx(struct nc_session *session, struct ly_ctx *ctx);

/**
 * @brief Fill libyang context in @p session. Context models are based on the stored session
 *        capabilities. If the server does not support \<get-schema\>, the models are searched
 *        for in the directory set using nc_client_schema_searchpath().
 *
 * @param[in] session Session to create the context for.
 * @return 0 on success, 1 on some missing schemas, -1 on error.
 */
int nc_ctx_check_and_fill(struct nc_session *session);

/**
 * @brief Perform NETCONF handshake on @p session.
 *
 * @param[in] session NETCONF session to use.
 * @return NC_MSG_HELLO on success, NC_MSG_BAD_HELLO on client \<hello\> message parsing fail
 * (server-side only), NC_MSG_WOULDBLOCK on timeout, NC_MSG_ERROR on other error.
 */
NC_MSG_TYPE nc_handshake_io(struct nc_session *session);

/**
 * @brief Bind a socket to an address and a port.
 *
 * @param[in] sock Socket to bind.
 * @param[in] address Address to bind to.
 * @param[in] port Port to bind to.
 * @param[in] is_ipv4 Whether the address is IPv4 or IPv6.
 * @return 0 on success, -1 on error.
 */
int nc_sock_bind_inet(int sock, const char *address, uint16_t port, int is_ipv4);

/**
 * @brief Create a socket connection.
 *
 * @param[in] src_addr Address to connect from.
 * @param[in] src_port Port to connect from.
 * @param[in] dst_addr Address to connect to.
 * @param[in] dst_port Port to connect to.
 * @param[in] timeout_ms Timeout in ms for blocking the connect + select call (-1 for infinite).
 * @param[in] ka Keepalives parameters.
 * @param[in,out] sock_pending Previous pending socket. If set, equal to -1, and the connection is still in progress
 * after @p timeout, it is set to the pending socket but -1 is returned. If NULL, the socket is closed on timeout.
 * @param[out] ip_host Optional parameter with string IP address of the connected host.
 * @return Connected socket or -1 on error.
 */
int nc_sock_connect(const char *src_addr, uint16_t src_port, const char *dst_addr, uint16_t dst_port, int timeout_ms,
        struct nc_keepalives *ka, int *sock_pending, char **ip_host);

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
 * @brief Create a listening socket (AF_INET or AF_INET6).
 *
 * @param[in] address IP address to listen on.
 * @param[in] port Port to listen on.
 * @return Listening socket, -1 on error.
 */
int nc_sock_listen_inet(const char *address, uint16_t port);

/**
 * @brief Accept a new connection on a listening socket.
 *
 * @param[in] binds Structure with the listening sockets.
 * @param[in] bind_count Number of @p binds.
 * @param[in] bind_lock Lock for avoiding concurrent poll/accept on a single bind.
 * @param[in] timeout Timeout for accepting.
 * @param[out] host Host of the remote peer. Can be NULL.
 * @param[out] port Port of the new connection. Can be NULL.
 * @param[out] idx Index of the bind that was accepted. Can be NULL.
 * @param[out] sock Accepted socket, if any.
 * @return -1 on error.
 * @return 0 on timeout.
 * @return 1 if a socket was accepted.
 */
int nc_sock_accept_binds(struct nc_bind *binds, uint16_t bind_count, pthread_mutex_t *bind_lock, int timeout,
        char **host, uint16_t *port, uint16_t *idx, int *sock);

/**
 * @brief Gets an endpoint structure based on its name.
 *
 * @param[in] name The name of the endpoint.
 * @param[out] endpt Pointer to the endpoint structure.
 * @return 0 on success, 1 on failure.
 */
int nc_server_get_referenced_endpt(const char *name, struct nc_endpt **endpt);

/**
 * @brief Add a client Call Home bind, listen on it.
 *
 * @param[in] address Address to bind to.
 * @param[in] port Port to bind to.
 * @param[in] hostname Expected server hostname, may be NULL.
 * @param[in] ti Transport to use.
 * @return 0 on success, -1 on error.
 */
int nc_client_ch_add_bind_listen(const char *address, uint16_t port, const char *hostname, NC_TRANSPORT_IMPL ti);

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

#ifdef NC_ENABLED_SSH_TLS

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
int nc_accept_ssh_session(struct nc_session *session, struct nc_server_ssh_opts *opts, int sock, int timeout);

/**
 * @brief Process a SSH message.
 *
 * @param[in] session Session structure of the connection.
 * @param[in] opts Endpoint SSH options on which the session was created.
 * @param[in] msg SSH message itself.
 * @param[in] auth_state State of the authentication.
 * @return 0 if the message was handled, 1 if it is left up to libssh.
 */
int nc_session_ssh_msg(struct nc_session *session, struct nc_server_ssh_opts *opts, ssh_message msg, struct nc_auth_state *auth_state);

void nc_client_ssh_destroy_opts(void);
void _nc_client_ssh_destroy_opts(struct nc_client_ssh_opts *opts);

struct nc_session *nc_accept_callhome_tls_sock(int sock, const char *host, uint16_t port, struct ly_ctx *ctx,
        int timeout, const char *peername);

/**
 * @brief Establish TLS transport on a socket.
 *
 * @param[in] session Session structure of the new connection.
 * @param[in] sock Socket of the new connection.
 * @param[in] timeout Transport operations timeout in msec.
 * @return 1 on success, 0 on timeout, -1 on error.
 */
int nc_accept_tls_session(struct nc_session *session, struct nc_server_tls_opts *opts, int sock, int timeout);

void nc_client_tls_destroy_opts(void);
void _nc_client_tls_destroy_opts(struct nc_client_tls_opts *opts);

/**
 * @brief Fetch CRLs from the x509v3 CRLDistributionPoints extension.
 *
 * @param[in] leaf_cert Server/client certificate.
 * @param[in] cert_store CA/EE certificates store.
 * @param[out] crl_store Created CRL store.
 * @return 0 on success, 1 on error.
 */
int nc_session_tls_crl_from_cert_ext_fetch(void *leaf_cert, void *cert_store, void **crl_store);

#endif /* NC_ENABLED_SSH_TLS */

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
 * @param[out] msg Input handled with the NETCONF message (application layer data).
 * @return 1 on success.
 * @return 0 on timeout.
 * @return -1 on error.
 * @return -2 on malformed message error.
 */
int nc_read_msg_poll_io(struct nc_session *session, int io_timeout, struct ly_in **msg);

/**
 * @brief Read a message from the wire.
 *
 * @param[in] session NETCONF session from which the message is being read.
 * @param[in] io_timeout Timeout in milliseconds. Negative value means infinite timeout,
 *            zero value causes to return immediately.
 * @param[out] msg Input handled with the NETCONF message (application layer data).
 * @param[in] passing_io_lock True if @p session IO lock is already held. This function always unlocks
 *            it before returning!
 * @return 1 on success.
 * @return 0 on timeout.
 * @return -1 on error.
 * @return -2 on malformed message error.
 */
int nc_read_msg_io(struct nc_session *session, int io_timeout, struct ly_in **msg, int passing_io_lock);

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
 *   - `const char *attrs;` - additional attributes to be added into the \<rpc/\> element. Required parameter.
 * - #NC_MSG_REPLY
 *   - `struct lyd_node_opaq *rpc_envp;` - parsed envelopes of the RPC to reply to. Required parameter.
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
int nc_session_is_connected(const struct nc_session *session);

#endif /* NC_SESSION_PRIVATE_H_ */
