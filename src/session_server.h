/**
 * @file session_server.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 session server manipulation
 *
 * @copyright
 * Copyright (c) 2015 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_SESSION_SERVER_H_
#define NC_SESSION_SERVER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <libyang/libyang.h>
#include <stdint.h>
#include <sys/types.h>

#include "netconf.h"
#include "session.h"

#ifdef NC_ENABLED_SSH_TLS
# include <libssh/callbacks.h>
# include <libssh/libssh.h>
# include <libssh/server.h>
#endif /* NC_ENABLED_SSH_TLS */

/**
 * @defgroup server_session Server Session
 * @ingroup server
 *
 * @brief Server-side NETCONF session manipulation.
 * @{
 */

/**
 * @brief Prototype of callbacks that are called if some RPCs are received.
 *
 * If @p session termination reason is changed in the callback, one last reply
 * is sent and then the session is considered invalid.
 *
 * The callback is set via nc_set_global_rpc_clb().
 *
 * @param[in] rpc Parsed client RPC request.
 * @param[in] session Session the RPC arrived on.
 * @return Server reply. If NULL, an operation-failed error will be sent to the client.
 */
typedef struct nc_server_reply *(*nc_rpc_clb)(struct lyd_node *rpc, struct nc_session *session);

/**
 * @brief Callback for certificate expiration notification.
 *
 * This callback is called when a certificate expiration notification is generated.
 * It is up to the user to decide what to do with the notification.
 *
 * In case an error occurs and you wish to terminate the notification thread,
 * call nc_server_notif_cert_expiration_thread_stop().
 *
 * @param[in] expiration_time Expiration time of the certificate obtained via ly_time_time2str().
 * @param[in] xpath Xpath of the certificate. Can be used to create the notification data.
 * @param[in] user_data Arbitrary user data.
 */
typedef void (*nc_cert_exp_notif_clb)(const char *expiration_time, const char *xpath, void *user_data);

/**
 * @brief Set the termination reason for a session. Use only in #nc_rpc_clb callbacks.
 *
 * @param[in] session Session to modify.
 * @param[in] reason Reason of termination.
 */
void nc_session_set_term_reason(struct nc_session *session, NC_SESSION_TERM_REASON reason);

/**
 * @brief Set the session-id of the session responsible for this session's termination.
 *
 * @param[in] session Session to modify. Must have term_reason set to #NC_SESSION_TERM_KILLED.
 * @param[in] sid SID of the killing session.
 */
void nc_session_set_killed_by(struct nc_session *session, uint32_t sid);

/**
 * @brief Set the status of a session.
 *
 * @param[in] session Session to modify.
 * @param[in] status Status of the session.
 */
void nc_session_set_status(struct nc_session *session, NC_STATUS status);

/**
 * @brief Set a global nc_rpc_clb that is called if the particular RPC request is
 * received and the private field in the corresponding RPC schema node is NULL.
 *
 * If this callback is set, the default callbacks for "get-schema" and "close-session" are not used.
 *
 * @param[in] clb An user-defined nc_rpc_clb function callback, NULL to default.
 */
void nc_set_global_rpc_clb(nc_rpc_clb clb);

/**
 * @brief Default RPC callback used for "ietf-netconf-monitoring:get-schema" RPC if no other specific
 * or global callback is set.
 *
 * @param[in] rpc Received RPC.
 * @param[in] session NC session @p rpc was received on.
 * @return Server reply.
 */
struct nc_server_reply *nc_clb_default_get_schema(struct lyd_node *rpc, struct nc_session *session);

/**
 * @brief Default RPC callback used for "ietf-netconf:close-session" RPC if no other specific
 * or global callback is set.
 *
 * @param[in] rpc Received RPC.
 * @param[in] session NC session @p rpc was received on.
 * @return Server reply.
 */
struct nc_server_reply *nc_clb_default_close_session(struct lyd_node *rpc, struct nc_session *session);

/** @} Server Session */

/**
 * @defgroup server_functions Server Functions
 * @ingroup server
 * @{
 */

/**
 * @brief Initialize libssh and/or libssl/libcrypto and the server.
 *
 * Must be called before other nc_server* functions.
 *
 * @return 0 on success, -1 on error.
 */
int nc_server_init(void);

/**
 * @brief Destroy any dynamically allocated libssh and/or libssl/libcrypto and
 *        server resources.
 */
void nc_server_destroy(void);

/**
 * @brief Initialize a context which can serve as a default server context.
 *
 * Loads the default modules ietf-netconf and ietf-netconf-monitoring and their enabled features - ietf-netconf
 * enabled features are : writable-running, candidate, rollback-on-error, validate, startup, url, xpath, confirmed-commit and
 * ietf-netconf-monitoring has no features.
 *
 * If ctx is :
 *      - NULL: a new context will be created and if the call is successful you have to free it,
 *      - non NULL: context will be searched for the two modules and their features
 *                  and if anything is missing, it will be implemented.
 *
 * @param[in,out] ctx Optional context in which the modules will be loaded. Created if ctx is null.
 * @return 0 on success, -1 on error.
 */
int nc_server_init_ctx(struct ly_ctx **ctx);

/**
 * @brief Set the with-defaults capability extra parameters.
 *
 * For the capability to be actually advertised, the server context must also
 * include the ietf-netconf-with-defaults model.
 *
 * Changing this option has the same ill effects as changing capabilities while
 * sessions are already established.
 *
 * @param[in] basic_mode basic-mode with-defaults parameter.
 * @param[in] also_supported NC_WD_MODE bit array, also-supported with-defaults
 * parameter.
 * @return 0 on success, -1 on error.
 */
int nc_server_set_capab_withdefaults(NC_WD_MODE basic_mode, int also_supported);

/**
 * @brief Get with-defaults capability extra parameters.
 *
 * At least one argument must be non-NULL.
 *
 * @param[out] basic_mode basic-mode parameter.
 * @param[out] also_supported also-supported parameter.
 */
void nc_server_get_capab_withdefaults(NC_WD_MODE *basic_mode, int *also_supported);

/**
 * @brief Set capability of the server.
 *
 * Capability can be used when some behavior or extension of the server is not defined
 * as a YANG module. The provided value will be advertised in the server's \<hello\>
 * messages. Note, that libnetconf only checks that the provided value is non-empty
 * string.
 *
 * @param[in] value Capability string to be advertised in server's \<hello\> messages.
 */
int nc_server_set_capability(const char *value);

/**
 * @brief Set the callback for getting yang-library capability identifier. If none is set, libyang context change count is used.
 *
 * @param[in] content_id_clb Callback that should return the yang-library content identifier.
 * @param[in] user_data Optional arbitrary user data that will be passed to @p content_id_clb.
 * @param[in] free_user_data Optional callback that will be called during cleanup to free any @p user_data.
 */
void nc_server_set_content_id_clb(char *(*content_id_clb)(void *user_data), void *user_data,
        void (*free_user_data)(void *user_data));

/**
 * @brief Get all the server capabilities including all the schemas.
 *
 * A few capabilities (with-defaults, interleave) depend on the current
 * server options.
 *
 * @param[in] ctx Context to read most capabilities from.
 * @return Array of capabilities, NULL on error.
 */
char **nc_server_get_cpblts(const struct ly_ctx *ctx);

/**
 * @brief Get the server capabilities including the schemas with the specified YANG version.
 *
 * A few capabilities (with-defaults, interleave) depend on the current
 * server options.
 *
 * @param[in] ctx Context to read most capabilities from.
 * @param[in] version YANG version of the schemas to be included in result, with
 * LYS_VERSION_UNDEF the result is the same as from nc_server_get_cpblts().
 * @return Array of capabilities, NULL on error.
 */
char **nc_server_get_cpblts_version(const struct ly_ctx *ctx, LYS_VERSION version);

/** @} Server Functions */

/**
 * @addtogroup server_session
 * @{
 */

/**
 * @brief Accept a new session on a pre-established transport session.
 *
 * For detailed description, look at ::nc_accept().
 *
 * @param[in] fdin File descriptor to read (unencrypted) XML data from.
 * @param[in] fdout File descriptor to write (unencrypted) XML data to.
 * @param[in] username NETCONF username as provided by the transport protocol.
 * @param[in] ctx Context for the session to use.
 * @param[out] session New session on success.
 * @return NC_MSG_HELLO on success, NC_MSG_BAD_HELLO on client \<hello\> message
 *         parsing fail, NC_MSG_WOULDBLOCK on timeout, NC_MSG_ERROR on other errors.
 */
NC_MSG_TYPE nc_accept_inout(int fdin, int fdout, const char *username, const struct ly_ctx *ctx,
        struct nc_session **session);

/**
 * @brief Create an empty structure for polling sessions.
 *
 * @return Empty pollsession structure, NULL on error.
 */
struct nc_pollsession *nc_ps_new(void);

/**
 * @brief Free a pollsession structure.
 *
 * !IMPORTANT! Make sure that @p ps is not accessible (is not used)
 * by any thread before and after this call!
 *
 * @param[in] ps Pollsession structure to free.
 */
void nc_ps_free(struct nc_pollsession *ps);

/**
 * @brief Add a session to a pollsession structure.
 *
 * @param[in] ps Pollsession structure to modify.
 * @param[in] session Session to add to @p ps.
 * @return 0 on success, -1 on error.
 */
int nc_ps_add_session(struct nc_pollsession *ps, struct nc_session *session);

/**
 * @brief Remove a session from a pollsession structure.
 *
 * @param[in] ps Pollsession structure to modify.
 * @param[in] session Session to remove from @p ps.
 * @return 0 on success, -1 on not found.
 */
int nc_ps_del_session(struct nc_pollsession *ps, struct nc_session *session);

/**
 * @brief Get a session from a pollsession structure matching the session ID.
 *
 * @param[in] ps Pollsession structure to read from.
 * @param[in] idx Index of the session.
 * @return Session on index, NULL if out-of-bounds.
 */
struct nc_session *nc_ps_get_session(const struct nc_pollsession *ps, uint16_t idx);

/**
 * @brief Callback for finding a session in a pollsession structure.
 *
 * @param[in] session Considered NETCONF session.
 * @param[in] cb_data User data.
 * @return 0 if the session does not match.
 * @return non-zero if the session matches and should be returned.
 */
typedef int (*nc_ps_session_match_cb)(struct nc_session *session, void *cb_data);

/**
 * @brief Find a session in a pollsession structure using a matching callback.
 *
 * @param[in] ps Pollsession structure to read from.
 * @param[in] match_cb Matching callback to use.
 * @param[in] cb_data User data passed to @p cb.
 * @return Found session, NULL if none matched.
 */
struct nc_session *nc_ps_find_session(const struct nc_pollsession *ps, nc_ps_session_match_cb match_cb, void *cb_data);

/**
 * @brief Learn the number of sessions in a pollsession structure.
 *
 * Does not lock @p ps structure for efficiency.
 *
 * @param[in] ps Pollsession structure to check.
 * @return Number of sessions (even invalid ones) in @p ps, -1 on error.
 */
uint16_t nc_ps_session_count(struct nc_pollsession *ps);

#define NC_PSPOLL_NOSESSIONS 0x0001    /**< No sessions to poll. */
#define NC_PSPOLL_TIMEOUT 0x0002       /**< Timeout elapsed. */
#define NC_PSPOLL_RPC 0x0004           /**< RPC was correctly parsed and processed. */
#define NC_PSPOLL_BAD_RPC 0x0008       /**< RPC was received, but failed to be parsed. */
#define NC_PSPOLL_REPLY_ERROR 0x0010   /**< Response to the RPC was a \<rpc-reply\> of type error. */
#define NC_PSPOLL_SESSION_TERM 0x0020  /**< Some session was terminated. */
#define NC_PSPOLL_SESSION_ERROR 0x0040 /**< Some session was terminated incorrectly (not by a \<close-session\> or \<kill-session\> RPC). */
#define NC_PSPOLL_ERROR 0x0080         /**< Other fatal errors (they are printed). */

#ifdef NC_ENABLED_SSH_TLS
# define NC_PSPOLL_SSH_MSG 0x00100      /**< SSH message received (and processed, if relevant, only with SSH support). */
# define NC_PSPOLL_SSH_CHANNEL 0x0200   /**< New SSH channel opened on an existing session (only with SSH support). */
#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Poll sessions and process any received RPCs.
 *
 * Only one event on one session is handled in one function call. If this event
 * is a session termination (#NC_PSPOLL_SESSION_TERM returned), the session
 * should be removed from @p ps.
 *
 * @param[in] ps Pollsession structure to use.
 * @param[in] timeout Poll timeout in milliseconds. 0 for non-blocking call, -1 for
 *                    infinite waiting.
 * @param[in] session Session that was processed and that specific return bits concern.
 *                    Can be NULL.
 * @return Bitfield of NC_PSPOLL_* macros.
 */
int nc_ps_poll(struct nc_pollsession *ps, int timeout, struct nc_session **session);

/**
 * @brief Remove sessions from a pollsession structure and
 *        call nc_session_free() on them.
 *
 * Calling this function with @p all false makes sense if nc_ps_poll() returned #NC_PSPOLL_SESSION_TERM.
 *
 * @param[in] ps Pollsession structure to clear.
 * @param[in] all Whether to free all sessions, or only the invalid ones.
 * @param[in] data_free Session user data destructor.
 */
void nc_ps_clear(struct nc_pollsession *ps, int all, void (*data_free)(void *));

/** @} Server Session */

/**
 * @addtogroup server_functions
 * @{
 */

/**
 * @brief Get the number of currently configured listening endpoints.
 * Note that an ednpoint without address and/or port will be included
 * even though it is not, in fact, listening.
 *
 * @return Number of added listening endpoints.
 */
int nc_server_endpt_count(void);

/**
 * @brief Create a new UNIX socket endpoint and start listening.
 *
 * @param[in] endpt_name Arbitrary unique identifier of the endpoint.
 * @param[in] unix_socket_path Path to the listening socket.
 * @param[in] mode New mode, -1 to use default.
 * @param[in] uid New uid, -1 to use default.
 * @param[in] gid New gid, -1 to use default.
 *
 * @return 0 on success, 1 on error.
 */
int nc_server_add_endpt_unix_socket_listen(const char *endpt_name, const char *unix_socket_path, mode_t mode, uid_t uid, gid_t gid);

/**
 * @brief Deletes a UNIX socket endpoint.
 *
 * @param[in] endpt_name Identifier of the endpoint.
 * Has no effect if the endpoint doesn't exist or if its transport is not UNIX socket.
 */
void nc_server_del_endpt_unix_socket(const char *endpt_name);

/** @} */

/**
 * @addtogroup server_session
 * @{
 */

/**
 * @brief Accept new sessions on all the listening endpoints.
 *
 * Once a new (TCP/IP) conection is established a different (quite long) timeout
 * is used for waiting for transport-related data, which means this call can block
 * for much longer that @p timeout, but only with slow/faulty/malicious clients.
 *
 * Server capabilities are generated based on the content of @p ctx. The context must
 * not be destroyed before the accepted NETCONF session is freed. Basic usable context may
 * be created by calling ::nc_server_init_ctx().
 *
 * Supported RPCs of models in the context are expected to have their callback
 * in the corresponding RPC schema node set to a nc_rpc_clb function callback using ::nc_set_rpc_callback().
 * This callback is called by ::nc_ps_poll() if the particular RPC request is
 * received. Callbacks for ietf-netconf:get-schema (supporting YANG and YIN format
 * only) and ietf-netconf:close-session are set internally if left unset.
 *
 * @param[in] timeout Timeout for receiving a new connection in milliseconds, 0 for
 * non-blocking call, -1 for infinite waiting.
 * @param[in] ctx Context for the session to use.
 * @param[out] session New session.
 * @return NC_MSG_HELLO on success, NC_MSG_BAD_HELLO on client \<hello\> message
 *         parsing fail, NC_MSG_WOULDBLOCK on timeout, NC_MSG_ERROR on other errors.
 */
NC_MSG_TYPE nc_accept(int timeout, const struct ly_ctx *ctx, struct nc_session **session);

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Accept a new NETCONF session on an SSH session of a running NETCONF @p orig_session.
 *        Call this function only when nc_ps_poll() returns #NC_PSPOLL_SSH_CHANNEL on @p orig_session.
 *
 * @param[in] orig_session Session that has a new SSH channel ready.
 * @param[out] session New session.
 * @return NC_MSG_HELLO on success, NC_MSG_BAD_HELLO on client \<hello\> message
 *         parsing fail, NC_MSG_WOULDBLOCK on timeout, NC_MSG_ERROR on other errors.
 */
NC_MSG_TYPE nc_session_accept_ssh_channel(struct nc_session *orig_session, struct nc_session **session);

/**
 * @brief Accept a new NETCONF session on an SSH session of a running NETCONF session
 *        that was polled in @p ps. Call this function only when nc_ps_poll() on @p ps returns #NC_PSPOLL_SSH_CHANNEL.
 *        The new session is only returned in @p session, it is not added to @p ps.
 *
 * @param[in] ps Unmodified pollsession structure from the previous nc_ps_poll() call.
 * @param[out] session New session.
 * @return NC_MSG_HELLO on success, NC_MSG_BAD_HELLO on client \<hello\> message
 *         parsing fail, NC_MSG_WOULDBLOCK on timeout, NC_MSG_ERROR on other errors.
 */
NC_MSG_TYPE nc_ps_accept_ssh_channel(struct nc_pollsession *ps, struct nc_session **session);

/** @} Server Session */

/**
 * @defgroup server_ssh Server SSH
 * @ingroup server
 *
 * @brief Server-side settings for SSH connections.
 * @{
 */

/**
 * @brief Set the format of the path to authorized_keys files.
 *
 * This path format will be set globally for all clients wishing to authenticate via the
 * SSH Public Key system authentication.
 *
 * @param[in] path Path to authorized_keys files. The path may contain the following tokens:
 * - %u - replaced by the username of the user trying to authenticate,
 * - %h - replaced by the home directory of the user trying to authenticate,
 * - %U - replaced by the UID of the user trying to authenticate,
 * - %% - a literal '%'.
 * @return 0 on success, 1 on error.
 */
int nc_server_ssh_set_authkey_path_format(const char *path);

/**
 * @brief Keyboard interactive authentication callback.
 *
 * The callback has to handle sending interactive challenges and receiving responses by itself.
 * An example callback may fit the following description:
 * Prepare all prompts for the user and send them via `ssh_message_auth_interactive_request()`.
 * Get the answers either by calling `ssh_message_get()` or `nc_server_ssh_kbdint_get_nanswers()`.
 * Return value based on your authentication logic and user answers retrieved by
 * calling `ssh_userauth_kbdint_getanswer()`.
 *
 * @param[in] session NETCONF session.
 * @param[in] ssh_sess libssh session.
 * @param[in] msg SSH message that contains the interactive request and which expects a reply with prompts.
 * @param[in] user_data Arbitrary user data.
 * @return 0 for successful authentication, non-zero to deny the user.
 */
typedef int (*nc_server_ssh_interactive_auth_clb)(const struct nc_session *session,
        ssh_session ssh_sess, ssh_message msg, void *user_data);

/**
 * @brief Set the callback for SSH interactive authentication.
 *
 * @param[in] auth_clb Keyboard interactive authentication callback. This callback is only called once per authentication.
 * @param[in] user_data Optional arbitrary user data that will be passed to @p interactive_auth_clb.
 * @param[in] free_user_data Optional callback that will be called during cleanup to free any @p user_data.
 */
void nc_server_ssh_set_interactive_auth_clb(nc_server_ssh_interactive_auth_clb auth_clb, void *user_data, void (*free_user_data)(void *user_data));

/**
 * @brief Get the number of answers to Keyboard interactive authentication prompts.
 *
 * The actual answers can later be retrieved by calling `ssh_userauth_kbdint_getanswer()` on
 * the @p libssh_session.
 *
 * @param[in] session NETCONF session.
 * @param[in] libssh_session libssh session.
 *
 * @return Non-negative number of answers on success, -1 on configurable authentication timeout,
 * disconnect or other error.
 */
int nc_server_ssh_kbdint_get_nanswers(const struct nc_session *session, ssh_session libssh_session);

/**
 * @brief Set the name of the PAM configuration file.
 *
 * This filename will be set globally for all clients wishing to authenticate via the
 * SSH Keyboard Interactive authentication method.
 *
 * @param[in] filename Name of the PAM configuration file. The file needs to be located in
 * the default PAM directory (usually /etc/pam.d/).
 *
 * @return 0 on success, 1 on error.
 */
int nc_server_ssh_set_pam_conf_filename(const char *filename);

/** @} Server SSH */

/**
 * @defgroup server_tls Server TLS
 * @ingroup server
 *
 * @brief Server-side settings for TLS connections.
 * @{
 */

/**
 * @brief Get client certificate.
 *
 * @param[in] session Session to get the information from.
 * @return Const session client certificate.
 */
const void *nc_session_get_client_cert(const struct nc_session *session);

/**
 * @brief Set TLS authentication additional verify callback.
 *
 * Server will always perform cert-to-name based on its configuration. Only after it passes
 * and this callback is set, it is also called. It should return non-zero for success, 0 to deny the user.
 *
 * @param[in] verify_clb Additional user verify callback.
 */
void nc_server_tls_set_verify_clb(int (*verify_clb)(const struct nc_session *session));

/** @} Server TLS */

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @addtogroup server_session
 * @{
 */

/**
 * @brief Get session start time.
 *
 * @param[in] session Session to get the information from.
 * @return Session start time.
 */
struct timespec nc_session_get_start_time(const struct nc_session *session);

/**
 * @brief Increase session notification subscription flag count.
 * Supports multiple subscriptions on one session.
 *
 * It is used only to ignore timeouts, because they are
 * ignored for sessions with active subscriptions.
 *
 * @param[in] session Session to modify.
 */
void nc_session_inc_notif_status(struct nc_session *session);

/**
 * @brief Decrease session notification subscription flag count.
 * Supports multiple subscriptions on one session.
 *
 * @param[in] session Session to modify.
 */
void nc_session_dec_notif_status(struct nc_session *session);

/**
 * @brief Get session notification subscription flag.
 *
 * @param[in] session Session to get the information from.
 * @return 0 for no active subscription, non-zero for an active subscription.
 */
int nc_session_get_notif_status(const struct nc_session *session);

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Start the certificate expiration notification thread.
 *
 * The thread will periodically check the expiration time of all certificates in the configuration.
 * When a notification is about to be generated, the callback @p cert_exp_notif_clb is called.
 * The times of when these notifications are generated are based on the expiration times of certificates
 * in the configuration and on the values of intervals set in the configuration. For more information,
 * see the libnetconf2-netconf-server YANG module.
 *
 * @param[in] cert_exp_notif_clb The callback to be called when a notification is generated.
 * @param[in] user_data Arbitrary user data to pass to the callback.
 * @param[in] free_data Optional callback to free the user data.
 *
 * @return 0 on success, 1 on error.
 */
int nc_server_notif_cert_expiration_thread_start(nc_cert_exp_notif_clb cert_exp_notif_clb,
        void *user_data, void (*free_data)(void *));

/**
 * @brief Stop the certificate expiration notification thread.
 *
 * @param[in] wait Boolean representing whether to block and wait for the thread to finish.
 */
void nc_server_notif_cert_expiration_thread_stop(int wait);

#endif /* NC_ENABLED_SSH_TLS */

/** @} Server Session */

#ifdef __cplusplus
}
#endif

#endif /* NC_SESSION_SERVER_H_ */
