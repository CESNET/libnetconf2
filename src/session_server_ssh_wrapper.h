/**
 * @file session_server_ssh_wrapper.h
 * @author Petr Hanzlik <Petr.Hanzlik@cesnet.cz>
 * @brief libnetconf2 - header for wrapped SSH server library function calls
 *
 * @copyright
 * Copyright (c) 2026 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _SESSION_SERVER_SSH_WRAPPER_H_
#define _SESSION_SERVER_SSH_WRAPPER_H_

#include "config.h" /* Expose HAVE_LIBPAM, HAVE_SHADOW */
#include "session_p.h"

#ifdef NC_ENABLED_SSH_TLS
    # include <libssh/server.h>
#endif

#ifdef HAVE_LIBPAM
#   include <security/pam_appl.h>

/** Fixed prompt name sent with every keyboard-interactive request. */
#define NC_PAM_KBDINT_NAME "Keyboard-Interactive Authentication"

/** Fixed prompt instruction sent with every keyboard-interactive request. */
#define NC_PAM_KBDINT_INSTRUCTION "Please enter your authentication token"
#endif
#ifdef HAVE_SHADOW
#   include <shadow.h>
#endif

#define LIBSSH_0_12 (LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 12, 0))

#if LIBSSH_0_12

#ifdef HAVE_LIBPAM

#include <pthread.h>

/**
 * @brief PAM thread bridge state for callback-based keyboard-interactive auth.
 *
 * PAM's pam_authenticate() is synchronous, but the libssh callback-based kbdint
 * protocol is asynchronous (callback must return SSH_AUTH_INFO and be called
 * again with the response). This structure bridges the two by running
 * pam_authenticate in a separate thread, with condvar-based communication.
 *
 * State machine (all transitions protected by @p lock, waiters re-check
 * @p state in a while loop):
 *
 *   RUNNING --(PAM thread: prompts)--> PROMPTS_READY --(main thread: answers)--> ANSWERS_READY
 *       ^                                                                                 |
 *       |                          (PAM thread: consumed answers, new prompts)            |
 *       +---------------------------------------------------------------------------------+
 *   RUNNING/PROMPTS_READY/ANSWERS_READY --(PAM thread: finished)--> DONE
 *   RUNNING/PROMPTS_READY --(main thread: timeout/disconnect)--> CANCELLED --> DONE
 *
 * The main thread owns transitions out of NC_PAM_ANSWERS_READY and the PAM
 * thread owns transitions out of NC_PAM_RUNNING/NC_PAM_PROMPTS_READY, so at
 * any moment at most one thread waits on @p changed and the other may signal
 * it.
 *
 * Invariants:
 * - While state == NC_PAM_PROMPTS_READY the PAM thread is parked on
 *   @p changed, so the prompt strings/arrays it handed to the main thread
 *   stay valid until the main thread leaves that state.
 * - NC_PAM_ANSWERS_READY is never observed by nc_server_ssh_cb_pam_cancel(), because
 *   cancel runs only in the main thread, which owns that state and leaves it
 *   itself (to PROMPTS_READY or DONE) before any cancel can happen.
 * - If the PAM thread does not cooperate with a graceful cancel (a PAM module
 *   blocked outside the conversation), nc_server_ssh_cb_pam_cancel() force-cancels
 *   it with pthread_cancel() and waits for it only for a bounded time; a thread
 *   that survives even that is detached and its resources intentionally leaked,
 *   so the main thread never blocks indefinitely. In that case the DONE
 *   transition never happens and @p state stays NC_PAM_CANCELLED.
 */
struct nc_server_ssh_cb_pam_data {
    pthread_t thread;               /**< PAM thread handle. */
    pthread_mutex_t lock;           /**< Protects all fields below. */
    pthread_cond_t changed;         /**< Signalled on every state change. */

    /** PAM bridge state. */
    enum {
        NC_PAM_RUNNING,             /**< PAM thread is processing, no prompts yet. */
        NC_PAM_PROMPTS_READY,       /**< PAM thread has prompts, waiting for answers. */
        NC_PAM_ANSWERS_READY,       /**< Main thread has answers, PAM should consume. */
        NC_PAM_DONE,                /**< PAM authentication complete (check pam_ret). */
        NC_PAM_CANCELLED            /**< Cancelled by main thread (disconnect/timeout). */
    } state;

    /* Prompts (PAM thread sets, main thread reads, while holding lock) */
    int n_prompts;                  /**< Number of prompts. */
    const char **prompts;           /**< Prompt strings. */
    char *echo;                     /**< Echo flags. */

    /* Answers (main thread sets, PAM thread reads, while holding lock) */
    int n_answers;                  /**< Number of answers. */
    char **answers;                 /**< Answer strings. */

    int pam_ret;                    /**< PAM return code (valid when state == DONE). */

    const char *username;           /**< Username for pam_start. */
    struct nc_session *session;     /**< NETCONF session for logging. */
};

/**
 * @brief Cancel the PAM thread and clean up (called on auth failure/timeout/disconnect).
 *
 * Never blocks indefinitely: if the thread does not terminate on the graceful
 * cancel, it is force-cancelled with pthread_cancel() and the join is bounded
 * (when pthread_timedjoin_np() is available); a thread that survives even that
 * is detached and its data is intentionally leaked instead.
 *
 * @param[in] data PAM data (may be NULL).
 */
void nc_server_ssh_cb_pam_cancel(struct nc_server_ssh_cb_pam_data *data);

#endif /* HAVE_LIBPAM */

/** @brief Data structure passed to SSH callback functions. */
struct nc_server_ssh_cb_data {
    struct ssh_server_callbacks_struct server_cb;  /**< libssh server callbacks. */
    struct nc_session *session;      /**< The current session. */
    struct nc_server_ssh_opts *opts;     /**< SSH server options. */
    struct nc_auth_state auth_state;  /**< Tracks multi-method authentication state. */
    struct nc_ssh_channel_cb_data *channels;  /**< List of additional channel callback data,
                                                   tracked so non-netconf channels can be freed. */
#ifdef HAVE_LIBPAM
    struct nc_server_ssh_cb_pam_data *pam_kbdint;  /**< PAM thread bridge state. */
#endif
};

/**
 * @brief libssh channel callbacks struct together with its owner.
 *
 * @remark channel_cb MUST stay the first member, so that a plain free() of
 * nc_session->ti.libssh.channel_cb frees the whole structure.
 */
struct nc_ssh_channel_cb_data {
    struct ssh_channel_callbacks_struct channel_cb;  /**< libssh channel callbacks (MUST be first). */
    struct nc_server_ssh_cb_data *cb_data;  /**< Shared SSH-session callback data. */
    struct nc_ssh_channel_cb_data *next;  /**< Next in the cb_data->channels list. */
};

/**
* @brief Callback function for SSH authentication with none method.
*
* @param[in] libssh_sess SSH session object.
* @param[in] user Username attempting to authenticate.
* @param[in] userdata Pointer to user data (struct nc_server_ssh_cb_data).
* @return SSH_AUTH_SUCCESS if authentication is successful.
* @return SSH_AUTH_DENIED otherwise.
*/
int nc_server_ssh_cb_auth_none(ssh_session libssh_sess, const char *user, void *userdata);

/**
* @brief Callback function for SSH authentication with password method.
*
* @param[in] libssh_sess SSH session object.
* @param[in] user Username attempting to authenticate.
* @param[in] password Password provided by the user.
* @param[in] userdata Pointer to user data (struct nc_server_ssh_cb_data).
* @return SSH_AUTH_SUCCESS if authentication is successful.
* @return SSH_AUTH_DENIED otherwise.
*/
int nc_server_ssh_cb_auth_password(ssh_session libssh_sess, const char *user, const char *password, void *userdata);

/**
 * @brief Callback function for SSH public key authentication.
 *
 * @param[in] libssh_sess SSH session object.
 * @param[in] user Username attempting to authenticate.
 * @param[in] pubkey Public key provided by the user.
 * @param[in] signature_state Whether this is a probe (NONE) or signed auth (VALID).
 * @param[in] userdata Pointer to user data (struct nc_server_ssh_cb_data).
 * @return SSH_AUTH_SUCCESS if authentication is successful (or probe accepted).
 * @return SSH_AUTH_DENIED otherwise.
 */
int nc_server_ssh_cb_auth_pubkey(ssh_session libssh_sess, const char *user, struct ssh_key_struct *pubkey, char signature_state, void *userdata);

/**
 * @brief Callback function for SSH keyboard-interactive authentication.
 *
 * @param[in] message SSH message containing the auth request or response.
 * @param[in] libssh_sess SSH session object.
 * @param[in] userdata Pointer to user data (struct nc_server_ssh_cb_data).
 * @return SSH_AUTH_INFO if prompts were sent (waiting for client response).
 * @return SSH_AUTH_SUCCESS if authentication is successful.
 * @return SSH_AUTH_DENIED otherwise.
 */
int nc_server_ssh_cb_auth_kbdint(ssh_message message, ssh_session libssh_sess, void *userdata);

/**
 * @brief Callback function for SSH channel open request.
 *
 * @param[in] libssh_sess SSH session object.
 * @param[in] userdata Pointer to user data (struct nc_server_ssh_cb_data).
 * @return The new SSH channel on success.
 * @return NULL on failure.
 */
ssh_channel nc_server_ssh_cb_channel_open_request_session(ssh_session libssh_sess, void *userdata);

#else

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

#endif

/**
 * @brief Free SSH callback data, reclaiming any channel callback data for channels
 *        that were never claimed by a NETCONF subsystem request.
 *
 * @param[in] cb_data Callback data to free, may be NULL.
 */
void nc_server_ssh_cb_data_free(void *cb_data);

/**
 * @brief Check if local users are supported via the ietf-ssh-server YANG model.
 *
 * @param[in] session NETCONF session.
 * @return 1 if local users are supported.
 * @return 0 if local users are not supported.
 * @return -1 on fatal error.
 */
int nc_ssh_check_local_user_support(struct nc_session *session);

/**
 * @brief Find an authentication client for a given username.
 *
 * @param[in] opts SSH server options.
 * @param[in] user Username to search for.
 * @param[in] session NETCONF session for logging.
 * @return Pointer to the authentication client if found.
 * @return NULL otherwise.
 */
struct nc_auth_client *nc_ssh_find_auth_client(struct nc_server_ssh_opts *opts, const char *user, struct nc_session *session);

/**
 * @brief Initialize the authentication state for multi-method authentication.
 *
 * @param[in] session NETCONF session.
 * @param[in,out] auth_state Authentication state to initialize.
 * @param[in] local_users_supported Whether local users are supported.
 * @param[in] auth_client The authenticated client configuration (may be NULL if !local_users_supported).
 */
void nc_ssh_auth_state_init(struct nc_session *session, struct nc_auth_state *auth_state,
        int local_users_supported, struct nc_auth_client *auth_client);

/**
 * @brief Handle a successful authentication attempt, tracking partial/multi-method auth.
 *
 * @param[in] session NETCONF session.
 * @param[in,out] auth_state Authentication state.
 * @param[in] method The SSH auth method that succeeded.
 * @return SSH_AUTH_SUCCESS if fully authenticated.
 * @return SSH_AUTH_PARTIAL if more methods are needed.
 */
int nc_ssh_auth_success(struct nc_session *session, struct nc_auth_state *auth_state, int method);

/**
 * @brief Send the SSH issue banner if configured.
 *
 * @param[in] session NETCONF session.
 * @param[in] opts SSH server options.
 */
void nc_server_ssh_send_banner(struct nc_session *session, struct nc_server_ssh_opts *opts);

/**
 * @brief Compare SSH key with configured authorized keys.
 *
 * @param[in] key Presented SSH key to compare.
 * @param[in] pubkeys Configured public keys to compare against.
 * @param[in] pubkey_count Number of @p pubkeys.
 * @return 0 if a match was found.
 * @return 1 if no match was found.
 */
int nc_server_ssh_auth_pubkey_compare_key(ssh_key key, struct nc_public_key *pubkeys, uint16_t pubkey_count);

/**
 * @brief Get public keys from the truststore.
 *
 * @param[in] referenced_name Name of the public key bag in the truststore.
 * @param[out] pubkeys Referenced public keys.
 * @param[out] pubkey_count Referenced public key count.
 * @return 0 on success, 1 on error.
 */
int nc_server_ssh_ts_ref_get_keys(const char *referenced_name, struct nc_public_key **pubkeys, uint32_t *pubkey_count);

/**
 * @brief Get user's public keys from the system.
 *
 * @param[in] username Username.
 * @param[out] pubkeys User's public keys.
 * @param[out] pubkey_count Public key count.
 * @return 0 on success, non-zero on error.
 */
int nc_server_ssh_get_system_keys(const char *username, struct nc_public_key **pubkeys, uint32_t *pubkey_count);

/**
 * @brief Compare stored hashed password with a cleartext received password.
 *
 * @param[in] stored_pw Hashed stored password.
 * @param[in] received_pw Cleartext received password.
 * @return 0 on match, non-zero otherwise.
 */
int nc_server_ssh_compare_password(const char *stored_pw, const char *received_pw);

/**
 * @brief Increase the failed authentication attempt counter and log the attempt.
 *
 * @param[in] session NETCONF session.
 */
void nc_server_ssh_auth_attempt_failed(struct nc_session *session);

/**
 * @brief Authenticate user with password (retrieves stored hash and compares).
 *
 * @param[in] session NETCONF session.
 * @param[in] user Username attempting authentication.
 * @param[in] password Password provided by the user.
 * @param[in] auth_client Client configuration (if local users supported).
 * @param[in] local_users_supported Flag indicating if local users are used.
 * @return 0 on success (password matches), non-zero on failure.
 */
int nc_server_ssh_auth_password_check(struct nc_session *session, const char *user,
        const char *password, struct nc_auth_client *auth_client, int local_users_supported);

/**
 * @brief Authenticate a user by verifying a public key against configured or system public keys.
 *
 * @param[in] session NETCONF session.
 * @param[in] pubkey Received libssh public key.
 * @param[in] auth_client Client configuration (if local users supported).
 * @param[in] local_users_supported Flag indicating if local users are configured.
 * @return 0 on success (key matches an authorized key), non-zero on failure/error.
 */
int nc_server_ssh_auth_pubkey_check(struct nc_session *session, ssh_key pubkey,
        struct nc_auth_client *auth_client, int local_users_supported);

/**
 * @brief Keyboard-interactive authentication backend.
 */
enum nc_kbdint_backend {
    NC_KBDINT_BACKEND_SYSTEM,       /**< Authenticate via the system method (PAM or shadow). */
    NC_KBDINT_BACKEND_CUSTOM_CLB    /**< Authenticate via the custom keyboard-interactive callback. */
};

/**
 * @brief Select the keyboard-interactive authentication backend based on the configuration.
 *
 * @param[in] session NETCONF session.
 * @param[in] local_users_supported Whether local users are supported.
 * @param[in] auth_client Configured client's authentication data (may be NULL for system users).
 * @param[out] backend Selected authentication backend.
 * @return 0 if a backend was selected, non-zero if the request must be denied (the reason was already logged).
 */
int nc_server_ssh_kbdint_select_method(struct nc_session *session, int local_users_supported,
        struct nc_auth_client *auth_client, enum nc_kbdint_backend *backend);

/**
 * @brief Check a channel subsystem request against the session state.
 *
 * @param[in] session NETCONF session.
 * @param[in] channel SSH channel the subsystem was requested on.
 * @param[in] subsystem Requested subsystem name (expected "netconf").
 * @return 0 if the "netconf" subsystem was requested on the first channel (the flag was set).
 * @return 1 if the request is for an additional channel (the caller must create a new session).
 * @return -1 on an invalid request (the reason was logged).
 */
int nc_server_ssh_channel_subsys_check(struct nc_session *session, ssh_channel channel, const char *subsystem);

/**
 * @brief Create a new NETCONF session for an additional SSH channel and insert it into the ring of sessions.
 *
 * @param[in] session Parent (first channel) NETCONF session.
 * @param[in] channel SSH channel of the additional subsystem request.
 * @return New session on success.
 * @return NULL on error (logged).
 */
struct nc_session *nc_server_ssh_new_channel_session(struct nc_session *session, ssh_channel channel);

#ifdef HAVE_LIBPAM
/**
 * @brief Parse PAM conversation messages into keyboard-interactive prompts.
 *
 * @param[in] session NETCONF session (used for logging).
 * @param[in] n_messages Number of PAM messages.
 * @param[in] msg PAM module's messages.
 * @param[out] resp PAM response array (allocated here, freed by PAM on success).
 * @param[out] n_prompts Number of actual prompts (0 if none).
 * @param[out] prompts Prompt strings borrowed from @p msg.
 * @param[out] echo Echo flags for the prompts.
 * @return PAM_SUCCESS on success, PAM_CONV_ERR on bad input, PAM_BUF_ERR on OOM.
 */
int nc_server_ssh_pam_conv_parse(struct nc_session *session, int n_messages,
        const struct pam_message **msg, struct pam_response **resp,
        int *n_prompts, const char ***prompts, char **echo);

/**
 * @brief Fill a prepared PAM response array with the client's answers.
 *
 * @param[in] session NETCONF session (used for logging).
 * @param[in] resp PAM response array allocated for @p n_prompts responses.
 * @param[in] n_prompts Number of prompts given to the client.
 * @param[in] n_answers Number of answers received from the client.
 * @param[in] answers Answer strings of the client.
 * @return PAM_SUCCESS on success, PAM_CONV_ERR if the answer count does not
 * match the prompt count, PAM_BUF_ERR on OOM.
 */
int nc_server_ssh_pam_conv_fill(struct nc_session *session, struct pam_response *resp,
        int n_prompts, int n_answers, const char **answers);

/**
 * @brief Run the PAM authentication sequence with a prepared conversation.
 *
 * @param[in] session NETCONF session (used for logging).
 * @param[in] username Username to authenticate.
 * @param[in] conv PAM conversation prepared by the caller.
 * @return PAM_SUCCESS (0) on success, a PAM error code or 1 otherwise.
 */
int nc_server_ssh_pam_authenticate(struct nc_session *session, const char *username,
        const struct pam_conv *conv);
#endif /* HAVE_LIBPAM */

#ifdef HAVE_SHADOW
/**
 * @brief Get the user's hashed password from the system.
 *
 * @param[in] username Username.
 * @return User's hashed password or NULL on error.
 */
char *nc_server_ssh_get_pwd_hash(const char *username);

/**
 * @brief Send a single "<username>'s password:" keyboard-interactive prompt to the client.
 *
 * @param[in] session NETCONF session (used for logging).
 * @param[in] username Username shown in the prompt.
 * @param[in] msg SSH message the interactive request is sent through.
 * @return 0 on success, non-zero on failure.
 */
int nc_server_ssh_kbdint_send_passwd_prompt(struct nc_session *session, const char *username, ssh_message msg);

/**
 * @brief Verify the client's single keyboard-interactive password answer against the user's system hash.
 *
 * @param[in] session NETCONF session.
 * @param[in] username Username whose system password hash is fetched.
 * @param[in] n_answers Number of answers the client provided (must be exactly 1).
 * @return 0 if the password matches, non-zero otherwise.
 */
int nc_server_ssh_kbdint_verify_passwd(struct nc_session *session, const char *username, int n_answers);
#endif /* HAVE_SHADOW */

#endif /* _SESSION_SERVER_SSH_WRAPPER_H_ */
