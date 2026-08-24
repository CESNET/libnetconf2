/**
 * @file session_server_ssh_auth_callback.c
 * @author Petr Hanzlik <Petr.Hanzlik@cesnet.cz>
 * @brief libnetconf2 SSH authentication with callbacks (Libssh 0.12 and newer).
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

#define _GNU_SOURCE

#include "config.h" /* Expose HAVE_LIBPAM and HAVE_SHADOW */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_LIBPAM
#   include <security/pam_appl.h>
#endif

#include "compat.h"
#include "log_p.h"
#include "session_server_ssh_wrapper.h"

#ifdef HAVE_LIBPAM

/** Time [s] to wait for a cancelled PAM thread to terminate before detaching it. */
#define NC_PAM_THREAD_JOIN_TIMEOUT 1

/**
 * @brief PAM conversation callback for the callback-based kbdint path.
 *
 * @param[in] n_messages Number of PAM messages.
 * @param[in] msg PAM module's messages.
 * @param[out] resp User responses (allocated here, freed by PAM).
 * @param[in] appdata_ptr Pointer to nc_server_ssh_cb_pam_data.
 * @return PAM_SUCCESS on success.
 * @return PAM_BUF_ERR on OOM.
 * @return PAM_CONV_ERR otherwise.
 */
static int
nc_server_ssh_cb_pam_conv(int n_messages, const struct pam_message **msg,
        struct pam_response **resp, void *appdata_ptr)
{
    struct nc_server_ssh_cb_pam_data *data = appdata_ptr;
    int r, n_prompts = 0;
    const char **prompts = NULL;
    char *echo = NULL;

    /* parse the PAM messages into prompts */
    r = nc_server_ssh_pam_conv_parse(data->session, n_messages, msg, resp, &n_prompts, &prompts, &echo);
    if (r != PAM_SUCCESS) {
        return r;
    }
    if (!n_prompts) {
        /* no actual prompts */
        return PAM_SUCCESS;
    }

    /* signal main thread that prompts are ready */
    /* LOCK */
    pthread_mutex_lock(&data->lock);
    if (data->state == NC_PAM_CANCELLED) {
        goto cancelled;
    }
    data->n_prompts = n_prompts;
    data->prompts = prompts;
    data->echo = echo;
    data->state = NC_PAM_PROMPTS_READY;
    pthread_cond_signal(&data->changed);

    /* wait for answers from main thread */
    while (data->state == NC_PAM_PROMPTS_READY) {
        pthread_cond_wait(&data->changed, &data->lock);
    }

    if (data->state == NC_PAM_CANCELLED) {
        goto cancelled;
    }

    /* state == NC_PAM_ANSWERS_READY: copy answers (freed by PAM on failure) */
    r = nc_server_ssh_pam_conv_fill(data->session, *resp, n_prompts, data->n_answers,
            (const char **)data->answers);
    /* UNLOCK */
    pthread_mutex_unlock(&data->lock);

    /* free prompts/echo arrays */
    free(prompts);
    free(echo);
    return r;

cancelled:
    /* UNLOCK */
    pthread_mutex_unlock(&data->lock);
    free(prompts);
    free(echo);
    free(*resp);
    *resp = NULL;
    return PAM_CONV_ERR;
}

/**
 * @brief PAM thread function — runs pam_authenticate/pam_acct_mgmt/pam_chauthtok.
 *
 * Never calls libssh. Communicates with the main thread via condvars.
 *
 * @param[in] arg Pointer to nc_server_ssh_cb_pam_data.
 * @return NULL.
 */
static void *
nc_server_ssh_cb_pam_thread(void *arg)
{
    struct nc_server_ssh_cb_pam_data *data = arg;
    struct pam_conv conv = {0};
    int ret;

    conv.conv = nc_server_ssh_cb_pam_conv;
    conv.appdata_ptr = data;

    /* run the PAM sequence (the PAM handle is created and released inside) */
    ret = nc_server_ssh_pam_authenticate(data->session, data->username, &conv);

    /* LOCK */
    pthread_mutex_lock(&data->lock);
    data->pam_ret = ret;
    data->state = NC_PAM_DONE;
    pthread_cond_signal(&data->changed);
    /* UNLOCK */
    pthread_mutex_unlock(&data->lock);

    return NULL;
}

/**
 * @brief Free PAM bridge data (must be called after thread is joined).
 *
 * @param[in] data PAM data to free.
 */
static void
nc_server_ssh_cb_pam_data_free(struct nc_server_ssh_cb_pam_data *data)
{
    if (!data) {
        return;
    }
    pthread_mutex_destroy(&data->lock);
    pthread_cond_destroy(&data->changed);
    free(data);
}

void
nc_server_ssh_cb_pam_cancel(struct nc_server_ssh_cb_pam_data *data)
{
#ifdef HAVE_PTHREAD_TIMEDJOIN_NP
    struct timespec ts_timeout;
#endif

    if (!data) {
        return;
    }

    /* signal PAM thread to cancel */
    /* LOCK */
    pthread_mutex_lock(&data->lock);
    if (data->state == NC_PAM_PROMPTS_READY) {
        /* PAM thread is waiting for answers - tell it to abort */
        data->state = NC_PAM_CANCELLED;
        pthread_cond_signal(&data->changed);
    } else if ((data->state != NC_PAM_DONE) && (data->state != NC_PAM_CANCELLED)) {
        /* PAM thread is still active - mark as cancelled and force it out of any blocking call;
         * any lock held at the cancellation point stays locked but the data is never used again */
        data->state = NC_PAM_CANCELLED;
        pthread_cancel(data->thread);
    }
    /* UNLOCK */
    pthread_mutex_unlock(&data->lock);

#ifdef HAVE_PTHREAD_TIMEDJOIN_NP
    /* join with a timeout, never block indefinitely */
    nc_realtime_get(&ts_timeout);
    ts_timeout.tv_sec += NC_PAM_THREAD_JOIN_TIMEOUT;
    if (pthread_timedjoin_np(data->thread, NULL, &ts_timeout)) {
        /* the thread could not be cancelled (misbehaving PAM module stuck at no cancellation point),
         * so just detach it and leak its resources, there is nothing more to do */
        pthread_detach(data->thread);
        ERR(data->session, "Unable to cancel a PAM thread, leaking its resources.");
        return;
    }
#else
    pthread_join(data->thread, NULL);
#endif

    nc_server_ssh_cb_pam_data_free(data);
}

/**
 * @brief Cancel and free the PAM exchange stored in the callback data, if any.
 *
 * @param[in] cb_data Callback data.
 */
static void
nc_server_ssh_cb_kbdint_pam_cancel_stored(struct nc_server_ssh_cb_data *cb_data)
{
    if (cb_data->pam_kbdint) {
        nc_server_ssh_cb_pam_cancel(cb_data->pam_kbdint);
        cb_data->pam_kbdint = NULL;
    }
}

/**
 * @brief Finish a completed PAM exchange: join the PAM thread and free its data.
 *
 * @param[in] cb_data Callback data (pam_kbdint pointer is cleared).
 * @param[in] pam_data PAM exchange data, called with its lock held (unlocked here).
 * @return SSH_AUTH_SUCCESS if PAM authentication succeeded.
 * @return SSH_AUTH_DENIED otherwise.
 */
static int
nc_server_ssh_cb_pam_finish(struct nc_server_ssh_cb_data *cb_data, struct nc_server_ssh_cb_pam_data *pam_data)
{
    int rc;

    rc = pam_data->pam_ret;
    /* UNLOCK */
    pthread_mutex_unlock(&pam_data->lock);
    pthread_join(pam_data->thread, NULL);
    nc_server_ssh_cb_pam_data_free(pam_data);
    cb_data->pam_kbdint = NULL;

    return (rc == PAM_SUCCESS) ? SSH_AUTH_SUCCESS : SSH_AUTH_DENIED;
}

/**
 * @brief Send PAM prompts to the client as a keyboard-interactive request.
 *
 * @param[in] cb_data Callback data (pam_kbdint pointer is cleared on error).
 * @param[in] pam_data PAM exchange data, called with its lock held (unlocked here).
 * @param[in] message SSH message for sending prompts.
 * @return SSH_AUTH_INFO if the prompts were sent.
 * @return SSH_AUTH_DENIED on error (the PAM exchange is cancelled).
 */
static int
nc_server_ssh_cb_kbdint_pam_send_prompts(struct nc_server_ssh_cb_data *cb_data,
        struct nc_server_ssh_cb_pam_data *pam_data, ssh_message message)
{
    int rc, n_prompts;
    const char **prompts;
    char *echo;

    n_prompts = pam_data->n_prompts;
    prompts = pam_data->prompts;
    echo = pam_data->echo;

    /* UNLOCK */
    pthread_mutex_unlock(&pam_data->lock);
    rc = ssh_message_auth_interactive_request(message, NC_PAM_KBDINT_NAME, NC_PAM_KBDINT_INSTRUCTION,
            n_prompts, prompts, echo);

    if (rc != SSH_OK) {
        ERR(cb_data->session, "Failed to send an authentication request.");
        nc_server_ssh_cb_pam_cancel(pam_data);
        cb_data->pam_kbdint = NULL;
        return SSH_AUTH_DENIED;
    }

    return SSH_AUTH_INFO;
}

/**
 * @brief Phase 1 of callback-based PAM kbdint: start PAM thread, wait for prompts, send to client.
 *
 * @param[in] cb_data Callback data (stores pam_kbdint pointer for Phase 2).
 * @param[in] message SSH message for sending prompts.
 * @return SSH_AUTH_INFO if prompts sent.
 * @return SSH_AUTH_SUCCESS/SSH_AUTH_DENIED on PAM completion.
 */
static int
nc_server_ssh_cb_kbdint_pam_request(struct nc_server_ssh_cb_data *cb_data, ssh_message message)
{
    struct nc_server_ssh_cb_pam_data *pam_data;
    char *pam_config_name = NULL;
    int rc;

    /* check the PAM configuration */
    if (nc_server_ssh_get_pam_conf_filename(&pam_config_name)) {
        return SSH_AUTH_DENIED;
    }
    if (!pam_config_name) {
        ERR(cb_data->session, "PAM configuration filename not set.");
        return SSH_AUTH_DENIED;
    }
    free(pam_config_name);

    /* cancel any in-progress PAM exchange, e.g. the client abandoned the previous one */
    nc_server_ssh_cb_kbdint_pam_cancel_stored(cb_data);

    /* allocate and initialize PAM bridge data */
    pam_data = calloc(1, sizeof *pam_data);
    NC_CHECK_ERRMEM_RET(!pam_data, SSH_AUTH_DENIED);

    pthread_mutex_init(&pam_data->lock, NULL);
    pthread_cond_init(&pam_data->changed, NULL);
    pam_data->username = cb_data->session->username;
    pam_data->session = cb_data->session;
    pam_data->state = NC_PAM_RUNNING;
    cb_data->pam_kbdint = pam_data;

    /* start PAM thread */
    rc = pthread_create(&pam_data->thread, NULL, nc_server_ssh_cb_pam_thread, pam_data);
    if (rc) {
        ERR(cb_data->session, "Failed to create PAM thread (%s).", strerror(rc));
        pthread_mutex_destroy(&pam_data->lock);
        pthread_cond_destroy(&pam_data->changed);
        free(pam_data);
        cb_data->pam_kbdint = NULL;
        return SSH_AUTH_DENIED;
    }

    /* wait for PAM thread to produce prompts or finish */
    /* LOCK */
    pthread_mutex_lock(&pam_data->lock);
    while (pam_data->state == NC_PAM_RUNNING) {
        pthread_cond_wait(&pam_data->changed, &pam_data->lock);
    }

    if (pam_data->state == NC_PAM_DONE) {
        /* PAM finished without needing prompts (error or immediate success) */
        return nc_server_ssh_cb_pam_finish(cb_data, pam_data);
    }

    /* state == NC_PAM_PROMPTS_READY: send prompts to client */
    return nc_server_ssh_cb_kbdint_pam_send_prompts(cb_data, pam_data, message);
}

/**
 * @brief Phase 2 of callback-based PAM kbdint: read answers, pass to PAM thread, wait for result.
 *
 * @param[in] cb_data Callback data (contains pam_kbdint from Phase 1).
 * @param[in] message SSH message for sending additional prompts if needed.
 * @return SSH_AUTH_INFO if more prompts needed.
 * @return SSH_AUTH_SUCCESS/SSH_AUTH_DENIED on completion.
 */
static int
nc_server_ssh_cb_kbdint_pam_response(struct nc_server_ssh_cb_data *cb_data, ssh_message message)
{
    struct nc_server_ssh_cb_pam_data *pam_data = cb_data->pam_kbdint;
    struct nc_session *session = cb_data->session;
    int n_answers, i, rc = SSH_AUTH_DENIED;
    char **answers = NULL;
    const char *answer;

    if (!pam_data) {
        ERR(session, "Keyboard-interactive response received without prior request.");
        return SSH_AUTH_DENIED;
    }

    /* read answers from libssh kbdint structure */
    n_answers = ssh_userauth_kbdint_getnanswers(session->ti.libssh.session);
    if (n_answers < 0) {
        ERR(session, "Failed to get number of kbdint answers.");
        nc_server_ssh_cb_pam_cancel(pam_data);
        cb_data->pam_kbdint = NULL;
        return SSH_AUTH_DENIED;
    }

    if (n_answers) {
        answers = calloc(n_answers, sizeof *answers);
        NC_CHECK_ERRMEM_GOTO(!answers, (rc = SSH_AUTH_DENIED, n_answers = 0), cleanup);
    }

    for (i = 0; i < n_answers; i++) {
        answer = ssh_userauth_kbdint_getanswer(session->ti.libssh.session, i);

        if (!answer) {
            ERR(session, "Failed to get keyboard-interactive answer %d.", i);
            rc = SSH_AUTH_DENIED;
            goto cleanup;
        }
        answers[i] = strdup(answer);
        NC_CHECK_ERRMEM_GOTO(!answers[i], rc = SSH_AUTH_DENIED, cleanup);
    }

    /* pass answers to PAM thread */
    /* LOCK */
    pthread_mutex_lock(&pam_data->lock);
    pam_data->n_answers = n_answers;
    pam_data->answers = answers;
    pam_data->state = NC_PAM_ANSWERS_READY;
    pthread_cond_signal(&pam_data->changed);

    /* wait for PAM thread to process: either new prompts or completion */
    while (pam_data->state == NC_PAM_ANSWERS_READY) {
        pthread_cond_wait(&pam_data->changed, &pam_data->lock);
    }

    /* answers have been consumed by PAM thread, free them */
    for (i = 0; i < n_answers; i++) {
        free(answers[i]);
    }
    free(answers);
    pam_data->answers = NULL;
    answers = NULL;

    if (pam_data->state == NC_PAM_DONE) {
        return nc_server_ssh_cb_pam_finish(cb_data, pam_data);
    }

    /* state == NC_PAM_PROMPTS_READY: send new prompts to client */
    return nc_server_ssh_cb_kbdint_pam_send_prompts(cb_data, pam_data, message);

cleanup:
    if (answers) {
        for (i = 0; i < n_answers; i++) {
            free(answers[i]);
        }
        free(answers);
    }
    nc_server_ssh_cb_pam_cancel(pam_data);
    cb_data->pam_kbdint = NULL;
    return rc;
}

#elif defined (HAVE_SHADOW)

/**
 * @brief Send a password prompt to the client (Phase 1 of callback-based shadow kbdint).
 *
 * @param[in] session NETCONF session.
 * @param[in] username Username of the client to authenticate.
 * @param[in] msg SSH message with the keyboard-interactive authentication request.
 * @return SSH_AUTH_INFO if the prompt was sent successfully.
 * @return SSH_AUTH_DENIED on error.
 */
static int
nc_server_ssh_cb_kbdint_shadow_request(struct nc_session *session, const char *username, ssh_message msg)
{
    return nc_server_ssh_kbdint_send_passwd_prompt(session, username, msg) ? SSH_AUTH_DENIED : SSH_AUTH_INFO;
}

/**
 * @brief Check the client's password answer against the shadow hash (Phase 2 of callback-based shadow kbdint).
 *
 * @param[in] session NETCONF session.
 * @param[in] username Username of the client to authenticate.
 * @return SSH_AUTH_SUCCESS if the password matches.
 * @return SSH_AUTH_DENIED otherwise.
 */
static int
nc_server_ssh_cb_kbdint_shadow_response(struct nc_session *session, const char *username)
{
    int n_answers = ssh_userauth_kbdint_getnanswers(session->ti.libssh.session);

    return nc_server_ssh_kbdint_verify_passwd(session, username, n_answers) ? SSH_AUTH_DENIED : SSH_AUTH_SUCCESS;
}

#endif

/**
 * @brief Common setup for all callback auth methods: save username, send banner,
 *        validate username consistency, check local-users support, find auth client,
 *        and initialize auth state.
 *
 * @param[in] cb_data Callback data.
 * @param[in] user Username.
 * @param[out] local_users_supported Set to 1 if local users are supported, 0 otherwise.
 * @param[out] auth_client Set to the found auth_client (may be NULL for system users).
 * @return 0 on success,
 * @return -1 on failure (caller should return SSH_AUTH_DENIED).
 */
static int
nc_server_ssh_cb_auth_common_setup(struct nc_server_ssh_cb_data *cb_data, const char *user,
        int *local_users_supported, struct nc_auth_client **auth_client)
{
    struct nc_session *session = cb_data->session;
    struct nc_server_ssh_opts *opts = cb_data->opts;

    if (session->flags & NC_SESSION_SSH_AUTHENTICATED) {
        ERR(session, "User \"%s\" authenticated, but requested another authentication.", session->username);
        return -1;
    }

    *local_users_supported = 0;
    *auth_client = NULL;

    if (!user) {
        nc_server_ssh_auth_attempt_failed(session);
        return -1;
    }

    /* Save the username if this is the first attempt */
    if (!session->username) {
        session->username = strdup(user);
        NC_CHECK_ERRMEM_RET(!session->username, -1);

        /* send the SSH issue banner on the first userauth request */
        nc_server_ssh_send_banner(session, opts);
    } else if (strcmp(user, session->username)) {
        /* changing username not allowed */
        ERR(session, "User \"%s\" changed its username to \"%s\".", session->username, user);
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_OTHER;
        nc_server_ssh_auth_attempt_failed(session);
        return -1;
    }

    /* Check if local users are supported via the YANG model */
    *local_users_supported = nc_ssh_check_local_user_support(session);
    if (*local_users_supported < 0) {
        /* fatal error checking local users support */
        nc_server_ssh_auth_attempt_failed(session);
        return -1;
    }

    /* Find the auth client if local users are supported */
    if (*local_users_supported) {
        *auth_client = nc_ssh_find_auth_client(opts, user, session);

        if (!*auth_client) {
            ERR(session, "User \"%s\" not known by the server.", user);
            /* advertise only publickey so there is no interaction and it is simply denied */
            ssh_set_auth_methods(session->ti.libssh.session, SSH_AUTH_METHOD_PUBLICKEY);
            nc_server_ssh_auth_attempt_failed(session);
            return -1;
        }
    }

    assert(!*local_users_supported || *auth_client);

    nc_ssh_auth_state_init(session, &cb_data->auth_state, *local_users_supported, *auth_client);

    return 0;
}

int
nc_server_ssh_cb_auth_none(ssh_session UNUSED(libssh_sess), const char *user, void *userdata)
{
    struct nc_server_ssh_cb_data *cb_data = (struct nc_server_ssh_cb_data *)userdata;
    struct nc_session *session = cb_data->session;
    struct nc_auth_client *auth_client = NULL;
    int local_users_supported = 0;

    if (nc_server_ssh_cb_auth_common_setup(cb_data, user, &local_users_supported, &auth_client)) {
        return SSH_AUTH_DENIED;
    }

    if (local_users_supported && auth_client->none_enabled) {
        return nc_ssh_auth_success(session, &cb_data->auth_state, SSH_AUTH_METHOD_NONE);
    }

    nc_server_ssh_auth_attempt_failed(session);
    return SSH_AUTH_DENIED;
}

int
nc_server_ssh_cb_auth_password(ssh_session UNUSED(libssh_sess), const char *user, const char *password, void *userdata)
{
    struct nc_server_ssh_cb_data *cb_data = (struct nc_server_ssh_cb_data *)userdata;
    struct nc_session *session = cb_data->session;
    int local_users_supported = 0;
    struct nc_auth_client *auth_client = NULL;
    int rc = 0;

    if (nc_server_ssh_cb_auth_common_setup(cb_data, user, &local_users_supported, &auth_client)) {
        return SSH_AUTH_DENIED;
    }

    rc = nc_server_ssh_auth_password_check(session, user, password, auth_client, local_users_supported);

    if (rc == 0) {
        return nc_ssh_auth_success(session, &cb_data->auth_state, SSH_AUTH_METHOD_PASSWORD);
    } else {
        nc_server_ssh_auth_attempt_failed(session);
        return SSH_AUTH_DENIED;
    }
}

int
nc_server_ssh_cb_auth_pubkey(ssh_session UNUSED(libssh_sess), const char *user, struct ssh_key_struct *pubkey, char signature_state, void *userdata)
{
    struct nc_server_ssh_cb_data *cb_data = (struct nc_server_ssh_cb_data *)userdata;
    struct nc_session *session = cb_data->session;
    struct nc_auth_client *auth_client = NULL;
    int local_users_supported = 0;
    int ret = 0;

    if (nc_server_ssh_cb_auth_common_setup(cb_data, user, &local_users_supported, &auth_client)) {
        return SSH_AUTH_DENIED;
    }

    ret = nc_server_ssh_auth_pubkey_check(session, pubkey, auth_client, local_users_supported);

    if (ret == 0) {
        if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
            /* just checking if the public key would be accepted */
            return SSH_AUTH_SUCCESS;
        } else if (signature_state == SSH_PUBLICKEY_STATE_VALID) {
            return nc_ssh_auth_success(session, &cb_data->auth_state, SSH_AUTH_METHOD_PUBLICKEY);
        } else {
            VRB(session, "User \"%s\" tried to use an invalid public key signature.", session->username);
            nc_server_ssh_auth_attempt_failed(session);
            return SSH_AUTH_DENIED;
        }
    } else {
        nc_server_ssh_auth_attempt_failed(session);
        return SSH_AUTH_DENIED;
    }
}

/**
 * @brief Dispatch callback-based system keyboard-interactive authentication.
 *
 * @param[in] cb_data Callback data.
 * @param[in] message SSH message.
 * @param[in] user Username.
 * @return SSH_AUTH_INFO if prompts sent.
 * @return SSH_AUTH_SUCCESS if authenticated.
 * @return SSH_AUTH_DENIED on failure.
 */
static int
nc_server_ssh_cb_kbdint_system(struct nc_server_ssh_cb_data *cb_data, ssh_message message, const char *user)
{
    int is_response = ssh_message_auth_kbdint_is_response(message);

#ifdef HAVE_LIBPAM
    (void)user;
    if (is_response) {
        return nc_server_ssh_cb_kbdint_pam_response(cb_data, message);
    } else {
        return nc_server_ssh_cb_kbdint_pam_request(cb_data, message);
    }
#elif defined (HAVE_SHADOW)
    if (is_response) {
        return nc_server_ssh_cb_kbdint_shadow_response(cb_data->session, user);
    } else {
        return nc_server_ssh_cb_kbdint_shadow_request(cb_data->session, user, message);
    }
#else
    (void)is_response;
    (void)user;
    ERR(cb_data->session, "Keyboard-interactive method not supported.");
    return SSH_AUTH_DENIED;
#endif
}

int
nc_server_ssh_cb_auth_kbdint(ssh_message message, ssh_session UNUSED(libssh_sess), void *userdata)
{
    struct nc_server_ssh_cb_data *cb_data = (struct nc_server_ssh_cb_data *)userdata;
    struct nc_session *session = cb_data->session;
    struct nc_auth_client *auth_client = NULL;
    enum nc_kbdint_backend backend;
    int local_users_supported = 0;
    int ret = SSH_AUTH_DENIED;
    const char *user;

    int (*interactive_auth_clb)(const struct nc_session *session, ssh_session ssh_sess, ssh_message msg,
            void *user_data);
    void *interactive_auth_data;

    /* Extract the username from the message. */
    if (ssh_message_auth_kbdint_is_response(message) && session->username) {
        user = session->username;
    } else {
        user = ssh_message_auth_user(message);
    }

    if (nc_server_ssh_cb_auth_common_setup(cb_data, user, &local_users_supported, &auth_client)) {
#ifdef HAVE_LIBPAM
        /* cancel any in-progress PAM exchange before denying */
        nc_server_ssh_cb_kbdint_pam_cancel_stored(cb_data);
#endif
        return SSH_AUTH_DENIED;
    }

    /* select the kbdint backend based on the configuration */
    if (nc_server_ssh_kbdint_select_method(session, local_users_supported, auth_client, &backend)) {
        /* denied, the reason was already logged */
        nc_server_ssh_auth_attempt_failed(session);
#ifdef HAVE_LIBPAM
        /* cancel any in-progress PAM exchange before denying */
        nc_server_ssh_cb_kbdint_pam_cancel_stored(cb_data);
#endif
        return SSH_AUTH_DENIED;
    }

    if (backend == NC_KBDINT_BACKEND_CUSTOM_CLB) {
        /* custom interactive auth callback, it must not be called with the options lock held */
        if (nc_server_ssh_get_interactive_auth_clb(&interactive_auth_clb, &interactive_auth_data)) {
            nc_server_ssh_auth_attempt_failed(session);
            return SSH_AUTH_DENIED;
        }
        if (!interactive_auth_clb) {
            /* the callback was unset in the meantime */
            ERR(session, "Custom keyboard-interactive authentication callback not set.");
            nc_server_ssh_auth_attempt_failed(session);
            return SSH_AUTH_DENIED;
        }

        ret = interactive_auth_clb(session, session->ti.libssh.session, message, interactive_auth_data);
    } else {
        ret = nc_server_ssh_cb_kbdint_system(cb_data, message, user);
    }

    /* handle the result from the kbdint system dispatch */
    if (ret == SSH_AUTH_INFO) {
        /* prompts sent, waiting for client response — libssh sends no reply */
        return SSH_AUTH_INFO;
    } else if ((ret == SSH_AUTH_SUCCESS) || (ret == SSH_AUTH_PARTIAL)) {
        /* the custom callback may return SSH_AUTH_PARTIAL (libssh doc), treat it as a method
         * success — the outcome is recomputed against the configured methods */
        VRB(session, "User \"%s\" authenticated via keyboard-interactive.", user);
        return nc_ssh_auth_success(session, &cb_data->auth_state, SSH_AUTH_METHOD_INTERACTIVE);
    } else {
        VRB(session, "User \"%s\" authentication denied via keyboard-interactive.", user);
        nc_server_ssh_auth_attempt_failed(session);
        return SSH_AUTH_DENIED;
    }
}

/**
 * @brief Callback function for SSH channel subsystem request.
 *
 * @param[in] libssh_sess SSH session object.
 * @param[in] channel SSH channel the subsystem was requested on.
 * @param[in] subsystem Requested subsystem name (expected "netconf").
 * @param[in] userdata Pointer to user data (struct nc_ssh_channel_cb_data).
 * @return 0 on success.
 * @return 1 on error (unknown subsystem, duplicate request, or memory error).
 */
static int
nc_server_ssh_cb_channel_subsystem(ssh_session UNUSED(libssh_sess), ssh_channel channel, const char *subsystem, void *userdata)
{
    struct nc_session *new_session;
    struct nc_ssh_channel_cb_data *channel_data = userdata;
    struct nc_server_ssh_cb_data *cb_data = channel_data->cb_data;
    struct nc_session *session = cb_data->session;
    struct nc_ssh_channel_cb_data **chan_ptr;
    int rc;

    rc = nc_server_ssh_channel_subsys_check(session, channel, subsystem);
    if (rc < 0) {
        /* invalid request */
        return 1;
    }
    if (!rc) {
        /* the "netconf" subsystem requested on the first channel */
        return 0;
    }

    /* additional channel subsystem request - the channel must still be unclaimed */
    chan_ptr = &cb_data->channels;
    while (*chan_ptr && (*chan_ptr != channel_data)) {
        chan_ptr = &(*chan_ptr)->next;
    }
    if (!*chan_ptr) {
        /* channel already claimed by an earlier subsystem request (normally caught by
         * nc_server_ssh_channel_subsys_check()) */
        return 1;
    }

    /* new session is ready as far as SSH is concerned */
    new_session = nc_server_ssh_new_channel_session(session, channel);
    if (!new_session) {
        return 1;
    }

    /* Transfer ownership of channel callbacks to the new session and remove from cb_data to avoid double-free */
    *chan_ptr = channel_data->next;
    channel_data->next = NULL;

    new_session->ti.libssh.channel_cb = &channel_data->channel_cb;
    return 0;
}

ssh_channel
nc_server_ssh_cb_channel_open_request_session(ssh_session libssh_sess, void *userdata)
{
    struct nc_server_ssh_cb_data *cb_data = (struct nc_server_ssh_cb_data *)userdata;
    struct nc_session *session = cb_data->session;
    ssh_channel chan;
    struct nc_ssh_channel_cb_data *channel_data;

    /* first channel request */
    if (!session->ti.libssh.channel && (session->status != NC_STATUS_STARTING)) {
        ERRINT;
        return NULL;
    }

    /* create the new channel */
    chan = ssh_channel_new(libssh_sess);
    if (!chan) {
        ERR(session, "Session %u: failed to create a new SSH channel.", session->id);
        return NULL;
    }

    channel_data = calloc(1, sizeof *channel_data);
    if (!channel_data) {
        ssh_channel_free(chan);
        return NULL;
    }
    /* userdata is the whole channel_data so the subsystem callback recovers both cb_data and,
     * for additional channels, this structure itself to hand its ownership to the new session */
    channel_data->cb_data = cb_data;
    channel_data->channel_cb.userdata = channel_data;
    channel_data->channel_cb.channel_subsystem_request_function = nc_server_ssh_cb_channel_subsystem;
    ssh_callbacks_init(&channel_data->channel_cb);

    /* Bind the subsystem callback to this specific channel */
    ssh_set_channel_callbacks(chan, &channel_data->channel_cb);

    if (!session->ti.libssh.channel) {
        /* first channel - owned by the session, freed when the session is freed */
        session->ti.libssh.channel_cb = &channel_data->channel_cb;
        session->ti.libssh.channel = chan;
    } else {
        /* additional channel - track on cb_data so it can be freed if it is never claimed
         * by a netconf subsystem request (ownership transfers to a new session then) */
        channel_data->next = cb_data->channels;
        cb_data->channels = channel_data;
    }

    return chan;
}

void
nc_server_ssh_cb_data_free(void *cb_data)
{
    struct nc_server_ssh_cb_data *data = (struct nc_server_ssh_cb_data *)cb_data;
    struct nc_ssh_channel_cb_data *cur, *next;

    if (!data) {
        return;
    }

#ifdef HAVE_LIBPAM
    /* safety net: cancel a PAM thread left running, e.g. when auth succeeded via another method */
    if (data->pam_kbdint) {
        nc_server_ssh_cb_pam_cancel(data->pam_kbdint);
        data->pam_kbdint = NULL;
    }
#endif

    /* free any channel callback data that was never claimed by a netconf subsystem request */
    for (cur = data->channels; cur; cur = next) {
        next = cur->next;
        free(cur);
    }

    free(data);
}
