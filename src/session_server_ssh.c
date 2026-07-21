/**
 * @file session_server_ssh.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 SSH server session manipulation functions
 *
 * @copyright
 * Copyright (c) 2017 - 2026 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "config.h" /* Expose HAVE_LIBPAM and HAVE_SHADOW */

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libyang/libyang.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_LIBPAM
#   include <security/pam_appl.h>
#endif
#ifdef HAVE_SHADOW
#   include <shadow.h>
#endif

#include "compat.h"
#include "log_p.h"
#include "nc_version.h"
#include "session.h"
#include "session_p.h"
#include "session_server_ssh_wrapper.h"
#include "session_wrapper.h"

int
nc_ssh_check_local_user_support(struct nc_session *session)
{
    const struct ly_ctx *ctx;
    struct lys_module *mod;
    int rc;

    ctx = nc_session_get_ctx(session);
    mod = ly_ctx_get_module_latest(ctx, "ietf-ssh-server");
    if (!mod) {
        ERRINT;
        return -1;
    }

    rc = lys_feature_value(mod, "local-users-supported");
    if (rc == LY_SUCCESS) {
        return 1;
    } else if (rc == LY_ENOTFOUND) {
        return 0;
    } else {
        return -1;
    }
}

struct nc_auth_client *
nc_ssh_find_auth_client(struct nc_server_ssh_opts *opts, const char *user, struct nc_session *session)
{
    struct nc_endpt *referenced_endpt;
    LY_ARRAY_COUNT_TYPE u;

    if (!user) {
        return NULL;
    }

    for (u = 0; u < LY_ARRAY_COUNT(opts->auth_clients); u++) {
        if (!strcmp(opts->auth_clients[u].username, user)) {
            return &opts->auth_clients[u];
        }
    }

    /* client not known by the endpt, but it references another one so try it */
    if (opts->referenced_endpt_name) {
        if (nc_server_endpt_get(opts->referenced_endpt_name, &referenced_endpt)) {
            ERR(session, "Referenced endpoint \"%s\" not found.", opts->referenced_endpt_name);
            return NULL;
        }
        return nc_ssh_find_auth_client(referenced_endpt->opts.ssh, user, session);
    }
    return NULL;
}

void
nc_ssh_auth_state_init(struct nc_session *session, struct nc_auth_state *auth_state,
        int local_users_supported, struct nc_auth_client *auth_client)
{
    if (auth_state->method_count) {
        return;
    }

    if (local_users_supported) {
        if (auth_client->pubkey_store != NC_STORE_UNKNOWN) {
            auth_state->methods |= SSH_AUTH_METHOD_PUBLICKEY;
            auth_state->method_count++;
        }
        if (auth_client->password) {
            auth_state->methods |= SSH_AUTH_METHOD_PASSWORD;
            auth_state->method_count++;
        }
        if (auth_client->kbdint_method != NC_KBDINT_AUTH_METHOD_NONE) {
            auth_state->methods |= SSH_AUTH_METHOD_INTERACTIVE;
            auth_state->method_count++;
        }
        if (auth_client->none_enabled) {
            auth_state->methods |= SSH_AUTH_METHOD_NONE;
            auth_state->method_count++;
        }
    } else {
        /* no local users meaning pw, pubkey and kbdint methods are supported, method count is set to 1,
         * because only one method is needed for successful auth */
        auth_state->methods = SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE;
        auth_state->method_count = 1;
    }

    ssh_set_auth_methods(session->ti.libssh.session, auth_state->methods);
}

int
nc_ssh_auth_success(struct nc_session *session, struct nc_auth_state *auth_state, int method)
{
    auth_state->success_methods |= method;
    auth_state->success_count++;

    if (auth_state->success_count < auth_state->method_count) {
        /* success, but he needs to do another method */
        VRB(session, "User \"%s\" partially authenticated, but still needs to authenticate via the rest of his configured methods.",
                session->username);
        ssh_set_auth_methods(session->ti.libssh.session, auth_state->methods & ~auth_state->success_methods);
        return SSH_AUTH_PARTIAL;
    }

    /* authenticated */
    session->flags |= NC_SESSION_SSH_AUTHENTICATED;
    VRB(session, "User \"%s\" authenticated.", session->username);
    return SSH_AUTH_SUCCESS;
}

void
nc_server_ssh_auth_attempt_failed(struct nc_session *session)
{
    ++session->opts.server.ssh_auth_attempts;
    VRB(session, "Failed user \"%s\" authentication attempt (#%d).",
            session->username ? session->username : "unknown", session->opts.server.ssh_auth_attempts);
}

int
nc_server_ssh_auth_password_check(struct nc_session *session, const char *user,
        const char *password, struct nc_auth_client *auth_client, int local_users_supported)
{
    int rc;
    char *stored_password = NULL;

    assert(!local_users_supported || auth_client);

    /* Get the stored password */
    if (local_users_supported) {
        stored_password = auth_client->password;
        if (!stored_password) {
            /* client requested password auth, but it is not configured for this user, so just deny */
            DBG(session,
                    "User \"%s\" does not have password method configured, but a request was received.", user);
            return 1;
        }
    } else {
#ifdef HAVE_SHADOW
        stored_password = nc_server_ssh_get_pwd_hash(user);
        if (!stored_password) {
            return 1;
        }
#else
        ERR(session, "Obtaining password from system not supported.");
        return 1;
#endif
    }

    /* Compare the passwords */
    rc = nc_server_ssh_compare_password(stored_password, password);

    if (!local_users_supported) {
        free(stored_password);
    }

    return rc;
}

int
nc_server_ssh_kbdint_select_method(struct nc_session *session, int local_users_supported,
        struct nc_auth_client *auth_client, enum nc_kbdint_backend *backend)
{
    assert(!local_users_supported || auth_client);

    if (!local_users_supported) {
        /* system users always authenticate against the system method */
        *backend = NC_KBDINT_BACKEND_SYSTEM;
        return 0;
    }

    if (auth_client->kbdint_method == NC_KBDINT_AUTH_METHOD_NONE) {
        /* client requested kbdint auth, but it is not configured for this user, so just deny */
        DBG(session,
                "User \"%s\" does not have kbdint method configured, but a request was received.", session->username);
        return 1;
    }

    if (server_opts.interactive_auth_clb) {
        /* custom callback has higher priority */
        *backend = NC_KBDINT_BACKEND_CUSTOM_CLB;
        return 0;
    }

    if (auth_client->kbdint_method == NC_KBDINT_AUTH_METHOD_SYSTEM) {
        *backend = NC_KBDINT_BACKEND_SYSTEM;
        return 0;
    }

    /* add future methods here */
    ERR(session, "Keyboard-interactive authentication method not supported.");
    return 1;
}

int
nc_server_ssh_auth_pubkey_check(struct nc_session *session, ssh_key pubkey,
        struct nc_auth_client *auth_client, int local_users_supported)
{
    struct nc_public_key *pubkeys = NULL;
    uint32_t pubkey_count = 0, i;
    int ret = 0;

    assert(!local_users_supported || auth_client);

    /* get the public keys */
    if (!local_users_supported) {
        /* system user, get the keys from the system (these need to be free'd as they're not in the config) */
        ret = nc_server_ssh_get_system_keys(session->username, &pubkeys, &pubkey_count);
        if (ret) {
            goto cleanup;
        }
    } else {
        if (auth_client->pubkey_store == NC_STORE_UNKNOWN) {
            /* client requested pubkey auth, but it is not configured for this user, so just deny */
            DBG(session,
                    "User \"%s\" does not have public key method configured, but a request was received.", session->username);
            return 1;
        }

        if (auth_client->pubkey_store == NC_STORE_SYSTEM) {
            /* get the keys from the system (these need to be free'd as they're not in the config) */
            ret = nc_server_ssh_get_system_keys(session->username, &pubkeys, &pubkey_count);
            if (ret) {
                goto cleanup;
            }
        } else if (auth_client->pubkey_store == NC_STORE_LOCAL) {
            /* saved directly in the user's config */
            pubkeys = auth_client->pubkeys;
            pubkey_count = LY_ARRAY_COUNT(auth_client->pubkeys);
        } else if (auth_client->pubkey_store == NC_STORE_TRUSTSTORE) {
            /* need to fetch from the truststore */
            ret = nc_server_ssh_ts_ref_get_keys(auth_client->ts_ref, &pubkeys, &pubkey_count);
            if (ret) {
                goto cleanup;
            }
        } else {
            ERRINT;
            return 1;
        }
    }

    /* compare the received pubkey with the authorized ones */
    if (nc_server_ssh_auth_pubkey_compare_key(pubkey, pubkeys, pubkey_count)) {
        VRB(session, "User \"%s\" tried to use an unknown (unauthorized) public key.", session->username);
        ret = 1;
        goto cleanup;
    }

cleanup:
    if (!local_users_supported || (auth_client->pubkey_store == NC_STORE_SYSTEM)) {
        for (i = 0; i < pubkey_count; i++) {
            free(pubkeys[i].name);
            free(pubkeys[i].data);
        }
        free(pubkeys);
    }

    return ret;
}

#ifdef HAVE_LIBPAM

int
nc_server_ssh_pam_conv_parse(struct nc_session *session, int n_messages,
        const struct pam_message **msg, struct pam_response **resp,
        int *n_prompts, const char ***prompts, char **echo)
{
    int i, j, t, n_requests = n_messages;

    *resp = NULL;
    *n_prompts = 0;
    *prompts = NULL;
    *echo = NULL;

    /* PAM_MAX_NUM_MSG == 32 by default */
    if ((n_messages <= 0) || (n_messages >= PAM_MAX_NUM_MSG)) {
        ERR(session, "Bad number of PAM messages (#%d).", n_messages);
        return PAM_CONV_ERR;
    }

    /* only accepting these 4 types of messages */
    for (i = 0; i < n_messages; i++) {
        t = msg[i]->msg_style;
        if ((t != PAM_PROMPT_ECHO_OFF) && (t != PAM_PROMPT_ECHO_ON) &&
                (t != PAM_TEXT_INFO) && (t != PAM_ERROR_MSG)) {
            ERR(session, "PAM conversation callback received an unexpected type of message.");
            return PAM_CONV_ERR;
        }
    }

    /* handle info/error messages, count actual prompts */
    for (i = 0; i < n_messages; i++) {
        if (msg[i]->msg_style == PAM_TEXT_INFO) {
            VRB(session, "PAM conversation callback received a message with some information for the client (%s).", msg[i]->msg);
            n_requests--;
        }
        if (msg[i]->msg_style == PAM_ERROR_MSG) {
            ERR(session, "PAM conversation callback received an error message (%s).", msg[i]->msg);
            return PAM_CONV_ERR;
        }
    }

    /* no actual prompts */
    if (n_requests <= 0) {
        return PAM_SUCCESS;
    }

    /* build response, prompt and echo arrays */
    *resp = calloc(n_requests, sizeof **resp);
    *prompts = calloc(n_requests, sizeof **prompts);
    *echo = calloc(n_requests, sizeof **echo);
    if (!(*resp) || !(*prompts) || !(*echo)) {
        ERRMEM;
        free(*resp);
        *resp = NULL;
        free(*prompts);
        *prompts = NULL;
        free(*echo);
        *echo = NULL;
        return PAM_BUF_ERR;
    }

    j = 0;
    for (i = 0; i < n_messages; i++) {
        if ((msg[i]->msg_style == PAM_PROMPT_ECHO_ON) || (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF)) {
            (*prompts)[j] = msg[i]->msg;
            if (msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
                (*echo)[j] = 1;
            }
            j++;
        }
    }

    *n_prompts = n_requests;
    return PAM_SUCCESS;
}

int
nc_server_ssh_pam_conv_fill(struct nc_session *session, struct pam_response *resp,
        int n_prompts, int n_answers, const char **answers)
{
    int i, j;

    if (n_answers != n_prompts) {
        ERR(session, "Expected %d response(s), got %d.", n_prompts, n_answers);
        return PAM_CONV_ERR;
    }

    for (i = 0; i < n_answers; i++) {
        resp[i].resp = strdup(answers[i]);
        /* freeing the responses is the caller's responsibility, however on mem alloc failure
         * it is safer to free the already copied responses here and set them to NULL */
        if (!resp[i].resp) {
            for (j = 0; j < i; j++) {
                free(resp[j].resp);
                resp[j].resp = NULL;
            }
            ERRMEM;
            return PAM_BUF_ERR;
        }
    }

    return PAM_SUCCESS;
}

int
nc_server_ssh_pam_authenticate(struct nc_session *session, const char *username,
        const struct pam_conv *conv)
{
    pam_handle_t *pam_h = NULL;
    int ret;

    /* check the PAM configuration */
    if (!server_opts.pam_config_name) {
        ERR(session, "PAM configuration filename not set.");
        return 1;
    }

    /* initialize PAM and see if the given configuration file exists */
    ret = pam_start(server_opts.pam_config_name, username, conv, &pam_h);
    if (ret != PAM_SUCCESS) {
        ERR(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
        goto cleanup;
    }

    /* authentication based on the modules listed in the configuration file */
    ret = pam_authenticate(pam_h, 0);
    if (ret != PAM_SUCCESS) {
        if (ret == PAM_ABORT) {
            ERR(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
        } else {
            VRB(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
        }
        goto cleanup;
    }

    /* correct token entered, check other requirements (the time of the day, expired token, ...) */
    ret = pam_acct_mgmt(pam_h, 0);
    if ((ret != PAM_SUCCESS) && (ret != PAM_NEW_AUTHTOK_REQD)) {
        VRB(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
        goto cleanup;
    }

    /* if a token has expired a new one will be generated */
    if (ret == PAM_NEW_AUTHTOK_REQD) {
        VRB(session, "PAM warning occurred (%s).", pam_strerror(pam_h, ret));
        ret = pam_chauthtok(pam_h, PAM_CHANGE_EXPIRED_AUTHTOK);
        if (ret == PAM_SUCCESS) {
            VRB(session, "The authentication token of user \"%s\" updated successfully.", username);
        } else {
            ERR(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
        }
    }

cleanup:
    /* destroy the PAM context */
    if (pam_h && (pam_end(pam_h, ret) != PAM_SUCCESS)) {
        ERR(NULL, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
    }
    return ret;
}

#endif /* HAVE_LIBPAM */

int
nc_server_ssh_channel_subsys_check(struct nc_session *session, ssh_channel channel, const char *subsystem)
{
    struct nc_session *siter;

    if (strcmp(subsystem, "netconf")) {
        WRN(session, "Received an unknown subsystem \"%s\" request.", subsystem);
        return -1;
    }

    if (session->ti.libssh.channel == channel) {
        /* first channel requested */
        if (session->ti.libssh.next || (session->status != NC_STATUS_STARTING)) {
            ERRINT;
            return -1;
        }
        if (session->flags & NC_SESSION_SSH_SUBSYS_NETCONF) {
            ERR(session, "Subsystem \"netconf\" requested for the second time.");
            return -1;
        }

        session->flags |= NC_SESSION_SSH_SUBSYS_NETCONF;
        return 0;
    }

    /* an additional channel must not be claimed by a session created by an earlier subsystem request */
    for (siter = session->ti.libssh.next; siter && (siter != session); siter = siter->ti.libssh.next) {
        if (siter->ti.libssh.channel == channel) {
            ERR(session, "Subsystem \"netconf\" requested for an already claimed channel.");
            return -1;
        }
    }

    /* an additional channel needs a new session */
    return 1;
}

struct nc_session *
nc_server_ssh_new_channel_session(struct nc_session *session, ssh_channel channel)
{
    struct nc_session *new_session;

    new_session = nc_new_session(NC_SERVER, 1);
    NC_CHECK_ERRMEM_RET(!new_session, NULL);

    new_session->status = NC_STATUS_STARTING;
    new_session->ti_type = NC_TI_SSH;
    new_session->io_lock = session->io_lock;
    new_session->ti.libssh.channel = channel;
    new_session->ti.libssh.session = session->ti.libssh.session;
    new_session->username = strdup(session->username);
    NC_CHECK_ERRMEM_GOTO(!new_session->username, , error);

    if (session->host) {
        new_session->host = strdup(session->host);
        NC_CHECK_ERRMEM_GOTO(!new_session->host, , error);
    }

    new_session->port = session->port;
    new_session->ctx = (struct ly_ctx *)session->ctx;
    new_session->flags = NC_SESSION_SSH_AUTHENTICATED | NC_SESSION_SSH_SUBSYS_NETCONF | NC_SESSION_SHAREDCTX;

    /* insert the new session into the ring now that it is fully constructed */
    if (!session->ti.libssh.next) {
        new_session->ti.libssh.next = session;
    } else {
        new_session->ti.libssh.next = session->ti.libssh.next;
    }
    session->ti.libssh.next = new_session;

    return new_session;

error:
    /* detach the state shared with the parent session, so that nc_session_free() does not free it */
    new_session->ti.libssh.session = NULL;
    new_session->io_lock = NULL;
    nc_session_free(new_session, NULL);
    return NULL;
}

/**
 * @brief Stores the private key data as a temporary file.
 *
 * @param[in] in Private key data.
 * @param[in] privkey_format String representation of the private key format.
 * @return Path to the created temporary file or NULL on fail.
 */
static char *
nc_server_ssh_privkey_data_to_tmp_file(const char *in, const char *privkey_format)
{
    char path[12] = "/tmp/XXXXXX";
    int fd, written;
    unsigned len;
    mode_t umode;
    FILE *file;

    NC_CHECK_ARG_RET(NULL, in, NULL);

    umode = umask(0177);
    fd = mkstemp(path);
    umask(umode);
    if (fd == -1) {
        return NULL;
    }

    file = fdopen(fd, "w");
    if (!file) {
        close(fd);
        return NULL;
    }

    /* write header */
    written = fwrite("-----BEGIN", 1, 10, file);
    if (privkey_format) {
        written += fwrite(privkey_format, 1, strlen(privkey_format), file);
        written += fwrite("PRIVATE KEY-----\n", 1, 17, file);
    } else {
        written += fwrite(" PRIVATE KEY-----\n", 1, 18, file);
    }

    /* write data */
    written += fwrite(in, 1, strlen(in), file);

    /* write footer */
    written += fwrite("\n-----END", 1, 9, file);
    if (privkey_format) {
        written += fwrite(privkey_format, 1, strlen(privkey_format), file);
        written += fwrite("PRIVATE KEY-----", 1, 16, file);
    } else {
        written += fwrite(" PRIVATE KEY-----", 1, 17, file);
    }

    fclose(file);

    /* checksum */
    if (privkey_format) {
        len = 10 + strlen(privkey_format) + 17 + strlen(in) + 9 + strlen(privkey_format) + 16;
    } else {
        len = 10 + 18 + strlen(in) + 9 + 17;
    }

    if ((unsigned)written != len) {
        unlink(path);
        return NULL;
    }

    return strdup(path);
}

/**
 * @brief Get asymmetric key from the keystore.
 *
 * @param[in] referenced_name Name of the asymmetric key in the keystore.
 * @param[out] askey Referenced asymmetric key.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_ssh_ks_ref_get_key(const char *referenced_name, struct nc_asymmetric_key **askey)
{
    LY_ARRAY_COUNT_TYPE i;
    struct nc_keystore *ks = &server_opts.config.keystore;

    *askey = NULL;

    /* lookup name */
    LY_ARRAY_FOR(ks->entries, i) {
        if (!strcmp(referenced_name, ks->entries[i].asym_key.name)) {
            break;
        }
    }
    if (i == LY_ARRAY_COUNT(ks->entries)) {
        ERR(NULL, "Keystore entry \"%s\" not found.", referenced_name);
        return 1;
    }

    *askey = &ks->entries[i].asym_key;

    /* check if the referenced public key is SubjectPublicKeyInfo */
    if ((*askey)->pubkey.data && nc_is_pk_subject_public_key_info((*askey)->pubkey.data)) {
        ERR(NULL, "The public key of the referenced hostkey \"%s\" is in the SubjectPublicKeyInfo format, "
                "which is not allowed in the SSH!", referenced_name);
        return 1;
    }

    return 0;
}

int
nc_server_ssh_ts_ref_get_keys(const char *referenced_name, struct nc_public_key **pubkeys, uint32_t *pubkey_count)
{
    LY_ARRAY_COUNT_TYPE i;
    struct nc_public_key *pubkey;
    struct nc_truststore *ts = &server_opts.config.truststore;

    *pubkeys = NULL;
    *pubkey_count = 0;

    /* lookup name */
    LY_ARRAY_FOR(ts->pubkey_bags, i) {
        if (!strcmp(referenced_name, ts->pubkey_bags[i].name)) {
            break;
        }
    }
    if (i == LY_ARRAY_COUNT(ts->pubkey_bags)) {
        ERR(NULL, "Truststore entry \"%s\" not found.", referenced_name);
        return 1;
    }

    /* check if any of the referenced public keys is SubjectPublicKeyInfo */
    LY_ARRAY_FOR(ts->pubkey_bags[i].pubkeys, struct nc_public_key, pubkey) {
        if (nc_is_pk_subject_public_key_info(pubkey->data)) {
            ERR(NULL, "A public key of the referenced public key bag \"%s\" is in the SubjectPublicKeyInfo format, "
                    "which is not allowed in SSH!", referenced_name);
            return 1;
        }
    }

    *pubkeys = ts->pubkey_bags[i].pubkeys;
    *pubkey_count = LY_ARRAY_COUNT(ts->pubkey_bags[i].pubkeys);
    return 0;
}

/**
 * @brief Convert UID to string.
 *
 * @param[in] uid UID to convert.
 * @return UID converted to string or NULL on fail.
 */
static char *
nc_server_ssh_uid_to_str(uid_t uid)
{
    int buf_len;
    char *uid_str;

    /* get the number of digits and alloc */
    buf_len = snprintf(NULL, 0, "%u", uid);
    uid_str = malloc(buf_len + 1);
    NC_CHECK_ERRMEM_RET(!uid_str, NULL);

    /* convert to string */
    sprintf(uid_str, "%u", uid);
    uid_str[buf_len] = '\0';
    return uid_str;
}

/**
 * @brief Append a character or a string to a string.
 *
 * @param[in] src_c Source character.
 * @param[in] src_str Source string.
 * @param[in,out] size Size of the destination string.
 * @param[out] idx Index of the next character to write.
 * @param[out] dst Destination string.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_ssh_str_append(const char src_c, const char *src_str, int *size, int *idx, char **dst)
{
    int src_size, allocate = 0, ret;

    /* get size of char/string we want to append */
    if (src_str) {
        src_size = strlen(src_str);
    } else {
        src_size = 1;
    }

    /* check if we have enough space, if not realloc */
    while ((src_size + *idx) >= *size) {
        (*size) += 16;
        allocate = 1;
    }
    if (allocate) {
        *dst = nc_realloc(*dst, *size);
        NC_CHECK_ERRMEM_RET(!*dst, 1);
    }

    /* append the char/string */
    if (src_str) {
        ret = sprintf(*dst + *idx, "%s", src_str);
    } else {
        ret = sprintf(*dst + *idx, "%c", src_c);
    }
    if (ret < 0) {
        return 1;
    }

    *idx += ret;
    return 0;
}

/**
 * @brief Get the path to the system public keys from format set by an API.
 *
 * @param[in] username Username.
 * @param[out] out_path Path to the system public keys.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_ssh_get_system_keys_path(const char *username, char **out_path)
{
    int ret = 0, i, have_percent = 0, size = 0, idx = 0;
    const char *path_fmt = server_opts.authkey_path_fmt;
    char *path = NULL, *buf = NULL, *uid = NULL;
    struct passwd *pw, pw_buf;
    size_t buf_len = 0;

    if (!path_fmt) {
        ERR(NULL, "System public keys path format not set.");
        return 1;
    }

    /* check if the path format contains any tokens */
    if (strstr(path_fmt, "%h") || strstr(path_fmt, "%U") || strstr(path_fmt, "%u") || strstr(path_fmt, "%%")) {
        /* get pw */
        pw = nc_getpw(0, username, &pw_buf, &buf, &buf_len);
        if (!pw) {
            ERR(NULL, "Unable to get passwd entry for user \"%s\".", username);
            ret = 1;
            goto cleanup;
        }

        /* convert UID to a string */
        uid = nc_server_ssh_uid_to_str(pw->pw_uid);
        if (!uid) {
            ret = 1;
            goto cleanup;
        }
    } else {
        /* no tokens, just copy the path and return */
        *out_path = strdup(path_fmt);
        NC_CHECK_ERRMEM_RET(!*out_path, 1);
        goto cleanup;
    }

    /* go over characters from format, copy them to path and interpret tokens correctly */
    for (i = 0; path_fmt[i]; i++) {
        if (have_percent) {
            /* special token, need to convert it */
            if (path_fmt[i] == '%') {
                ret = nc_server_ssh_str_append('%', NULL, &size, &idx, &path);
            } else if (path_fmt[i] == 'h') {
                /* user home */
                ret = nc_server_ssh_str_append(0, pw->pw_dir, &size, &idx, &path);
            } else if (path_fmt[i] == 'u') {
                /* username */
                ret = nc_server_ssh_str_append(0, username, &size, &idx, &path);
            } else if (path_fmt[i] == 'U') {
                /* UID */
                ret = nc_server_ssh_str_append(0, uid, &size, &idx, &path);
            } else {
                ERR(NULL, "Failed to parse system public keys path format \"%s\".", server_opts.authkey_path_fmt);
                ret = 1;
            }

            have_percent = 0;
        } else {
            if (path_fmt[i] == '%') {
                have_percent = 1;
            } else {
                /* ordinary character with no meaning */
                ret = nc_server_ssh_str_append(path_fmt[i], NULL, &size, &idx, &path);
            }
        }

        if (ret) {
            goto cleanup;
        }
    }

    *out_path = path;
    path = NULL;

cleanup:
    free(uid);
    free(buf);
    free(path);
    return ret;
}

/**
 * @brief Read public keys from the authorized keys file.
 *
 * @param[in] path Path to the authorized keys file.
 * @param[out] pubkeys Public keys.
 * @param[out] pubkey_count Public key count.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_ssh_read_authorized_keys_file(const char *path, struct nc_public_key **pubkeys, uint32_t *pubkey_count)
{
    int ret = 0, rc, line_num = 0;
    FILE *f = NULL;
    char *line = NULL, *ptr, *ptr2;
    size_t n;
    enum ssh_keytypes_e ktype;

    NC_CHECK_ARG_RET(NULL, path, pubkeys, 1);

    *pubkeys = NULL;
    *pubkey_count = 0;

    f = fopen(path, "r");
    if (!f) {
        ERR(NULL, "Unable to open \"%s\" (%s).", path, strerror(errno));
        ret = 1;
        goto cleanup;
    }

    while (getline(&line, &n, f) > -1) {
        ++line_num;
        if ((line[0] == '#') || (line[0] == '\n')) {
            /* comment or empty line */
            continue;
        }

        /* separate key type */
        ptr = line;
        for (ptr2 = ptr; ptr2[0] && !isspace(ptr2[0]); ptr2++) {}
        if (!ptr2[0]) {
            ERR(NULL, "Invalid format of authorized keys file \"%s\" on line %d.", path, line_num);
            ret = 1;
            goto cleanup;
        }
        ptr2[0] = '\0';

        /* detect key type */
        ktype = ssh_key_type_from_name(ptr);
        if ((ktype != SSH_KEYTYPE_RSA) && (ktype != SSH_KEYTYPE_ECDSA_P256) && (ktype != SSH_KEYTYPE_ECDSA_P384) &&
                (ktype != SSH_KEYTYPE_ECDSA_P521) && (ktype != SSH_KEYTYPE_ED25519)) {
            WRN(NULL, "Unsupported key type \"%s\" in authorized keys file \"%s\" on line %d.", ptr, path, line_num);
            continue;
        }

        /* get key data */
        ptr = ptr2 + 1;
        for (ptr2 = ptr; ptr2[0] && !isspace(ptr2[0]); ptr2++) {}
        ptr2[0] = '\0';

        /* add the key */
        *pubkeys = nc_realloc(*pubkeys, (*pubkey_count + 1) * sizeof **pubkeys);
        NC_CHECK_ERRMEM_GOTO(!(*pubkeys), ret = 1, cleanup);
        rc = asprintf(&(*pubkeys)[*pubkey_count].name, "authorized_key_%" PRIu32, *pubkey_count);
        NC_CHECK_ERRMEM_GOTO(rc == -1, (*pubkeys)[*pubkey_count].name = NULL; ret = 1, cleanup);
        (*pubkeys)[*pubkey_count].type = NC_PUBKEY_FORMAT_SSH;
        (*pubkeys)[*pubkey_count].data = strdup(ptr);
        NC_CHECK_ERRMEM_GOTO(!(*pubkeys)[*pubkey_count].data, ret = 1, cleanup);
        (*pubkey_count)++;
    }

    /* ok */
    ret = 0;
cleanup:
    if (f) {
        fclose(f);
    }
    free(line);
    return ret;
}

int
nc_server_ssh_get_system_keys(const char *username, struct nc_public_key **pubkeys, uint32_t *pubkey_count)
{
    int ret = 0;
    char *path = NULL;

    /* convert the path format to get the actual path */
    ret = nc_server_ssh_get_system_keys_path(username, &path);
    if (ret) {
        ERR(NULL, "Getting system keys path failed.");
        goto cleanup;
    }

    /* get the keys */
    ret = nc_server_ssh_read_authorized_keys_file(path, pubkeys, pubkey_count);
    if (ret) {
        ERR(NULL, "Reading system keys failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

#ifdef HAVE_SHADOW

/**
 * @brief Get the user's /etc/passwd entry.
 *
 * @param[in] username Username.
 * @param[out] pwd_buf Buffer for the passwd structure.
 * @param[out] buf Buffer for the pwd's strings.
 * @param[out] buf_size Size of the buffer.
 * @return User's passwd entry or NULL on error.
 */
static struct passwd *
nc_server_ssh_getpwnam(const char *username, struct passwd *pwd_buf, char **buf, size_t *buf_size)
{
    struct passwd *pwd = NULL;
    char *mem;
    int r = 0;

    do {
        r = getpwnam_r(username, pwd_buf, *buf, *buf_size, &pwd);
        if (pwd) {
            /* entry found */
            break;
        }

        if (r == ERANGE) {
            /* small buffer, enlarge */
            *buf_size <<= 2;
            mem = realloc(*buf, *buf_size);
            if (!mem) {
                ERRMEM;
                return NULL;
            }
            *buf = mem;
        }
    } while (r == ERANGE);

    return pwd;
}

/**
 * @brief Get the user's /etc/shadow entry.
 *
 * @param[in] username Username.
 * @param[out] spwd_buf Buffer for the spwd structure.
 * @param[out] buf Buffer for the spwd's strings.
 * @param[out] buf_size Size of the buffer.
 * @return User's shadow entry or NULL on error.
 */
static struct spwd *
nc_server_ssh_getspnam(const char *username, struct spwd *spwd_buf, char **buf, size_t *buf_size)
{
    struct spwd *spwd = NULL;
    char *mem;
    int r = 0;

    do {
# ifndef __QNXNTO__
        r = getspnam_r(username, spwd_buf, *buf, *buf_size, &spwd);
# else
        spwd = getspnam_r(username, spwd_buf, *buf, *buf_size);
        r = errno;
# endif
        if (spwd) {
            /* entry found */
            break;
        }

        if (r == ERANGE) {
            /* small buffer, enlarge */
            *buf_size <<= 2;
            mem = realloc(*buf, *buf_size);
            if (!mem) {
                ERRMEM;
                return NULL;
            }
            *buf = mem;
        }
    } while (r == ERANGE);

    return spwd;
}

char *
nc_server_ssh_get_pwd_hash(const char *username)
{
    struct passwd *pwd, pwd_buf;
    struct spwd *spwd, spwd_buf;
    char *pass_hash = NULL, *buf = NULL;
    size_t buf_size = 256;

    buf = malloc(buf_size);
    NC_CHECK_ERRMEM_GOTO(!buf, , error);

    pwd = nc_server_ssh_getpwnam(username, &pwd_buf, &buf, &buf_size);
    if (!pwd) {
        VRB(NULL, "User \"%s\" not found in the system.", username);
        goto error;
    }

    if (!strcmp(pwd->pw_passwd, "x")) {
        spwd = nc_server_ssh_getspnam(username, &spwd_buf, &buf, &buf_size);
        if (!spwd) {
            VRB(NULL, "Failed to retrieve the shadow entry for \"%s\".", username);
            goto error;
        } else if ((spwd->sp_expire > -1) && (spwd->sp_expire <= (time(NULL) / (60 * 60 * 24)))) {
            WRN(NULL, "User \"%s\" account has expired.", username);
            goto error;
        }

        pass_hash = spwd->sp_pwdp;
    } else {
        pass_hash = pwd->pw_passwd;
    }

    if (!pass_hash) {
        ERR(NULL, "No password could be retrieved for \"%s\".", username);
        goto error;
    }

    /* check the hash structure for special meaning */
    if (!strcmp(pass_hash, "*") || !strcmp(pass_hash, "!")) {
        VRB(NULL, "User \"%s\" is not allowed to authenticate using a password.", username);
        goto error;
    }
    if (!strcmp(pass_hash, "*NP*")) {
        VRB(NULL, "Retrieving password for \"%s\" from a NIS+ server not supported.", username);
        goto error;
    }

    pass_hash = strdup(pass_hash);
    free(buf);
    return pass_hash;

error:
    free(buf);
    return NULL;
}

int
nc_server_ssh_kbdint_send_passwd_prompt(struct nc_session *session, const char *username, ssh_message msg)
{
    const char *name = "Keyboard-Interactive Authentication";
    const char *instruction = "Please enter your authentication token";
    char *prompt = NULL;
    char echo[] = {0};
    int rc;

    rc = asprintf(&prompt, "%s's password:", username);
    NC_CHECK_ERRMEM_RET(rc == -1, 1);

    rc = ssh_message_auth_interactive_request(msg, name, instruction, 1, (const char **)&prompt, echo);
    free(prompt);
    if (rc) {
        ERR(session, "Failed to send an authentication request to client \"%s\".", username);
        return 1;
    }

    return 0;
}

int
nc_server_ssh_kbdint_verify_passwd(struct nc_session *session, const char *username, int n_answers)
{
    char *pw = NULL, *received_pw = NULL;
    const char *answer;
    int rc;

    if (n_answers != 1) {
        ERR(session, "Unexpected amount of answers in system auth. Expected 1, got \"%d\".", n_answers);
        return 1;
    }

    pw = nc_server_ssh_get_pwd_hash(username);
    if (!pw) {
        return 1;
    }

    answer = ssh_userauth_kbdint_getanswer(session->ti.libssh.session, 0);
    if (!answer) {
        ERR(session, "Failed to get keyboard-interactive password answer.");
        free(pw);
        return 1;
    }
    received_pw = strdup(answer);
    if (!received_pw) {
        ERRMEM;
        free(pw);
        return 1;
    }

    rc = nc_server_ssh_compare_password(pw, received_pw);
    free(pw);
    free(received_pw);

    return rc;
}

#endif

int
nc_server_ssh_compare_password(const char *stored_pw, const char *received_pw)
{
    char *received_pw_hash = NULL;
    struct crypt_data *cdata;
    int ret;

    NC_CHECK_ARG_RET(NULL, stored_pw, received_pw, 1);

    if (!stored_pw[0]) {
        if (!received_pw[0]) {
            WRN(NULL, "User authentication successful with an empty password!");
            return 0;
        } else {
            /* the user did now know he does not need any password,
             * (which should not be used) so deny authentication */
            return 1;
        }
    }

    if (!strncmp(stored_pw, "$0$", 3)) {
        /* cleartext password, simply compare the values */
        return strcmp(stored_pw + 3, received_pw);
    }

    cdata = calloc(1, sizeof *cdata);
    NC_CHECK_ERRMEM_RET(!cdata, 1);

    received_pw_hash = crypt_r(received_pw, stored_pw, cdata);
    if (!received_pw_hash) {
        ERR(NULL, "Hashing the password failed (%s).", strerror(errno));
        free(cdata);
        return 1;
    }

    ret = strcmp(received_pw_hash, stored_pw);
    free(cdata);

    return ret;
}

API int
nc_server_ssh_kbdint_get_nanswers(const struct nc_session *session, ssh_session libssh_session)
{
    int ret = 0;
    struct timespec ts_timeout = {0};
    ssh_message reply = NULL;
    uint16_t auth_timeout = *((uint16_t *)session->data);

    NC_CHECK_ARG_RET(NULL, session, libssh_session, -1);

    if (auth_timeout) {
        nc_timeouttime_get(&ts_timeout, auth_timeout * 1000);
    }

    /* wait for answers from the client */
    do {
        if (!ssh_is_connected(session->ti.libssh.session)) {
            ERR(NULL, "SSH communication socket unexpectedly closed while waiting for keyboard-interactive authentication answers.");
            ret = -1;
            goto cleanup;
        }

        reply = ssh_message_get(libssh_session);
        if (reply) {
            break;
        }

        usleep(NC_TIMEOUT_STEP);
    } while (auth_timeout && (nc_timeouttime_cur_diff(&ts_timeout) >= 1));
    if (!reply) {
        ERR(NULL, "Authentication timeout.");
        ret = -1;
        goto cleanup;
    }

    ret = ssh_userauth_kbdint_getnanswers(libssh_session);

cleanup:
    ssh_message_free(reply);
    return ret;
}

API void
nc_server_ssh_set_interactive_auth_clb(int (*interactive_auth_clb)(const struct nc_session *session, ssh_session ssh_sess, ssh_message msg, void *user_data),
        void *user_data, void (*free_user_data)(void *user_data))
{
    /* CONFIG LOCK */
    if (nc_rwlock_lock(&server_opts.config_lock, NC_RWLOCK_WRITE, NC_CONFIG_LOCK_TIMEOUT, __func__) != 1) {
        return;
    }

    server_opts.interactive_auth_clb = interactive_auth_clb;
    server_opts.interactive_auth_data = user_data;
    server_opts.interactive_auth_data_free = free_user_data;

    /* CONFIG UNLOCK */
    nc_rwlock_unlock(&server_opts.config_lock, __func__);
}

#ifdef HAVE_LIBPAM

API int
nc_server_ssh_set_pam_conf_filename(const char *filename)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, filename, 1);

    /* CONFIG LOCK */
    if (nc_rwlock_lock(&server_opts.config_lock, NC_RWLOCK_WRITE, NC_CONFIG_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    free(server_opts.pam_config_name);
    server_opts.pam_config_name = strdup(filename);
    if (!server_opts.pam_config_name) {
        ERRMEM;
        ret = 1;
    }

    /* CONFIG UNLOCK */
    nc_rwlock_unlock(&server_opts.config_lock, __func__);
    return ret;
}

#else

API int
nc_server_ssh_set_pam_conf_filename(const char *filename)
{
    /* LibPAM not supported */
    (void) filename;
    return 1;
}

#endif /* HAVE_LIBPAM */

API int
nc_server_ssh_set_authkey_path_format(const char *path)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, path, 1);

    /* CONFIG LOCK */
    if (nc_rwlock_lock(&server_opts.config_lock, NC_RWLOCK_WRITE, NC_CONFIG_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    free(server_opts.authkey_path_fmt);
    server_opts.authkey_path_fmt = strdup(path);
    if (!server_opts.authkey_path_fmt) {
        ERRMEM;
        ret = 1;
    }

    /* CONFIG UNLOCK */
    nc_rwlock_unlock(&server_opts.config_lock, __func__);
    return ret;
}

/**
 * @brief Forge the SSH protocol identification string based on the given prefix and the library versions.
 *
 * @param[in] prefix Optional prefix to include in the protocol string, can be NULL.
 * @return Protocol string on success, NULL on error.
 */
static char *
nc_server_ssh_forge_protocol_string(const char *prefix)
{
    int r;
    char *protocol_str = NULL;

    if (prefix) {
        r = asprintf(&protocol_str, "%s-libnetconf2_%s-libssh_%d.%d.%d",
                prefix, NC_VERSION,
                LIBSSH_VERSION_MAJOR, LIBSSH_VERSION_MINOR, LIBSSH_VERSION_MICRO);
    } else {
        r = asprintf(&protocol_str, "libnetconf2_%s-libssh_%d.%d.%d",
                NC_VERSION,
                LIBSSH_VERSION_MAJOR, LIBSSH_VERSION_MINOR, LIBSSH_VERSION_MICRO);
    }
    NC_CHECK_ERRMEM_RET(r == -1, NULL);

    if (strlen(protocol_str) > 245) {
        ERR(NULL, "SSH protocol identification string too long (max 245 characters).");
        free(protocol_str);
        return NULL;
    }

    return protocol_str;
}

API int
nc_server_ssh_set_protocol_string(const char *prefix)
{
    int rc = 0;
    char *protocol_str = NULL;

    NC_CHECK_ARG_RET(NULL, prefix, 1);

    protocol_str = nc_server_ssh_forge_protocol_string(prefix);
    NC_CHECK_ERRMEM_GOTO(!protocol_str, rc = 1, cleanup);

    /* CONFIG LOCK */
    if (nc_rwlock_lock(&server_opts.config_lock, NC_RWLOCK_WRITE, NC_CONFIG_LOCK_TIMEOUT, __func__) != 1) {
        rc = 1;
        goto cleanup;
    }

    /* transfer ownership */
    free(server_opts.ssh_protocol_string);
    server_opts.ssh_protocol_string = protocol_str;
    protocol_str = NULL;

    /* CONFIG UNLOCK */
    nc_rwlock_unlock(&server_opts.config_lock, __func__);

cleanup:
    free(protocol_str);
    return rc;
}

/**
 * @brief Get the public key type from binary data.
 *
 * @param[in] buffer Binary key data, which is in the form of: 4 bytes = data length, then data of data length.
 * Data is in network byte order. The key has to be in the SSH2 format.
 * @param[out] len Length of the key type.
 * @return Pointer to where the key type starts in the buffer and is of the length @p len .
 */
static const char *
nc_server_ssh_get_pubkey_type(const unsigned char *buffer, uint32_t *len)
{
    uint32_t type_len;

    /* copy the 4 bytes */
    memcpy(&type_len, buffer, sizeof type_len);
    /* type_len now stores the length of the key type */
    type_len = ntohl(type_len);
    *len = type_len;

    /* move 4 bytes in the buffer, this is where the type should be */
    buffer += sizeof type_len;
    return (const char *)buffer;
}

/**
 * @brief Create ssh key from base64 pubkey data.
 *
 * @param[in] base64 base64 encoded public key.
 * @param[out] key created ssh key.
 * @return 0 on success, 1 otherwise.
 */
static int
nc_server_ssh_create_ssh_pubkey(const char *base64, ssh_key *key)
{
    int ret = 0;
    unsigned char *bin = NULL;
    const char *pub_type = NULL;
    uint32_t pub_type_len = 0;

    NC_CHECK_ARG_RET(NULL, base64, key, 1);

    *key = NULL;

    /* convert base64 to binary */
    if (nc_base64_decode_wrap(base64, &bin) == -1) {
        ret = 1;
        goto cleanup;
    }

    /* get the key type and try to import it if possible */
    pub_type = nc_server_ssh_get_pubkey_type(bin, &pub_type_len);
    if (!pub_type) {
        ret = 1;
        goto cleanup;
    } else if (!strncmp(pub_type, "ssh-dss", pub_type_len)) {
        ERR(NULL, "DSA keys are not supported.");
        ret = 1;
        goto cleanup;
    } else if (!strncmp(pub_type, "ssh-rsa", pub_type_len)) {
        ret = ssh_pki_import_pubkey_base64(base64, SSH_KEYTYPE_RSA, key);
    } else if (!strncmp(pub_type, "ecdsa-sha2-nistp256", pub_type_len)) {
        ret = ssh_pki_import_pubkey_base64(base64, SSH_KEYTYPE_ECDSA_P256, key);
    } else if (!strncmp(pub_type, "ecdsa-sha2-nistp384", pub_type_len)) {
        ret = ssh_pki_import_pubkey_base64(base64, SSH_KEYTYPE_ECDSA_P384, key);
    } else if (!strncmp(pub_type, "ecdsa-sha2-nistp521", pub_type_len)) {
        ret = ssh_pki_import_pubkey_base64(base64, SSH_KEYTYPE_ECDSA_P521, key);
    } else if (!strncmp(pub_type, "ssh-ed25519", pub_type_len)) {
        ret = ssh_pki_import_pubkey_base64(base64, SSH_KEYTYPE_ED25519, key);
    } else {
        ERR(NULL, "Public key type not recognised.");
        ret = 1;
        goto cleanup;
    }

cleanup:
    if (ret != SSH_OK) {
        ERR(NULL, "Error importing public key.");
    }
    free(bin);
    return ret;
}

int
nc_server_ssh_auth_pubkey_compare_key(ssh_key key, struct nc_public_key *pubkeys, uint16_t pubkey_count)
{
    uint16_t i;
    int ret = 0;
    ssh_key new_key = NULL;

    /* try to compare all of the client's keys with the key received in the SSH message */
    for (i = 0; i < pubkey_count; i++) {
        /* create the SSH key from the data */
        if (nc_server_ssh_create_ssh_pubkey(pubkeys[i].data, &new_key)) {
            /* skip */
            ssh_key_free(new_key);
            continue;
        }

        /* compare the keys */
        ret = ssh_key_cmp(key, new_key, SSH_KEY_CMP_PUBLIC);
        ssh_key_free(new_key);
        if (!ret) {
            /* found a match */
            break;
        }
    }
    if (i == pubkey_count) {
        ret = 1;
    }

    return ret;
}

void
nc_server_ssh_send_banner(struct nc_session *session, struct nc_server_ssh_opts *opts)
{
    if (!opts->banner) {
        return;
    }

#if (LIBSSH_VERSION_MAJOR > 0) || (LIBSSH_VERSION_MAJOR == 0 && LIBSSH_VERSION_MINOR >= 10)
    ssh_string ban;

    ban = ssh_string_from_char(opts->banner);
    if (ban) {
        if (ssh_send_issue_banner(session->ti.libssh.session, ban)) {
            ERR(session, "Failed to send SSH banner (%s).", ssh_get_error(session->ti.libssh.session));
        }
        ssh_string_free(ban);
    }
#else
    WRN(session, "SSH banner set but cannot be sent (libssh version 0.10.0 or later required).");
#endif
}

/* ret 1 on success, 0 on timeout, -1 on error */
static int
nc_accept_ssh_session_open_netconf_channel(struct nc_session *session, struct nc_server_ssh_opts *opts)
{
    struct timespec ts_timeout;

#if LIBSSH_0_12
    int32_t time_diff;
    int ret;
#else
    ssh_message msg;
#endif

    DBG(session, "Waiting for \"netconf\" SSH subsystem request...");

    nc_timeouttime_get(&ts_timeout, NC_TRANSPORT_MSG_TIMEOUT);

#if LIBSSH_0_12
    (void) opts;

    /* Run the event loop instead of ssh_message_get() */
    while (!(session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
        if (!ssh_is_connected(session->ti.libssh.session)) {
            ERR(session, "Communication SSH socket unexpectedly closed.");
            return -1;
        }

        time_diff = nc_timeouttime_cur_diff(&ts_timeout);
        if (time_diff < 1) {
            /* timeout */
            ERR(session, "Failed to start \"netconf\" SSH subsystem for too long, disconnecting.");
            break;
        }

        /* This functions listens to the network and automatically calls callback funcitons. */
        ret = ssh_event_dopoll(session->ti.libssh.event, time_diff);
        if (ret == SSH_ERROR) {
            ERR(session, "Failed to poll SSH event (%s).", ssh_get_error(session->ti.libssh.session));
            return -1;
        } else if (ret == SSH_AGAIN) {
            /* Timeout reached */
            break;
        }
    }

    if (session->flags & NC_SESSION_SSH_SUBSYS_NETCONF) {
        VRB(session, "NETCONF subsystem successfully opened.");
        return 1;
    }
#else
    while (1) {
        if (!ssh_is_connected(session->ti.libssh.session)) {
            ERR(session, "Communication SSH socket unexpectedly closed while waiting for \"netconf\" subsystem request.");
            return -1;
        }

        msg = ssh_message_get(session->ti.libssh.session);
        if (msg) {
            if (nc_session_ssh_msg(session, opts, msg, NULL)) {
                ssh_message_reply_default(msg);
            }
            ssh_message_free(msg);
        }

        if (session->ti.libssh.channel && session->flags & NC_SESSION_SSH_SUBSYS_NETCONF) {
            return 1;
        }

        usleep(NC_TIMEOUT_STEP);
        if (nc_timeouttime_cur_diff(&ts_timeout) < 1) {
            /* timeout */
            ERR(session, "Failed to start \"netconf\" SSH subsystem for too long, disconnecting.");
            break;
        }
    }
#endif
    return 0;
}

/**
 * @brief Set hostkeys to be used for an SSH bind.
 *
 * @param[in] sbind SSH bind to use.
 * @param[in] opts SSH server options.
 * @return 0 on success, -1 on error.
 */
static int
nc_ssh_bind_add_hostkeys(ssh_bind sbind, struct nc_server_ssh_opts *opts)
{
    int rc;
    char *privkey_path;
    struct nc_hostkey *hostkey = NULL;
    struct nc_asymmetric_key *key = NULL;

    LY_ARRAY_FOR(opts->hostkeys, struct nc_hostkey, hostkey) {
        privkey_path = NULL;

        /* get the asymmetric key */
        if (hostkey->store == NC_STORE_LOCAL) {
            /* stored locally */
            key = &hostkey->key;
        } else {
            /* keystore reference, need to get it */
            NC_CHECK_RET(nc_server_ssh_ks_ref_get_key(hostkey->ks_ref, &key), -1);
        }

        privkey_path = nc_server_ssh_privkey_data_to_tmp_file(key->privkey.data, nc_privkey_format_to_str(key->privkey.type));
        NC_CHECK_ERR_RET(!privkey_path, ERR(NULL, "Temporarily storing a host key into a file failed."), -1);

        rc = ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HOSTKEY, privkey_path);
        if (unlink(privkey_path)) {
            WRN(NULL, "Removing a temporary host key file \"%s\" failed (%s).", privkey_path, strerror(errno));
        }
        free(privkey_path);
        NC_CHECK_ERR_RET(rc != SSH_OK, ERR(NULL, "Failed to set hostkey \"%s\".", hostkey->name), -1);
    }

    return 0;
}

static int
nc_accept_ssh_session_auth(struct nc_session *session, struct nc_server_ssh_opts *opts)
{
    struct timespec ts_timeout = {0};

#if LIBSSH_0_12
    ssh_event event;
    int32_t time_diff;
    int ret;
#else
    ssh_message msg;
    struct nc_auth_state auth_state = {0};
#endif

    DBG(session, "SSH authentication...");

    /* authenticate */
    if (opts->auth_timeout) {
        nc_timeouttime_get(&ts_timeout, opts->auth_timeout * 1000);
    }
#if LIBSSH_0_12
    /* Create an event loop */
    event = ssh_event_new();
    if (!event) {
        ERR(session, "Failed to create SSH event.");
        return -1;
    }

    if (ssh_event_add_session(event, session->ti.libssh.session) == SSH_ERROR) {
        ERR(session, "Failed to add SSH session to event.");
        ssh_event_free(event);
        return -1;
    }
    session->ti.libssh.event = event;

    /* Run the event loop instead of ssh_message_get() */
    while (!(session->flags & NC_SESSION_SSH_AUTHENTICATED)) {
        if (!ssh_is_connected(session->ti.libssh.session)) {
            ERR(session, "Communication SSH socket unexpectedly closed.");
            return -1;
        }

        if (opts->auth_timeout) {
            time_diff = nc_timeouttime_cur_diff(&ts_timeout);
            if (time_diff < 1) {
                /* timeout */
                break;
            }
        } else {
            /* no authentication timeout, wait indefinitely */
            time_diff = -1;
        }

        /* This functions listens to the network and automatically calls callback funcitons. */
        ret = ssh_event_dopoll(event, time_diff);
        if (ret == SSH_ERROR) {
            ERR(session, "Failed to poll SSH event (%s).", ssh_get_error(session->ti.libssh.session));
            return -1;
        } else if (ret == SSH_AGAIN) {
            /* Timeout reached */
            break;
        }
    }
#else
    while (1) {
        if (!ssh_is_connected(session->ti.libssh.session)) {
            ERR(session, "Communication SSH socket unexpectedly closed while waiting for authentication.");
            return -1;
        }

        msg = ssh_message_get(session->ti.libssh.session);
        if (msg) {
            if (nc_session_ssh_msg(session, opts, msg, &auth_state)) {
                ssh_message_reply_default(msg);
            }
            ssh_message_free(msg);
        }

        if (session->flags & NC_SESSION_SSH_AUTHENTICATED) {
            break;
        }

        usleep(NC_TIMEOUT_STEP);
        if (opts->auth_timeout && (nc_timeouttime_cur_diff(&ts_timeout) < 1)) {
            /* timeout */
            break;
        }
    }
#endif

    if (!(session->flags & NC_SESSION_SSH_AUTHENTICATED)) {
        /* timeout */
        if (session->username) {
            ERR(session, "User \"%s\" failed to authenticate for too long, disconnecting.", session->username);
        } else {
            ERR(session, "User failed to authenticate for too long, disconnecting.");
        }
        return 0;
    }

    return 1;
}

int
nc_accept_ssh_session(struct nc_session *session, struct nc_server_ssh_opts *opts, int sock)
{
    ssh_bind sbind = NULL;
    int rc = 1, r;
    struct timespec ts_timeout;
    const char *err_msg;
    char *proto_str = NULL, *proto_str_dyn = NULL;

#if LIBSSH_0_12
    struct nc_server_ssh_cb_data *cb_data = NULL;
#endif

    /* other transport-specific data */
    session->ti_type = NC_TI_SSH;
    session->ti.libssh.session = ssh_new();
    if (!session->ti.libssh.session) {
        ERR(NULL, "Failed to initialize a new SSH session.");
        rc = -1;
        goto cleanup;
    }

#if LIBSSH_0_12
    cb_data = calloc(1, sizeof *cb_data);
    NC_CHECK_ERRMEM_GOTO(!cb_data, rc = -1, cleanup);
    cb_data->session = session;
    cb_data->opts = opts;

    cb_data->server_cb.userdata = cb_data;
    cb_data->server_cb.auth_password_function = nc_server_ssh_cb_auth_password;
    cb_data->server_cb.auth_pubkey_function = nc_server_ssh_cb_auth_pubkey;
    cb_data->server_cb.auth_none_function = nc_server_ssh_cb_auth_none;
    cb_data->server_cb.auth_kbdint_function = nc_server_ssh_cb_auth_kbdint;
    cb_data->server_cb.channel_open_request_session_function = nc_server_ssh_cb_channel_open_request_session;

    ssh_callbacks_init(&cb_data->server_cb);
    ssh_set_server_callbacks(session->ti.libssh.session, &cb_data->server_cb);
    session->ti.libssh.cb_data = cb_data;
#endif /* LIBSSH_0_12 */

    sbind = ssh_bind_new();
    if (!sbind) {
        ERR(session, "Failed to create an SSH bind.");
        rc = -1;
        goto cleanup;
    }

    /* configure host keys */
    if (nc_ssh_bind_add_hostkeys(sbind, opts)) {
        rc = -1;
        goto cleanup;
    }

    /* configure supported algorithms */
    if (opts->hostkey_algs && ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS, opts->hostkey_algs)) {
        ERR(session, "Failed to set hostkey algorithms (%s).", ssh_get_error(sbind));
        rc = -1;
        goto cleanup;
    }
    if (opts->encryption_algs) {
        /* both client->server and server->client directions set for the same reason as for MAC algorithms below */
        if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_CIPHERS_S_C, opts->encryption_algs) ||
                ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_CIPHERS_C_S, opts->encryption_algs)) {
            ERR(session, "Failed to set encryption algorithms (%s).", ssh_get_error(sbind));
            rc = -1;
            goto cleanup;
        }
    }
    if (opts->kex_algs && ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_KEY_EXCHANGE, opts->kex_algs)) {
        ERR(session, "Failed to set key exchange algorithms (%s).", ssh_get_error(sbind));
        rc = -1;
        goto cleanup;
    }
    if (opts->mac_algs) {
        /* * SSH negotiates MAC algorithms independently for each direction (Client->Server
         * and Server->Client). We must explicitly apply the configured algorithms to
         * both directions to ensure consistent security and avoid falling back to
         * libssh defaults for the unspecified direction.
         * Ref: https://github.com/CESNET/libnetconf2/issues/523
         */
        if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HMAC_S_C, opts->mac_algs) ||
                ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HMAC_C_S, opts->mac_algs)) {
            ERR(session, "Failed to set MAC algorithms (%s).", ssh_get_error(sbind));
            rc = -1;
            goto cleanup;
        }
    }

    /* configure the ssh protocol identification string */
    if (server_opts.ssh_protocol_string) {
        proto_str = server_opts.ssh_protocol_string;
    } else {
        proto_str_dyn = nc_server_ssh_forge_protocol_string(NULL);
        NC_CHECK_ERRMEM_GOTO(!proto_str_dyn, rc = -1, cleanup);
        proto_str = proto_str_dyn;
    }
    if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_BANNER, proto_str)) {
        rc = -1;
        goto cleanup;
    }

    /* accept new connection on the bind */
    if (ssh_bind_accept_fd(sbind, session->ti.libssh.session, sock) == SSH_ERROR) {
        ERR(session, "SSH failed to accept a new connection (%s).", ssh_get_error(sbind));
        rc = -1;

        /* Avoid closing the socket on failure to prevent a possible double close.
         * On failure, sock may or not be set to the session. In theory, we should
         * be able to compare sock with ssh_get_fd() and close it only if it was
         * not set, for example:
         *
         *     if (ssh_get_fd(session) == sock)
         *         sock = -1;
         *
         * However, if ssh_bind_accept_fd() fails to allocate the socket structure
         * internally, calling ssh_get_fd() will dereference a NULL pointer due to
         * a buggy behavior in libssh.
         */
        sock = -1;
        goto cleanup;
    }

    /* use SSH_OPTIONS_FD so libssh won't close the socket in ssh_disconnect() */
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_FD, &sock);
    sock = -1;

    /* set to non-blocking */
    ssh_set_blocking(session->ti.libssh.session, 0);

    DBG(session, "Performing SSH key exchange...");
    nc_timeouttime_get(&ts_timeout, NC_TRANSPORT_HANDSHAKE_TIMEOUT);
    while ((r = ssh_handle_key_exchange(session->ti.libssh.session)) == SSH_AGAIN) {
        /* this tends to take longer */
        usleep(NC_TIMEOUT_STEP * 20);
        if (nc_timeouttime_cur_diff(&ts_timeout) < 1) {
            break;
        }
    }
    if (r == SSH_AGAIN) {
        ERR(session, "SSH key exchange timeout.");
        rc = 0;
        goto cleanup;
    } else if (r != SSH_OK) {
        err_msg = ssh_get_error(session->ti.libssh.session);
        if (err_msg[0] == '\0') {
            err_msg = "hostkey algorithm generated from the hostkey most likely not found in the set of configured hostkey algorithms";
        }
        ERR(session, "SSH key exchange error (%s).", err_msg);
        rc = -1;
        goto cleanup;
    }

    /* authenticate, store auth_timeout in session so we can retrieve it in kb interactive API */
    session->data = &opts->auth_timeout;
    rc = nc_accept_ssh_session_auth(session, opts);
    session->data = NULL;

#if LIBSSH_0_12 && defined (HAVE_LIBPAM)
    /* if a PAM thread is still running (auth may have succeeded via another method), cancel and clean it up */
    if (cb_data) {
        nc_server_ssh_cb_pam_cancel(cb_data->pam_kbdint);
        cb_data->pam_kbdint = NULL;
    }
#endif

    if (rc != 1) {
        goto cleanup;
    }

    /* open channel and request 'netconf' subsystem */
    if ((rc = nc_accept_ssh_session_open_netconf_channel(session, opts)) != 1) {
        goto cleanup;
    }

cleanup:
    if (sock > -1) {
        close(sock);
    }
    free(proto_str_dyn);
    ssh_bind_free(sbind);
    return rc;
}

API NC_MSG_TYPE
nc_session_accept_ssh_channel(struct nc_session *orig_session, struct nc_session **session)
{
    NC_MSG_TYPE msgtype;
    struct nc_session *new_session = NULL;
    struct timespec ts_cur;

    NC_CHECK_ARG_RET(orig_session, orig_session, session, NC_MSG_ERROR);

    if ((orig_session->status == NC_STATUS_RUNNING) && (orig_session->ti_type == NC_TI_SSH) &&
            orig_session->ti.libssh.next) {
        for (new_session = orig_session->ti.libssh.next;
                new_session != orig_session;
                new_session = new_session->ti.libssh.next) {
            if ((new_session->status == NC_STATUS_STARTING) && new_session->ti.libssh.channel &&
                    (new_session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
                /* we found our session */
                break;
            }
        }
        if (new_session == orig_session) {
            new_session = NULL;
        }
    }

    if (!new_session) {
        ERR(orig_session, "Session does not have a NETCONF SSH channel ready.");
        return NC_MSG_ERROR;
    }

    /* assign new SID atomically */
    new_session->id = ATOMIC_INC_RELAXED(server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(new_session);
    if (msgtype != NC_MSG_HELLO) {
        return msgtype;
    }

    nc_realtime_get(&ts_cur);
    new_session->opts.server.session_start = ts_cur;
    nc_timeouttime_get(&ts_cur, 0);
    new_session->opts.server.last_rpc = ts_cur.tv_sec;
    new_session->status = NC_STATUS_RUNNING;
    *session = new_session;

    return msgtype;
}

API NC_MSG_TYPE
nc_ps_accept_ssh_channel(struct nc_pollsession *ps, struct nc_session **session)
{
    uint8_t q_id;
    NC_MSG_TYPE msgtype;
    struct nc_session *new_session = NULL, *cur_session;
    struct timespec ts_cur;
    uint16_t i;

    NC_CHECK_ARG_RET(NULL, ps, session, NC_MSG_ERROR);

    /* LOCK */
    if (nc_ps_lock(ps, &q_id, __func__)) {
        return NC_MSG_ERROR;
    }

    for (i = 0; i < ps->session_count; ++i) {
        cur_session = ps->sessions[i]->session;
        if ((cur_session->status == NC_STATUS_RUNNING) && (cur_session->ti_type == NC_TI_SSH) &&
                cur_session->ti.libssh.next) {
            /* an SSH session with more channels */
            for (new_session = cur_session->ti.libssh.next;
                    new_session != cur_session;
                    new_session = new_session->ti.libssh.next) {
                if ((new_session->status == NC_STATUS_STARTING) && new_session->ti.libssh.channel &&
                        (new_session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
                    /* we found our session */
                    break;
                }
            }
            if (new_session != cur_session) {
                break;
            }

            new_session = NULL;
        }
    }

    /* UNLOCK */
    nc_ps_unlock(ps, q_id, __func__);

    if (!new_session) {
        ERR(NULL, "No session with a NETCONF SSH channel ready was found.");
        return NC_MSG_ERROR;
    }

    /* assign new SID atomically */
    new_session->id = ATOMIC_INC_RELAXED(server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(new_session);
    if (msgtype != NC_MSG_HELLO) {
        return msgtype;
    }

    nc_realtime_get(&ts_cur);
    new_session->opts.server.session_start = ts_cur;
    nc_timeouttime_get(&ts_cur, 0);
    new_session->opts.server.last_rpc = ts_cur.tv_sec;
    new_session->status = NC_STATUS_RUNNING;
    *session = new_session;

    return msgtype;
}
