/**
 * @file session_server_ssh.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 SSH server session manipulation functions
 *
 * @copyright
 * Copyright (c) 2017 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "config.h" /* Expose HAVE_SHADOW and HAVE_CRYPT */

#ifdef HAVE_SHADOW
    #include <shadow.h>
#endif
#ifdef HAVE_CRYPT
    #include <crypt.h>
#endif
#ifdef HAVE_LIBPAM
    #include <security/pam_appl.h>
#endif

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "compat.h"
#include "libnetconf.h"
#include "session_server.h"
#include "session_server_ch.h"

#if !defined (HAVE_CRYPT_R)
pthread_mutex_t crypt_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

extern struct nc_server_opts server_opts;

static char *
base64der_key_to_tmp_file(const char *in, const char *key_str, int is_public)
{
    char path[12] = "/tmp/XXXXXX";
    int fd, written, pub_written = 0;
    unsigned len;
    mode_t umode;
    FILE *file;
    int c, i;

    if (in == NULL) {
        return NULL;
    }

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

    /* write the key into the file */
    if (key_str) {
        written = fwrite("-----BEGIN ", 1, 11, file);
        written += fwrite(key_str, 1, strlen(key_str), file);
        if (is_public) {
            written += fwrite(" PUBLIC KEY-----\n", 1, 17, file);
        } else {
            written += fwrite(" PRIVATE KEY-----\n", 1, 18, file);
        }
        written += fwrite(in, 1, strlen(in), file);
        written += fwrite("\n-----END ", 1, 10, file);
        written += fwrite(key_str, 1, strlen(key_str), file);
        if (is_public) {
            written += fwrite(" PUBLIC KEY-----", 1, 16, file);
        } else {
            written += fwrite(" PRIVATE KEY-----", 1, 17, file);
        }

        fclose(file);

        len = 11 + strlen(key_str) + 18 + strlen(in) + 10 + strlen(key_str) + 17;
        if (is_public) {
            len -= 2;
        }

        if ((unsigned)written != len) {
            unlink(path);
            return NULL;
        }
    } else {
        if (is_public) {
            written = fwrite("-----BEGIN PUBLIC KEY-----\n", 1, 27, file);
        } else {
            written = fwrite("-----BEGIN PRIVATE KEY-----\n", 1, 28, file);
        }

        if (is_public) {
            i = 0;
            c = in[i];
            while (c) {
                fputc(c, file);
                pub_written++;
                if (pub_written % 64 == 0) {
                    fputc('\n', file);
                }
                c = in[++i];
            }
            written += pub_written;
        } else {
            written += fwrite(in, 1, strlen(in), file);
        }
        if (is_public) {
            written += fwrite("\n-----END PUBLIC KEY-----\n", 1, 26, file);
        } else {
            written += fwrite("\n-----END PRIVATE KEY-----", 1, 26, file);
        }

        fclose(file);

        len = 28 + strlen(in) + 26;
        if (is_public) {
            len -= 1;
        }

        if ((unsigned)written != len) {
            unlink(path);
            return NULL;
        }
    }

    return strdup(path);
}

API void
nc_server_ssh_set_passwd_auth_clb(int (*passwd_auth_clb)(const struct nc_session *session, const char *password, void *user_data),
        void *user_data, void (*free_user_data)(void *user_data))
{
    server_opts.passwd_auth_clb = passwd_auth_clb;
    server_opts.passwd_auth_data = user_data;
    server_opts.passwd_auth_data_free = free_user_data;
}

API void
nc_server_ssh_set_interactive_auth_clb(int (*interactive_auth_clb)(const struct nc_session *session, ssh_message msg, void *user_data),
        void *user_data, void (*free_user_data)(void *user_data))
{
    server_opts.interactive_auth_clb = interactive_auth_clb;
    server_opts.interactive_auth_data = user_data;
    server_opts.interactive_auth_data_free = free_user_data;
}

API void
nc_server_ssh_set_pubkey_auth_clb(int (*pubkey_auth_clb)(const struct nc_session *session, ssh_key key, void *user_data),
        void *user_data, void (*free_user_data)(void *user_data))
{
    server_opts.pubkey_auth_clb = pubkey_auth_clb;
    server_opts.pubkey_auth_data = user_data;
    server_opts.pubkey_auth_data_free = free_user_data;
}

static int
nc_server_ssh_set_auth_attempts(uint16_t auth_attempts, struct nc_server_ssh_opts *opts)
{
    if (!auth_attempts) {
        ERRARG("auth_attempts");
        return -1;
    }

    opts->auth_attempts = auth_attempts;
    return 0;
}

API int
nc_server_ssh_ch_client_endpt_set_auth_attempts(const char *client_name, const char *endpt_name, uint16_t auth_attempts)
{
    int ret;
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, NC_TI_LIBSSH, &client);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_set_auth_attempts(auth_attempts, endpt->opts.ssh);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static int
nc_server_ssh_set_auth_timeout(uint16_t auth_timeout, struct nc_server_ssh_opts *opts)
{
    if (!auth_timeout) {
        ERRARG("auth_timeout");
        return -1;
    }

    opts->auth_timeout = auth_timeout;
    return 0;
}

API int
nc_server_ssh_ch_client_endpt_set_auth_timeout(const char *client_name, const char *endpt_name, uint16_t auth_timeout)
{
    int ret;
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, NC_TI_LIBSSH, &client);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_set_auth_timeout(auth_timeout, endpt->opts.ssh);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

/**
 * @brief Compare hashed password with a cleartext password for a match.
 *
 * @param[in] pass_hash Hashed password.
 * @param[in] pass_clear Cleartext password.
 * @return 0 on match.
 * @return non-zero if not a match.
 */
static int
auth_password_compare_pwd(const char *pass_hash, const char *pass_clear)
{
    char *new_pass_hash;

#ifdef HAVE_CRYPT_R
    struct crypt_data cdata;
#endif

    if (!pass_hash[0]) {
        if (!pass_clear[0]) {
            WRN(NULL, "User authentication successful with an empty password!");
            return 0;
        } else {
            /* the user did now know he does not need any password,
             * (which should not be used) so deny authentication */
            return 1;
        }
    }

#ifdef HAVE_CRYPT_R
    cdata.initialized = 0;
    new_pass_hash = crypt_r(pass_clear, pass_hash, &cdata);
#else
    pthread_mutex_lock(&crypt_lock);
    new_pass_hash = crypt(pass_clear, pass_hash);
    pthread_mutex_unlock(&crypt_lock);
#endif

    if (!new_pass_hash) {
        return 1;
    }

    return strcmp(new_pass_hash, pass_hash);
}

static void
nc_sshcb_auth_password(struct nc_session *session, struct nc_client_auth *auth_client, ssh_message msg)
{
    int auth_ret = 1;

    if (server_opts.passwd_auth_clb) {
        auth_ret = server_opts.passwd_auth_clb(session, ssh_message_auth_password(msg), server_opts.passwd_auth_data);
    } else {
        auth_ret = auth_password_compare_pwd(auth_client->password, ssh_message_auth_password(msg));
    }

    if (!auth_ret) {
        session->flags |= NC_SESSION_SSH_AUTHENTICATED;
        VRB(session, "User \"%s\" authenticated.", session->username);
        ssh_message_auth_reply_success(msg, 0);
    } else {
        ++session->opts.server.ssh_auth_attempts;
        VRB(session, "Failed user \"%s\" authentication attempt (#%d).", session->username,
                session->opts.server.ssh_auth_attempts);
        ssh_message_reply_default(msg);
    }
}

#ifdef HAVE_LIBPAM

/**
 * @brief PAM conversation function, which serves as a callback for exchanging messages between the client and a PAM module.
 *
 * @param[in] n_messages Number of messages.
 * @param[in] msg PAM module's messages.
 * @param[out] resp User responses.
 * @param[in] appdata_ptr Callback's data.
 * @return PAM_SUCCESS on success;
 * @return PAM_BUF_ERR on memory allocation error;
 * @return PAM_CONV_ERR otherwise.
 */
static int
nc_pam_conv_clb(int n_messages, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    int i, j, t, r = PAM_SUCCESS, n_answers, n_requests = n_messages;
    const char **prompts = NULL;
    char *echo = NULL;
    const char *name = "Keyboard-Interactive Authentication";
    const char *instruction = "Please enter your authentication token";
    ssh_message reply = NULL;
    struct nc_pam_thread_arg *clb_data = appdata_ptr;
    ssh_session libssh_session;
    struct timespec ts_timeout;
    struct nc_server_ssh_opts *opts;

    libssh_session = clb_data->session->ti.libssh.session;
    opts = clb_data->opts;

    /* PAM_MAX_NUM_MSG == 32 by default */
    if ((n_messages <= 0) || (n_messages >= PAM_MAX_NUM_MSG)) {
        ERR(NULL, "Bad number of PAM messages (#%d).", n_messages);
        r = PAM_CONV_ERR;
        goto cleanup;
    }

    /* only accepting these 4 types of messages */
    for (i = 0; i < n_messages; i++) {
        t = msg[i]->msg_style;
        if ((t != PAM_PROMPT_ECHO_OFF) && (t != PAM_PROMPT_ECHO_ON) && (t != PAM_TEXT_INFO) && (t != PAM_ERROR_MSG)) {
            ERR(NULL, "PAM conversation callback received an unexpected type of message.");
            r = PAM_CONV_ERR;
            goto cleanup;
        }
    }

    /* display messages with errors and/or some information and count the amount of actual authentication challenges */
    for (i = 0; i < n_messages; i++) {
        if (msg[i]->msg_style == PAM_TEXT_INFO) {
            VRB(NULL, "PAM conversation callback received a message with some information for the client (%s).", msg[i]->msg);
            n_requests--;
        }
        if (msg[i]->msg_style == PAM_ERROR_MSG) {
            ERR(NULL, "PAM conversation callback received an error message (%s).", msg[i]->msg);
            r = PAM_CONV_ERR;
            goto cleanup;
        }
    }

    /* there are no requests left for the user, only messages with some information for the client were sent */
    if (n_requests <= 0) {
        r = PAM_SUCCESS;
        goto cleanup;
    }

    /* it is the PAM module's responsibility to release both, this array and the responses themselves */
    *resp = calloc(n_requests, sizeof **resp);
    prompts = calloc(n_requests, sizeof *prompts);
    echo = calloc(n_requests, sizeof *echo);
    if (!(*resp) || !prompts || !echo) {
        ERRMEM;
        r = PAM_BUF_ERR;
        goto cleanup;
    }

    /* set the prompts for the user */
    j = 0;
    for (i = 0; i < n_messages; i++) {
        if ((msg[i]->msg_style == PAM_PROMPT_ECHO_ON) || (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF)) {
            prompts[j++] = msg[i]->msg;
        }
    }

    /* iterate over all the messages and adjust the echo array accordingly */
    j = 0;
    for (i = 0; i < n_messages; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            echo[j++] = 1;
        }
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            /* no need to set to 0 because of calloc */
            j++;
        }
    }

    /* print all the keyboard-interactive challenges to the user */
    r = ssh_message_auth_interactive_request(clb_data->msg, name, instruction, n_requests, prompts, echo);
    if (r != SSH_OK) {
        ERR(NULL, "Failed to send an authentication request.");
        r = PAM_CONV_ERR;
        goto cleanup;
    }

    if (opts->auth_timeout) {
        nc_gettimespec_mono_add(&ts_timeout, opts->auth_timeout * 1000);
    }

    /* get user's replies */
    do {
        if (!nc_session_is_connected(clb_data->session)) {
            ERR(NULL, "Communication SSH socket unexpectedly closed.");
            r = PAM_CONV_ERR;
            goto cleanup;
        }

        reply = ssh_message_get(libssh_session);
        if (reply) {
            break;
        }

        usleep(NC_TIMEOUT_STEP);
    } while ((opts->auth_timeout) && (nc_difftimespec_mono_cur(&ts_timeout) >= 1));

    if (!reply) {
        ERR(NULL, "Authentication timeout.");
        r = PAM_CONV_ERR;
        goto cleanup;
    }

    /* check if the amount of replies matches the amount of requests */
    n_answers = ssh_userauth_kbdint_getnanswers(libssh_session);
    if (n_answers != n_requests) {
        ERR(NULL, "Expected %d response(s), got %d.", n_requests, n_answers);
        r = PAM_CONV_ERR;
        goto cleanup;
    }

    /* give the replies to a PAM module */
    for (i = 0; i < n_answers; i++) {
        (*resp)[i].resp = strdup(ssh_userauth_kbdint_getanswer(libssh_session, i));
        /* it should be the caller's responsibility to free this, however if mem alloc fails,
         * it is safer to free the responses here and set them to NULL */
        if ((*resp)[i].resp == NULL) {
            for (j = 0; j < i; j++) {
                free((*resp)[j].resp);
                (*resp)[j].resp = NULL;
            }
            ERRMEM;
            r = PAM_BUF_ERR;
            goto cleanup;
        }
    }

cleanup:
    ssh_message_free(reply);
    free(prompts);
    free(echo);
    return r;
}

/**
 * @brief Handles authentication via Linux PAM.
 *
 * @param[in] session NETCONF session.
 * @param[in] ssh_msg SSH message with a keyboard-interactive authentication request.
 * @return PAM_SUCCESS on success;
 * @return PAM error otherwise.
 */
static int
nc_pam_auth(struct nc_session *session, struct nc_server_ssh_opts *opts, ssh_message ssh_msg)
{
    pam_handle_t *pam_h = NULL;
    int ret;
    struct nc_pam_thread_arg clb_data;
    struct pam_conv conv;
    uint16_t i;

    /* structure holding callback's data */
    clb_data.msg = ssh_msg;
    clb_data.session = session;
    clb_data.opts = opts;

    /* PAM conversation structure holding the callback and it's data */
    conv.conv = nc_pam_conv_clb;
    conv.appdata_ptr = &clb_data;

    /* get the current client's configuration file */
    for (i = 0; i < opts->client_count; i++) {
        if (!strcmp(opts->auth_clients[i].username, session->username)) {
            break;
        }
    }

    if (i == opts->client_count) {
        ERR(NULL, "User \"%s\" not found.", session->username);
        ret = 1;
        goto cleanup;
    }

    if (!opts->auth_clients[i].pam_config_name) {
        ERR(NULL, "User's \"%s\" PAM configuration filename not set.");
        ret = 1;
        goto cleanup;
    }

    /* initialize PAM and see if the given configuration file exists */
# ifdef LIBPAM_HAVE_CONFDIR
    /* PAM version >= 1.4 */
    ret = pam_start_confdir(opts->auth_clients[i].pam_config_name, session->username, &conv, opts->auth_clients[i].pam_config_dir, &pam_h);
# else
    /* PAM version < 1.4 */
    ret = pam_start(opts->auth_clients[i].pam_config_name, session->username, &conv, &pam_h);
# endif
    if (ret != PAM_SUCCESS) {
        ERR(NULL, "PAM error occurred (%s).\n", pam_strerror(pam_h, ret));
        goto cleanup;
    }

    /* authentication based on the modules listed in the configuration file */
    ret = pam_authenticate(pam_h, 0);
    if (ret != PAM_SUCCESS) {
        if (ret == PAM_ABORT) {
            ERR(NULL, "PAM error occurred (%s).\n", pam_strerror(pam_h, ret));
            goto cleanup;
        } else {
            VRB(NULL, "PAM error occurred (%s).\n", pam_strerror(pam_h, ret));
            goto cleanup;
        }
    }

    /* correct token entered, check other requirements(the time of the day, expired token, ...) */
    ret = pam_acct_mgmt(pam_h, 0);
    if ((ret != PAM_SUCCESS) && (ret != PAM_NEW_AUTHTOK_REQD)) {
        VRB(NULL, "PAM error occurred (%s).\n", pam_strerror(pam_h, ret));
        goto cleanup;
    }

    /* if a token has expired a new one will be generated */
    if (ret == PAM_NEW_AUTHTOK_REQD) {
        VRB(NULL, "PAM warning occurred (%s).\n", pam_strerror(pam_h, ret));
        ret = pam_chauthtok(pam_h, PAM_CHANGE_EXPIRED_AUTHTOK);
        if (ret == PAM_SUCCESS) {
            VRB(NULL, "The authentication token of user \"%s\" updated successfully.", session->username);
        } else {
            ERR(NULL, "PAM error occurred (%s).\n", pam_strerror(pam_h, ret));
            goto cleanup;
        }
    }

cleanup:
    /* destroy the PAM context */
    if (pam_end(pam_h, ret) != PAM_SUCCESS) {
        ERR(NULL, "PAM error occurred (%s).\n", pam_strerror(pam_h, ret));
    }
    return ret;
}

#endif

static void
nc_sshcb_auth_kbdint(struct nc_session *session, struct nc_server_ssh_opts *opts, ssh_message msg)
{
    int auth_ret = 1;

    if (server_opts.interactive_auth_clb) {
        auth_ret = server_opts.interactive_auth_clb(session, msg, server_opts.interactive_auth_data);
    } else {
#ifdef HAVE_LIBPAM
        if (nc_pam_auth(session, opts, msg) == PAM_SUCCESS) {
            auth_ret = 0;
        }
#else
        ERR(session, "PAM-based SSH authentication is not supported.");
#endif
    }

    /* We have already sent a reply */
    if (auth_ret == -1) {
        return;
    }

    /* Authenticate message based on outcome */
    if (!auth_ret) {
        session->flags |= NC_SESSION_SSH_AUTHENTICATED;
        VRB(session, "User \"%s\" authenticated.", session->username);
        ssh_message_auth_reply_success(msg, 0);
    } else {
        ++session->opts.server.ssh_auth_attempts;
        VRB(session, "Failed user \"%s\" authentication attempt (#%d).", session->username,
                session->opts.server.ssh_auth_attempts);
        ssh_message_reply_default(msg);
    }
}

static int
nc_server_ssh_decode_base64(const char *base64, char **buffer)
{
    BIO *bio, *bio64;
    size_t used = 0, size = 0, r = 0;
    void *tmp = NULL;
    int nl_count, i, remainder;
    char *b64;

    /* insert new lines into the base64 string, so BIO_read works correctly */
    nl_count = strlen(base64) / 64;
    remainder = strlen(base64) - 64 * nl_count;
    b64 = calloc(strlen(base64) + nl_count + 1, 1);
    if (!b64) {
        ERRMEM;
        return 1;
    }

    for (i = 0; i < nl_count; i++) {
        /* copy 64 bytes and add a NL */
        strncpy(b64 + i * 65, base64 + i * 64, 64);
        b64[i * 65 + 64] = '\n';
    }

    /* copy the rest */
    strncpy(b64 + i * 65, base64 + i * 64, remainder);

    bio64 = BIO_new(BIO_f_base64());
    if (!bio64) {
        ERR(NULL, "Error creating a bio (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    bio = BIO_new_mem_buf(b64, strlen(b64));
    if (!bio) {
        ERR(NULL, "Error creating a bio (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    BIO_push(bio64, bio);

    /* store the decoded base64 in buffer */
    *buffer = NULL;
    do {
        size += 64;

        tmp = realloc(*buffer, size);
        if (!tmp) {
            free(buffer);
            return 1;
        }
        *buffer = tmp;

        r = BIO_read(bio64, *buffer + used, 64);
        used += r;
    } while (r == 64);

    free(b64);
    BIO_free_all(bio64);
    return 0;
}

/*
 *  Get the public key type from binary data stored in buffer.
 *  The data is in the form of: 4 bytes = data length, then data of data legnth
 *  and the data is in network byte order
 */
static char *
nc_server_ssh_get_pubkey_type(char *buffer, NC_SSH_KEY_TYPE *type)
{
    uint32_t type_len;

    memcpy(&type_len, buffer, sizeof type_len);
    type_len = ntohl(type_len);
    buffer += sizeof type_len;

    if (!strncmp(buffer, "ssh-dss", type_len)) {
        *type = NC_SSH_KEY_DSA;
    } else if (!strncmp(buffer, "ssh-rsa", type_len)) {
        *type = NC_SSH_KEY_RSA;
    } else if (!strncmp(buffer, "ecdsa-sha2-nistp256", type_len)) {
        *type = NC_SSH_KEY_ECDSA;
        /*todo*/
    } else {
        return NULL;
    }

    return buffer + type_len;
}

/**
 * @brief Get the RSA public key parameters from the binary data.
 *
 * @param[in] buffer Binary data.
 * @param[out] e Public key exponent.
 * @param[out] n Modulus common to both public and private key.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_ssh_get_rsa_data(const unsigned char *buffer, BIGNUM **e, BIGNUM **n)
{
    uint32_t data_len;

    data_len = ntohl(*(uint32_t *)buffer);
    buffer += sizeof data_len;

    *e = BN_bin2bn(buffer, data_len, NULL);
    if (!*e) {
        ERR(NULL, "Error converting binary to bignum (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    buffer += data_len;
    data_len = ntohl(*(uint32_t *)buffer);
    buffer += sizeof data_len;

    *n = BN_bin2bn(buffer, data_len, NULL);
    if (!*n) {
        ERR(NULL, "Error converting binary to bignum (%s).", ERR_reason_error_string(ERR_get_error()));
        return 1;
    }

    return 0;
}

/**
 * @brief Create the EVP_PKEY structure storing the public key, which can later be compared.
 *
 * @param[in] buffer Binary data from which the EVP_PKEY structure is built.
 * @param[out] rsa The EVP_PKEY structure holding the public key.
 * @return 0 on success, 1 otherwise.
 */
static int
nc_server_ssh_build_rsa_key(char *buffer, EVP_PKEY **rsa)
{
    RSA *key = NULL;
    BIGNUM *e = NULL, *n = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    key = RSA_new();
    pkey = EVP_PKEY_new();
    if (!key || !pkey) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    if (nc_server_ssh_get_rsa_data((const unsigned char *)buffer, &e, &n)) {
        ret = 1;
        goto cleanup;
    }

    if (!RSA_set0_key(key, n, e, NULL)) {
        ERR(NULL, "Error setting RSA key (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }
    e = n = NULL;

    if (!EVP_PKEY_set1_RSA(pkey, key)) {
        ERR(NULL, "Error setting EVP_PKEY (%s).", ERR_reason_error_string(ERR_get_error()));
        ret = 1;
        goto cleanup;
    }

    *rsa = pkey;
    pkey = NULL;

cleanup:
    BN_free(e);
    BN_free(n);
    RSA_free(key);
    EVP_PKEY_free(pkey);
    return ret;
}

/**
 * @brief Convert keys from base64 string to EVP_PKEY structure.
 *
 * @param[in] key SSH key sent from the client in a SSH message.
 * @param[in] b64 base64 public key stored in server's client_authentication structure.
 * @param[out] pkey EVP_PKEY public key structure.
 * @return 0 on success, 1 otherwise.
 */
static int
nc_server_ssh_convert_key(const ssh_key key, char *b64, EVP_PKEY **pkey)
{
    char *base64, *bin = NULL, *bin_no_type;
    NC_SSH_KEY_TYPE pub_type;
    int ret = 0;

    if ((!key && !b64) || (key && b64)) {
        ERRINT;
        ret = 1;
        goto cleanup;
    }

    if (key) {
        ret = ssh_pki_export_pubkey_base64(key, &base64);
        if (ret != SSH_OK) {
            ERR(NULL, "Error exporting SSH key to base64.");
            goto cleanup;
        }
    } else {
        base64 = b64;
    }

    if (nc_server_ssh_decode_base64(base64, &bin)) {
        ERR(NULL, "Unable to decode base64.");
        ret = 1;
        goto cleanup;
    }

    bin_no_type = nc_server_ssh_get_pubkey_type(bin, &pub_type);
    if (!bin_no_type) {
        ERR(NULL, "Error decoding type.");
        ret = 1;
        goto cleanup;
    }

    switch (pub_type) {
    case NC_SSH_KEY_DSA:
        ERR(NULL, "DSA keys are not supported.");
        break;

    case NC_SSH_KEY_RSA:
        if (nc_server_ssh_build_rsa_key(bin_no_type, pkey)) {
            ERR(NULL, "Error creating RSA key.");
            ret = 1;
            goto cleanup;
        }
        break;

    case NC_SSH_KEY_ECDSA:

        break;

    case NC_SSH_KEY_UNKNOWN:
    default:
        ERR(NULL, "Unknown key type.");
        break;
    }

cleanup:
    if (key) {
        free(base64);
    }
    free(bin);
    return ret;
}

/**
 * @brief Compare SSH key with configured authorized keys and return the username of the matching one, if any.
 *
 * @param[in] key Presented SSH key to compare.
 * @return Authorized key username, NULL if no match was found.
 */
static int
auth_pubkey_compare_key(ssh_key key, struct nc_client_auth *auth_client)
{
    uint32_t i;
    int ret = 0;
    EVP_PKEY *stored, *received;

    if (nc_server_ssh_convert_key(key, NULL, &received)) {
        ret = 1;
    }

    if (auth_client->ks_type == NC_STORE_LOCAL) {
        for (i = 0; i < auth_client->pubkey_count; i++) {
            if (nc_server_ssh_convert_key(NULL, auth_client->pubkeys[i].pub_base64, &stored)) {
                continue;
            }

            ret = EVP_PKEY_cmp(stored, received);
            if (ret == 1) {
                ret = 0;
                break;
            } else if (ret == 0) {
                WRN(NULL, "User's \"%s\" public key doesn't match, trying another.", auth_client->username);
            } else if (ret == -1) {
                WRN(NULL, "User's \"%s\" public key type doesn't match, trying another.", auth_client->username);
            } else if (ret == -2) {
                WRN(NULL, "Operation for this key comparison not supported.");
            }
        }
    } else {
        /* todo keystore */
    }

    if (i == auth_client->pubkey_count) {
        ret = 1;
    }

    EVP_PKEY_free(stored);
    EVP_PKEY_free(received);
    return ret;
}

static void
nc_sshcb_auth_none(struct nc_session *session, struct nc_client_auth *auth_client, ssh_message msg)
{
    if (auth_client->supports_none) {
        VRB(session, "User \"%s\" authenticated.", session->username);
        session->flags |= NC_SESSION_SSH_AUTHENTICATED;
        ssh_message_auth_reply_success(msg, 0);
    }

    ssh_message_reply_default(msg);
}

static void
nc_sshcb_auth_pubkey(struct nc_session *session, struct nc_client_auth *auth_client, ssh_message msg)
{
    int signature_state;

    if (server_opts.pubkey_auth_clb) {
        if (server_opts.pubkey_auth_clb(session, ssh_message_auth_pubkey(msg), server_opts.pubkey_auth_data)) {
            goto fail;
        }
    } else {
        if (auth_pubkey_compare_key(ssh_message_auth_pubkey(msg), auth_client)) {
            VRB(session, "User \"%s\" tried to use an unknown (unauthorized) public key.", session->username);
            goto fail;
        }
    }

    signature_state = ssh_message_auth_publickey_state(msg);
    if (signature_state == SSH_PUBLICKEY_STATE_VALID) {
        VRB(session, "User \"%s\" authenticated.", session->username);
        session->flags |= NC_SESSION_SSH_AUTHENTICATED;
        ssh_message_auth_reply_success(msg, 0);
    } else if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
        /* accepting only the use of a public key */
        ssh_message_auth_reply_pk_ok_simple(msg);
    }

    return;

fail:
    ++session->opts.server.ssh_auth_attempts;
    VRB(session, "Failed user \"%s\" authentication attempt (#%d).", session->username,
            session->opts.server.ssh_auth_attempts);
    ssh_message_reply_default(msg);
}

static int
nc_sshcb_channel_open(struct nc_session *session, ssh_message msg)
{
    ssh_channel chan;

    /* first channel request */
    if (!session->ti.libssh.channel) {
        if (session->status != NC_STATUS_STARTING) {
            ERRINT;
            return -1;
        }
        chan = ssh_message_channel_request_open_reply_accept(msg);
        if (!chan) {
            ERR(session, "Failed to create a new SSH channel.");
            return -1;
        }
        session->ti.libssh.channel = chan;

        /* additional channel request */
    } else {
        chan = ssh_message_channel_request_open_reply_accept(msg);
        if (!chan) {
            ERR(session, "Session %u: failed to create a new SSH channel.", session->id);
            return -1;
        }
        /* channel was created and libssh stored it internally in the ssh_session structure, good enough */
    }

    return 0;
}

static int
nc_sshcb_channel_subsystem(struct nc_session *session, ssh_channel channel, const char *subsystem)
{
    struct nc_session *new_session;

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
    } else {
        /* additional channel subsystem request, new session is ready as far as SSH is concerned */
        new_session = nc_new_session(NC_SERVER, 1);
        if (!new_session) {
            ERRMEM;
            return -1;
        }

        /* insert the new session */
        if (!session->ti.libssh.next) {
            new_session->ti.libssh.next = session;
        } else {
            new_session->ti.libssh.next = session->ti.libssh.next;
        }
        session->ti.libssh.next = new_session;

        new_session->status = NC_STATUS_STARTING;
        new_session->ti_type = NC_TI_LIBSSH;
        new_session->io_lock = session->io_lock;
        new_session->ti.libssh.channel = channel;
        new_session->ti.libssh.session = session->ti.libssh.session;
        new_session->username = strdup(session->username);
        new_session->host = strdup(session->host);
        new_session->port = session->port;
        new_session->ctx = (struct ly_ctx *)session->ctx;
        new_session->flags = NC_SESSION_SSH_AUTHENTICATED | NC_SESSION_SSH_SUBSYS_NETCONF | NC_SESSION_SHAREDCTX;
    }

    return 0;
}

int
nc_session_ssh_msg(struct nc_session *session, struct nc_server_ssh_opts *opts, ssh_message msg)
{
    const char *str_type, *str_subtype = NULL, *username;
    int subtype, type, libssh_auth_methods = 0;
    uint16_t i;
    struct nc_client_auth *auth_client = NULL;

    type = ssh_message_type(msg);
    subtype = ssh_message_subtype(msg);

    switch (type) {
    case SSH_REQUEST_AUTH:
        str_type = "request-auth";
        switch (subtype) {
        case SSH_AUTH_METHOD_NONE:
            str_subtype = "none";
            break;
        case SSH_AUTH_METHOD_PASSWORD:
            str_subtype = "password";
            break;
        case SSH_AUTH_METHOD_PUBLICKEY:
            str_subtype = "publickey";
            break;
        case SSH_AUTH_METHOD_HOSTBASED:
            str_subtype = "hostbased";
            break;
        case SSH_AUTH_METHOD_INTERACTIVE:
            str_subtype = "interactive";
            break;
        case SSH_AUTH_METHOD_GSSAPI_MIC:
            str_subtype = "gssapi-mic";
            break;
        }
        break;

    case SSH_REQUEST_CHANNEL_OPEN:
        str_type = "request-channel-open";
        switch (subtype) {
        case SSH_CHANNEL_SESSION:
            str_subtype = "session";
            break;
        case SSH_CHANNEL_DIRECT_TCPIP:
            str_subtype = "direct-tcpip";
            break;
        case SSH_CHANNEL_FORWARDED_TCPIP:
            str_subtype = "forwarded-tcpip";
            break;
        case (int)SSH_CHANNEL_X11:
            str_subtype = "channel-x11";
            break;
        case SSH_CHANNEL_UNKNOWN:
        /* fallthrough */
        default:
            str_subtype = "unknown";
            break;
        }
        break;

    case SSH_REQUEST_CHANNEL:
        str_type = "request-channel";
        switch (subtype) {
        case SSH_CHANNEL_REQUEST_PTY:
            str_subtype = "pty";
            break;
        case SSH_CHANNEL_REQUEST_EXEC:
            str_subtype = "exec";
            break;
        case SSH_CHANNEL_REQUEST_SHELL:
            str_subtype = "shell";
            break;
        case SSH_CHANNEL_REQUEST_ENV:
            str_subtype = "env";
            break;
        case SSH_CHANNEL_REQUEST_SUBSYSTEM:
            str_subtype = "subsystem";
            break;
        case SSH_CHANNEL_REQUEST_WINDOW_CHANGE:
            str_subtype = "window-change";
            break;
        case SSH_CHANNEL_REQUEST_X11:
            str_subtype = "x11";
            break;
        case SSH_CHANNEL_REQUEST_UNKNOWN:
        /* fallthrough */
        default:
            str_subtype = "unknown";
            break;
        }
        break;

    case SSH_REQUEST_SERVICE:
        str_type = "request-service";
        str_subtype = ssh_message_service_service(msg);
        break;

    case SSH_REQUEST_GLOBAL:
        str_type = "request-global";
        switch (subtype) {
        case SSH_GLOBAL_REQUEST_TCPIP_FORWARD:
            str_subtype = "tcpip-forward";
            break;
        case SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD:
            str_subtype = "cancel-tcpip-forward";
            break;
        case SSH_GLOBAL_REQUEST_UNKNOWN:
        /* fallthrough */
        default:
            str_subtype = "unknown";
            break;
        }
        break;

    default:
        str_type = "unknown";
        str_subtype = "unknown";
        break;
    }

    VRB(session, "Received an SSH message \"%s\" of subtype \"%s\".", str_type, str_subtype);
    if (!session || (session->status == NC_STATUS_CLOSING) || (session->status == NC_STATUS_INVALID)) {
        /* "valid" situation if, for example, receiving some auth or channel request timeouted,
         * but we got it now, during session free */
        VRB(session, "SSH message arrived on a %s session, the request will be denied.",
                (session && session->status == NC_STATUS_CLOSING ? "closing" : "invalid"));
        ssh_message_reply_default(msg);
        return 0;
    }

    /*
     * process known messages
     */
    if (type == SSH_REQUEST_AUTH) {
        if (session->flags & NC_SESSION_SSH_AUTHENTICATED) {
            ERR(session, "User \"%s\" authenticated, but requested another authentication.", session->username);
            ssh_message_reply_default(msg);
            return 0;
        }

        /* save the username, do not let the client change it */
        username = ssh_message_auth_user(msg);
        assert(username);
        assert(opts);

        for (i = 0; i < opts->client_count; i++) {
            if (!strcmp(opts->auth_clients[i].username, username)) {
                auth_client = &opts->auth_clients[i];
                break;
            }
        }

        if (!auth_client) {
            ERR(NULL, "User \"%s\" not known by the server.", session->username);
            ssh_message_reply_default(msg); /*todo*/
            return 0;
        }

        if (!session->username) {
            session->username = strdup(username);

            /* configure accepted auth methods */
            if (auth_client->ks_type == NC_STORE_LOCAL) {
                if (auth_client->pubkey_count) {
                    libssh_auth_methods |= SSH_AUTH_METHOD_PUBLICKEY;
                }
            } else if (auth_client->ts_reference) {
                libssh_auth_methods |= SSH_AUTH_METHOD_PUBLICKEY;
            }
            if (auth_client->password) {
                libssh_auth_methods |= SSH_AUTH_METHOD_PASSWORD;
            }
            if (auth_client->pam_config_name) {
                libssh_auth_methods |= SSH_AUTH_METHOD_INTERACTIVE;
            }
            if (auth_client->supports_none) {
                libssh_auth_methods |= SSH_AUTH_METHOD_NONE;
            }
            ssh_set_auth_methods(session->ti.libssh.session, libssh_auth_methods);
        } else {
            if (strcmp(username, session->username)) {
                ERR(session, "User \"%s\" changed its username to \"%s\".", session->username, username);
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_OTHER;
                return 1;
            }
        }

        if (subtype == SSH_AUTH_METHOD_NONE) {
            nc_sshcb_auth_none(session, auth_client, msg);
            return 0;
        } else if (subtype == SSH_AUTH_METHOD_PASSWORD) {
            nc_sshcb_auth_password(session, auth_client, msg);
            return 0;
        } else if (subtype == SSH_AUTH_METHOD_PUBLICKEY) {
            nc_sshcb_auth_pubkey(session, auth_client, msg);
            return 0;
        } else if (subtype == SSH_AUTH_METHOD_INTERACTIVE) {
            nc_sshcb_auth_kbdint(session, opts, msg);
            return 0;
        }
    } else if (session->flags & NC_SESSION_SSH_AUTHENTICATED) {
        if ((type == SSH_REQUEST_CHANNEL_OPEN) && ((enum ssh_channel_type_e)subtype == SSH_CHANNEL_SESSION)) {
            if (nc_sshcb_channel_open(session, msg)) {
                ssh_message_reply_default(msg);
            }
            return 0;

        } else if ((type == SSH_REQUEST_CHANNEL) && ((enum ssh_channel_requests_e)subtype == SSH_CHANNEL_REQUEST_SUBSYSTEM)) {
            if (nc_sshcb_channel_subsystem(session, ssh_message_channel_request_channel(msg),
                    ssh_message_channel_request_subsystem(msg))) {
                ssh_message_reply_default(msg);
            } else {
                ssh_message_channel_request_reply_success(msg);
            }
            return 0;
        }
    }

    /* we did not process it */
    return 1;
}

/* ret 1 on success, 0 on timeout, -1 on error */
static int
nc_accept_ssh_session_open_netconf_channel(struct nc_session *session, struct nc_server_ssh_opts *opts, int timeout)
{
    struct timespec ts_timeout;
    ssh_message msg;

    if (timeout) {
        nc_gettimespec_mono_add(&ts_timeout, timeout * 1000);
    }
    while (1) {
        if (!nc_session_is_connected(session)) {
            ERR(session, "Communication SSH socket unexpectedly closed.");
            return -1;
        }

        msg = ssh_message_get(session->ti.libssh.session);
        if (msg) {
            if (nc_session_ssh_msg(session, opts, msg)) {
                ssh_message_reply_default(msg);
            }
            ssh_message_free(msg);
        }

        if (session->ti.libssh.channel && session->flags & NC_SESSION_SSH_SUBSYS_NETCONF) {
            return 1;
        }

        usleep(NC_TIMEOUT_STEP);
        if ((opts->auth_timeout) && (nc_difftimespec_mono_cur(&ts_timeout) < 1)) {
            /* timeout */
            ERR(session, "Failed to start \"netconf\" SSH subsystem for too long, disconnecting.");
            break;
        }
    }

    return 0;
}

/**
 * @brief Set hostkeys to be used for an SSH bind.
 *
 * @param[in] sbind SSH bind to use.
 * @param[in] hostkeys Array of hostkeys.
 * @param[in] hostkey_count Count of @p hostkeys.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
nc_ssh_bind_add_hostkeys(ssh_bind sbind, struct nc_server_ssh_opts *opts, uint16_t hostkey_count)
{
    uint16_t i;
    char *privkey_path, *privkey_data;
    int ret;

    for (i = 0; i < hostkey_count; ++i) {
        privkey_path = privkey_data = NULL;

        if (opts->hostkeys[i].ks_type == NC_STORE_LOCAL) {
            privkey_data = opts->hostkeys[i].priv_base64;
            privkey_path = base64der_key_to_tmp_file(privkey_data, nc_keytype2str(opts->hostkeys[i].privkey_type), 0);
        } else if (opts->hostkeys[i].ks_type == NC_STORE_KEYSTORE) {
            privkey_data = opts->hostkeys[i].keystore->priv_base64;
            privkey_path = base64der_key_to_tmp_file(privkey_data, nc_keytype2str(opts->hostkeys[i].keystore->privkey_type), 0);
        } else {
            ERR(NULL, "Internal error, invalid PK store (%d)", opts->hostkeys[i].ks_type);
            return -1;
        }

        if (!privkey_path) {
            ERR(NULL, "Temporarily storing a host key into a file failed (%s).", strerror(errno));
            return -1;
        }

        ret = ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HOSTKEY, privkey_path);

        /* cleanup */
        if (privkey_data && unlink(privkey_path)) {
            WRN(NULL, "Removing a temporary host key file \"%s\" failed (%s).", privkey_path, strerror(errno));
        }

        if (ret != SSH_OK) {
            ERR(NULL, "Failed to set hostkey \"%s\" (%s).", opts->hostkeys[i].name, privkey_path);
        }
        free(privkey_path);

        if (ret != SSH_OK) {
            return -1;
        }
    }

    return 0;
}

static int
nc_accept_ssh_session_auth(struct nc_session *session, struct nc_server_ssh_opts *opts)
{
    struct timespec ts_timeout;
    ssh_message msg;

    /* authenticate */
    if (opts->auth_timeout) {
        nc_gettimespec_mono_add(&ts_timeout, opts->auth_timeout * 1000);
    }
    while (1) {
        if (!nc_session_is_connected(session)) {
            ERR(session, "Communication SSH socket unexpectedly closed.");
            return -1;
        }

        msg = ssh_message_get(session->ti.libssh.session);
        if (msg) {
            if (nc_session_ssh_msg(session, opts, msg)) {
                ssh_message_reply_default(msg);
            }
            ssh_message_free(msg);
        }

        if (session->flags & NC_SESSION_SSH_AUTHENTICATED) {
            break;
        }

        if (session->opts.server.ssh_auth_attempts >= opts->auth_attempts) {
            ERR(session, "Too many failed authentication attempts of user \"%s\".", session->username);
            return -1;
        }

        usleep(NC_TIMEOUT_STEP);
        if ((opts->auth_timeout) && (nc_difftimespec_mono_cur(&ts_timeout) < 1)) {
            /* timeout */
            break;
        }
    }

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
nc_accept_ssh_session(struct nc_session *session, struct nc_server_ssh_opts *opts, int sock, int timeout)
{
    ssh_bind sbind = NULL;
    int rc = 1, r;
    struct timespec ts_timeout;

    /* other transport-specific data */
    session->ti_type = NC_TI_LIBSSH;
    session->ti.libssh.session = ssh_new();
    if (!session->ti.libssh.session) {
        ERR(NULL, "Failed to initialize a new SSH session.");
        rc = -1;
        goto cleanup;
    }

    sbind = ssh_bind_new();
    if (!sbind) {
        ERR(session, "Failed to create an SSH bind.");
        rc = -1;
        goto cleanup;
    }

    /* configure host keys */
    if (nc_ssh_bind_add_hostkeys(sbind, opts, opts->hostkey_count)) {
        rc = -1;
        goto cleanup;
    }

    /* configure supported algorithms */
    if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS, opts->hostkey_algs)) {
        rc = -1;
        goto cleanup;
    }
    if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_CIPHERS_S_C, opts->encryption_algs)) {
        rc = -1;
        goto cleanup;
    }
    if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_KEY_EXCHANGE, opts->kex_algs)) {
        rc = -1;
        goto cleanup;
    }
    if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HMAC_S_C, opts->mac_algs)) {
        rc = -1;
        goto cleanup;
    }

    /* accept new connection on the bind */
    if (ssh_bind_accept_fd(sbind, session->ti.libssh.session, sock) == SSH_ERROR) {
        ERR(session, "SSH failed to accept a new connection (%s).", ssh_get_error(sbind));
        rc = -1;
        goto cleanup;
    }
    sock = -1;

    /* set to non-blocking */
    ssh_set_blocking(session->ti.libssh.session, 0);

    if (timeout > -1) {
        nc_gettimespec_mono_add(&ts_timeout, timeout);
    }
    while ((r = ssh_handle_key_exchange(session->ti.libssh.session)) == SSH_AGAIN) {
        /* this tends to take longer */
        usleep(NC_TIMEOUT_STEP * 20);
        if ((timeout > -1) && (nc_difftimespec_mono_cur(&ts_timeout) < 1)) {
            break;
        }
    }
    if (r == SSH_AGAIN) {
        ERR(session, "SSH key exchange timeout.");
        rc = 0;
        goto cleanup;
    } else if (r != SSH_OK) {
        ERR(session, "SSH key exchange error (%s).", ssh_get_error(session->ti.libssh.session));
        rc = -1;
        goto cleanup;
    }

    /* authenticate */
    if ((rc = nc_accept_ssh_session_auth(session, opts)) != 1) {
        goto cleanup;
    }

    /* open channel and request 'netconf' subsystem */
    if ((rc = nc_accept_ssh_session_open_netconf_channel(session, opts, timeout)) != 1) {
        goto cleanup;
    }

cleanup:
    if (sock > -1) {
        close(sock);
    }
    ssh_bind_free(sbind);
    return rc;
}

API NC_MSG_TYPE
nc_session_accept_ssh_channel(struct nc_session *orig_session, struct nc_session **session)
{
    NC_MSG_TYPE msgtype;
    struct nc_session *new_session = NULL;
    struct timespec ts_cur;

    if (!orig_session) {
        ERRARG("orig_session");
        return NC_MSG_ERROR;
    } else if (!session) {
        ERRARG("session");
        return NC_MSG_ERROR;
    }

    if ((orig_session->status == NC_STATUS_RUNNING) && (orig_session->ti_type == NC_TI_LIBSSH) &&
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

    nc_gettimespec_real_add(&ts_cur, 0);
    new_session->opts.server.session_start = ts_cur.tv_sec;
    nc_gettimespec_mono_add(&ts_cur, 0);
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

    if (!ps) {
        ERRARG("ps");
        return NC_MSG_ERROR;
    } else if (!session) {
        ERRARG("session");
        return NC_MSG_ERROR;
    }

    /* LOCK */
    if (nc_ps_lock(ps, &q_id, __func__)) {
        return NC_MSG_ERROR;
    }

    for (i = 0; i < ps->session_count; ++i) {
        cur_session = ps->sessions[i]->session;
        if ((cur_session->status == NC_STATUS_RUNNING) && (cur_session->ti_type == NC_TI_LIBSSH) &&
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

    nc_gettimespec_real_add(&ts_cur, 0);
    new_session->opts.server.session_start = ts_cur.tv_sec;
    nc_gettimespec_mono_add(&ts_cur, 0);
    new_session->opts.server.last_rpc = ts_cur.tv_sec;
    new_session->status = NC_STATUS_RUNNING;
    *session = new_session;

    return msgtype;
}
