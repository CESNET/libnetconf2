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

#include "config.h" /* Expose HAVE_LIBPAM and HAVE_SHADOW */

#ifdef HAVE_LIBPAM
#   include <security/pam_appl.h>
#endif
#ifdef HAVE_SHADOW
#   include <shadow.h>
#endif

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

#include "compat.h"
#include "log_p.h"
#include "session.h"
#include "session_p.h"
#include "session_wrapper.h"

extern struct nc_server_opts server_opts;

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
    uint16_t i;
    struct nc_keystore *ks = &server_opts.keystore;

    *askey = NULL;

    /* lookup name */
    for (i = 0; i < ks->asym_key_count; i++) {
        if (!strcmp(referenced_name, ks->asym_keys[i].name)) {
            break;
        }
    }

    if (i == ks->asym_key_count) {
        ERR(NULL, "Keystore entry \"%s\" not found.", referenced_name);
        return 1;
    }

    *askey = &ks->asym_keys[i];

    /* check if the referenced public key is SubjectPublicKeyInfo */
    if ((*askey)->pubkey_data && nc_is_pk_subject_public_key_info((*askey)->pubkey_data)) {
        ERR(NULL, "The public key of the referenced hostkey \"%s\" is in the SubjectPublicKeyInfo format, "
                "which is not allowed in the SSH!", referenced_name);
        return 1;
    }

    return 0;
}

/**
 * @brief Get public keys from the truststore.
 *
 * @param[in] referenced_name Name of the public key bag in the truststore.
 * @param[out] pubkeys Referenced public keys.
 * @param[out] pubkey_count Referenced public key count.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_ssh_ts_ref_get_keys(const char *referenced_name, struct nc_public_key **pubkeys, uint16_t *pubkey_count)
{
    uint16_t i, j;
    struct nc_truststore *ts = &server_opts.truststore;

    *pubkeys = NULL;
    *pubkey_count = 0;

    /* lookup name */
    for (i = 0; i < ts->pub_bag_count; i++) {
        if (!strcmp(referenced_name, ts->pub_bags[i].name)) {
            break;
        }
    }

    if (i == ts->pub_bag_count) {
        ERR(NULL, "Truststore entry \"%s\" not found.", referenced_name);
        return 1;
    }

    /* check if any of the referenced public keys is SubjectPublicKeyInfo */
    for (j = 0; j < ts->pub_bags[i].pubkey_count; j++) {
        if (nc_is_pk_subject_public_key_info(ts->pub_bags[i].pubkeys[j].data)) {
            ERR(NULL, "A public key of the referenced public key bag \"%s\" is in the SubjectPublicKeyInfo format, "
                    "which is not allowed in the SSH!", referenced_name);
            return 1;
        }
    }

    *pubkeys = ts->pub_bags[i].pubkeys;
    *pubkey_count = ts->pub_bags[i].pubkey_count;
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
            free(path);
            goto cleanup;
        }
    }

    *out_path = path;
cleanup:
    free(uid);
    free(buf);
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
nc_server_ssh_read_authorized_keys_file(const char *path, struct nc_public_key **pubkeys, uint16_t *pubkey_count)
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
        rc = asprintf(&(*pubkeys)[*pubkey_count].name, "authorized_key_%" PRIu16, *pubkey_count);
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

/**
 * @brief Get user's public keys from the system.
 *
 * @param[in] username Username.
 * @param[out] pubkeys User's public keys.
 * @param[out] pubkey_count Public key count.
 * @return 0 on success, non-zero on error.
 */
static int
nc_server_ssh_get_system_keys(const char *username, struct nc_public_key **pubkeys, uint16_t *pubkey_count)
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

/**
 * @brief Get the user's hashed password from the system.
 *
 * @param[in] username Username.
 * @return User's hashed password or NULL on error.
 */
static char *
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

#endif

/**
 * @brief Compare stored hashed password with a cleartext received password.
 *
 * @param[in] stored_pw Hashed stored password.
 * @param[in] received_pw Cleartext received password.
 * @return 0 on match, non-zero otherwise.
 */
static int
nc_server_ssh_compare_password(const char *stored_pw, const char *received_pw)
{
    char *received_pw_hash = NULL;
    struct crypt_data cdata = {0};

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

    received_pw_hash = crypt_r(received_pw, stored_pw, &cdata);
    if (!received_pw_hash) {
        ERR(NULL, "Hashing the password failed (%s).", strerror(errno));
        return 1;
    }

    return strcmp(received_pw_hash, stored_pw);
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
        if (!nc_session_is_connected(session)) {
            ERR(NULL, "SSH communication socket unexpectedly closed.");
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

#ifdef HAVE_LIBPAM

/**
 * @brief PAM conversation function, which serves as a callback for exchanging messages between the client and a PAM module.
 *
 * @param[in] n_messages Number of messages.
 * @param[in] msg PAM module's messages.
 * @param[out] resp User responses.
 * @param[in] appdata_ptr Callback's data.
 * @return PAM_SUCCESS on success, PAM_BUF_ERR on memory allocation error, PAM_CONV_ERR otherwise.
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

    libssh_session = clb_data->session->ti.libssh.session;

    /* PAM_MAX_NUM_MSG == 32 by default */
    if ((n_messages <= 0) || (n_messages >= PAM_MAX_NUM_MSG)) {
        ERR(clb_data->session, "Bad number of PAM messages (#%d).", n_messages);
        r = PAM_CONV_ERR;
        goto cleanup;
    }

    /* only accepting these 4 types of messages */
    for (i = 0; i < n_messages; i++) {
        t = msg[i]->msg_style;
        if ((t != PAM_PROMPT_ECHO_OFF) && (t != PAM_PROMPT_ECHO_ON) && (t != PAM_TEXT_INFO) && (t != PAM_ERROR_MSG)) {
            ERR(clb_data->session, "PAM conversation callback received an unexpected type of message.");
            r = PAM_CONV_ERR;
            goto cleanup;
        }
    }

    /* display messages with errors and/or some information and count the amount of actual authentication challenges */
    for (i = 0; i < n_messages; i++) {
        if (msg[i]->msg_style == PAM_TEXT_INFO) {
            VRB(clb_data->session, "PAM conversation callback received a message with some information for the client (%s).", msg[i]->msg);
            n_requests--;
        }
        if (msg[i]->msg_style == PAM_ERROR_MSG) {
            ERR(clb_data->session, "PAM conversation callback received an error message (%s).", msg[i]->msg);
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
    NC_CHECK_ERRMEM_GOTO(!(*resp) || !prompts || !echo, r = PAM_BUF_ERR, cleanup);

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
        ERR(clb_data->session, "Failed to send an authentication request.");
        r = PAM_CONV_ERR;
        goto cleanup;
    }

    n_answers = nc_server_ssh_kbdint_get_nanswers(clb_data->session, libssh_session);
    if (n_answers < 0) {
        /* timeout or dc */
        r = PAM_CONV_ERR;
        goto cleanup;
    } else if (n_answers != n_requests) {
        /* check if the number of answers and requests matches */
        ERR(clb_data->session, "Expected %d response(s), got %d.", n_requests, n_answers);
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
 * @param[in] username Username of the client to auhtenticate.
 * @param[in] ssh_msg SSH message with a keyboard-interactive authentication request.
 * @return PAM_SUCCESS on success;
 * @return PAM error otherwise.
 */
static int
nc_server_ssh_auth_kbdint_pam(struct nc_session *session, const char *username, ssh_message ssh_msg)
{
    pam_handle_t *pam_h = NULL;
    int ret;
    struct nc_pam_thread_arg clb_data;
    struct pam_conv conv;

    /* structure holding callback's data */
    clb_data.msg = ssh_msg;
    clb_data.session = session;

    /* PAM conversation structure holding the callback and it's data */
    conv.conv = nc_pam_conv_clb;
    conv.appdata_ptr = &clb_data;

    if (!server_opts.pam_config_name) {
        ERR(session, "PAM configuration filename not set.");
        ret = 1;
        goto cleanup;
    }

    /* initialize PAM and see if the given configuration file exists */
    ret = pam_start(server_opts.pam_config_name, username, &conv, &pam_h);
    if (ret != PAM_SUCCESS) {
        ERR(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
        goto cleanup;
    }

    /* authentication based on the modules listed in the configuration file */
    ret = pam_authenticate(pam_h, 0);
    if (ret != PAM_SUCCESS) {
        if (ret == PAM_ABORT) {
            ERR(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
            goto cleanup;
        } else {
            VRB(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
            goto cleanup;
        }
    }

    /* correct token entered, check other requirements(the time of the day, expired token, ...) */
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
            goto cleanup;
        }
    }

cleanup:
    /* destroy the PAM context */
    if (pam_h && (pam_end(pam_h, ret) != PAM_SUCCESS)) {
        ERR(NULL, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
    }
    return ret;
}

#elif defined (HAVE_SHADOW)

/**
 * @brief Authenticate using credentials stored in the system.
 *
 * @param[in] session Session to authenticate on.
 * @param[in] username Username of the client to authenticate.
 * @param[in] msg SSH message that originally requested kbdint authentication.
 *
 * @return 0 on success, non-zero otherwise.
 */
static int
nc_server_ssh_auth_kbdint_system(struct nc_session *session, const char *username, ssh_message msg)
{
    int ret = 0, n_answers;
    const char *name = "Keyboard-Interactive Authentication";
    const char *instruction = "Please enter your authentication token";
    char *prompt = NULL, *pw = NULL, *received_pw = NULL;
    char echo[] = {0};

    /* try to get the client's pw hash from the system */
    pw = nc_server_ssh_get_pwd_hash(username);
    if (!pw) {
        ret = 1;
        goto cleanup;
    }

    ret = asprintf(&prompt, "%s's password:", username);
    NC_CHECK_ERRMEM_GOTO(ret == -1, prompt = NULL; ret = 1, cleanup);

    /* send the password prompt to the client */
    ret = ssh_message_auth_interactive_request(msg, name, instruction, 1, (const char **) &prompt, echo);
    if (ret) {
        ERR(session, "Failed to send an authentication request to client \"%s\".", username);
        goto cleanup;
    }

    /* get the reply */
    n_answers = nc_server_ssh_kbdint_get_nanswers(session, session->ti.libssh.session);
    if (n_answers < 0) {
        /* timeout or dc */
        ret = 1;
        goto cleanup;
    } else if (n_answers != 1) {
        /* only expecting a single answer */
        ERR(session, "Unexpected amount of answers in system auth. Expected 1, got \"%d\".", n_answers);
        ret = 1;
        goto cleanup;
    }
    received_pw = strdup(ssh_userauth_kbdint_getanswer(session->ti.libssh.session, 0));
    NC_CHECK_ERRMEM_GOTO(!received_pw, ret = 1, cleanup);

    /* cmp the passwords */
    ret = nc_server_ssh_compare_password(pw, received_pw);

cleanup:
    free(pw);
    free(received_pw);
    free(prompt);
    return ret;
}

#endif

API void
nc_server_ssh_set_interactive_auth_clb(int (*interactive_auth_clb)(const struct nc_session *session, ssh_session ssh_sess, ssh_message msg, void *user_data),
        void *user_data, void (*free_user_data)(void *user_data))
{
    /* CONFIG LOCK */
    pthread_rwlock_wrlock(&server_opts.config_lock);

    server_opts.interactive_auth_clb = interactive_auth_clb;
    server_opts.interactive_auth_data = user_data;
    server_opts.interactive_auth_data_free = free_user_data;

    /* CONFIG UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);
}

#ifdef HAVE_LIBPAM

API int
nc_server_ssh_set_pam_conf_filename(const char *filename)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, filename, 1);

    /* CONFIG LOCK */
    pthread_rwlock_wrlock(&server_opts.config_lock);

    free(server_opts.pam_config_name);
    server_opts.pam_config_name = strdup(filename);
    if (!server_opts.pam_config_name) {
        ERRMEM;
        ret = 1;
    }

    /* CONFIG UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);
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
    pthread_rwlock_wrlock(&server_opts.config_lock);

    free(server_opts.authkey_path_fmt);
    server_opts.authkey_path_fmt = strdup(path);
    if (!server_opts.authkey_path_fmt) {
        ERRMEM;
        ret = 1;
    }

    /* CONFIG UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);
    return ret;
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

/**
 * @brief Compare SSH key with configured authorized keys and return the username of the matching one, if any.
 *
 * @param[in] key Presented SSH key to compare.
 * @return Authorized key username, NULL if no match was found.
 */
static int
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

/**
 * @brief Handle authentication request for the None method.
 *
 * @param[in] local_users_supported Whether the server supports local users.
 * @param[in] auth_client Configured client's authentication data.
 * @param[in] msg libssh message.
 * @return 0 if the authentication was successful, -1 if not (@p msg already replied to).
 */
static int
nc_server_ssh_auth_none(int local_users_supported, struct nc_auth_client *auth_client, ssh_message msg)
{
    assert(!local_users_supported || auth_client);

    if (local_users_supported && auth_client->none_enabled) {
        /* success */
        return 0;
    }

    /* reply and return -1 so that this does not get counted as an unsuccessful authentication attempt */
    ssh_message_reply_default(msg);
    return -1;
}

/**
 * @brief Handle authentication request for the Password method.
 *
 * @param[in] session NETCONF session.
 * @param[in] local_users_supported Whether the server supports local users.
 * @param[in] auth_client Configured client's authentication data.
 * @param[in] msg libssh message.
 * @return 0 if the authentication was successful, 1 if not (@p msg not yet replied to).
 */
static int
nc_server_ssh_auth_password(struct nc_session *session, int local_users_supported,
        struct nc_auth_client *auth_client, ssh_message msg)
{
    int rc;
    char *password = NULL;

    assert(!local_users_supported || auth_client);

    if (local_users_supported) {
        /* obtain pw from config */
        password = auth_client->password;
        if (!password) {
            VRB(session, "User \"%s\" does not have password method configured, but a request was received.", session->username);
            return 1;
        }
    } else {
#ifdef HAVE_SHADOW
        /* obtain pw from system, this one needs to be free'd */
        password = nc_server_ssh_get_pwd_hash(session->username);
        if (!password) {
            return 1;
        }
#else
        ERR(session, "Obtaining password from system not supported.");
        return 1;
#endif
    }

    /* compare the passwords */
    rc = nc_server_ssh_compare_password(password, ssh_message_auth_password(msg));

    if (!local_users_supported) {
        free(password);
    }

    return rc ? 1 : 0;
}

/**
 * @brief Handle authentication request for the Publickey method.
 *
 * @param[in] session NETCONF session.
 * @param[in] local_users_supported Whether the server supports local users.
 * @param[in] auth_client Configured client's authentication data.
 * @param[in] msg libssh message.
 * @return 0 if the authentication was successful, 1 if not and the @p msg not yet replied to, -1 if not and @p msg was replied to.
 */
static int
nc_server_ssh_auth_pubkey(struct nc_session *session, int local_users_supported,
        struct nc_auth_client *auth_client, ssh_message msg)
{
    int signature_state, ret = 0;
    struct nc_public_key *pubkeys = NULL;
    uint16_t pubkey_count = 0, i;

    assert(!local_users_supported || auth_client);

    /* get the public keys */
    if (!local_users_supported || (auth_client->store == NC_STORE_SYSTEM)) {
        /* system user or the user has 'use system keys' configured, these need to be free'd */
        ret = nc_server_ssh_get_system_keys(session->username, &pubkeys, &pubkey_count);
        if (ret) {
            goto cleanup;
        }
    } else if (auth_client->store == NC_STORE_LOCAL) {
        pubkeys = auth_client->pubkeys;
        pubkey_count = auth_client->pubkey_count;
    } else if (auth_client->store == NC_STORE_TRUSTSTORE) {
        ret = nc_server_ssh_ts_ref_get_keys(auth_client->ts_ref, &pubkeys, &pubkey_count);
        if (ret) {
            goto cleanup;
        }
    } else {
        ERRINT;
        return 1;
    }

    /* compare the received pubkey with the authorized ones */
    if (nc_server_ssh_auth_pubkey_compare_key(ssh_message_auth_pubkey(msg), pubkeys, pubkey_count)) {
        VRB(session, "User \"%s\" tried to use an unknown (unauthorized) public key.", session->username);
        ret = 1;
        goto cleanup;
    }

    signature_state = ssh_message_auth_publickey_state(msg);
    if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
        /* accepting only the use of a public key */
        ssh_message_auth_reply_pk_ok_simple(msg);
        ret = -1;
    }

cleanup:
    if (!local_users_supported || (auth_client->store == NC_STORE_SYSTEM)) {
        for (i = 0; i < pubkey_count; i++) {
            free(pubkeys[i].name);
            free(pubkeys[i].data);
        }
        free(pubkeys);
    }

    return ret;
}

/**
 * @brief Handle authentication request for the Keyboard-interactive method.
 *
 * @param[in] session NETCONF session.
 * @param[in] local_users_supported Whether the server supports local users.
 * @param[in] auth_client Configured client's authentication data.
 * @param[in] msg libssh message.
 * @return 0 if the authentication was successful, 1 if not.
 */
static int
nc_server_ssh_auth_kbdint(struct nc_session *session, int local_users_supported, struct nc_auth_client *auth_client, ssh_message msg)
{
    int rc = 0;

    assert(!local_users_supported || auth_client);

    if (local_users_supported && !auth_client->kb_int_enabled) {
        VRB(session, "User \"%s\" does not have Keyboard-interactive method configured, but a request was received.", session->username);
        return 1;
    } else if (server_opts.interactive_auth_clb) {
        rc = server_opts.interactive_auth_clb(session, session->ti.libssh.session, msg, server_opts.interactive_auth_data);
    } else {
#ifdef HAVE_LIBPAM
        /* authenticate using PAM */
        rc = nc_server_ssh_auth_kbdint_pam(session, session->username, msg);
#elif defined (HAVE_SHADOW)
        /* authenticate using the system */
        rc = nc_server_ssh_auth_kbdint_system(session, session->username, msg);
#else
        ERR(NULL, "Keyboard-interactive method not supported.");
        return 1;
#endif
    }

    return rc ? 1 : 0;
}

/**
 * @brief Handle SSH channel open request.
 *
 * @param[in] session NETCONF session.
 * @param[in] msg libssh message.
 * @return 0 on success, -1 on failure.
 */
static int
nc_server_ssh_channel_open(struct nc_session *session, ssh_message msg)
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

/**
 * @brief Handle SSH channel request subsystem request.
 *
 * @param[in] session NETCONF session.
 * @param[in] channel Requested SSH channel.
 * @param[in] subsystem Name of the requested subsystem.
 * @return 0 on success, -1 on failure.
 */
static int
nc_server_ssh_channel_subsystem(struct nc_session *session, ssh_channel channel, const char *subsystem)
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
        NC_CHECK_ERRMEM_RET(!new_session, -1);

        /* insert the new session */
        if (!session->ti.libssh.next) {
            new_session->ti.libssh.next = session;
        } else {
            new_session->ti.libssh.next = session->ti.libssh.next;
        }
        session->ti.libssh.next = new_session;

        new_session->status = NC_STATUS_STARTING;
        new_session->ti_type = NC_TI_SSH;
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

/**
 * @brief Handle NETCONF SSH authentication.
 *
 * @param[in] session NETCONF session.
 * @param[in] opts SSH server options.
 * @param[in] msg libssh message.
 * @param[in] method Type of the authentication method.
 * @param[in] str_method String representation of the authentication method.
 * @param[in] local_users_supported Whether the server supports local users.
 * @param[in,out] auth_state Authentication state.
 * @return 1 in case of a fatal error, 0 otherwise.
 */
static int
nc_server_ssh_auth(struct nc_session *session, struct nc_server_ssh_opts *opts, ssh_message msg,
        int method, const char *str_method, int local_users_supported, struct nc_auth_state *auth_state)
{
    const char *username;
    int ret = 0;
    uint16_t i;
    struct nc_auth_client *auth_client = NULL;
    struct nc_endpt *referenced_endpt;

    /* save the username, do not let the client change it */
    username = ssh_message_auth_user(msg);
    assert(username);

    if (local_users_supported) {
        /* get the locally configured user */
        for (i = 0; i < opts->client_count; i++) {
            if (!strcmp(opts->auth_clients[i].username, username)) {
                auth_client = &opts->auth_clients[i];
                break;
            }
        }

        if (!auth_client) {
            if (opts->referenced_endpt_name) {
                /* client not known by the endpt, but it references another one so try it */
                if (nc_server_get_referenced_endpt(opts->referenced_endpt_name, &referenced_endpt)) {
                    ERRINT;
                    return 1;
                }

                return nc_server_ssh_auth(session, referenced_endpt->opts.ssh, msg, method,
                        str_method, local_users_supported, auth_state);
            }

            /* user not known, set his authentication methods to public key only so that
             * there is no interaction and it will simply be denied */
            ERR(NULL, "User \"%s\" not known by the server.", username);
            ssh_set_auth_methods(session->ti.libssh.session, SSH_AUTH_METHOD_PUBLICKEY);
            ssh_message_reply_default(msg);
            return 0;
        }
    }

    if (!session->username) {
        session->username = strdup(username);
        NC_CHECK_ERRMEM_RET(!session->username, 1);

        /* configure and count accepted auth methods */
        if (local_users_supported) {
            if (((auth_client->store == NC_STORE_LOCAL) && (auth_client->pubkey_count)) ||
                    (auth_client->store == NC_STORE_TRUSTSTORE) || (auth_client->store == NC_STORE_SYSTEM)) {
                /* either locally configured pubkeys, or truststore or system (need to check for
                 * pubkey count, because NC_STORE_LOCAL is the default enum value) */
                auth_state->methods |= SSH_AUTH_METHOD_PUBLICKEY;
                auth_state->method_count++;
            }
            if (auth_client->password) {
                auth_state->methods |= SSH_AUTH_METHOD_PASSWORD;
                auth_state->method_count++;
            }
            if (auth_client->kb_int_enabled) {
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
    } else {
        if (strcmp(username, session->username)) {
            /* changing username not allowed */
            ERR(session, "User \"%s\" changed its username to \"%s\".", session->username, username);
            session->status = NC_STATUS_INVALID;
            session->term_reason = NC_SESSION_TERM_OTHER;
            return 1;
        }
    }

    /* try authenticating, if local users are supported, then the configured user must authenticate via all of his
     * configured auth methods, otherwise for system users just one is needed,
     * 0 return indicates success, 1 fail (msg not yet replied to), -1 fail (msg was replied to) */
    if (method == SSH_AUTH_METHOD_NONE) {
        ret = nc_server_ssh_auth_none(local_users_supported, auth_client, msg);
    } else if (method == SSH_AUTH_METHOD_PASSWORD) {
        ret = nc_server_ssh_auth_password(session, local_users_supported, auth_client, msg);
    } else if (method == SSH_AUTH_METHOD_PUBLICKEY) {
        ret = nc_server_ssh_auth_pubkey(session, local_users_supported, auth_client, msg);
    } else if (method == SSH_AUTH_METHOD_INTERACTIVE) {
        ret = nc_server_ssh_auth_kbdint(session, local_users_supported, auth_client, msg);
    } else {
        ++session->opts.server.ssh_auth_attempts;
        VRB(session, "Authentication method \"%s\" not supported.", str_method);
        ssh_message_reply_default(msg);
        return 0;
    }

    if (!ret) {
        auth_state->success_methods |= method;
        auth_state->success_count++;

        if (auth_state->success_count < auth_state->method_count) {
            /* success, but he needs to do another method */
            VRB(session, "User \"%s\" partially authenticated, but still needs to authenticate via the rest of his configured methods.", username);
            ssh_set_auth_methods(session->ti.libssh.session, auth_state->methods & ~auth_state->success_methods);
            ssh_message_auth_reply_success(msg, 1);
        } else {
            /* authenticated */
            ssh_message_auth_reply_success(msg, 0);
            session->flags |= NC_SESSION_SSH_AUTHENTICATED;
            VRB(session, "User \"%s\" authenticated.", username);
        }
    } else if (ret == 1) {
        /* failed attempt, msg wasnt yet replied to */
        ++session->opts.server.ssh_auth_attempts;
        VRB(session, "Failed user \"%s\" authentication attempt (#%d).", session->username,
                session->opts.server.ssh_auth_attempts);
        ssh_message_reply_default(msg);
    }

    return 0;
}

int
nc_session_ssh_msg(struct nc_session *session, struct nc_server_ssh_opts *opts, ssh_message msg, struct nc_auth_state *auth_state)
{
    const char *str_type, *str_subtype = NULL;
    int subtype, type, rc, local_users_supported;
    const struct ly_ctx *ctx;
    struct lys_module *mod;

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
        } else if (!auth_state || !opts) {
            /* these two parameters should always be set during an authentication,
             * however do a check just in case something goes really wrong, since they
             * are not needed for other types of messages
             */
            ERRINT;
            return 1;
        }

        /* get libyang ctx from session and ietf-ssh-server yang model from the ctx */
        ctx = nc_session_get_ctx(session);
        mod = ly_ctx_get_module_latest(ctx, "ietf-ssh-server");
        if (!mod) {
            ERRINT;
            return 1;
        }

        /* check if local-users-supported feature is enabled */
        rc = lys_feature_value(mod, "local-users-supported");
        if (!rc) {
            /* using users from the YANG data */
            local_users_supported = 1;
        } else if (rc == LY_ENOT) {
            /* using users from the system */
            local_users_supported = 0;
        } else {
            ERRINT;
            return 1;
        }

        /* authenticate */
        return nc_server_ssh_auth(session, opts, msg, subtype, str_subtype, local_users_supported, auth_state);
    } else if (session->flags & NC_SESSION_SSH_AUTHENTICATED) {
        if ((type == SSH_REQUEST_CHANNEL_OPEN) && ((enum ssh_channel_type_e)subtype == SSH_CHANNEL_SESSION)) {
            if (nc_server_ssh_channel_open(session, msg)) {
                ssh_message_reply_default(msg);
            }
            return 0;

        } else if ((type == SSH_REQUEST_CHANNEL) && ((enum ssh_channel_requests_e)subtype == SSH_CHANNEL_REQUEST_SUBSYSTEM)) {
            if (nc_server_ssh_channel_subsystem(session, ssh_message_channel_request_channel(msg),
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
        nc_timeouttime_get(&ts_timeout, timeout * 1000);
    }
    while (1) {
        if (!nc_session_is_connected(session)) {
            ERR(session, "Communication SSH socket unexpectedly closed.");
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
        if (timeout && (nc_timeouttime_cur_diff(&ts_timeout) < 1)) {
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
    char *privkey_path;
    int ret;
    struct nc_asymmetric_key *key = NULL;

    for (i = 0; i < hostkey_count; ++i) {
        privkey_path = NULL;

        /* get the asymmetric key */
        if (opts->hostkeys[i].store == NC_STORE_LOCAL) {
            /* stored locally */
            key = &opts->hostkeys[i].key;
        } else {
            /* keystore reference, need to get it */
            if (nc_server_ssh_ks_ref_get_key(opts->hostkeys[i].ks_ref, &key)) {
                return -1;
            }
        }

        privkey_path = nc_server_ssh_privkey_data_to_tmp_file(key->privkey_data, nc_privkey_format_to_str(key->privkey_type));
        if (!privkey_path) {
            ERR(NULL, "Temporarily storing a host key into a file failed (%s).", strerror(errno));
            return -1;
        }

        ret = ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HOSTKEY, privkey_path);

        /* cleanup */
        if (unlink(privkey_path)) {
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
    struct nc_auth_state auth_state = {0};

    /* authenticate */
    if (opts->auth_timeout) {
        nc_timeouttime_get(&ts_timeout, opts->auth_timeout * 1000);
    }
    while (1) {
        if (!nc_session_is_connected(session)) {
            ERR(session, "Communication SSH socket unexpectedly closed.");
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
    const char *err_msg;

    /* other transport-specific data */
    session->ti_type = NC_TI_SSH;
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
    if (opts->hostkey_algs && ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS, opts->hostkey_algs)) {
        rc = -1;
        goto cleanup;
    }
    if (opts->encryption_algs && ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_CIPHERS_S_C, opts->encryption_algs)) {
        rc = -1;
        goto cleanup;
    }
    if (opts->kex_algs && ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_KEY_EXCHANGE, opts->kex_algs)) {
        rc = -1;
        goto cleanup;
    }
    if (opts->mac_algs && ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HMAC_S_C, opts->mac_algs)) {
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
        nc_timeouttime_get(&ts_timeout, timeout);
    }
    while ((r = ssh_handle_key_exchange(session->ti.libssh.session)) == SSH_AGAIN) {
        /* this tends to take longer */
        usleep(NC_TIMEOUT_STEP * 20);
        if ((timeout > -1) && (nc_timeouttime_cur_diff(&ts_timeout) < 1)) {
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
    if (rc != 1) {
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
