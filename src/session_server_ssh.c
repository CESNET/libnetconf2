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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <security/pam_appl.h>
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
base64der_key_to_tmp_file(const char *in, const char *key_str)
{
    char path[12] = "/tmp/XXXXXX";
    int fd, written;
    mode_t umode;
    FILE *file;

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
        written += fwrite(" PRIVATE KEY-----\n", 1, 18, file);
        written += fwrite(in, 1, strlen(in), file);
        written += fwrite("\n-----END ", 1, 10, file);
        written += fwrite(key_str, 1, strlen(key_str), file);
        written += fwrite(" PRIVATE KEY-----", 1, 17, file);

        fclose(file);
        if ((unsigned)written != 11 + strlen(key_str) + 18 + strlen(in) + 10 + strlen(key_str) + 17) {
            unlink(path);
            return NULL;
        }
    } else {
        written = fwrite("-----BEGIN PRIVATE KEY-----\n", 1, 28, file);
        written += fwrite(in, 1, strlen(in), file);
        written += fwrite("\n-----END PRIVATE KEY-----", 1, 26, file);

        fclose(file);
        if ((unsigned)written != 28 + strlen(in) + 26) {
            unlink(path);
            return NULL;
        }
    }

    return strdup(path);
}

static int
nc_server_ssh_add_hostkey(const char *name, int16_t idx, struct nc_server_ssh_opts *opts)
{
    uint8_t i;

    if (!name) {
        ERRARG("name");
        return -1;
    } else if (idx > opts->hostkey_count) {
        ERRARG("idx");
        return -1;
    }

    for (i = 0; i < opts->hostkey_count; ++i) {
        if (!strcmp(opts->hostkeys[i], name)) {
            ERRARG("name");
            return -1;
        }
    }

    ++opts->hostkey_count;
    opts->hostkeys = nc_realloc(opts->hostkeys, opts->hostkey_count * sizeof *opts->hostkeys);
    if (!opts->hostkeys) {
        ERRMEM;
        return -1;
    }

    if (idx < 0) {
        idx = opts->hostkey_count - 1;
    }
    if (idx != opts->hostkey_count - 1) {
        memmove(opts->hostkeys + idx + 1, opts->hostkeys + idx, opts->hostkey_count - idx);
    }
    opts->hostkeys[idx] = strdup(name);

    return 0;
}

API int
nc_server_ssh_endpt_add_hostkey(const char *endpt_name, const char *name, int16_t idx)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_LIBSSH, NULL);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_add_hostkey(name, idx, endpt->opts.ssh);

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
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

API int
nc_server_ssh_set_pam_conf_path(const char *conf_name, const char *conf_dir)
{
    free(server_opts.conf_name);
    free(server_opts.conf_dir);
    server_opts.conf_name = NULL;
    server_opts.conf_dir = NULL;

    if (conf_dir) {
#ifdef LIBPAM_HAVE_CONFDIR
        server_opts.conf_dir = strdup(conf_dir);
        if (!(server_opts.conf_dir)) {
            ERRMEM;
            return -1;
        }
#else
        ERR(NULL, "Failed to set PAM config directory because of old version of PAM. "
                "Put the config file in the system directory (usually /etc/pam.d/).");
        return -1;
#endif
    }

    if (conf_name) {
        server_opts.conf_name = strdup(conf_name);
        if (!(server_opts.conf_name)) {
            ERRMEM;
            return -1;
        }
    }

    return 0;
}

API void
nc_server_ssh_set_pubkey_auth_clb(int (*pubkey_auth_clb)(const struct nc_session *session, ssh_key key, void *user_data),
        void *user_data, void (*free_user_data)(void *user_data))
{
    server_opts.pubkey_auth_clb = pubkey_auth_clb;
    server_opts.pubkey_auth_data = user_data;
    server_opts.pubkey_auth_data_free = free_user_data;
}

API int
nc_server_ssh_ch_client_endpt_add_hostkey(const char *client_name, const char *endpt_name, const char *name, int16_t idx)
{
    int ret;
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, NC_TI_LIBSSH, &client);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_add_hostkey(name, idx, endpt->opts.ssh);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

API void
nc_server_ssh_set_hostkey_clb(int (*hostkey_clb)(const char *name, void *user_data, char **privkey_path,
        char **privkey_data, NC_SSH_KEY_TYPE *privkey_type), void *user_data, void (*free_user_data)(void *user_data))
{
    if (!hostkey_clb) {
        ERRARG("hostkey_clb");
        return;
    }

    server_opts.hostkey_clb = hostkey_clb;
    server_opts.hostkey_data = user_data;
    server_opts.hostkey_data_free = free_user_data;
}

static int
nc_server_ssh_del_hostkey(const char *name, int16_t idx, struct nc_server_ssh_opts *opts)
{
    uint8_t i;

    if (name && (idx > -1)) {
        ERRARG("name and idx");
        return -1;
    } else if (idx >= opts->hostkey_count) {
        ERRARG("idx");
    }

    if (!name && (idx < 0)) {
        for (i = 0; i < opts->hostkey_count; ++i) {
            free(opts->hostkeys[i]);
        }
        free(opts->hostkeys);
        opts->hostkeys = NULL;
        opts->hostkey_count = 0;
    } else if (name) {
        for (i = 0; i < opts->hostkey_count; ++i) {
            if (!strcmp(opts->hostkeys[i], name)) {
                idx = i;
                goto remove_idx;
            }
        }

        ERRARG("name");
        return -1;
    } else {
remove_idx:
        --opts->hostkey_count;
        free(opts->hostkeys[idx]);
        if (idx < opts->hostkey_count - 1) {
            memmove(opts->hostkeys + idx, opts->hostkeys + idx + 1, (opts->hostkey_count - idx) * sizeof *opts->hostkeys);
        }
        if (!opts->hostkey_count) {
            free(opts->hostkeys);
            opts->hostkeys = NULL;
        }
    }

    return 0;
}

API int
nc_server_ssh_endpt_del_hostkey(const char *endpt_name, const char *name, int16_t idx)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_LIBSSH, NULL);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_del_hostkey(name, idx, endpt->opts.ssh);

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_ssh_ch_client_endpt_del_hostkey(const char *client_name, const char *endpt_name, const char *name, int16_t idx)
{
    int ret;
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, NC_TI_LIBSSH, &client);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_del_hostkey(name, idx, endpt->opts.ssh);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static int
nc_server_ssh_mov_hostkey(const char *key_mov, const char *key_after, struct nc_server_ssh_opts *opts)
{
    uint8_t i;
    int16_t mov_idx = -1, after_idx = -1;
    char *bckup;

    if (!key_mov) {
        ERRARG("key_mov");
        return -1;
    }

    for (i = 0; i < opts->hostkey_count; ++i) {
        if (key_after && (after_idx == -1) && !strcmp(opts->hostkeys[i], key_after)) {
            after_idx = i;
        }
        if ((mov_idx == -1) && !strcmp(opts->hostkeys[i], key_mov)) {
            mov_idx = i;
        }

        if ((!key_after || (after_idx > -1)) && (mov_idx > -1)) {
            break;
        }
    }

    if (key_after && (after_idx == -1)) {
        ERRARG("key_after");
        return -1;
    }
    if (mov_idx == -1) {
        ERRARG("key_mov");
        return -1;
    }
    if ((mov_idx == after_idx) || (mov_idx == after_idx + 1)) {
        /* nothing to do */
        return 0;
    }

    /* finally move the key */
    bckup = opts->hostkeys[mov_idx];
    if (mov_idx > after_idx) {
        memmove(opts->hostkeys + after_idx + 2, opts->hostkeys + after_idx + 1,
                ((mov_idx - after_idx) - 1) * sizeof *opts->hostkeys);
        opts->hostkeys[after_idx + 1] = bckup;
    } else {
        memmove(opts->hostkeys + mov_idx, opts->hostkeys + mov_idx + 1, (after_idx - mov_idx) * sizeof *opts->hostkeys);
        opts->hostkeys[after_idx] = bckup;
    }

    return 0;
}

API int
nc_server_ssh_endpt_mov_hostkey(const char *endpt_name, const char *key_mov, const char *key_after)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_LIBSSH, NULL);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_mov_hostkey(key_mov, key_after, endpt->opts.ssh);

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_ssh_ch_client_endpt_mov_hostkey(const char *client_name, const char *endpt_name, const char *key_mov,
        const char *key_after)
{
    int ret;
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, NC_TI_LIBSSH, &client);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_mov_hostkey(key_mov, key_after, endpt->opts.ssh);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static int
nc_server_ssh_set_auth_methods(int auth_methods, struct nc_server_ssh_opts *opts)
{
    if ((auth_methods & NC_SSH_AUTH_INTERACTIVE) && !server_opts.conf_name) {
        /* path to a configuration file not set */
        ERR(NULL, "Unable to use Keyboard-Interactive authentication method without setting the name of the PAM configuration file first.");
        return 1;
    }
    opts->auth_methods = auth_methods;
    return 0;
}

API int
nc_server_ssh_endpt_set_auth_methods(const char *endpt_name, int auth_methods)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_LIBSSH, NULL);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_set_auth_methods(auth_methods, endpt->opts.ssh);

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_ssh_ch_client_endpt_set_auth_methods(const char *client_name, const char *endpt_name, int auth_methods)
{
    int ret;
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, NC_TI_LIBSSH, &client);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_set_auth_methods(auth_methods, endpt->opts.ssh);

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

API int
nc_server_ssh_endpt_get_auth_methods(const char *endpt_name)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_LIBSSH, NULL);
    if (!endpt) {
        return -1;
    }

    ret = endpt->opts.ssh->auth_methods;

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_ssh_ch_client_endpt_get_auth_methods(const char *client_name, const char *endpt_name)
{
    int ret;
    struct nc_ch_client *client;
    struct nc_ch_endpt *endpt;

    /* LOCK */
    endpt = nc_server_ch_client_lock(client_name, endpt_name, NC_TI_LIBSSH, &client);
    if (!endpt) {
        return -1;
    }

    ret = endpt->opts.ssh->auth_methods;

    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
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
nc_server_ssh_endpt_set_auth_attempts(const char *endpt_name, uint16_t auth_attempts)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_LIBSSH, NULL);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_set_auth_attempts(auth_attempts, endpt->opts.ssh);

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
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
nc_server_ssh_endpt_set_auth_timeout(const char *endpt_name, uint16_t auth_timeout)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_LIBSSH, NULL);
    if (!endpt) {
        return -1;
    }

    ret = nc_server_ssh_set_auth_timeout(auth_timeout, endpt->opts.ssh);

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
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

static int
_nc_server_ssh_add_authkey(const char *pubkey_path, const char *pubkey_base64, NC_SSH_KEY_TYPE type, const char *username)
{
    int ret = 0;

    /* LOCK */
    pthread_mutex_lock(&server_opts.authkey_lock);

    ++server_opts.authkey_count;
    server_opts.authkeys = nc_realloc(server_opts.authkeys, server_opts.authkey_count * sizeof *server_opts.authkeys);
    if (!server_opts.authkeys) {
        ERRMEM;
        ret = -1;
        goto cleanup;
    }
    server_opts.authkeys[server_opts.authkey_count - 1].path = pubkey_path ? strdup(pubkey_path) : NULL;
    server_opts.authkeys[server_opts.authkey_count - 1].base64 = pubkey_base64 ? strdup(pubkey_base64) : NULL;
    server_opts.authkeys[server_opts.authkey_count - 1].type = type;
    server_opts.authkeys[server_opts.authkey_count - 1].username = strdup(username);

cleanup:
    /* UNLOCK */
    pthread_mutex_unlock(&server_opts.authkey_lock);
    return ret;
}

API int
nc_server_ssh_add_authkey_path(const char *pubkey_path, const char *username)
{
    if (!pubkey_path) {
        ERRARG("pubkey_path");
        return -1;
    } else if (!username) {
        ERRARG("username");
        return -1;
    }

    return _nc_server_ssh_add_authkey(pubkey_path, NULL, 0, username);
}

API int
nc_server_ssh_add_authkey(const char *pubkey_base64, NC_SSH_KEY_TYPE type, const char *username)
{
    if (!pubkey_base64) {
        ERRARG("pubkey_base64");
        return -1;
    } else if (!type) {
        ERRARG("type");
        return -1;
    } else if (!username) {
        ERRARG("username");
        return -1;
    }

    return _nc_server_ssh_add_authkey(NULL, pubkey_base64, type, username);
}

API int
nc_server_ssh_del_authkey(const char *pubkey_path, const char *pubkey_base64, NC_SSH_KEY_TYPE type,
        const char *username)
{
    uint32_t i;
    int ret = -1;

    /* LOCK */
    pthread_mutex_lock(&server_opts.authkey_lock);

    if (!pubkey_path && !pubkey_base64 && !type && !username) {
        for (i = 0; i < server_opts.authkey_count; ++i) {
            free(server_opts.authkeys[i].path);
            free(server_opts.authkeys[i].base64);
            free(server_opts.authkeys[i].username);

            ret = 0;
        }
        free(server_opts.authkeys);
        server_opts.authkeys = NULL;
        server_opts.authkey_count = 0;
    } else {
        for (i = 0; i < server_opts.authkey_count; ++i) {
            if ((!pubkey_path || !strcmp(server_opts.authkeys[i].path, pubkey_path)) &&
                    (!pubkey_base64 || !strcmp(server_opts.authkeys[i].base64, pubkey_base64)) &&
                    (!type || (server_opts.authkeys[i].type == type)) &&
                    (!username || !strcmp(server_opts.authkeys[i].username, username))) {
                free(server_opts.authkeys[i].path);
                free(server_opts.authkeys[i].base64);
                free(server_opts.authkeys[i].username);

                --server_opts.authkey_count;
                if (i < server_opts.authkey_count) {
                    memcpy(&server_opts.authkeys[i], &server_opts.authkeys[server_opts.authkey_count],
                            sizeof *server_opts.authkeys);
                } else if (!server_opts.authkey_count) {
                    free(server_opts.authkeys);
                    server_opts.authkeys = NULL;
                }

                ret = 0;
            }
        }
    }

    /* UNLOCK */
    pthread_mutex_unlock(&server_opts.authkey_lock);

    return ret;
}

void
nc_server_ssh_clear_opts(struct nc_server_ssh_opts *opts)
{
    nc_server_ssh_del_hostkey(NULL, -1, opts);
}

/**
 * @brief SSH channel callback for subsystem request.
 */
static int
nc_sshcb_channel_subsystem(ssh_session UNUSED(session), ssh_channel channel, const char *subsystem, void *userdata)
{
    struct nc_session *nc_sess = userdata;

    assert(nc_sess->ti.libssh.channel == channel);

    if (strcmp(subsystem, "netconf")) {
        WRN(nc_sess, "Received an unknown subsystem \"%s\" request.", subsystem);
        return SSH_ERROR;
    }

    if (nc_sess->status != NC_STATUS_STARTING) {
        ERRINT;
        return SSH_ERROR;
    }
    if (nc_sess->flags & NC_SESSION_SSH_SUBSYS_NETCONF) {
        ERR(nc_sess, "Subsystem \"netconf\" already requested.");
        return SSH_ERROR;
    }

    nc_sess->flags |= NC_SESSION_SSH_SUBSYS_NETCONF;

    return SSH_OK;
}

/**
 * @brief Create an SSH channel and set SSH channel callbacks for a NC session.
 *
 * @param[in] session NC session to use.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
nc_session_ssh_channel_new(struct nc_session *session)
{
    assert(!session->ti.libssh.channel);

    /* SSH channel */
    session->ti.libssh.channel = ssh_channel_new(session->ti.libssh.shared->session);
    if (!session->ti.libssh.channel) {
        ERR(session, "Failed to create a new SSH channel.");
        return -1;
    }

    /* set the SSH channel callbacks */
    session->ti.libssh.channel_cb = calloc(1, sizeof *session->ti.libssh.channel_cb);
    if (!session->ti.libssh.channel_cb) {
        ERRMEM;
        return -1;
    }
    session->ti.libssh.channel_cb->userdata = session;
    session->ti.libssh.channel_cb->channel_subsystem_request_function = nc_sshcb_channel_subsystem;

    ssh_callbacks_init(session->ti.libssh.channel_cb);
    ssh_set_channel_callbacks(session->ti.libssh.channel, session->ti.libssh.channel_cb);

    return 0;
}

#ifdef HAVE_SHADOW

/**
 * @brief Get passwd entry for a user.
 *
 * @param[in] username Name of the user.
 * @param[in] pwd_buf Passwd entry buffer.
 * @param[in,out] buf Passwd entry string buffer.
 * @param[in,out] buf_size Current @p buf size.
 * @return Found passwd entry for the user, NULL if none found.
 */
static struct passwd *
auth_password_getpwnam(const char *username, struct passwd *pwd_buf, char **buf, size_t *buf_size)
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
 * @brief Get shadow entry for a user.
 *
 * @param[in] username Name of the user.
 * @param[in] spwd_buf Shadow entry buffer.
 * @param[in,out] buf Shadow entry string buffer.
 * @param[in,out] buf_size Current @p buf size.
 * @return Found shadow entry for the user, NULL if none found.
 */
static struct spwd *
auth_password_getspnam(const char *username, struct spwd *spwd_buf, char **buf, size_t *buf_size)
{
    struct spwd *spwd = NULL;
    char *mem;
    int r = 0;

    do {
# ifndef __QNXNTO__
        r = getspnam_r(username, spwd_buf, *buf, *buf_size, &spwd);
# else
        spwd = getspnam_r(username, spwd_buf, *buf, *buf_size);
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
 * @brief Get hashed system apssword for a user.
 *
 * @param[in] username Name of the user.
 * @return Hashed password of @p username.
 */
static char *
auth_password_get_pwd_hash(const char *username)
{
    struct passwd *pwd, pwd_buf;
    struct spwd *spwd, spwd_buf;
    char *pass_hash = NULL, *buf = NULL;
    size_t buf_size = 256;

    buf = malloc(buf_size);
    if (!buf) {
        ERRMEM;
        goto error;
    }

    pwd = auth_password_getpwnam(username, &pwd_buf, &buf, &buf_size);
    if (!pwd) {
        VRB(NULL, "User \"%s\" not found locally.", username);
        goto error;
    }

    if (!strcmp(pwd->pw_passwd, "x")) {
        spwd = auth_password_getspnam(username, &spwd_buf, &buf, &buf_size);
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

#else

/**
 * @brief Get hashed system password for a user.
 *
 * @param[in] username Name of the user.
 * @return Hashed password of @p username.
 */
static char *
auth_password_get_pwd_hash(const char *username)
{
    (void)username;
    return strdup("");
}

#endif

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

/**
 * @brief SSH server callback for 'password' authentication.
 */
static int
nc_sshcb_auth_password(ssh_session UNUSED(session), const char *user, const char *pass, void *userdata)
{
    struct nc_session *nc_sess = userdata;
    char *pass_hash;
    int auth_ret = 1;

    if (!nc_sess->username) {
        nc_sess->username = strdup(user);
        if (!nc_sess->username) {
            ERRMEM;
            return SSH_AUTH_ERROR;
        }
    } else if (strcmp(user, nc_sess->username)) {
        ERR(nc_sess, "User \"%s\" changed its username to \"%s\".", nc_sess->username, user);
        return SSH_AUTH_DENIED;
    }

    if (server_opts.passwd_auth_clb) {
        auth_ret = server_opts.passwd_auth_clb(nc_sess, pass, server_opts.passwd_auth_data);
    } else {
        pass_hash = auth_password_get_pwd_hash(user);
        if (pass_hash) {
            auth_ret = auth_password_compare_pwd(pass_hash, pass);
            free(pass_hash);
        }
    }

    if (!auth_ret) {
        VRB(nc_sess, "User \"%s\" authenticated.", user);
        nc_sess->flags |= NC_SESSION_SSH_AUTHENTICATED;
        return SSH_AUTH_SUCCESS;
    } else {
        VRB(nc_sess, "Failed user \"%s\" authentication attempt (#%d).", user, nc_sess->opts.server.ssh_auth_attempts);
        ++nc_sess->opts.server.ssh_auth_attempts;
        return SSH_AUTH_DENIED;
    }
}

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

    libssh_session = clb_data->session->ti.libssh.shared->session;
    opts = clb_data->session->data;

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
nc_pam_auth(struct nc_session *session, ssh_message ssh_msg)
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

    /* initialize PAM and see if the given configuration file exists */
#ifdef LIBPAM_HAVE_CONFDIR
    /* PAM version >= 1.4 */
    ret = pam_start_confdir(server_opts.conf_name, session->username, &conv, server_opts.conf_dir, &pam_h);
#else
    /* PAM version < 1.4 */
    ret = pam_start(server_opts.conf_name, session->username, &conv, &pam_h);
#endif
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

static void
nc_sshcb_auth_kbdint(struct nc_session *session, ssh_message msg)
{
    int auth_ret = 1;

    /*if (!nc_sess->username) {
        nc_sess->username = strdup(user);
        if (!nc_sess->username) {
            ERRMEM;
            return SSH_AUTH_ERROR;
        }
    } else if (strcmp(user, nc_sess->username)) {
        ERR(nc_sess, "User \"%s\" changed its username to \"%s\".", nc_sess->username, user);
        return SSH_AUTH_DENIED;
    }*/

    if (server_opts.interactive_auth_clb) {
        auth_ret = server_opts.interactive_auth_clb(session, msg, server_opts.interactive_auth_data);
    } else if (nc_pam_auth(session, msg) == PAM_SUCCESS) {
        auth_ret = 0;
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

/**
 * @brief Compare SSH key with configured authorized keys and return the username of the matching one, if any.
 *
 * @param[in] key Presented SSH key to compare.
 * @return Authorized key username, NULL if no match was found.
 */
static const char *
auth_pubkey_compare_key(ssh_key key)
{
    uint32_t i;
    ssh_key pub_key;
    const char *username = NULL;
    int ret = 0;

    /* LOCK */
    pthread_mutex_lock(&server_opts.authkey_lock);

    for (i = 0; i < server_opts.authkey_count; ++i) {
        switch (server_opts.authkeys[i].type) {
        case NC_SSH_KEY_UNKNOWN:
            ret = ssh_pki_import_pubkey_file(server_opts.authkeys[i].path, &pub_key);
            break;
        case NC_SSH_KEY_DSA:
            ret = ssh_pki_import_pubkey_base64(server_opts.authkeys[i].base64, SSH_KEYTYPE_DSS, &pub_key);
            break;
        case NC_SSH_KEY_RSA:
            ret = ssh_pki_import_pubkey_base64(server_opts.authkeys[i].base64, SSH_KEYTYPE_RSA, &pub_key);
            break;
        case NC_SSH_KEY_ECDSA:
            ret = ssh_pki_import_pubkey_base64(server_opts.authkeys[i].base64, SSH_KEYTYPE_ECDSA, &pub_key);
            break;
        }

        if (ret == SSH_EOF) {
            WRN(NULL, "Failed to import a public key of \"%s\" (File access problem).", server_opts.authkeys[i].username);
            continue;
        } else if (ret == SSH_ERROR) {
            WRN(NULL, "Failed to import a public key of \"%s\" (SSH error).", server_opts.authkeys[i].username);
            continue;
        }

        if (!ssh_key_cmp(key, pub_key, SSH_KEY_CMP_PUBLIC)) {
            ssh_key_free(pub_key);
            break;
        }

        ssh_key_free(pub_key);
    }

    if (i < server_opts.authkey_count) {
        username = server_opts.authkeys[i].username;
    }

    /* UNLOCK */
    pthread_mutex_unlock(&server_opts.authkey_lock);

    return username;
}

/**
 * @brief SSH server callback for 'publickey' authentication.
 */
static int
nc_sshcb_auth_pubkey(ssh_session UNUSED(session), const char *user, struct ssh_key_struct *pubkey, char signature_state,
        void *userdata)
{
    struct nc_session *nc_sess = userdata;
    const char *key_user;

    if (!nc_sess->username) {
        nc_sess->username = strdup(user);
        if (!nc_sess->username) {
            ERRMEM;
            return SSH_AUTH_ERROR;
        }
    } else if (strcmp(user, nc_sess->username)) {
        ERR(nc_sess, "User \"%s\" changed its username to \"%s\".", nc_sess->username, user);
        return SSH_AUTH_DENIED;
    }

    if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
        /* accepting only the use of a public key */
        return SSH_AUTH_SUCCESS;
    }
    if (signature_state != SSH_PUBLICKEY_STATE_VALID) {
        /* invalid key */
        return SSH_AUTH_DENIED;
    }

    if (server_opts.pubkey_auth_clb) {
        if (server_opts.pubkey_auth_clb(nc_sess, pubkey, server_opts.pubkey_auth_data)) {
            goto fail;
        }
    } else {
        if ((key_user = auth_pubkey_compare_key(pubkey)) == NULL) {
            VRB(nc_sess, "User \"%s\" tried to use an unknown (unauthorized) public key.", user);
            goto fail;
        } else if (strcmp(user, key_user)) {
            VRB(nc_sess, "User \"%s\" is not the username identified with the presented public key.", user);
            goto fail;
        }
    }

    VRB(nc_sess, "User \"%s\" authenticated.", user);
    nc_sess->flags |= NC_SESSION_SSH_AUTHENTICATED;
    return SSH_AUTH_SUCCESS;

fail:
    ++nc_sess->opts.server.ssh_auth_attempts;
    VRB(nc_sess, "Failed user \"%s\" authentication attempt (#%d).", user, nc_sess->opts.server.ssh_auth_attempts);
    return SSH_AUTH_DENIED;
}

/**
 * @brief SSH server callback for channel open.
 */
static ssh_channel
nc_sshcb_channel_open(ssh_session UNUSED(session), void *userdata)
{
    struct nc_session *nc_sess = userdata, *nc_sess2;

    if (!(nc_sess->flags & NC_SESSION_SSH_AUTHENTICATED)) {
        /* not authenticated yet */
        ERR(nc_sess, "Not authenticated yet, cannot open a new SSH channel.");
        return NULL;
    }

    if (nc_sess->ti.libssh.channel) {
        /* create the new NC session structure on this SSH session */
        nc_sess2 = nc_new_session(NC_SERVER, 1);
        if (!nc_sess2) {
            ERRMEM;
            return NULL;
        }

        /* insert the new session */
        if (!nc_sess->ti.libssh.next) {
            nc_sess2->ti.libssh.next = nc_sess;
        } else {
            nc_sess2->ti.libssh.next = nc_sess->ti.libssh.next;
        }
        nc_sess->ti.libssh.next = nc_sess2;

        /* init */
        nc_sess2->status = NC_STATUS_STARTING;
        nc_sess2->ti_type = NC_TI_LIBSSH;
        nc_sess2->io_lock = nc_sess->io_lock;

        nc_sess2->ti.libssh.shared = nc_sess->ti.libssh.shared;
        nc_sess2->username = strdup(nc_sess->username);
        nc_sess2->host = strdup(nc_sess->host);
        if (!nc_sess2->username || !nc_sess2->host) {
            ERRMEM;
            return NULL;
        }
        nc_sess2->port = nc_sess->port;
        nc_sess2->ctx = (struct ly_ctx *)nc_sess->ctx;
        nc_sess2->flags = NC_SESSION_SSH_AUTHENTICATED | NC_SESSION_SHAREDCTX;

        nc_sess = nc_sess2;
    }

    if (nc_session_ssh_channel_new(nc_sess)) {
        return NULL;
    }

    return nc_sess->ti.libssh.channel;
}

int
nc_session_ssh_shared_new(struct nc_session *session, ssh_session ssh_session, int use_event)
{
    struct nc_session_libssh_shared *shared;

    /* shared */
    shared = calloc(1, sizeof *shared);
    if (!shared) {
        ERRMEM;
        return -1;
    }
    session->ti.libssh.shared = shared;

    /* SSH session */
    if (ssh_session) {
        shared->session = ssh_session;
    } else {
        shared->session = ssh_new();
        if (!shared->session) {
            ERR(NULL, "Failed to initialize a new SSH session.");
            return -1;
        }
    }

    if (use_event) {
        /* SSH server callbacks */
        shared->server_cb = calloc(1, sizeof *shared->server_cb);
        if (!shared->server_cb) {
            ERRMEM;
            return -1;
        }
        shared->server_cb->userdata = session;
        shared->server_cb->auth_password_function = nc_sshcb_auth_password;
        shared->server_cb->auth_pubkey_function = nc_sshcb_auth_pubkey;
        shared->server_cb->channel_open_request_session_function = nc_sshcb_channel_open;

        ssh_callbacks_init(shared->server_cb);
        ssh_set_server_callbacks(shared->session, shared->server_cb);

        /* SSH event */
        shared->event = ssh_event_new();
        if (!shared->event) {
            ERR(NULL, "Failed to initialize a new SSH event.");
            return -1;
        }
    }

    return 0;
}

/**
 * @brief When accepting a new NC session, handle SSH channel 'netconf' subsystem request.
 *
 * @param[in] session Starting NC session.
 * @param[in] abs_timeout Absolute timeout for the tasks.
 * @return 1 on success.
 * @return 0 on timeout.
 * @return -1 on error.
 */
static int
nc_accept_ssh_session_netconf_subsystem(struct nc_session *session, const struct timespec *abs_timeout)
{
    /* wait for subsystem request */
    while (!(session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
        if (!nc_session_is_connected(session)) {
            ERR(session, "Communication socket unexpectedly closed (libssh).");
            return -1;
        }

        if (ssh_event_dopoll(session->ti.libssh.shared->event, 1) == SSH_ERROR) {
            ERR(session, "SSH event poll failed (%s).", ssh_get_error(session->ti.libssh.shared->session));
            return -1;
        }

        if (!(session->flags & NC_SESSION_SSH_SUBSYS_NETCONF) && abs_timeout->tv_sec &&
                (nc_difftimespec_mono_cur(abs_timeout) < 1)) {
            /* new session timeout */
            break;
        }
    }

    if (!(session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
        ERR(session, "Failed to start \"netconf\" SSH subsystem for too long, disconnecting.");
        return 0;
    }

    return 1;
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
nc_ssh_bind_add_hostkeys(ssh_bind sbind, char **hostkeys, uint8_t hostkey_count)
{
    uint8_t i;
    char *privkey_path, *privkey_data;
    int ret;
    NC_SSH_KEY_TYPE privkey_type;

    if (!server_opts.hostkey_clb) {
        ERR(NULL, "Callback for retrieving SSH host keys not set.");
        return -1;
    }

    for (i = 0; i < hostkey_count; ++i) {
        privkey_path = privkey_data = NULL;
        if (server_opts.hostkey_clb(hostkeys[i], server_opts.hostkey_data, &privkey_path, &privkey_data, &privkey_type)) {
            ERR(NULL, "Host key callback failed.");
            return -1;
        }

        if (privkey_data) {
            privkey_path = base64der_key_to_tmp_file(privkey_data, nc_keytype2str(privkey_type));
            if (!privkey_path) {
                ERR(NULL, "Temporarily storing a host key into a file failed (%s).", strerror(errno));
                free(privkey_data);
                return -1;
            }
        }

        ret = ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HOSTKEY, privkey_path);

        /* cleanup */
        if (privkey_data && unlink(privkey_path)) {
            WRN(NULL, "Removing a temporary host key file \"%s\" failed (%s).", privkey_path, strerror(errno));
        }
        free(privkey_data);

        if (ret != SSH_OK) {
            ERR(NULL, "Failed to set hostkey \"%s\" (%s).", hostkeys[i], privkey_path);
        }
        free(privkey_path);

        if (ret != SSH_OK) {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief When accepting a new NC session, handle SSH authentication and channel open.
 *
 * @param[in] session Starting NC session.
 * @param[in] opts SSH server options.
 * @param[in] abs_timeout Absolute timeout for the tasks.
 * @return 1 on success.
 * @return 0 on timeout.
 * @return -1 on error.
 */
static int
nc_accept_ssh_session_auth_open_channel(struct nc_session *session, const struct nc_server_ssh_opts *opts,
        const struct timespec *abs_timeout)
{
    struct timespec auth_timeout = {0};
    int libssh_auth_methods = 0;

    /* configure accepted auth methods */
    if (opts->auth_methods & NC_SSH_AUTH_PUBLICKEY) {
        libssh_auth_methods |= SSH_AUTH_METHOD_PUBLICKEY;
    }
    if (opts->auth_methods & NC_SSH_AUTH_PASSWORD) {
        libssh_auth_methods |= SSH_AUTH_METHOD_PASSWORD;
    }
    if (opts->auth_methods & NC_SSH_AUTH_INTERACTIVE) {
        libssh_auth_methods |= SSH_AUTH_METHOD_INTERACTIVE;
    }
    ssh_set_auth_methods(session->ti.libssh.shared->session, libssh_auth_methods);

    /* authenticate */
    if (opts->auth_timeout) {
        nc_gettimespec_mono_add(&auth_timeout, opts->auth_timeout * 1000);
    }
    while (!(session->flags & NC_SESSION_SSH_AUTHENTICATED) || !session->ti.libssh.channel) {
        if (!nc_session_is_connected(session)) {
            ERR(session, "Communication SSH socket unexpectedly closed.");
            return -1;
        }

        if (ssh_event_dopoll(session->ti.libssh.shared->event, 1) == SSH_ERROR) {
            ERR(session, "SSH event poll failed (%s).", ssh_get_error(session->ti.libssh.shared->session));
            return -1;
        }

        if (!(session->flags & NC_SESSION_SSH_AUTHENTICATED)) {
            /* not authenticated yet */
            if (session->opts.server.ssh_auth_attempts >= opts->auth_attempts) {
                ERR(session, "Too many failed authentication attempts of user \"%s\".", session->username);
                return -1;
            }

            if (auth_timeout.tv_sec && (nc_difftimespec_mono_cur(&auth_timeout) < 1)) {
                /* authentication timeout */
                break;
            }
        } else if (!session->ti.libssh.channel) {
            /* SSH channel not opened yet */
            if (abs_timeout->tv_sec && (nc_difftimespec_mono_cur(abs_timeout) < 1)) {
                /* new session timeout */
                break;
            }
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
    } else if (!session->ti.libssh.channel) {
        ERR(session, "Failed to open an SSH channel for too long, disconnecting.");
        return 0;
    }

    return 1;
}

int
nc_accept_ssh_session(struct nc_session *session, int sock, int timeout)
{
    ssh_bind sbind = NULL;
    struct nc_server_ssh_opts *opts;
    int rc = 1, r;
    struct timespec ts_timeout = {0};

    assert(timeout);

    opts = session->data;

    /* other transport-specific data */
    session->ti_type = NC_TI_LIBSSH;
    if ((rc = nc_session_ssh_shared_new(session, NULL, 1))) {
        goto cleanup;
    }

    sbind = ssh_bind_new();
    if (!sbind) {
        ERR(session, "Failed to create an SSH bind.");
        rc = -1;
        goto cleanup;
    }

    /* configure host keys */
    if (nc_ssh_bind_add_hostkeys(sbind, opts->hostkeys, opts->hostkey_count)) {
        rc = -1;
        goto cleanup;
    }

    /* accept new connection on the bind */
    if (ssh_bind_accept_fd(sbind, session->ti.libssh.shared->session, sock) == SSH_ERROR) {
        ERR(session, "SSH failed to accept a new connection (%s).", ssh_get_error(sbind));
        rc = -1;
        goto cleanup;
    }
    sock = -1;

    /* non-blocking key exchange */
    ssh_set_blocking(session->ti.libssh.shared->session, 0);
    if (timeout > -1) {
        nc_gettimespec_mono_add(&ts_timeout, timeout);
    }
    while ((r = ssh_handle_key_exchange(session->ti.libssh.shared->session)) == SSH_AGAIN) {
        /* this tends to take longer */
        usleep(NC_TIMEOUT_STEP * 20);
        if (ts_timeout.tv_sec && (nc_difftimespec_mono_cur(&ts_timeout) < 1)) {
            break;
        }
    }
    if (r == SSH_AGAIN) {
        ERR(session, "SSH key exchange timeout.");
        rc = 0;
        goto cleanup;
    } else if (r != SSH_OK) {
        ERR(session, "SSH key exchange error (%s).", ssh_get_error(session->ti.libssh.shared->session));
        rc = -1;
        goto cleanup;
    }

    /* SSH session handled by an event */
    ssh_event_add_session(session->ti.libssh.shared->event, session->ti.libssh.shared->session);

    /* authenticate and open an SSH channel */
    if ((rc = nc_accept_ssh_session_auth_open_channel(session, opts, &ts_timeout)) != 1) {
        goto cleanup;
    }

    /* open channel and request 'netconf' subsystem */
    if ((rc = nc_accept_ssh_session_netconf_subsystem(session, &ts_timeout)) != 1) {
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
