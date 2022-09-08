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

#ifdef HAVE_SHADOW

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

static char *
auth_password_get_pwd_hash(const char *username)
{
    (void)username;
    return strdup("");
}

#endif

static int
auth_password_compare_pwd(const char *pass_hash, const char *pass_clear)
{
    char *new_pass_hash;

#if defined (HAVE_CRYPT_R)
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

#if defined (HAVE_CRYPT_R)
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
nc_sshcb_auth_password(struct nc_session *session, ssh_message msg)
{
    char *pass_hash;
    int auth_ret = 1;

    if (server_opts.passwd_auth_clb) {
        auth_ret = server_opts.passwd_auth_clb(session, ssh_message_auth_password(msg), server_opts.passwd_auth_data);
    } else {
        pass_hash = auth_password_get_pwd_hash(session->username);
        if (pass_hash) {
            auth_ret = auth_password_compare_pwd(pass_hash, ssh_message_auth_password(msg));
            free(pass_hash);
        }
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

static void
nc_sshcb_auth_pubkey(struct nc_session *session, ssh_message msg)
{
    const char *username;
    int signature_state;

    if (server_opts.pubkey_auth_clb) {
        if (server_opts.pubkey_auth_clb(session, ssh_message_auth_pubkey(msg), server_opts.pubkey_auth_data)) {
            goto fail;
        }
    } else {
        if ((username = auth_pubkey_compare_key(ssh_message_auth_pubkey(msg))) == NULL) {
            VRB(session, "User \"%s\" tried to use an unknown (unauthorized) public key.", session->username);
            goto fail;
        } else if (strcmp(session->username, username)) {
            VRB(session, "User \"%s\" is not the username identified with the presented public key.", session->username);
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
nc_sshcb_msg(ssh_session UNUSED(sshsession), ssh_message msg, void *data)
{
    const char *str_type, *str_subtype = NULL, *username;
    int subtype, type;
    struct nc_session *session = (struct nc_session *)data;

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
    session->flags |= NC_SESSION_SSH_NEW_MSG;

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
        if (!session->username) {
            if (!username) {
                ERR(session, "Denying an auth request without a username.");
                return 1;
            }

            session->username = strdup(username);
        } else if (username) {
            if (strcmp(username, session->username)) {
                ERR(session, "User \"%s\" changed its username to \"%s\".", session->username, username);
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_OTHER;
                return 1;
            }
        }

        if (subtype == SSH_AUTH_METHOD_NONE) {
            /* libssh will return the supported auth methods */
            return 1;
        } else if (subtype == SSH_AUTH_METHOD_PASSWORD) {
            nc_sshcb_auth_password(session, msg);
            return 0;
        } else if (subtype == SSH_AUTH_METHOD_PUBLICKEY) {
            nc_sshcb_auth_pubkey(session, msg);
            return 0;
        } else if (subtype == SSH_AUTH_METHOD_INTERACTIVE) {
            nc_sshcb_auth_kbdint(session, msg);
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
nc_accept_ssh_session_open_netconf_channel(struct nc_session *session, int timeout)
{
    int ret;
    struct timespec ts_timeout;

    /* message callback is executed twice to give chance for the channel to be
     * created if timeout == 0 (it takes 2 messages, channel-open, subsystem-request) */
    if (!timeout) {
        if (!nc_session_is_connected(session)) {
            ERR(session, "Communication socket unexpectedly closed (libssh).");
            return -1;
        }

        ret = ssh_execute_message_callbacks(session->ti.libssh.session);
        if (ret != SSH_OK) {
            ERR(session, "Failed to receive SSH messages on a session (%s).",
                    ssh_get_error(session->ti.libssh.session));
            return -1;
        }

        if (!session->ti.libssh.channel) {
            return 0;
        }

        ret = ssh_execute_message_callbacks(session->ti.libssh.session);
        if (ret != SSH_OK) {
            ERR(session, "Failed to receive SSH messages on a session (%s).",
                    ssh_get_error(session->ti.libssh.session));
            return -1;
        }

        if (!(session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
            /* we did not receive subsystem-request, timeout */
            return 0;
        }

        return 1;
    }

    if (timeout > -1) {
        nc_gettimespec_mono_add(&ts_timeout, timeout);
    }
    while (1) {
        if (!nc_session_is_connected(session)) {
            ERR(session, "Communication socket unexpectedly closed (libssh).");
            return -1;
        }

        ret = ssh_execute_message_callbacks(session->ti.libssh.session);
        if (ret != SSH_OK) {
            ERR(session, "Failed to receive SSH messages on a session (%s).",
                    ssh_get_error(session->ti.libssh.session));
            return -1;
        }

        if (session->ti.libssh.channel && (session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
            return 1;
        }

        usleep(NC_TIMEOUT_STEP);
        if ((timeout > -1) && (nc_difftimespec_mono_cur(&ts_timeout) < 1)) {
            /* timeout */
            ERR(session, "Failed to start \"netconf\" SSH subsystem for too long, disconnecting.");
            break;
        }
    }

    return 0;
}

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

static int
nc_accept_ssh_session_auth(struct nc_session *session, const struct nc_server_ssh_opts *opts)
{
    struct timespec ts_timeout;
    ssh_message msg;
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
    ssh_set_auth_methods(session->ti.libssh.session, libssh_auth_methods);

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
            if (nc_sshcb_msg(session->ti.libssh.session, msg, (void *) session)) {
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
nc_accept_ssh_session(struct nc_session *session, int sock, int timeout)
{
    ssh_bind sbind = NULL;
    struct nc_server_ssh_opts *opts;
    int rc = 1, r;
    struct timespec ts_timeout;

    opts = session->data;

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
    if (nc_ssh_bind_add_hostkeys(sbind, opts->hostkeys, opts->hostkey_count)) {
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

    /* set the message callback after a successful authentication */
    ssh_set_message_callback(session->ti.libssh.session, nc_sshcb_msg, session);

    /* remember that this session was just set as nc_sshcb_msg() parameter */
    session->flags |= NC_SESSION_SSH_MSG_CB;

    /* open channel and request 'netconf' subsystem */
    if ((rc = nc_accept_ssh_session_open_netconf_channel(session, timeout)) != 1) {
        goto cleanup;
    }

    /* all SSH messages were processed */
    session->flags &= ~NC_SESSION_SSH_NEW_MSG;

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
