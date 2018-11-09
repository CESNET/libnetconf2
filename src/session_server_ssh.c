/**
 * \file session_server_ssh.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 SSH server session manipulation functions
 *
 * Copyright (c) 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <errno.h>
#include <time.h>

#include "session_server.h"
#include "session_server_ch.h"
#include "libnetconf.h"

#if !defined(HAVE_CRYPT_R)
pthread_mutex_t crypt_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

extern struct nc_server_opts server_opts;

static char *
base64der_key_to_tmp_file(const char *in, int rsa)
{
    char path[12] = "/tmp/XXXXXX";
    int fd, written;
    mode_t umode;
    FILE *file;

    if (in == NULL) {
        return NULL;
    }

    umode = umask(0600);
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
    written = fwrite("-----BEGIN ", 1, 11, file);
    written += fwrite((rsa ? "RSA" : "DSA"), 1, 3, file);
    written += fwrite(" PRIVATE KEY-----\n", 1, 18, file);
    written += fwrite(in, 1, strlen(in), file);
    written += fwrite("\n-----END ", 1, 10, file);
    written += fwrite((rsa ? "RSA" : "DSA"), 1, 3, file);
    written += fwrite(" PRIVATE KEY-----", 1, 17, file);

    fclose(file);
    if ((unsigned)written != 62 + strlen(in)) {
        unlink(path);
        return NULL;
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
    opts->hostkeys[idx] = lydict_insert(server_opts.ctx, name, 0);

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

API void
nc_server_ssh_set_pubkey_auth_clb(int (*pubkey_auth_clb)(const struct nc_session *session, ssh_key key, void *user_data),
                                  void *user_data, void (*free_user_data)(void *user_data))
{
    server_opts.pubkey_auth_clb = pubkey_auth_clb;
    server_opts.pubkey_auth_data = user_data;
    server_opts.pubkey_auth_data_free = free_user_data;
}


API int
nc_server_ssh_ch_client_add_hostkey(const char *client_name, const char *name, int16_t idx)
{
    int ret;
    struct nc_ch_client *client;

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_LIBSSH, NULL);
    if (!client) {
        return -1;
    }
    ret = nc_server_ssh_add_hostkey(name, idx, client->opts.ssh);
    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

API void
nc_server_ssh_set_hostkey_clb(int (*hostkey_clb)(const char *name, void *user_data, char **privkey_path,
                                                 char **privkey_data, int *privkey_data_rsa),
                              void *user_data, void (*free_user_data)(void *user_data))
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
            lydict_remove(server_opts.ctx, opts->hostkeys[i]);
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
        lydict_remove(server_opts.ctx, opts->hostkeys[idx]);
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
nc_server_ssh_ch_client_del_hostkey(const char *client_name, const char *name, int16_t idx)
{
    int ret;
    struct nc_ch_client *client;

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_LIBSSH, NULL);
    if (!client) {
        return -1;
    }
    ret = nc_server_ssh_del_hostkey(name, idx, client->opts.ssh);
    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static int
nc_server_ssh_mov_hostkey(const char *key_mov, const char *key_after, struct nc_server_ssh_opts *opts)
{
    uint8_t i;
    int16_t mov_idx = -1, after_idx = -1;
    const char *bckup;

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
nc_server_ssh_ch_client_mov_hostkey(const char *client_name, const char *key_mov, const char *key_after)
{
    int ret;
    struct nc_ch_client *client;

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_LIBSSH, NULL);
    if (!client) {
        return -1;
    }
    ret = nc_server_ssh_mov_hostkey(key_mov, key_after, client->opts.ssh);
    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static int
nc_server_ssh_mod_hostkey(const char *name, const char *new_name, struct nc_server_ssh_opts *opts)
{
    uint8_t i;

    if (!name) {
        ERRARG("name");
        return -1;
    } else if (!new_name) {
        ERRARG("new_name");
        return -1;
    }

    for (i = 0; i < opts->hostkey_count; ++i) {
        if (!strcmp(opts->hostkeys[i], name)) {
            lydict_remove(server_opts.ctx, opts->hostkeys[i]);
            opts->hostkeys[i] = lydict_insert(server_opts.ctx, new_name, 0);
            return 0;
        }
    }

    ERRARG("name");
    return -1;
}

API int
nc_server_ssh_endpt_mod_hostkey(const char *endpt_name, const char *name, const char *new_name)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock_get(endpt_name, NC_TI_LIBSSH, NULL);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_ssh_mov_hostkey(name, new_name, endpt->opts.ssh);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.endpt_lock);

    return ret;
}

API int
nc_server_ssh_ch_client_mod_hostkey(const char *client_name, const char *name, const char *new_name)
{
    int ret;
    struct nc_ch_client *client;

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_LIBSSH, NULL);
    if (!client) {
        return -1;
    }
    ret = nc_server_ssh_mod_hostkey(name, new_name, client->opts.ssh);
    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static int
nc_server_ssh_set_auth_methods(int auth_methods, struct nc_server_ssh_opts *opts)
{
    if (!(auth_methods & NC_SSH_AUTH_PUBLICKEY) && !(auth_methods & NC_SSH_AUTH_PASSWORD)
            && !(auth_methods & NC_SSH_AUTH_INTERACTIVE)) {
        ERRARG("auth_methods");
        return -1;
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
nc_server_ssh_ch_client_set_auth_methods(const char *client_name, int auth_methods)
{
    int ret;
    struct nc_ch_client *client;

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_LIBSSH, NULL);
    if (!client) {
        return -1;
    }
    ret = nc_server_ssh_set_auth_methods(auth_methods, client->opts.ssh);
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
nc_server_ssh_set_ch_client_auth_attempts(const char *client_name, uint16_t auth_attempts)
{
    int ret;
    struct nc_ch_client *client;

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_LIBSSH, NULL);
    if (!client) {
        return -1;
    }
    ret = nc_server_ssh_set_auth_attempts(auth_attempts, client->opts.ssh);
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
nc_server_ssh_ch_client_set_auth_timeout(const char *client_name, uint16_t auth_timeout)
{
    int ret;
    struct nc_ch_client *client;

    /* LOCK */
    client = nc_server_ch_client_lock(client_name, NC_TI_LIBSSH, NULL);
    if (!client) {
        return -1;
    }
    ret = nc_server_ssh_set_auth_timeout(auth_timeout, client->opts.ssh);
    /* UNLOCK */
    nc_server_ch_client_unlock(client);

    return ret;
}

static int
_nc_server_ssh_add_authkey(const char *pubkey_path, const char *pubkey_base64, NC_SSH_KEY_TYPE type,
                          const char *username)
{
    /* LOCK */
    pthread_mutex_lock(&server_opts.authkey_lock);

    ++server_opts.authkey_count;
    server_opts.authkeys = nc_realloc(server_opts.authkeys, server_opts.authkey_count * sizeof *server_opts.authkeys);
    if (!server_opts.authkeys) {
        ERRMEM;
        return -1;
    }
    server_opts.authkeys[server_opts.authkey_count - 1].path = lydict_insert(server_opts.ctx, pubkey_path, 0);
    server_opts.authkeys[server_opts.authkey_count - 1].base64 = lydict_insert(server_opts.ctx, pubkey_base64, 0);
    server_opts.authkeys[server_opts.authkey_count - 1].type = type;
    server_opts.authkeys[server_opts.authkey_count - 1].username = lydict_insert(server_opts.ctx, username, 0);

    /* UNLOCK */
    pthread_mutex_unlock(&server_opts.authkey_lock);

    return 0;
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
            lydict_remove(server_opts.ctx, server_opts.authkeys[i].path);
            lydict_remove(server_opts.ctx, server_opts.authkeys[i].base64);
            lydict_remove(server_opts.ctx, server_opts.authkeys[i].username);

            ret = 0;
        }
        free(server_opts.authkeys);
        server_opts.authkeys = NULL;
        server_opts.authkey_count = 0;
    } else {
        for (i = 0; i < server_opts.authkey_count; ++i) {
            if ((!pubkey_path || !strcmp(server_opts.authkeys[i].path, pubkey_path))
                    && (!pubkey_base64 || strcmp(server_opts.authkeys[i].base64, pubkey_base64))
                    && (!type || (server_opts.authkeys[i].type == type))
                    && (!username || !strcmp(server_opts.authkeys[i].username, username))) {
                lydict_remove(server_opts.ctx, server_opts.authkeys[i].path);
                lydict_remove(server_opts.ctx, server_opts.authkeys[i].base64);
                lydict_remove(server_opts.ctx, server_opts.authkeys[i].username);

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

static char *
auth_password_get_pwd_hash(const char *username)
{
    struct passwd *pwd, pwd_buf;
    struct spwd *spwd, spwd_buf;
    char *pass_hash = NULL, buf[256];

    getpwnam_r(username, &pwd_buf, buf, 256, &pwd);
    if (!pwd) {
        VRB("User \"%s\" not found locally.", username);
        return NULL;
    }

    if (!strcmp(pwd->pw_passwd, "x")) {
        getspnam_r(username, &spwd_buf, buf, 256, &spwd);
        if (!spwd) {
            VRB("Failed to retrieve the shadow entry for \"%s\".", username);
            return NULL;
        }

        pass_hash = spwd->sp_pwdp;
    } else {
        pass_hash = pwd->pw_passwd;
    }

    if (!pass_hash) {
        ERR("No password could be retrieved for \"%s\".", username);
        return NULL;
    }

    /* check the hash structure for special meaning */
    if (!strcmp(pass_hash, "*") || !strcmp(pass_hash, "!")) {
        VRB("User \"%s\" is not allowed to authenticate using a password.", username);
        return NULL;
    }
    if (!strcmp(pass_hash, "*NP*")) {
        VRB("Retrieving password for \"%s\" from a NIS+ server not supported.", username);
        return NULL;
    }

    return strdup(pass_hash);
}

static int
auth_password_compare_pwd(const char *pass_hash, const char *pass_clear)
{
    char *new_pass_hash;
#if defined(HAVE_CRYPT_R)
    struct crypt_data cdata;
#endif

    if (!pass_hash[0]) {
        if (!pass_clear[0]) {
            WRN("User authentication successful with an empty password!");
            return 0;
        } else {
            /* the user did now know he does not need any password,
             * (which should not be used) so deny authentication */
            return 1;
        }
    }

#if defined(HAVE_CRYPT_R)
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
        VRB("User \"%s\" authenticated.", session->username);
        ssh_message_auth_reply_success(msg, 0);
    } else {
        ++session->opts.server.ssh_auth_attempts;
        VRB("Failed user \"%s\" authentication attempt (#%d).", session->username, session->opts.server.ssh_auth_attempts);
        ssh_message_reply_default(msg);
    }
}

static void
nc_sshcb_auth_kbdint(struct nc_session *session, ssh_message msg)
{
    int auth_ret = 1;
    char *pass_hash;

    if (server_opts.interactive_auth_clb) {
        auth_ret = server_opts.interactive_auth_clb(session, msg, server_opts.interactive_auth_data);
    } else {
        if (!ssh_message_auth_kbdint_is_response(msg)) {
            const char *prompts[] = {"Password: "};
            char echo[] = {0};

            ssh_message_auth_interactive_request(msg, "Interactive SSH Authentication", "Type your password:", 1, prompts, echo);
            auth_ret = -1;
        } else {
            if (ssh_userauth_kbdint_getnanswers(session->ti.libssh.session) != 1) {// failed session
                ssh_message_reply_default(msg);
                return;
            }
            pass_hash = auth_password_get_pwd_hash(session->username);// get hashed password
            if (pass_hash) {
                /* Normalize auth_password_compare_pwd result to 0 or 1 */
                auth_ret = !!auth_password_compare_pwd(pass_hash, ssh_userauth_kbdint_getanswer(session->ti.libssh.session, 0));
                free(pass_hash);// free hashed password
            }
        }
    }

    /* We have already sent a reply */
    if (auth_ret == -1) {
        return;
    }

    /* Authenticate message based on outcome */
    if (!auth_ret) {
        session->flags |= NC_SESSION_SSH_AUTHENTICATED;
        VRB("User \"%s\" authenticated.", session->username);
        ssh_message_auth_reply_success(msg, 0);
    } else {
        ++session->opts.server.ssh_auth_attempts;
        VRB("Failed user \"%s\" authentication attempt (#%d).", session->username, session->opts.server.ssh_auth_attempts);
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
            WRN("Failed to import a public key of \"%s\" (File access problem).", server_opts.authkeys[i].username);
            continue;
        } else if (ret == SSH_ERROR) {
            WRN("Failed to import a public key of \"%s\" (SSH error).", server_opts.authkeys[i].username);
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
            VRB("User \"%s\" tried to use an unknown (unauthorized) public key.", session->username);
            goto fail;
        } else if (strcmp(session->username, username)) {
            VRB("User \"%s\" is not the username identified with the presented public key.", session->username);
            goto fail;
        }
    }

    signature_state = ssh_message_auth_publickey_state(msg);
    if (signature_state == SSH_PUBLICKEY_STATE_VALID) {
        VRB("User \"%s\" authenticated.", session->username);
        session->flags |= NC_SESSION_SSH_AUTHENTICATED;
        ssh_message_auth_reply_success(msg, 0);
    } else if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
        /* accepting only the use of a public key */
        ssh_message_auth_reply_pk_ok_simple(msg);
    }

    return;

fail:
    ++session->opts.server.ssh_auth_attempts;
    VRB("Failed user \"%s\" authentication attempt (#%d).", session->username, session->opts.server.ssh_auth_attempts);
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
            ERR("Failed to create a new SSH channel.");
            return -1;
        }
        session->ti.libssh.channel = chan;

    /* additional channel request */
    } else {
        chan = ssh_message_channel_request_open_reply_accept(msg);
        if (!chan) {
            ERR("Session %u: failed to create a new SSH channel.", session->id);
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
        WRN("Received an unknown subsystem \"%s\" request.", subsystem);
        return -1;
    }

    if (session->ti.libssh.channel == channel) {
        /* first channel requested */
        if (session->ti.libssh.next || (session->status != NC_STATUS_STARTING)) {
            ERRINT;
            return -1;
        }
        if (session->flags & NC_SESSION_SSH_SUBSYS_NETCONF) {
            ERR("Session %u: subsystem \"netconf\" requested for the second time.", session->id);
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
        new_session->username = lydict_insert(server_opts.ctx, session->username, 0);
        new_session->host = lydict_insert(server_opts.ctx, session->host, 0);
        new_session->port = session->port;
        new_session->ctx = server_opts.ctx;
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

    VRB("Received an SSH message \"%s\" of subtype \"%s\".", str_type, str_subtype);
    if ((session->status == NC_STATUS_CLOSING) || (session->status == NC_STATUS_INVALID)) {
        /* "valid" situation if, for example, receiving some auth or channel request timeouted,
         * but we got it now, during session free */
        VRB("SSH message arrived on a %s session, the request will be denied.",
            (session->status == NC_STATUS_CLOSING ? "closing" : "invalid"));
        ssh_message_reply_default(msg);
        return 0;
    }
    session->flags |= NC_SESSION_SSH_NEW_MSG;

    /*
     * process known messages
     */
    if (type == SSH_REQUEST_AUTH) {
        if (session->flags & NC_SESSION_SSH_AUTHENTICATED) {
            ERR("User \"%s\" authenticated, but requested another authentication.", session->username);
            ssh_message_reply_default(msg);
            return 0;
        }

        /* save the username, do not let the client change it */
        username = ssh_message_auth_user(msg);
        if (!session->username) {
            if (!username) {
                ERR("Denying an auth request without a username.");
                return 1;
            }

            session->username = lydict_insert(server_opts.ctx, username, 0);
        } else if (username) {
            if (strcmp(username, session->username)) {
                ERR("User \"%s\" changed its username to \"%s\".", session->username, username);
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
nc_open_netconf_channel(struct nc_session *session, int timeout)
{
    int ret;
    struct timespec ts_timeout, ts_cur;

    /* message callback is executed twice to give chance for the channel to be
     * created if timeout == 0 (it takes 2 messages, channel-open, subsystem-request) */
    if (!timeout) {
        if (!nc_session_is_connected(session)) {
            ERR("Communication socket unexpectedly closed (libssh).");
            return -1;
        }

        ret = ssh_execute_message_callbacks(session->ti.libssh.session);
        if (ret != SSH_OK) {
            ERR("Failed to receive SSH messages on a session (%s).",
                ssh_get_error(session->ti.libssh.session));
            return -1;
        }

        if (!session->ti.libssh.channel) {
            return 0;
        }

        ret = ssh_execute_message_callbacks(session->ti.libssh.session);
        if (ret != SSH_OK) {
            ERR("Failed to receive SSH messages on a session (%s).",
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
        nc_gettimespec_mono(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);
    }
    while (1) {
        if (!nc_session_is_connected(session)) {
            ERR("Communication socket unexpectedly closed (libssh).");
            return -1;
        }

        ret = ssh_execute_message_callbacks(session->ti.libssh.session);
        if (ret != SSH_OK) {
            ERR("Failed to receive SSH messages on a session (%s).",
                ssh_get_error(session->ti.libssh.session));
            return -1;
        }

        if (session->ti.libssh.channel && (session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
            return 1;
        }

        usleep(NC_TIMEOUT_STEP);
        if (timeout > -1) {
            nc_gettimespec_mono(&ts_cur);
            if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
                /* timeout */
                ERR("Failed to start \"netconf\" SSH subsystem for too long, disconnecting.");
                break;
            }
        }
    }

    return 0;
}

static int
nc_ssh_bind_add_hostkeys(ssh_bind sbind, const char **hostkeys, uint8_t hostkey_count)
{
    uint8_t i;
    char *privkey_path, *privkey_data;
    int privkey_data_rsa, ret;

    if (!server_opts.hostkey_clb) {
        ERR("Callback for retrieving SSH host keys not set.");
        return -1;
    }

    for (i = 0; i < hostkey_count; ++i) {
        privkey_path = privkey_data = NULL;
        if (server_opts.hostkey_clb(hostkeys[i], server_opts.hostkey_data, &privkey_path, &privkey_data, &privkey_data_rsa)) {
            ERR("Host key callback failed.");
            return -1;
        }

        if (privkey_data) {
            privkey_path = base64der_key_to_tmp_file(privkey_data, privkey_data_rsa);
            if (!privkey_path) {
                ERR("Temporarily storing a host key into a file failed (%s).", strerror(errno));
                free(privkey_data);
                return -1;
            }
        }

        ret = ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HOSTKEY, privkey_path);

        /* cleanup */
        if (privkey_data && unlink(privkey_path)) {
            WRN("Removing a temporary host key file \"%s\" failed (%s).", privkey_path, strerror(errno));
        }
        free(privkey_data);

        if (ret != SSH_OK) {
            ERR("Failed to set hostkey \"%s\" (%s).", hostkeys[i], privkey_path);
        }
        free(privkey_path);

        if (ret != SSH_OK) {
            return -1;
        }
    }

    return 0;
}

int
nc_accept_ssh_session(struct nc_session *session, int sock, int timeout)
{
    ssh_bind sbind;
    struct nc_server_ssh_opts *opts;
    int libssh_auth_methods = 0, ret;
    struct timespec ts_timeout, ts_cur;

    opts = session->data;

    /* other transport-specific data */
    session->ti_type = NC_TI_LIBSSH;
    session->ti.libssh.session = ssh_new();
    if (!session->ti.libssh.session) {
        ERR("Failed to initialize a new SSH session.");
        close(sock);
        return -1;
    }

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

    sbind = ssh_bind_new();
    if (!sbind) {
        ERR("Failed to create an SSH bind.");
        close(sock);
        return -1;
    }

    if (nc_ssh_bind_add_hostkeys(sbind, opts->hostkeys, opts->hostkey_count)) {
        close(sock);
        ssh_bind_free(sbind);
        return -1;
    }

    ssh_set_message_callback(session->ti.libssh.session, nc_sshcb_msg, session);
    /* remember that this session was just set as nc_sshcb_msg() parameter */
    session->flags |= NC_SESSION_SSH_MSG_CB;

    if (ssh_bind_accept_fd(sbind, session->ti.libssh.session, sock) == SSH_ERROR) {
        ERR("SSH failed to accept a new connection (%s).", ssh_get_error(sbind));
        close(sock);
        ssh_bind_free(sbind);
        return -1;
    }
    ssh_bind_free(sbind);

    ssh_set_blocking(session->ti.libssh.session, 0);

    if (timeout > -1) {
        nc_gettimespec_mono(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);
    }
    while ((ret = ssh_handle_key_exchange(session->ti.libssh.session)) == SSH_AGAIN) {
        /* this tends to take longer */
        usleep(NC_TIMEOUT_STEP * 20);
        if (timeout > -1) {
            nc_gettimespec_mono(&ts_cur);
            if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
                break;
            }
        }
    }
    if (ret == SSH_AGAIN) {
        ERR("SSH key exchange timeout.");
        return 0;
    } else if (ret != SSH_OK) {
        ERR("SSH key exchange error (%s).", ssh_get_error(session->ti.libssh.session));
        return -1;
    }

    /* authenticate */
    if (opts->auth_timeout) {
        nc_gettimespec_mono(&ts_timeout);
        nc_addtimespec(&ts_timeout, opts->auth_timeout * 1000);
    }
    while (1) {
        if (!nc_session_is_connected(session)) {
            ERR("Communication SSH socket unexpectedly closed.");
            return -1;
        }

        if (ssh_execute_message_callbacks(session->ti.libssh.session) != SSH_OK) {
            ERR("Failed to receive SSH messages on a session (%s).",
                ssh_get_error(session->ti.libssh.session));
            return -1;
        }

        if (session->flags & NC_SESSION_SSH_AUTHENTICATED) {
            break;
        }

        if (session->opts.server.ssh_auth_attempts >= opts->auth_attempts) {
            ERR("Too many failed authentication attempts of user \"%s\".", session->username);
            return -1;
        }

        usleep(NC_TIMEOUT_STEP);
        if (opts->auth_timeout) {
            nc_gettimespec_mono(&ts_cur);
            if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
                /* timeout */
                break;
            }
        }
    }

    if (!(session->flags & NC_SESSION_SSH_AUTHENTICATED)) {
        /* timeout */
        if (session->username) {
            ERR("User \"%s\" failed to authenticate for too long, disconnecting.", session->username);
        } else {
            ERR("User failed to authenticate for too long, disconnecting.");
        }
        return 0;
    }

    /* open channel */
    ret = nc_open_netconf_channel(session, timeout);
    if (ret < 1) {
        return ret;
    }

    session->flags &= ~NC_SESSION_SSH_NEW_MSG;
    return 1;
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

    if ((orig_session->status == NC_STATUS_RUNNING) && (orig_session->ti_type == NC_TI_LIBSSH)
            && orig_session->ti.libssh.next) {
        for (new_session = orig_session->ti.libssh.next;
                new_session != orig_session;
                new_session = new_session->ti.libssh.next) {
            if ((new_session->status == NC_STATUS_STARTING) && new_session->ti.libssh.channel
                    && (new_session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
                /* we found our session */
                break;
            }
        }
        if (new_session == orig_session) {
            new_session = NULL;
        }
    }

    if (!new_session) {
        ERR("Session does not have a NETCONF SSH channel ready.");
        return NC_MSG_ERROR;
    }

    /* assign new SID atomically */
    new_session->id = ATOMIC_INC(&server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(new_session);
    if (msgtype != NC_MSG_HELLO) {
        return msgtype;
    }

    nc_gettimespec_real(&ts_cur);
    new_session->opts.server.session_start = ts_cur.tv_sec;
    nc_gettimespec_mono(&ts_cur);
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
        if ((cur_session->status == NC_STATUS_RUNNING) && (cur_session->ti_type == NC_TI_LIBSSH)
                && cur_session->ti.libssh.next) {
            /* an SSH session with more channels */
            for (new_session = cur_session->ti.libssh.next;
                    new_session != cur_session;
                    new_session = new_session->ti.libssh.next) {
                if ((new_session->status == NC_STATUS_STARTING) && new_session->ti.libssh.channel
                        && (new_session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
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
        ERR("No session with a NETCONF SSH channel ready was found.");
        return NC_MSG_ERROR;
    }

    /* assign new SID atomically */
    new_session->id = ATOMIC_INC(&server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(new_session);
    if (msgtype != NC_MSG_HELLO) {
        return msgtype;
    }

    nc_gettimespec_real(&ts_cur);
    new_session->opts.server.session_start = ts_cur.tv_sec;
    nc_gettimespec_mono(&ts_cur);
    new_session->opts.server.last_rpc = ts_cur.tv_sec;
    new_session->status = NC_STATUS_RUNNING;
    *session = new_session;

    return msgtype;
}
