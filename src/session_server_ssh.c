/**
 * \file session_server_ssh.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 SSH server session manipulation functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <errno.h>

#include "libnetconf.h"
#include "session_server.h"

extern struct nc_server_opts server_opts;

struct nc_ssh_server_opts ssh_opts = {
    .sshbind_lock = PTHREAD_MUTEX_INITIALIZER,
    .authkey_lock = PTHREAD_MUTEX_INITIALIZER,
    .auth_methods = NC_SSH_AUTH_PUBLICKEY | NC_SSH_AUTH_PASSWORD | NC_SSH_AUTH_INTERACTIVE,
    .auth_attempts = 3,
    .auth_timeout = 10
};

struct nc_ssh_server_opts ssh_ch_opts = {
    .sshbind_lock = PTHREAD_MUTEX_INITIALIZER,
    .authkey_lock = PTHREAD_MUTEX_INITIALIZER,
    .auth_methods = NC_SSH_AUTH_PUBLICKEY | NC_SSH_AUTH_PASSWORD | NC_SSH_AUTH_INTERACTIVE,
    .auth_attempts = 3,
    .auth_timeout = 10
};

static int
_nc_ssh_server_set_hostkey(const char *privkey_path, int ch)
{
    struct nc_ssh_server_opts *opts;

    if (!privkey_path) {
        ERRARG;
        return -1;
    }

    opts = (ch ? &ssh_ch_opts : &ssh_opts);

    /* LOCK */
    pthread_mutex_lock(&opts->sshbind_lock);

    if (!opts->sshbind) {
        opts->sshbind = ssh_bind_new();
        if (!opts->sshbind) {
            ERR("Failed to create a new ssh_bind.");
            goto fail;
        }
    }

    if (ssh_bind_options_set(opts->sshbind, SSH_BIND_OPTIONS_HOSTKEY, privkey_path) != SSH_OK) {
        ERR("Failed to set host key (%s).", ssh_get_error(opts->sshbind));
        goto fail;
    }

    /* UNLOCK */
    pthread_mutex_unlock(&opts->sshbind_lock);
    return 0;

fail:
    /* UNLOCK */
    pthread_mutex_unlock(&opts->sshbind_lock);
    return -1;
}

API int
nc_ssh_server_set_hostkey(const char *privkey_path)
{
    return _nc_ssh_server_set_hostkey(privkey_path, 0);
}

API int
nc_ssh_server_ch_set_hostkey(const char *privkey_path)
{
    return _nc_ssh_server_set_hostkey(privkey_path, 1);
}

static int
_nc_ssh_server_set_banner(const char *banner, int ch)
{
    struct nc_ssh_server_opts *opts;

    if (!banner) {
        ERRARG;
        return -1;
    }

    opts = (ch ? &ssh_ch_opts : &ssh_opts);

    /* LOCK */
    pthread_mutex_lock(&opts->sshbind_lock);

    if (!opts->sshbind) {
        opts->sshbind = ssh_bind_new();
        if (!opts->sshbind) {
            ERR("Failed to create a new ssh_bind.");
            goto fail;
        }
    }

    ssh_bind_options_set(opts->sshbind, SSH_BIND_OPTIONS_BANNER, banner);

    /* UNLOCK */
    pthread_mutex_unlock(&opts->sshbind_lock);
    return 0;

fail:
    /* UNLOCK */
    pthread_mutex_unlock(&opts->sshbind_lock);
    return -1;
}

API int
nc_ssh_server_set_banner(const char *banner)
{
    return _nc_ssh_server_set_banner(banner, 0);
}

API int
nc_ssh_server_ch_set_banner(const char *banner)
{
    return _nc_ssh_server_set_banner(banner, 1);
}

static int
_nc_ssh_server_set_auth_methods(int auth_methods, int ch)
{
    struct nc_ssh_server_opts *opts;

    if (!(auth_methods & NC_SSH_AUTH_PUBLICKEY) && !(auth_methods & NC_SSH_AUTH_PASSWORD)
            && !(auth_methods & NC_SSH_AUTH_INTERACTIVE)) {
        ERRARG;
        return -1;
    }

    opts = (ch ? &ssh_ch_opts : &ssh_opts);

    opts->auth_methods = auth_methods;
    return 0;
}

API int
nc_ssh_server_set_auth_methods(int auth_methods)
{
    return _nc_ssh_server_set_auth_methods(auth_methods, 0);
}

API int
nc_ssh_server_ch_set_auth_methods(int auth_methods)
{
    return _nc_ssh_server_set_auth_methods(auth_methods, 1);
}

static int
_nc_ssh_server_set_auth_attempts(uint16_t auth_attempts, int ch)
{
    struct nc_ssh_server_opts *opts;

    if (!auth_attempts) {
        ERRARG;
        return -1;
    }

    opts = (ch ? &ssh_ch_opts : &ssh_opts);

    opts->auth_attempts = auth_attempts;
    return 0;
}

API int
nc_ssh_server_set_auth_attempts(uint16_t auth_attempts)
{
    return _nc_ssh_server_set_auth_attempts(auth_attempts, 0);
}

API int
nc_ssh_server_set_ch_auth_attempts(uint16_t auth_attempts)
{
    return _nc_ssh_server_set_auth_attempts(auth_attempts, 1);
}

static int
_nc_ssh_server_set_auth_timeout(uint16_t auth_timeout, int ch)
{
    struct nc_ssh_server_opts *opts;

    if (!auth_timeout) {
        ERRARG;
        return -1;
    }

    opts = (ch ? &ssh_ch_opts : &ssh_opts);

    opts->auth_timeout = auth_timeout;
    return 0;
}

API int
nc_ssh_server_set_auth_timeout(uint16_t auth_timeout)
{
    return _nc_ssh_server_set_auth_timeout(auth_timeout, 0);
}

API int
nc_ssh_server_ch_set_auth_timeout(uint16_t auth_timeout)
{
    return _nc_ssh_server_set_auth_timeout(auth_timeout, 1);
}

static int
_nc_ssh_server_add_authkey(const char *pubkey_path, const char *username, int ch)
{
    struct nc_ssh_server_opts *opts;

    if (!pubkey_path || !username) {
        ERRARG;
        return -1;
    }

    opts = (ch ? &ssh_ch_opts : &ssh_opts);

    /* LOCK */
    pthread_mutex_lock(&opts->authkey_lock);

    ++opts->authkey_count;
    opts->authkeys = realloc(opts->authkeys, opts->authkey_count * sizeof *opts->authkeys);

    nc_ctx_lock(-1, NULL);
    opts->authkeys[opts->authkey_count - 1].path = lydict_insert(server_opts.ctx, pubkey_path, 0);
    opts->authkeys[opts->authkey_count - 1].username = lydict_insert(server_opts.ctx, username, 0);
    nc_ctx_unlock();

    /* UNLOCK */
    pthread_mutex_unlock(&opts->authkey_lock);

    return 0;
}

API int
nc_ssh_server_add_authkey(const char *pubkey_path, const char *username)
{
    return _nc_ssh_server_add_authkey(pubkey_path, username, 0);
}

API int
nc_ssh_server_ch_add_authkey(const char *pubkey_path, const char *username)
{
    return _nc_ssh_server_add_authkey(pubkey_path, username, 1);
}

static int
_nc_ssh_server_del_authkey(const char *pubkey_path, const char *username, int ch)
{
    struct nc_ssh_server_opts *opts;
    uint32_t i;
    int ret = -1;

    opts = (ch ? &ssh_ch_opts : &ssh_opts);

    /* LOCK */
    pthread_mutex_lock(&opts->authkey_lock);

    if (!pubkey_path && !username) {
        nc_ctx_lock(-1, NULL);
        for (i = 0; i < opts->authkey_count; ++i) {
            lydict_remove(server_opts.ctx, opts->authkeys[i].path);
            lydict_remove(server_opts.ctx, opts->authkeys[i].username);

            ret = 0;
        }
        nc_ctx_unlock();
        free(opts->authkeys);
        opts->authkeys = NULL;
        opts->authkey_count = 0;
    } else {
        for (i = 0; i < opts->authkey_count; ++i) {
            if ((!pubkey_path || !strcmp(opts->authkeys[i].path, pubkey_path))
                    && (!username || !strcmp(opts->authkeys[i].username, username))) {
                nc_ctx_lock(-1, NULL);
                lydict_remove(server_opts.ctx, opts->authkeys[i].path);
                lydict_remove(server_opts.ctx, opts->authkeys[i].username);
                nc_ctx_unlock();

                --opts->authkey_count;
                memcpy(&opts->authkeys[i], &opts->authkeys[opts->authkey_count], sizeof *opts->authkeys);

                ret = 0;
            }
        }
    }

    /* UNLOCK */
    pthread_mutex_unlock(&opts->authkey_lock);

    return ret;
}

API int
nc_ssh_server_del_authkey(const char *pubkey_path, const char *username)
{
    return _nc_ssh_server_del_authkey(pubkey_path, username, 0);
}

API int
nc_ssh_server_ch_del_authkey(const char *pubkey_path, const char *username)
{
    return _nc_ssh_server_del_authkey(pubkey_path, username, 1);
}

API void
nc_ssh_server_free_opts(void)
{
    /* LOCK */
    pthread_mutex_lock(&ssh_opts.sshbind_lock);

    if (ssh_opts.sshbind) {
        ssh_bind_free(ssh_opts.sshbind);
        ssh_opts.sshbind = NULL;
    }

    /* UNLOCK */
    pthread_mutex_unlock(&ssh_opts.sshbind_lock);

    nc_ssh_server_del_authkey(NULL, NULL);

    /* Call Home */

    /* LOCK */
    pthread_mutex_lock(&ssh_ch_opts.sshbind_lock);

    if (ssh_ch_opts.sshbind) {
        ssh_bind_free(ssh_ch_opts.sshbind);
        ssh_ch_opts.sshbind = NULL;
    }

    /* UNLOCK */
    pthread_mutex_unlock(&ssh_ch_opts.sshbind_lock);

    nc_ssh_server_ch_del_authkey(NULL, NULL);
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
    struct crypt_data cdata;

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

    cdata.initialized = 0;
    new_pass_hash = crypt_r(pass_clear, pass_hash, &cdata);
    return strcmp(new_pass_hash, pass_hash);
}

static void
nc_sshcb_auth_password(struct nc_session *session, ssh_message msg)
{
    char *pass_hash;

    pass_hash = auth_password_get_pwd_hash(session->username);
    if (pass_hash && !auth_password_compare_pwd(pass_hash, ssh_message_auth_password(msg))) {
        VRB("User \"%s\" authenticated.", session->username);
        ssh_message_auth_reply_success(msg, 0);
        session->flags |= NC_SESSION_SSH_AUTHENTICATED;
        free(pass_hash);
        return;
    }

    free(pass_hash);
    ++session->ssh_auth_attempts;
    VRB("Failed user \"'%s\" authentication attempt (#%d).", session->username, session->ssh_auth_attempts);
    ssh_message_reply_default(msg);
}

static void
nc_sshcb_auth_kbdint(struct nc_session *session, ssh_message msg)
{
    char *pass_hash;

    if (!ssh_message_auth_kbdint_is_response(msg)) {
        const char *prompts[] = {"Password: "};
        char echo[] = {0};

        ssh_message_auth_interactive_request(msg, "Interactive SSH Authentication", "Type your password:", 1, prompts, echo);
    } else {
        if (ssh_userauth_kbdint_getnanswers(session->ti.libssh.session) != 1) {
            ssh_message_reply_default(msg);
            return;
        }
        pass_hash = auth_password_get_pwd_hash(session->username);
        if (!pass_hash) {
            ssh_message_reply_default(msg);
            return;
        }
        if (!auth_password_compare_pwd(pass_hash, ssh_userauth_kbdint_getanswer(session->ti.libssh.session, 0))) {
            VRB("User \"%s\" authenticated.", session->username);
            session->flags |= NC_SESSION_SSH_AUTHENTICATED;
            ssh_message_auth_reply_success(msg, 0);
        } else {
            ++session->ssh_auth_attempts;
            VRB("Failed user \"%s\" authentication attempt (#%d).", session->username, session->ssh_auth_attempts);
            ssh_message_reply_default(msg);
        }
    }
}

static const char *
auth_pubkey_compare_key(ssh_key key)
{
    uint32_t i;
    ssh_key pub_key;
    const char *username = NULL;

    /* LOCK */
    pthread_mutex_lock(&ssh_opts.authkey_lock);

    for (i = 0; i < ssh_opts.authkey_count; ++i) {
        if (ssh_pki_import_pubkey_file(ssh_opts.authkeys[i].path, &pub_key) != SSH_OK) {
            if (eaccess(ssh_opts.authkeys[i].path, R_OK)) {
                WRN("Failed to import the public key \"%s\" (%s).", ssh_opts.authkeys[i].path, strerror(errno));
            } else {
                WRN("Failed to import the public key \"%s\" (%s).", __func__, ssh_opts.authkeys[i].path, ssh_get_error(pub_key));
            }
            continue;
        }

        if (!ssh_key_cmp(key, pub_key, SSH_KEY_CMP_PUBLIC)) {
            ssh_key_free(pub_key);
            break;
        }

        ssh_key_free(pub_key);
    }

    if (i < ssh_opts.authkey_count) {
        username = ssh_opts.authkeys[i].username;
    }

    /* UNLOCK */
    pthread_mutex_unlock(&ssh_opts.authkey_lock);

    return username;
}

static void
nc_sshcb_auth_pubkey(struct nc_session *session, ssh_message msg)
{
    const char *username;
    int signature_state;

    signature_state = ssh_message_auth_publickey_state(msg);
    if (signature_state == SSH_PUBLICKEY_STATE_VALID) {
        VRB("User \"%s\" authenticated.", session->username);
        session->flags |= NC_SESSION_SSH_AUTHENTICATED;
        ssh_message_auth_reply_success(msg, 0);
        return;

    } else if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
        if ((username = auth_pubkey_compare_key(ssh_message_auth_pubkey(msg))) == NULL) {
            VRB("User \"%s\" tried to use an unknown (unauthorized) public key.", session->username);

        } else if (strcmp(session->username, username)) {
            VRB("User \"%s\" is not the username identified with the presented public key.", session->username);

        } else {
            /* accepting only the use of a public key */
            ssh_message_auth_reply_pk_ok_simple(msg);
            return;
        }
    }

    ++session->ssh_auth_attempts;
    VRB("Failed user \"%s\" authentication attempt (#%d).", session->username, session->ssh_auth_attempts);
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
        new_session = calloc(1, sizeof *new_session);

        /* insert the new session */
        if (!session->ti.libssh.next) {
            new_session->ti.libssh.next = session;
        } else {
            new_session->ti.libssh.next = session->ti.libssh.next;
        }
        session->ti.libssh.next = new_session;

        new_session->status = NC_STATUS_STARTING;
        new_session->side = NC_SERVER;
        new_session->ti_type = NC_TI_LIBSSH;
        new_session->ti_lock = session->ti_lock;
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

        if (session->ssh_auth_attempts >= ssh_opts.auth_attempts) {
            /* too many failed attempts */
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
    int elapsed = 0, ret;

    /* message callback is executed twice to give chance for the channel to be
     * created if timeout == 0 (it takes 2 messages, channel-open, subsystem-request) */
    if (!timeout) {
        if (!nc_session_is_connected(session)) {
            ERR("Communication socket unexpectedly closed (libssh).");
            return -1;
        }

        ret = nc_timedlock(session->ti_lock, timeout, NULL);
        if (ret != 1) {
            return ret;
        }

        ret = ssh_execute_message_callbacks(session->ti.libssh.session);
        if (ret != SSH_OK) {
            ERR("Failed to receive SSH messages on a session (%s).",
                ssh_get_error(session->ti.libssh.session));
            pthread_mutex_unlock(session->ti_lock);
            return -1;
        }

        if (!session->ti.libssh.channel) {
            /* we did not receive channel-open, timeout */
            pthread_mutex_unlock(session->ti_lock);
            return 0;
        }

        ret = ssh_execute_message_callbacks(session->ti.libssh.session);
        if (ret != SSH_OK) {
            ERR("Failed to receive SSH messages on a session (%s).",
                ssh_get_error(session->ti.libssh.session));
            pthread_mutex_unlock(session->ti_lock);
            return -1;
        }
        pthread_mutex_unlock(session->ti_lock);

        if (!(session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
            /* we did not receive subsystem-request, timeout */
            return 0;
        }

        return 1;
    }

    while (1) {
        if (!nc_session_is_connected(session)) {
            ERR("Communication socket unexpectedly closed (libssh).");
            return -1;
        }

        ret = nc_timedlock(session->ti_lock, timeout, &elapsed);
        if (ret != 1) {
            return ret;
        }

        ret = ssh_execute_message_callbacks(session->ti.libssh.session);
        if (ret != SSH_OK) {
            ERR("Failed to receive SSH messages on a session (%s).",
                ssh_get_error(session->ti.libssh.session));
            pthread_mutex_unlock(session->ti_lock);
            return -1;
        }

        pthread_mutex_unlock(session->ti_lock);

        if (session->ti.libssh.channel && (session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
            return 1;
        }

        if ((timeout != -1) && (timeout >= elapsed)) {
            /* timeout */
            break;
        }

        usleep(NC_TIMEOUT_STEP);
        elapsed += NC_TIMEOUT_STEP;
    }

    return 0;
}

/* ret 0 - timeout, 1 channel has data, 2 some other channel has data,
 * 3 status change, 4 new SSH message, 5 new NETCONF SSH channel, -1 error */
int
nc_ssh_pollin(struct nc_session *session, int *timeout)
{
    int ret, elapsed = 0;
    struct nc_session *new;

    ret = nc_timedlock(session->ti_lock, *timeout, &elapsed);
    if (*timeout > 0) {
        *timeout -= elapsed;
    }

    if (ret != 1) {
        return ret;
    }

    ret = ssh_execute_message_callbacks(session->ti.libssh.session);
    pthread_mutex_unlock(session->ti_lock);

    if (ret != SSH_OK) {
        ERR("Session %u: failed to receive SSH messages (%s).", session->id,
            ssh_get_error(session->ti.libssh.session));
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_OTHER;
        return 3;
    }

    /* new SSH message */
    if (session->flags & NC_SESSION_SSH_NEW_MSG) {
        session->flags &= ~NC_SESSION_SSH_NEW_MSG;
        if (session->ti.libssh.next) {
            for (new = session->ti.libssh.next; new != session; new = new->ti.libssh.next) {
                if ((new->status == NC_STATUS_STARTING) && new->ti.libssh.channel
                        && (new->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
                    /* new NETCONF SSH channel */
                    return 5;
                }
            }
        }

        /* just some SSH message */
        return 4;
    }

    /* no new SSH message, maybe NETCONF data? */
    ret = ssh_channel_poll_timeout(session->ti.libssh.channel, 0, 0);
    /* not this one */
    if (!ret) {
        return 2;
    } else if (ret == SSH_ERROR) {
        ERR("Session %u: SSH channel error (%s).", session->id,
            ssh_get_error(session->ti.libssh.session));
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_OTHER;
        return 3;
    } else if (ret == SSH_EOF) {
        ERR("Session %u: communication channel unexpectedly closed (libssh).",
            session->id);
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_DROPPED;
        return 3;
    }

    return 1;
}

int
nc_accept_ssh_session(struct nc_session *session, int sock, int timeout)
{
    int libssh_auth_methods = 0, elapsed = 0, ret;

    /* other transport-specific data */
    session->ti_type = NC_TI_LIBSSH;
    session->ti.libssh.session = ssh_new();
    if (!session->ti.libssh.session) {
        ERR("Failed to initialize a new SSH session.");
        close(sock);
        return -1;
    }

    if (ssh_opts.auth_methods & NC_SSH_AUTH_PUBLICKEY) {
        libssh_auth_methods |= SSH_AUTH_METHOD_PUBLICKEY;
    }
    if (ssh_opts.auth_methods & NC_SSH_AUTH_PASSWORD) {
        libssh_auth_methods |= SSH_AUTH_METHOD_PASSWORD;
    }
    if (ssh_opts.auth_methods & NC_SSH_AUTH_INTERACTIVE) {
        libssh_auth_methods |= SSH_AUTH_METHOD_INTERACTIVE;
    }
    ssh_set_auth_methods(session->ti.libssh.session, libssh_auth_methods);

    ssh_set_message_callback(session->ti.libssh.session, nc_sshcb_msg, session);
    session->flags |= NC_SESSION_SSH_MSG_CB;

    /* LOCK */
    ret = nc_timedlock(&ssh_opts.sshbind_lock, timeout, &elapsed);
    if (ret < 1) {
        return ret;
    }

    if (ssh_bind_accept_fd(ssh_opts.sshbind, session->ti.libssh.session, sock) == SSH_ERROR) {
        ERR("SSH failed to accept a new connection (%s).", ssh_get_error(ssh_opts.sshbind));
        close(sock);
        /* UNLOCK */
        pthread_mutex_unlock(&ssh_opts.sshbind_lock);
        return -1;
    }

    /* UNLOCK */
    pthread_mutex_unlock(&ssh_opts.sshbind_lock);

    if (ssh_handle_key_exchange(session->ti.libssh.session) != SSH_OK) {
        ERR("SSH key exchange error (%s).", ssh_get_error(session->ti.libssh.session));
        return -1;
    }

    /* authenticate */
    do {
        if (!nc_session_is_connected(session)) {
            ERR("Communication socket unexpectedly closed (libssh).");
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

        usleep(NC_TIMEOUT_STEP);
        elapsed += NC_TIMEOUT_STEP;
    } while ((timeout == -1) || (timeout && (elapsed < timeout)));

    if (!(session->flags & NC_SESSION_SSH_AUTHENTICATED)) {
        /* timeout */
        return 0;
    }

    if (timeout > 0) {
        timeout -= elapsed;
    }

    /* open channel */
    ret = nc_open_netconf_channel(session, timeout);
    if (ret < 1) {
        return ret;
    }

    session->flags &= ~NC_SESSION_SSH_NEW_MSG;

    return 1;
}

API int
nc_ps_accept_ssh_channel(struct nc_pollsession *ps, struct nc_session **session)
{
    uint16_t i;
    struct nc_session *new_session = NULL;

    if (!ps || !session) {
        ERRARG;
        return -1;
    }

    for (i = 0; i < ps->session_count; ++i) {
        if ((ps->sessions[i]->status == NC_STATUS_RUNNING) && (ps->sessions[i]->ti_type == NC_TI_LIBSSH)
                && ps->sessions[i]->ti.libssh.next) {
            /* an SSH session with more channels */
            for (new_session = ps->sessions[i]->ti.libssh.next;
                    new_session != ps->sessions[i];
                    new_session = new_session->ti.libssh.next) {
                if ((new_session->status == NC_STATUS_STARTING) && new_session->ti.libssh.channel
                        && (new_session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
                    /* we found our session */
                    break;
                }
            }
            if (new_session != ps->sessions[i]) {
                break;
            }

            new_session = NULL;
        }
    }

    if (!new_session) {
        ERR("No session with a NETCONF SSH channel ready was found.");
        return -1;
    }

    /* assign new SID atomically */
    pthread_spin_lock(&server_opts.sid_lock);
    new_session->id = server_opts.new_session_id++;
    pthread_spin_unlock(&server_opts.sid_lock);

    /* NETCONF handshake */
    if (nc_handshake(new_session)) {
        return -1;
    }
    new_session->status = NC_STATUS_RUNNING;
    *session = new_session;

    return 0;
}
