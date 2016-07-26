/**
 * \file session_server_ssh.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 SSH server session manipulation functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
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
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <errno.h>

#include "session_server.h"
#include "session_server_ch.h"
#include "libnetconf.h"

struct nc_server_ssh_opts ssh_ch_opts = {
    .auth_methods = NC_SSH_AUTH_PUBLICKEY | NC_SSH_AUTH_PASSWORD | NC_SSH_AUTH_INTERACTIVE,
    .auth_attempts = 3,
    .auth_timeout = 10
};
pthread_mutex_t ssh_ch_opts_lock = PTHREAD_MUTEX_INITIALIZER;
extern struct nc_server_opts server_opts;

API int
nc_server_ssh_add_endpt_listen(const char *name, const char *address, uint16_t port)
{
    return nc_server_add_endpt_listen(name, address, port, NC_TI_LIBSSH);
}

API int
nc_server_ssh_endpt_set_address(const char *endpt_name, const char *address)
{
    return nc_server_endpt_set_address_port(endpt_name, address, 0, NC_TI_LIBSSH);
}

API int
nc_server_ssh_endpt_set_port(const char *endpt_name, uint16_t port)
{
    return nc_server_endpt_set_address_port(endpt_name, NULL, port, NC_TI_LIBSSH);
}

API int
nc_server_ssh_del_endpt(const char *name)
{
    return nc_server_del_endpt(name, NC_TI_LIBSSH);
}

static int
nc_server_ssh_set_hostkey(const char *privkey_path, struct nc_server_ssh_opts *opts)
{
    if (!privkey_path) {
        ERRARG("privkey_path");
        return -1;
    }

    if (!opts->sshbind) {
        opts->sshbind = ssh_bind_new();
        if (!opts->sshbind) {
            ERR("Failed to create a new ssh_bind.");
            return -1;
        }
    }

    if (ssh_bind_options_set(opts->sshbind, SSH_BIND_OPTIONS_HOSTKEY, privkey_path) != SSH_OK) {
        if (eaccess(privkey_path, R_OK)) {
            ERR("Failed to set host key (%s).", strerror(errno));
        } else {
            ERR("Failed to set host key (%s).", ssh_get_error(opts->sshbind));
        }
        return -1;
    }

    return 0;
}

API int
nc_server_ssh_endpt_set_hostkey(const char *endpt_name, const char *privkey_path)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock(endpt_name, NC_TI_LIBSSH);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_ssh_set_hostkey(privkey_path, endpt->ti_opts);
    /* UNLOCK */
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_ssh_ch_set_hostkey(const char *privkey_path)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&ssh_ch_opts_lock);
    ret = nc_server_ssh_set_hostkey(privkey_path, &ssh_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&ssh_ch_opts_lock);

    return ret;
}

static int
nc_server_ssh_set_banner(const char *banner, struct nc_server_ssh_opts *opts)
{
    if (!banner) {
        ERRARG("banner");
        return -1;
    }

    if (!opts->sshbind) {
        opts->sshbind = ssh_bind_new();
        if (!opts->sshbind) {
            ERR("Failed to create a new ssh_bind.");
            return -1;
        }
    }

    ssh_bind_options_set(opts->sshbind, SSH_BIND_OPTIONS_BANNER, banner);

    return 0;
}

API int
nc_server_ssh_endpt_set_banner(const char *endpt_name, const char *banner)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock(endpt_name, NC_TI_LIBSSH);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_ssh_set_banner(banner, endpt->ti_opts);
    /* UNLOCK */
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_ssh_ch_set_banner(const char *banner)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&ssh_ch_opts_lock);
    ret = nc_server_ssh_set_banner(banner, &ssh_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&ssh_ch_opts_lock);

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
    endpt = nc_server_endpt_lock(endpt_name, NC_TI_LIBSSH);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_ssh_set_auth_methods(auth_methods, endpt->ti_opts);
    /* UNLOCK */
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_ssh_ch_set_auth_methods(int auth_methods)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&ssh_ch_opts_lock);
    ret = nc_server_ssh_set_auth_methods(auth_methods, &ssh_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&ssh_ch_opts_lock);

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
    endpt = nc_server_endpt_lock(endpt_name, NC_TI_LIBSSH);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_ssh_set_auth_attempts(auth_attempts, endpt->ti_opts);
    /* UNLOCK */
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_ssh_set_ch_auth_attempts(uint16_t auth_attempts)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&ssh_ch_opts_lock);
    ret = nc_server_ssh_set_auth_attempts(auth_attempts, &ssh_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&ssh_ch_opts_lock);

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
    endpt = nc_server_endpt_lock(endpt_name, NC_TI_LIBSSH);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_ssh_set_auth_timeout(auth_timeout, endpt->ti_opts);
    /* UNLOCK */
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_ssh_ch_set_auth_timeout(uint16_t auth_timeout)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&ssh_ch_opts_lock);
    ret = nc_server_ssh_set_auth_timeout(auth_timeout, &ssh_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&ssh_ch_opts_lock);

    return ret;
}

static int
nc_server_ssh_add_authkey(const char *pubkey_path, const char *username, struct nc_server_ssh_opts *opts)
{
    if (!pubkey_path) {
        ERRARG("pubkey_path");
        return -1;
    } else if (!username) {
        ERRARG("username");
        return -1;
    }

    ++opts->authkey_count;
    opts->authkeys = nc_realloc(opts->authkeys, opts->authkey_count * sizeof *opts->authkeys);
    if (!opts->authkeys) {
        ERRMEM;
        return -1;
    }
    opts->authkeys[opts->authkey_count - 1].path = lydict_insert(server_opts.ctx, pubkey_path, 0);
    opts->authkeys[opts->authkey_count - 1].username = lydict_insert(server_opts.ctx, username, 0);

    return 0;
}

API int
nc_server_ssh_endpt_add_authkey(const char *endpt_name, const char *pubkey_path, const char *username)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock(endpt_name, NC_TI_LIBSSH);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_ssh_add_authkey(pubkey_path, username, endpt->ti_opts);
    /* UNLOCK */
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_ssh_ch_add_authkey(const char *pubkey_path, const char *username)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&ssh_ch_opts_lock);
    ret = nc_server_ssh_add_authkey(pubkey_path, username, &ssh_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&ssh_ch_opts_lock);

    return ret;
}

static int
nc_server_ssh_del_authkey(const char *pubkey_path, const char *username, struct nc_server_ssh_opts *opts)
{
    uint32_t i;
    int ret = -1;

    if (!pubkey_path && !username) {
        for (i = 0; i < opts->authkey_count; ++i) {
            lydict_remove(server_opts.ctx, opts->authkeys[i].path);
            lydict_remove(server_opts.ctx, opts->authkeys[i].username);

            ret = 0;
        }
        free(opts->authkeys);
        opts->authkeys = NULL;
        opts->authkey_count = 0;
    } else {
        for (i = 0; i < opts->authkey_count; ++i) {
            if ((!pubkey_path || !strcmp(opts->authkeys[i].path, pubkey_path))
                    && (!username || !strcmp(opts->authkeys[i].username, username))) {
                lydict_remove(server_opts.ctx, opts->authkeys[i].path);
                lydict_remove(server_opts.ctx, opts->authkeys[i].username);

                --opts->authkey_count;
                if (i < opts->authkey_count) {
                    memcpy(&opts->authkeys[i], &opts->authkeys[opts->authkey_count], sizeof *opts->authkeys);
                } else if (!opts->authkey_count) {
                    free(opts->authkeys);
                    opts->authkeys = NULL;
                }

                ret = 0;
            }
        }
    }

    return ret;
}

API int
nc_server_ssh_endpt_del_authkey(const char *endpt_name, const char *pubkey_path, const char *username)
{
    int ret;
    struct nc_endpt *endpt;

    /* LOCK */
    endpt = nc_server_endpt_lock(endpt_name, NC_TI_LIBSSH);
    if (!endpt) {
        return -1;
    }
    ret = nc_server_ssh_del_authkey(pubkey_path, username, endpt->ti_opts);
    /* UNLOCK */
    nc_server_endpt_unlock(endpt);

    return ret;
}

API int
nc_server_ssh_ch_del_authkey(const char *pubkey_path, const char *username)
{
    int ret;

    /* OPTS LOCK */
    pthread_mutex_lock(&ssh_ch_opts_lock);
    ret = nc_server_ssh_del_authkey(pubkey_path, username, &ssh_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&ssh_ch_opts_lock);

    return ret;
}

void
nc_server_ssh_clear_opts(struct nc_server_ssh_opts *opts)
{
    if (opts->sshbind) {
        ssh_bind_free(opts->sshbind);
        opts->sshbind = NULL;
    }

    nc_server_ssh_del_authkey(NULL, NULL, opts);
}

API void
nc_server_ssh_ch_clear_opts(void)
{
    /* OPTS LOCK */
    pthread_mutex_lock(&ssh_ch_opts_lock);
    nc_server_ssh_clear_opts(&ssh_ch_opts);
    /* OPTS UNLOCK */
    pthread_mutex_unlock(&ssh_ch_opts_lock);
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
    VRB("Failed user \"%s\" authentication attempt (#%d).", session->username, session->ssh_auth_attempts);
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
        free(pass_hash);
    }
}

static const char *
auth_pubkey_compare_key(struct nc_server_ssh_opts *opts, ssh_key key)
{
    uint32_t i;
    ssh_key pub_key;
    const char *username = NULL;
    int ret;

    for (i = 0; i < opts->authkey_count; ++i) {
        ret = ssh_pki_import_pubkey_file(opts->authkeys[i].path, &pub_key);
        if (ret == SSH_EOF) {
            WRN("Failed to import the public key \"%s\" (File access problem).", opts->authkeys[i].path);
            continue;
        } else if (ret == SSH_ERROR) {
            WRN("Failed to import the public key \"%s\" (SSH error).", opts->authkeys[i].path);
            continue;
        }

        if (!ssh_key_cmp(key, pub_key, SSH_KEY_CMP_PUBLIC)) {
            ssh_key_free(pub_key);
            break;
        }

        ssh_key_free(pub_key);
    }

    if (i < opts->authkey_count) {
        username = opts->authkeys[i].username;
    }

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
        if ((username = auth_pubkey_compare_key(session->data, ssh_message_auth_pubkey(msg))) == NULL) {
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
        new_session->side = NC_SERVER;
        new_session->ti_type = NC_TI_LIBSSH;
        new_session->ti_lock = session->ti_lock;
        new_session->ti.libssh.channel = channel;
        new_session->ti.libssh.session = session->ti.libssh.session;
        new_session->username = lydict_insert(server_opts.ctx, session->username, 0);
        new_session->host = lydict_insert(server_opts.ctx, session->host, 0);
        new_session->port = session->port;
        new_session->ctx = server_opts.ctx;
        new_session->flags = NC_SESSION_SSH_AUTHENTICATED | NC_SESSION_SSH_SUBSYS_NETCONF | NC_SESSION_SHAREDCTX
                             | (session->flags & NC_SESSION_CALLHOME ? NC_SESSION_CALLHOME : 0);
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

        if (session->ssh_auth_attempts >= ((struct nc_server_ssh_opts *)session->data)->auth_attempts) {
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
    int elapsed_usec = 0, ret;

    /* message callback is executed twice to give chance for the channel to be
     * created if timeout == 0 (it takes 2 messages, channel-open, subsystem-request) */
    if (!timeout) {
        if (!nc_session_is_connected(session)) {
            ERR("Communication socket unexpectedly closed (libssh).");
            return -1;
        }

        ret = nc_timedlock(session->ti_lock, timeout);
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

        ret = nc_timedlock(session->ti_lock, timeout);
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

        if ((timeout != -1) && (elapsed_usec / 1000 >= timeout)) {
            /* timeout */
            ERR("Failed to start \"netconf\" SSH subsystem for too long, disconnecting.");
            break;
        }

        usleep(NC_TIMEOUT_STEP);
        elapsed_usec += NC_TIMEOUT_STEP;
    }

    return 0;
}

int
nc_ssh_pollin(struct nc_session *session, int timeout)
{
    int ret;
    struct nc_session *new;

    ret = nc_timedlock(session->ti_lock, timeout);

    if (ret < 0) {
        return NC_PSPOLL_ERROR;
    } else if (!ret) {
        return NC_PSPOLL_TIMEOUT;
    }

    ret = ssh_execute_message_callbacks(session->ti.libssh.session);
    pthread_mutex_unlock(session->ti_lock);

    if (ret != SSH_OK) {
        ERR("Session %u: failed to receive SSH messages (%s).", session->id,
            ssh_get_error(session->ti.libssh.session));
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_OTHER;
        return NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
    }

    /* new SSH message */
    if (session->flags & NC_SESSION_SSH_NEW_MSG) {
        session->flags &= ~NC_SESSION_SSH_NEW_MSG;
        if (session->ti.libssh.next) {
            for (new = session->ti.libssh.next; new != session; new = new->ti.libssh.next) {
                if ((new->status == NC_STATUS_STARTING) && new->ti.libssh.channel
                        && (new->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
                    /* new NETCONF SSH channel */
                    return NC_PSPOLL_SSH_CHANNEL;
                }
            }
        }

        /* just some SSH message */
        return NC_PSPOLL_SSH_MSG;
    }

    /* no new SSH message, maybe NETCONF data? */
    ret = ssh_channel_poll_timeout(session->ti.libssh.channel, 0, 0);
    /* not this one */
    if (!ret) {
        return NC_PSPOLL_PENDING;
    } else if (ret == SSH_ERROR) {
        ERR("Session %u: SSH channel error (%s).", session->id,
            ssh_get_error(session->ti.libssh.session));
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_OTHER;
        return NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
    } else if (ret == SSH_EOF) {
        ERR("Session %u: communication channel unexpectedly closed (libssh).",
            session->id);
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_DROPPED;
        return NC_PSPOLL_SESSION_TERM | NC_PSPOLL_SESSION_ERROR;
    }

    return NC_PSPOLL_RPC;
}

API NC_MSG_TYPE
nc_connect_callhome_ssh(const char *host, uint16_t port, struct nc_session **session)
{
    return nc_connect_callhome(host, port, NC_TI_LIBSSH, session);
}

int
nc_accept_ssh_session(struct nc_session *session, int sock, int timeout)
{
    struct nc_server_ssh_opts *opts;
    int libssh_auth_methods = 0, elapsed_usec = 0, ret;

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

    ssh_set_message_callback(session->ti.libssh.session, nc_sshcb_msg, session);
    /* remember that this session was just set as nc_sshcb_msg() parameter */
    session->flags |= NC_SESSION_SSH_MSG_CB;

    if (ssh_bind_accept_fd(opts->sshbind, session->ti.libssh.session, sock) == SSH_ERROR) {
        ERR("SSH failed to accept a new connection (%s).", ssh_get_error(opts->sshbind));
        close(sock);
        return -1;
    }

    ssh_set_blocking(session->ti.libssh.session, 0);

    while ((ret = ssh_handle_key_exchange(session->ti.libssh.session)) == SSH_AGAIN) {
        /* this tends to take longer */
        usleep(NC_TIMEOUT_STEP * 20);
        elapsed_usec += NC_TIMEOUT_STEP * 20;
        if ((timeout > -1) && (elapsed_usec / 1000 >= timeout)) {
            break;
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
    elapsed_usec = 0;
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
        elapsed_usec += NC_TIMEOUT_STEP;
    } while (!opts->auth_timeout || (elapsed_usec / 1000000 < opts->auth_timeout));

    if (!(session->flags & NC_SESSION_SSH_AUTHENTICATED)) {
        /* timeout */
        ERR("Client failed to authenticate for too long, disconnecting.");
        return 0;
    }

    /* open channel */
    ret = nc_open_netconf_channel(session, opts->auth_timeout ? (opts->auth_timeout * 1000 - elapsed_usec / 1000) : -1);
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
    pthread_spin_lock(&server_opts.sid_lock);
    new_session->id = server_opts.new_session_id++;
    pthread_spin_unlock(&server_opts.sid_lock);

    /* NETCONF handshake */
    msgtype = nc_handshake(new_session);
    if (msgtype != NC_MSG_HELLO) {
        return msgtype;
    }

    new_session->session_start = time(NULL);
    new_session->status = NC_STATUS_RUNNING;
    *session = new_session;

    return msgtype;
}

API NC_MSG_TYPE
nc_ps_accept_ssh_channel(struct nc_pollsession *ps, struct nc_session **session)
{
    uint8_t q_id;
    NC_MSG_TYPE msgtype;
    struct nc_session *new_session = NULL;
    uint16_t i;

    if (!ps) {
        ERRARG("ps");
        return NC_MSG_ERROR;
    } else if (!session) {
        ERRARG("session");
        return NC_MSG_ERROR;
    }

    /* LOCK */
    if (nc_ps_lock(ps, &q_id)) {
        return NC_MSG_ERROR;
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

    /* UNLOCK */
    nc_ps_unlock(ps, q_id);

    if (!new_session) {
        ERR("No session with a NETCONF SSH channel ready was found.");
        return NC_MSG_ERROR;
    }

    /* assign new SID atomically */
    pthread_spin_lock(&server_opts.sid_lock);
    new_session->id = server_opts.new_session_id++;
    pthread_spin_unlock(&server_opts.sid_lock);

    /* NETCONF handshake */
    msgtype = nc_handshake(new_session);
    if (msgtype != NC_MSG_HELLO) {
        return msgtype;
    }

    new_session->session_start = time(NULL);
    new_session->status = NC_STATUS_RUNNING;
    *session = new_session;

    return msgtype;
}
