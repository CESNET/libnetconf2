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

#include "session_server.h"
#include "session_p.h"

extern struct nc_server_opts server_opts;
static struct nc_ssh_server_opts ssh_opts = {
    .auth_methods = NC_SSH_AUTH_PUBLICKEY | NC_SSH_AUTH_PASSWORD | NC_SSH_AUTH_INTERACTIVE,
    .auth_attempts = 3,
    .auth_timeout = 10
};

API int
nc_ssh_server_set_hostkey(const char *key_path)
{
    if (!key_path) {
        ERRARG;
        return -1;
    }

    if (!ssh_opts.sshbind) {
        ssh_opts.sshbind = ssh_bind_new();
        if (!ssh_opts.sshbind) {
            ERR("%s: failed to create a new ssh_bind.", __func__);
            return -1;
        }
    }

    if (ssh_bind_options_set(ssh_opts.sshbind, SSH_BIND_OPTIONS_HOSTKEY, key_path) != SSH_OK) {
        ERR("%s: failed to set host key (%s).", __func__, ssh_get_error(ssh_opts.sshbind));
        return -1;
    }

    return 0;
}

API int
nc_ssh_server_set_banner(const char *banner)
{
    if (!banner) {
        ERRARG;
        return -1;
    }

    if (!ssh_opts.sshbind) {
        ssh_opts.sshbind = ssh_bind_new();
        if (!ssh_opts.sshbind) {
            ERR("%s: failed to create a new ssh_bind", __func__);
            return -1;
        }
    }

    ssh_bind_options_set(ssh_opts.sshbind, SSH_BIND_OPTIONS_BANNER, banner);
    return 0;
}

API int
nc_ssh_server_set_auth_methods(int auth_methods)
{
    if (!(auth_methods & NC_SSH_AUTH_PUBLICKEY) && !(auth_methods & NC_SSH_AUTH_PASSWORD)
            && !(auth_methods & NC_SSH_AUTH_INTERACTIVE)) {
        ERRARG;
        return -1;
    }

    ssh_opts.auth_methods = auth_methods;
    return 0;
}

API int
nc_ssh_server_set_auth_attempts(uint16_t auth_attempts)
{
    if (!auth_attempts) {
        ERRARG;
        return -1;
    }

    ssh_opts.auth_attempts = auth_attempts;
    return 0;
}

API int
nc_ssh_server_set_auth_timeout(uint16_t auth_timeout)
{
    if (!auth_timeout) {
        ERRARG;
        return -1;
    }

    ssh_opts.auth_timeout = auth_timeout;
    return 0;
}

API int
nc_ssh_server_add_authkey(const char *keypath, const char *username)
{
    if (!keypath || !username) {
        ERRARG;
        return -1;
    }

    ++ssh_opts.authkey_count;
    ssh_opts.authkeys = realloc(ssh_opts.authkeys, ssh_opts.authkey_count * sizeof *ssh_opts.authkeys);

    ssh_opts.authkeys[ssh_opts.authkey_count - 1].path = strdup(keypath);
    ssh_opts.authkeys[ssh_opts.authkey_count - 1].username = strdup(username);

    return 0;
}

API int
nc_ssh_server_del_authkey(const char *keypath, const char *username)
{
    uint32_t i;
    int ret = -1;

    for (i = 0; i < ssh_opts.authkey_count; ++i) {
        if ((!keypath || !strcmp(ssh_opts.authkeys[i].path, keypath))
                && (!username || !strcmp(ssh_opts.authkeys[i].username, username))) {
            free(ssh_opts.authkeys[i].path);
            free(ssh_opts.authkeys[i].username);

            --ssh_opts.authkey_count;
            memmove(&ssh_opts.authkeys[i], &ssh_opts.authkeys[i + 1], (ssh_opts.authkey_count - i) * sizeof *ssh_opts.authkeys);

            ret = 0;
        }
    }

    return ret;
}

API void
nc_ssh_server_free_opts(void)
{
    int i;

    if (ssh_opts.sshbind) {
        ssh_bind_free(ssh_opts.sshbind);
    }

    if (ssh_opts.authkeys) {
        for (i = 0; i < ssh_opts.authkey_count; ++i) {
            free(ssh_opts.authkeys[i].path);
            free(ssh_opts.authkeys[i].username);
        }
        free(ssh_opts.authkeys);
    }
}

static char *
auth_password_get_pwd_hash(const char *username)
{
    struct passwd *pwd, pwd_buf;
    struct spwd *spwd, spwd_buf;
    char *pass_hash = NULL, buf[256];

    getpwnam_r(username, &pwd_buf, buf, 256, &pwd);
    if (!pwd) {
        VRB("User '%s' not found locally.", username);
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
        ERR("%s: no password could be retrieved for \"%s\".", __func__, username);
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
        VRB("User '%s' authenticated.", session->username);
        ssh_message_auth_reply_success(msg, 0);
        session->flags |= NC_SESSION_SSH_AUTHENTICATED;
        free(pass_hash);
        return;
    }

    free(pass_hash);
    ++session->auth_attempts;
    VRB("Failed user '%s' authentication attempt (#%d).", session->username, session->auth_attempts);
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
            ++session->auth_attempts;
            VRB("Failed user \"%s\" authentication attempt (#%d).", session->username, session->auth_attempts);
            ssh_message_reply_default(msg);
        }
    }
}

static const char *
auth_pubkey_compare_key(ssh_key key)
{
    uint32_t i;
    ssh_key pub_key;
    char *username = NULL;

    for (i = 0; i < ssh_opts.authkey_count; ++i) {
        if (ssh_pki_import_pubkey_file(ssh_opts.authkeys[i].path, &pub_key) != SSH_OK) {
            if (eaccess(ssh_opts.authkeys[i].path, R_OK)) {
                VRB("%s: failed to import the public key \"%s\" (%s)", __func__, ssh_opts.authkeys[i].path, strerror(errno));
            } else {
                VRB("%s: failed to import the public key \"%s\" (%s)", __func__, ssh_opts.authkeys[i].path, ssh_get_error(pub_key));
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

    ++session->auth_attempts;
    VRB("Failed user \"%s\" authentication attempt (#%d).", session->username, session->auth_attempts);
    ssh_message_reply_default(msg);
}

static int
nc_sshcb_channel_open(struct nc_session *session, ssh_channel channel)
{
    while (session->ti.libssh.next) {
        if (session->status == NC_STATUS_STARTING) {
            ERRINT;
            return -1;
        }
        session = session->ti.libssh.next;
    }

    if ((session->status != NC_STATUS_STARTING) || session->ti.libssh.channel) {
        ERRINT;
        return -1;
    }

    session->ti.libssh.channel = channel;

    return 0;
}

static int
nc_sshcb_channel_subsystem(struct nc_session *session, ssh_channel channel, const char *subsystem)
{
    while (session && (session->ti.libssh.channel != channel)) {
        session = session->ti.libssh.next;
    }

    if (!session) {
        ERRINT;
        return -1;
    }

    if (!strcmp(subsystem, "netconf")) {
        if (session->flags & NC_SESSION_SSH_SUBSYS_NETCONF) {
            WRN("Client \"%s\" requested subsystem 'netconf' for the second time.", session->username);
        } else {
            session->flags |= NC_SESSION_SSH_SUBSYS_NETCONF;
        }
    } else {
        WRN("Client \"%s\" requested an unknown subsystem '%s'.", session->username, subsystem);
        return -1;
    }

    return 0;
}

static int
nc_sshcb_msg(ssh_session sshsession, ssh_message msg, void *data)
{
    const char *str_type, *str_subtype = NULL, *username;
    int subtype, type;
    struct nc_session *session = (struct nc_session *)data;
    (void)sshsession;

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

    /*
     * process known messages
     */
    if (type == SSH_REQUEST_AUTH) {
        if (session->flags & NC_SESSION_SSH_AUTHENTICATED) {
            ERR("User \"%s\" authenticated, but requested another authentication.", session->username);
            ssh_message_reply_default(msg);
            return 0;
        }

        if (session->auth_attempts >= ssh_opts.auth_attempts) {
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

            session->username = lydict_insert(session->ctx, username, 0);
        } else if (username) {
            if (strcmp(username, session->username)) {
                ERR("User \"%s\" changed its username to \"%s\".", session->username, username);
                session->status = NC_STATUS_INVALID;
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
        if ((type == SSH_REQUEST_CHANNEL_OPEN) && (subtype == (int)SSH_CHANNEL_SESSION)) {
            ssh_channel chan;
            if ((chan = ssh_message_channel_request_open_reply_accept(msg)) == NULL) {
                ssh_message_reply_default(msg);
                return 0;
            }
            nc_sshcb_channel_open(session, chan);
            return 0;
        } else if ((type == SSH_REQUEST_CHANNEL) && (subtype == (int)SSH_CHANNEL_REQUEST_SUBSYSTEM)) {
            if (!nc_sshcb_channel_subsystem(session, ssh_message_channel_request_channel(msg),
                                            ssh_message_channel_request_subsystem(msg))) {
                ssh_message_channel_request_reply_success(msg);
            } else {
                ssh_message_reply_default(msg);
            }
            return 0;
        }
    }

    /* we did not process it */
    return 1;
}

static int
nc_open_netconf_channel(struct nc_session *session, int timeout)
{
    int elapsed = 0;

    /* message callback is executed twice to give chance for the channel to be
     * created if timeout == 0 (it takes 2 messages, channel-open, subsystem-request) */
    do {
        if (ssh_execute_message_callbacks(session->ti.libssh.session) != SSH_OK) {
            ERR("%s: failed to receive new messages on the SSH session (%s)",
                __func__, ssh_get_error(session->ti.libssh.session));
            return -1;
        }

        if (session->ti.libssh.channel && (session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
            return 0;
        }

        usleep(NC_TIMEOUT_STEP);
        elapsed += NC_TIMEOUT_STEP;
        if ((timeout > NC_TIMEOUT_STEP) && (elapsed >= timeout)) {
            break;
        }

        if (ssh_execute_message_callbacks(session->ti.libssh.session) != SSH_OK) {
            ERR("%s: failed to receive new messages on the SSH session (%s)",
                __func__, ssh_get_error(session->ti.libssh.session));
            return -1;
        }

        if (session->ti.libssh.channel && (session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
            return 0;
        }

        usleep(NC_TIMEOUT_STEP);
        elapsed += NC_TIMEOUT_STEP;
    } while ((timeout == -1) || (timeout && (elapsed < timeout)));

    return 1;
}

int
nc_accept_ssh_session(struct nc_session *session, int sock, int timeout)
{
    int libssh_auth_methods = 0, elapsed = 0;

    /* other transport-specific data */
    session->ti_type = NC_TI_LIBSSH;
    session->ti.libssh.session = ssh_new();
    if (!session->ti.libssh.session) {
        ERR("%s: failed to initialize SSH session", __func__);
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

    if (ssh_bind_accept_fd(ssh_opts.sshbind, session->ti.libssh.session, sock) == SSH_ERROR) {
        ERR("%s: SSH failed to accept a new connection (%s)", __func__, ssh_get_error(ssh_opts.sshbind));
        return -1;
    }

    if (ssh_handle_key_exchange(session->ti.libssh.session) != SSH_OK) {
        ERR("%s: SSH key exchange error (%s)", __func__, ssh_get_error(session->ti.libssh.session));
        return -1;
    }

    /* authenticate */
    do {
        if (ssh_execute_message_callbacks(session->ti.libssh.session) != SSH_OK) {
            ERR("%s: failed to receive new messages on the SSH session (%s)",
                __func__, ssh_get_error(session->ti.libssh.session));
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
        return -1;
    }

    if (timeout > 0) {
        timeout -= elapsed;
    }

    /* open channel */
    if (nc_open_netconf_channel(session, timeout)) {
        return -1;
    }

    return 0;
}

API struct nc_session *
nc_accept_ssh_channel(struct nc_session *session, int timeout)
{
    struct nc_session *new_session;
    int ret;

    new_session = calloc(1, sizeof *new_session);
    new_session->ti.libssh.session = session->ti.libssh.session;
    ret = nc_open_netconf_channel(new_session, timeout);
    if (ret) {
        if (ret == -1) {
            do {
                session->status = NC_STATUS_INVALID;
                session = session->ti.libssh.next;
            } while (session);
        }
        goto fail;
    }

    /* new channel was requested and opened, fill in the whole session now */
    for (; session->ti.libssh.next; session = session->ti.libssh.next);
    session->ti.libssh.next = new_session;

    new_session->status = NC_STATUS_STARTING;
    new_session->side = NC_SERVER;
    new_session->ti_type = NC_TI_LIBSSH;
    new_session->ti_lock = session->ti_lock;
    new_session->flags = NC_SESSION_SSH_AUTHENTICATED | NC_SESSION_SHAREDCTX;
    new_session->ctx = session->ctx;

    new_session->username = lydict_insert(new_session->ctx, session->username, 0);
    new_session->host = lydict_insert(new_session->ctx, session->host, 0);
    new_session->port = session->port;

    /* NETCONF handshake */
    if (nc_handshake(new_session)) {
        goto fail;
    }
    new_session->status = NC_STATUS_RUNNING;

    return new_session;

fail:
    nc_session_free(new_session);

    return NULL;
}
