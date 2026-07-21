/**
 * @file session_server_ssh_auth_message.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 SSH authentication with messages
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

#include <assert.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libyang/libyang.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef HAVE_LIBPAM
#   include <security/pam_appl.h>
#endif

#include "compat.h"
#include "log_p.h"
#include "session.h"
#include "session_p.h"
#include "session_server_ssh_wrapper.h"

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
    int i, r, n_answers, n_prompts = 0;
    const char **prompts = NULL, **answers = NULL, *answer;
    char *echo = NULL;
    struct nc_pam_thread_arg *clb_data = appdata_ptr;
    ssh_session libssh_session;

    libssh_session = clb_data->session->ti.libssh.session;

    /* parse the PAM messages into prompts */
    r = nc_server_ssh_pam_conv_parse(clb_data->session, n_messages, msg, resp, &n_prompts, &prompts, &echo);
    if (r != PAM_SUCCESS) {
        return r;
    }
    if (!n_prompts) {
        /* there are no requests left for the user, only messages with some information for the client were sent */
        return PAM_SUCCESS;
    }

    /* print all the keyboard-interactive challenges to the user */
    r = ssh_message_auth_interactive_request(clb_data->msg, NC_PAM_KBDINT_NAME, NC_PAM_KBDINT_INSTRUCTION,
            n_prompts, prompts, echo);
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
    }

    /* collect the replies */
    if (n_answers) {
        answers = calloc(n_answers, sizeof *answers);
        NC_CHECK_ERRMEM_GOTO(!answers, r = PAM_BUF_ERR, cleanup);
    }
    for (i = 0; i < n_answers; i++) {
        answer = ssh_userauth_kbdint_getanswer(libssh_session, i);
        if (!answer) {
            ERR(clb_data->session, "Failed to get keyboard-interactive answer %d.", i);
            r = PAM_CONV_ERR;
            goto cleanup;
        }
        answers[i] = answer;
    }

    /* give the replies to a PAM module (also checks that the counts match) */
    r = nc_server_ssh_pam_conv_fill(clb_data->session, *resp, n_prompts, n_answers, answers);

cleanup:
    free(prompts);
    free(echo);
    free(answers);
    return r;
}

/**
 * @brief Handles authentication via Linux PAM.
 *
 * @param[in] session NETCONF session.
 * @param[in] username Username of the client to authenticate.
 * @param[in] ssh_msg SSH message with a keyboard-interactive authentication request.
 * @return PAM_SUCCESS on success;
 * @return PAM error otherwise.
 */
static int
nc_server_ssh_msg_auth_kbdint_pam(struct nc_session *session, const char *username, ssh_message ssh_msg)
{
    struct nc_pam_thread_arg clb_data;
    struct pam_conv conv;

    /* structure holding callback's data */
    clb_data.msg = ssh_msg;
    clb_data.session = session;

    /* PAM conversation structure holding the callback and its data */
    conv.conv = nc_pam_conv_clb;
    conv.appdata_ptr = &clb_data;

    /* run the PAM sequence (the PAM handle is created and released inside) */
    return nc_server_ssh_pam_authenticate(session, username, &conv);
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
nc_server_ssh_msg_auth_kbdint_passwd(struct nc_session *session, const char *username, ssh_message msg)
{
    int n_answers;

    /* send the password prompt to the client */
    if (nc_server_ssh_kbdint_send_passwd_prompt(session, username, msg)) {
        return 1;
    }

    /* get the reply */
    n_answers = nc_server_ssh_kbdint_get_nanswers(session, session->ti.libssh.session);
    if (n_answers < 0) {
        /* timeout or dc */
        return 1;
    }

    /* verify the answer against the user's system password hash */
    return nc_server_ssh_kbdint_verify_passwd(session, username, n_answers) ? 1 : 0;
}

#endif /* HAVE_SHADOW */

/**
 * @brief Keyboard-interactive authentication method using the system's authentication methods.
 *
 * @param[in] session NETCONF session.
 * @param[in] msg SSH message with a keyboard-interactive authentication request.
 * @return 0 on success, non-zero otherwise.
 */
static int
nc_server_ssh_msg_auth_kbdint_system(struct nc_session *session, ssh_message msg)
{
    int rc;

#ifdef HAVE_LIBPAM
    /* authenticate using PAM */
    rc = nc_server_ssh_msg_auth_kbdint_pam(session, session->username, msg);
#elif defined (HAVE_SHADOW)
    /* authenticate using /etc/passwd and /etc/shadow */
    rc = nc_server_ssh_msg_auth_kbdint_passwd(session, session->username, msg);
#else
    (void)session;
    (void)msg;

    ERR(NULL, "Keyboard-interactive method not supported.");
    rc = 1;
#endif

    return rc;
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
nc_server_ssh_msg_auth_none(int local_users_supported, struct nc_auth_client *auth_client, ssh_message msg)
{
    assert(!local_users_supported || auth_client);

    if (local_users_supported && auth_client->none_enabled) {
        return 0;
    }

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
nc_server_ssh_msg_auth_password(struct nc_session *session, int local_users_supported,
        struct nc_auth_client *auth_client, ssh_message msg)
{
    int rc;

    rc = nc_server_ssh_auth_password_check(session, session->username, ssh_message_auth_password(msg), auth_client, local_users_supported);

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
nc_server_ssh_msg_auth_pubkey(struct nc_session *session, int local_users_supported,
        struct nc_auth_client *auth_client, ssh_message msg)
{
    int signature_state, ret;

    ret = nc_server_ssh_auth_pubkey_check(session, ssh_message_auth_pubkey(msg), auth_client, local_users_supported);
    if (!ret) {
        /* the key is authorized */
        signature_state = ssh_message_auth_publickey_state(msg);
        if (signature_state == SSH_PUBLICKEY_STATE_NONE) {
            /* accepting only the use of a public key */
            ssh_message_auth_reply_pk_ok_simple(msg);
            ret = -1;
        }
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
nc_server_ssh_msg_auth_kbdint(struct nc_session *session, int local_users_supported, struct nc_auth_client *auth_client, ssh_message msg)
{
    int r;
    enum nc_kbdint_backend backend;

    /* select the kbdint backend based on the configuration */
    if (nc_server_ssh_kbdint_select_method(session, local_users_supported, auth_client, &backend)) {
        return 1;
    }

    if (backend == NC_KBDINT_BACKEND_CUSTOM_CLB) {
        /* custom callback has higher priority */
        r = server_opts.interactive_auth_clb(session,
                session->ti.libssh.session, msg, server_opts.interactive_auth_data);
    } else {
        r = nc_server_ssh_msg_auth_kbdint_system(session, msg);
    }

    return r ? 1 : 0;
}

/**
 * @brief Handle SSH channel open request.
 *
 * @param[in] session NETCONF session.
 * @param[in] msg libssh message.
 * @return 0 on success, -1 on failure.
 */
static int
nc_server_ssh_msg_channel_open(struct nc_session *session, ssh_message msg)
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
nc_server_ssh_msg_channel_subsystem(struct nc_session *session, ssh_channel channel, const char *subsystem)
{
    struct nc_session *new_session;
    int rc;

    rc = nc_server_ssh_channel_subsys_check(session, channel, subsystem);
    if (rc < 0) {
        return -1;
    }
    if (!rc) {
        /* the "netconf" subsystem requested on the first channel */
        return 0;
    }

    /* additional channel subsystem request, new session is ready as far as SSH is concerned */
    new_session = nc_server_ssh_new_channel_session(session, channel);
    if (!new_session) {
        return -1;
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
nc_server_ssh_msg_auth(struct nc_session *session, struct nc_server_ssh_opts *opts, ssh_message msg,
        int method, const char *str_method, int local_users_supported, struct nc_auth_state *auth_state)
{
    const char *username;
    int ret = 0;
    struct nc_auth_client *auth_client = NULL;
    int first_time = 0;

    /* save the username, do not let the client change it */
    username = ssh_message_auth_user(msg);
    assert(username);

    if (!session->username) {
        session->username = strdup(username);
        NC_CHECK_ERRMEM_RET(!session->username, 1);
        first_time = 1;

        /* send the SSH issue banner on the first userauth request */
        nc_server_ssh_send_banner(session, opts);
    } else if (strcmp(username, session->username)) {
        /* changing username not allowed */
        ERR(session, "User \"%s\" changed its username to \"%s\".", session->username, username);
        session->status = NC_STATUS_INVALID;
        session->term_reason = NC_SESSION_TERM_OTHER;
        nc_server_ssh_auth_attempt_failed(session);
        return 1;
    }

    if (local_users_supported) {
        auth_client = nc_ssh_find_auth_client(opts, username, session);

        if (!auth_client) {
            /* user not known, set his authentication methods to public key only so that
             * there is no interaction and it will simply be denied */
            ERR(session, "User \"%s\" not known by the server.", username);
            ssh_set_auth_methods(session->ti.libssh.session, SSH_AUTH_METHOD_PUBLICKEY);
            nc_server_ssh_auth_attempt_failed(session);
            ssh_message_reply_default(msg);
            return 0;
        }
    }

    if (first_time) {
        /* configure and count accepted auth methods */
        nc_ssh_auth_state_init(session, auth_state, local_users_supported, auth_client);
    }

    /* try authenticating, if local users are supported, then the configured user must authenticate via all of his
     * configured auth methods, otherwise for system users just one is needed,
     * 0 return indicates success, 1 fail (msg not yet replied to), -1 fail (msg was replied to) */
    if (method == SSH_AUTH_METHOD_NONE) {
        ret = nc_server_ssh_msg_auth_none(local_users_supported, auth_client, msg);
    } else if (method == SSH_AUTH_METHOD_PASSWORD) {
        ret = nc_server_ssh_msg_auth_password(session, local_users_supported, auth_client, msg);
    } else if (method == SSH_AUTH_METHOD_PUBLICKEY) {
        ret = nc_server_ssh_msg_auth_pubkey(session, local_users_supported, auth_client, msg);
    } else if (method == SSH_AUTH_METHOD_INTERACTIVE) {
        ret = nc_server_ssh_msg_auth_kbdint(session, local_users_supported, auth_client, msg);
    } else {
        ++session->opts.server.ssh_auth_attempts;
        VRB(session, "Authentication method \"%s\" not supported.", str_method);
        ssh_message_reply_default(msg);
        return 0;
    }

    if (!ret) {
        int success = nc_ssh_auth_success(session, auth_state, method);

        if (success == SSH_AUTH_PARTIAL) {
            ssh_message_auth_reply_success(msg, 1);
        } else {
            ssh_message_auth_reply_success(msg, 0);
        }
    } else if (ret == 1) {
        /* failed attempt, msg wasnt yet replied to */
        nc_server_ssh_auth_attempt_failed(session);
        ssh_message_reply_default(msg);
    }

    return 0;
}

int
nc_session_ssh_msg(struct nc_session *session, struct nc_server_ssh_opts *opts, ssh_message msg, struct nc_auth_state *auth_state)
{
    const char *str_type, *str_subtype = NULL;
    int subtype, type, local_users_supported;

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

        /* check if local-users-supported feature is enabled */
        local_users_supported = nc_ssh_check_local_user_support(session);
        if (local_users_supported < 0) {
            return 1;
        }

        /* authenticate */
        return nc_server_ssh_msg_auth(session, opts, msg, subtype, str_subtype, local_users_supported, auth_state);
    } else if (session->flags & NC_SESSION_SSH_AUTHENTICATED) {
        if ((type == SSH_REQUEST_CHANNEL_OPEN) && ((enum ssh_channel_type_e)subtype == SSH_CHANNEL_SESSION)) {
            if (nc_server_ssh_msg_channel_open(session, msg)) {
                ssh_message_reply_default(msg);
            }
            return 0;

        } else if ((type == SSH_REQUEST_CHANNEL) && ((enum ssh_channel_requests_e)subtype == SSH_CHANNEL_REQUEST_SUBSYSTEM)) {
            if (nc_server_ssh_msg_channel_subsystem(session, ssh_message_channel_request_channel(msg),
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
