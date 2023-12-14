/**
 * @file pam_netconf.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 Linux PAM test module
 *
 * @copyright
 * Copyright (c) 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#define N_MESSAGES 2
#define N_REQUESTS 2

/**
 * @brief Exchange module's messages for user's replies.
 *
 * @param[in] pam_h PAM handle.
 * @param[in] n_messages Number of messages.
 * @param[in] msg Module's messages for the user.
 * @param[out] resp User's responses.
 * @return PAM_SUCCESS on success;
 * @return PAM error otherwise.
 */
static int
nc_pam_mod_call_clb(pam_handle_t *pam_h, int n_messages, const struct pam_message **msg, struct pam_response **resp)
{
    struct pam_conv *conv;
    int r;

    /* the callback can be accessed through the handle */
    r = pam_get_item(pam_h, PAM_CONV, (void *) &conv);
    if (r != PAM_SUCCESS) {
        return r;
    }
    return conv->conv(n_messages, msg, resp, conv->appdata_ptr);
}

/**
 * @brief Validate the user's responses.
 *
 * @param[in] username Username.
 * @param[in] reversed_username User's response to the first challenge.
 * @param[in] eq_ans User's response to the second challenge.
 * @return PAM_SUCCESS on success;
 * @return PAM_AUTH_ERR whenever the user's replies are incorrect.
 */
static int
nc_pam_mod_auth(const char *username, char *reversed_username, char *eq_ans)
{
    int i, j, r;
    size_t len;
    char *buffer;

    len = strlen(reversed_username);
    buffer = calloc(len + 1, sizeof *buffer);
    if (!buffer) {
        fprintf(stderr, "Memory allocation error.\n");
        return PAM_BUF_ERR;
    }

    /* reverse the user's response */
    for (i = len - 1, j = 0; i >= 0; i--) {
        buffer[j++] = reversed_username[i];
    }
    buffer[j] = '\0';

    if (!strcmp(username, buffer) && !strcmp(eq_ans, "2")) {
        /* it's a match */
        r = PAM_SUCCESS;
    } else {
        r = PAM_AUTH_ERR;
    }

    free(buffer);
    return r;
}

/**
 * @brief Free the user's responses.
 *
 * @param[in] resp Responses.
 * @param[in] n Number of responses to be freed.
 */
static void
nc_pam_mod_resp_free(struct pam_response *resp, int n)
{
    int i;

    if (!resp) {
        return;
    }

    for (i = 0; i < n; i++) {
        free((resp + i)->resp);
    }
    free(resp);
}

/**
 * @brief Test module's implementation of "auth" service.
 *
 * Prepare prompts for the client and decide based on his
 * answers whether to allow or disallow access.
 *
 * @param[in] pam_h PAM handle.
 * @param[in] flags Flags.
 * @param[in] argc Count of module options defined in the PAM configuration file.
 * @param[in] argv Module options.
 * @return PAM_SUCCESS on success;
 * @return PAM error otherwise.
 */
API int
pam_sm_authenticate(pam_handle_t *pam_h, int flags, int argc, const char **argv)
{
    int r;
    const char *username;
    char *reversed_username = NULL, *eq_ans = NULL;
    struct pam_message echo_msg, no_echo_msg, unexpected_type_msg, info_msg, err_msg;
    const struct pam_message *msg[N_MESSAGES];
    struct pam_response *resp = NULL;

    (void) flags;
    (void) argc;
    (void) argv;

    /* get the username and if it's not known then the user will be prompted to enter it */
    r = pam_get_user(pam_h, &username, NULL);
    if (r != PAM_SUCCESS) {
        fprintf(stderr, "Unable to get username.\n");
        r = PAM_AUTHINFO_UNAVAIL;
        goto cleanup;
    }

    /* prepare the messages */
    echo_msg.msg_style = PAM_PROMPT_ECHO_ON;
    echo_msg.msg = "Enter your username backwards: ";
    no_echo_msg.msg_style = PAM_PROMPT_ECHO_OFF;
    no_echo_msg.msg = "Enter the result to 1+1: ";
    unexpected_type_msg.msg_style = PAM_AUTH_ERR;
    unexpected_type_msg.msg = "Arbitrary test message";
    info_msg.msg_style = PAM_TEXT_INFO;
    info_msg.msg = "Test info message";
    err_msg.msg_style = PAM_ERROR_MSG;
    err_msg.msg = "Test error message";

    /* tests */
    printf("[TEST #1] Too many PAM messages. Output:\n");
    r = nc_pam_mod_call_clb(pam_h, 500, msg, &resp);
    if (r == PAM_SUCCESS) {
        fprintf(stderr, "[TEST #1] Failed.\n");
        r = PAM_AUTH_ERR;
        goto cleanup;
    }
    printf("[TEST #1] Passed.\n\n");

    printf("[TEST #2] Negative number of PAM messages. Output:\n");
    r = nc_pam_mod_call_clb(pam_h, -1, msg, &resp);
    if (r == PAM_SUCCESS) {
        fprintf(stderr, "[TEST #2] Failed.\n");
        r = PAM_AUTH_ERR;
        goto cleanup;
    }
    printf("[TEST #2] Passed.\n\n");

    printf("[TEST #3] 0 PAM messages. Output:\n");
    r = nc_pam_mod_call_clb(pam_h, 0, msg, &resp);
    if (r == PAM_SUCCESS) {
        fprintf(stderr, "[TEST #3] Failed.\n");
        r = PAM_AUTH_ERR;
        goto cleanup;
    }
    printf("[TEST #3] Passed.\n\n");

    printf("[TEST #4] Unexpected message type. Output:\n");
    msg[0] = &unexpected_type_msg;
    r = nc_pam_mod_call_clb(pam_h, N_MESSAGES, msg, &resp);
    if (r == PAM_SUCCESS) {
        fprintf(stderr, "[TEST #4] Failed.\n");
        r = PAM_AUTH_ERR;
        goto cleanup;
    }
    printf("[TEST #4] Passed.\n\n");

    printf("[TEST #5] Info and error messages. Output:\n");
    msg[0] = &info_msg;
    msg[1] = &err_msg;
    r = nc_pam_mod_call_clb(pam_h, N_MESSAGES, msg, &resp);
    if (r == PAM_SUCCESS) {
        fprintf(stderr, "[TEST #5] Failed.\n");
        r = PAM_AUTH_ERR;
        goto cleanup;
    }
    printf("[TEST #5] Passed.\n\n");

    printf("[TEST #6] Authentication attempt with an expired token. Output:\n");
    /* store the correct messages */
    msg[0] = &echo_msg;
    msg[1] = &no_echo_msg;

    /* get responses */
    r = nc_pam_mod_call_clb(pam_h, N_MESSAGES, msg, &resp);
    if (r != PAM_SUCCESS) {
        fprintf(stderr, "[TEST #6] Failed.\n");
        goto cleanup;
    }

    reversed_username = resp[0].resp;
    eq_ans = resp[1].resp;

    /* validate the responses */
    r = nc_pam_mod_auth(username, reversed_username, eq_ans);

    /* not authenticated */
    if (r != PAM_SUCCESS) {
        fprintf(stderr, "[TEST #6] Failed.\n");
        r = PAM_AUTH_ERR;
    }

cleanup:
    /* free the responses */
    nc_pam_mod_resp_free(resp, N_REQUESTS);
    return r;
}

/**
 * @brief Test module's silly implementation of "account" service.
 *
 * @param[in] pam_h PAM handle.
 * @param[in] flags Flags.
 * @param[in] argc The count of module options defined in the PAM configuration file.
 * @param[in] argv Module options.
 * @return PAM_NEW_AUTHTOK_REQD on success;
 * @return PAM error otherwise.
 */
API int
pam_sm_acct_mgmt(pam_handle_t *pam_h, int flags, int argc, const char *argv[])
{
    int r;
    const void *username;

    (void) flags;
    (void) argc;
    (void) argv;

    /* get and check the username */
    r = pam_get_item(pam_h, PAM_USER, &username);
    if (r != PAM_SUCCESS) {
        return r;
    }
    if (!strcmp((const char *)username, "test")) {
        return PAM_NEW_AUTHTOK_REQD;
    }
    return PAM_SYSTEM_ERR;
}

/**
 * @brief Test module's silly implementation of "password" service.
 *
 * @param[in] pam_h PAM handle.
 * @param[in] flags Flags.
 * @param[in] argc The count of module options defined in the PAM configuration file.
 * @param[in] argv Module options.
 * @return PAM_SUCCESS on success;
 * @return PAM error otherwise.
 */
API int
pam_sm_chauthtok(pam_handle_t *pam_h, int flags, int argc, const char *argv[])
{
    int r;
    const void *username;

    (void) argc;
    (void) argv;

    /* the function is called twice, each time with a different flag,
     * in the first call just check the username if it matches */
    if (flags & PAM_PRELIM_CHECK) {
        r = pam_get_item(pam_h, PAM_USER, &username);
        if (r != PAM_SUCCESS) {
            return r;
        }
        if (!strcmp((const char *)username, "test")) {
            return PAM_SUCCESS;
        } else {
            return PAM_SYSTEM_ERR;
        }

        /* change the authentication token in the second call */
    } else if (flags & PAM_UPDATE_AUTHTOK) {
        r = pam_set_item(pam_h, PAM_AUTHTOK, "test");
        if (r == PAM_SUCCESS) {
            printf("[TEST #6] Passed.\n\n");
        } else {
            fprintf(stderr, "[TEST #6] Failed.\n");
        }
        return r;
    }
    return PAM_SYSTEM_ERR;
}
