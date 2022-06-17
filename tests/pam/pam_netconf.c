/**
 * @file pam_netconf.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 keyboard-interactive authentication PAM module
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

/* required to be able to use some functions declared in the pam_modules.h header file */
#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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
nc_pam_mod_auth(const char* username, char *reversed_username, char *eq_ans)
{
	int i, j = 0;
	int len = strlen(reversed_username);
	char *buffer = calloc(len + 1, sizeof *buffer);

	/* reverse the user's response */
	for (i = len - 1; i >= 0; i--) {
		buffer[j++] = reversed_username[i];
	}
	buffer[j] = '\0';

	if (!strcmp(username, buffer) && !strcmp(eq_ans, "2")) {
		/* it's a match */
		free(buffer);
		return PAM_SUCCESS;
	} else {
		free(buffer);
		return PAM_AUTH_ERR;
	}
}

/**
 * @brief Free and erase the user's responses.
 *
 * @param[in] resp Responses.
 * @param[in] n The number of responses to be free'd.
 */
static void
nc_pam_mod_resp_free(struct pam_response *resp, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		bzero((resp + i)->resp, strlen((resp + i)->resp));
		free((resp + i)->resp);
	}
	free(resp);
}

/**
 * @brief _main_ function of the module, meaning it gets called first whenever
 * this module is invoked. The prompts for the user are prepared and based on his
 * answers decide whether to allow or disallow access.
 *
 * @param[in] pam_h PAM handle.
 * @param[in] flags Logically OR'd flags.
 * @param[in] argc The count of module options defined in the PAM configuration.
 * @param[in] argv Module options.
 * @return PAM_SUCCESS on success;
 * @return PAM error otherwise.
 */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pam_h, int flags, int argc, const char **argv)
{
	int i, r = PAM_SUCCESS, status;
	const char *username;
	char *reversed_username = NULL, *eq_ans = NULL;
	struct pam_message msg[N_MESSAGES];
	const struct pam_message **msgp;
	struct pam_response *resp;

	(void) flags;
	(void) argc;
	(void) argv;

	/* get the username and if it's not known then the user will be prompted to enter it */
	if (pam_get_user(pam_h, &username, NULL) != PAM_SUCCESS) {
		fprintf(stderr, "Unable to get username.\n");
		return PAM_AUTHINFO_UNAVAIL;
	}

	/* prepare the messages */
	msg[0].msg_style = PAM_PROMPT_ECHO_ON;
	msg[0].msg = "Enter your username backwards: ";
	msg[1].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[1].msg = "Enter the result to 1+1: ";

	msgp = malloc(N_MESSAGES * sizeof **msgp);
	if (!msgp) {
		fprintf(stderr, "Memory allocation error.\n");
		r = PAM_BUF_ERR;
		goto cleanup;
	}

	/* store the messages */
	for (i = 0; i < N_MESSAGES; i++) {
		msgp[i] = &msg[i];
	}

	/* get responses */
	r = nc_pam_mod_call_clb(pam_h, N_MESSAGES, msgp, &resp);
	if (r != PAM_SUCCESS || !resp) {
		goto cleanup;
	}

	/* go through the responses and return an error if one is missing */
	for (i = 0; i < N_REQUESTS; i++) {
		if (!resp[i].resp) {
			fprintf(stderr, "No response.\n");
			nc_pam_mod_resp_free(resp, i);
			r = PAM_AUTH_ERR;
			goto cleanup;
		}

		if (i == 0) {
			reversed_username = resp[i].resp;
		}
		if (i == 1) {
			eq_ans = resp[i].resp;
		}
	}

	/* validate the reponses */
	status = nc_pam_mod_auth(username, reversed_username, eq_ans);

	/* free the responses */
	nc_pam_mod_resp_free(resp, i);

	/* not authenticated */
	if (status != PAM_SUCCESS) {
		r = PAM_MAXTRIES;
	}

cleanup:
	free(msgp);
	return r;
}
