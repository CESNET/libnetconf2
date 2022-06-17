/**
 * @file test_pam.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 Linux PAM keyboard-interactive authentication test
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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>
#include <log.h>
#include <session_client.h>
#include <session_server.h>
#include "tests/config.h"

#define nc_assert(cond) if (!(cond)) { fprintf(stderr, "assert failed (%s:%d)\n", __FILE__, __LINE__); abort(); }

#define NC_ACCEPT_TIMEOUT 5000

struct ly_ctx *ctx;

static void *
server_thread(void *arg)
{
    (void) arg;
    NC_MSG_TYPE msgtype;
    struct nc_session *session;

    /* accept a session and check if it went well */
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, ctx, &session);
    nc_assert(msgtype == NC_MSG_HELLO);

    /* free the session before the client receives a reply to a close-session RPC, hence a warning message */
    nc_session_free(session, NULL);
    nc_thread_destroy();
    return NULL;
}

static int
clb_hostkeys(const char *name, void *user_data, char **privkey_path, char **privkey_data,
        NC_SSH_KEY_TYPE *privkey_type)
{
    (void) user_data;
    (void) privkey_data;
    (void) privkey_type;

    /* set the path to the testing private keys */
    if (!strcmp(name, "key_rsa")) {
        *privkey_path = strdup(TESTS_DIR "/data/key_rsa");
        return 0;
    } else if (!strcmp(name, "key_dsa")) {
        *privkey_path = strdup(TESTS_DIR "/data/key_dsa");
        return 0;
    }

    return 1;
}

static char *
auth_interactive(const char *auth_name, const char *instruction, const char *prompt, int echo, void *priv)
{
    (void) instruction;
    (void) echo;
    (void) auth_name;
    (void) priv;

    /* set the replies to keyboard-interactive authentication */
    if (strstr(prompt, "backwards")) {
        return strdup("tset");
    } else if (strstr(prompt, "1+1")) {
        return strdup("2");
    } else {
        return NULL;
    }
}

static int
ssh_hostkey_check_clb(const char *hostname, ssh_session session, void *priv)
{
    (void)hostname;
    (void)session;
    (void)priv;

    return 0;
}

static void *
client_thread(void *arg)
{
    (void) arg;
    int ret;
    struct nc_session *session = NULL;

    nc_client_init();
    ret = nc_client_set_schema_searchpath(TESTS_DIR "/data/modules");
    nc_assert(!ret);
    /* skip the knownhost check */
    nc_client_ssh_set_auth_hostkey_check_clb(ssh_hostkey_check_clb, NULL);

    ret = nc_client_ssh_set_username("test");
    nc_assert(!ret);

    /* set keyboard-interactive authentication callback */
    nc_client_ssh_set_auth_interactive_clb(auth_interactive, NULL);
    session = nc_connect_ssh("0.0.0.0", 6001, NULL);
    nc_assert(session);

    fprintf(stdout, "SSH client finished.\n");
    nc_session_free(session, NULL);
    nc_client_destroy();
    nc_thread_destroy();
    return NULL;
}

int
main()
{
    int ret, i;
    pthread_t tids[2];

    ly_ctx_new(TESTS_DIR "/data/modules", 0, &ctx);
    nc_assert(ctx);
    ly_ctx_load_module(ctx, "ietf-netconf", NULL, NULL);

    nc_server_init();

    /* set callback */
    nc_server_ssh_set_hostkey_clb(clb_hostkeys, NULL, NULL);

    /* do first, so that client can connect on SSH */
    ret = nc_server_add_endpt("main_ssh", NC_TI_LIBSSH);
    nc_assert(!ret);
    ret = nc_server_endpt_set_address("main_ssh", "0.0.0.0");
    nc_assert(!ret);
    ret = nc_server_endpt_set_port("main_ssh", 6001);
    nc_assert(!ret);
    ret = nc_server_ssh_endpt_add_hostkey("main_ssh", "key_rsa", -1);
    nc_assert(!ret);

    /* in order to use the Linux PAM keyboard-interactive method,
     * the PAM module has to know where to find the desired configuration file */
    nc_server_ssh_set_pam_conf_path("netconf.conf", PAM_CONF_DIR);
    ret = nc_server_ssh_endpt_set_auth_methods("main_ssh", NC_SSH_AUTH_INTERACTIVE);
    nc_assert(!ret);

    ret = pthread_create(&tids[0], NULL, client_thread, NULL);
    nc_assert(!ret);
    ret = pthread_create(&tids[1], NULL, server_thread, NULL);
    nc_assert(!ret);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    nc_server_destroy();
    ly_ctx_destroy(ctx);
    return 0;
}
