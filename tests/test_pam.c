/**
 * @file test_pam.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 SSH Keyboard Interactive auth using PAM test
 *
 * @copyright
 * Copyright (c) 2023 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>

#include <cmocka.h>

#include "ln2_test.h"

int TEST_PORT = 10050;
const char *TEST_PORT_STR = "10050";

/* mock pam_start to just call pam_start_confdir instead */
int __real_pam_start(const char *service_name, const char *user, const struct pam_conv *pam_conversation, pam_handle_t **pamh);
int
__wrap_pam_start(const char *service_name, const char *user, const struct pam_conv *pam_conversation, pam_handle_t **pamh)
{
    return pam_start_confdir(service_name, user, pam_conversation, BUILD_DIR "/tests", pamh);
}

static char *
auth_interactive(const char *UNUSED(auth_name), const char *UNUSED(instruction),
        const char *prompt, int UNUSED(echo), void *UNUSED(priv))
{
    /* send the replies to keyboard-interactive authentication */
    if (strstr(prompt, "backwards")) {
        return strdup("tset");
    } else if (strstr(prompt, "1+1")) {
        return strdup("2");
    } else {
        return NULL;
    }
}

static void *
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username("test");
    assert_int_equal(ret, 0);

    /* set keyboard-interactive authentication callback */
    nc_client_ssh_set_auth_interactive_clb(auth_interactive, NULL);

    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_pam(void **state)
{
    int ret, i;
    pthread_t tids[2];

    assert_non_null(state);

    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static int
setup_f(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    *state = test_ctx;

    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_interactive(test_ctx->ctx, "endpt", "test", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_ssh_set_pam_conf_filename("netconf.conf");
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    lyd_free_all(tree);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_pam, setup_f, ln2_glob_test_teardown)
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
