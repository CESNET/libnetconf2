/**
 * @file test_system_users.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 SSH authentication of system users (local-users-supported feature disabled)
 *
 * @copyright
 * Copyright (c) 2026 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <pthread.h>
#include <pwd.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "ln2_test.h"

/** @brief Name of the mocked system user. */
#define SYS_USER "ln2_sys_user"

/** @brief Password of the mocked system user. */
#define SYS_USER_PW "syspassword"

/** @brief SHA-512 crypt hash of ::SYS_USER_PW, stored in the mocked system user's passwd entry. */
#define SYS_USER_PW_HASH \
    "$6$ln2salt$cKBKymtK/vE6aRV7D/v6IYhVRD4FgVi.qTV2B/KegQAecVzpN.gz9OEJSiQFWAYMGWkmsrGNNAX0HC3bjkggV."

struct test_sys_users_data {
    const char *pubkey_path;    /**< Client's public key, password authentication is used if not set. */
    const char *privkey_path;   /**< Client's private key. */
    const char *password;       /**< Password sent by the client. */
    int expect_fail;            /**< Whether the authentication is expected to fail. */
};

int TEST_PORT = 10050;
const char *TEST_PORT_STR = "10050";

/* mock getpwnam_r to make SYS_USER a system user with its password hash stored directly in its passwd entry,
 * linked shared libraries reference getpwnam_r too, so the wrapper must not be hidden for the linker to accept it */
int __real_getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result);
__attribute__((visibility("default"))) int
__wrap_getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result)
{
    if (strcmp(name, SYS_USER)) {
        return __real_getpwnam_r(name, pwd, buf, buflen, result);
    }

    memset(pwd, 0, sizeof *pwd);
    pwd->pw_name = (char *)SYS_USER;
    pwd->pw_passwd = (char *)SYS_USER_PW_HASH;
    pwd->pw_uid = 4242;
    pwd->pw_gid = 4242;
    pwd->pw_gecos = (char *)"";
    pwd->pw_dir = (char *)"/nonexistent";
    pwd->pw_shell = (char *)"/bin/false";
    *result = pwd;
    return 0;
}

static char *
auth_password(const char *UNUSED(username), const char *UNUSED(hostname), void *priv)
{
    struct test_sys_users_data *test_data = priv;

    return strdup(test_data->password);
}

static void *
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;
    struct test_sys_users_data *test_data = test_ctx->test_data;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username(SYS_USER);
    assert_int_equal(ret, 0);

    /* the server offers all the methods to system users, use only the tested one */
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, -1);
    if (test_data->pubkey_path) {
        nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, -1);
        ret = nc_client_ssh_add_keypair(test_data->pubkey_path, test_data->privkey_path);
        assert_int_equal(ret, 0);
    } else {
        nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, -1);
        nc_client_ssh_set_auth_password_clb(auth_password, test_data);
    }

    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    if (test_data->expect_fail) {
        assert_null(session);
    } else {
        assert_non_null(session);
    }

    nc_session_free(session, NULL);
    return NULL;
}

/**
 * @brief Connect a client to the server and wait for both of them to finish.
 *
 * @param[in] test_ctx Test context.
 */
static void
run_client_server(struct ln2_test_ctx *test_ctx)
{
    int ret, i;
    pthread_t tids[2];
    struct test_sys_users_data *test_data = test_ctx->test_data;

    ret = pthread_create(&tids[0], NULL, client_thread, test_ctx);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, test_data->expect_fail ? ln2_glob_test_server_thread_fail :
            ln2_glob_test_server_thread, test_ctx);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_local_users_disabled(void **state)
{
    struct ln2_test_ctx *test_ctx = *state;
    struct lys_module *mod;

    /* make sure the feature is really disabled, so the system users are authenticated */
    mod = ly_ctx_get_module_implemented(test_ctx->ctx, "ietf-ssh-server");
    assert_non_null(mod);
    assert_int_equal(lys_feature_value(mod, "local-users-supported"), LY_ENOT);
}

static void
test_pubkey(void **state)
{
    struct ln2_test_ctx *test_ctx = *state;
    struct test_sys_users_data *test_data = test_ctx->test_data;

    /* the key is in the authorized_keys file */
    test_data->pubkey_path = TESTS_DIR "/data/id_ed25519.pub";
    test_data->privkey_path = TESTS_DIR "/data/id_ed25519";
    test_data->expect_fail = 0;

    run_client_server(test_ctx);
}

static void
test_pubkey_bad_key(void **state)
{
    struct ln2_test_ctx *test_ctx = *state;
    struct test_sys_users_data *test_data = test_ctx->test_data;

    /* the key is not in the authorized_keys file */
    test_data->pubkey_path = TESTS_DIR "/data/id_ecdsa521.pub";
    test_data->privkey_path = TESTS_DIR "/data/id_ecdsa521";
    test_data->expect_fail = 1;

    run_client_server(test_ctx);
}

#ifdef HAVE_SHADOW

static void
test_password(void **state)
{
    struct ln2_test_ctx *test_ctx = *state;
    struct test_sys_users_data *test_data = test_ctx->test_data;

    test_data->password = SYS_USER_PW;
    test_data->expect_fail = 0;

    run_client_server(test_ctx);
}

static void
test_password_bad(void **state)
{
    struct ln2_test_ctx *test_ctx = *state;
    struct test_sys_users_data *test_data = test_ctx->test_data;

    test_data->password = "wrongpassword";
    test_data->expect_fail = 1;

    run_client_server(test_ctx);
}

#endif /* HAVE_SHADOW */

static int
setup_f(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx;
    struct test_sys_users_data *test_data;
    struct lys_module *mod;
    const char *no_features[] = {NULL};

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    test_data = calloc(1, sizeof *test_data);
    assert_non_null(test_data);

    test_ctx->test_data = test_data;
    test_ctx->free_test_data = ln2_glob_test_free_test_data;
    *state = test_ctx;

    /* disable local-users-supported, all the other ietf-ssh-server features depend on it */
    mod = ly_ctx_get_module_implemented(test_ctx->ctx, "ietf-ssh-server");
    assert_non_null(mod);
    ret = lys_set_implemented(mod, no_features);
    assert_int_equal(ret, LY_SUCCESS);

    /* no tokens in the path, so the keys are read without looking up the user */
    ret = nc_server_ssh_set_authkey_path_format(TESTS_DIR "/data/authorized_keys");
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data, there are no users to configure */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    lyd_free_all(tree);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_local_users_disabled, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_pubkey, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_pubkey_bad_key, setup_f, ln2_glob_test_teardown),
#ifdef HAVE_SHADOW
        cmocka_unit_test_setup_teardown(test_password, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_password_bad, setup_f, ln2_glob_test_teardown),
#endif
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
