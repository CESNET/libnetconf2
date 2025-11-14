/**
 * @file test_ssh.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 NETCONF over SSH test
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

#include <cmocka.h>

#include "ln2_test.h"

struct test_ssh_data {
    const char *username;
    const char *pubkey_path;
    const char *privkey_path;
    int check_banner;
    int expect_fail;
};

int TEST_PORT = 10050;
const char *TEST_PORT_STR = "10050";

static char *
auth_password(const char *username, const char *hostname, void *priv)
{
    (void) hostname;
    (void) priv;

    /* set the reply to password authentication */
    if (!strcmp(username, "test_pw")) {
        return strdup("testpw");
    } else {
        return NULL;
    }
}

static void
check_banner(const struct nc_session *session)
{
    const char *banner;

    banner = nc_session_ssh_get_banner(session);
    assert_non_null(banner);

    assert_string_equal(banner, "SSH-2.0-test-banner");
}

static void *
client_thread_ssh(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;
    struct test_ssh_data *test_data = test_ctx->test_data;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username(test_data->username);
    assert_int_equal(ret, 0);

    if (test_data->pubkey_path) {
        ret = nc_client_ssh_add_keypair(test_data->pubkey_path, test_data->privkey_path);
        assert_int_equal(ret, 0);
    } else {
        nc_client_ssh_set_auth_password_clb(auth_password, NULL);
    }

    /* wait for the server to be ready */
    pthread_barrier_wait(&test_ctx->barrier);

    /* connect */
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);

    if (test_data->expect_fail) {
        /* the connection is expected to fail */
        assert_null(session);
        return NULL;
    }

    assert_non_null(session);

    if (test_data->check_banner) {
        check_banner(session);
    }

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_password(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_pw";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_none(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_none";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_rsa_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_pk";
    test_data->pubkey_path = TESTS_DIR "/data/key_rsa.pub";
    test_data->privkey_path = TESTS_DIR "/data/key_rsa";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_ec256_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_ec256";
    test_data->pubkey_path = TESTS_DIR "/data/id_ecdsa256.pub";
    test_data->privkey_path = TESTS_DIR "/data/id_ecdsa256";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_ec384_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_ec384";
    test_data->pubkey_path = TESTS_DIR "/data/id_ecdsa384.pub";
    test_data->privkey_path = TESTS_DIR "/data/id_ecdsa384";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_ec521_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_ec521";
    test_data->pubkey_path = TESTS_DIR "/data/id_ecdsa521.pub";
    test_data->privkey_path = TESTS_DIR "/data/id_ecdsa521";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_ed25519_pubkey(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_ed25519";
    test_data->pubkey_path = TESTS_DIR "/data/id_ed25519.pub";
    test_data->privkey_path = TESTS_DIR "/data/id_ed25519";

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_banner(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ssh_data *test_data = test_ctx->test_data;

    test_data->username = "test_ed25519";
    test_data->pubkey_path = TESTS_DIR "/data/id_ed25519.pub";
    test_data->privkey_path = TESTS_DIR "/data/id_ed25519";
    test_data->check_banner = 1;

    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_transport_params(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ssh_data *test_data = test_ctx->test_data;
    const char *diff;
    char *diff_filled;
    struct lyd_node *tree = NULL;

    /* setup a client */
    test_data->username = "test_pw";

    /* try deleting a MAC alg, none was set before so should fail */
    diff = "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\""
            " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
            "  <listen>\n"
            "    <endpoints>\n"
            "      <endpoint>\n"
            "        <name>endpt</name>\n"
            "        <ssh>\n"
            "          <tcp-server-parameters>\n"
            "            <local-bind>\n"
            "              <local-address>127.0.0.1</local-address>\n"
            "              <local-port>%s</local-port>\n"
            "            </local-bind>\n"
            "          </tcp-server-parameters>\n"
            "          <ssh-server-parameters>\n"
            "            <server-identity>\n"
            "              <host-key>\n"
            "                <name>hostkey</name>\n"
            "                <public-key>\n"
            "                  <inline-definition>\n"
            "                    <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>\n"
            "                    <public-key>AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDRIB2eNSRWU+HNWRUGKr76ghCLg8RaMlUCps9lBjnc6ggaJl2Q+TOLn8se2wAdK3lYBMz3dcqR+SlU7eB8wJAc=</public-key>\n"
            "                    <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ec-private-key-format</private-key-format>\n"
            "                    <cleartext-private-key>MHcCAQEEICQ2fr9Jt2xluom0YQQ7HseE8YTo5reZRVcQENKUWOrooAoGCCqGSM49AwEHoUQDQgAENEgHZ41JFZT4c1ZFQYqvvqCEIuDxFoyVQKmz2UGOdzqCBomXZD5M4ufyx7bAB0reVgEzPd1ypH5KVTt4HzAkBw==</cleartext-private-key>\n"
            "                  </inline-definition>\n"
            "                </public-key>\n"
            "              </host-key>\n"
            "            </server-identity>\n"
            "            <client-authentication>\n"
            "              <users>\n"
            "                <user>\n"
            "                  <name>test_pw</name>\n"
            "                  <password>\n"
            "                    <hashed-password>$0$testpw</hashed-password>\n"
            "                  </password>\n"
            "                </user>\n"
            "              </users>\n"
            "            </client-authentication>\n"
            "            <transport-params>\n"
            "              <mac>\n"
            "                <mac-alg yang:operation=\"delete\">hmac-sha1</mac-alg>\n" // not set before
            "              </mac>\n"
            "            </transport-params>\n"
            "          </ssh-server-parameters>\n"
            "        </ssh>\n"
            "      </endpoint>\n"
            "    </endpoints>\n"
            "  </listen>\n"
            "</netconf-server>\n";

    /* print port number into the diff */
    ret = asprintf(&diff_filled, diff, TEST_PORT_STR);
    assert_int_not_equal(ret, -1);

    ret = lyd_parse_data_mem(test_ctx->ctx, diff_filled, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &tree);
    assert_int_equal(ret, 0);

    /* add implicit nodes */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);

    /* apply the diff, should fail */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 1);

    free(diff_filled);
    lyd_free_all(tree);

    /* set only a RSA host key supported algorithm, even though an ECDSA host key is used */
    diff = "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\""
            " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
            "  <listen>\n"
            "    <endpoints>\n"
            "      <endpoint>\n"
            "        <name>endpt</name>\n"
            "        <ssh>\n"
            "          <tcp-server-parameters>\n"
            "            <local-bind>\n"
            "              <local-address>127.0.0.1</local-address>\n"
            "              <local-port>%s</local-port>\n"
            "            </local-bind>\n"
            "          </tcp-server-parameters>\n"
            "          <ssh-server-parameters>\n"
            "            <server-identity>\n"
            "              <host-key>\n"
            "                <name>hostkey</name>\n"
            "                <public-key>\n"
            "                  <inline-definition>\n"
            "                    <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>\n"
            "                    <public-key>AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDRIB2eNSRWU+HNWRUGKr76ghCLg8RaMlUCps9lBjnc6ggaJl2Q+TOLn8se2wAdK3lYBMz3dcqR+SlU7eB8wJAc=</public-key>\n"
            "                    <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ec-private-key-format</private-key-format>\n"
            "                    <cleartext-private-key>MHcCAQEEICQ2fr9Jt2xluom0YQQ7HseE8YTo5reZRVcQENKUWOrooAoGCCqGSM49AwEHoUQDQgAENEgHZ41JFZT4c1ZFQYqvvqCEIuDxFoyVQKmz2UGOdzqCBomXZD5M4ufyx7bAB0reVgEzPd1ypH5KVTt4HzAkBw==</cleartext-private-key>\n"
            "                  </inline-definition>\n"
            "                </public-key>\n"
            "              </host-key>\n"
            "            </server-identity>\n"
            "            <client-authentication>\n"
            "              <users>\n"
            "                <user>\n"
            "                  <name>test_pw</name>\n"
            "                  <password>\n"
            "                    <hashed-password>$0$testpw</hashed-password>\n"
            "                  </password>\n"
            "                </user>\n"
            "              </users>\n"
            "            </client-authentication>\n"
            "            <transport-params>\n"
            "              <host-key>\n"
            "                <host-key-alg yang:operation=\"create\">ecdsa-sha2-nistp384</host-key-alg>\n" // restrict to ECDSA
            "              </host-key>\n"
            "            </transport-params>\n"
            "          </ssh-server-parameters>\n"
            "        </ssh>\n"
            "      </endpoint>\n"
            "    </endpoints>\n"
            "  </listen>\n"
            "</netconf-server>\n";

    /* print port number into the diff */
    ret = asprintf(&diff_filled, diff, TEST_PORT_STR);
    assert_int_not_equal(ret, -1);

    ret = lyd_parse_data_mem(test_ctx->ctx, diff_filled, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &tree);
    assert_int_equal(ret, 0);

    /* add implicit nodes */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);

    /* apply the diff, should succeed */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    /* create client and server threads, the client should not be able to connect if the server
    * transport parameters are applied correctly */
    test_data->expect_fail = 1;
    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread_fail, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    test_data->expect_fail = 0;
    free(diff_filled);
    lyd_free_all(tree);

    /* unset the host key algorithm restriction, since there should be no algs set now,
     * the default ones will be used and the client should be able to connect */
    diff = "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\""
            " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
            "  <listen>\n"
            "    <endpoints>\n"
            "      <endpoint>\n"
            "        <name>endpt</name>\n"
            "        <ssh>\n"
            "          <tcp-server-parameters>\n"
            "            <local-bind>\n"
            "              <local-address>127.0.0.1</local-address>\n"
            "              <local-port>%s</local-port>\n"
            "            </local-bind>\n"
            "          </tcp-server-parameters>\n"
            "          <ssh-server-parameters>\n"
            "            <server-identity>\n"
            "              <host-key>\n"
            "                <name>hostkey</name>\n"
            "                <public-key>\n"
            "                  <inline-definition>\n"
            "                    <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>\n"
            "                    <public-key>AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDRIB2eNSRWU+HNWRUGKr76ghCLg8RaMlUCps9lBjnc6ggaJl2Q+TOLn8se2wAdK3lYBMz3dcqR+SlU7eB8wJAc=</public-key>\n"
            "                    <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ec-private-key-format</private-key-format>\n"
            "                    <cleartext-private-key>MHcCAQEEICQ2fr9Jt2xluom0YQQ7HseE8YTo5reZRVcQENKUWOrooAoGCCqGSM49AwEHoUQDQgAENEgHZ41JFZT4c1ZFQYqvvqCEIuDxFoyVQKmz2UGOdzqCBomXZD5M4ufyx7bAB0reVgEzPd1ypH5KVTt4HzAkBw==</cleartext-private-key>\n"
            "                  </inline-definition>\n"
            "                </public-key>\n"
            "              </host-key>\n"
            "            </server-identity>\n"
            "            <client-authentication>\n"
            "              <users>\n"
            "                <user>\n"
            "                  <name>test_pw</name>\n"
            "                  <password>\n"
            "                    <hashed-password>$0$testpw</hashed-password>\n"
            "                  </password>\n"
            "                </user>\n"
            "              </users>\n"
            "            </client-authentication>\n"
            "            <transport-params>\n"
            "              <host-key>\n"
            "                <host-key-alg yang:operation=\"delete\">ecdsa-sha2-nistp384</host-key-alg>\n" // remove restriction
            "              </host-key>\n"
            "            </transport-params>\n"
            "          </ssh-server-parameters>\n"
            "        </ssh>\n"
            "      </endpoint>\n"
            "    </endpoints>\n"
            "  </listen>\n"
            "</netconf-server>\n";

    /* print port number into the diff */
    ret = asprintf(&diff_filled, diff, TEST_PORT_STR);
    assert_int_not_equal(ret, -1);

    ret = lyd_parse_data_mem(test_ctx->ctx, diff_filled, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &tree);
    assert_int_equal(ret, 0);

    /* add implicit nodes */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);

    /* apply the diff, should succeed */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    /* create client and server threads, the client should be able to connect now */
    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    free(diff_filled);
    lyd_free_all(tree);

    /* set "reasonable" (= should be able to connect) transport parameters, overwriting the libssh defaults */
    diff = "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\""
            " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
            "  <listen>\n"
            "    <endpoints>\n"
            "      <endpoint>\n"
            "        <name>endpt</name>\n"
            "        <ssh>\n"
            "          <tcp-server-parameters>\n"
            "            <local-bind>\n"
            "              <local-address>127.0.0.1</local-address>\n"
            "              <local-port>%s</local-port>\n"
            "            </local-bind>\n"
            "          </tcp-server-parameters>\n"
            "          <ssh-server-parameters>\n"
            "            <server-identity>\n"
            "              <host-key>\n"
            "                <name>hostkey</name>\n"
            "                <public-key>\n"
            "                  <inline-definition>\n"
            "                    <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>\n"
            "                    <public-key>AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDRIB2eNSRWU+HNWRUGKr76ghCLg8RaMlUCps9lBjnc6ggaJl2Q+TOLn8se2wAdK3lYBMz3dcqR+SlU7eB8wJAc=</public-key>\n"
            "                    <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ec-private-key-format</private-key-format>\n"
            "                    <cleartext-private-key>MHcCAQEEICQ2fr9Jt2xluom0YQQ7HseE8YTo5reZRVcQENKUWOrooAoGCCqGSM49AwEHoUQDQgAENEgHZ41JFZT4c1ZFQYqvvqCEIuDxFoyVQKmz2UGOdzqCBomXZD5M4ufyx7bAB0reVgEzPd1ypH5KVTt4HzAkBw==</cleartext-private-key>\n"
            "                  </inline-definition>\n"
            "                </public-key>\n"
            "              </host-key>\n"
            "            </server-identity>\n"
            "            <client-authentication>\n"
            "              <users>\n"
            "                <user>\n"
            "                  <name>test_pw</name>\n"
            "                  <password>\n"
            "                    <hashed-password>$0$testpw</hashed-password>\n"
            "                  </password>\n"
            "                </user>\n"
            "              </users>\n"
            "            </client-authentication>\n"
            "            <transport-params yang:operation=\"create\">\n"
            "              <host-key>\n"
            "                <host-key-alg>ecdsa-sha2-nistp256</host-key-alg>\n"
            "              </host-key>\n"
            "              <key-exchange>\n"
            "                <key-exchange-alg>curve25519-sha256</key-exchange-alg>\n"
            "              </key-exchange>\n"
            "              <encryption>\n"
            "                <encryption-alg>aes256-ctr</encryption-alg>\n"
            "              </encryption>\n"
            "              <mac>\n"
            "                <mac-alg>hmac-sha2-512</mac-alg>\n"
            "              </mac>\n"
            "            </transport-params>\n"
            "          </ssh-server-parameters>\n"
            "        </ssh>\n"
            "      </endpoint>\n"
            "    </endpoints>\n"
            "  </listen>\n"
            "</netconf-server>\n";

    /* print port number into the diff */
    ret = asprintf(&diff_filled, diff, TEST_PORT_STR);
    assert_int_not_equal(ret, -1);

    ret = lyd_parse_data_mem(test_ctx->ctx, diff_filled, LYD_XML, LYD_PARSE_ONLY | LYD_PARSE_STRICT, 0, &tree);
    assert_int_equal(ret, 0);

    /* add implicit nodes */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);

    /* apply the diff, should succeed */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    /* create client and server threads, the client should be able to connect now */
    ret = pthread_create(&tids[0], NULL, client_thread_ssh, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    free(diff_filled);
    lyd_free_all(tree);
}

static int
setup_ssh(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx;
    struct test_ssh_data *test_data;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    test_data = calloc(1, sizeof *test_data);
    assert_non_null(test_data);

    test_ctx->test_data = test_data;
    test_ctx->free_test_data = ln2_glob_test_free_test_data;
    *state = test_ctx;

    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa", NULL, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_pk", "pubkey", TESTS_DIR "/data/key_rsa.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_ec256", "pubkey", TESTS_DIR "/data/id_ecdsa256.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_ec384", "pubkey", TESTS_DIR "/data/id_ecdsa384.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_ec521", "pubkey", TESTS_DIR "/data/id_ecdsa521.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_pubkey(test_ctx->ctx, "endpt", "test_ed25519", "pubkey", TESTS_DIR "/data/id_ed25519.pub", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ssh_user_password(test_ctx->ctx, "endpt", "test_pw", "testpw", &tree);
    assert_int_equal(ret, 0);

    ret = lyd_new_path(tree, test_ctx->ctx, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='endpt']/ssh/"
            "ssh-server-parameters/server-identity/libnetconf2-netconf-server:banner", "test-banner", 0, NULL);
    assert_int_equal(ret, 0);

    ret = lyd_new_path(tree, test_ctx->ctx, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='endpt']/ssh/"
            "ssh-server-parameters/client-authentication/users/user[name='test_none']/none", NULL, 0, NULL);
    assert_int_equal(ret, 0);

    /* add all the default nodes/np containers */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
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
        cmocka_unit_test_setup_teardown(test_password, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_none, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_rsa_pubkey, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_ec256_pubkey, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_ec384_pubkey, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_ec521_pubkey, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_ed25519_pubkey, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_banner, setup_ssh, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_transport_params, setup_ssh, ln2_glob_test_teardown),
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
