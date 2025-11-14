/**
 * @file test_tls.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 TLS authentication test
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

#include <pthread.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_MBEDTLS
#include <mbedtls/ssl_ciphersuites.h>
#endif /* HAVE_MBEDTLS */

#include <cmocka.h>

#include "ln2_test.h"

#define KEYLOG_FILENAME "ln2_test_tls_keylog.txt"

struct test_tls_data {
    struct lyd_node *tree;      /**< Test data for the server configuration. */
    int root_ca;                /**< Whether the root CA is used (client-only). */
    int intermediate_ca;        /**< Whether the intermediate CA is used (client-only). */
    int expect_fail;            /**< Whether the connection is expected to fail. */
};

int TEST_PORT = 10050;
const char *TEST_PORT_STR = "10050";

static void *
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;
    struct test_tls_data *test_data = test_ctx->test_data;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set client cert */
    ret = nc_client_tls_set_cert_key_paths(TESTS_DIR "/data/client.crt", TESTS_DIR "/data/client.key");
    assert_int_equal(ret, 0);

    /* set client ca */
    ret = nc_client_tls_set_trusted_ca_paths(NULL, TESTS_DIR "/data");
    assert_int_equal(ret, 0);

    pthread_barrier_wait(&test_ctx->barrier);
    session = nc_connect_tls("127.0.0.1", TEST_PORT, NULL);

    if (test_data->expect_fail) {
        /* the connection is expected to fail */
        assert_null(session);
        return NULL;
    }

    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_tls(void **state)
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

static void
test_nc_tls_ca_cert_only(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_tls_data *test_data = test_ctx->test_data;

    /* delete a client certificate so that only CA certs are used */
    assert_int_equal(nc_server_config_del_tls_client_cert("endpt",
            "client_cert", &test_data->tree), 0);

    /* apply the configuration */
    assert_int_equal(nc_server_config_setup_data(test_data->tree), 0);

    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_tls_ee_cert_only(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_tls_data *test_data = test_ctx->test_data;

    /* delete a CA certificate so that only end entity client cert is used */
    assert_int_equal(nc_server_config_del_tls_ca_cert("endpt",
            "client_ca", &test_data->tree), 0);

    /* apply the configuration */
    assert_int_equal(nc_server_config_setup_data(test_data->tree), 0);

    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void *
client_thread_intermediate_ca(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;
    struct test_tls_data *test_data = test_ctx->test_data;

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set client cert */
    ret = nc_client_tls_set_cert_key_paths(TESTS_DIR "/data/certs/client.pem", TESTS_DIR "/data/certs/client.key");
    assert_int_equal(ret, 0);

    if (test_data->root_ca && test_data->intermediate_ca) {
        /* set the dir with the root and intermediate CAs */
        ret = nc_client_tls_set_trusted_ca_paths(NULL, TESTS_DIR "/data/certs");
    } else if (test_data->root_ca) {
        /* set the root CA */
        ret = nc_client_tls_set_trusted_ca_paths(TESTS_DIR "/data/certs/rootca.pem", NULL);
    } else if (test_data->intermediate_ca) {
        /* set the intermediate CA */
        ret = nc_client_tls_set_trusted_ca_paths(TESTS_DIR "/data/certs/intermediate_ca.pem", NULL);
    }

    pthread_barrier_wait(&test_ctx->barrier);

    session = nc_connect_tls("localhost", TEST_PORT, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_nc_tls_intermediate_ca_server(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_tls_data *test_data = test_ctx->test_data;

    printf("\nINTERMEDIATE CA ALL\n\n");

    /* all certs are set */
    test_data->root_ca = 1;
    test_data->intermediate_ca = 1;
    ret = pthread_create(&tids[0], NULL, client_thread_intermediate_ca, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);
    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

#ifndef HAVE_MBEDTLS
    /* this use case is not supported by mbedTLS, so skip it for now */

    printf("\nINTERMEDIATE CA ROOT ONLY\n\n");

    /* delete server's intermediate CA */
    assert_int_equal(nc_server_config_del_tls_ca_cert("endpt",
            "intermediate_ca", &test_data->tree), 0);
    assert_int_equal(nc_server_config_setup_data(test_data->tree), 0);
    ret = pthread_create(&tids[0], NULL, client_thread_intermediate_ca, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);
    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
#endif

    printf("\nINTERMEDIATE CA INTERMEDIATE ONLY\n\n");

    /* delete server's root CA */
    assert_int_equal(nc_server_config_del_tls_ca_cert("endpt",
            "root_ca", &test_data->tree), 0);
    /* add back the intermediate CA, expect success */
    assert_int_equal(nc_server_config_add_tls_ca_cert(test_ctx->ctx, "endpt", "intermediate_ca",
            TESTS_DIR "/data/certs/intermediate_ca.pem", &test_data->tree), 0);
    assert_int_equal(nc_server_config_setup_data(test_data->tree), 0);
    ret = pthread_create(&tids[0], NULL, client_thread_intermediate_ca, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);
    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_tls_intermediate_ca_client(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_tls_data *test_data = test_ctx->test_data;

    printf("\nINTERMEDIATE CA ALL\n\n");

    /* all certs are set */
    test_data->root_ca = 1;
    test_data->intermediate_ca = 1;
    ret = pthread_create(&tids[0], NULL, client_thread_intermediate_ca, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);
    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

#ifndef HAVE_MBEDTLS
    /* this use case is not supported by mbedTLS, so skip it for now */

    printf("\nINTERMEDIATE CA ROOT ONLY\n\n");

    /* delete client's intermediate CA */
    test_data->intermediate_ca = 0;
    ret = pthread_create(&tids[0], NULL, client_thread_intermediate_ca, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);
    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
#endif

    printf("\nINTERMEDIATE CA INTERMEDIATE ONLY\n\n");

    /* delete client's root CA, expect success */
    test_data->root_ca = 0;
    test_data->intermediate_ca = 1;
    ret = pthread_create(&tids[0], NULL, client_thread_intermediate_ca, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);
    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_nc_tls_ec_key(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_tls_data *test_data = test_ctx->test_data;

    ret = nc_server_config_add_tls_server_cert(test_ctx->ctx, "endpt", TESTS_DIR "/data/ec_server.key",
            NULL, TESTS_DIR "/data/ec_server.crt", &test_data->tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(test_data->tree);
    assert_int_equal(ret, 0);

    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
check_keylog_file(const char *filename)
{
    char buf[256];
    FILE *f;
    int cli_random, cli_hs, cli_traffic, srv_hs, srv_traffic;

    cli_random = cli_hs = cli_traffic = srv_hs = srv_traffic = 0;

    f = fopen(filename, "r");
    assert_non_null(f);

    while (fgets(buf, sizeof(buf), f)) {
        if (!strncmp(buf, "CLIENT_RANDOM", 13)) {
            cli_random++;
        } else if (!strncmp(buf, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", 31)) {
            cli_hs++;
        } else if (!strncmp(buf, "CLIENT_TRAFFIC_SECRET_0", 23)) {
            cli_traffic++;
        } else if (!strncmp(buf, "SERVER_HANDSHAKE_TRAFFIC_SECRET", 31)) {
            srv_hs++;
        } else if (!strncmp(buf, "SERVER_TRAFFIC_SECRET_0", 23)) {
            srv_traffic++;
        }
    }

    fclose(f);

    if (cli_random) {
        /* tls 1.2 */
        assert_int_equal(cli_random, 1);
        assert_int_equal(cli_hs + cli_traffic + srv_hs + srv_traffic, 0);
    } else {
        /* tls 1.3 */
        assert_int_equal(cli_hs + cli_traffic + srv_hs + srv_traffic, 4);
    }
}

static void
test_nc_tls_keylog(void **state)
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

    check_keylog_file(KEYLOG_FILENAME);
}

static void
test_cipher_suites(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_tls_data *test_data = test_ctx->test_data;
    const char *diff;
    char *diff_filled;
    struct lyd_node *tree = NULL;

    /* try deleting a cipher suite when none is configured */
    diff = "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\""
            " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
            "  <listen>\n"
            "    <endpoints>\n"
            "      <endpoint>\n"
            "        <name>endpt</name>\n"
            "        <tls>\n"
            "          <tcp-server-parameters>\n"
            "            <local-bind>\n"
            "              <local-address>127.0.0.1</local-address>\n"
            "              <local-port>%s</local-port>\n"
            "            </local-bind>\n"
            "          </tcp-server-parameters>\n"
            "          <tls-server-parameters>\n"
            "            <server-identity>\n"
            "              <certificate>\n"
            "                <inline-definition>\n"
            "                  <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>\n"
            "                  <cleartext-private-key>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</cleartext-private-key>\n"
            "                  <cert-data>MIIETjCCAzYCFEO1ljvG2ET9vb1itRsNMb8xN0R3MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMjEwOTAzMTExNjMyWhcNMzEwOTAxMTExNjMyWjBkMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxEjAQBgNVBAMMCTEyNy4wLjAuMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOqI7Y3w5r8kD9WZCMAaa/e3ig7nm76aIJUR0Xb1bk6X/4FNVQKwEJsBodOYupZvE5FZdZ6DJSMSyQ3FrJWnlZ+isr7F9B4bELV8Kj6sJGuVAr+mpcH/4rwL3DaXF9Y9Lf7iBgiOHUoip80Asn9BU4q80JI6w2VHd5ng4TUE67gmpRleIHzViKt3taBrsAJ9bS5bvaE6xOB8zKYGzRFOsDZrEqqcBsVIWC6EmjO29HS5qj/mXM0ktFGnNDxTZHoRkNgmCE/NH+fNKOFxraCwlFBpKemAky+GdgngRGiQAVowyAx/nSmCFAalKc+E4ddoFwD/oft6iOvvXqaXh6368wEQ7Hy48FDcUCbHtUEgK4wMrX9BSrRh6zkXO1tE4ghb0dM2qFDS0ypO3p04kUPa31mTgLuOH1LzwmlwxOs113mlYKCgqOFR5YaN+nq1HI5RATPo5NvCMpG2RrQW+ooCr2GtbT0oHmJv8yaBVY0HJ69eLnIv37dfjWvoTiBKBBIisXAD5Nm9rwSjZUSFu1iyd7u2YrkBCUzZuvt3BOPpX8GgQgagU6BPnac76FF6DMhRUXlBXdTuWsbuH14LdNIzGjkMZhNL/Tpkf6S/z1iH5VReGc+clTjWGg1XO5fr3mNKBGa7hDydIZRIMbgsy63DIY7n5dqhNkO30CGmr/9TagVZAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEjP2Zed4zY/nProMy67JyI3vV2fDYpYUkPD7ofSjFHjQc3ooXfBCF6Ho0dCdBTpof6kGIjfDmhcKoVcPqr8A/EA1pEGOB0RZkCjrwEnbAVdIb/5QP6nLtm7M5md3dEF+rttfBwisH6CV4XbXXZct/cNP+MPK2sXevCK2w8Xbt9nHeI/MXZoUW3WNGFwlRNlmQxCIoI0hnge9Gyb0WcTciHvhm8WtUQI1Ff3DLDgcQZQ1oOhci+ocBJVhC9l9lDCOpu93coyM7PD4CbVTFxfnPnOy81525W6ya0nmZOKafG20bdc+T1LqMXM+uR5hBHsg9K6UbREHEoP3pLYW7zg0Aw=</cert-data>\n"
            "                </inline-definition>\n"
            "              </certificate>\n"
            "            </server-identity>\n"
            "            <client-authentication>\n"
            "              <ca-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_ca</name>\n"
            "                    <cert-data>MIIDnDCCAoSgAwIBAgIJAIjf7UNx4uabMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMTgxMTA1MDcyNjM5WhcNMjgxMTAyMDcyNjM5WjBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyMrKraqraFGklO2itRIEWxfuzWo1IwxZ22aJmeXDLeomt6893NXelMLaC3swQ+hu49JjiIY81DXvbVgmIgLm7cAz5tHTHuJbfdI4Q6gyic4aOpy2s3s1/vYz+1TvEUFCiPXEsJrH72he/z9nBxL8vY6Eg8U8EG8NvKp9zyCKA7vmNSgQOtuyF18fesYHAnvQjNXO5q6diPXdHOr2bjTRUvARGbWlv4Rvf81RwUkRsWoF/0pglV/TxnW2MoHnn3apxb/kmH92CQ+GWKxq5SkhvbkYePlA87kgKnDtXl4wEXIhYwM51kafRhhlAKN+qYeV9teBqGpjsZRYesrh3mXHlQIDAQABo1MwUTAdBgNVHQ4EFgQU60nJ4q3ItcfaOOBjJSqadAPiMg8wHwYDVR0jBBgwFoAU60nJ4q3ItcfaOOBjJSqadAPiMg8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAxIqIQ5SCXnKslZfrXiAEbB5dglxVOSa8me5a/70uHK/27JZ6veeIgRqZ4VgPHnBCa3m6EHr+mnTjjqSUcGIUiKV3g2Dumw8paqZC+Qv+Ib/NKquS1lO2Ry1wHBtXzn5KKHHyM1bWMDaDszirw2+pp22VdRrPZNA9NWXheEDYOLyQekyL2CfidhxhaXvUZyWgalLyF2XRZ5/jAT+NjfWw39EmWPUGk13Jm83OaFc1VdrXNCiD0sGCQ+BTCllDinQvR08yzd4fzA3YXthvX1dBu1SvqQAGOS7gssRCyv9uWI6MXta25X91eY1ZMz1euJ04mB8EdyYiZc0kzrb9dv5d0g==</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ca-certs>\n"
            "              <ee-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_cert</name>\n"
            "                    <cert-data>MIIEQDCCAygCCQCV65JgDvfWkDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMB4XDTE4MTEwNTA3MzAzOVoXDTI4MTEwMjA3MzAzOVowYTELMAkGA1UEBhMCQ1oxEzARBgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAcMBEJybm8xDzANBgNVBAoMBkNFU05FVDEMMAoGA1UECwwDVE1DMQ8wDQYDVQQDDAZjbGllbnQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+kqPqDL9GbWmqVQhp4qla4vYo4kFuh2HG48b7RLp/4l/guik4Hvq2aDVFD9sBcs3FeQbjoLH1Q4doUr8jG6VwJsfovE5SD3T8dVLs2dtpW0OyXTccb0I9lOVDMz6f6IUBe/m5vk8XNbdUII0NJ8y1dQ51VH3e784Bzu7PSdaMaFac4fkw8kJA9LxkWkv2FDFC7IBcVjRgtb/15EwODH849O6+VPEgX5gdozNj5bL45rKDBvvx0KjD7dFBGAIHbSjmjp7HHadfYKqvtQnMb83fRcK6wohxNP3vy13wBTtSOlvOg16Gb+2ZB0Or7wgOw19ZvEIcNgswPwhHfZQNcYMNVLCu02BSzwdY00IEqNM0J5B/W//KJF3uFF/ZqP7D2wO7w8j5UL2lpuxF7YrGecNT1Kr7ggHdkzcLlekkNu7wNWKAZlJ6+Kbun8PqZbamGXLG2Ur1aZDkyKyD9nyMzsRneAlxO+HbQhLojimUbsMm+wgL89zchLYkL/DSmsJlryA4qhvzHaaONBw4DV5UhSbLDpZtXVfrn+MAm8hLpqf+gUCThsFN8kDp9h9Tg9v01ai9jGb941HkFtGYUWHS5drSz3ZLnSI6i1/wKdbs9ns9YqDMqq2c305v5h7taMN0b40KuGSIME4K4cOsdfCprFYGZQgKjaadQwrsm4k1Jl7kMwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAtwH2u1o16jkABlqEGDIvAJSMwBmZzNTNHgOXtWDlkzWGsj+L1wc/DNjDRBkE31h4h7ASthhqi1nzzHYQ1hhPVhUUqI532AS/V7EPsBg3f+BI8gxqQ31TUBEQ4Ll6FtW36nqpJOe6Uui2rH2FonuUg2Av5BvDRil42Tu7fYW4WpSU3e00HiGJ0J0t+QjoKRnnoLJJqlmzk8Y4aIlQim7Azvrlo1WEtOhI3L9UE1GEqxLjRB45P36FSe1wfkgt7xmD0Xjy33Wh6Ae2Fvx7OfJ0K1zy0LHr4rDDJ3tLTqjPqHIFhaa73jGXwXk8sZnbAk542Oa6C6AjzNFyqV7T5Q5lg</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ee-certs>\n"
            "            </client-authentication>\n"
            "            <hello-params>\n"
            "              <cipher-suites>\n"
            "                <cipher-suite yang:operation=\"delete\">TLS_AES_128_GCM_SHA256</cipher-suite>\n" // not set before
            "              </cipher-suites>\n"
            "            </hello-params>\n"
            "          </tls-server-parameters>\n"
            "          <netconf-server-parameters>\n"
            "            <client-identity-mappings>\n"
            "              <cert-to-name>\n"
            "                <id>1</id>\n"
            "                <fingerprint>04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D</fingerprint>\n"
            "                <map-type xmlns:x509c2n=\"urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name\">x509c2n:specified</map-type>\n"
            "                <name>client</name>\n"
            "              </cert-to-name>\n"
            "            </client-identity-mappings>\n"
            "          </netconf-server-parameters>\n"
            "        </tls>\n"
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

    /* reset to original config */
    ret = nc_server_config_setup_data(test_data->tree);
    assert_int_equal(ret, 0);

    /* try deleting a cipher suite that was not set before */
    diff = "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\""
            " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
            "  <listen>\n"
            "    <endpoints>\n"
            "      <endpoint>\n"
            "        <name>endpt</name>\n"
            "        <tls>\n"
            "          <tcp-server-parameters>\n"
            "            <local-bind>\n"
            "              <local-address>127.0.0.1</local-address>\n"
            "              <local-port>%s</local-port>\n"
            "            </local-bind>\n"
            "          </tcp-server-parameters>\n"
            "          <tls-server-parameters>\n"
            "            <server-identity>\n"
            "              <certificate>\n"
            "                <inline-definition>\n"
            "                  <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>\n"
            "                  <cleartext-private-key>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</cleartext-private-key>\n"
            "                  <cert-data>MIIETjCCAzYCFEO1ljvG2ET9vb1itRsNMb8xN0R3MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMjEwOTAzMTExNjMyWhcNMzEwOTAxMTExNjMyWjBkMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxEjAQBgNVBAMMCTEyNy4wLjAuMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOqI7Y3w5r8kD9WZCMAaa/e3ig7nm76aIJUR0Xb1bk6X/4FNVQKwEJsBodOYupZvE5FZdZ6DJSMSyQ3FrJWnlZ+isr7F9B4bELV8Kj6sJGuVAr+mpcH/4rwL3DaXF9Y9Lf7iBgiOHUoip80Asn9BU4q80JI6w2VHd5ng4TUE67gmpRleIHzViKt3taBrsAJ9bS5bvaE6xOB8zKYGzRFOsDZrEqqcBsVIWC6EmjO29HS5qj/mXM0ktFGnNDxTZHoRkNgmCE/NH+fNKOFxraCwlFBpKemAky+GdgngRGiQAVowyAx/nSmCFAalKc+E4ddoFwD/oft6iOvvXqaXh6368wEQ7Hy48FDcUCbHtUEgK4wMrX9BSrRh6zkXO1tE4ghb0dM2qFDS0ypO3p04kUPa31mTgLuOH1LzwmlwxOs113mlYKCgqOFR5YaN+nq1HI5RATPo5NvCMpG2RrQW+ooCr2GtbT0oHmJv8yaBVY0HJ69eLnIv37dfjWvoTiBKBBIisXAD5Nm9rwSjZUSFu1iyd7u2YrkBCUzZuvt3BOPpX8GgQgagU6BPnac76FF6DMhRUXlBXdTuWsbuH14LdNIzGjkMZhNL/Tpkf6S/z1iH5VReGc+clTjWGg1XO5fr3mNKBGa7hDydIZRIMbgsy63DIY7n5dqhNkO30CGmr/9TagVZAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEjP2Zed4zY/nProMy67JyI3vV2fDYpYUkPD7ofSjFHjQc3ooXfBCF6Ho0dCdBTpof6kGIjfDmhcKoVcPqr8A/EA1pEGOB0RZkCjrwEnbAVdIb/5QP6nLtm7M5md3dEF+rttfBwisH6CV4XbXXZct/cNP+MPK2sXevCK2w8Xbt9nHeI/MXZoUW3WNGFwlRNlmQxCIoI0hnge9Gyb0WcTciHvhm8WtUQI1Ff3DLDgcQZQ1oOhci+ocBJVhC9l9lDCOpu93coyM7PD4CbVTFxfnPnOy81525W6ya0nmZOKafG20bdc+T1LqMXM+uR5hBHsg9K6UbREHEoP3pLYW7zg0Aw=</cert-data>\n"
            "                </inline-definition>\n"
            "              </certificate>\n"
            "            </server-identity>\n"
            "            <client-authentication>\n"
            "              <ca-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_ca</name>\n"
            "                    <cert-data>MIIDnDCCAoSgAwIBAgIJAIjf7UNx4uabMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMTgxMTA1MDcyNjM5WhcNMjgxMTAyMDcyNjM5WjBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyMrKraqraFGklO2itRIEWxfuzWo1IwxZ22aJmeXDLeomt6893NXelMLaC3swQ+hu49JjiIY81DXvbVgmIgLm7cAz5tHTHuJbfdI4Q6gyic4aOpy2s3s1/vYz+1TvEUFCiPXEsJrH72he/z9nBxL8vY6Eg8U8EG8NvKp9zyCKA7vmNSgQOtuyF18fesYHAnvQjNXO5q6diPXdHOr2bjTRUvARGbWlv4Rvf81RwUkRsWoF/0pglV/TxnW2MoHnn3apxb/kmH92CQ+GWKxq5SkhvbkYePlA87kgKnDtXl4wEXIhYwM51kafRhhlAKN+qYeV9teBqGpjsZRYesrh3mXHlQIDAQABo1MwUTAdBgNVHQ4EFgQU60nJ4q3ItcfaOOBjJSqadAPiMg8wHwYDVR0jBBgwFoAU60nJ4q3ItcfaOOBjJSqadAPiMg8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAxIqIQ5SCXnKslZfrXiAEbB5dglxVOSa8me5a/70uHK/27JZ6veeIgRqZ4VgPHnBCa3m6EHr+mnTjjqSUcGIUiKV3g2Dumw8paqZC+Qv+Ib/NKquS1lO2Ry1wHBtXzn5KKHHyM1bWMDaDszirw2+pp22VdRrPZNA9NWXheEDYOLyQekyL2CfidhxhaXvUZyWgalLyF2XRZ5/jAT+NjfWw39EmWPUGk13Jm83OaFc1VdrXNCiD0sGCQ+BTCllDinQvR08yzd4fzA3YXthvX1dBu1SvqQAGOS7gssRCyv9uWI6MXta25X91eY1ZMz1euJ04mB8EdyYiZc0kzrb9dv5d0g==</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ca-certs>\n"
            "              <ee-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_cert</name>\n"
            "                    <cert-data>MIIEQDCCAygCCQCV65JgDvfWkDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMB4XDTE4MTEwNTA3MzAzOVoXDTI4MTEwMjA3MzAzOVowYTELMAkGA1UEBhMCQ1oxEzARBgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAcMBEJybm8xDzANBgNVBAoMBkNFU05FVDEMMAoGA1UECwwDVE1DMQ8wDQYDVQQDDAZjbGllbnQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+kqPqDL9GbWmqVQhp4qla4vYo4kFuh2HG48b7RLp/4l/guik4Hvq2aDVFD9sBcs3FeQbjoLH1Q4doUr8jG6VwJsfovE5SD3T8dVLs2dtpW0OyXTccb0I9lOVDMz6f6IUBe/m5vk8XNbdUII0NJ8y1dQ51VH3e784Bzu7PSdaMaFac4fkw8kJA9LxkWkv2FDFC7IBcVjRgtb/15EwODH849O6+VPEgX5gdozNj5bL45rKDBvvx0KjD7dFBGAIHbSjmjp7HHadfYKqvtQnMb83fRcK6wohxNP3vy13wBTtSOlvOg16Gb+2ZB0Or7wgOw19ZvEIcNgswPwhHfZQNcYMNVLCu02BSzwdY00IEqNM0J5B/W//KJF3uFF/ZqP7D2wO7w8j5UL2lpuxF7YrGecNT1Kr7ggHdkzcLlekkNu7wNWKAZlJ6+Kbun8PqZbamGXLG2Ur1aZDkyKyD9nyMzsRneAlxO+HbQhLojimUbsMm+wgL89zchLYkL/DSmsJlryA4qhvzHaaONBw4DV5UhSbLDpZtXVfrn+MAm8hLpqf+gUCThsFN8kDp9h9Tg9v01ai9jGb941HkFtGYUWHS5drSz3ZLnSI6i1/wKdbs9ns9YqDMqq2c305v5h7taMN0b40KuGSIME4K4cOsdfCprFYGZQgKjaadQwrsm4k1Jl7kMwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAtwH2u1o16jkABlqEGDIvAJSMwBmZzNTNHgOXtWDlkzWGsj+L1wc/DNjDRBkE31h4h7ASthhqi1nzzHYQ1hhPVhUUqI532AS/V7EPsBg3f+BI8gxqQ31TUBEQ4Ll6FtW36nqpJOe6Uui2rH2FonuUg2Av5BvDRil42Tu7fYW4WpSU3e00HiGJ0J0t+QjoKRnnoLJJqlmzk8Y4aIlQim7Azvrlo1WEtOhI3L9UE1GEqxLjRB45P36FSe1wfkgt7xmD0Xjy33Wh6Ae2Fvx7OfJ0K1zy0LHr4rDDJ3tLTqjPqHIFhaa73jGXwXk8sZnbAk542Oa6C6AjzNFyqV7T5Q5lg</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ee-certs>\n"
            "            </client-authentication>\n"
            "            <hello-params>\n"
            "              <cipher-suites>\n"
            "                <cipher-suite yang:operation=\"create\">TLS_AES_128_GCM_SHA256</cipher-suite>\n" // should succeed
            "                <cipher-suite yang:operation=\"delete\">TLS_CHACHA20_POLY1305_SHA256</cipher-suite>\n" // not set before, should fail
            "              </cipher-suites>\n"
            "            </hello-params>\n"
            "          </tls-server-parameters>\n"
            "          <netconf-server-parameters>\n"
            "            <client-identity-mappings>\n"
            "              <cert-to-name>\n"
            "                <id>1</id>\n"
            "                <fingerprint>04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D</fingerprint>\n"
            "                <map-type xmlns:x509c2n=\"urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name\">x509c2n:specified</map-type>\n"
            "                <name>client</name>\n"
            "              </cert-to-name>\n"
            "            </client-identity-mappings>\n"
            "          </netconf-server-parameters>\n"
            "        </tls>\n"
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

    /* reset to original config */
    ret = nc_server_config_setup_data(test_data->tree);
    assert_int_equal(ret, 0);

    /* set one commonly used TLS1.3 and one TLS1.2 cipher suite, should be able to connect */
    diff = "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\""
            " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
            "  <listen>\n"
            "    <endpoints>\n"
            "      <endpoint>\n"
            "        <name>endpt</name>\n"
            "        <tls>\n"
            "          <tcp-server-parameters>\n"
            "            <local-bind>\n"
            "              <local-address>127.0.0.1</local-address>\n"
            "              <local-port>%s</local-port>\n"
            "            </local-bind>\n"
            "          </tcp-server-parameters>\n"
            "          <tls-server-parameters>\n"
            "            <server-identity>\n"
            "              <certificate>\n"
            "                <inline-definition>\n"
            "                  <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>\n"
            "                  <cleartext-private-key>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</cleartext-private-key>\n"
            "                  <cert-data>MIIETjCCAzYCFEO1ljvG2ET9vb1itRsNMb8xN0R3MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMjEwOTAzMTExNjMyWhcNMzEwOTAxMTExNjMyWjBkMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxEjAQBgNVBAMMCTEyNy4wLjAuMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOqI7Y3w5r8kD9WZCMAaa/e3ig7nm76aIJUR0Xb1bk6X/4FNVQKwEJsBodOYupZvE5FZdZ6DJSMSyQ3FrJWnlZ+isr7F9B4bELV8Kj6sJGuVAr+mpcH/4rwL3DaXF9Y9Lf7iBgiOHUoip80Asn9BU4q80JI6w2VHd5ng4TUE67gmpRleIHzViKt3taBrsAJ9bS5bvaE6xOB8zKYGzRFOsDZrEqqcBsVIWC6EmjO29HS5qj/mXM0ktFGnNDxTZHoRkNgmCE/NH+fNKOFxraCwlFBpKemAky+GdgngRGiQAVowyAx/nSmCFAalKc+E4ddoFwD/oft6iOvvXqaXh6368wEQ7Hy48FDcUCbHtUEgK4wMrX9BSrRh6zkXO1tE4ghb0dM2qFDS0ypO3p04kUPa31mTgLuOH1LzwmlwxOs113mlYKCgqOFR5YaN+nq1HI5RATPo5NvCMpG2RrQW+ooCr2GtbT0oHmJv8yaBVY0HJ69eLnIv37dfjWvoTiBKBBIisXAD5Nm9rwSjZUSFu1iyd7u2YrkBCUzZuvt3BOPpX8GgQgagU6BPnac76FF6DMhRUXlBXdTuWsbuH14LdNIzGjkMZhNL/Tpkf6S/z1iH5VReGc+clTjWGg1XO5fr3mNKBGa7hDydIZRIMbgsy63DIY7n5dqhNkO30CGmr/9TagVZAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEjP2Zed4zY/nProMy67JyI3vV2fDYpYUkPD7ofSjFHjQc3ooXfBCF6Ho0dCdBTpof6kGIjfDmhcKoVcPqr8A/EA1pEGOB0RZkCjrwEnbAVdIb/5QP6nLtm7M5md3dEF+rttfBwisH6CV4XbXXZct/cNP+MPK2sXevCK2w8Xbt9nHeI/MXZoUW3WNGFwlRNlmQxCIoI0hnge9Gyb0WcTciHvhm8WtUQI1Ff3DLDgcQZQ1oOhci+ocBJVhC9l9lDCOpu93coyM7PD4CbVTFxfnPnOy81525W6ya0nmZOKafG20bdc+T1LqMXM+uR5hBHsg9K6UbREHEoP3pLYW7zg0Aw=</cert-data>\n"
            "                </inline-definition>\n"
            "              </certificate>\n"
            "            </server-identity>\n"
            "            <client-authentication>\n"
            "              <ca-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_ca</name>\n"
            "                    <cert-data>MIIDnDCCAoSgAwIBAgIJAIjf7UNx4uabMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMTgxMTA1MDcyNjM5WhcNMjgxMTAyMDcyNjM5WjBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyMrKraqraFGklO2itRIEWxfuzWo1IwxZ22aJmeXDLeomt6893NXelMLaC3swQ+hu49JjiIY81DXvbVgmIgLm7cAz5tHTHuJbfdI4Q6gyic4aOpy2s3s1/vYz+1TvEUFCiPXEsJrH72he/z9nBxL8vY6Eg8U8EG8NvKp9zyCKA7vmNSgQOtuyF18fesYHAnvQjNXO5q6diPXdHOr2bjTRUvARGbWlv4Rvf81RwUkRsWoF/0pglV/TxnW2MoHnn3apxb/kmH92CQ+GWKxq5SkhvbkYePlA87kgKnDtXl4wEXIhYwM51kafRhhlAKN+qYeV9teBqGpjsZRYesrh3mXHlQIDAQABo1MwUTAdBgNVHQ4EFgQU60nJ4q3ItcfaOOBjJSqadAPiMg8wHwYDVR0jBBgwFoAU60nJ4q3ItcfaOOBjJSqadAPiMg8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAxIqIQ5SCXnKslZfrXiAEbB5dglxVOSa8me5a/70uHK/27JZ6veeIgRqZ4VgPHnBCa3m6EHr+mnTjjqSUcGIUiKV3g2Dumw8paqZC+Qv+Ib/NKquS1lO2Ry1wHBtXzn5KKHHyM1bWMDaDszirw2+pp22VdRrPZNA9NWXheEDYOLyQekyL2CfidhxhaXvUZyWgalLyF2XRZ5/jAT+NjfWw39EmWPUGk13Jm83OaFc1VdrXNCiD0sGCQ+BTCllDinQvR08yzd4fzA3YXthvX1dBu1SvqQAGOS7gssRCyv9uWI6MXta25X91eY1ZMz1euJ04mB8EdyYiZc0kzrb9dv5d0g==</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ca-certs>\n"
            "              <ee-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_cert</name>\n"
            "                    <cert-data>MIIEQDCCAygCCQCV65JgDvfWkDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMB4XDTE4MTEwNTA3MzAzOVoXDTI4MTEwMjA3MzAzOVowYTELMAkGA1UEBhMCQ1oxEzARBgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAcMBEJybm8xDzANBgNVBAoMBkNFU05FVDEMMAoGA1UECwwDVE1DMQ8wDQYDVQQDDAZjbGllbnQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+kqPqDL9GbWmqVQhp4qla4vYo4kFuh2HG48b7RLp/4l/guik4Hvq2aDVFD9sBcs3FeQbjoLH1Q4doUr8jG6VwJsfovE5SD3T8dVLs2dtpW0OyXTccb0I9lOVDMz6f6IUBe/m5vk8XNbdUII0NJ8y1dQ51VH3e784Bzu7PSdaMaFac4fkw8kJA9LxkWkv2FDFC7IBcVjRgtb/15EwODH849O6+VPEgX5gdozNj5bL45rKDBvvx0KjD7dFBGAIHbSjmjp7HHadfYKqvtQnMb83fRcK6wohxNP3vy13wBTtSOlvOg16Gb+2ZB0Or7wgOw19ZvEIcNgswPwhHfZQNcYMNVLCu02BSzwdY00IEqNM0J5B/W//KJF3uFF/ZqP7D2wO7w8j5UL2lpuxF7YrGecNT1Kr7ggHdkzcLlekkNu7wNWKAZlJ6+Kbun8PqZbamGXLG2Ur1aZDkyKyD9nyMzsRneAlxO+HbQhLojimUbsMm+wgL89zchLYkL/DSmsJlryA4qhvzHaaONBw4DV5UhSbLDpZtXVfrn+MAm8hLpqf+gUCThsFN8kDp9h9Tg9v01ai9jGb941HkFtGYUWHS5drSz3ZLnSI6i1/wKdbs9ns9YqDMqq2c305v5h7taMN0b40KuGSIME4K4cOsdfCprFYGZQgKjaadQwrsm4k1Jl7kMwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAtwH2u1o16jkABlqEGDIvAJSMwBmZzNTNHgOXtWDlkzWGsj+L1wc/DNjDRBkE31h4h7ASthhqi1nzzHYQ1hhPVhUUqI532AS/V7EPsBg3f+BI8gxqQ31TUBEQ4Ll6FtW36nqpJOe6Uui2rH2FonuUg2Av5BvDRil42Tu7fYW4WpSU3e00HiGJ0J0t+QjoKRnnoLJJqlmzk8Y4aIlQim7Azvrlo1WEtOhI3L9UE1GEqxLjRB45P36FSe1wfkgt7xmD0Xjy33Wh6Ae2Fvx7OfJ0K1zy0LHr4rDDJ3tLTqjPqHIFhaa73jGXwXk8sZnbAk542Oa6C6AjzNFyqV7T5Q5lg</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ee-certs>\n"
            "            </client-authentication>\n"
            "            <hello-params>\n"
            "              <cipher-suites>\n"
            "                <cipher-suite yang:operation=\"create\">TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</cipher-suite>\n"
            "                <cipher-suite yang:operation=\"create\">TLS_AES_256_GCM_SHA384</cipher-suite>\n"
            "              </cipher-suites>\n"
            "            </hello-params>\n"
            "          </tls-server-parameters>\n"
            "          <netconf-server-parameters>\n"
            "            <client-identity-mappings>\n"
            "              <cert-to-name>\n"
            "                <id>1</id>\n"
            "                <fingerprint>04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D</fingerprint>\n"
            "                <map-type xmlns:x509c2n=\"urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name\">x509c2n:specified</map-type>\n"
            "                <name>client</name>\n"
            "              </cert-to-name>\n"
            "            </client-identity-mappings>\n"
            "          </netconf-server-parameters>\n"
            "        </tls>\n"
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

    /* apply the diff */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    free(diff_filled);
    lyd_free_all(tree);

    /* should be able to connect */
    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    /* reset to original config */
    ret = nc_server_config_setup_data(test_data->tree);
    assert_int_equal(ret, 0);
}

static void
test_tls_version(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct ln2_test_ctx *test_ctx = *state;
    struct test_tls_data *test_data = test_ctx->test_data;
    const char *diff;
    char *diff_filled;
    struct lyd_node *tree = NULL;

    /* set TLS1.2 and check if connection works */
    diff = "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\""
            " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
            "  <listen>\n"
            "    <endpoints>\n"
            "      <endpoint>\n"
            "        <name>endpt</name>\n"
            "        <tls>\n"
            "          <tcp-server-parameters>\n"
            "            <local-bind>\n"
            "              <local-address>127.0.0.1</local-address>\n"
            "              <local-port>%s</local-port>\n"
            "            </local-bind>\n"
            "          </tcp-server-parameters>\n"
            "          <tls-server-parameters>\n"
            "            <server-identity>\n"
            "              <certificate>\n"
            "                <inline-definition>\n"
            "                  <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>\n"
            "                  <cleartext-private-key>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</cleartext-private-key>\n"
            "                  <cert-data>MIIETjCCAzYCFEO1ljvG2ET9vb1itRsNMb8xN0R3MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMjEwOTAzMTExNjMyWhcNMzEwOTAxMTExNjMyWjBkMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxEjAQBgNVBAMMCTEyNy4wLjAuMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOqI7Y3w5r8kD9WZCMAaa/e3ig7nm76aIJUR0Xb1bk6X/4FNVQKwEJsBodOYupZvE5FZdZ6DJSMSyQ3FrJWnlZ+isr7F9B4bELV8Kj6sJGuVAr+mpcH/4rwL3DaXF9Y9Lf7iBgiOHUoip80Asn9BU4q80JI6w2VHd5ng4TUE67gmpRleIHzViKt3taBrsAJ9bS5bvaE6xOB8zKYGzRFOsDZrEqqcBsVIWC6EmjO29HS5qj/mXM0ktFGnNDxTZHoRkNgmCE/NH+fNKOFxraCwlFBpKemAky+GdgngRGiQAVowyAx/nSmCFAalKc+E4ddoFwD/oft6iOvvXqaXh6368wEQ7Hy48FDcUCbHtUEgK4wMrX9BSrRh6zkXO1tE4ghb0dM2qFDS0ypO3p04kUPa31mTgLuOH1LzwmlwxOs113mlYKCgqOFR5YaN+nq1HI5RATPo5NvCMpG2RrQW+ooCr2GtbT0oHmJv8yaBVY0HJ69eLnIv37dfjWvoTiBKBBIisXAD5Nm9rwSjZUSFu1iyd7u2YrkBCUzZuvt3BOPpX8GgQgagU6BPnac76FF6DMhRUXlBXdTuWsbuH14LdNIzGjkMZhNL/Tpkf6S/z1iH5VReGc+clTjWGg1XO5fr3mNKBGa7hDydIZRIMbgsy63DIY7n5dqhNkO30CGmr/9TagVZAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEjP2Zed4zY/nProMy67JyI3vV2fDYpYUkPD7ofSjFHjQc3ooXfBCF6Ho0dCdBTpof6kGIjfDmhcKoVcPqr8A/EA1pEGOB0RZkCjrwEnbAVdIb/5QP6nLtm7M5md3dEF+rttfBwisH6CV4XbXXZct/cNP+MPK2sXevCK2w8Xbt9nHeI/MXZoUW3WNGFwlRNlmQxCIoI0hnge9Gyb0WcTciHvhm8WtUQI1Ff3DLDgcQZQ1oOhci+ocBJVhC9l9lDCOpu93coyM7PD4CbVTFxfnPnOy81525W6ya0nmZOKafG20bdc+T1LqMXM+uR5hBHsg9K6UbREHEoP3pLYW7zg0Aw=</cert-data>\n"
            "                </inline-definition>\n"
            "              </certificate>\n"
            "            </server-identity>\n"
            "            <client-authentication>\n"
            "              <ca-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_ca</name>\n"
            "                    <cert-data>MIIDnDCCAoSgAwIBAgIJAIjf7UNx4uabMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMTgxMTA1MDcyNjM5WhcNMjgxMTAyMDcyNjM5WjBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyMrKraqraFGklO2itRIEWxfuzWo1IwxZ22aJmeXDLeomt6893NXelMLaC3swQ+hu49JjiIY81DXvbVgmIgLm7cAz5tHTHuJbfdI4Q6gyic4aOpy2s3s1/vYz+1TvEUFCiPXEsJrH72he/z9nBxL8vY6Eg8U8EG8NvKp9zyCKA7vmNSgQOtuyF18fesYHAnvQjNXO5q6diPXdHOr2bjTRUvARGbWlv4Rvf81RwUkRsWoF/0pglV/TxnW2MoHnn3apxb/kmH92CQ+GWKxq5SkhvbkYePlA87kgKnDtXl4wEXIhYwM51kafRhhlAKN+qYeV9teBqGpjsZRYesrh3mXHlQIDAQABo1MwUTAdBgNVHQ4EFgQU60nJ4q3ItcfaOOBjJSqadAPiMg8wHwYDVR0jBBgwFoAU60nJ4q3ItcfaOOBjJSqadAPiMg8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAxIqIQ5SCXnKslZfrXiAEbB5dglxVOSa8me5a/70uHK/27JZ6veeIgRqZ4VgPHnBCa3m6EHr+mnTjjqSUcGIUiKV3g2Dumw8paqZC+Qv+Ib/NKquS1lO2Ry1wHBtXzn5KKHHyM1bWMDaDszirw2+pp22VdRrPZNA9NWXheEDYOLyQekyL2CfidhxhaXvUZyWgalLyF2XRZ5/jAT+NjfWw39EmWPUGk13Jm83OaFc1VdrXNCiD0sGCQ+BTCllDinQvR08yzd4fzA3YXthvX1dBu1SvqQAGOS7gssRCyv9uWI6MXta25X91eY1ZMz1euJ04mB8EdyYiZc0kzrb9dv5d0g==</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ca-certs>\n"
            "              <ee-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_cert</name>\n"
            "                    <cert-data>MIIEQDCCAygCCQCV65JgDvfWkDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMB4XDTE4MTEwNTA3MzAzOVoXDTI4MTEwMjA3MzAzOVowYTELMAkGA1UEBhMCQ1oxEzARBgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAcMBEJybm8xDzANBgNVBAoMBkNFU05FVDEMMAoGA1UECwwDVE1DMQ8wDQYDVQQDDAZjbGllbnQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+kqPqDL9GbWmqVQhp4qla4vYo4kFuh2HG48b7RLp/4l/guik4Hvq2aDVFD9sBcs3FeQbjoLH1Q4doUr8jG6VwJsfovE5SD3T8dVLs2dtpW0OyXTccb0I9lOVDMz6f6IUBe/m5vk8XNbdUII0NJ8y1dQ51VH3e784Bzu7PSdaMaFac4fkw8kJA9LxkWkv2FDFC7IBcVjRgtb/15EwODH849O6+VPEgX5gdozNj5bL45rKDBvvx0KjD7dFBGAIHbSjmjp7HHadfYKqvtQnMb83fRcK6wohxNP3vy13wBTtSOlvOg16Gb+2ZB0Or7wgOw19ZvEIcNgswPwhHfZQNcYMNVLCu02BSzwdY00IEqNM0J5B/W//KJF3uFF/ZqP7D2wO7w8j5UL2lpuxF7YrGecNT1Kr7ggHdkzcLlekkNu7wNWKAZlJ6+Kbun8PqZbamGXLG2Ur1aZDkyKyD9nyMzsRneAlxO+HbQhLojimUbsMm+wgL89zchLYkL/DSmsJlryA4qhvzHaaONBw4DV5UhSbLDpZtXVfrn+MAm8hLpqf+gUCThsFN8kDp9h9Tg9v01ai9jGb941HkFtGYUWHS5drSz3ZLnSI6i1/wKdbs9ns9YqDMqq2c305v5h7taMN0b40KuGSIME4K4cOsdfCprFYGZQgKjaadQwrsm4k1Jl7kMwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAtwH2u1o16jkABlqEGDIvAJSMwBmZzNTNHgOXtWDlkzWGsj+L1wc/DNjDRBkE31h4h7ASthhqi1nzzHYQ1hhPVhUUqI532AS/V7EPsBg3f+BI8gxqQ31TUBEQ4Ll6FtW36nqpJOe6Uui2rH2FonuUg2Av5BvDRil42Tu7fYW4WpSU3e00HiGJ0J0t+QjoKRnnoLJJqlmzk8Y4aIlQim7Azvrlo1WEtOhI3L9UE1GEqxLjRB45P36FSe1wfkgt7xmD0Xjy33Wh6Ae2Fvx7OfJ0K1zy0LHr4rDDJ3tLTqjPqHIFhaa73jGXwXk8sZnbAk542Oa6C6AjzNFyqV7T5Q5lg</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ee-certs>\n"
            "            </client-authentication>\n"
            "            <hello-params>\n"
            "              <tls-versions>\n"
            "                <max yang:operation=\"create\" xmlns:tlscmn=\"urn:ietf:params:xml:ns:yang:ietf-tls-common\">tlscmn:tls12</max>\n" // set to TLS1.2
            "              </tls-versions>\n"
            "            </hello-params>\n"
            "          </tls-server-parameters>\n"
            "          <netconf-server-parameters>\n"
            "            <client-identity-mappings>\n"
            "              <cert-to-name>\n"
            "                <id>1</id>\n"
            "                <fingerprint>04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D</fingerprint>\n"
            "                <map-type xmlns:x509c2n=\"urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name\">x509c2n:specified</map-type>\n"
            "                <name>client</name>\n"
            "              </cert-to-name>\n"
            "            </client-identity-mappings>\n"
            "          </netconf-server-parameters>\n"
            "        </tls>\n"
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

    /* apply the diff */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    free(diff_filled);
    lyd_free_all(tree);

    /* should be able to connect */
    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    /* reset to original config */
    ret = nc_server_config_setup_data(test_data->tree);
    assert_int_equal(ret, 0);

    /* set TLS1.2 with TLS1.3 ciphers and check that connection fails */
    diff = "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\""
            " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
            "  <listen>\n"
            "    <endpoints>\n"
            "      <endpoint>\n"
            "        <name>endpt</name>\n"
            "        <tls>\n"
            "          <tcp-server-parameters>\n"
            "            <local-bind>\n"
            "              <local-address>127.0.0.1</local-address>\n"
            "              <local-port>%s</local-port>\n"
            "            </local-bind>\n"
            "          </tcp-server-parameters>\n"
            "          <tls-server-parameters>\n"
            "            <server-identity>\n"
            "              <certificate>\n"
            "                <inline-definition>\n"
            "                  <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>\n"
            "                  <cleartext-private-key>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</cleartext-private-key>\n"
            "                  <cert-data>MIIETjCCAzYCFEO1ljvG2ET9vb1itRsNMb8xN0R3MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMjEwOTAzMTExNjMyWhcNMzEwOTAxMTExNjMyWjBkMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxEjAQBgNVBAMMCTEyNy4wLjAuMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOqI7Y3w5r8kD9WZCMAaa/e3ig7nm76aIJUR0Xb1bk6X/4FNVQKwEJsBodOYupZvE5FZdZ6DJSMSyQ3FrJWnlZ+isr7F9B4bELV8Kj6sJGuVAr+mpcH/4rwL3DaXF9Y9Lf7iBgiOHUoip80Asn9BU4q80JI6w2VHd5ng4TUE67gmpRleIHzViKt3taBrsAJ9bS5bvaE6xOB8zKYGzRFOsDZrEqqcBsVIWC6EmjO29HS5qj/mXM0ktFGnNDxTZHoRkNgmCE/NH+fNKOFxraCwlFBpKemAky+GdgngRGiQAVowyAx/nSmCFAalKc+E4ddoFwD/oft6iOvvXqaXh6368wEQ7Hy48FDcUCbHtUEgK4wMrX9BSrRh6zkXO1tE4ghb0dM2qFDS0ypO3p04kUPa31mTgLuOH1LzwmlwxOs113mlYKCgqOFR5YaN+nq1HI5RATPo5NvCMpG2RrQW+ooCr2GtbT0oHmJv8yaBVY0HJ69eLnIv37dfjWvoTiBKBBIisXAD5Nm9rwSjZUSFu1iyd7u2YrkBCUzZuvt3BOPpX8GgQgagU6BPnac76FF6DMhRUXlBXdTuWsbuH14LdNIzGjkMZhNL/Tpkf6S/z1iH5VReGc+clTjWGg1XO5fr3mNKBGa7hDydIZRIMbgsy63DIY7n5dqhNkO30CGmr/9TagVZAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEjP2Zed4zY/nProMy67JyI3vV2fDYpYUkPD7ofSjFHjQc3ooXfBCF6Ho0dCdBTpof6kGIjfDmhcKoVcPqr8A/EA1pEGOB0RZkCjrwEnbAVdIb/5QP6nLtm7M5md3dEF+rttfBwisH6CV4XbXXZct/cNP+MPK2sXevCK2w8Xbt9nHeI/MXZoUW3WNGFwlRNlmQxCIoI0hnge9Gyb0WcTciHvhm8WtUQI1Ff3DLDgcQZQ1oOhci+ocBJVhC9l9lDCOpu93coyM7PD4CbVTFxfnPnOy81525W6ya0nmZOKafG20bdc+T1LqMXM+uR5hBHsg9K6UbREHEoP3pLYW7zg0Aw=</cert-data>\n"
            "                </inline-definition>\n"
            "              </certificate>\n"
            "            </server-identity>\n"
            "            <client-authentication>\n"
            "              <ca-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_ca</name>\n"
            "                    <cert-data>MIIDnDCCAoSgAwIBAgIJAIjf7UNx4uabMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMTgxMTA1MDcyNjM5WhcNMjgxMTAyMDcyNjM5WjBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyMrKraqraFGklO2itRIEWxfuzWo1IwxZ22aJmeXDLeomt6893NXelMLaC3swQ+hu49JjiIY81DXvbVgmIgLm7cAz5tHTHuJbfdI4Q6gyic4aOpy2s3s1/vYz+1TvEUFCiPXEsJrH72he/z9nBxL8vY6Eg8U8EG8NvKp9zyCKA7vmNSgQOtuyF18fesYHAnvQjNXO5q6diPXdHOr2bjTRUvARGbWlv4Rvf81RwUkRsWoF/0pglV/TxnW2MoHnn3apxb/kmH92CQ+GWKxq5SkhvbkYePlA87kgKnDtXl4wEXIhYwM51kafRhhlAKN+qYeV9teBqGpjsZRYesrh3mXHlQIDAQABo1MwUTAdBgNVHQ4EFgQU60nJ4q3ItcfaOOBjJSqadAPiMg8wHwYDVR0jBBgwFoAU60nJ4q3ItcfaOOBjJSqadAPiMg8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAxIqIQ5SCXnKslZfrXiAEbB5dglxVOSa8me5a/70uHK/27JZ6veeIgRqZ4VgPHnBCa3m6EHr+mnTjjqSUcGIUiKV3g2Dumw8paqZC+Qv+Ib/NKquS1lO2Ry1wHBtXzn5KKHHyM1bWMDaDszirw2+pp22VdRrPZNA9NWXheEDYOLyQekyL2CfidhxhaXvUZyWgalLyF2XRZ5/jAT+NjfWw39EmWPUGk13Jm83OaFc1VdrXNCiD0sGCQ+BTCllDinQvR08yzd4fzA3YXthvX1dBu1SvqQAGOS7gssRCyv9uWI6MXta25X91eY1ZMz1euJ04mB8EdyYiZc0kzrb9dv5d0g==</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ca-certs>\n"
            "              <ee-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_cert</name>\n"
            "                    <cert-data>MIIEQDCCAygCCQCV65JgDvfWkDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMB4XDTE4MTEwNTA3MzAzOVoXDTI4MTEwMjA3MzAzOVowYTELMAkGA1UEBhMCQ1oxEzARBgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAcMBEJybm8xDzANBgNVBAoMBkNFU05FVDEMMAoGA1UECwwDVE1DMQ8wDQYDVQQDDAZjbGllbnQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+kqPqDL9GbWmqVQhp4qla4vYo4kFuh2HG48b7RLp/4l/guik4Hvq2aDVFD9sBcs3FeQbjoLH1Q4doUr8jG6VwJsfovE5SD3T8dVLs2dtpW0OyXTccb0I9lOVDMz6f6IUBe/m5vk8XNbdUII0NJ8y1dQ51VH3e784Bzu7PSdaMaFac4fkw8kJA9LxkWkv2FDFC7IBcVjRgtb/15EwODH849O6+VPEgX5gdozNj5bL45rKDBvvx0KjD7dFBGAIHbSjmjp7HHadfYKqvtQnMb83fRcK6wohxNP3vy13wBTtSOlvOg16Gb+2ZB0Or7wgOw19ZvEIcNgswPwhHfZQNcYMNVLCu02BSzwdY00IEqNM0J5B/W//KJF3uFF/ZqP7D2wO7w8j5UL2lpuxF7YrGecNT1Kr7ggHdkzcLlekkNu7wNWKAZlJ6+Kbun8PqZbamGXLG2Ur1aZDkyKyD9nyMzsRneAlxO+HbQhLojimUbsMm+wgL89zchLYkL/DSmsJlryA4qhvzHaaONBw4DV5UhSbLDpZtXVfrn+MAm8hLpqf+gUCThsFN8kDp9h9Tg9v01ai9jGb941HkFtGYUWHS5drSz3ZLnSI6i1/wKdbs9ns9YqDMqq2c305v5h7taMN0b40KuGSIME4K4cOsdfCprFYGZQgKjaadQwrsm4k1Jl7kMwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAtwH2u1o16jkABlqEGDIvAJSMwBmZzNTNHgOXtWDlkzWGsj+L1wc/DNjDRBkE31h4h7ASthhqi1nzzHYQ1hhPVhUUqI532AS/V7EPsBg3f+BI8gxqQ31TUBEQ4Ll6FtW36nqpJOe6Uui2rH2FonuUg2Av5BvDRil42Tu7fYW4WpSU3e00HiGJ0J0t+QjoKRnnoLJJqlmzk8Y4aIlQim7Azvrlo1WEtOhI3L9UE1GEqxLjRB45P36FSe1wfkgt7xmD0Xjy33Wh6Ae2Fvx7OfJ0K1zy0LHr4rDDJ3tLTqjPqHIFhaa73jGXwXk8sZnbAk542Oa6C6AjzNFyqV7T5Q5lg</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ee-certs>\n"
            "            </client-authentication>\n"
            "            <hello-params>\n"
            "              <tls-versions>\n"
            "                <max yang:operation=\"create\" xmlns:tlscmn=\"urn:ietf:params:xml:ns:yang:ietf-tls-common\">tlscmn:tls12</max>\n" // set to TLS1.2
            "              </tls-versions>\n"
            "              <cipher-suites yang:operation=\"create\">\n"
            "                <cipher-suite>TLS_AES_128_GCM_SHA256</cipher-suite>\n"
            "                <cipher-suite>TLS_AES_256_GCM_SHA384</cipher-suite>\n"
            "                <cipher-suite>TLS_CHACHA20_POLY1305_SHA256</cipher-suite>\n"
            "                <cipher-suite>TLS_AES_128_CCM_SHA256</cipher-suite>\n"
            "                <cipher-suite>TLS_AES_128_CCM_8_SHA256</cipher-suite>\n"
            "              </cipher-suites>\n"
            "            </hello-params>\n"
            "          </tls-server-parameters>\n"
            "          <netconf-server-parameters>\n"
            "            <client-identity-mappings>\n"
            "              <cert-to-name>\n"
            "                <id>1</id>\n"
            "                <fingerprint>04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D</fingerprint>\n"
            "                <map-type xmlns:x509c2n=\"urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name\">x509c2n:specified</map-type>\n"
            "                <name>client</name>\n"
            "              </cert-to-name>\n"
            "            </client-identity-mappings>\n"
            "          </netconf-server-parameters>\n"
            "        </tls>\n"
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

    /* apply the diff */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    free(diff_filled);
    lyd_free_all(tree);

    /* should not be able to connect */
    test_data->expect_fail = 1;
    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread_fail, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
    test_data->expect_fail = 0;

    /* reset to original config */
    ret = nc_server_config_setup_data(test_data->tree);
    assert_int_equal(ret, 0);

#if defined (MBEDTLS_TLS1_3_AES_256_GCM_SHA384) || !defined (HAVE_MBEDTLS)
    /* mbedtls v3.5.2 doesnt support TLS1.3 ciphersuites by default, so this can only
     * be tested when OpenSSL is used or mbedtls is built with TLS1.3 ciphersuites */

    /* set TLS1.3 with TLS1.3 ciphers and check that connection is ok */
    diff = "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\""
            " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
            "  <listen>\n"
            "    <endpoints>\n"
            "      <endpoint>\n"
            "        <name>endpt</name>\n"
            "        <tls>\n"
            "          <tcp-server-parameters>\n"
            "            <local-bind>\n"
            "              <local-address>127.0.0.1</local-address>\n"
            "              <local-port>%s</local-port>\n"
            "            </local-bind>\n"
            "          </tcp-server-parameters>\n"
            "          <tls-server-parameters>\n"
            "            <server-identity>\n"
            "              <certificate>\n"
            "                <inline-definition>\n"
            "                  <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>\n"
            "                  <cleartext-private-key>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</cleartext-private-key>\n"
            "                  <cert-data>MIIETjCCAzYCFEO1ljvG2ET9vb1itRsNMb8xN0R3MA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMjEwOTAzMTExNjMyWhcNMzEwOTAxMTExNjMyWjBkMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxEjAQBgNVBAMMCTEyNy4wLjAuMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOqI7Y3w5r8kD9WZCMAaa/e3ig7nm76aIJUR0Xb1bk6X/4FNVQKwEJsBodOYupZvE5FZdZ6DJSMSyQ3FrJWnlZ+isr7F9B4bELV8Kj6sJGuVAr+mpcH/4rwL3DaXF9Y9Lf7iBgiOHUoip80Asn9BU4q80JI6w2VHd5ng4TUE67gmpRleIHzViKt3taBrsAJ9bS5bvaE6xOB8zKYGzRFOsDZrEqqcBsVIWC6EmjO29HS5qj/mXM0ktFGnNDxTZHoRkNgmCE/NH+fNKOFxraCwlFBpKemAky+GdgngRGiQAVowyAx/nSmCFAalKc+E4ddoFwD/oft6iOvvXqaXh6368wEQ7Hy48FDcUCbHtUEgK4wMrX9BSrRh6zkXO1tE4ghb0dM2qFDS0ypO3p04kUPa31mTgLuOH1LzwmlwxOs113mlYKCgqOFR5YaN+nq1HI5RATPo5NvCMpG2RrQW+ooCr2GtbT0oHmJv8yaBVY0HJ69eLnIv37dfjWvoTiBKBBIisXAD5Nm9rwSjZUSFu1iyd7u2YrkBCUzZuvt3BOPpX8GgQgagU6BPnac76FF6DMhRUXlBXdTuWsbuH14LdNIzGjkMZhNL/Tpkf6S/z1iH5VReGc+clTjWGg1XO5fr3mNKBGa7hDydIZRIMbgsy63DIY7n5dqhNkO30CGmr/9TagVZAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEjP2Zed4zY/nProMy67JyI3vV2fDYpYUkPD7ofSjFHjQc3ooXfBCF6Ho0dCdBTpof6kGIjfDmhcKoVcPqr8A/EA1pEGOB0RZkCjrwEnbAVdIb/5QP6nLtm7M5md3dEF+rttfBwisH6CV4XbXXZct/cNP+MPK2sXevCK2w8Xbt9nHeI/MXZoUW3WNGFwlRNlmQxCIoI0hnge9Gyb0WcTciHvhm8WtUQI1Ff3DLDgcQZQ1oOhci+ocBJVhC9l9lDCOpu93coyM7PD4CbVTFxfnPnOy81525W6ya0nmZOKafG20bdc+T1LqMXM+uR5hBHsg9K6UbREHEoP3pLYW7zg0Aw=</cert-data>\n"
            "                </inline-definition>\n"
            "              </certificate>\n"
            "            </server-identity>\n"
            "            <client-authentication>\n"
            "              <ca-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_ca</name>\n"
            "                    <cert-data>MIIDnDCCAoSgAwIBAgIJAIjf7UNx4uabMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYDVQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcNMTgxMTA1MDcyNjM5WhcNMjgxMTAyMDcyNjM5WjBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyMrKraqraFGklO2itRIEWxfuzWo1IwxZ22aJmeXDLeomt6893NXelMLaC3swQ+hu49JjiIY81DXvbVgmIgLm7cAz5tHTHuJbfdI4Q6gyic4aOpy2s3s1/vYz+1TvEUFCiPXEsJrH72he/z9nBxL8vY6Eg8U8EG8NvKp9zyCKA7vmNSgQOtuyF18fesYHAnvQjNXO5q6diPXdHOr2bjTRUvARGbWlv4Rvf81RwUkRsWoF/0pglV/TxnW2MoHnn3apxb/kmH92CQ+GWKxq5SkhvbkYePlA87kgKnDtXl4wEXIhYwM51kafRhhlAKN+qYeV9teBqGpjsZRYesrh3mXHlQIDAQABo1MwUTAdBgNVHQ4EFgQU60nJ4q3ItcfaOOBjJSqadAPiMg8wHwYDVR0jBBgwFoAU60nJ4q3ItcfaOOBjJSqadAPiMg8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAxIqIQ5SCXnKslZfrXiAEbB5dglxVOSa8me5a/70uHK/27JZ6veeIgRqZ4VgPHnBCa3m6EHr+mnTjjqSUcGIUiKV3g2Dumw8paqZC+Qv+Ib/NKquS1lO2Ry1wHBtXzn5KKHHyM1bWMDaDszirw2+pp22VdRrPZNA9NWXheEDYOLyQekyL2CfidhxhaXvUZyWgalLyF2XRZ5/jAT+NjfWw39EmWPUGk13Jm83OaFc1VdrXNCiD0sGCQ+BTCllDinQvR08yzd4fzA3YXthvX1dBu1SvqQAGOS7gssRCyv9uWI6MXta25X91eY1ZMz1euJ04mB8EdyYiZc0kzrb9dv5d0g==</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ca-certs>\n"
            "              <ee-certs>\n"
            "                <inline-definition>\n"
            "                  <certificate>\n"
            "                    <name>client_cert</name>\n"
            "                    <cert-data>MIIEQDCCAygCCQCV65JgDvfWkDANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJDWjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMB4XDTE4MTEwNTA3MzAzOVoXDTI4MTEwMjA3MzAzOVowYTELMAkGA1UEBhMCQ1oxEzARBgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAcMBEJybm8xDzANBgNVBAoMBkNFU05FVDEMMAoGA1UECwwDVE1DMQ8wDQYDVQQDDAZjbGllbnQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC+kqPqDL9GbWmqVQhp4qla4vYo4kFuh2HG48b7RLp/4l/guik4Hvq2aDVFD9sBcs3FeQbjoLH1Q4doUr8jG6VwJsfovE5SD3T8dVLs2dtpW0OyXTccb0I9lOVDMz6f6IUBe/m5vk8XNbdUII0NJ8y1dQ51VH3e784Bzu7PSdaMaFac4fkw8kJA9LxkWkv2FDFC7IBcVjRgtb/15EwODH849O6+VPEgX5gdozNj5bL45rKDBvvx0KjD7dFBGAIHbSjmjp7HHadfYKqvtQnMb83fRcK6wohxNP3vy13wBTtSOlvOg16Gb+2ZB0Or7wgOw19ZvEIcNgswPwhHfZQNcYMNVLCu02BSzwdY00IEqNM0J5B/W//KJF3uFF/ZqP7D2wO7w8j5UL2lpuxF7YrGecNT1Kr7ggHdkzcLlekkNu7wNWKAZlJ6+Kbun8PqZbamGXLG2Ur1aZDkyKyD9nyMzsRneAlxO+HbQhLojimUbsMm+wgL89zchLYkL/DSmsJlryA4qhvzHaaONBw4DV5UhSbLDpZtXVfrn+MAm8hLpqf+gUCThsFN8kDp9h9Tg9v01ai9jGb941HkFtGYUWHS5drSz3ZLnSI6i1/wKdbs9ns9YqDMqq2c305v5h7taMN0b40KuGSIME4K4cOsdfCprFYGZQgKjaadQwrsm4k1Jl7kMwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAtwH2u1o16jkABlqEGDIvAJSMwBmZzNTNHgOXtWDlkzWGsj+L1wc/DNjDRBkE31h4h7ASthhqi1nzzHYQ1hhPVhUUqI532AS/V7EPsBg3f+BI8gxqQ31TUBEQ4Ll6FtW36nqpJOe6Uui2rH2FonuUg2Av5BvDRil42Tu7fYW4WpSU3e00HiGJ0J0t+QjoKRnnoLJJqlmzk8Y4aIlQim7Azvrlo1WEtOhI3L9UE1GEqxLjRB45P36FSe1wfkgt7xmD0Xjy33Wh6Ae2Fvx7OfJ0K1zy0LHr4rDDJ3tLTqjPqHIFhaa73jGXwXk8sZnbAk542Oa6C6AjzNFyqV7T5Q5lg</cert-data>\n"
            "                  </certificate>\n"
            "                </inline-definition>\n"
            "              </ee-certs>\n"
            "            </client-authentication>\n"
            "            <hello-params>\n"
            "              <tls-versions>\n"
            "                <min yang:operation=\"create\" xmlns:tlscmn=\"urn:ietf:params:xml:ns:yang:ietf-tls-common\">tlscmn:tls13</min>\n" // set to TLS1.3
            "              </tls-versions>\n"
            "              <cipher-suites yang:operation=\"create\">\n"
            "                <cipher-suite>TLS_AES_128_GCM_SHA256</cipher-suite>\n"
            "                <cipher-suite>TLS_AES_256_GCM_SHA384</cipher-suite>\n"
            "                <cipher-suite>TLS_CHACHA20_POLY1305_SHA256</cipher-suite>\n"
            "                <cipher-suite>TLS_AES_128_CCM_SHA256</cipher-suite>\n"
            "                <cipher-suite>TLS_AES_128_CCM_8_SHA256</cipher-suite>\n"
            "              </cipher-suites>\n"
            "            </hello-params>\n"
            "          </tls-server-parameters>\n"
            "          <netconf-server-parameters>\n"
            "            <client-identity-mappings>\n"
            "              <cert-to-name>\n"
            "                <id>1</id>\n"
            "                <fingerprint>04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D</fingerprint>\n"
            "                <map-type xmlns:x509c2n=\"urn:ietf:params:xml:ns:yang:ietf-x509-cert-to-name\">x509c2n:specified</map-type>\n"
            "                <name>client</name>\n"
            "              </cert-to-name>\n"
            "            </client-identity-mappings>\n"
            "          </netconf-server-parameters>\n"
            "        </tls>\n"
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

    /* apply the diff */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    free(diff_filled);
    lyd_free_all(tree);

    /* should not be able to connect */
    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    /* reset to original config */
    ret = nc_server_config_setup_data(test_data->tree);
    assert_int_equal(ret, 0);
#endif
}

static void
test_nc_tls_free_test_data(void *test_data)
{
    struct test_tls_data *data = test_data;

    lyd_free_all(data->tree);
    free(data);
}

static int
setup_f(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx;
    struct test_tls_data *test_data;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    *state = test_ctx;

    /* create new address and port data */
    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_TLS, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    /* create new server certificate data */
    ret = nc_server_config_add_tls_server_cert(test_ctx->ctx, "endpt", TESTS_DIR "/data/server.key", NULL, TESTS_DIR "/data/server.crt", &tree);
    assert_int_equal(ret, 0);

    /* create new end entity client cert data */
    ret = nc_server_config_add_tls_client_cert(test_ctx->ctx, "endpt", "client_cert", TESTS_DIR "/data/client.crt", &tree);
    assert_int_equal(ret, 0);

    /* create new client ca data */
    ret = nc_server_config_add_tls_ca_cert(test_ctx->ctx, "endpt", "client_ca", TESTS_DIR "/data/serverca.pem", &tree);
    assert_int_equal(ret, 0);

    /* create new cert-to-name */
    ret = nc_server_config_add_tls_ctn(test_ctx->ctx, "endpt", 1,
            "04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D",
            NC_TLS_CTN_SPECIFIED, "client", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    test_data = calloc(1, sizeof *test_data);
    assert_non_null(test_data);

    test_data->tree = tree;

    test_ctx->test_data = test_data;
    test_ctx->free_test_data = test_nc_tls_free_test_data;

    return 0;
}

static int
setup_intermediate_ca(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx;
    struct test_tls_data *test_data;

    ret = ln2_glob_test_setup(&test_ctx);
    assert_int_equal(ret, 0);

    *state = test_ctx;

    /* create new address and port data */
    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_TLS, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);

    /* create new server certificate data */
    ret = nc_server_config_add_tls_server_cert(test_ctx->ctx, "endpt", TESTS_DIR "/data/certs/server.key", NULL, TESTS_DIR "/data/certs/server.pem", &tree);
    assert_int_equal(ret, 0);

    /* add the root CA */
    ret = nc_server_config_add_tls_ca_cert(test_ctx->ctx, "endpt", "root_ca", TESTS_DIR "/data/certs/rootca.pem", &tree);
    assert_int_equal(ret, 0);

    /* add the intermediate CA */
    ret = nc_server_config_add_tls_ca_cert(test_ctx->ctx, "endpt", "intermediate_ca", TESTS_DIR "/data/certs/intermediate_ca.pem", &tree);
    assert_int_equal(ret, 0);

    /* create new cert-to-name */
    ret = nc_server_config_add_tls_ctn(test_ctx->ctx, "endpt", 1,
            "04:9F:36:25:23:52:1C:9D:9F:31:2C:A3:07:DF:71:8C:FD:66:93:E1:FA:7B:90:E7:C5:1D:50:A8:16:10:5B:F0:52",
            NC_TLS_CTN_SPECIFIED, "client", &tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    test_data = calloc(1, sizeof *test_data);
    assert_non_null(test_data);

    test_data->tree = tree;

    test_ctx->test_data = test_data;
    test_ctx->free_test_data = test_nc_tls_free_test_data;

    return 0;
}

static int
keylog_setup_f(void **state)
{
    unlink(KEYLOG_FILENAME);
    setenv("SSLKEYLOGFILE", KEYLOG_FILENAME, 1);

    return setup_f(state);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_tls, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_tls_ca_cert_only, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_tls_ee_cert_only, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_tls_intermediate_ca_server, setup_intermediate_ca, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_tls_intermediate_ca_client, setup_intermediate_ca, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_tls_ec_key, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_nc_tls_keylog, keylog_setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_cipher_suites, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_tls_version, setup_f, ln2_glob_test_teardown),
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
