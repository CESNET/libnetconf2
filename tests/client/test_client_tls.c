#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <session_client.h>
#include <log.h>
#include <config.h>
#include "tests/config.h"

static int
setup_f(void **state)
{
    (void)state;

    nc_verbosity(NC_VERB_VERBOSE);

    return 0;
}

static int
teardown_f(void **state)
{
    (void)state;

    return 0;
}

MOCK int
__wrap_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    (void)sockfd;
    (void)addr;
    (void)addrlen;

    return (int)mock();
}

MOCK int
__wrap_SSL_connect(SSL *ssl)
{
    (void)ssl;

    return (int)mock();
}

MOCK int
__wrap_nc_handshake_io(struct nc_session *session)
{
    (void)session;

    return (int)mock();
}

MOCK int
__wrap_nc_ctx_check_and_fill(struct nc_session *session)
{
    (void)session;

    return (int)mock();
}

static void
test_nc_client_tls_setting_cert_key_paths(void **state)
{
    (void)state;
    const char *cert, *key;
    int ret;

    nc_client_init();

    /* no certificats are set, nc_client_tls_get_cert_key_paths should output NULL */
    nc_client_tls_get_cert_key_paths(&cert, &key);
    assert_null(cert);
    assert_null(key);

    /* set certificate path */
    ret = nc_client_tls_set_cert_key_paths("cert_path", "key_path");
    assert_int_equal(ret, 0);
    nc_client_tls_get_cert_key_paths(&cert, &key);
    assert_string_equal(cert, "cert_path");
    assert_string_equal(key, "key_path");

    /* override certificate path */
    ret = nc_client_tls_set_cert_key_paths("cert_path1", "key_path1");
    assert_int_equal(ret, 0);
    nc_client_tls_get_cert_key_paths(&cert, &key);
    assert_string_equal(cert, "cert_path1");
    assert_string_equal(key, "key_path1");
}

static void
test_nc_client_tls_setting_trusted_ca_paths(void **state)
{
    (void)state;
    const char *file, *dir;
    int ret;

    ret = nc_client_tls_set_trusted_ca_paths("ca_file", "ca_dir");
    assert_int_equal(ret, 0);
    nc_client_tls_get_trusted_ca_paths(&file, &dir);
    assert_string_equal("ca_file", file);
    assert_string_equal("ca_dir", dir);

    ret = nc_client_tls_set_trusted_ca_paths("ca_file1", "ca_dir1");
    assert_int_equal(ret, 0);
    nc_client_tls_get_trusted_ca_paths(&file, &dir);
    assert_string_equal("ca_file1", file);
    assert_string_equal("ca_dir1", dir);
}

static void
test_nc_connect_tls_succesfull(void **state)
{
    (void)state;
    int ret;
    struct nc_session *session;

    ret = nc_client_tls_set_cert_key_paths(TESTS_DIR"/data/client.crt", TESTS_DIR"/data/client.key");
    assert_int_equal(ret, 0);
    ret = nc_client_tls_set_trusted_ca_paths(NULL, TESTS_DIR"/data");
    assert_int_equal(ret, 0);

    will_return(__wrap_connect, 0);
    will_return(__wrap_SSL_connect, 1);

    /* fake succesfull handshake */
    will_return(__wrap_nc_handshake_io, 3);
    will_return(__wrap_nc_ctx_check_and_fill, 0);
    session = nc_connect_tls("0.0.0.0", 6001, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
}

static void
test_nc_client_tls_setting_crl_paths(void **state)
{
    (void)state;
    const char *file, *dir;
    int ret;

    nc_client_tls_get_crl_paths(&file, &dir);
    assert_null(file);
    assert_null(dir);

    ret = nc_client_tls_set_crl_paths("file", "dir");
    assert_int_equal(ret, 0);
    nc_client_tls_get_crl_paths(&file, &dir);
    assert_string_equal(file, "file");
    assert_string_equal(dir, "dir");

    ret = nc_client_tls_set_crl_paths("file1", "dir1");
    assert_int_equal(ret, 0);
    nc_client_tls_get_crl_paths(&file, &dir);
    assert_string_equal(file, "file1");
    assert_string_equal(dir, "dir1");

    /* destroy client */
    nc_client_destroy();
}

static void
test_nc_connect_tls_handshake_failed(void **state)
{
    (void)state;
    int ret;
    struct nc_session *session;

    ret = nc_client_tls_set_cert_key_paths(TESTS_DIR"/data/client.crt", TESTS_DIR"/data/client.key");
    assert_int_equal(ret, 0);
    ret = nc_client_tls_set_trusted_ca_paths(NULL, TESTS_DIR"/data");
    assert_int_equal(ret, 0);

    will_return(__wrap_connect, 0);
    will_return(__wrap_SSL_connect, 1);

    /* fake failed handshake */
    will_return(__wrap_nc_handshake_io, 0);
    session = nc_connect_tls("0.0.0.0", 6001, NULL);
    assert_null(session);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_client_tls_setting_cert_key_paths, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_tls_handshake_failed, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_tls_succesfull, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_tls_setting_trusted_ca_paths, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_tls_setting_crl_paths, setup_f, teardown_f),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}