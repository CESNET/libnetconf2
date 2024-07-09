/**
 * @file test_cert_exp_notif.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 certificate expiration notification test
 *
 * @copyright
 * Copyright (c) 2024 CESNET, z.s.p.o.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <cmocka.h>

#include "ln2_test.h"

#ifdef HAVE_MBEDTLS

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

#else

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#endif

#define VALID_CERT_ADD_SEC 15   /* should be enough even with valgrind on slower machines */
#define EXPIRED_CERT_ADD_SEC -10

/* leave a 2 second leeway at most for both sending and receiving */
#define NC_RECV_NOTIF_TIMEOUT (VALID_CERT_ADD_SEC + 2) * 1000
#define NC_SEND_NOTIF_TIMEOUT (VALID_CERT_ADD_SEC + 2) * 1000

struct ly_ctx *server_ctx, *client_ctx;

struct test_state {
    pthread_barrier_t barrier;
    pthread_barrier_t ntf_barrier;
    struct nc_server_notif *ntf;
    struct lyd_node *tree;
};

int TEST_PORT = 10050;
const char *TEST_PORT_STR = "10050";

#ifdef HAVE_MBEDTLS

static const char *
mbedtls_strerr(int err)
{
    const char *err_str;

    err_str = mbedtls_high_level_strerr(err);
    if (err_str) {
        return err_str;
    }

    err_str = mbedtls_low_level_strerr(err);
    if (err_str) {
        return err_str;
    }

    return "unknown error";
}

static int
custom_exp_date_cert_create(long offset_sec, char cert_path[12])
{
    int ret = 0, fd;
    mbedtls_pk_context pkey;
    mbedtls_x509write_cert cert;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    time_t exp_time;
    struct tm *exp_tm;
    const char *not_before = "20000101000000";
    char not_after[15];
    unsigned char output_buf[4096] = {0};
    mode_t umode;

    /* init */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_pk_init(&pkey);
    mbedtls_x509write_crt_init(&cert);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret) {
        fprintf(stderr, "mbedtls_ctr_drbg_seed() failed (%s)\n", mbedtls_strerr(ret));
        goto cleanup;
    }

    /* parse the private key */
    ret = mbedtls_pk_parse_keyfile(&pkey, TESTS_DIR "/data/client.key", NULL, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret) {
        fprintf(stderr, "mbedtls_pk_parse_keyfile() failed (%s)\n", mbedtls_strerr(ret));
        goto cleanup;
    }

    /* cert will be self signed, so the subject's and issuer's key can be the same */
    mbedtls_x509write_crt_set_subject_key(&cert, &pkey);
    mbedtls_x509write_crt_set_issuer_key(&cert, &pkey);

    /* likewise for their CNs */
    ret = mbedtls_x509write_crt_set_subject_name(&cert, "CN=cert_exp_test");
    if (ret) {
        fprintf(stderr, "mbedtls_x509write_crt_set_subject_name() failed (%s)\n", mbedtls_strerr(ret));
        goto cleanup;
    }

    ret = mbedtls_x509write_crt_set_issuer_name(&cert, "CN=cert_exp_test");
    if (ret) {
        fprintf(stderr, "mbedtls_x509write_crt_set_issuer_name() failed (%s)\n", mbedtls_strerr(ret));
        goto cleanup;
    }

    /* set SN to 1 */
    ret = mbedtls_x509write_crt_set_serial_raw(&cert, (unsigned char *)"1", 1);
    if (ret) {
        fprintf(stderr, "mbedtls_x509write_crt_set_serial_raw() failed (%s)\n", mbedtls_strerr(ret));
        goto cleanup;
    }

    /* generate the expiration date in GMT */
    exp_time = time(NULL) + offset_sec;
    exp_tm = gmtime(&exp_time);

    ret = strftime(not_after, 15, "%Y%m%d%H%M%S", exp_tm);
    if (ret != 14) {
        fprintf(stderr, "strftime() failed (%s)\n", strerror(errno));
        ret = 1;
        goto cleanup;
    }

    /* set the validity dates */
    ret = mbedtls_x509write_crt_set_validity(&cert, not_before, not_after);
    if (ret) {
        fprintf(stderr, "mbedtls_x509write_crt_set_validity() failed (%s)\n", mbedtls_strerr(ret));
        goto cleanup;
    }

    mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);

    /* write the cert to mem */
    ret = mbedtls_x509write_crt_pem(&cert, output_buf, 4096, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret < 0) {
        fprintf(stderr, "mbedtls_x509write_crt_pem() failed (%s)\n", mbedtls_strerr(ret));
        goto cleanup;
    }

    /* then create a tmp file and write it from mem to this file */
    umode = umask(0177);
    fd = mkstemp(cert_path);
    if (fd < 0) {
        fprintf(stderr, "mkstemp() failed (%s)\n", strerror(errno));
        ret = 1;
        goto cleanup;
    }
    umask(umode);

    if (write(fd, output_buf, strlen((char *)output_buf)) < 0) {
        fprintf(stderr, "write() failed (%s)\n", strerror(errno));
        ret = 1;
        goto cleanup;
    }

cleanup:
    mbedtls_x509write_crt_free(&cert);
    mbedtls_pk_free(&pkey);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

#else

static const char *
openssl_strerr(void)
{
    return ERR_reason_error_string(ERR_get_error());
}

static int
custom_exp_date_cert_create(long offset_sec, char cert_path[12])
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    X509_NAME *name;
    FILE *f;
    mode_t umode;
    BIO *out_bio = NULL;
    int fd;

    /* get the private key */
    f = fopen(TESTS_DIR "/data/client.key", "r");
    if (!f) {
        fprintf(stderr, "fopen() failed (%s)\n", strerror(errno));
        ret = 1;
        goto cleanup;
    }

    pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "PEM_read_PrivateKey() failed (%s)\n", openssl_strerr());
        ret = 1;
        goto cleanup;
    }

    /* new cert */
    cert = X509_new();
    if (!cert) {
        fprintf(stderr, "X509_new() failed (%s)\n", openssl_strerr());
        ret = 1;
        goto cleanup;
    }

    /* set the public key */
    if (!X509_set_pubkey(cert, pkey)) {
        fprintf(stderr, "X509_set_pubkey() failed (%s)\n", openssl_strerr());
        ret = 1;
        goto cleanup;
    }

    /* set the issuer's CN */
    name = X509_get_subject_name(cert);
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"cert_exp_test", -1, -1, 0)) {
        fprintf(stderr, "X509_NAME_add_entry_by_txt() failed (%s)\n", openssl_strerr());
        ret = 1;
        goto cleanup;
    }
    if (!X509_set_issuer_name(cert, name)) {
        fprintf(stderr, "X509_set_issuer_name() failed (%s)\n", openssl_strerr());
        ret = 1;
        goto cleanup;
    }

    /* set SN to 1 */
    if (!ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)) {
        fprintf(stderr, "ASN1_INTEGER_set() failed (%s)\n", openssl_strerr());
        ret = 1;
        goto cleanup;
    }

    /* set the validity dates */
    if (!X509_gmtime_adj(X509_get_notBefore(cert), 0) || !X509_gmtime_adj(X509_get_notAfter(cert), offset_sec)) {
        fprintf(stderr, "X509_gmtime_adj() failed (%s)\n", openssl_strerr());
        ret = 1;
        goto cleanup;
    }

    /* sign it using the private key */
    if (!X509_sign(cert, pkey, EVP_sha256())) {
        fprintf(stderr, "X509_sign() failed (%s)\n", openssl_strerr());
        ret = 1;
        goto cleanup;
    }

    /* write the cert to a file */
    umode = umask(0177);
    fd = mkstemp(cert_path);
    if (fd < 0) {
        fprintf(stderr, "mkstemp() failed (%s)\n", strerror(errno));
        ret = 1;
        goto cleanup;
    }
    umask(umode);

    out_bio = BIO_new_fd(fd, BIO_NOCLOSE);
    if (!out_bio) {
        fprintf(stderr, "BIO_new_fd() failed (%s)\n", openssl_strerr());
        ret = 1;
        goto cleanup;
    }

    if (!PEM_write_bio_X509(out_bio, cert)) {
        fprintf(stderr, "PEM_write_bio_X509() failed (%s)\n", openssl_strerr());
        ret = 1;
        goto cleanup;
    }

cleanup:
    if (f) {
        fclose(f);
    }
    X509_free(cert);
    EVP_PKEY_free(pkey);
    BIO_free(out_bio);
    return ret;
}

#endif

static void *
server_thread(void *arg)
{
    NC_MSG_TYPE msgtype;
    struct nc_session *session;
    struct test_state *state = arg;
    struct nc_pollsession *ps;
    int ret;

    ps = nc_ps_new();
    assert_non_null(ps);

    /* wait until the client is ready to connect */
    pthread_barrier_wait(&state->barrier);
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, server_ctx, &session);
    assert_int_equal(msgtype, NC_MSG_HELLO);

    /* add sess to ps */
    ret = nc_ps_add_session(ps, session);
    assert_int_equal(ret, 0);

    /* serve all the RPCs */
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
    } while (ret & NC_PSPOLL_RPC);

    /* increase session notification subscription flag count */
    nc_session_inc_notif_status(session);

    /* wait until the notif is ready to be sent */
    printf("Server waiting for the certificate to expire...\n");
    pthread_barrier_wait(&state->ntf_barrier);

    /* send the notif */
    msgtype = nc_server_notif_send(session, state->ntf, NC_SEND_NOTIF_TIMEOUT);
    assert_int_equal(msgtype, NC_MSG_NOTIF);

    /* wait until the client has received the notif and closed the session */
    pthread_barrier_wait(&state->barrier);

    nc_session_dec_notif_status(session);
    nc_server_notif_free(state->ntf);
    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);
    return NULL;
}

static void *
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct test_state *state = arg;
    NC_MSG_TYPE msgtype;
    struct lyd_node *envp, *op, *node;

    /* set schema search path */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set client cert */
    ret = nc_client_tls_set_cert_key_paths(TESTS_DIR "/data/client.crt", TESTS_DIR "/data/client.key");
    assert_int_equal(ret, 0);

    /* set client ca */
    ret = nc_client_tls_set_trusted_ca_paths(NULL, TESTS_DIR "/data");
    assert_int_equal(ret, 0);

    /* wait until the server is ready to accept the connection */
    pthread_barrier_wait(&state->barrier);
    session = nc_connect_tls("127.0.0.1", TEST_PORT, client_ctx);
    assert_non_null(session);

    /* receive the notif */
    msgtype = nc_recv_notif(session, NC_RECV_NOTIF_TIMEOUT, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_NOTIF);

    /* check the notif content and print the expiration date */
    ret = lyd_find_path(op, "expiration-date", 0, &node);
    assert_int_equal(ret, 0);
    printf("Certificate expires on :%s\n", lyd_get_value(node));

    /* close the session and signal the server */
    lyd_free_all(envp);
    lyd_free_all(op);
    nc_session_free(session, NULL);
    pthread_barrier_wait(&state->barrier);
    return NULL;
}

static void
nc_cert_exp_notif_cb(const char *exp_time, const char *xpath, void *user_data)
{
    int ret;
    struct nc_server_notif *ntf = NULL;
    struct lyd_node *ntf_data = NULL;
    time_t ntf_time;
    char *ntf_time_str = NULL;
    struct test_state *state = user_data;

    /* create the notification data */
    ret = lyd_new_path(NULL, server_ctx, xpath, exp_time, 0, &ntf_data);
    assert_int_equal(ret, 0);

    /* yang time str from time_t */
    ntf_time = time(NULL);
    ret = ly_time_time2str(ntf_time, NULL, &ntf_time_str);
    assert_int_equal(ret, 0);

    /* create the notification */
    ntf = nc_server_notif_new(ntf_data, ntf_time_str, NC_PARAMTYPE_FREE);
    assert_non_null(ntf);
    state->ntf = ntf;

    /* signal the server that the notif is ready to be sent */
    pthread_barrier_wait(&state->ntf_barrier);
}

static void
test_nc_cert_exp_notif_valid_cert(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *st = *state;
    char cert_path[12] = "/tmp/XXXXXX";

    assert_non_null(state);

    /* create a soon expiring cert and get a path to it */
    ret = custom_exp_date_cert_create(VALID_CERT_ADD_SEC, cert_path);
    assert_int_equal(ret, 0);

    /* create new end entity client cert data */
    ret = nc_server_config_add_tls_client_cert(server_ctx, "endpt", "exp_cert_test", cert_path, &st->tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(st->tree);
    assert_int_equal(ret, 0);

    /* start the cert exp notification thread */
    ret = nc_server_notif_cert_expiration_thread_start(nc_cert_exp_notif_cb, st, NULL);
    assert_int_equal(ret, 0);

    /* start the client and server threads */
    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    /* stop the cert exp notif thread */
    nc_server_notif_cert_expiration_thread_stop(1);
}

static void
test_nc_cert_exp_notif_expired_cert(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct test_state *st = *state;
    char cert_path[12] = "/tmp/XXXXXX";

    assert_non_null(state);

    /* create an expired cert and get a path to it */
    ret = custom_exp_date_cert_create(EXPIRED_CERT_ADD_SEC, cert_path);
    assert_int_equal(ret, 0);

    /* create new end entity client cert data from it */
    ret = nc_server_config_add_tls_client_cert(server_ctx, "endpt", "exp_cert_test", cert_path, &st->tree);
    assert_int_equal(ret, 0);

    /* configure the server based on the data */
    ret = nc_server_config_setup_data(st->tree);
    assert_int_equal(ret, 0);

    /* start the cert exp notification thread */
    ret = nc_server_notif_cert_expiration_thread_start(nc_cert_exp_notif_cb, st, NULL);
    assert_int_equal(ret, 0);

    /* start the client and server threads */
    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    /* stop the cert exp notif thread */
    nc_server_notif_cert_expiration_thread_stop(1);
}

static void
test_nc_cert_exp_notif_bad_interval_period(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    const  char *invalid_data =
            "<ln2-netconf-server xmlns=\"urn:cesnet:libnetconf2-netconf-server\">\n"
            "  <certificate-expiration-notif-intervals>\n"
            "    <interval>\n"
            "      <anchor>5d</anchor>\n"
            "      <period>1w</period>\n"
            "    </interval>\n"
            "  </certificate-expiration-notif-intervals>\n"
            "</ln2-netconf-server>";

    (void) state;

    /* validating this data should fail because of a must condition, the period
     * must not be bigger than the anchor (at least unit wise) */
    ret = lyd_parse_data_mem(server_ctx, invalid_data, LYD_XML, 0, LYD_VALIDATE_PRESENT, &tree);
    assert_int_not_equal(ret, 0);
}

static void
init_test_ctx(struct ly_ctx **ctx)
{
    int ret;
    struct lys_module *mod;
    const char *ietf_ct_features[] = {"cleartext-passwords", "cleartext-private-keys", "certificate-expiration-notification", NULL};

    ret = ly_ctx_new(MODULES_DIR, 0, ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_init_ctx(ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_config_load_modules(ctx);
    assert_int_equal(ret, 0);

    mod = ly_ctx_get_module_implemented(*ctx, "ietf-crypto-types");
    assert_non_null(mod);

    /* enable the certificate-expiration-notification feature */
    ret = lys_set_implemented(mod, ietf_ct_features);
    assert_int_equal(ret, 0);
}

static int
setup_f(void **state)
{
    int ret;
    struct test_state *st;

    nc_verbosity(NC_VERB_VERBOSE);

    /* init barriers */
    st = malloc(sizeof *st);
    assert_non_null(st);

    ret = pthread_barrier_init(&st->barrier, NULL, 2);
    assert_int_equal(ret, 0);

    ret = pthread_barrier_init(&st->ntf_barrier, NULL, 2);
    assert_int_equal(ret, 0);

    st->tree = NULL;
    st->ntf = NULL;

    *state = st;

    /* init server */
    ret = nc_server_init();
    assert_int_equal(ret, 0);

    /* init client */
    ret = nc_client_init();
    assert_int_equal(ret, 0);

    /* init server ctx */
    init_test_ctx(&server_ctx);

    /* init client ctx to avoid the need to implement get-schema */
    init_test_ctx(&client_ctx);

    /* create new address and port data */
    ret = nc_server_config_add_address_port(server_ctx, "endpt", NC_TI_TLS, "127.0.0.1", TEST_PORT, &st->tree);
    assert_int_equal(ret, 0);

    /* create new server certificate data */
    ret = nc_server_config_add_tls_server_cert(server_ctx, "endpt", TESTS_DIR "/data/server.key", NULL, TESTS_DIR "/data/server.crt", &st->tree);
    assert_int_equal(ret, 0);

    /* create new end entity client cert data */
    ret = nc_server_config_add_tls_client_cert(server_ctx, "endpt", "client_cert", TESTS_DIR "/data/client.crt", &st->tree);
    assert_int_equal(ret, 0);

    /* create new client ca data */
    ret = nc_server_config_add_tls_ca_cert(server_ctx, "endpt", "client_ca", TESTS_DIR "/data/serverca.pem", &st->tree);
    assert_int_equal(ret, 0);

    /* create new cert-to-name */
    ret = nc_server_config_add_tls_ctn(server_ctx, "endpt", 1,
            "04:85:6B:75:D1:1A:86:E0:D8:FE:5B:BD:72:F5:73:1D:07:EA:32:BF:09:11:21:6A:6E:23:78:8E:B6:D5:73:C3:2D",
            NC_TLS_CTN_SPECIFIED, "client", &st->tree);
    assert_int_equal(ret, 0);

    return 0;
}

static int
teardown_f(void **state)
{
    int ret = 0;
    struct test_state *test_state;

    assert_non_null(state);
    test_state = *state;

    ret = pthread_barrier_destroy(&test_state->barrier);
    assert_int_equal(ret, 0);

    ret = pthread_barrier_destroy(&test_state->ntf_barrier);
    assert_int_equal(ret, 0);

    lyd_free_all(test_state->tree);

    free(*state);
    nc_client_destroy();
    nc_server_destroy();
    ly_ctx_destroy(server_ctx);
    ly_ctx_destroy(client_ctx);

    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_cert_exp_notif_valid_cert, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_cert_exp_notif_expired_cert, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_cert_exp_notif_bad_interval_period, setup_f, teardown_f),
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
