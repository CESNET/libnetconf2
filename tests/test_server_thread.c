/**
 * \file test_server_thread.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 tests - thread-safety of all server functions
 *
 * Copyright (c) 2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <libyang/libyang.h>

#include <session_client.h>
#include <session_server.h>
#include <log.h>
#include "tests/config.h"

/* millisec */
#define NC_ACCEPT_TIMEOUT 5000
/* millisec */
#define NC_PS_POLL_TIMEOUT 5000
/* sec */
#define CLIENT_SSH_AUTH_TIMEOUT 10

#define nc_assert(cond) if (!(cond)) { fprintf(stderr, "assert failed (%s:%d)\n", __FILE__, __LINE__); exit(1); }

pthread_barrier_t barrier;

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)

static void *
server_thread(void *arg)
{
    (void)arg;
    NC_MSG_TYPE msgtype;
    int ret;
    struct nc_pollsession *ps;
    struct nc_session *session;

    ps = nc_ps_new();
    nc_assert(ps);

    pthread_barrier_wait(&barrier);

#if defined(NC_ENABLED_SSH) && defined(NC_ENABLED_TLS)
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, &session);
    nc_assert(msgtype == NC_MSG_HELLO);

    nc_ps_add_session(ps, session);
    ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
    nc_assert(ret & NC_PSPOLL_RPC);
    nc_ps_clear(ps, 0, NULL);
#endif

    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, &session);
    nc_assert(msgtype == NC_MSG_HELLO);

    nc_ps_add_session(ps, session);
    ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
    nc_assert(ret & NC_PSPOLL_RPC);
    nc_ps_clear(ps, 0, NULL);

    nc_ps_free(ps);

    nc_thread_destroy();
    return NULL;
}

#endif /* NC_ENABLED_SSH || NC_ENABLED_TLS */

#ifdef NC_ENABLED_SSH

static int
clb_hostkeys(const char *name, void *UNUSED(user_data), char **privkey_path, char **UNUSED(privkey_data),
             int *UNUSED(privkey_data_rsa))
{
    if (!strcmp(name, "key_rsa")) {
        *privkey_path = strdup(TESTS_DIR"/data/key_rsa");
        return 0;
    } else if (!strcmp(name, "key_dsa")) {
        *privkey_path = strdup(TESTS_DIR"/data/key_dsa");
        return 0;
    }

    return 1;
}

static void *
add_endpt_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);
    ret = nc_server_add_endpt("tertiary", NC_TI_LIBSSH);
    nc_assert(!ret);

    return NULL;
}

static void *
del_endpt_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_del_endpt("secondary", 0);
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_set_hostkey_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_add_hostkey("main_ssh", "key_dsa", -1);
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_set_auth_methods_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_set_auth_methods("main_ssh", NC_SSH_AUTH_PUBLICKEY | NC_SSH_AUTH_PASSWORD | NC_SSH_AUTH_INTERACTIVE);
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_set_auth_attempts_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_set_auth_attempts("main_ssh", 2);
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_set_auth_timeout_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_set_auth_timeout("main_ssh", 5);
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_add_authkey_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_add_authkey_path(TESTS_DIR"/data/key_rsa.pub", "test3");
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_del_authkey_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_del_authkey(TESTS_DIR"/data/key_ecdsa.pub", NULL, 0, "test2");
    nc_assert(!ret);

    return NULL;
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
ssh_client_thread(void *arg)
{
    int ret, read_pipe = *(int *)arg;
    char buf[9];
    struct nc_session *session;

    ret = read(read_pipe, buf, 9);
    nc_assert(ret == 9);
    nc_assert(!strncmp(buf, "ssh_ready", 9));

    /* skip the knownhost check */
    nc_client_ssh_set_auth_hostkey_check_clb(ssh_hostkey_check_clb, NULL);

    ret = nc_client_ssh_set_username("test");
    nc_assert(!ret);

    ret = nc_client_ssh_add_keypair(TESTS_DIR"/data/key_dsa.pub", TESTS_DIR"/data/key_dsa");
    nc_assert(!ret);

    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, 1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, -1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, -1);

    session = nc_connect_ssh("127.0.0.1", 6001, NULL);
    nc_assert(session);

    nc_session_free(session, NULL);

    fprintf(stdout, "SSH client finished.\n");

    nc_thread_destroy();
    return NULL;
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

static int
clb_server_cert(const char *name, void *UNUSED(user_data), char **cert_path, char **cert_data, char **privkey_path,
                char **privkey_data, int *privkey_data_rsa)
{
    if (!strcmp(name, "server_cert1")) {
        *cert_data = strdup("MIIEQDCCAygCCQCV65JgDvfWkTANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJD\n"
            "WjETMBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwG\n"
            "Q0VTTkVUMQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMB4XDTE4MTEw\n"
            "NTA3MzExMFoXDTI4MTEwMjA3MzExMFowYTELMAkGA1UEBhMCQ1oxEzARBgNVBAgM\n"
            "ClNvbWUtU3RhdGUxDTALBgNVBAcMBEJybm8xDzANBgNVBAoMBkNFU05FVDEMMAoG\n"
            "A1UECwwDVE1DMQ8wDQYDVQQDDAZzZXJ2ZXIwggIiMA0GCSqGSIb3DQEBAQUAA4IC\n"
            "DwAwggIKAoICAQDqiO2N8Oa/JA/VmQjAGmv3t4oO55u+miCVEdF29W5Ol/+BTVUC\n"
            "sBCbAaHTmLqWbxORWXWegyUjEskNxayVp5WforK+xfQeGxC1fCo+rCRrlQK/pqXB\n"
            "/+K8C9w2lxfWPS3+4gYIjh1KIqfNALJ/QVOKvNCSOsNlR3eZ4OE1BOu4JqUZXiB8\n"
            "1Yird7Wga7ACfW0uW72hOsTgfMymBs0RTrA2axKqnAbFSFguhJoztvR0uao/5lzN\n"
            "JLRRpzQ8U2R6EZDYJghPzR/nzSjhca2gsJRQaSnpgJMvhnYJ4ERokAFaMMgMf50p\n"
            "ghQGpSnPhOHXaBcA/6H7eojr716ml4et+vMBEOx8uPBQ3FAmx7VBICuMDK1/QUq0\n"
            "Yes5FztbROIIW9HTNqhQ0tMqTt6dOJFD2t9Zk4C7jh9S88JpcMTrNdd5pWCgoKjh\n"
            "UeWGjfp6tRyOUQEz6OTbwjKRtka0FvqKAq9hrW09KB5ib/MmgVWNByevXi5yL9+3\n"
            "X41r6E4gSgQSIrFwA+TZva8Eo2VEhbtYsne7tmK5AQlM2br7dwTj6V/BoEIGoFOg\n"
            "T52nO+hRegzIUVF5QV3U7lrG7h9eC3TSMxo5DGYTS/06ZH+kv89Yh+VUXhnPnJU4\n"
            "1hoNVzuX695jSgRmu4Q8nSGUSDG4LMutwyGO5+XaoTZDt9Ahpq//U2oFWQIDAQAB\n"
            "MA0GCSqGSIb3DQEBCwUAA4IBAQAXWHf/MG8RPCyA0rC3RwxmM70ndyKPIJoL4ggU\n"
            "VgkN66BdpsE4UlWdlp0XL3aauMPxzLn9rq1yRtoHWT4/ucL9iEa6B295JBNjkgW+\n"
            "ct9/y8060P9BUhY1DTv5DLzitsA4bjRaraIevjATDPfsbHFx9DTNrS5pXHIFbRcz\n"
            "y3WniYXTKhpfM6m+1X8ogImE968DG8RqAW5YZZtrZW0VF/dhlQp20jEX/8Rv33Bp\n"
            "RhNEIhPnYAquKCesMMclUtPW+5n2z8rgj5t/ETv4wc5QegpyPfdHNq09bGKB10Sy\n"
            "sGvC6hP9GKU3R2Jhxih/t88O3WoisFQ8+Tf9s2LuSxUV0bzp");
        *privkey_data = strdup("MIIJKAIBAAKCAgEA6ojtjfDmvyQP1ZkIwBpr97eKDuebvpoglRHRdvVuTpf/gU1V\n"
            "ArAQmwGh05i6lm8TkVl1noMlIxLJDcWslaeVn6KyvsX0HhsQtXwqPqwka5UCv6al\n"
            "wf/ivAvcNpcX1j0t/uIGCI4dSiKnzQCyf0FTirzQkjrDZUd3meDhNQTruCalGV4g\n"
            "fNWIq3e1oGuwAn1tLlu9oTrE4HzMpgbNEU6wNmsSqpwGxUhYLoSaM7b0dLmqP+Zc\n"
            "zSS0Uac0PFNkehGQ2CYIT80f580o4XGtoLCUUGkp6YCTL4Z2CeBEaJABWjDIDH+d\n"
            "KYIUBqUpz4Th12gXAP+h+3qI6+9eppeHrfrzARDsfLjwUNxQJse1QSArjAytf0FK\n"
            "tGHrORc7W0TiCFvR0zaoUNLTKk7enTiRQ9rfWZOAu44fUvPCaXDE6zXXeaVgoKCo\n"
            "4VHlho36erUcjlEBM+jk28IykbZGtBb6igKvYa1tPSgeYm/zJoFVjQcnr14uci/f\n"
            "t1+Na+hOIEoEEiKxcAPk2b2vBKNlRIW7WLJ3u7ZiuQEJTNm6+3cE4+lfwaBCBqBT\n"
            "oE+dpzvoUXoMyFFReUFd1O5axu4fXgt00jMaOQxmE0v9OmR/pL/PWIflVF4Zz5yV\n"
            "ONYaDVc7l+veY0oEZruEPJ0hlEgxuCzLrcMhjufl2qE2Q7fQIaav/1NqBVkCAwEA\n"
            "AQKCAgAeRZw75Oszoqj0jfMmMILdD3Cfad+dY3FvLESYESeyt0XAX8XoOed6ymQj\n"
            "1qPGxQGGkkBvPEgv1b3jrC8Rhfb3Ct39Z7mRpTar5iHhwwBUboBTUmQ0vR173iAH\n"
            "X8sw2Oa17mCO/CDlr8Fu4Xcom7r3vlVBepo72VSjpPYMjN0MANjwhEi3NCyWzTXB\n"
            "RgUK3TuZbzfzto0w2Irlpx0S7dAqxfk70jXBgwv2vSDWKfg1lL1X0BkMVX98xpMk\n"
            "cjMW2muSqp4KBtTma4GqT6z0f7Y1Bs3lGLZmvPlBXxQVVvkFtiQsENCtSd/h17Gk\n"
            "2mb4EbReaaBzwCYqJdRWtlpJ54kzy8U00co+Yn//ZS7sbbIDkqHPnXkpdIr+0rED\n"
            "MlOw2Y3vRZCxqZFqfWCW0uzhwKqk2VoYqtDL+ORKG/aG/KTBQ4Y71Uh+7aabPwj5\n"
            "R+NaVMjbqmrVeH70eKjoNVgcNYY1C9rGVF1d+LQEm7UsqS0DPp4wN9QKLAqIfuar\n"
            "AhQBhZy1R7Sj1r5macD9DsGxsurM4mHZV0LNmYLZiFHjTUb6iRSPD5RBFW80vcNt\n"
            "xZ0cxmkLtxrj/DVyExV11Cl0SbZLLa9mScYvxdl/qZutXt3PQyab0NiYxGzCD2Rn\n"
            "LkCyxkh1vuHHjhvIWYfbd2VgZB/qGr+o9T07FGfMCu23//fugQKCAQEA9UH38glH\n"
            "/rAjZ431sv6ryUEFY8I2FyLTijtvoj9CNGcQn8vJQAHvUPfMdyqDoum6wgcTmG+U\n"
            "XA6mZzpGQCiY8JW5CoItgXRoYgNzpvVVe2aLf51QGtNLLEFpNDMpCtI+I+COpAmG\n"
            "vWAukku0pZfRjm9eb1ydvTpHlFC9+VhVUsLzw3VtSC5PVW6r65mZcYcB6SFVPap+\n"
            "31ENP/9jOMFoymh57lSMZJMxTEA5b0l2miFb9Rp906Zqiud5zv2jIqF6gL70giW3\n"
            "ovVxR7LGKKTKIa9pxawHwB6Ithygs7YoJkjF2dm8pZTMZKsQN92K70XGj07SmYRL\n"
            "ZpkVD7i+cqbbKQKCAQEA9M6580Rcw6W0twfcy0/iB4U5ZS52EcCjW8vHlL+MpUo7\n"
            "YvXadSgV1ZaM28zW/ZGk3wE0zy1YT5s30SQkm0NiWN3t/J0l19ccAOxlPWfjhF7v\n"
            "IQZr7XMo5HeaK0Ak5+68J6bx6KgcXmlJOup7INaE8DyGXB6vd4K6957IXyqs3/bf\n"
            "JAUmz49hnveCfLFdTVVT/Uq4IoPKfQSbSZc0BvPBsnBCF164l4jllGBaWS302dhg\n"
            "W4cgxzG0SZGgNwow4AhB+ygiiS8yvOa7UcHfUObVrzWeeq9mYSQ1PkvUTjkWR2/Y\n"
            "8xy7WP0TRBdJOVSs90H51lerEDGNQWvQvI97S9ZOsQKCAQB59u9lpuXtqwxAQCFy\n"
            "fSFSuQoEHR2nDcOjF4GhbtHum15yCPaw5QVs/33nuPWze4ZLXReKk9p0mTh5V0p+\n"
            "N3IvGlXl+uzEVu5d55eI7LIw5sLymHmwjWjxvimiMtrzLbCHSPHGc5JU9NLUH9/b\n"
            "BY/JxGpy+NzcsHHOOQTwTdRIjviIOAo7fgQn2RyX0k+zXE8/7zqjqvji9zyemdNu\n"
            "8we4uJICSntyvJwkbj/hrufTKEnBrwXpzfVn1EsH+6w32ZPBGLUhT75txJ8r56SR\n"
            "q7l1XPU9vxovmT+lSMFF/Y0j1MbHWnds5H1shoFPNtYTvWBL/gfPHjIc+H23zsiu\n"
            "3XlZAoIBAC2xB/Pnpoi9vOUMiqFH36AXtYa1DURy+AqCFlYlClMvb7YgvQ1w1eJv\n"
            "nwrHSLk7HdKhnwGsLPduuRRH8q0n/osnoOutSQroE0n41UyIv2ZNccRwNmSzQcai\n"
            "rBu2dSz02hlsh2otNl5IuGpOqXyPjXBpW4qGD6n2tH7THALnLC0BHtTSQVQsJsRM\n"
            "3gX39LoiWvLDp2qJvplm6rTpi8Rgap6rZSqHe1yNKIxxD2vlr/WY9SMgLXYASO4S\n"
            "SBz9wfGOmQIPk6KXNJkdV4kC7nNjIi75iwLLCgjHgUiHTrDq5sWekpeNnUoWsinb\n"
            "Tsdsjnv3zHG9GyiClyLGxMbs4M5eyYECggEBAKuC8ZMpdIrjk6tERYB6g0LnQ7mW\n"
            "8XYbDFAmLYMLs9yfG2jcjVbsW9Kugsr+3poUUv/q+hNO3jfY4HazhZDa0MalgNPo\n"
            "Swr/VNRnkck40x2ovFb989J7yl++zTrnIrax9XRH1V0cNu+Kj7OMwZ2RRfbNv5JB\n"
            "dOZPvkfqyIKFmbQgYbtD66rHuzNOfJpzqr/WVLO57/zzW8245NKG2B6B0oXkei/K\n"
            "qDY0DAbHR3i3EOj1NPtVI1FC/xX8R9BREaid458bqoHJKuInrGcBjaUI9Cvymv8T\n"
            "bstUgD6NPbJR4Sm6vrLeUqzjWZP3t1+Z6DjXmnpR2vvhMU/FWb//21p/88o=");
        *privkey_data_rsa = 1;
        return 0;
    } else if (!strcmp(name, "main_cert")) {
        *cert_path = strdup(TESTS_DIR"/data/server.crt");
        *privkey_path = strdup(TESTS_DIR"/data/server.key");
        return 0;
    }

    return 1;
}

static int
clb_trusted_cert_lists(const char *name, void *UNUSED(user_data), char ***cert_paths, int *cert_path_count,
                       char ***cert_data, int *cert_data_count)
{
    if (!strcmp(name, "trusted_cert_list1")) {
        *cert_data = malloc(sizeof **cert_data);
        (*cert_data)[0] = strdup("MIIDnDCCAoSgAwIBAgIJAIjf7UNx4uabMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV\n"
            "BAYTAkNaMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQHDARCcm5vMQ8wDQYD\n"
            "VQQKDAZDRVNORVQxDDAKBgNVBAsMA1RNQzERMA8GA1UEAwwIc2VydmVyY2EwHhcN\n"
            "MTgxMTA1MDcyNjM5WhcNMjgxMTAyMDcyNjM5WjBjMQswCQYDVQQGEwJDWjETMBEG\n"
            "A1UECAwKU29tZS1TdGF0ZTENMAsGA1UEBwwEQnJubzEPMA0GA1UECgwGQ0VTTkVU\n"
            "MQwwCgYDVQQLDANUTUMxETAPBgNVBAMMCHNlcnZlcmNhMIIBIjANBgkqhkiG9w0B\n"
            "AQEFAAOCAQ8AMIIBCgKCAQEAyMrKraqraFGklO2itRIEWxfuzWo1IwxZ22aJmeXD\n"
            "Leomt6893NXelMLaC3swQ+hu49JjiIY81DXvbVgmIgLm7cAz5tHTHuJbfdI4Q6gy\n"
            "ic4aOpy2s3s1/vYz+1TvEUFCiPXEsJrH72he/z9nBxL8vY6Eg8U8EG8NvKp9zyCK\n"
            "A7vmNSgQOtuyF18fesYHAnvQjNXO5q6diPXdHOr2bjTRUvARGbWlv4Rvf81RwUkR\n"
            "sWoF/0pglV/TxnW2MoHnn3apxb/kmH92CQ+GWKxq5SkhvbkYePlA87kgKnDtXl4w\n"
            "EXIhYwM51kafRhhlAKN+qYeV9teBqGpjsZRYesrh3mXHlQIDAQABo1MwUTAdBgNV\n"
            "HQ4EFgQU60nJ4q3ItcfaOOBjJSqadAPiMg8wHwYDVR0jBBgwFoAU60nJ4q3Itcfa\n"
            "OOBjJSqadAPiMg8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA\n"
            "xIqIQ5SCXnKslZfrXiAEbB5dglxVOSa8me5a/70uHK/27JZ6veeIgRqZ4VgPHnBC\n"
            "a3m6EHr+mnTjjqSUcGIUiKV3g2Dumw8paqZC+Qv+Ib/NKquS1lO2Ry1wHBtXzn5K\n"
            "KHHyM1bWMDaDszirw2+pp22VdRrPZNA9NWXheEDYOLyQekyL2CfidhxhaXvUZyWg\n"
            "alLyF2XRZ5/jAT+NjfWw39EmWPUGk13Jm83OaFc1VdrXNCiD0sGCQ+BTCllDinQv\n"
            "R08yzd4fzA3YXthvX1dBu1SvqQAGOS7gssRCyv9uWI6MXta25X91eY1ZMz1euJ04\n"
            "mB8EdyYiZc0kzrb9dv5d0g==");
        *cert_data_count = 1;
        return 0;
    } else if (!strcmp(name, "client_cert_list")) {
        *cert_paths = malloc(sizeof **cert_paths);
        (*cert_paths)[0] = strdup(TESTS_DIR"/data/client.crt");
        *cert_path_count = 1;
        return 0;
    }

    return 1;
}

static void *
endpt_set_address_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_endpt_set_address("quaternary", "0.0.0.0");
    nc_assert(!ret);

    return NULL;
}

static void *
endpt_set_port_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_endpt_set_port("quaternary", 6003);
    nc_assert(!ret);

    return NULL;
}

static void *
tls_endpt_set_server_cert_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_endpt_set_server_cert("quaternary", "server_cert1");
    nc_assert(!ret);

    nc_thread_destroy();
    return NULL;
}

static void *
tls_endpt_add_trusted_cert_list_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_endpt_add_trusted_cert_list("quaternary", "trusted_cert_list1");
    nc_assert(!ret);

    nc_thread_destroy();
    return NULL;
}

static void *
tls_endpt_set_trusted_ca_paths_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_endpt_set_trusted_ca_paths("quaternary", TESTS_DIR"/data/serverca.pem", "data");
    nc_assert(!ret);

    nc_thread_destroy();
    return NULL;
}

static void *
tls_endpt_del_trusted_cert_list_thread(void *arg)
{
    (void)arg;

    pthread_barrier_wait(&barrier);

    nc_server_tls_endpt_del_trusted_cert_list("quaternary", "trusted_cert_list1");

    return NULL;
}

static void *
tls_endpt_set_crl_paths_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_endpt_set_crl_paths("quaternary", NULL, "data");
    nc_assert(!ret);

    nc_thread_destroy();
    return NULL;
}

static void *
tls_endpt_clear_crls_thread(void *arg)
{
    (void)arg;

    pthread_barrier_wait(&barrier);

    nc_server_tls_endpt_clear_crls("quaternary");

    return NULL;
}

static void *
tls_endpt_add_ctn_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_endpt_add_ctn("main_tls", 2, "02:F0:F1:F2:F3:F4:F5:F6:F7:F8:F9:10:11:12:EE:FF:A0:A1:A2:A3",
                                      NC_TLS_CTN_SAN_IP_ADDRESS, NULL);
    nc_assert(!ret);

    return NULL;
}

static void *
tls_endpt_del_ctn_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_endpt_del_ctn("main_tls", -1, NULL, NC_TLS_CTN_SAN_ANY, NULL);
    nc_assert(!ret);

    return NULL;
}

static void *
tls_client_thread(void *arg)
{
    int ret, read_pipe = *(int *)arg;
    char buf[9];
    struct nc_session *session;

    ret = read(read_pipe, buf, 9);
    nc_assert(ret == 9);
    nc_assert(!strncmp(buf, "tls_ready", 9));

    ret = nc_client_tls_set_cert_key_paths(TESTS_DIR"/data/client.crt", TESTS_DIR"/data/client.key");
    nc_assert(!ret);
    ret = nc_client_tls_set_trusted_ca_paths(NULL, TESTS_DIR"/data");
    nc_assert(!ret);

    session = nc_connect_tls("127.0.0.1", 6501, NULL);
    nc_assert(session);

    nc_session_free(session, NULL);

    fprintf(stdout, "TLS client finished.\n");

    nc_thread_destroy();
    return NULL;
}

#endif /* NC_ENABLED_TLS */

static void *(*thread_funcs[])(void *) = {
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
    server_thread,
#endif
#ifdef NC_ENABLED_SSH
    add_endpt_thread,
    del_endpt_thread,
    ssh_endpt_set_hostkey_thread,
    ssh_endpt_set_auth_methods_thread,
    ssh_endpt_set_auth_attempts_thread,
    ssh_endpt_set_auth_timeout_thread,
    ssh_endpt_add_authkey_thread,
    ssh_endpt_del_authkey_thread,
#endif
#ifdef NC_ENABLED_TLS
    endpt_set_address_thread,
    endpt_set_port_thread,
    tls_endpt_set_server_cert_thread,
    tls_endpt_add_trusted_cert_list_thread,
    tls_endpt_set_trusted_ca_paths_thread,
    tls_endpt_del_trusted_cert_list_thread,
    tls_endpt_set_crl_paths_thread,
    tls_endpt_clear_crls_thread,
    tls_endpt_add_ctn_thread,
    tls_endpt_del_ctn_thread,
#endif
};

const int thread_count = sizeof thread_funcs / sizeof *thread_funcs;

#if defined(NC_ENABLED_SSH) && defined(NC_ENABLED_TLS)
const int client_count = 2;
pid_t pids[2];
int pipes[4];
#else
const int client_count = 1;
pid_t pids[1];
int pipes[2];
#endif

static void
client_fork(void)
{
    int ret, clients = 0;

#ifdef NC_ENABLED_SSH
    pipe(pipes + clients * 2);

    if (!(pids[clients] = fork())) {
        nc_client_init();

        ret = nc_client_set_schema_searchpath(TESTS_DIR"/../schemas");
        nc_assert(!ret);

        /* close write */
        close(pipes[clients * 2 + 1]);
        ssh_client_thread(&pipes[clients * 2]);
        close(pipes[clients * 2]);
        nc_client_destroy();
        exit(0);
    }
    /* close read */
    close(pipes[clients * 2]);

    ++clients;
#endif

#ifdef NC_ENABLED_TLS
    pipe(pipes + clients * 2);

    if (!(pids[clients] = fork())) {
        nc_client_init();

        ret = nc_client_set_schema_searchpath(TESTS_DIR"/../schemas");
        nc_assert(!ret);

        /* close write */
        close(pipes[clients * 2 + 1]);
        tls_client_thread(&pipes[clients * 2]);
        close(pipes[clients * 2]);
        nc_client_destroy();
        exit(0);
    }
    /* close read */
    close(pipes[clients * 2]);

    ++clients;
#endif
}

int
main(void)
{
    struct ly_ctx *ctx;
    int ret, i, clients = 0;
    pthread_t tids[thread_count];

    nc_verbosity(NC_VERB_VERBOSE);

    client_fork();

    ctx = ly_ctx_new(TESTS_DIR"/../schemas", 0);
    nc_assert(ctx);
    ly_ctx_load_module(ctx, "ietf-netconf", NULL);
    nc_server_init(ctx);

    pthread_barrier_init(&barrier, NULL, thread_count);

#ifdef NC_ENABLED_SSH
    /* set callback */
    nc_server_ssh_set_hostkey_clb(clb_hostkeys, NULL, NULL);

    /* do first, so that client can connect on SSH */
    ret = nc_server_add_endpt("main_ssh", NC_TI_LIBSSH);
    nc_assert(!ret);
    ret = nc_server_endpt_set_address("main_ssh", "0.0.0.0");
    nc_assert(!ret);
    ret = nc_server_endpt_set_port("main_ssh", 6001);
    nc_assert(!ret);
    ret = nc_server_ssh_add_authkey_path(TESTS_DIR"/data/key_dsa.pub", "test");
    nc_assert(!ret);
    ret = nc_server_ssh_endpt_add_hostkey("main_ssh", "key_rsa", -1);
    nc_assert(!ret);

    /* client ready */
    ret = write(pipes[clients * 2 + 1], "ssh_ready", 9);
    nc_assert(ret == 9);
    ++clients;

    /* for ssh_endpt_del_authkey */
    ret = nc_server_ssh_add_authkey_path(TESTS_DIR"/data/key_ecdsa.pub", "test2");
    nc_assert(!ret);

    ret = nc_server_add_endpt("secondary", NC_TI_LIBSSH);
    nc_assert(!ret);
#endif

#ifdef NC_ENABLED_TLS
    /* set callbacks */
    nc_server_tls_set_server_cert_clb(clb_server_cert, NULL, NULL);
    nc_server_tls_set_trusted_cert_list_clb(clb_trusted_cert_lists, NULL, NULL);

    /* do first, so that client can connect on TLS */
    ret = nc_server_add_endpt("main_tls", NC_TI_OPENSSL);
    nc_assert(!ret);
    ret = nc_server_endpt_set_address("main_tls", "0.0.0.0");
    nc_assert(!ret);
    ret = nc_server_endpt_set_port("main_tls", 6501);
    nc_assert(!ret);
    ret = nc_server_tls_endpt_set_server_cert("main_tls", "main_cert");
    nc_assert(!ret);
    ret = nc_server_tls_endpt_add_trusted_cert_list("main_tls", "client_cert_list");
    nc_assert(!ret);
    ret = nc_server_tls_endpt_add_ctn("main_tls", 0, "02:B3:9F:26:65:76:6B:CC:FC:86:8E:D4:1A:81:64:0F:92:EB:18:AE:FF", NC_TLS_CTN_SPECIFIED, "test");
    nc_assert(!ret);

    /* client ready */
    ret = write(pipes[clients * 2 + 1], "tls_ready", 9);
    nc_assert(ret == 9);
    ++clients;

    /* for tls_endpt_del_ctn */
    ret = nc_server_tls_endpt_add_ctn("main_tls", 1, "02:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:A0:A1:A2:A3", NC_TLS_CTN_SAN_ANY, NULL);
    nc_assert(!ret);

    ret = nc_server_add_endpt("quaternary", NC_TI_OPENSSL);
    nc_assert(!ret);
#endif

    /* threads'n'stuff */
    ret = 0;
    for (i = 0; i < thread_count; ++i) {
        ret += pthread_create(&tids[i], NULL, thread_funcs[i], NULL);
    }
    nc_assert(!ret);

    /* cleanup */
    for (i = 0; i < thread_count; ++i) {
        pthread_join(tids[i], NULL);
    }
    for (i = 0; i < client_count; ++i) {
        waitpid(pids[i], NULL, 0);
        close(pipes[i * 2 + 1]);
    }

    pthread_barrier_destroy(&barrier);

    nc_server_destroy();
    ly_ctx_destroy(ctx, NULL);

    return 0;
}
