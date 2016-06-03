/**
 * \file test_server_thread.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 tests - thread-safety of all server functions
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
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
#include "config.h"

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

static void *
ssh_add_endpt_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_add_endpt_listen("tertiary", "0.0.0.0", 6003);
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_set_port_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_set_port("quaternary", 6005);
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_del_endpt_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_del_endpt("secondary");
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_set_hostkey_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_set_hostkey("main", TESTS_DIR"/data/key_dsa");
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_set_banner_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_set_banner("main", "Howdy, partner!");
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_set_auth_methods_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_set_auth_methods("main", NC_SSH_AUTH_PUBLICKEY | NC_SSH_AUTH_PASSWORD | NC_SSH_AUTH_INTERACTIVE);
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_set_auth_attempts_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_set_auth_attempts("main", 2);
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_set_auth_timeout_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_set_auth_timeout("main", 5);
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_add_authkey_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_add_authkey("main", TESTS_DIR"/data/key_rsa.pub", "test3");
    nc_assert(!ret);

    return NULL;
}

static void *
ssh_endpt_del_authkey_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_ssh_endpt_del_authkey("main", TESTS_DIR"/data/key_ecdsa.pub", "test2");
    nc_assert(!ret);

    return NULL;
}

static int
ssh_hostkey_check_clb(const char *hostname, ssh_session session)
{
    (void)hostname;
    (void)session;

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
    nc_client_ssh_set_auth_hostkey_check_clb(ssh_hostkey_check_clb);

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

    nc_thread_destroy();
    return NULL;
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

static void *
tls_add_endpt_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_add_endpt_listen("tertiary", "0.0.0.0", 6503);
    nc_assert(!ret);

    return NULL;
}

static void *
tls_endpt_set_port_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_endpt_set_port("quaternary", 6505);
    nc_assert(!ret);

    return NULL;
}

static void *
tls_del_endpt_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_del_endpt("secondary");
    nc_assert(!ret);

    return NULL;
}

static void *
tls_endpt_set_cert_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_endpt_set_cert("quaternary", "MIIEKjCCAxICCQDqSTPpuoUZkzANBgkqhkiG9w0BAQUFADBYMQswCQYDVQQGEwJB\n"
                                       "VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0\n"
                                       "cyBQdHkgTHRkMREwDwYDVQQDDAhzZXJ2ZXJjYTAeFw0xNjAyMDgxMTE0MzdaFw0y\n"
                                       "NjAyMDUxMTE0MzdaMFYxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRl\n"
                                       "MSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxDzANBgNVBAMMBnNl\n"
                                       "cnZlcjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOqI7Y3w5r8kD9WZ\n"
                                       "CMAaa/e3ig7nm76aIJUR0Xb1bk6X/4FNVQKwEJsBodOYupZvE5FZdZ6DJSMSyQ3F\n"
                                       "rJWnlZ+isr7F9B4bELV8Kj6sJGuVAr+mpcH/4rwL3DaXF9Y9Lf7iBgiOHUoip80A\n"
                                       "sn9BU4q80JI6w2VHd5ng4TUE67gmpRleIHzViKt3taBrsAJ9bS5bvaE6xOB8zKYG\n"
                                       "zRFOsDZrEqqcBsVIWC6EmjO29HS5qj/mXM0ktFGnNDxTZHoRkNgmCE/NH+fNKOFx\n"
                                       "raCwlFBpKemAky+GdgngRGiQAVowyAx/nSmCFAalKc+E4ddoFwD/oft6iOvvXqaX\n"
                                       "h6368wEQ7Hy48FDcUCbHtUEgK4wMrX9BSrRh6zkXO1tE4ghb0dM2qFDS0ypO3p04\n"
                                       "kUPa31mTgLuOH1LzwmlwxOs113mlYKCgqOFR5YaN+nq1HI5RATPo5NvCMpG2RrQW\n"
                                       "+ooCr2GtbT0oHmJv8yaBVY0HJ69eLnIv37dfjWvoTiBKBBIisXAD5Nm9rwSjZUSF\n"
                                       "u1iyd7u2YrkBCUzZuvt3BOPpX8GgQgagU6BPnac76FF6DMhRUXlBXdTuWsbuH14L\n"
                                       "dNIzGjkMZhNL/Tpkf6S/z1iH5VReGc+clTjWGg1XO5fr3mNKBGa7hDydIZRIMbgs\n"
                                       "y63DIY7n5dqhNkO30CGmr/9TagVZAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAEVr\n"
                                       "4skCpwuMuR+3WCmH6S17sYzWMYogJCGQdbZtFqmf4W3EDlNClk4HszAeUdmROMj6\n"
                                       "MdqNDUnDM/GPxHB4Aje1DZOH1h68CCAl9W32LFRDC0KaUOquuYIG4rnZADJl6P4T\n"
                                       "WVlaXfuE2bQjE7iYPhWGNWJtkb7JNIHmB8EAIa4tt3+XJs+vZiSpVDpiP2ucgrCn\n"
                                       "BltsK0iOMPDLVlXdk1hpU5HvlMXdBHQebfTiCFDQSX7ViKc4wSJUHDt4CyoCzchY\n"
                                       "mbQIcTc7uNDE5chQWV8Z3Vxkp4yuqZM3HdLskoo4IgFDOoj8eCAi+58+YRuKpaEQ\n"
                                       "fWt+A9rvlaOApWryMW4=");
    nc_assert(!ret);

    nc_thread_destroy();
    return NULL;
}

static void *
tls_endpt_set_key_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_endpt_set_key("quaternary", "MIIJKAIBAAKCAgEA6ojtjfDmvyQP1ZkIwBpr97eKDuebvpoglRHRdvVuTpf/gU1V\n"
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
                                      "bstUgD6NPbJR4Sm6vrLeUqzjWZP3t1+Z6DjXmnpR2vvhMU/FWb//21p/88o=", 1);
    nc_assert(!ret);

    nc_thread_destroy();
    return NULL;
}

static void *
tls_endpt_add_trusted_cert_thread(void *arg)
{
    (void)arg;
    int ret;

    pthread_barrier_wait(&barrier);

    ret = nc_server_tls_endpt_add_trusted_cert("quaternary", "MIIDgzCCAmugAwIBAgIJAL+y0WMRGax0MA0GCSqGSIb3DQEBBQUAMFgxCzAJBgNV\n"
                                               "BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n"
                                               "aWRnaXRzIFB0eSBMdGQxETAPBgNVBAMMCGNsaWVudGNhMB4XDTE2MDExMTEyMTAx\n"
                                               "OVoXDTE4MTAzMTEyMTAxOVowWDELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUt\n"
                                               "U3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDERMA8GA1UE\n"
                                               "AwwIY2xpZW50Y2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCw7Eyq\n"
                                               "5T5tX6tAv5DHHfWNuaD/a3gVIBlGRWMAXkFWWJEa3o6leIjKxoDnL6tcBWNVJ+Gw\n"
                                               "32MHerpHY6o5czsEHQ2XsOgodyFqe5cvx0kjQbjYQqnIMrslcdvSYuNe/ItqFP/w\n"
                                               "uxb6kQbCYnCQKd/qhdhfoXjIHcnXpZzMCPKQ/uqls7LANJymtQkAuzydlf3+UqoG\n"
                                               "4oo04GXK1Dc0A12cgCXxf+kWx7x34ctx2VEvDsJzw6LiZm8czOWjMFcuqqm/+kla\n"
                                               "N3+6O7Z1kZlft/KNSrOYtc45xKNoSVrdVwFLkxipVDfOql6/DmWfE8iVmlX3QflO\n"
                                               "u3+fzZZQpR5jYzUNAgMBAAGjUDBOMB0GA1UdDgQWBBTjBbQJ6p/mjnjBWXLgXXXW\n"
                                               "a3ieoTAfBgNVHSMEGDAWgBTjBbQJ6p/mjnjBWXLgXXXWa3ieoTAMBgNVHRMEBTAD\n"
                                               "AQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAZr9b0YTaDV5XZr/QQPP1pvHkN3Ezbm9F4\n"
                                               "MiYe4e0QnM9JtjNLDKq1dDnqVDQ/BYdupWWh0398tObFACssWkm4aubPG7LVh5Ck\n"
                                               "O8I8i/GHiXYLmYT22hslWe5dFvidUICkTXoj1h5X2vwfBrNTI1+gnVXXw842xCvU\n"
                                               "sgq28vGMSXLSYKBNaP/llXNmqW35oLs6CwVuiCL7Go0IDIOmiXN2bssb87hZSw3B\n"
                                               "6iwU78wYshJUGZjLaK9PuMvFYJLFWSAePA2Yb+aEv80wMbX1oANSryU7Uf5BJk8V\n"
                                               "kO3mlRDh2b1/5Gb5xA2vU2z3ReHdPNy6qSx0Mk4XJvQw9FsVHZ13");
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
tls_endpt_clear_certs_thread(void *arg)
{
    (void)arg;

    pthread_barrier_wait(&barrier);

    nc_server_tls_endpt_clear_certs("quaternary");

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

    ret = nc_server_tls_endpt_add_ctn("main", 0, "02:F0:F1:F2:F3:F4:F5:F6:F7:F8:F9:10:11:12:EE:FF:A0:A1:A2:A3",
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

    ret = nc_server_tls_endpt_del_ctn("main", -1, NULL, NC_TLS_CTN_SAN_ANY, NULL);
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

    nc_thread_destroy();
    return NULL;
}

#endif /* NC_ENABLED_TLS */

static void *(*thread_funcs[])(void *) = {
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
    server_thread,
#endif
#ifdef NC_ENABLED_SSH
    ssh_add_endpt_thread,
    ssh_endpt_set_port_thread,
    ssh_del_endpt_thread,
    ssh_endpt_set_hostkey_thread,
    ssh_endpt_set_banner_thread,
    ssh_endpt_set_auth_methods_thread,
    ssh_endpt_set_auth_attempts_thread,
    ssh_endpt_set_auth_timeout_thread,
    ssh_endpt_add_authkey_thread,
    ssh_endpt_del_authkey_thread,
#endif
#ifdef NC_ENABLED_TLS
    tls_add_endpt_thread,
    tls_endpt_set_port_thread,
    tls_del_endpt_thread,
    tls_endpt_set_cert_thread,
    tls_endpt_set_key_thread,
    tls_endpt_add_trusted_cert_thread,
    tls_endpt_set_trusted_ca_paths_thread,
    tls_endpt_clear_certs_thread,
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

    ctx = ly_ctx_new(TESTS_DIR"/../schemas");
    nc_assert(ctx);
    ly_ctx_load_module(ctx, "ietf-netconf", NULL);
    nc_server_init(ctx);

    pthread_barrier_init(&barrier, NULL, thread_count);

#ifdef NC_ENABLED_SSH
    /* do first, so that client can connect on SSH */
    ret = nc_server_ssh_add_endpt_listen("main", "0.0.0.0", 6001);
    nc_assert(!ret);
    ret = nc_server_ssh_endpt_add_authkey("main", TESTS_DIR"/data/key_dsa.pub", "test");
    nc_assert(!ret);
    ret = nc_server_ssh_endpt_set_hostkey("main", TESTS_DIR"/data/key_rsa");
    nc_assert(!ret);

    /* client ready */
    ret = write(pipes[clients * 2 + 1], "ssh_ready", 9);
    nc_assert(ret == 9);
    ++clients;

    /* for ssh_endpt_del_authkey */
    ret = nc_server_ssh_endpt_add_authkey("main", TESTS_DIR"/data/key_ecdsa.pub", "test2");
    nc_assert(!ret);

    /* for ssh_del_endpt */
    ret = nc_server_ssh_add_endpt_listen("secondary", "0.0.0.0", 6002);
    nc_assert(!ret);

    /* for ssh_endpt_set_port */
    ret = nc_server_ssh_add_endpt_listen("quaternary", "0.0.0.0", 6004);
    nc_assert(!ret);
#endif

#ifdef NC_ENABLED_TLS
    /* do first, so that client can connect on TLS */
    ret = nc_server_tls_add_endpt_listen("main", "0.0.0.0", 6501);
    nc_assert(!ret);
    ret = nc_server_tls_endpt_set_cert_path("main", TESTS_DIR"/data/server.crt");
    nc_assert(!ret);
    ret = nc_server_tls_endpt_set_key_path("main", TESTS_DIR"/data/server.key");
    nc_assert(!ret);
    ret = nc_server_tls_endpt_add_trusted_cert_path("main", TESTS_DIR"/data/client.crt");
    nc_assert(!ret);
    ret = nc_server_tls_endpt_add_ctn("main", 0, "02:D3:03:0E:77:21:E2:14:1F:E5:75:48:98:6B:FD:8A:63:BB:DE:40:34", NC_TLS_CTN_SPECIFIED, "test");
    nc_assert(!ret);

    /* client ready */
    ret = write(pipes[clients * 2 + 1], "tls_ready", 9);
    nc_assert(ret == 9);
    ++clients;

    /* for tls_del_endpt */
    ret = nc_server_tls_add_endpt_listen("secondary", "0.0.0.0", 6502);
    nc_assert(!ret);

    /* for tls_endpt_set_port */
    ret = nc_server_tls_add_endpt_listen("quaternary", "0.0.0.0", 6504);
    nc_assert(!ret);

    /* for tls_endpt_del_ctn */
    ret = nc_server_tls_endpt_add_ctn("main", 0, "02:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:A0:A1:A2:A3", NC_TLS_CTN_SAN_ANY, NULL);
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
