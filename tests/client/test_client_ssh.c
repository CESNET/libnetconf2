/**
 * @file test_client_ssh.c
 * @author David Sedlák <xsedla1d@stud.fit.vutbr.cz>
 * @brief client SSH test
 *
 * Copyright (c) 2018 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cmocka.h>
#include <config.h>
#include <config_server.h>
#include <libyang/libyang.h>
#include <log.h>
#include <session_client.h>
#include <session_client_ch.h>
#include <session_p.h>
#include <session_server.h>
#include "tests/config.h"

#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

const char *data =
        "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\" xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
        "    <listen yang:operation=\"create\">\n"
        "        <idle-timeout>10</idle-timeout>\n"
        "        <endpoint>\n"
        "            <name>default-ssh</name>\n"
        "            <ssh>\n"
        "                <tcp-server-parameters>\n"
        "                    <local-address>127.0.0.1</local-address>\n"
        "                    <local-port>10005</local-port>\n"
        "                </tcp-server-parameters>\n"
        "                <ssh-server-parameters>\n"
        "                    <server-identity>\n"
        "                        <host-key>\n"
        "                            <name>key</name>\n"
        "                            <public-key>\n"
        "                                <local-definition>\n"
        "                                    <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>\n"
        "                                    <public-key>MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6ojtjfDmvyQP1ZkIwBpr97eKDuebvpoglRHRdvVuTpf/gU1VArAQmwGh05i6lm8TkVl1noMlIxLJDcWslaeVn6KyvsX0HhsQtXwqPqwka5UCv6alwf/ivAvcNpcX1j0t/uIGCI4dSiKnzQCyf0FTirzQkjrDZUd3meDhNQTruCalGV4gfNWIq3e1oGuwAn1tLlu9oTrE4HzMpgbNEU6wNmsSqpwGxUhYLoSaM7b0dLmqP+ZczSS0Uac0PFNkehGQ2CYIT80f580o4XGtoLCUUGkp6YCTL4Z2CeBEaJABWjDIDH+dKYIUBqUpz4Th12gXAP+h+3qI6+9eppeHrfrzARDsfLjwUNxQJse1QSArjAytf0FKtGHrORc7W0TiCFvR0zaoUNLTKk7enTiRQ9rfWZOAu44fUvPCaXDE6zXXeaVgoKCo4VHlho36erUcjlEBM+jk28IykbZGtBb6igKvYa1tPSgeYm/zJoFVjQcnr14uci/ft1+Na+hOIEoEEiKxcAPk2b2vBKNlRIW7WLJ3u7ZiuQEJTNm6+3cE4+lfwaBCBqBToE+dpzvoUXoMyFFReUFd1O5axu4fXgt00jMaOQxmE0v9OmR/pL/PWIflVF4Zz5yVONYaDVc7l+veY0oEZruEPJ0hlEgxuCzLrcMhjufl2qE2Q7fQIaav/1NqBVkCAwEAAQ==</public-key>\n"
        "                                    <private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>\n"
        "                                    <cleartext-private-key>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</cleartext-private-key>\n"
        "                                </local-definition>\n"
        "                            </public-key>\n"
        "                        </host-key>\n"
        "                    </server-identity>\n"
        "                    <client-authentication>\n"
        "                        <users>\n"
        "                            <user>\n"
        "                                <name>test</name>\n"
        "                                <public-keys>\n"
        "                                    <local-definition>\n"
        "                                        <public-key>\n"
        "                                            <name>client</name>\n"
        "                                            <public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>\n"
        "                                            <public-key>AAAAB3NzaC1yc2EAAAADAQABAAABAQDPavVALiM7QwTIUAndO8E9GOkSDQWjuEwkzbJ3kOBPa7kkq71UOZFeecDjFb9eipkljfFys/JYHGQaYVF8/svT0KV5h7HlutRdF6yvqSEbjpbTORb27pdHX3iFEyDCwCIoq9vMeX+wyXnteyn01GpIL0ig0WAnvkqX/SPjuplX5ZItUSr0MhXM7fNSX50BD6G8IO0/djUcdMUcjTjGv73SxB9ZzLvxnhXuUJbzEJJJLj6qajyEIVaJSa73vA33JCD8qzarrsuITojVLPDFmeHwSAoB5dP86yop6e6ypuXzKxxef6yNXcE8oTj8UFYBIXsgIP2nBvWk41EaK0Vk3YFl</public-key>\n"
        "                                        </public-key>\n"
        "                                    </local-definition>\n"
        "                                </public-keys>\n"
        "                            </user>\n"
        "                        </users>\n"
        "                    </client-authentication>\n"
        "                    <transport-params>\n"
        "                        <host-key>\n"
        "                            <host-key-alg xmlns:sshpka=\"urn:ietf:params:xml:ns:yang:iana-ssh-public-key-algs\">sshpka:rsa-sha2-512</host-key-alg>\n"
        "                        </host-key>\n"
        "                        <key-exchange>\n"
        "                            <key-exchange-alg xmlns:sshkea=\"urn:ietf:params:xml:ns:yang:iana-ssh-key-exchange-algs\">sshkea:curve25519-sha256</key-exchange-alg>\n"
        "                        </key-exchange>\n"
        "                        <encryption>\n"
        "                            <encryption-alg xmlns:sshea=\"urn:ietf:params:xml:ns:yang:iana-ssh-encryption-algs\">sshea:aes256-ctr</encryption-alg>\n"
        "                        </encryption>\n"
        "                        <mac>\n"
        "                            <mac-alg xmlns:sshma=\"urn:ietf:params:xml:ns:yang:iana-ssh-mac-algs\">sshma:hmac-sha2-512</mac-alg>\n"
        "                        </mac>\n"
        "                    </transport-params>\n"
        "                </ssh-server-parameters>\n"
        "            </ssh>\n"
        "        </endpoint>\n"
        "    </listen>\n"
        "</netconf-server>\n";

static int
ssh_hostkey_check_clb(const char *hostname, ssh_session session, void *priv)
{
    (void)hostname;
    (void)session;
    (void)priv;

    return 0;
}

static int
setup_f(void **state)
{
    (void)state;
    int ret;

    nc_verbosity(NC_VERB_VERBOSE);

    ret = nc_client_ssh_set_username("username");
    assert_int_equal(ret, 0);
    ret = nc_client_ssh_ch_set_username("ch_username");
    assert_int_equal(ret, 0);
    nc_client_ssh_set_auth_hostkey_check_clb(ssh_hostkey_check_clb, NULL);

    return 0;
}

static int
teardown_f(void **state)
{
    (void)state;
    nc_client_destroy();
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
__wrap_ssh_connect(ssh_session session)
{
    (void)session;

    /* set support of all authentication methods by fake server */
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE);
    return (int)mock();
}

MOCK int
__wrap_ssh_userauth_none(ssh_session session, const char *username)
{
    (void)session;
    (void)username;

    return (int)mock();
}

MOCK int
__wrap_ssh_userauth_kbdint(ssh_session session, const char *user, const char *submethods)
{
    (void)session;
    (void)user;
    (void)submethods;

    return (int)mock();
}

MOCK int
__wrap_ssh_is_connected(ssh_session session)
{
    (void)session;

    return (int)mock();
}

MOCK int
__wrap_ssh_channel_open_session(ssh_channel channel)
{
    (void)channel;

    return (int)mock();
}

MOCK int
__wrap_ssh_channel_request_subsystem(ssh_channel channel, const char *subsystem)
{
    (void)channel;
    (void)subsystem;

    return (int)mock();
}

MOCK int
__wrap_ssh_channel_is_closed(ssh_channel channel)
{
    (void)channel;

    return 0;
}

MOCK int
__wrap_ssh_channel_write(ssh_channel channel, const void *data, uint32_t len)
{
    (void)channel;
    (void)data;

    return len;
}

MOCK int
__wrap_ssh_channel_poll_timeout(ssh_channel channel, int timeout, int is_stderr)
{
    (void)channel;
    (void)timeout;
    (void)is_stderr;

    return (int)mock();
}

MOCK int
__wrap_ssh_userauth_password(ssh_session session, const char *username, const char *password)
{
    (void)session;
    check_expected(password);
    check_expected(username);

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

MOCK int
__wrap_ssh_userauth_try_publickey(ssh_session session, const char *username, const ssh_key pubkey)
{
    (void)session;
    (void)username;
    (void)pubkey;

    return (int)mock();
}

MOCK int
__wrap_ssh_userauth_publickey(ssh_session session, const char *username, const ssh_key privkey)
{
    (void)session;
    (void)username;
    (void)privkey;

    return (int)mock();
}

MOCK int
__wrap_nc_sock_listen_inet(const char *address, uint16_t port, struct nc_keepalives *ka)
{
    (void)address;
    (void)port;
    (void)ka;

    return (int)mock();
}

MOCK int
__wrap_nc_sock_accept_binds(struct nc_bind *binds, uint16_t bind_count, int timeout, char **host, uint16_t *port, uint16_t *idx)
{
    (void)binds;
    (void)bind_count;
    (void)timeout;
    (void)host;
    (void)port;

    *idx = 0;
    return (int)mock();
}

MOCK struct nc_session *
__wrap_nc_accept_callhome_ssh_sock(int sock, const char *host, uint16_t port, struct ly_ctx *ctx, int timeout)
{
    (void)sock;
    (void)host;
    (void)port;
    (void)ctx;
    (void)timeout;

    return mock_ptr_type(struct nc_session *);
}

static int
test_hostkey_clb(const char *hostname, ssh_session session, void *priv)
{
    (void)hostname;
    (void)session;
    (void)priv;

    return 0;
}

static void
test_nc_client_ssh_setting_auth_hostkey_check_clb(void **state)
{
    (void)state;
    int (*ret_f)(const char *hostname, ssh_session session, void *priv);
    char *priv_data_ret;

    /* ssh_hostkey_check_clb is set in setup_f */
    nc_client_ssh_get_auth_hostkey_check_clb(&ret_f, (void **)&priv_data_ret);
    assert_ptr_equal(ret_f, ssh_hostkey_check_clb);
    assert_null(priv_data_ret);

    /* set different callback and private data */
    nc_client_ssh_set_auth_hostkey_check_clb(test_hostkey_clb, "DATA");
    nc_client_ssh_get_auth_hostkey_check_clb(&ret_f, (void **)&priv_data_ret);
    assert_ptr_equal(ret_f, test_hostkey_clb);
    assert_string_equal(priv_data_ret, "DATA");
}

char *
test_pwd_clb1(const char *username, const char *hostname, void *priv)
{
    char *pass, *pass_to_return;

    check_expected(username);
    check_expected(hostname);
    check_expected(priv);

    pass = (char *)mock();
    pass_to_return = malloc(sizeof *pass * (strlen(pass) + 1));
    strcpy(pass_to_return, pass);

    return pass_to_return;
}

char *
test_pwd_clb2(const char *username, const char *hostname, void *priv)
{
    (void)username;
    (void)hostname;
    (void)priv;

    return 0;
}

static void
test_nc_client_ssh_setting_auth_password_clb(void **state)
{
    (void)state;
    char *(*ret_f)(const char *username, const char *hostname, void *priv);
    char *priv_data_ret;

    /* set callback */
    nc_client_ssh_set_auth_password_clb(test_pwd_clb1, "DATA");
    nc_client_ssh_get_auth_password_clb(&ret_f, (void **)&priv_data_ret);
    assert_ptr_equal(test_pwd_clb1, ret_f);
    assert_string_equal("DATA", priv_data_ret);

    /* set different callback */
    nc_client_ssh_set_auth_password_clb(test_pwd_clb2, "NEW DATA");
    nc_client_ssh_get_auth_password_clb(&ret_f, (void **)&priv_data_ret);
    assert_ptr_equal(test_pwd_clb2, ret_f);
    assert_string_equal("NEW DATA", priv_data_ret);
}

char *
test_inter_clb1(const char *auth_name, const char *instruction, const char *prompt, int echo, void *priv)
{
    (void)auth_name;
    (void)instruction;
    (void)prompt;
    (void)echo;
    (void)priv;

    return 0;
}

char *
test_inter_clb2(const char *auth_name, const char *instruction, const char *prompt, int echo, void *priv)
{
    (void)auth_name;
    (void)instruction;
    (void)prompt;
    (void)echo;
    (void)priv;

    return 0;
}

static void
test_nc_client_ssh_setting_auth_interactive_clb(void **state)
{
    (void)state;
    char *(*ret_f)(const char *auth_name, const char *instruction, const char *prompt, int echo, void *priv);
    char *priv_data_ret;

    /* set callback */
    nc_client_ssh_set_auth_interactive_clb(test_inter_clb1, "DATA");
    nc_client_ssh_get_auth_interactive_clb(&ret_f, (void **)&priv_data_ret);
    assert_ptr_equal(test_inter_clb1, ret_f);
    assert_string_equal("DATA", priv_data_ret);

    /* set diferent callback */
    nc_client_ssh_set_auth_interactive_clb(test_inter_clb2, "NEW DATA");
    nc_client_ssh_get_auth_interactive_clb(&ret_f, (void **)&priv_data_ret);
    assert_ptr_equal(test_inter_clb2, ret_f);
    assert_string_equal("NEW DATA", priv_data_ret);
}

char *
test_passphrase_clb1(const char *privkey_path, void *priv)
{
    (void)privkey_path;
    (void)priv;

    return 0;
}

char *
test_passphrase_clb2(const char *privkey_path, void *priv)
{
    (void)privkey_path;
    (void)priv;

    return 0;
}

static void
test_nc_client_ssh_setting_auth_privkey_passphrase_clb(void **state)
{
    (void)state;
    char *(*ret_f)(const char *privkey_path, void *priv);
    char *priv_data_ret;

    /* set first callback */
    nc_client_ssh_set_auth_privkey_passphrase_clb(test_passphrase_clb1, "DATA");
    nc_client_ssh_get_auth_privkey_passphrase_clb(&ret_f, (void **)&priv_data_ret);
    assert_ptr_equal(ret_f, test_passphrase_clb1);
    assert_string_equal("DATA", priv_data_ret);

    /* set different callback */
    nc_client_ssh_set_auth_privkey_passphrase_clb(test_passphrase_clb2, "NEW DATA");
    nc_client_ssh_get_auth_privkey_passphrase_clb(&ret_f, (void **)&priv_data_ret);
    assert_ptr_equal(ret_f, test_passphrase_clb2);
    assert_string_equal("NEW DATA", priv_data_ret);
}

static void
test_nc_client_ssh_adding_keypair(void **state)
{
    (void)state;
    int ret;
    const char *pubkey1, *pubkey2;

    /* at the beginning keypair count should be 0 */
    ret = nc_client_ssh_get_keypair_count();
    assert_int_equal(ret, 0);

    /* add first key pair */
    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/key_ecdsa.pub", TESTS_DIR "/data/key_ecdsa");
    assert_int_equal(ret, 0);
    ret = nc_client_ssh_get_keypair_count();
    assert_int_equal(ret, 1);

    /* add second keypair */
    ret = nc_client_ssh_add_keypair("key_pub", "key_priv");
    assert_int_equal(ret, 0);
    ret = nc_client_ssh_get_keypair_count();
    assert_int_equal(ret, 2);
    ret = nc_client_ssh_get_keypair(1, &pubkey1, &pubkey2);
    assert_int_equal(ret, 0);
    assert_string_equal(pubkey1, "key_pub");
    assert_string_equal(pubkey2, "key_priv");

    /* delete first keypair */
    ret = nc_client_ssh_del_keypair(0);
    assert_int_equal(ret, 0);
    ret = nc_client_ssh_get_keypair_count();
    assert_int_equal(ret, 1);
    /* try to get deleted keypair */
    ret = nc_client_ssh_get_keypair(5, &pubkey1, &pubkey2);
    assert_int_equal(ret, -1);

    /* try to add keypair that is already set */
    ret = nc_client_ssh_add_keypair("key_pub", "key_priv");
    assert_int_equal(ret, -1);
    ret = nc_client_ssh_get_keypair_count();
    assert_int_equal(ret, 1);

    /* try to delete keypair with id that is not used */
    ret = nc_client_ssh_del_keypair(42);
    assert_int_equal(ret, -1);
    ret = nc_client_ssh_get_keypair_count();
    assert_int_equal(ret, 1);

    /* remove remaining keypairs */
    ret = nc_client_ssh_del_keypair(0);
    assert_int_equal(ret, 0);
    ret = nc_client_ssh_get_keypair_count();
    assert_int_equal(ret, 0);
}

static void
test_nc_client_ssh_setting_auth_pref(void **state)
{
    (void)state;
    int ret;

    /* initiate client, must be called in first test */
    nc_client_init();

    /* check default prefference settings according to documentation */
    ret = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_INTERACTIVE);
    assert_int_equal(ret, 1);
    ret = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PASSWORD);
    assert_int_equal(ret, 2);
    ret = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PUBLICKEY);
    assert_int_equal(ret, 3);

    /* try to set prefetence of non existing method */
    nc_client_ssh_set_auth_pref(42, 22);

    /* try to get preference of non existing method */
    ret = nc_client_ssh_get_auth_pref(42);
    assert_int_equal(ret, 0);

    /* change values of all methods and check if they actually changed */
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, 9);
    ret = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_INTERACTIVE);
    assert_int_equal(ret, 9);

    /* negative value should be set as -1 */
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, -5);
    ret = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PASSWORD);
    assert_int_equal(ret, -1);

    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, 11);
    ret = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PUBLICKEY);
    assert_int_equal(ret, 11);
}

static void
test_nc_client_ssh_setting_username(void **state)
{
    (void)state;
    int ret;
    const char *username_ret;

    username_ret = nc_client_ssh_get_username();
    /* username is set to "username" in setup_f */
    assert_string_equal(username_ret, "username");

    /* set new username and check if it changes */
    ret = nc_client_ssh_set_username("new_username");
    assert_int_equal(ret, 0);
    username_ret = nc_client_ssh_get_username();
    assert_string_equal(username_ret, "new_username");
}

static void
test_nc_connect_ssh_interactive_succesfull(void **state)
{
    (void)state;
    struct nc_session *session;

    /* set authentication method to use interactive authentication */
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, 1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, -1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, -1);

    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, 20);

    /* prepare return values for functions used by nc_connect_ssh */
    will_return(__wrap_connect, 0);
    will_return(__wrap_ssh_connect, 0);
    will_return(__wrap_ssh_userauth_none, 1);

    will_return(__wrap_ssh_userauth_kbdint, 0);
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_is_connected, 1);

    will_return(__wrap_ssh_channel_open_session, 0);
    will_return(__wrap_ssh_channel_request_subsystem, 0);

    will_return(__wrap_nc_handshake_io, 3);
    will_return(__wrap_nc_ctx_check_and_fill, 0);

    session = nc_connect_ssh("127.0.0.1", 8080, NULL);
    assert_non_null(session);

    will_return(__wrap_ssh_channel_poll_timeout, 0);
    nc_session_free(session, NULL);
}

static void
test_nc_connect_ssh_password_succesfull(void **state)
{
    (void)state;
    struct nc_session *session;

    /* set authentication method to use password authentication */
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, 1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, -1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, -1);

    /* set authentication callback */
    nc_client_ssh_set_auth_password_clb(test_pwd_clb1, "private_data");
    will_return(test_pwd_clb1, "secret password");
    /* set values that are expected as parameters for authentication callback */
    expect_string(test_pwd_clb1, username, "username");
    expect_string(test_pwd_clb1, hostname, "127.0.0.1");
    expect_string(test_pwd_clb1, priv, "private_data");

    /* fake succesfull connection */
    will_return(__wrap_connect, 0);
    will_return(__wrap_ssh_connect, 0);
    /* do not authenticate using no authentication method */
    will_return(__wrap_ssh_userauth_none, 1);

    /* succesfully authenticate via password authentication */
    expect_string(__wrap_ssh_userauth_password, password, "secret password");
    expect_string(__wrap_ssh_userauth_password, username, "username");
    will_return(__wrap_ssh_userauth_password, 0);

    /* fake ssh functions that are used to open netconf channel */
    will_return(__wrap_ssh_channel_open_session, 0);
    will_return(__wrap_ssh_channel_request_subsystem, 0);

    /* fake that connection is still alive*/
    will_return(__wrap_ssh_is_connected, 1);

    /* fake ssh function for recieving hello message */
    will_return(__wrap_ssh_is_connected, 1);

    will_return(__wrap_nc_handshake_io, 3);
    will_return(__wrap_nc_ctx_check_and_fill, 0);

    session = nc_connect_ssh("127.0.0.1", 8080, NULL);
    assert_non_null(session);

    /* disconnect */
    will_return(__wrap_ssh_channel_poll_timeout, 0);
    nc_session_free(session, NULL);
}

static void
test_nc_connect_ssh_pubkey_ecdsa_succesfull(void **state)
{
    (void)state;
    struct nc_session *session;
    int ret = 0;

    /* set authentication method to use password authentication */
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, -1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, 1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, -1);

    /* add keypair for authentication */
    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/key_ecdsa.pub", TESTS_DIR "/data/key_ecdsa");
    assert_int_equal(ret, 0);

    /* fake succesfull connection */
    will_return(__wrap_connect, 0);
    will_return(__wrap_ssh_connect, 0);
    /* do not authenticate using no authentication method */
    will_return(__wrap_ssh_userauth_none, 1);
    will_return(__wrap_ssh_userauth_try_publickey, 0);
    will_return(__wrap_ssh_userauth_publickey, 0);
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_channel_open_session, 0);
    will_return(__wrap_ssh_channel_request_subsystem, 0);

    /* fake ssh function for recieving hello message */
    will_return(__wrap_ssh_is_connected, 1);

    will_return(__wrap_nc_handshake_io, 3);
    will_return(__wrap_nc_ctx_check_and_fill, 0);
    session = nc_connect_ssh("127.0.0.1", 8080, NULL);
    assert_non_null(session);

    /* disconnect */
    will_return(__wrap_ssh_channel_poll_timeout, 0);
    nc_session_free(session, NULL);

    /* delete the keypair */
    ret = nc_client_ssh_del_keypair(0);
    assert_int_equal(ret, 0);
}

static void
test_nc_connect_ssh_pubkey_succesfull(void **state)
{
    (void)state;
    struct nc_session *session;
    struct ly_ctx *ctx;
    struct lyd_node *tree;
    int ret = 0;

    /* set authentication method to use password authentication */
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, -1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, 1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, -1);

    /* add keypair for authentication */
    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/key_rsa.pub", TESTS_DIR "/data/key_rsa");
    assert_int_equal(ret, 0);

    /* fake succesfull connection */
    will_return(__wrap_connect, 0);
    will_return(__wrap_ssh_connect, 0);
    will_return(__wrap_nc_sock_listen_inet, 0);
    /* do not authenticate using no authentication method */
    will_return(__wrap_ssh_userauth_none, 1);
    will_return(__wrap_ssh_userauth_try_publickey, 0);
    will_return(__wrap_ssh_userauth_publickey, 0);
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_channel_open_session, 0);
    will_return(__wrap_ssh_channel_request_subsystem, 0);

    /* fake ssh function for recieving hello message */
    will_return(__wrap_ssh_is_connected, 1);

    will_return(__wrap_nc_handshake_io, 3);
    will_return(__wrap_nc_ctx_check_and_fill, 0);

    ret = ly_ctx_new(MODULES_DIR, 0, &ctx);
    assert_int_equal(ret, 0);

    ret = nc_server_config_load_modules(&ctx);
    assert_int_equal(ret, 0);

    ret = lyd_parse_data_mem(ctx, data, LYD_XML, LYD_PARSE_NO_STATE | LYD_PARSE_STRICT, LYD_VALIDATE_NO_STATE, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup(tree);
    assert_int_equal(ret, 0);

    session = nc_connect_ssh("127.0.0.1", 8080, NULL);
    assert_non_null(session);

    /* disconnect */
    will_return(__wrap_ssh_channel_poll_timeout, 0);

    /* free everything used */
    nc_session_free(session, NULL);
    lyd_free_all(tree);
    nc_server_destroy();
    ly_ctx_destroy(ctx);
}

static void
test_nc_connect_connection_failed(void **state)
{
    (void)state;
    struct nc_session *session;

    errno = ECONNREFUSED;
    will_return(__wrap_connect, -1);
    will_return(__wrap_ssh_is_connected, 0);

    session = nc_connect_ssh("127.0.0.1", 8080, NULL);
    assert_null(session);
}

static void
test_nc_connect_ssh_bad_hello(void **state)
{
    (void)state;
    struct nc_session *session;

    /* set authentication method to use interactive authentication */
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_INTERACTIVE, 1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PASSWORD, -1);
    nc_client_ssh_set_auth_pref(NC_SSH_AUTH_PUBLICKEY, 1);

    nc_client_ssh_set_auth_password_clb(test_pwd_clb2, NULL);

    will_return(__wrap_connect, 0);
    will_return(__wrap_ssh_connect, 0);
    will_return(__wrap_ssh_userauth_none, 1);

    will_return(__wrap_ssh_userauth_kbdint, 0);
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_is_connected, 1);

    will_return(__wrap_ssh_channel_open_session, 0);
    will_return(__wrap_ssh_channel_request_subsystem, 0);
    will_return(__wrap_nc_handshake_io, 4);

    session = nc_connect_ssh("127.0.0.1", 8080, NULL);
    assert_null(session);

    /* destroy client, must be called in last test */
    nc_client_destroy();
}

static void
test_nc_client_ssh_ch_setting_username(void **state)
{
    (void)state;
    const char *username_ret;
    int ret;

    /* username is set to "ch_username" in setup_f */
    username_ret = nc_client_ssh_ch_get_username();
    assert_string_equal(username_ret, "ch_username");
    /* set new username and check if it changes */
    ret = nc_client_ssh_ch_set_username("new_ch_username");
    assert_int_equal(ret, 0);
    username_ret = nc_client_ssh_ch_get_username();
    assert_string_equal(username_ret, "new_ch_username");
}

static void
test_nc_client_ssh_ch_add_bind_listen(void **state)
{
    (void)state;
    int ret;

    /* invalid parameters, address NULL or port 0 */
    ret = nc_client_ssh_ch_add_bind_listen(NULL, 4334);
    assert_int_equal(ret, -1);
    ret = nc_client_ssh_ch_add_bind_listen("127.0.0.1", 0);
    assert_int_equal(ret, -1);

    /* failed to create an ssh listening socket */
    will_return(__wrap_nc_sock_listen_inet, -1);
    ret = nc_client_ssh_ch_add_bind_listen("127.0.0.1", 4334);
    assert_int_equal(ret, -1);

    /* fake a successful CH ssh listening socket */
    will_return(__wrap_nc_sock_listen_inet, 1);
    ret = nc_client_ssh_ch_add_bind_listen("127.0.0.1", 4334);
    assert_int_equal(ret, 0);

    /* remove ssh listening client binds */
    ret = nc_client_ssh_ch_del_bind("127.0.0.1", 4334);
    assert_int_equal(ret, 0);
}

static void
test_nc_accept_callhome(void **state)
{
    (void)state;
    struct nc_session *session = NULL;
    int timeout = 10;
    int ret;

    /* invalid parameter session */
    ret = nc_accept_callhome(timeout, NULL, NULL);
    assert_int_equal(ret, -1);

    /* no client bind */
    ret = nc_accept_callhome(timeout, NULL, &session);
    assert_int_equal(ret, -1);

    /* successfully add a client Call Home bind */
    will_return(__wrap_nc_sock_listen_inet, 1);
    ret = nc_client_ssh_ch_add_bind_listen("127.0.0.1", 4334);
    assert_int_equal(ret, 0);

    /* failed to accept a client bind */
    will_return(__wrap_nc_sock_accept_binds, -1);
    ret = nc_accept_callhome(timeout, NULL, &session);
    assert_int_equal(ret, -1);

    /* failed to accept a server Call Home connection */
    will_return(__wrap_nc_accept_callhome_ssh_sock, NULL);
    will_return(__wrap_nc_sock_accept_binds, 2);
    ret = nc_accept_callhome(timeout, NULL, &session);
    assert_int_equal(ret, -1);

    /* create session structure to fake a successful server call home connection */
    session = nc_new_session(NC_CLIENT, 0);
    assert_non_null(session);
    will_return(__wrap_nc_sock_accept_binds, 2);
    will_return(__wrap_nc_accept_callhome_ssh_sock, session);
    ret = nc_accept_callhome(timeout, NULL, &session);
    assert_int_equal(ret, 1);

    /* remove ssh listening client binds */
    ret = nc_client_ssh_ch_del_bind("127.0.0.1", 4334);
    assert_int_equal(ret, 0);

    /* free session */
    nc_session_free(session, NULL);
}

static void
test_nc_client_ssh_callhome_successful(void **state)
{
    (void)state;
    struct nc_session *session = NULL;
    int timeout = 10;
    int ret;

    /* create session structure */
    session = nc_new_session(NC_CLIENT, 0);
    assert_non_null(session);

    /* prepare to fake return values for functions used by nc_accept_callhome */
    will_return(__wrap_nc_sock_listen_inet, 1);
    will_return(__wrap_nc_sock_accept_binds, 2);
    will_return(__wrap_nc_accept_callhome_ssh_sock, session);

    ret = nc_client_ssh_ch_add_bind_listen("127.0.0.1", 4334);
    assert_int_equal(ret, 0);
    ret = nc_accept_callhome(timeout, NULL, &session);
    assert_int_equal(ret, 1);

    /* remove ssh listening client binds */
    ret = nc_client_ssh_ch_del_bind("127.0.0.1", 4334);
    assert_int_equal(ret, 0);

    /* free session */
    nc_session_free(session, NULL);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_auth_pref, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_auth_hostkey_check_clb, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_auth_password_clb, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_auth_interactive_clb, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_auth_privkey_passphrase_clb, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_adding_keypair, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_username, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_ssh_interactive_succesfull, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_ssh_password_succesfull, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_ssh_pubkey_ecdsa_succesfull, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_ssh_pubkey_succesfull, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_connection_failed, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_ssh_bad_hello, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_ch_setting_username, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_ch_add_bind_listen, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_accept_callhome, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_callhome_successful, setup_f, teardown_f),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
