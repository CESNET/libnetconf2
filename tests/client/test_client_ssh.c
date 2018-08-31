#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include "nc_client.h"
#include "tests/config.h"

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>

#define VALID_HELLO "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"                \
                    "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">" \
                    "<capabilities>"                                            \
                    "<capability>"                                              \
                    "urn:ietf:params:netconf:base:1.1"                          \
                    "</capability>"                                             \
                    "<capability>"                                              \
                    "urn:ietf:params:ns:netconf:capability:startup:1.0"         \
                    "</capability>"                                             \
                    "</capabilities>"                                           \
                    "<session-id>4</session-id>"                                \
                    "</hello>"                                                  \
                    "]]>]]>";

#define VALID_OK    "\n#126\n"                                                  \
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"              \
                    "<rpc-reply id=\"106\"\n"                                   \
                    "xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"      \
                    "<ok/>\n"                                                   \
                    "</rpc-reply>"                                              \
                    "\n##\n";

/* variable to store pointer to msg used by __wrap_ssh_channel_read */
const char *msg = NULL;
/* variable to count how many bytes of msg are already read in __wrap_ssh_channel_read */
uint32_t already_read = 0;

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
    already_read = 0;
    msg = NULL;
    int ret;

    nc_verbosity(NC_VERB_VERBOSE);

    /* initiate client */
    nc_client_init();
    ret = nc_client_ssh_set_username("username");
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

int
__wrap_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    (void)sockfd;
    (void)addr;
    (void)addrlen;

    return (int)mock();
}

int
__wrap_ssh_connect(ssh_session session)
{
    (void)session;

    /* set support of all authentication methods by fake server */
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE);
    return (int)mock();
}

int
__wrap_ssh_userauth_none(ssh_session session, const char *username)
{
    (void)session;
    (void)username;

    return (int)mock();
}

int
__wrap_ssh_userauth_kbdint(ssh_session session, const char *user, const char *submethods)
{
    (void)session;
    (void)user;
    (void)submethods;

    return (int)mock();
}

int
__wrap_ssh_is_connected(ssh_session session)
{
    (void)session;

    return (int)mock();
}

int
__wrap_ssh_channel_open_session(ssh_channel channel)
{
    (void)channel;

    return (int)mock();
}

int
__wrap_ssh_channel_request_subsystem(ssh_channel channel, const char *subsystem)
{
    (void)channel;
    (void)subsystem;

    return (int)mock();
}

int
__wrap_ssh_channel_is_closed(ssh_channel channel)
{
    (void)channel;

    return 0;
}

int
__wrap_ssh_channel_write(ssh_channel channel, const void *data, uint32_t len)
{
    (void)channel;
    (void)data;

    return len;
}

int
__wrap_ssh_channel_poll_timeout(ssh_channel channel, int timeout, int is_stderr)
{
    (void)channel;
    (void)timeout;
    (void)is_stderr;

    return (int)mock();
}

int
__wrap_ssh_channel_read(ssh_channel channel, void *dest, uint32_t count, int is_stderr)
{
    (void)channel;
    (void)is_stderr;

    /* read message stored in global variable msg */
    /* global variable already_read is counter of how many bytes of msg are read */
    uint32_t msg_len = strlen(msg);
    uint32_t to_read_len = (msg_len > (already_read + count)) ? count : msg_len - already_read;
    memcpy(dest, &msg[already_read], to_read_len);
    already_read += to_read_len;

    return to_read_len;
}

int
__wrap_ssh_userauth_password(ssh_session session, const char *username, const char *password)
{
    (void)session;
    check_expected(password);
    check_expected(username);


    return (int)mock();
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
    ret = nc_client_ssh_add_keypair(TESTS_DIR"/data/key_dsa.pub", TESTS_DIR"/data/key_dsa");
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
    /* check default prefference settings according to documentation */
    ret = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_INTERACTIVE);
    assert_int_equal(ret, 3);
    ret = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PASSWORD);
    assert_int_equal(ret, 2);
    ret = nc_client_ssh_get_auth_pref(NC_SSH_AUTH_PUBLICKEY);
    assert_int_equal(ret, 1);

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

    /* set valid hello message */
    msg = VALID_HELLO;

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
    will_return(__wrap_ssh_is_connected, 1);

    will_return(__wrap_ssh_channel_poll_timeout, 1);
    will_return(__wrap_ssh_is_connected, 1);

    session = nc_connect_ssh("127.0.0.1", 8080, NULL);
    assert_non_null(session);

    already_read = 0;
    /* set valid ok reply */
    msg = VALID_OK;

    /* prepare return values used by nc_session_free */
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_is_connected, 1);

    will_return(__wrap_ssh_channel_poll_timeout, 1);

    nc_session_free(session, NULL);
}

static void
test_nc_connect_ssh_password_succesfull(void **state)
{
    (void)state;
    struct nc_session *session;

    /* set valid hello message */
    msg = VALID_HELLO;

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

    /* fake that connection is still alive */
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_is_connected, 1);

    /* fake ssh functions that are used to open netconf channel */
    will_return(__wrap_ssh_channel_open_session, 0);
    will_return(__wrap_ssh_channel_request_subsystem, 0);

    /* fake that connection is still alive*/
    will_return(__wrap_ssh_is_connected, 1);

    /* fake ssh function for recieving hello message */
    will_return(__wrap_ssh_channel_poll_timeout, 1);
    will_return(__wrap_ssh_is_connected, 1);

    session = nc_connect_ssh("127.0.0.1", 8080, NULL);
    assert_non_null(session);

    /* prepare to read new message */
    already_read = 0;
    /* set valid ok reply */
    msg = VALID_OK;

    /* prepare return values used by nc_session_free */
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_channel_poll_timeout, 1);

    /* disconnect */
    nc_session_free(session, NULL);
}

static void
test_nc_connect_ssh_malformed_hello(void **state)
{
    (void)state;
    struct nc_session *session;

    /* set malformed hello message */
    msg = "<?xml ve\"1.0\" ding-8\"?>"
          "<hello xmlns=\"urn:ietf:pml:ns:netconf:base:1.0\">"
          "<capiapability:startup:1.0"
          "</capability>"
          "<session-idssion-id>"
          "]]>]]>";

    will_return(__wrap_connect, 0);
    will_return(__wrap_ssh_connect, 0);
    will_return(__wrap_ssh_userauth_none, 1);

    will_return(__wrap_ssh_userauth_kbdint, 0);
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_is_connected, 1);

    will_return(__wrap_ssh_channel_open_session, 0);
    will_return(__wrap_ssh_channel_request_subsystem, 0);
    will_return(__wrap_ssh_is_connected, 1);

    will_return(__wrap_ssh_channel_poll_timeout, 1);
    will_return(__wrap_ssh_is_connected, 1);

    session = nc_connect_ssh("127.0.0.1", 8080, NULL);
    assert_null(session);
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
test_nc_connect_ssh_disconnected(void **state)
{
    (void)state;
    struct nc_session *session;

    will_return(__wrap_connect, 0);
    will_return(__wrap_ssh_connect, 0);
    will_return(__wrap_ssh_userauth_none, 1);

    will_return(__wrap_ssh_userauth_kbdint, 0);
    will_return(__wrap_ssh_is_connected, 1);
    will_return(__wrap_ssh_is_connected, 1);

    will_return(__wrap_ssh_channel_open_session, 0);
    will_return(__wrap_ssh_channel_request_subsystem, 0);
    will_return(__wrap_ssh_is_connected, 0);
    will_return(__wrap_ssh_is_connected, 0);

    session = nc_connect_ssh("127.0.0.1", 8080, NULL);
    assert_null(session);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_auth_hostkey_check_clb, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_auth_password_clb, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_auth_interactive_clb, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_auth_privkey_passphrase_clb, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_adding_keypair, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_auth_pref, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_client_ssh_setting_username, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_connection_failed, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_ssh_malformed_hello, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_ssh_disconnected, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_ssh_interactive_succesfull, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_connect_ssh_password_succesfull, setup_f, teardown_f),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
