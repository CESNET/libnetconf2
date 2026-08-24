/**
 * @file test_config.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 YANG data configuration test
 *
 * @copyright
 * Copyright (c) 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>

#include "ln2_test.h"

int TEST_PORT = 10050, TEST_PORT_2 = 10051, TEST_PORT_3 = 10052,
        TEST_PORT_4 = 10053, TEST_PORT_5 = 10054, TEST_PORT_6 = 10055;
const char *TEST_PORT_STR = "10050", *TEST_PORT_2_STR = "10051",
        *TEST_PORT_3_STR = "10052", *TEST_PORT_4_STR = "10053",
        *TEST_PORT_5_STR = "10054", *TEST_PORT_6_STR = "10055";

const char *keystore_truststore_data =
        "<keystore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-keystore\">"
        "<asymmetric-keys>"
        "<asymmetric-key>"
        "<name>hostkey</name>"
        "<public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>"
        "<public-key>AAAAB3NzaC1yc2EAAAADAQABAAABAQDPavVALiM7QwTIUAndO8E9GOkSDQWjuEwkzbJ3kOBPa7kkq71UOZFeecDjFb9eipkljfFys/JYHGQaYVF8/svT0KV5h7HlutRdF6yvqSEbjpbTORb27pdHX3iFEyDCwCIoq9vMeX+wyXnteyn01GpIL0ig0WAnvkqX/SPjuplX5ZItUSr0MhXM7fNSX50BD6G8IO0/djUcdMUcjTjGv73SxB9ZzLvxnhXuUJbzEJJJLj6qajyEIVaJSa73vA33JCD8qzarrsuITojVLPDFmeHwSAoB5dP86yop6e6ypuXzKxxef6yNXcE8oTj8UFYBIXsgIP2nBvWk41EaK0Vk3YFl</public-key>"
        "<private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>"
        "<cleartext-private-key>MIIEpAIBAAKCAQEAz2r1QC4jO0MEyFAJ3TvBPRjpEg0Fo7hMJM2yd5DgT2u5JKu9VDmRXnnA4xW/XoqZJY3xcrPyWBxkGmFRfP7L09CleYex5brUXResr6khG46W0zkW9u6XR194hRMgwsAiKKvbzHl/sMl57Xsp9NRqSC9IoNFgJ75Kl/0j47qZV+WSLVEq9DIVzO3zUl+dAQ+hvCDtP3Y1HHTFHI04xr+90sQfWcy78Z4V7lCW8xCSSS4+qmo8hCFWiUmu97wN9yQg/Ks2q67LiE6I1SzwxZnh8EgKAeXT/OsqKenusqbl8yscXn+sjV3BPKE4/FBWASF7ICD9pwb1pONRGitFZN2BZQIDAQABAoIBAQC1jeTQYdI67EXCZLTNrqFNroFMaJOYJBiaWmat2+VL/3nWzHDzyVQiQyaAXyfcRCsbQSyn/zTQxUEmCis+4vRdGpPNVeZ0tN1wAuoH9F3jdiM1DhK44E0Qj1O5/+08Ktt7iDrjtzH699A+/ADUqh3Bw4mqIrss7pbyhQSmME5LLTbaWikZ8LgtUiF9f5JWzsqjPb6Yd8JEg0O+5lDngLfgEYevKCJxxBMtQQQ6gZCjQQWmir+/0NBezSHsoltPlw1m8Vs8Y5zz684yv33J/qxDM7+rbGbte2fSQ06OuK7abCZMyfXyWdp4cQpG1JZRxGp4Y8vQKvsU5ZOQUT/v7ur9AoGBAO+Li/vUzU3GlL7mxBlPTg5LavItWq6C7Rnwftjql7yPxrQ/+m5RZa0YujnqvZq5SpdpljCZbF9KYrFr92wgFqlt5uYptI4eD0/6xALEUcJJIlllTjiKtJmuyFkkD45WEn1IlDGAURQiDn6aqd40odlPsv4L5EdnQEQQz6Kfv6JLAoGBAN2qchHTKv1PBXfqRm0ABYSPyFhki2RqI4DWsbwykFXn3qP7tDDnmR/VMsAbApgTVW77LGffJ7DZXsqgzujwcqvLBKf8Wl5MRJg2jTe0GkKEBYqhGWNzBhuIwnIcKu/6HsEdFfCD93hwUPaVTBE+2ckXQVb9RSUCpGarXKk9cZ0PAoGBAJ/Hku29OdwA80KKpo7DSStbvtAe1HfGuOQueE2z3NZXiJC+hAqFnK5i6gSrwSCtK0XnldiA3bqJ4V66x2SF2tfUiMlJVDffcRNGDuxRir9vDMxYOF6alnBUFyruVLn6S4bpnH+QOYSWWtizzU58CODsulWeFPxTsJg2Jmkw6SAVAoGANWBGqX4k2uw9T9vM65BWw83vm0FSw3I/bFXGZJ/0W4tC9E+22xPZrm2jE9ktLbtyFhBLaBO3NgGRrs88I6FKq41uaJj+lbhdyB1SsfgfXqb1wqT6PRVEgjrTP7ECsdiTsUK0tr7AR3McO9RFhd2Ribec1zqTfM7/EW3wGRyfkAcCgYAtw6KO+5fXHE79v9pUdZAJ4PAc/KdHjv0zE9s5snwUrh7TO5fIB62di6nPBWLwD5InDZ9sNgxzTBt+0o2N6PsvKQFtfEBemKimmZShMytFkx9/KTRNR9se2qcBMiJsdAaz6hHUliYVWV3Ui+Uy+vYh5reuEhcvEjEzT6ySaCrZfg==</cleartext-private-key>"
        "</asymmetric-key>"
        "</asymmetric-keys>"
        "</keystore>"
        "<truststore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-truststore\">"
        "<public-key-bags>"
        "<public-key-bag>"
        "<name>pkbag</name>"
        "<description>Test public key bag</description>"
        "<public-key>"
        "<name>ED25519 key</name>"
        "<public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>"
        "<public-key>AAAAC3NzaC1lZDI1NTE5AAAAIOr46rptg6BsWhO1JMomuh3cuCYmeuO6JfOUPs/YO35w</public-key>"
        "</public-key>"
        "</public-key-bag>"
        "</public-key-bags>"
        "</truststore>";

const char *data =
        "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\" "
        "    xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"create\">"
        "  <listen>"
        "    <endpoints>"
        "      <endpoint>"
        "        <name>e1</name>"
        "        <ssh>"
        "          <tcp-server-parameters>"
        "            <local-bind>"
        "              <local-address>127.0.0.1</local-address>"
        "              <local-port>%s</local-port>"
        "            </local-bind>"
        "          </tcp-server-parameters>"
        "          <ssh-server-parameters>"
        "            <server-identity>"
        "              <host-key>"
        "                <name>hostkey1</name>"
        "                <public-key>"
        "                  <central-keystore-reference>hostkey</central-keystore-reference>"
        "                </public-key>"
        "              </host-key>"
        "            </server-identity>"
        "            <client-authentication>"
        "              <users>"
        "                <user>"
        "                  <name>user1</name>"
        "                  <public-keys>"
        "                    <central-truststore-reference>pkbag</central-truststore-reference>"
        "                  </public-keys>"
        "                </user>"
        "              </users>"
        "            </client-authentication>"
        "          </ssh-server-parameters>"
        "        </ssh>"
        "      </endpoint>"
        "    </endpoints>"
        "  </listen>"
        "</netconf-server>\n";

const char *data2 =
        "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\" "
        " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
        "  <listen>\n"
        "    <endpoints>\n"
        "      <endpoint yang:operation=\"delete\">\n"
        "        <name>e1</name>\n"
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
        "                <name>hostkey1</name>\n"
        "                <public-key>\n"
        "                  <central-keystore-reference>hostkey</central-keystore-reference>\n"
        "                </public-key>\n"
        "              </host-key>\n"
        "            </server-identity>\n"
        "            <client-authentication>\n"
        "              <users>\n"
        "                <user>\n"
        "                  <name>user1</name>\n"
        "                  <public-keys>\n"
        "                    <central-truststore-reference>pkbag</central-truststore-reference>\n"
        "                  </public-keys>\n"
        "                </user>\n"
        "              </users>\n"
        "            </client-authentication>\n"
        "          </ssh-server-parameters>\n"
        "        </ssh>\n"
        "      </endpoint>\n"
        "      <endpoint yang:operation=\"create\">\n"
        "        <name>e2</name>\n"
        "        <ssh>\n"
        "          <tcp-server-parameters>\n"
        "            <local-bind>\n"
        "              <local-address>127.0.0.1</local-address>\n"
        "              <local-port>0</local-port>\n"
        "            </local-bind>\n"
        "          </tcp-server-parameters>\n"
        "          <ssh-server-parameters>\n"
        "            <server-identity>\n"
        "              <host-key>\n"
        "                <name>hostkey1</name>\n"
        "                <public-key>\n"
        "                  <central-keystore-reference>hostkey</central-keystore-reference>\n"
        "                </public-key>\n"
        "              </host-key>\n"
        "            </server-identity>\n"
        "            <client-authentication>\n"
        "              <users>\n"
        "                <user>\n"
        "                  <name>user1</name>\n"
        "                  <public-keys>\n"
        "                    <central-truststore-reference>pkbag</central-truststore-reference>\n"
        "                  </public-keys>\n"
        "                </user>\n"
        "              </users>\n"
        "            </client-authentication>\n"
        "            <transport-params>\n"
        "              <host-key>\n"
        "                <host-key-alg yang:operation=\"delete\">ssh-rsa</host-key-alg>\n" // invalid, not set before
        "              </host-key>\n"
        "            </transport-params>\n"
        "          </ssh-server-parameters>\n"
        "        </ssh>\n"
        "      </endpoint>\n"
        "    </endpoints>\n"
        "  </listen>\n"
        "</netconf-server>";

const char *data3 =
        "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\" "
        " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">\n"
        "  <listen>\n"
        "    <endpoints>\n"
        "      <endpoint>\n"
        "        <name>e1</name>\n"
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
        "                <name>hostkey1</name>\n"
        "                <public-key>\n"
        "                  <central-keystore-reference>hostkey</central-keystore-reference>\n"
        "                </public-key>\n"
        "              </host-key>\n"
        "            </server-identity>\n"
        "            <client-authentication>\n"
        "              <users>\n"
        "                <user>\n"
        "                  <name>user1</name>\n"
        "                  <public-keys>\n"
        "                    <central-truststore-reference>pkbag</central-truststore-reference>\n"
        "                  </public-keys>\n"
        "                  <password yang:operation=\"create\">\n"
        "                    <hashed-password>$0$cleartextpassword</hashed-password>\n"
        "                  </password>\n"
        "                </user>\n"
        "              </users>\n"
        "            </client-authentication>\n"
        "          </ssh-server-parameters>\n"
        "        </ssh>\n"
        "      </endpoint>\n"
        "    </endpoints>\n"
        "  </listen>\n"
        "</netconf-server>\n";

const char *diff1 =
        "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\" "
        " xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"create\">\n"
        "  <listen>\n"
        "    <idle-timeout>420</idle-timeout>\n"
        "    <endpoints>\n"
        "      <endpoint>\n"
        "        <name>test-e1</name>\n"
        "        <ssh>\n"
        "          <tcp-server-parameters>\n"
        "            <local-bind>\n"
        "              <local-address>127.0.0.1</local-address>\n"
        "              <local-port>%s</local-port>\n"
        "            </local-bind>\n"
        "            <keepalives>\n"
        "              <idle-time>17</idle-time>\n"
        "              <max-probes>42</max-probes>\n"
        "              <probe-interval>59</probe-interval>\n"
        "            </keepalives>\n"
        "          </tcp-server-parameters>\n"
        "          <ssh-server-parameters>\n"
        "            <server-identity>\n"
        "              <host-key>\n"
        "                <name>hostkey1</name>\n"
        "                <public-key>\n"
        "                  <central-keystore-reference>hostkey</central-keystore-reference>\n"
        "                </public-key>\n"
        "              </host-key>\n"
        "            </server-identity>\n"
        "            <client-authentication>\n"
        "              <users>\n"
        "                <user>\n"
        "                  <name>user1</name>\n"
        "                  <public-keys>\n"
        "                    <central-truststore-reference>pkbag</central-truststore-reference>\n"
        "                  </public-keys>\n"
        "                </user>\n"
        "              </users>\n"
        "            </client-authentication>\n"
        "          </ssh-server-parameters>\n"
        "        </ssh>\n"
        "      </endpoint>\n"
        "      <endpoint>\n"
        "        <name>e2</name>\n"
        "        <ssh>\n"
        "          <tcp-server-parameters>\n"
        "            <local-bind>\n"
        "              <local-address>127.0.0.1</local-address>\n"
        "              <local-port>0</local-port>\n"
        "            </local-bind>\n"
        "          </tcp-server-parameters>\n"
        "          <ssh-server-parameters>\n"
        "            <server-identity>\n"
        "              <host-key>\n"
        "                <name>hostkey1</name>\n"
        "                <public-key>\n"
        "                  <central-keystore-reference>hostkey</central-keystore-reference>\n"
        "                </public-key>\n"
        "              </host-key>\n"
        "            </server-identity>\n"
        "            <client-authentication>\n"
        "              <users>\n"
        "                <user>\n"
        "                  <name>user1</name>\n"
        "                  <public-keys>\n"
        "                    <central-truststore-reference>pkbag</central-truststore-reference>\n"
        "                  </public-keys>\n"
        "                </user>\n"
        "              </users>\n"
        "            </client-authentication>\n"
        "            <transport-params>\n"
        "              <host-key>\n"
        "                <host-key-alg yang:operation=\"delete\">ssh-rsa</host-key-alg>\n"
        "              </host-key>\n"
        "            </transport-params>\n"
        "          </ssh-server-parameters>\n"
        "        </ssh>\n"
        "      </endpoint>\n"
        "    </endpoints>\n"
        "  </listen>\n"
        "</netconf-server>\n";

static void *
client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    /* set directory where to search for modules */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set ssh username */
    ret = nc_client_ssh_set_username("user1");
    assert_int_equal(ret, 0);

    /* add client's key pair */
    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/id_ed25519.pub", TESTS_DIR "/data/id_ed25519");
    assert_int_equal(ret, 0);

    /* wait for the server to reach polling */
    pthread_barrier_wait(&test_ctx->barrier);

    /* connect */
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);

    nc_session_free(session, NULL);
    return NULL;
}

static void
test_rollback(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx = *state;
    char *data_filled = NULL;

    /* print port number into the diff */
    ret = asprintf(&data_filled, data, TEST_PORT_STR);
    assert_int_not_equal(ret, -1);

    /* setup base configuration */
    ret = lyd_parse_data_mem(test_ctx->ctx, data_filled, LYD_XML, LYD_PARSE_ONLY, 0, &tree);
    assert_int_equal(ret, 0);

    /* add all implicit nodes */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);
    lyd_free_all(tree);
    free(data_filled);

    /* print port number into the new data */
    ret = asprintf(&data_filled, data2, TEST_PORT_STR);
    assert_int_not_equal(ret, -1);

    /* edit the configuration, try to delete existing endpoint and add a new one with invalid operation,
     * which should cause the whole edit to be rejected and rolled back */
    ret = lyd_parse_data_mem(test_ctx->ctx, data_filled, LYD_XML, LYD_PARSE_ONLY, 0, &tree);
    assert_int_equal(ret, 0);

    /* add all implicit nodes */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 1);
    lyd_free_all(tree);
    free(data_filled);

    /* start client and server threads, the client should be able to connect */
    ret = pthread_create(&tids[0], NULL, client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void *
conn_preserve_client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;
    struct nc_rpc *rpc;
    uint64_t msgid;
    NC_MSG_TYPE msgtype;
    struct lyd_node *envp = NULL, *op = NULL;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    /* set directory where to search for modules */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set ssh username */
    ret = nc_client_ssh_set_username("user1");
    assert_int_equal(ret, 0);

    /* add client's key pair */
    ret = nc_client_ssh_add_keypair(TESTS_DIR "/data/id_ed25519.pub", TESTS_DIR "/data/id_ed25519");
    assert_int_equal(ret, 0);

    /* wait for the server to reach polling */
    pthread_barrier_wait(&test_ctx->barrier);

    /* connect */
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_non_null(session);

    /* create a simple get-config rpc */
    rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, NULL, 0, NC_PARAMTYPE_CONST);
    assert_non_null(rpc);

    /* wait until the server applied its new config */
    pthread_barrier_wait(&test_ctx->barrier);

    /* send the rpc */
    ret = nc_send_rpc(session, rpc, 1000, &msgid);
    assert_int_equal(ret, NC_MSG_RPC);

    /* receive the reply */
    msgtype = nc_recv_reply(session, rpc, msgid, 1000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);

    /* wait for the server thread to finish */
    pthread_barrier_wait(&test_ctx->barrier);

    lyd_free_all(envp);
    lyd_free_all(op);
    nc_rpc_free(rpc);
    nc_session_free(session, NULL);
    return NULL;
}

static struct nc_server_reply *
glob_rpc(struct lyd_node *rpc, struct nc_session *session)
{
    (void)rpc;
    (void)session;
    return nc_server_reply_ok();
}

static void *
conn_preserve_server_thread(void *arg)
{
    int ret;
    NC_MSG_TYPE msgtype;
    struct nc_session *session = NULL;
    struct nc_pollsession *ps = NULL;
    struct ln2_test_ctx *test_ctx = arg;
    struct lyd_node *tree = NULL;
    char *data_filled = NULL;

    /* set the global rpc cb */
    nc_set_global_rpc_clb(glob_rpc);

    ps = nc_ps_new();
    assert_non_null(ps);

    /* wait for the client to be ready to connect */
    pthread_barrier_wait(&test_ctx->barrier);

    /* accept a session and add it to the poll session structure */
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, test_ctx->ctx, &session);
    assert_int_equal(msgtype, NC_MSG_HELLO);

    ret = nc_ps_add_session(ps, session);
    assert_int_equal(ret, 0);

    /* poll until the session is fully established */
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
    } while (ret & NC_PSPOLL_RPC);

    /* print port number into the new data */
    ret = asprintf(&data_filled, data3, TEST_PORT_STR);
    assert_int_not_equal(ret, -1);

    /* connection established, change the server configuration */
    ret = lyd_parse_data_mem(test_ctx->ctx, data_filled, LYD_XML, LYD_PARSE_ONLY, 0, &tree);
    assert_int_equal(ret, 0);

    /* add all implicit nodes */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);
    lyd_free_all(tree);
    free(data_filled);

    /* wait for the client */
    pthread_barrier_wait(&test_ctx->barrier);

    /* poll until we receive the rpc from the client */
    do {
        ret = nc_ps_poll(ps, NC_PS_POLL_TIMEOUT, NULL);
    } while (!(ret & NC_PSPOLL_RPC));

    /* wait for the client */
    pthread_barrier_wait(&test_ctx->barrier);

    nc_ps_clear(ps, 1, NULL);
    nc_ps_free(ps);
    return NULL;
}

static void
test_preserve_conn(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx = *state;
    char *data_filled = NULL;

    /* print port number into the diff */
    ret = asprintf(&data_filled, data, TEST_PORT_STR);
    assert_int_not_equal(ret, -1);

    /* setup base configuration */
    ret = lyd_parse_data_mem(test_ctx->ctx, data_filled, LYD_XML, LYD_PARSE_ONLY, 0, &tree);
    assert_int_equal(ret, 0);

    /* add all implicit nodes */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);
    lyd_free_all(tree);
    free(data_filled);

    ret = pthread_create(&tids[0], NULL, conn_preserve_client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, conn_preserve_server_thread, *state);
    assert_int_equal(ret, 0);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }
}

static void
test_transport_params_oper_get(void **state)
{
    int ret;
    struct lyd_node *algs = NULL;
    const char *expected_algs;
    struct ln2_test_ctx *test_ctx = *state;
    char *buf;

    /* check ssh supported algorithms */
    expected_algs = "<supported-algorithms xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ssh-common\">"
            "<public-key-algorithms>"
            "<supported-algorithm>ssh-ed25519</supported-algorithm>"
            "<supported-algorithm>ecdsa-sha2-nistp521</supported-algorithm>"
            "<supported-algorithm>ecdsa-sha2-nistp384</supported-algorithm>"
            "<supported-algorithm>ecdsa-sha2-nistp256</supported-algorithm>"
            "<supported-algorithm>sk-ssh-ed25519@openssh.com</supported-algorithm>"
            "<supported-algorithm>sk-ecdsa-sha2-nistp256@openssh.com</supported-algorithm>"
            "<supported-algorithm>rsa-sha2-512</supported-algorithm>"
            "<supported-algorithm>rsa-sha2-256</supported-algorithm>"
            "<supported-algorithm>ssh-rsa</supported-algorithm>"
            "<supported-algorithm>ssh-ed25519-cert-v01@openssh.com</supported-algorithm>"
            "<supported-algorithm>sk-ssh-ed25519-cert-v01@openssh.com</supported-algorithm>"
            "<supported-algorithm>ecdsa-sha2-nistp521-cert-v01@openssh.com</supported-algorithm>"
            "<supported-algorithm>ecdsa-sha2-nistp384-cert-v01@openssh.com</supported-algorithm>"
            "<supported-algorithm>ecdsa-sha2-nistp256-cert-v01@openssh.com</supported-algorithm>"
            "<supported-algorithm>sk-ecdsa-sha2-nistp256-cert-v01@openssh.com</supported-algorithm>"
            "<supported-algorithm>rsa-sha2-512-cert-v01@openssh.com</supported-algorithm>"
            "<supported-algorithm>rsa-sha2-256-cert-v01@openssh.com</supported-algorithm>"
            "<supported-algorithm>ssh-rsa-cert-v01@openssh.com</supported-algorithm>"
            "</public-key-algorithms>"
            "<encryption-algorithms>"
            "<supported-algorithm>chacha20-poly1305@openssh.com</supported-algorithm>"
            "<supported-algorithm>aes256-gcm@openssh.com</supported-algorithm>"
            "<supported-algorithm>aes128-gcm@openssh.com</supported-algorithm>"
            "<supported-algorithm>aes256-ctr</supported-algorithm>"
            "<supported-algorithm>aes192-ctr</supported-algorithm>"
            "<supported-algorithm>aes128-ctr</supported-algorithm>"
            "<supported-algorithm>aes256-cbc</supported-algorithm>"
            "<supported-algorithm>aes192-cbc</supported-algorithm>"
            "<supported-algorithm>aes128-cbc</supported-algorithm>"
            "<supported-algorithm>blowfish-cbc</supported-algorithm>"
            "<supported-algorithm>3des-cbc</supported-algorithm>"
            "<supported-algorithm>none</supported-algorithm>"
            "</encryption-algorithms>"
            "<key-exchange-algorithms>"
            "<supported-algorithm>diffie-hellman-group-exchange-sha1</supported-algorithm>"
            "<supported-algorithm>curve25519-sha256</supported-algorithm>"
            "<supported-algorithm>curve25519-sha256@libssh.org</supported-algorithm>"
            "<supported-algorithm>sntrup761x25519-sha512</supported-algorithm>"
            "<supported-algorithm>sntrup761x25519-sha512@openssh.com</supported-algorithm>"
            "<supported-algorithm>ecdh-sha2-nistp256</supported-algorithm>"
            "<supported-algorithm>ecdh-sha2-nistp384</supported-algorithm>"
            "<supported-algorithm>ecdh-sha2-nistp521</supported-algorithm>"
            "<supported-algorithm>diffie-hellman-group18-sha512</supported-algorithm>"
            "<supported-algorithm>diffie-hellman-group16-sha512</supported-algorithm>"
            "<supported-algorithm>diffie-hellman-group-exchange-sha256</supported-algorithm>"
            "<supported-algorithm>diffie-hellman-group14-sha256</supported-algorithm>"
            "<supported-algorithm>diffie-hellman-group14-sha1</supported-algorithm>"
            "<supported-algorithm>diffie-hellman-group1-sha1</supported-algorithm>"
            "</key-exchange-algorithms>"
            "<mac-algorithms>"
            "<supported-algorithm>hmac-sha2-256-etm@openssh.com</supported-algorithm>"
            "<supported-algorithm>hmac-sha2-512-etm@openssh.com</supported-algorithm>"
            "<supported-algorithm>hmac-sha1-etm@openssh.com</supported-algorithm>"
            "<supported-algorithm>hmac-sha2-256</supported-algorithm>"
            "<supported-algorithm>hmac-sha2-512</supported-algorithm>"
            "<supported-algorithm>hmac-sha1</supported-algorithm>"
            "<supported-algorithm>none</supported-algorithm>"
            "</mac-algorithms>"
            "</supported-algorithms>";
    ret = nc_server_config_oper_get_supported_ssh_algs(test_ctx->ctx, &algs);
    assert_int_equal(ret, 0);
    ret = lyd_print_mem(&buf, algs, LYD_XML, LYD_PRINT_SHRINK);

    assert_string_equal(buf, expected_algs);
    free(buf);
    lyd_free_all(algs);

    /* for tls supported algorithms only try getting them without comparing */
    ret = nc_server_config_oper_get_supported_tls_algs(test_ctx->ctx, &algs);
    assert_int_equal(ret, 0);
    lyd_free_all(algs);
}

static void
read_config_file(const char *path, char **mem)
{
    FILE *f;
    long fsize;
    size_t read;

    f = fopen(path, "r");
    assert_non_null(f);

    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    assert_true(fsize > 0);
    fseek(f, 0, SEEK_SET);

    *mem = malloc(fsize + 1);
    assert_non_null(*mem);

    read = fread(*mem, 1, fsize, f);
    assert_int_equal(read, fsize);
    (*mem)[read] = '\0';

    fclose(f);
}

static void
test_config_all_nodes(void **state)
{
    int ret;
    struct lyd_node *tree = NULL, *dup = NULL, *n;
    struct lyd_meta *meta;
    struct ln2_test_ctx *test_ctx = *state;
    char *mem = NULL, *mem_filled = NULL;

    /* read the config file into memory */
    read_config_file(TESTS_DIR "/data/config.xml", &mem);

    /* print the port numbers into the config */
    ret = asprintf(&mem_filled, mem, TEST_PORT_STR, TEST_PORT_2_STR, TEST_PORT_3_STR,
            TEST_PORT_4_STR, TEST_PORT_5_STR, TEST_PORT_6_STR);
    assert_int_not_equal(ret, -1);

    /* load configuration from memory */
    ret = lyd_parse_data_mem(test_ctx->ctx, mem_filled, LYD_XML, LYD_PARSE_STRICT, LYD_VALIDATE_PRESENT, &tree);
    assert_int_equal(ret, 0);

    /* apply the configuration */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* apply it again, should succeed without changes */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* duplicate the configuration */
    ret = lyd_dup_single(tree, NULL, LYD_DUP_RECURSIVE, &dup);
    assert_int_equal(ret, 0);

    /* add the delete operation to the root */
    ret = lyd_new_meta(test_ctx->ctx, dup, NULL, "yang:operation", "delete", 0, &meta);
    assert_int_equal(ret, 0);

    /* should delete everything without errors */
    ret = nc_server_config_setup_diff(dup);
    assert_int_equal(ret, 0);

    /* change the meta to create, should add everything back without errors */
    ret = lyd_change_meta(meta, "create");
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(dup);
    assert_int_equal(ret, 0);

    /* set the operation to none */
    ret = lyd_change_meta(meta, "none");
    assert_int_equal(ret, 0);

    /* try to delete the SSH endpoint only */
    ret = lyd_find_path(dup, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='ssh']", 0, &n);
    assert_int_equal(ret, 0);

    ret = lyd_new_meta(test_ctx->ctx, n, NULL, "yang:operation", "delete", 0, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(dup);
    assert_int_equal(ret, 0);

    lyd_free_tree(n);

    /* try to delete the TLS endpoint only */
    ret = lyd_find_path(dup, "/ietf-netconf-server:netconf-server/listen/endpoints/endpoint[name='tls']", 0, &n);
    assert_int_equal(ret, 0);

    ret = lyd_new_meta(test_ctx->ctx, n, NULL, "yang:operation", "delete", 0, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(dup);
    assert_int_equal(ret, 0);

    lyd_free_tree(n);

    /* try to delete call home ssh endpoint only */
    ret = lyd_find_path(dup, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='persistent']/"
            "endpoints/endpoint[name='ssh']", 0, &n);
    assert_int_equal(ret, 0);

    ret = lyd_new_meta(test_ctx->ctx, n, NULL, "yang:operation", "delete", 0, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(dup);
    assert_int_equal(ret, 0);

    lyd_free_tree(n);

    /* try to delete call home tls endpoint only */
    ret = lyd_find_path(dup, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='persistent']/"
            "endpoints/endpoint[name='tls']", 0, &n);
    assert_int_equal(ret, 0);

    ret = lyd_new_meta(test_ctx->ctx, n, NULL, "yang:operation", "delete", 0, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(dup);
    assert_int_equal(ret, 0);

    lyd_free_tree(n);

    /* try to delete a persistent call home client */
    ret = lyd_find_path(dup, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='persistent']", 0, &n);
    assert_int_equal(ret, 0);

    ret = lyd_new_meta(test_ctx->ctx, n, NULL, "yang:operation", "delete", 0, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(dup);
    assert_int_equal(ret, 0);

    lyd_free_tree(n);

    /* try to delete a periodic call home client */
    ret = lyd_find_path(dup, "/ietf-netconf-server:netconf-server/call-home/netconf-client[name='periodic']", 0, &n);
    assert_int_equal(ret, 0);

    ret = lyd_new_meta(test_ctx->ctx, n, NULL, "yang:operation", "delete", 0, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(dup);
    assert_int_equal(ret, 0);

    free(mem);
    free(mem_filled);
    lyd_free_all(dup);
    lyd_free_all(tree);
}

static void
test_config_cascade_delete(void **state)
{
    int ret;
    struct lyd_node *tree = NULL, *node = NULL;
    struct ln2_test_ctx *test_ctx = *state;

    /*
     * Test the fix for GitHub issue #614:
     * Deleting the last entry of a list inside a presence container must
     * also delete the empty presence container to maintain YANG validity.
     */

    /* add a listen endpoint and a call-home client */
    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_SSH,
            "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "endpt", "hostkey1",
            TESTS_DIR "/data/key_rsa", NULL, &tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ssh_user_password(test_ctx->ctx, "endpt", "user1", "passwd", &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ch_address_port(test_ctx->ctx, "ch1", "ch-endpt1",
            NC_TI_SSH, "127.0.0.1", TEST_PORT_2_STR, &tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ch_ssh_hostkey(test_ctx->ctx, "ch1", "ch-endpt1",
            "hostkey1", TESTS_DIR "/data/key_rsa", NULL, &tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ch_ssh_user_password(test_ctx->ctx, "ch1", "ch-endpt1",
            "user1", "passwd", &tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ch_persistent(test_ctx->ctx, "ch1", &tree);
    assert_int_equal(ret, 0);

    /* must be valid */
    ret = lyd_validate_all(&tree, test_ctx->ctx, LYD_VALIDATE_PRESENT, NULL);
    assert_int_equal(ret, 0);

    /* delete the last listen endpoint, the listen container should be deleted as well */
    ret = nc_server_config_del_endpt("endpt", &tree);
    assert_int_equal(ret, 0);
    ret = lyd_find_path(tree, "/ietf-netconf-server:netconf-server/listen", 0, &node);

    /* listen should have been deleted, lyd_find_path should find the parent netconf-server container */
    assert_int_equal(ret, LY_EINCOMPLETE);
    assert_int_equal(strcmp(LYD_NAME(node), "netconf-server"), 0);

    /* delete the last call-home client, the call-home container should be deleted as well */
    ret = nc_server_config_del_ch_client("ch1", &tree);
    assert_int_equal(ret, 0);
    ret = lyd_find_path(tree, "/ietf-netconf-server:netconf-server/call-home", 0, &node);

    /* call-home should have been deleted, lyd_find_path should find the parent netconf-server container */
    assert_int_equal(ret, LY_EINCOMPLETE);
    assert_int_equal(strcmp(LYD_NAME(node), "netconf-server"), 0);

    /* the configuration should stay valid */
    ret = lyd_validate_all(&tree, test_ctx->ctx, LYD_VALIDATE_PRESENT, NULL);
    assert_int_equal(ret, 0);

    lyd_free_all(tree);
}

static void *
unsupported_asymkey_client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    /* set directory where to search for modules */
    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    /* set ssh username */
    ret = nc_client_ssh_set_username("user1");
    assert_int_equal(ret, 0);

    /* wait for the server to reach polling */
    pthread_barrier_wait(&test_ctx->barrier);

    /* connect, expecting fail */
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_null(session);

    return NULL;
}

static void
test_unusupported_asymkey_format(void **state)
{
    int ret;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx = *state;
    const char *data, *mod;
    pthread_t tids[2];
    char *data_filled = NULL;

    /* create a module defining libnetconf2 unsupported key formats */
    mod =
            "module a {yang-version 1.1; namespace urn:a; prefix a; import ietf-crypto-types {prefix ct;}"
            "identity unsupported-public-key-format {base ct:public-key-format;}"
            "identity unsupported-private-key-format {base ct:private-key-format;}}";

    /* load the module */
    ret = lys_parse_mem(test_ctx->ctx, mod, LYS_IN_YANG, NULL);
    assert_int_equal(ret, 0);

    /* prepare data with unsupported asymmetric key formats */
    data =
            "<keystore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-keystore\">"
            "  <asymmetric-keys>"
            "    <asymmetric-key>"
            "      <name>UNSUPPORTED</name>"
            "      <public-key-format xmlns:a=\"urn:a\">a:unsupported-public-key-format</public-key-format>"
            "      <public-key>base64blob==</public-key>"
            "      <private-key-format xmlns:a=\"urn:a\">a:unsupported-private-key-format</private-key-format>"
            "      <cleartext-private-key>base64blob==</cleartext-private-key>"
            "      <certificates/>"
            "    </asymmetric-key>"
            "  </asymmetric-keys>"
            "</keystore>";

    /* parse the data */
    ret = lyd_parse_data_mem(test_ctx->ctx, data, LYD_XML, LYD_PARSE_ONLY, 0, &tree);
    assert_int_equal(ret, 0);

    /* applying the data should succeed, unsupported formats are allowed */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    lyd_free_all(tree);

    /* use the asymmetric key in netconf-server config */
    data =
            "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\" "
            "    xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"create\">"
            "  <listen>"
            "    <endpoints>"
            "      <endpoint>"
            "        <name>e1</name>"
            "        <ssh>"
            "          <tcp-server-parameters>"
            "            <local-bind>"
            "              <local-address>127.0.0.1</local-address>"
            "              <local-port>%s</local-port>"
            "            </local-bind>"
            "          </tcp-server-parameters>"
            "          <ssh-server-parameters>"
            "            <server-identity>"
            "              <host-key>"
            "                <name>hostkey1</name>"
            "                <public-key>"
            "                  <central-keystore-reference>UNSUPPORTED</central-keystore-reference>" // use it here
            "                </public-key>"
            "              </host-key>"
            "            </server-identity>"
            "            <client-authentication>"
            "              <users>"
            "                <user>"
            "                  <name>user1</name>"
            "                  <none/>" // no keys or password
            "                </user>"
            "              </users>"
            "            </client-authentication>"
            "          </ssh-server-parameters>"
            "        </ssh>"
            "      </endpoint>"
            "    </endpoints>"
            "  </listen>"
            "</netconf-server>\n";

    /* print port number into the data */
    ret = asprintf(&data_filled, data, TEST_PORT_STR);
    assert_int_not_equal(ret, -1);

    /* parse the data */
    ret = lyd_parse_data_mem(test_ctx->ctx, data_filled, LYD_XML, LYD_PARSE_ONLY, 0, &tree);
    assert_int_equal(ret, 0);

    /* add all implicit nodes */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);

    /* applying the data should succeed, unsupported key formats are allowed */
    ret = nc_server_config_setup_diff(tree);
    assert_int_equal(ret, 0);

    /* start client and server threads, the client should NOT be able to connect */
    ret = pthread_create(&tids[0], NULL, unsupported_asymkey_client_thread, *state);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, ln2_glob_test_server_thread_fail, *state);
    assert_int_equal(ret, 0);

    for (int i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    free(data_filled);
    lyd_free_all(tree);
}

static void
test_invalid_diff(void **state)
{
    int ret;
    struct lyd_node *diff = NULL, *node = NULL;
    struct ln2_test_ctx *test_ctx = *state;
    const struct lys_module *yang_mod;

    yang_mod = ly_ctx_get_module_implemented(test_ctx->ctx, "yang");
    assert_non_null(yang_mod);

    /* dup the keystore config */
    ret = lyd_find_path(test_ctx->test_data, "/ietf-keystore:keystore", 0, &node);
    assert_int_equal(ret, 0);
    ret = lyd_dup_single(node, NULL, LYD_DUP_RECURSIVE, &diff);
    assert_int_equal(ret, 0);

    /* add none operation to the root */
    ret = lyd_new_meta(test_ctx->ctx, diff, yang_mod, "operation", "none", 0, NULL);
    assert_int_equal(ret, 0);

    /* Delete the "hostkey" asymmetric key from the keystore */
    ret = lyd_find_path(diff, "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='hostkey']", 0, &node);
    assert_int_equal(ret, 0);
    ret = lyd_new_meta(test_ctx->ctx, node, yang_mod, "operation", "delete", 0, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(diff);
    assert_int_equal(ret, 0);

    /* Now apply a diff with op=none on the deleted key and op=delete on its previously existing child public-key */
    ret = lyd_new_meta(test_ctx->ctx, node, yang_mod, "operation", "none", 0, NULL);
    assert_int_equal(ret, 0);

    /* add delete op to the previously existing child public-key */
    ret = lyd_find_path(diff,
            "/ietf-keystore:keystore/asymmetric-keys/asymmetric-key[name='hostkey']/public-key", 0, &node);
    assert_int_equal(ret, 0);
    ret = lyd_new_meta(test_ctx->ctx, node, yang_mod, "operation", "delete", 0, NULL);
    assert_int_equal(ret, 0);

    /* should fail because the key was already deleted and the diff is invalid, but it should not crash */
    ret = nc_server_config_setup_diff(diff);
    assert_int_equal(ret, 1);

    lyd_free_all(diff);
}

/**
 * @brief Moving an entry of an ordered-by user list is reported as a replace operation,
 * which must be handled and must not crash.
 */
static void
test_ordered_list_move(void **state)
{
    int ret;
    struct lyd_node *tree = NULL, *diff = NULL;
    struct ln2_test_ctx *test_ctx = *state;
    char *mem = NULL, *mem_filled = NULL;

    /* a diff that only moves entries of the two ordered-by user lists, just like sysrepo
     * reports it - the moved list entry is present with its keys only, without the new position */
    const char *move_diff =
            "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\" "
            "    xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">"
            "  <listen>"
            "    <endpoints>"
            "      <endpoint>"
            "        <name>ssh</name>"
            "        <ssh>"
            "          <ssh-server-parameters>"
            "            <server-identity>"
            "              <host-key yang:operation=\"replace\">"
            "                <name>ssh-rsa</name>"
            "              </host-key>"
            "            </server-identity>"
            "          </ssh-server-parameters>"
            "        </ssh>"
            "      </endpoint>"
            "    </endpoints>"
            "  </listen>"
            "  <call-home>"
            "    <netconf-client>"
            "      <name>persistent</name>"
            "      <endpoints>"
            "        <endpoint yang:operation=\"replace\">"
            "          <name>tls</name>"
            "        </endpoint>"
            "      </endpoints>"
            "    </netconf-client>"
            "  </call-home>"
            "</netconf-server>\n";

    /* read the config file into memory */
    read_config_file(TESTS_DIR "/data/config.xml", &mem);

    /* print the port numbers into the config */
    ret = asprintf(&mem_filled, mem, TEST_PORT_STR, TEST_PORT_2_STR, TEST_PORT_3_STR,
            TEST_PORT_4_STR, TEST_PORT_5_STR, TEST_PORT_6_STR);
    assert_int_not_equal(ret, -1);

    ret = lyd_parse_data_mem(test_ctx->ctx, mem_filled, LYD_XML, LYD_PARSE_STRICT, LYD_VALIDATE_PRESENT, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* the move must be handled, not crash and not fail */
    ret = lyd_parse_data_mem(test_ctx->ctx, move_diff, LYD_XML, LYD_PARSE_ONLY, 0, &diff);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_diff(diff);
    assert_int_equal(ret, 0);

    lyd_free_all(diff);
    lyd_free_all(tree);
    free(mem);
    free(mem_filled);
}

/**
 * @brief Time in seconds the client stalls in its password callback.
 *
 * Has to be longer than ::NC_CONFIG_LOCK_TIMEOUT (10 s) so that a configuration update waiting for
 * the whole authentication would be dropped instead of applied.
 */
#define TEST_STALL_AUTH_SLEEP 13

/** @brief Time in seconds the client stalls when only an in-flight handshake is needed. */
#define TEST_STALL_AUTH_SLEEP_SHORT 5

/** @brief Maximum time in msec anything done while a handshake is stalled may take. */
#define TEST_NO_BLOCK_TIMEOUT 2000

/** @brief Time in seconds the client stalls in its password callback, set by each test. */
static unsigned int test_stall_auth_sleep = TEST_STALL_AUTH_SLEEP;

/** @brief Time in seconds to wait for a Call Home client to report failed connection attempts. */
#define TEST_CH_WATCH_TIME 4

/** @brief Maximum number of distinct Call Home threads the test keeps track of. */
#define TEST_CH_TID_MAX 8

struct test_ch_threads {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t tids[TEST_CH_TID_MAX];
    uint32_t tid_count;
    char endpt[64];
    char last_endpt[64];
};

/* acquire ctx cb for the Call Home dispatch */
static const struct ly_ctx *
test_ch_acquire_ctx_cb(void *cb_data)
{
    return ((struct ln2_test_ctx *)cb_data)->ctx;
}

/* release ctx cb for the Call Home dispatch */
static void
test_ch_release_ctx_cb(void *cb_data)
{
    (void) cb_data;
}

/* new session cb for the Call Home dispatch, never actually called in these tests */
static int
test_ch_new_session_cb(const char *client_name, struct nc_session *new_session, void *user_data)
{
    (void) client_name;
    (void) new_session;
    (void) user_data;
    return 1;
}

/**
 * @brief Record the thread of every failed Call Home connection attempt.
 *
 * Called by the Call Home thread itself, so the number of distinct thread IDs seen is the number
 * of Call Home threads running for the client.
 */
static void
test_ch_new_session_fail_cb(const char *client_name, const char *endpt_name, uint8_t max_attempts,
        uint8_t cur_attempt, void *user_data)
{
    struct test_ch_threads *threads = user_data;
    pthread_t self = pthread_self();
    uint32_t i;

    (void) client_name;
    (void) max_attempts;
    (void) cur_attempt;

    pthread_mutex_lock(&threads->lock);
    if (!threads->endpt[0]) {
        /* the endpoint of the very first failed attempt is the first one in the configuration */
        strncpy(threads->endpt, endpt_name, sizeof threads->endpt - 1);
    }
    memset(threads->last_endpt, 0, sizeof threads->last_endpt);
    strncpy(threads->last_endpt, endpt_name, sizeof threads->last_endpt - 1);
    for (i = 0; i < threads->tid_count; ++i) {
        if (pthread_equal(threads->tids[i], self)) {
            break;
        }
    }
    if ((i == threads->tid_count) && (threads->tid_count < TEST_CH_TID_MAX)) {
        threads->tids[threads->tid_count++] = self;
    }
    pthread_cond_broadcast(&threads->cond);
    pthread_mutex_unlock(&threads->lock);
}

/**
 * @brief Create the YANG data of a Call Home endpoint that can never connect anywhere.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Name of the Call Home client.
 * @param[in] endpt_name Name of the Call Home endpoint.
 * @param[out] tree Created YANG data.
 */
static void
test_create_ch_endpt_data(const struct ly_ctx *ctx, const char *client_name, const char *endpt_name,
        struct lyd_node **tree)
{
    int ret;

    /* port 1 is never listening, so the connection is refused immediately */
    ret = nc_server_config_add_ch_address_port(ctx, client_name, endpt_name, NC_TI_SSH, "127.0.0.1", "1", tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ch_ssh_hostkey(ctx, client_name, endpt_name, "hostkey",
            TESTS_DIR "/data/key_ecdsa", NULL, tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_add_ch_ssh_user_pubkey(ctx, client_name, endpt_name, "user", "pubkey",
            TESTS_DIR "/data/id_ed25519.pub", tree);
    assert_int_equal(ret, 0);
}

/**
 * @brief Create the YANG data of a Call Home client that can never connect anywhere.
 *
 * @param[in] ctx libyang context.
 * @param[in] client_name Name of the Call Home client.
 * @param[out] tree Created YANG data.
 */
static void
test_create_ch_client_data(const struct ly_ctx *ctx, const char *client_name, struct lyd_node **tree)
{
    int ret;

    test_create_ch_endpt_data(ctx, client_name, "endpt", tree);

    ret = nc_server_config_add_ch_persistent(ctx, client_name, tree);
    assert_int_equal(ret, 0);

    /* retry quickly so that the test does not have to wait long */
    ret = nc_server_config_add_ch_reconnect_strategy(ctx, client_name, NC_CH_FIRST_LISTED, 1, 3, tree);
    assert_int_equal(ret, 0);
}

/**
 * @brief Applying the whole configuration data again must not dispatch a second thread
 * for an already running Call Home client.
 */
static void
test_ch_dispatch_not_duplicated(void **state)
{
    int ret;
    uint32_t tid_count;
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ch_threads threads = {0};
    struct timespec ts;

    pthread_mutex_init(&threads.lock, NULL);
    pthread_cond_init(&threads.cond, NULL);

    nc_server_ch_set_dispatch_data(test_ch_acquire_ctx_cb, test_ch_release_ctx_cb, test_ctx,
            test_ch_new_session_cb, NULL);
    nc_server_ch_set_new_session_fail_cb(test_ch_new_session_fail_cb, &threads);

    test_create_ch_client_data(test_ctx->ctx, "ch", &tree);

    /* dispatch the Call Home client */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* wait until its thread reports a failed connection attempt */
    pthread_mutex_lock(&threads.lock);
    while (!threads.tid_count) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 10;
        ret = pthread_cond_timedwait(&threads.cond, &threads.lock, &ts);
        assert_int_equal(ret, 0);
    }
    pthread_mutex_unlock(&threads.lock);

    /* apply the very same data again, the client is already running */
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* give a duplicate thread enough time to report a failed connection attempt of its own */
    sleep(TEST_CH_WATCH_TIME);

    pthread_mutex_lock(&threads.lock);
    tid_count = threads.tid_count;
    pthread_mutex_unlock(&threads.lock);

    /* exactly one Call Home thread may be running for the client */
    assert_int_equal(tid_count, 1);

    lyd_free_all(tree);
    pthread_cond_destroy(&threads.cond);
    pthread_mutex_destroy(&threads.lock);
}

/**
 * @brief A moved entry of an ordered-by user list must actually change its position.
 *
 * The Call Home thread always starts with the first endpoint of the client, so the endpoint of the
 * first failed connection attempt tells which one that is.
 */
static void
test_ch_endpoint_order(void **state)
{
    int ret;
    struct lyd_node *tree = NULL, *diff = NULL;
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ch_threads threads = {0};
    struct timespec ts;

    /* move the second endpoint to the front, an empty "key" means the entry belongs first */
    const char *move_diff =
            "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\" "
            "    xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">"
            "  <call-home>"
            "    <netconf-client>"
            "      <name>ch</name>"
            "      <endpoints>"
            "        <endpoint yang:operation=\"replace\" yang:key=\"\">"
            "          <name>second</name>"
            "        </endpoint>"
            "      </endpoints>"
            "    </netconf-client>"
            "  </call-home>"
            "</netconf-server>\n";

    pthread_mutex_init(&threads.lock, NULL);
    pthread_cond_init(&threads.cond, NULL);

    /* two endpoints, "first" is listed first */
    test_create_ch_endpt_data(test_ctx->ctx, "ch", "first", &tree);
    test_create_ch_endpt_data(test_ctx->ctx, "ch", "second", &tree);

    ret = nc_server_config_add_ch_persistent(test_ctx->ctx, "ch", &tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ch_reconnect_strategy(test_ctx->ctx, "ch", NC_CH_FIRST_LISTED, 1, 1, &tree);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    ret = lyd_parse_data_mem(test_ctx->ctx, move_diff, LYD_XML, LYD_PARSE_ONLY, 0, &diff);
    assert_int_equal(ret, 0);
    ret = nc_server_config_setup_diff(diff);
    assert_int_equal(ret, 0);

    /* dispatch the client only now, so that it starts with the reordered endpoints */
    nc_server_ch_set_new_session_fail_cb(test_ch_new_session_fail_cb, &threads);
    ret = nc_connect_ch_client_dispatch("ch", test_ch_acquire_ctx_cb, test_ch_release_ctx_cb, test_ctx,
            test_ch_new_session_cb, NULL);
    assert_int_equal(ret, 0);

    /* wait for the first failed connection attempt */
    pthread_mutex_lock(&threads.lock);
    while (!threads.endpt[0]) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 10;
        ret = pthread_cond_timedwait(&threads.cond, &threads.lock, &ts);
        assert_int_equal(ret, 0);
    }
    assert_string_equal(threads.endpt, "second");
    pthread_mutex_unlock(&threads.lock);

    lyd_free_all(diff);
    lyd_free_all(tree);
    pthread_cond_destroy(&threads.cond);
    pthread_mutex_destroy(&threads.lock);
}

/* password callback of the stalling client */
static char *
test_stall_auth_password(const char *username, const char *hostname, void *priv)
{
    (void) username;
    (void) hostname;
    (void) priv;

    /* keep the server waiting for the authentication */
    sleep(test_stall_auth_sleep);

    /* a wrong password, the connection is expected to fail */
    return strdup("wrong");
}

static void *
test_stall_auth_client_thread(void *arg)
{
    int ret;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* skip all hostkey and known_hosts checks */
    nc_client_ssh_set_knownhosts_mode(NC_SSH_KNOWNHOSTS_SKIP);

    ret = nc_client_set_schema_searchpath(MODULES_DIR);
    assert_int_equal(ret, 0);

    ret = nc_client_ssh_set_username("stall");
    assert_int_equal(ret, 0);

    nc_client_ssh_set_auth_password_clb(test_stall_auth_password, NULL);

    /* wait for the server to be ready */
    pthread_barrier_wait(&test_ctx->barrier);

    /* the authentication is stalled and then fails */
    session = nc_connect_ssh("127.0.0.1", TEST_PORT, NULL);
    assert_null(session);

    return NULL;
}

static void *
test_stall_auth_server_thread(void *arg)
{
    NC_MSG_TYPE msgtype;
    struct nc_session *session = NULL;
    struct ln2_test_ctx *test_ctx = arg;

    /* wait for the client to be ready to connect */
    pthread_barrier_wait(&test_ctx->barrier);

    /* the client never authenticates, so this is expected to fail after the stall */
    msgtype = nc_accept(NC_ACCEPT_TIMEOUT, test_ctx->ctx, &session);
    assert_int_not_equal(msgtype, NC_MSG_HELLO);
    nc_session_free(session, NULL);

    return NULL;
}

/**
 * @brief A configuration update must not be dropped because a session handshake is holding
 * the configuration lock.
 */
static void
test_config_update_during_auth(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct lyd_node *tree = NULL, *diff = NULL;
    struct ln2_test_ctx *test_ctx = *state;
    const struct lys_module *yang_mod;
    struct timespec ts_start, ts_end;
    int64_t elapsed_ms;

    test_stall_auth_sleep = TEST_STALL_AUTH_SLEEP;

    yang_mod = ly_ctx_get_module_implemented(test_ctx->ctx, "yang");
    assert_non_null(yang_mod);

    /* a listening SSH endpoint with a password-authenticated user */
    ret = nc_server_config_add_address_port(test_ctx->ctx, "endpt", NC_TI_SSH, "127.0.0.1", TEST_PORT, &tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ssh_hostkey(test_ctx->ctx, "endpt", "hostkey", TESTS_DIR "/data/key_ecdsa",
            NULL, &tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ssh_user_password(test_ctx->ctx, "endpt", "stall", "correct", &tree);
    assert_int_equal(ret, 0);

    /* add all the default nodes, the authentication timeout has to be longer than the stall */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* prepare the configuration update in advance so that only the lock wait is measured */
    test_create_ch_client_data(test_ctx->ctx, "ch", &diff);
    ret = lyd_new_meta(test_ctx->ctx, diff, yang_mod, "operation", "create", 0, NULL);
    assert_int_equal(ret, 0);

    ret = pthread_create(&tids[0], NULL, test_stall_auth_client_thread, test_ctx);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, test_stall_auth_server_thread, test_ctx);
    assert_int_equal(ret, 0);

    /* let the key exchange finish, the server is now waiting for the authentication
     * while holding the configuration READ lock */
    sleep(2);

    /* this must neither be silently dropped nor wait out the stalled authentication */
    clock_gettime(CLOCK_MONOTONIC, &ts_start);
    ret = nc_server_config_setup_diff(diff);
    assert_int_equal(ret, 0);
    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    elapsed_ms = ((int64_t)(ts_end.tv_sec - ts_start.tv_sec) * 1000) +
            ((ts_end.tv_nsec - ts_start.tv_nsec) / 1000000);
    assert_true(elapsed_ms < TEST_NO_BLOCK_TIMEOUT);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    lyd_free_all(diff);
    lyd_free_all(tree);
}

/**
 * @brief Create the YANG data of a listening SSH endpoint with a password-authenticated user.
 *
 * @param[in] ctx libyang context.
 * @param[in] endpt_name Name of the endpoint.
 * @param[in] port Port to listen on.
 * @param[out] tree Created YANG data.
 */
static void
test_create_stall_endpt_data(const struct ly_ctx *ctx, const char *endpt_name, uint16_t port,
        struct lyd_node **tree)
{
    int ret;

    ret = nc_server_config_add_address_port(ctx, endpt_name, NC_TI_SSH, "127.0.0.1", port, tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ssh_hostkey(ctx, endpt_name, "hostkey", TESTS_DIR "/data/key_ecdsa",
            NULL, tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ssh_user_password(ctx, endpt_name, "stall", "correct", tree);
    assert_int_equal(ret, 0);

    /* add all the default nodes, the authentication timeout has to be longer than the stall */
    ret = lyd_new_implicit_tree(*tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);
}

/**
 * @brief Try to establish a TCP connection to a local port.
 *
 * @param[in] port Port to connect to.
 * @return 0 if the connection was established, -1 if it was refused.
 */
static int
test_tcp_connect(uint16_t port)
{
    int sock, r;
    struct sockaddr_in addr = {0};

    sock = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(sock > -1);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    r = connect(sock, (struct sockaddr *)&addr, sizeof addr);
    close(sock);

    return r ? -1 : 0;
}

/**
 * @brief Removing an endpoint must stop its listening socket right away.
 *
 * A stalled handshake keeps a reference to the configuration generation the endpoint belongs to, but
 * the listening socket lives outside of it, so it is closed as soon as the update is applied.
 */
static void
test_removed_endpt_stops_listening(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx = *state;

    test_stall_auth_sleep = TEST_STALL_AUTH_SLEEP_SHORT;

    test_create_stall_endpt_data(test_ctx->ctx, "endpt", TEST_PORT, &tree);
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* the endpoint is listening now */
    assert_int_equal(test_tcp_connect(TEST_PORT), 0);

    ret = pthread_create(&tids[0], NULL, test_stall_auth_client_thread, test_ctx);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, test_stall_auth_server_thread, test_ctx);
    assert_int_equal(ret, 0);

    /* let the key exchange finish, the server is now stalled in the authentication */
    sleep(2);

    /* remove all the endpoints, only the keystore and the truststore are left */
    ret = nc_server_config_setup_data(test_ctx->test_data);
    assert_int_equal(ret, 0);

    /* the socket must be gone even though the stalled handshake still uses the old generation */
    assert_int_equal(test_tcp_connect(TEST_PORT), -1);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    lyd_free_all(tree);
}

/**
 * @brief The API-settable options must be settable while a handshake is in flight.
 */
static void
test_api_setters_during_auth(void **state)
{
    int ret, i;
    pthread_t tids[2];
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx = *state;
    struct timespec ts_start, ts_end;
    int64_t elapsed_ms;

    test_stall_auth_sleep = TEST_STALL_AUTH_SLEEP_SHORT;

    test_create_stall_endpt_data(test_ctx->ctx, "endpt", TEST_PORT, &tree);
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    ret = pthread_create(&tids[0], NULL, test_stall_auth_client_thread, test_ctx);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, test_stall_auth_server_thread, test_ctx);
    assert_int_equal(ret, 0);

    /* let the key exchange finish, the server is now stalled in the authentication */
    sleep(2);

    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    ret = nc_server_ssh_set_protocol_string("test");
    assert_int_equal(ret, 0);
    nc_server_tls_set_verify_clb(NULL);
    /* returns an error without libpam support, which is fine, it must just not block */
    nc_server_ssh_set_pam_conf_filename("netconf");
    ret = nc_server_ssh_set_authkey_path_format("/tmp/%u/authorized_keys");
    assert_int_equal(ret, 0);
    ret = nc_server_set_unix_socket_dir("/tmp");
    assert_int_equal(ret, 0);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    elapsed_ms = ((int64_t)(ts_end.tv_sec - ts_start.tv_sec) * 1000) +
            ((ts_end.tv_nsec - ts_start.tv_nsec) / 1000000);
    assert_true(elapsed_ms < TEST_NO_BLOCK_TIMEOUT);

    for (i = 0; i < 2; i++) {
        pthread_join(tids[i], NULL);
    }

    lyd_free_all(tree);
}

/**
 * @brief Wait until the Call Home client reports a failed attempt on the given endpoint.
 *
 * @param[in] threads Call Home thread tracking data.
 * @param[in] endpt_name Expected endpoint name.
 */
static void
test_ch_wait_for_endpt(struct test_ch_threads *threads, const char *endpt_name)
{
    int ret;
    struct timespec ts;

    pthread_mutex_lock(&threads->lock);
    while (strcmp(threads->last_endpt, endpt_name)) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 10;
        ret = pthread_cond_timedwait(&threads->cond, &threads->lock, &ts);
        assert_int_equal(ret, 0);
    }
    pthread_mutex_unlock(&threads->lock);
}

/**
 * @brief A running Call Home thread must survive a configuration swap and pick up the new endpoints.
 */
static void
test_ch_survives_config_swap(void **state)
{
    int ret;
    uint32_t tid_count;
    struct lyd_node *tree = NULL, *tree2 = NULL;
    struct ln2_test_ctx *test_ctx = *state;
    struct test_ch_threads threads = {0};

    pthread_mutex_init(&threads.lock, NULL);
    pthread_cond_init(&threads.cond, NULL);

    /* a client with a single endpoint that can never connect anywhere */
    test_create_ch_endpt_data(test_ctx->ctx, "ch", "first", &tree);
    ret = nc_server_config_add_ch_persistent(test_ctx->ctx, "ch", &tree);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ch_reconnect_strategy(test_ctx->ctx, "ch", NC_CH_FIRST_LISTED, 1, 3, &tree);
    assert_int_equal(ret, 0);

    nc_server_ch_set_dispatch_data(test_ch_acquire_ctx_cb, test_ch_release_ctx_cb, test_ctx,
            test_ch_new_session_cb, NULL);
    nc_server_ch_set_new_session_fail_cb(test_ch_new_session_fail_cb, &threads);

    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* the thread is running and attempting to connect to the only endpoint */
    test_ch_wait_for_endpt(&threads, "first");

    pthread_mutex_lock(&threads.lock);
    assert_int_equal(threads.tid_count, 1);
    pthread_mutex_unlock(&threads.lock);

    /* replace the whole configuration, the client keeps its name but gets a different endpoint */
    test_create_ch_endpt_data(test_ctx->ctx, "ch", "second", &tree2);
    ret = nc_server_config_add_ch_persistent(test_ctx->ctx, "ch", &tree2);
    assert_int_equal(ret, 0);
    ret = nc_server_config_add_ch_reconnect_strategy(test_ctx->ctx, "ch", NC_CH_FIRST_LISTED, 1, 3, &tree2);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(tree2);
    assert_int_equal(ret, 0);

    /* the very same thread must pick the new endpoint up */
    test_ch_wait_for_endpt(&threads, "second");

    pthread_mutex_lock(&threads.lock);
    tid_count = threads.tid_count;
    pthread_mutex_unlock(&threads.lock);
    assert_int_equal(tid_count, 1);

    lyd_free_all(tree2);
    lyd_free_all(tree);
    pthread_cond_destroy(&threads.cond);
    pthread_mutex_destroy(&threads.lock);
}

/** @brief Number of threads applying the configuration concurrently. */
#define TEST_APPLY_THREAD_COUNT 4

/** @brief Number of configuration updates each applying thread performs. */
#define TEST_APPLY_COUNT 10

struct test_apply_arg {
    struct ln2_test_ctx *test_ctx;
    struct lyd_node *tree;
};

static void *
test_apply_thread(void *arg)
{
    struct test_apply_arg *apply_arg = arg;
    int ret, i;

    for (i = 0; i < TEST_APPLY_COUNT; ++i) {
        ret = nc_server_config_setup_data(apply_arg->tree);
        assert_int_equal(ret, 0);
    }

    return NULL;
}

/**
 * @brief Several threads applying the configuration while a handshake is stalled.
 *
 * Every apply publishes a new configuration generation while the stalled handshake holds a reference
 * to an older one, so the valgrind twin of this test is what actually checks the refcounting.
 */
static void
test_concurrent_apply_and_accept(void **state)
{
    int ret, i;
    pthread_t tids[2 + TEST_APPLY_THREAD_COUNT];
    struct lyd_node *tree = NULL;
    struct ln2_test_ctx *test_ctx = *state;
    struct test_apply_arg apply_arg;

    test_stall_auth_sleep = TEST_STALL_AUTH_SLEEP_SHORT;

    test_create_stall_endpt_data(test_ctx->ctx, "endpt", TEST_PORT, &tree);
    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    apply_arg.test_ctx = test_ctx;
    apply_arg.tree = tree;

    ret = pthread_create(&tids[0], NULL, test_stall_auth_client_thread, test_ctx);
    assert_int_equal(ret, 0);
    ret = pthread_create(&tids[1], NULL, test_stall_auth_server_thread, test_ctx);
    assert_int_equal(ret, 0);

    /* let the key exchange finish, the server is now stalled in the authentication */
    sleep(2);

    for (i = 0; i < TEST_APPLY_THREAD_COUNT; ++i) {
        ret = pthread_create(&tids[2 + i], NULL, test_apply_thread, &apply_arg);
        assert_int_equal(ret, 0);
    }

    for (i = 0; i < 2 + TEST_APPLY_THREAD_COUNT; i++) {
        pthread_join(tids[i], NULL);
    }

    lyd_free_all(tree);
}

static void
test_config_data_free(void *data)
{
    lyd_free_all(data);
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

    /* setup keystore and truststore */
    ret = lyd_parse_data_mem(test_ctx->ctx, keystore_truststore_data, LYD_XML,
            LYD_PARSE_ONLY, 0, &tree);
    assert_int_equal(ret, 0);

    /* add all implicit nodes */
    ret = lyd_new_implicit_tree(tree, LYD_IMPLICIT_NO_STATE, NULL);
    assert_int_equal(ret, 0);

    ret = nc_server_config_setup_data(tree);
    assert_int_equal(ret, 0);

    /* set the base directory for UNIX sockets */
    ret = nc_server_set_unix_socket_dir("/tmp");
    assert_int_equal(ret, 0);

    /* set hidden path for UNIX endpoint */
    ret = nc_server_set_unix_socket_path("unix", "netconf-test-server.sock");
    assert_int_equal(ret, 0);

    test_ctx->test_data = tree;
    test_ctx->free_test_data = test_config_data_free;
    return 0;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_rollback, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_preserve_conn, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_transport_params_oper_get, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_config_all_nodes, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_config_cascade_delete, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_unusupported_asymkey_format, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_diff, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_ordered_list_move, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_ch_dispatch_not_duplicated, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_ch_endpoint_order, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_config_update_during_auth, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_removed_endpt_stops_listening, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_api_setters_during_auth, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_ch_survives_config_swap, setup_f, ln2_glob_test_teardown),
        cmocka_unit_test_setup_teardown(test_concurrent_apply_and_accept, setup_f, ln2_glob_test_teardown),
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
