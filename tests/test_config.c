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

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    /* set hidden path for UNIX endpoint */
    ret = nc_server_set_unix_socket_path("unix", "/tmp/netconf-test-server.sock");
    assert_int_equal(ret, 0);

    lyd_free_all(tree);
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
        cmocka_unit_test_setup_teardown(test_unusupported_asymkey_format, setup_f, ln2_glob_test_teardown),
    };

    /* try to get ports from the environment, otherwise use the default */
    if (ln2_glob_test_get_ports(1, &TEST_PORT, &TEST_PORT_STR)) {
        return 1;
    }

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    return cmocka_run_group_tests(tests, NULL, NULL);
}
