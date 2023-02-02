/**
 * @file test_pam.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 Linux PAM keyboard-interactive authentication test
 *
 * @copyright
 * Copyright (c) 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>
#include <log.h>
#include <session_client.h>
#include <session_server.h>
#include "config_server.h"

#include "tests/config.h"

#define nc_assert(cond) if (!(cond)) { fprintf(stderr, "assert failed (%s:%d)\n", __FILE__, __LINE__); abort(); }

#define NC_ACCEPT_TIMEOUT 5000
#define NC_PS_POLL_TIMEOUT 5000

const char *data =
        "<netconf-server xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-server\" xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" yang:operation=\"none\">"
        "<listen yang:operation=\"create\">"
        "<idle-timeout>10</idle-timeout>"
        "<endpoint>"
        "<name>default-ssh</name>"
        "<ssh>"
        "<tcp-server-parameters>"
        "<local-address>127.0.0.1</local-address>"
        "<local-port>10005</local-port>"
        "</tcp-server-parameters>"
        "<ssh-server-parameters>"
        "<server-identity>"
        "<host-key>"
        "<name>key</name>"
        "<public-key>"
        "<local-definition>"
        "<public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>"
        "<public-key>MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6ojtjfDmvyQP1ZkIwBpr"
        "97eKDuebvpoglRHRdvVuTpf/gU1VArAQmwGh05i6lm8TkVl1noMlIxLJDcWslaeV"
        "n6KyvsX0HhsQtXwqPqwka5UCv6alwf/ivAvcNpcX1j0t/uIGCI4dSiKnzQCyf0FT"
        "irzQkjrDZUd3meDhNQTruCalGV4gfNWIq3e1oGuwAn1tLlu9oTrE4HzMpgbNEU6w"
        "NmsSqpwGxUhYLoSaM7b0dLmqP+ZczSS0Uac0PFNkehGQ2CYIT80f580o4XGtoLCU"
        "UGkp6YCTL4Z2CeBEaJABWjDIDH+dKYIUBqUpz4Th12gXAP+h+3qI6+9eppeHrfrz"
        "ARDsfLjwUNxQJse1QSArjAytf0FKtGHrORc7W0TiCFvR0zaoUNLTKk7enTiRQ9rf"
        "WZOAu44fUvPCaXDE6zXXeaVgoKCo4VHlho36erUcjlEBM+jk28IykbZGtBb6igKv"
        "Ya1tPSgeYm/zJoFVjQcnr14uci/ft1+Na+hOIEoEEiKxcAPk2b2vBKNlRIW7WLJ3"
        "u7ZiuQEJTNm6+3cE4+lfwaBCBqBToE+dpzvoUXoMyFFReUFd1O5axu4fXgt00jMa"
        "OQxmE0v9OmR/pL/PWIflVF4Zz5yVONYaDVc7l+veY0oEZruEPJ0hlEgxuCzLrcMh"
        "jufl2qE2Q7fQIaav/1NqBVkCAwEAAQ==</public-key>"
        "<private-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:rsa-private-key-format</private-key-format>"
        "<cleartext-private-key>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</cleartext-private-key>"
        "</local-definition>"
        "</public-key>"
        "</host-key>"
        "</server-identity>"
        "<client-authentication>"
        "<users>"
        "<user>"
        "<name>test</name>"
        "<public-keys>"
        "<local-definition>"
        "<public-key>"
        "<name>client</name>"
        "<public-key-format xmlns:ct=\"urn:ietf:params:xml:ns:yang:ietf-crypto-types\">ct:ssh-public-key-format</public-key-format>"
        "<public-key>MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvpKj6gy/Rm1pqlUIaeKp"
        "WuL2KOJBbodhxuPG+0S6f+Jf4LopOB76tmg1RQ/bAXLNxXkG46Cx9UOHaFK/Ixul"
        "cCbH6LxOUg90/HVS7NnbaVtDsl03HG9CPZTlQzM+n+iFAXv5ub5PFzW3VCCNDSfM"
        "tXUOdVR93u/OAc7uz0nWjGhWnOH5MPJCQPS8ZFpL9hQxQuyAXFY0YLW/9eRMDgx/"
        "OPTuvlTxIF+YHaMzY+Wy+Oaygwb78dCow+3RQRgCB20o5o6exx2nX2Cqr7UJzG/N"
        "30XCusKIcTT978td8AU7UjpbzoNehm/tmQdDq+8IDsNfWbxCHDYLMD8IR32UDXGD"
        "DVSwrtNgUs8HWNNCBKjTNCeQf1v/yiRd7hRf2aj+w9sDu8PI+VC9pabsRe2KxnnD"
        "U9Sq+4IB3ZM3C5XpJDbu8DVigGZSevim7p/D6mW2phlyxtlK9WmQ5Misg/Z8jM7E"
        "Z3gJcTvh20IS6I4plG7DJvsIC/Pc3IS2JC/w0prCZa8gOKob8x2mjjQcOA1eVIUm"
        "yw6WbV1X65/jAJvIS6an/oFAk4bBTfJA6fYfU4Pb9NWovYxm/eNR5BbRmFFh0uXa"
        "0s92S50iOotf8CnW7PZ7PWKgzKqtnN9Ob+Ye7WjDdG+NCrhkiDBOCuHDrHXwqaxW"
        "BmUICo2mnUMK7JuJNSZe5DMCAwEAAQ==</public-key>"
        "</public-key>"
        "</local-definition>"
        "</public-keys>"
        "<none/>"
        "</user>"
        "</users>"
        "</client-authentication>"
        "<transport-params>"
        "<host-key>"
        "<host-key-alg xmlns:sshpka=\"urn:ietf:params:xml:ns:yang:iana-ssh-public-key-algs\">sshpka:ssh-rsa</host-key-alg>"
        "<host-key-alg xmlns:sshpka=\"urn:ietf:params:xml:ns:yang:iana-ssh-public-key-algs\">sshpka:rsa-sha2-512</host-key-alg>"
        "</host-key>"
        "<key-exchange>"
        "<key-exchange-alg xmlns:sshkea=\"urn:ietf:params:xml:ns:yang:iana-ssh-key-exchange-algs\">sshkea:diffie-hellman-group18-sha512</key-exchange-alg>"
        "</key-exchange>"
        "<encryption>"
        "<encryption-alg xmlns:sshea=\"urn:ietf:params:xml:ns:yang:iana-ssh-encryption-algs\">sshea:aes256-cbc</encryption-alg>"
        "</encryption>"
        "<mac>"
        "<mac-alg xmlns:sshma=\"urn:ietf:params:xml:ns:yang:iana-ssh-mac-algs\">sshma:hmac-sha1</mac-alg>"
        "</mac>"
        "</transport-params>"
        "</ssh-server-parameters>"
        "</ssh>"
        "</endpoint>"
        "</listen>"
        "</netconf-server>";

static int
setup(struct ly_ctx *ctx)
{
    int i;
    const char *all_features[] = {"*", NULL};
    /* no ssh-x509-certs */
    const char *ssh_common_features[] = {"transport-params", "public-key-generation", NULL};
    /* no ssh-server-keepalives and local-user-auth-hostbased */
    const char *ssh_server_features[] = {"local-users-supported", "local-user-auth-publickey", "local-user-auth-password", "local-user-auth-none", NULL};
    /* no private-key-encryption and csr-generation */
    const char *crypto_types_features[] = {
        "one-symmetric-key-format", "one-asymmetric-key-format", "symmetrically-encrypted-value-format",
        "asymmetrically-encrypted-value-format", "cms-enveloped-data-format", "cms-encrypted-data-format",
        "p10-based-csrs", "certificate-expiration-notification", "hidden-keys", "password-encryption",
        "symmetric-key-encryption", NULL
    };

    const char *module_names[] = {
        "ietf-netconf-server", "ietf-tls-common", "ietf-tls-server", "ietf-truststore", "iana-crypt-hash", "ietf-keystore",
        "ietf-tcp-server", "ietf-tcp-common", "ietf-tcp-client", "iana-ssh-public-key-algs",
        "iana-ssh-key-exchange-algs", "iana-ssh-encryption-algs", "iana-ssh-mac-algs", NULL
    };

    for (i = 0; module_names[i] != NULL; i++) {
        if (!ly_ctx_load_module(ctx, module_names[i], NULL, all_features)) {
            fprintf(stderr, "Loading module (%s) failed.\n", module_names[i]);
            goto error;
        }
    }

    if (!ly_ctx_load_module(ctx, "ietf-ssh-common", NULL, ssh_common_features)) {
        fprintf(stderr, "Loading module (ietf-ssh-common) failed.\n");
        goto error;
    }
    if (!ly_ctx_load_module(ctx, "ietf-ssh-server", NULL, ssh_server_features)) {
        fprintf(stderr, "Loading module (ietf-ssh-server) failed.\n");
        goto error;
    }
    if (!ly_ctx_load_module(ctx, "ietf-crypto-types", NULL, crypto_types_features)) {
        fprintf(stderr, "Loading module (ietf-crypto-types) failed.\n");
        goto error;
    }

    return 0;

error:
    return 1;
}

int
main(void)
{
    int ret;
    struct ly_ctx *ctx;
    struct lyd_node *tree;

    nc_verbosity(NC_VERB_VERBOSE);

    ret = ly_ctx_new("/home/roman/Downloads/yang", 0, &ctx);
    nc_assert(!ret);

    ret = setup(ctx);
    nc_assert(!ret);

    ret = lyd_parse_data_mem(ctx, data, LYD_XML, LYD_PARSE_NO_STATE | LYD_PARSE_STRICT, LYD_VALIDATE_NO_STATE, &tree);
    nc_assert(!ret);

    ret = nc_server_config_setup(tree);
    nc_assert(!ret);

    nc_server_init();

    nc_server_destroy();
    lyd_free_all(tree);
    ly_ctx_destroy(ctx);
    return 0;
}
