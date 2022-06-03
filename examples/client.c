/**
 * @file client.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 client example
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

#include "example.h"

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "log.h"
#include "messages_client.h"
#include "netconf.h"
#include "session_client.h"
#include "session_client_ch.h"

static void
help_print()
{
    printf("Example usage:\n"
            "    client -u ./unix_socket get\n"
            "\n"
            "    Available options:\n"
            "    -h, --help\t     \tPrint usage help.\n"
            "    -u, --unix\t<path>\tConnect to a UNIX socket at the place specified by <path>.\n"
            "    -s, --ssh\t\tConnect to a SSH server.\n\n"
            "    Available RPCs:\n"
            "    get [xpath-filter]\t\t\t\t\t send a <get> RPC with optional XPath filter\n"
            "    get-config [datastore] [xpath-filter]\t\t send a <get-config> RPC with optional XPath filter and datastore, the default datastore is \"running\" \n\n");
}

static enum NC_DATASTORE_TYPE
string2datastore(const char *str)
{
    if (!str) {
        return NC_DATASTORE_RUNNING;
    }

    if (!strcmp(str, "candidate")) {
        return NC_DATASTORE_CANDIDATE;
    } else if (!strcmp(str, "running")) {
        return NC_DATASTORE_RUNNING;
    } else if (!strcmp(str, "startup")) {
        return NC_DATASTORE_STARTUP;
    } else {
        return 0;
    }
}

static int
send_rpc(struct nc_session *session, NC_RPC_TYPE rpc_type, const char *param1, const char *param2)
{
    enum NC_DATASTORE_TYPE datastore;
    int r = 0, rc = 0;
    uint64_t msg_id = 0;
    struct lyd_node *envp = NULL, *op = NULL;
    struct nc_rpc *rpc = NULL;

    /* decide which type of RPC to send */
    switch (rpc_type) {
    case NC_RPC_GET:
        /* create get RPC with an optional filter */
        rpc = nc_rpc_get(param1, NC_WD_UNKNOWN, NC_PARAMTYPE_CONST);
        break;

    case NC_RPC_GETCONFIG:
        /* create get-config RPC with a source datastore and an optional filter */
        datastore = string2datastore(param1);
        if (!datastore) {
            ERR_MSG_CLEANUP("Invalid name of a datastore. Use candidate, running, startup or neither.\n");
        }
        rpc = nc_rpc_getconfig(datastore, param2, NC_WD_UNKNOWN, NC_PARAMTYPE_CONST);
        break;

    default:
        break;
    }
    if (!rpc) {
        ERR_MSG_CLEANUP("Error while creating a RPC\n");
    }

    /* send the RPC on the session and remember NETCONF message ID */
    r = nc_send_rpc(session, rpc, 100, &msg_id);
    if (r != NC_MSG_RPC) {
        ERR_MSG_CLEANUP("Couldn't send a RPC\n");
    }

    /* receive the server's reply with the expected message ID
     * as separate rpc-reply NETCONF envelopes and the parsed YANG output itself, if any */
    r = nc_recv_reply(session, rpc, msg_id, 100, &envp, &op);
    if (r != NC_MSG_REPLY) {
        ERR_MSG_CLEANUP("Couldn't receive a reply from the server\n");
    }

    /* print the whole reply */
    if (!op) {
        r = lyd_print_file(stdout, envp, LYD_XML, 0);
    } else {
        r = lyd_print_file(stdout, op, LYD_XML, 0);
        if (r) {
            ERR_MSG_CLEANUP("Couldn't print the RPC to stdout\n");
        }
        r = lyd_print_file(stdout, envp, LYD_XML, 0);
    }
    if (r) {
        ERR_MSG_CLEANUP("Couldn't print the RPC to stdout\n");
    }

cleanup:
    lyd_free_all(envp);
    lyd_free_all(op);
    nc_rpc_free(rpc);
    return rc;
}

int
main(int argc, char **argv)
{
    int rc = 0, opt, connection_type = NONE;
    struct nc_session *session = NULL;
    const char *unix_socket_path = NULL, *rpc_parameter_1 = NULL, *rpc_parameter_2 = NULL;

    struct option options[] = {
        {"help",    no_argument,        NULL, 'h'},
        {"unix",    required_argument,  NULL, 'u'},
        {"ssh",     no_argument,                NULL, 's'},
        {"debug",   no_argument,        NULL, 'd'},
        {NULL,      0,                  NULL,  0}
    };

    if (argc == 1) {
        help_print();
        goto cleanup;
    }

    nc_client_init();
    /* set the path to search for schemas */
    nc_client_set_schema_searchpath(MODULES_DIR);

    opterr = 0;

    while ((opt = getopt_long(argc, argv, "hu:sd", options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            help_print();
            goto cleanup;

        case 'u':
            unix_socket_path = optarg;
            connection_type = UNIX;
            break;

        case 's':
            connection_type = SSH;
            /* set the client SSH username to always be used when connecting to the server */
            if (nc_client_ssh_set_username(SSH_USERNAME)) {
                ERR_MSG_CLEANUP("Couldn't set the SSH username\n");
            }
            break;

        case 'd':
            nc_verbosity(NC_VERB_DEBUG);
            break;

        default:
            ERR_MSG_CLEANUP("Invalid option or missing argument\n");
        }
    }

    if (optind == argc) {
        ERR_MSG_CLEANUP("Expected the name of RPC after options\n");
    }

    /* connect to the server using the specified transport protocol */
    switch (connection_type) {
    case UNIX:
        session = nc_connect_unix(unix_socket_path, NULL);
        break;

    case SSH:
        session = nc_connect_ssh(SSH_ADDRESS, SSH_PORT, NULL);
        break;

    case NONE:
        ERR_MSG_CLEANUP("Expected connection type (either SSH or UNIX)!\n");
    }
    if (!session) {
        ERR_MSG_CLEANUP("Couldn't connect to the server\n");
    }

    /* sending a get RPC */
    if (!strcmp(argv[optind], "get")) {
        if (optind + 1 < argc) {
            /* use the specified XPath filter */
            rpc_parameter_1 = argv[optind + 1];
        }
        if (send_rpc(session, NC_RPC_GET, rpc_parameter_1, rpc_parameter_2)) {
            rc = 1;
            goto cleanup;
        }
        /* sending a get-config RPC */
    } else if (!strcmp(argv[optind], "get-config")) {
        /* use the specified datastore and optional XPath filter */
        if (optind + 2 < argc) {
            rpc_parameter_1 = argv[optind + 1];
            rpc_parameter_2 = argv[optind + 2];
        } else if (optind + 1 < argc) {
            rpc_parameter_1 = argv[optind + 1];
        }
        if (send_rpc(session, NC_RPC_GETCONFIG, rpc_parameter_1, rpc_parameter_2)) {
            rc = 1;
            goto cleanup;
        }
    } else {
        ERR_MSG_CLEANUP("Invalid name of a RPC\n");
    }

cleanup:
    nc_session_free(session, NULL);
    nc_client_destroy();
    return rc;
}
