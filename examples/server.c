/**
 * @file server.c
 * @author Roman Janota <xjanot04@fit.vutbr.cz>
 * @brief libnetconf2 server example
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

#define _GNU_SOURCE
#include "example.h"

#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "log.h"
#include "messages_server.h"
#include "netconf.h"
#include "session_server.h"
#include "session_server_ch.h"

volatile int exit_application = 0;

static void
sigint_handler(int signum)
{
    (void) signum;
    /* notify the main loop if we should exit */
    exit_application = 1;
}

static struct nc_server_reply *
get_rpc(struct lyd_node *rpc, struct nc_session *session)
{
    const struct ly_ctx *ctx;
    const char *xpath;
    struct lyd_node *root = NULL, *root2 = NULL, *duplicate = NULL;
    struct lyd_node *filter, *err;
    struct lyd_meta *m, *type = NULL, *select = NULL;
    struct ly_set *set = NULL;

    ctx = nc_session_get_ctx(session);

    /* load the ietf-yang-library data of the session, which represent this server's state data */
    if (ly_ctx_get_yanglib_data(ctx, &root, "%u", ly_ctx_get_change_count(ctx))) {
        err = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        goto error;
    }

    /* search for the optional filter in the RPC */
    if (lyd_find_path(rpc, "filter", 0, &filter)) {
        err = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        goto error;
    }

    if (filter) {
        /* look for the expected filter attributes type and select */
        LY_LIST_FOR(filter->meta, m) {
            if (!strcmp(m->name, "type")) {
                type = m;
            }
            if (!strcmp(m->name, "select")) {
                select = m;
            }
        }

        /* only XPath filter is supported */
        if (!type || strcmp(lyd_get_meta_value(type), "xpath") || !select) {
            err = nc_err(ctx, NC_ERR_OP_NOT_SUPPORTED, NC_ERR_TYPE_APP);
            goto error;
        }
        xpath = lyd_get_meta_value(select);

        /* find all the subtrees matching the filter */
        if (lyd_find_xpath(root, xpath, &set)) {
            err = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            goto error;
        }

        root2 = NULL;
        for (uint32_t i = 0; i < set->count; i++) {
            /* create a copy of the subtree with its parent nodes */
            if (lyd_dup_single(set->dnodes[i], NULL, LYD_DUP_RECURSIVE | LYD_DUP_WITH_PARENTS, &duplicate)) {
                err = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                goto error;
            }

            /* merge another top-level filtered subtree into the result */
            while (duplicate->parent) {
                duplicate = lyd_parent(duplicate);
            }
            if (lyd_merge_tree(&root2, duplicate, LYD_MERGE_DESTRUCT)) {
                err = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                goto error;
            }
            duplicate = NULL;
        }

        /* replace the original full data with only the filtered data */
        lyd_free_siblings(root);
        root = root2;
        root2 = NULL;
    }

    /* duplicate the rpc node without its input nodes so the output nodes can be appended */
    if (lyd_dup_single(rpc, NULL, 0, &duplicate)) {
        err = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        goto error;
    }

    /* create the get RPC anyxml "data" output node with the requested data */
    if (lyd_new_any(duplicate, NULL, "data", root, 1, LYD_ANYDATA_DATATREE, 1, NULL)) {
        err = nc_err(ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        goto error;
    }

    ly_set_free(set, NULL);

    /* send data reply with the RPC output data */
    return nc_server_reply_data(duplicate, NC_WD_UNKNOWN, NC_PARAMTYPE_FREE);

error:
    ly_set_free(set, NULL);
    lyd_free_siblings(root);
    lyd_free_siblings(duplicate);
    lyd_free_siblings(root2);

    /* send error reply with the specific NETCONF error */
    return nc_server_reply_err(err);
}

static struct nc_server_reply *
glob_rpc(struct lyd_node *rpc, struct nc_session *session)
{
    struct lyd_node *iter;
    struct lyd_meta *m;

    printf("Received RPC:\n");

    /* iterate over all the nodes in the RPC */
    LYD_TREE_DFS_BEGIN(rpc, iter) {
        /* if the node has a value, then print its name and value */
        if (iter->schema->nodetype & (LYD_NODE_TERM | LYD_NODE_ANY)) {
            printf("  %s = \"%s\"\n", LYD_NAME(iter), lyd_get_value(iter));
            /* then iterate through all the metadata, which may include the XPath filter */
            LY_LIST_FOR(iter->meta, m) {
                printf("    %s = \"%s\"\n", m->name, lyd_get_meta_value(m));
            }
            /* else print just the name */
        } else if (iter->schema->nodetype == LYS_RPC) {
            printf("  %s\n", LYD_NAME(iter));
        }

        LYD_TREE_DFS_END(rpc, iter);
    }

    /* if close-session RPC is received, then call library's default function to properly close the session */
    if (!strcmp(LYD_NAME(rpc), "close-session") && !strcmp(lyd_owner_module(rpc)->name, "ietf-netconf")) {
        return nc_clb_default_close_session(rpc, session);
    }

    /* if get-schema RPC is received, then use the library implementation of this RPC */
    if (!strcmp(LYD_NAME(rpc), "get-schema") && !strcmp(lyd_owner_module(rpc)->name, "ietf-netconf-monitoring")) {
        return nc_clb_default_get_schema(rpc, session);
    }

    if (!strcmp(LYD_NAME(rpc), "get") && !strcmp(lyd_owner_module(rpc)->name, "ietf-netconf")) {
        return get_rpc(rpc, session);
    }

    /* return an okay reply to every other RPC */
    return nc_server_reply_ok();
}

static void
help_print()
{
    printf("Example usage:\n"
            "    server -u ./unix_socket\n"
            "\n"
            "    Available options:\n"
            "    -h, --help\t     \tPrint usage help.\n"
            "    -u, --unix\t<path>\tCreate a UNIX socket at the place specified by <path>.\n"
            "    -s, --ssh\t<path>\tCreate a SSH server with the host SSH key located at <path>.\n\n");
}

static int
hostkey_callback(const char *name, void *user_data, char **privkey_path, char **privkey_data, NC_SSH_KEY_TYPE *privkey_type)
{
    /* return only known hostkey */
    if (strcmp(name, "server_hostkey")) {
        return 1;
    }

    /* the hostkey is in a file */
    *privkey_path = strdup(user_data);
    *privkey_data = NULL;
    *privkey_type = NC_SSH_KEY_UNKNOWN;

    return 0;
}

static int
password_callback(const struct nc_session *session, const char *password, void *user_data)
{
    (void) user_data;
    const char *username;

    /* get username from the NETCONF session */
    username = nc_session_get_username(session);

    /* compare it with the defined username and password */
    if (strcmp(username, SSH_USERNAME) || strcmp(password, SSH_PASSWORD)) {
        return 1;
    }

    return 0;
}

static int
init(struct ly_ctx **context, struct nc_pollsession **ps, const char *path, NC_TRANSPORT_IMPL server_type)
{
    struct lys_module *module;
    int rc = 0;
    const char *features[] = {"*", NULL};

    /* initialize the server */
    if (nc_server_init()) {
        ERR_MSG_CLEANUP("Error occurred while initializing the server.\n");
    }

    if (server_type == NC_TI_UNIX) {
        /* add a new UNIX socket endpoint with an arbitrary name main_unix */
        if (nc_server_add_endpt("main_unix", NC_TI_UNIX)) {
            ERR_MSG_CLEANUP("Couldn't add end point.\n");
        }

        /* set endpoint listening address to the path from the parameter */
        if (nc_server_endpt_set_address("main_unix", path)) {
            ERR_MSG_CLEANUP("Couldn't set address of end point.\n");
        }
    } else {
        /* add a new SSH endpoint with an arbitrary name main_ssh */
        if (nc_server_add_endpt("main_ssh", NC_TI_LIBSSH)) {
            ERR_MSG_CLEANUP("Couldn't add end point.\n");
        }

        /* set generic hostkey callback which will be used for retrieving all the hostkeys */
        nc_server_ssh_set_hostkey_clb(hostkey_callback, (void *)path, NULL);

        /* set 'password' SSH authentication callback */
        nc_server_ssh_set_passwd_auth_clb(password_callback, NULL, NULL);

        /* add a new hostkey called server_hostkey, whose data will be retrieved by the hostkey callback */
        nc_server_ssh_endpt_add_hostkey("main_ssh", "server_hostkey", -1);

        /* set endpoint listening address to the defined IP address */
        if (nc_server_endpt_set_address("main_ssh", SSH_ADDRESS)) {
            ERR_MSG_CLEANUP("Couldn't set address of end point.\n");
        }

        /* set endpoint listening port to the defined one */
        if (nc_server_endpt_set_port("main_ssh", SSH_PORT)) {
            ERR_MSG_CLEANUP("Couldn't set port of end point.\n");
        }

        /* allow only 'password' SSH authentication method for the endpoint */
        if (nc_server_ssh_endpt_set_auth_methods("main_ssh", NC_SSH_AUTH_PASSWORD)) {
            ERR_MSG_CLEANUP("Couldn't set authentication methods of end point.\n");
        }
    }

    /* create a libyang context that will determine which YANG modules will be supported by the server */
    if (ly_ctx_new(MODULES_DIR, 0, context)) {
        ERR_MSG_CLEANUP("Couldn't create new libyang context.\n");
    }

    /* support and load the base NETCONF ietf-netconf module with all its features enabled */
    module = ly_ctx_load_module(*context, "ietf-netconf", NULL, features);
    if (!module) {
        ERR_MSG_CLEANUP("Couldn't load ietf-netconf module.\n");
    }

    /* support get-schema RPC for the server to be able to send YANG modules */
    module = ly_ctx_load_module(*context, "ietf-netconf-monitoring", NULL, features);
    if (!module) {
        ERR_MSG_CLEANUP("Couldn't load ietf-netconf-monitoring module.\n");
    }

    /* create a new poll session structure, which is used for polling RPCs sent by clients */
    *ps = nc_ps_new();
    if (!*ps) {
        ERR_MSG_CLEANUP("Couldn't create a poll session\n");
    }

    /* set the global RPC callback, which is called every time a new RPC is received */
    nc_set_global_rpc_clb(glob_rpc);

    /* upon receiving SIGINT the handler will notify the program that is should terminate */
    signal(SIGINT, sigint_handler);

cleanup:
    return rc;
}

int
main(int argc, char **argv)
{
    int r, opt, no_new_sessions, rc = 0;
    struct ly_ctx *context = NULL;
    struct nc_session *session, *new_session;
    struct nc_pollsession *ps = NULL;
    const char *unix_socket_path = NULL, *ssh_public_key_path = NULL;

    struct option options[] = {
        {"help",    no_argument,        NULL, 'h'},
        {"unix",    required_argument,  NULL, 'u'},
        {"ssh",     required_argument,  NULL, 's'},
        {"debug",   no_argument,        NULL, 'd'},
        {NULL,      0,                  NULL,  0}
    };

    if (argc == 1) {
        help_print();
        goto cleanup;
    }

    opterr = 0;

    while ((opt = getopt_long(argc, argv, "hu:s:d", options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            help_print();
            goto cleanup;

        case 'u':
            unix_socket_path = optarg;
            if (init(&context, &ps, unix_socket_path, NC_TI_UNIX)) {
                ERR_MSG_CLEANUP("Failed to initialize a UNIX socket\n");
            }
            printf("Using UNIX socket!\n");
            break;

        case 's':
            ssh_public_key_path = optarg;
            if (init(&context, &ps, ssh_public_key_path, NC_TI_LIBSSH)) {
                ERR_MSG_CLEANUP("Failed to initialize a SSH server\n");
            }
            printf("Using SSH!\n");
            break;

        case 'd':
            nc_verbosity(NC_VERB_DEBUG);
            break;

        default:
            ERR_MSG_CLEANUP("Invalid option or missing argument\n");
        }
    }

    while (!exit_application) {
        no_new_sessions = 0;

        /* try to accept new NETCONF sessions on all configured endpoints */
        r = nc_accept(0, context, &session);

        switch (r) {

        /* session accepted and its hello message received */
        case NC_MSG_HELLO:
            printf("Connection established\n");

            /* add the new session to the poll structure */
            if (nc_ps_add_session(ps, session)) {
                ERR_MSG_CLEANUP("Couldn't add session to poll\n");
            }
            break;

        /* there were no new sessions */
        case NC_MSG_WOULDBLOCK:
            no_new_sessions = 1;
            break;

        /* session accepted, but its hello message was invalid */
        case NC_MSG_BAD_HELLO:
            printf("Parsing client hello message error.\n");
            break;

        /* something else went wrong */
        case NC_MSG_ERROR:
            /* accepting a session failed, but the server should continue handling RPCs on established sessions */
            printf("Error while accepting a hello message.\n");
            rc = 1;
            break;
        }

        /* poll all the sessions in the structure and process a single event on a session which is then returned,
         * in case it is a new RPC then the global RPC callback is also called */
        r = nc_ps_poll(ps, 0, &new_session);

        /* a fatal error occurred */
        if (r & NC_PSPOLL_ERROR) {
            ERR_MSG_CLEANUP("Error polling RPCs\n");
        }

        /* a session was terminated, so remove it from the ps structure and free it */
        if (r & NC_PSPOLL_SESSION_TERM) {
            r = nc_ps_del_session(ps, new_session);
            assert(!r);
            nc_session_free(new_session, NULL);
        }

        /* there were no new sessions and no new events on any established sessions,
         * prevent active waiting by sleeping for a short period of time */
        if (no_new_sessions && (r & (NC_PSPOLL_TIMEOUT | NC_PSPOLL_NOSESSIONS))) {
            usleep(BACKOFF_TIMEOUT_USECS);
        }

        /* other set bits of the return value of nc_ps_poll() are not interesting in this example */
    }

cleanup:
    /* free all the remaining sessions in the ps structure before destroying the context */
    if (ps) {
        nc_ps_clear(ps, 1, NULL);
    }
    nc_ps_free(ps);
    nc_server_destroy();
    ly_ctx_destroy(context);
    return rc;
}
