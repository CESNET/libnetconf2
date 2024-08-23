/**
 * @file server_config.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server configuration functions
 *
 * @copyright
 * Copyright (c) 2022-2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <libyang/tree_data.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "server_config.h"
#include "server_config_p.h"
#include "session_p.h"

extern struct nc_server_opts server_opts;

/* returns a parent node of 'node' that matches the name 'name' */
static const struct lyd_node *
nc_server_config_get_parent(const struct lyd_node *node, const char *name)
{
    NC_CHECK_ARG_RET(NULL, node, name, NULL);

    while (node) {
        if (!strcmp(LYD_NAME(node), name)) {
            return node;
        }
        node = lyd_parent(node);
    }

    return NULL;
}

/* returns a parent list node of 'node' that matches the name 'name' */
static const struct lyd_node *
nc_server_config_get_parent_list(const struct lyd_node *node, const char *name)
{
    NC_CHECK_ARG_RET(NULL, node, name, NULL);

    while (node) {
        /* check if the node is a list and its name matches the param */
        if ((node->schema->nodetype == LYS_LIST) && (!strcmp(LYD_NAME(node), name))) {
            return node;
        }
        node = lyd_parent(node);
    }

    return NULL;
}

/* returns the key of a list node with the name 'name' */
static const char *
nc_server_config_get_parent_list_key_value(const struct lyd_node *node, const char *name, const char *key_name)
{
    const char *original_name;

    NC_CHECK_ARG_RET(NULL, node, name, key_name, NULL);
    original_name = LYD_NAME(node);

    /* get the supposed parent list */
    node = nc_server_config_get_parent_list(node, name);
    if (!node) {
        ERR(NULL, "Node \"%s\" not contained in \"%s\" subtree.", original_name, name);
        return NULL;
    }

    /* child should be the key */
    node = lyd_child(node);
    if (!node) {
        ERR(NULL, "Node \"%s\" has no child nodes.", name);
        return NULL;
    }
    if (strcmp(LYD_NAME(node), key_name)) {
        ERR(NULL, "Node \"%s\" child names mismatch (found:\"%s\", expected:\"%s\").", original_name, LYD_NAME(node), key_name);
        return NULL;
    }

    return lyd_get_value(node);
}

/* returns true if a node is a part of the listen subtree */
static int
is_listen(const struct lyd_node *node)
{
    node = nc_server_config_get_parent(node, "listen");
    return node != NULL;
}

/* returns true if a node is a part of the Call Home subtree */
static int
is_ch(const struct lyd_node *node)
{
    node = nc_server_config_get_parent(node, "call-home");
    return node != NULL;
}

#ifdef NC_ENABLED_SSH_TLS

/* returns true if a node is a part of the ssh subtree */
static int
is_ssh(const struct lyd_node *node)
{
    node = nc_server_config_get_parent(node, "ssh");
    return node != NULL;
}

/* returns true if a node is a part of the tls subtree */
static int
is_tls(const struct lyd_node *node)
{
    node = nc_server_config_get_parent(node, "tls");
    return node != NULL;
}

#endif /* NC_ENABLED_SSH_TLS */

/* gets the endpoint struct (and optionally bind) based on node's location in the YANG data tree */
static int
nc_server_config_get_endpt(const struct lyd_node *node, struct nc_endpt **endpt, struct nc_bind **bind)
{
    uint16_t i;
    const char *name;

    NC_CHECK_ARG_RET(NULL, node, endpt, 1);

    name = nc_server_config_get_parent_list_key_value(node, "endpoint", "name");
    if (!name) {
        return 1;
    }

    for (i = 0; i < server_opts.endpt_count; i++) {
        if (!strcmp(server_opts.endpts[i].name, name)) {
            *endpt = &server_opts.endpts[i];
            if (bind) {
                *bind = &server_opts.binds[i];
            }
            return 0;
        }
    }

    ERR(NULL, "Endpoint \"%s\" was not found.", name);
    return 1;
}

/* gets the ch_client struct based on node's location in the YANG data tree
 * THE ch_client_lock HAS TO BE LOCKED PRIOR TO CALLING THIS
 */
static int
nc_server_config_get_ch_client(const struct lyd_node *node, struct nc_ch_client **ch_client)
{
    uint16_t i;
    const char *name;

    NC_CHECK_ARG_RET(NULL, node, ch_client, 1);

    name = nc_server_config_get_parent_list_key_value(node, "netconf-client", "name");
    if (!name) {
        return 1;
    }

    for (i = 0; i < server_opts.ch_client_count; i++) {
        if (!strcmp(server_opts.ch_clients[i].name, name)) {
            *ch_client = &server_opts.ch_clients[i];
            return 0;
        }
    }

    ERR(NULL, "Call-home client \"%s\" was not found.", name);
    return 1;
}

/* gets the ch_endpt struct based on node's location in the YANG data tree,
 * ch_client has to be locked
 */
static int
nc_server_config_get_ch_endpt(const struct lyd_node *node, const struct nc_ch_client *ch_client,
        struct nc_ch_endpt **ch_endpt)
{
    uint16_t i;
    const char *name;

    NC_CHECK_ARG_RET(NULL, node, ch_client, ch_endpt, 1);

    name = nc_server_config_get_parent_list_key_value(node, "endpoint", "name");
    if (!name) {
        return 1;
    }

    for (i = 0; i < ch_client->ch_endpt_count; i++) {
        if (!strcmp(ch_client->ch_endpts[i].name, name)) {
            *ch_endpt = &ch_client->ch_endpts[i];
            return 0;
        }
    }

    ERR(NULL, "Call-home client's \"%s\" endpoint \"%s\" was not found.", ch_client->name, name);
    return 1;
}

#ifdef NC_ENABLED_SSH_TLS

/* gets the ssh_opts struct based on node's location in the YANG data tree */
static int
nc_server_config_get_ssh_opts(const struct lyd_node *node, const struct nc_ch_client *ch_client,
        struct nc_server_ssh_opts **opts)
{
    struct nc_endpt *endpt;
    struct nc_ch_endpt *ch_endpt;

    NC_CHECK_ARG_RET(NULL, node, opts, 1);

    if (is_listen(node)) {
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            return 1;
        }
        *opts = endpt->opts.ssh;
    } else {
        if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
            return 1;
        }
        *opts = ch_endpt->opts.ssh;
    }

    return 0;
}

/* gets the hostkey struct based on node's location in the YANG data tree */
static int
nc_server_config_get_hostkey(const struct lyd_node *node, const struct nc_ch_client *ch_client,
        struct nc_hostkey **hostkey)
{
    uint16_t i;
    const char *name;
    struct nc_server_ssh_opts *opts;

    NC_CHECK_ARG_RET(NULL, node, hostkey, 1);

    if (nc_server_config_get_ssh_opts(node, ch_client, &opts)) {
        return 1;
    }

    name = nc_server_config_get_parent_list_key_value(node, "host-key", "name");
    if (!name) {
        return 1;
    }

    for (i = 0; i < opts->hostkey_count; i++) {
        if (!strcmp(opts->hostkeys[i].name, name)) {
            *hostkey = &opts->hostkeys[i];
            return 0;
        }
    }

    ERR(NULL, "Host-key \"%s\" was not found.", name);
    return 1;
}

/* gets the client_auth struct based on node's location in the YANG data tree */
static int
nc_server_config_get_auth_client(const struct lyd_node *node, const struct nc_ch_client *ch_client,
        struct nc_auth_client **auth_client)
{
    uint16_t i;
    const char *name;
    struct nc_server_ssh_opts *opts;

    NC_CHECK_ARG_RET(NULL, node, auth_client, 1);

    if (nc_server_config_get_ssh_opts(node, ch_client, &opts)) {
        return 1;
    }

    name = nc_server_config_get_parent_list_key_value(node, "user", "name");
    if (!name) {
        return 1;
    }

    for (i = 0; i < opts->client_count; i++) {
        if (!strcmp(opts->auth_clients[i].username, name)) {
            *auth_client = &opts->auth_clients[i];
            return 0;
        }
    }

    ERR(NULL, "Authorized key \"%s\" was not found.", name);
    return 1;
}

/* gets the pubkey struct based on node's location in the YANG data tree */
static int
nc_server_config_get_pubkey(const struct lyd_node *node, const struct nc_ch_client *ch_client,
        struct nc_public_key **pubkey)
{
    uint16_t i;
    const char *name;
    struct nc_auth_client *auth_client;

    NC_CHECK_ARG_RET(NULL, node, pubkey, 1);

    if (nc_server_config_get_auth_client(node, ch_client, &auth_client)) {
        return 1;
    }

    name = nc_server_config_get_parent_list_key_value(node, "public-key", "name");
    if (!name) {
        return 1;
    }

    for (i = 0; i < auth_client->pubkey_count; i++) {
        if (!strcmp(auth_client->pubkeys[i].name, name)) {
            *pubkey = &auth_client->pubkeys[i];
            return 0;
        }
    }

    ERR(NULL, "Public key \"%s\" was not found.", name);
    return 1;
}

/* gets the tls_opts struct based on node's location in the YANG data tree */
static int
nc_server_config_get_tls_opts(const struct lyd_node *node, const struct nc_ch_client *ch_client,
        struct nc_server_tls_opts **opts)
{
    struct nc_endpt *endpt;
    struct nc_ch_endpt *ch_endpt;

    NC_CHECK_ARG_RET(NULL, node, opts, 1);

    if (is_listen(node)) {
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            return 1;
        }
        *opts = endpt->opts.tls;
    } else {
        if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
            return 1;
        }
        *opts = ch_endpt->opts.tls;
    }

    return 0;
}

/* gets the cert struct based on node's location in the YANG data tree */
static int
nc_server_config_get_cert(const struct lyd_node *node, const struct nc_ch_client *ch_client,
        struct nc_certificate **cert)
{
    uint16_t i;
    const char *name;
    struct nc_cert_grouping *certs;
    struct nc_server_tls_opts *opts;
    int is_cert_end_entity;
    const struct lyd_node *tmp;

    NC_CHECK_ARG_RET(NULL, node, cert, 1);

    if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
        return 1;
    }

    name = nc_server_config_get_parent_list_key_value(node, "certificate", "name");
    if (!name) {
        return 1;
    }

    /* it's in certificate subtree, now check if it's end entity or certificate authority */
    tmp = nc_server_config_get_parent(node, "ee-certs");
    if (tmp) {
        is_cert_end_entity = 1;
    } else {
        tmp = nc_server_config_get_parent(node, "ca-certs");
        if (!tmp) {
            ERR(NULL, "Node \"%s\" is not contained in ee-certs nor ca-certs subtree.", name);
            return 1;
        }
        is_cert_end_entity = 0;
    }

    /* get the right cert stack, either ee or ca */
    if (is_cert_end_entity) {
        certs = &opts->ee_certs;
    } else {
        certs = &opts->ca_certs;
    }

    for (i = 0; i < certs->cert_count; i++) {
        if (!strcmp(certs->certs[i].name, name)) {
            *cert = &certs->certs[i];
            return 0;
        }
    }

    ERR(NULL, "%s certificate \"%s\" was not found.", is_cert_end_entity ? "End-entity" : "Certificate authority", name);
    return 1;
}

/* gets the ctn struct based on node's location in the YANG data tree */
static int
nc_server_config_get_ctn(const struct lyd_node *node, const struct nc_ch_client *ch_client,
        struct nc_ctn **ctn)
{
    uint32_t id;
    struct nc_ctn *iter;
    struct nc_server_tls_opts *opts;
    const char *name;

    NC_CHECK_ARG_RET(NULL, node, ctn, 1);

    if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
        return 1;
    }

    name = LYD_NAME(node);
    node = nc_server_config_get_parent_list(node, "cert-to-name");
    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in a cert-to-name subtree.", name);
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "id"));
    id = ((struct lyd_node_term *)node)->value.uint32;

    iter = opts->ctn;
    while (iter) {
        if (iter->id == id) {
            *ctn = iter;
            return 0;
        }

        iter = iter->next;
    }

    ERR(NULL, "Cert-to-name entry with id \"%d\" was not found.", id);
    return 1;
}

NC_PRIVKEY_FORMAT
nc_server_config_get_private_key_type(const char *format)
{
    if (!strcmp(format, "rsa-private-key-format")) {
        return NC_PRIVKEY_FORMAT_RSA;
    } else if (!strcmp(format, "ec-private-key-format")) {
        return NC_PRIVKEY_FORMAT_EC;
    } else if (!strcmp(format, "private-key-info-format")) {
        return NC_PRIVKEY_FORMAT_X509;
    } else if (!strcmp(format, "openssh-private-key-format")) {
        return NC_PRIVKEY_FORMAT_OPENSSH;
    } else {
        ERR(NULL, "Private key format (%s) not supported.", format);
        return NC_PRIVKEY_FORMAT_UNKNOWN;
    }
}

#endif /* NC_ENABLED_SSH_TLS */

/* gets the ch_client struct based on node's location in the YANG data tree and locks it for reading */
static int
nc_server_config_get_ch_client_with_lock(const struct lyd_node *node, struct nc_ch_client **ch_client)
{
    uint16_t i;
    const char *name;

    NC_CHECK_ARG_RET(NULL, node, ch_client, 1);

    name = nc_server_config_get_parent_list_key_value(node, "netconf-client", "name");
    if (!name) {
        return 1;
    }

    /* LOCK */
    pthread_rwlock_rdlock(&server_opts.ch_client_lock);
    for (i = 0; i < server_opts.ch_client_count; i++) {
        if (!strcmp(server_opts.ch_clients[i].name, name)) {
            /* LOCK */
            pthread_mutex_lock(&server_opts.ch_clients[i].lock);
            *ch_client = &server_opts.ch_clients[i];
            return 0;
        }
    }

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);
    ERR(NULL, "Call-home client \"%s\" was not found.", name);
    return 1;
}

static void
nc_ch_client_unlock(struct nc_ch_client *client)
{
    assert(client);

    pthread_mutex_unlock(&client->lock);
    pthread_rwlock_unlock(&server_opts.ch_client_lock);
}

int
equal_parent_name(const struct lyd_node *node, uint16_t parent_count, const char *parent_name)
{
    uint16_t i;

    assert(node && parent_count && parent_name);

    node = lyd_parent(node);
    for (i = 1; i < parent_count; i++) {
        node = lyd_parent(node);
    }

    if (!strcmp(LYD_NAME(node), parent_name)) {
        return 1;
    }

    return 0;
}

int
nc_server_config_realloc(const char *key_value, void **ptr, size_t size, uint16_t *count)
{
    int ret = 0;
    void *tmp;
    char **name;

    tmp = realloc(*ptr, (*count + 1) * size);
    NC_CHECK_ERRMEM_GOTO(!tmp, ret = 1, cleanup);
    *ptr = tmp;

    /* set the newly allocated memory to 0 */
    memset((char *)(*ptr) + (*count * size), 0, size);
    (*count)++;

    /* access the first member of the supposed structure */
    name = (char **)((*ptr) + ((*count - 1) * size));

    /* and set it's value */
    *name = strdup(key_value);
    NC_CHECK_ERRMEM_GOTO(!*name, ret = 1, cleanup);

cleanup:
    return ret;
}

#ifdef NC_ENABLED_SSH_TLS

static void
nc_server_config_del_hostkey(struct nc_server_ssh_opts *opts, struct nc_hostkey *hostkey)
{
    assert(hostkey->store == NC_STORE_LOCAL || hostkey->store == NC_STORE_KEYSTORE);

    free(hostkey->name);

    if (hostkey->store == NC_STORE_LOCAL) {
        free(hostkey->key.pubkey_data);
        free(hostkey->key.privkey_data);
    } else {
        free(hostkey->ks_ref);
    }

    opts->hostkey_count--;
    if (!opts->hostkey_count) {
        free(opts->hostkeys);
        opts->hostkeys = NULL;
    } else if (hostkey != &opts->hostkeys[opts->hostkey_count]) {
        memcpy(hostkey, &opts->hostkeys[opts->hostkey_count], sizeof *opts->hostkeys);
    }
}

static void
nc_server_config_del_auth_client_pubkey(struct nc_auth_client *auth_client, struct nc_public_key *pubkey)
{
    free(pubkey->name);
    free(pubkey->data);

    auth_client->pubkey_count--;
    if (!auth_client->pubkey_count) {
        free(auth_client->pubkeys);
        auth_client->pubkeys = NULL;
    } else if (pubkey != &auth_client->pubkeys[auth_client->pubkey_count]) {
        memcpy(pubkey, &auth_client->pubkeys[auth_client->pubkey_count], sizeof *auth_client->pubkeys);
    }
}

static void
nc_server_config_del_auth_client_pubkeys(struct nc_auth_client *auth_client)
{
    uint16_t i, pubkey_count;

    if (auth_client->store == NC_STORE_LOCAL) {
        pubkey_count = auth_client->pubkey_count;
        for (i = 0; i < pubkey_count; i++) {
            nc_server_config_del_auth_client_pubkey(auth_client, &auth_client->pubkeys[i]);
        }
    } else if (auth_client->store == NC_STORE_TRUSTSTORE) {
        free(auth_client->ts_ref);
        auth_client->ts_ref = NULL;
    }
}

static void
nc_server_config_del_auth_client(struct nc_server_ssh_opts *opts, struct nc_auth_client *auth_client)
{
    free(auth_client->username);

    nc_server_config_del_auth_client_pubkeys(auth_client);

    free(auth_client->password);

    opts->client_count--;
    if (!opts->client_count) {
        free(opts->auth_clients);
        opts->auth_clients = NULL;
    } else if (auth_client != &opts->auth_clients[opts->client_count]) {
        memcpy(auth_client, &opts->auth_clients[opts->client_count], sizeof *opts->auth_clients);
    }
}

static void
nc_server_config_del_ssh_opts(struct nc_bind *bind, struct nc_server_ssh_opts *opts)
{
    uint16_t i, hostkey_count, client_count;

    if (bind) {
        free(bind->address);
        if (bind->sock > -1) {
            close(bind->sock);
        }
    }

    /* store in variable because it gets decremented in the function call */
    hostkey_count = opts->hostkey_count;
    for (i = 0; i < hostkey_count; i++) {
        nc_server_config_del_hostkey(opts, &opts->hostkeys[i]);
    }

    client_count = opts->client_count;
    for (i = 0; i < client_count; i++) {
        nc_server_config_del_auth_client(opts, &opts->auth_clients[i]);
    }

    free(opts->hostkey_algs);
    free(opts->kex_algs);
    free(opts->encryption_algs);
    free(opts->mac_algs);

    free(opts);
}

/* delete references to endpoint with the name 'referenced_endpt_name' from other endpts */
static void
nc_server_config_del_endpt_references(const char *referenced_endpt_name)
{
    uint16_t i, j;

    /* first go through listen endpoints */
    for (i = 0; i < server_opts.endpt_count; i++) {
        if (server_opts.endpts[i].referenced_endpt_name) {
            if (!strcmp(server_opts.endpts[i].referenced_endpt_name, referenced_endpt_name)) {
                free(server_opts.endpts[i].referenced_endpt_name);
                server_opts.endpts[i].referenced_endpt_name = NULL;

                if (server_opts.endpts[i].ti == NC_TI_SSH) {
                    server_opts.endpts[i].opts.ssh->referenced_endpt_name = NULL;
                } else {
                    server_opts.endpts[i].opts.tls->referenced_endpt_name = NULL;
                }
            }
        }
    }

    /* LOCK */
    pthread_rwlock_rdlock(&server_opts.ch_client_lock);
    /* next go through ch endpoints */
    for (i = 0; i < server_opts.ch_client_count; i++) {
        /* LOCK */
        pthread_mutex_lock(&server_opts.ch_clients[i].lock);
        for (j = 0; j < server_opts.ch_clients[i].ch_endpt_count; j++) {
            if (server_opts.ch_clients[i].ch_endpts[j].referenced_endpt_name) {
                if (!strcmp(server_opts.ch_clients[i].ch_endpts[j].referenced_endpt_name, referenced_endpt_name)) {
                    free(server_opts.ch_clients[i].ch_endpts[j].referenced_endpt_name);
                    server_opts.ch_clients[i].ch_endpts[j].referenced_endpt_name = NULL;

                    if (server_opts.ch_clients[i].ch_endpts[j].ti == NC_TI_SSH) {
                        server_opts.ch_clients[i].ch_endpts[j].opts.ssh->referenced_endpt_name = NULL;
                    } else {
                        server_opts.ch_clients[i].ch_endpts[j].opts.tls->referenced_endpt_name = NULL;
                    }
                }
            }
        }
        /* UNLOCK */
        pthread_mutex_unlock(&server_opts.ch_clients[i].lock);
    }

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);
}

void
nc_server_config_del_endpt_ssh(struct nc_endpt *endpt, struct nc_bind *bind)
{
    /* delete any references to this endpoint */
    nc_server_config_del_endpt_references(endpt->name);
    free(endpt->name);

    free(endpt->referenced_endpt_name);
    nc_server_config_del_ssh_opts(bind, endpt->opts.ssh);

    server_opts.endpt_count--;
    if (!server_opts.endpt_count) {
        free(server_opts.endpts);
        free(server_opts.binds);
        server_opts.endpts = NULL;
        server_opts.binds = NULL;
    } else if (endpt != &server_opts.endpts[server_opts.endpt_count]) {
        memcpy(endpt, &server_opts.endpts[server_opts.endpt_count], sizeof *server_opts.endpts);
        memcpy(bind, &server_opts.binds[server_opts.endpt_count], sizeof *server_opts.binds);
    }
}

static void
nc_server_config_del_cert(struct nc_cert_grouping *certs, struct nc_certificate *cert)
{
    free(cert->name);
    free(cert->data);

    certs->cert_count--;
    if (!certs->cert_count) {
        free(certs->certs);
        certs->certs = NULL;
    } else if (cert != &certs->certs[certs->cert_count]) {
        memcpy(cert, &certs->certs[certs->cert_count], sizeof *certs->certs);
    }
}

static void
nc_server_config_del_certs(struct nc_cert_grouping *certs_grp)
{
    uint16_t i;

    if (certs_grp->store == NC_STORE_LOCAL) {
        for (i = 0; i < certs_grp->cert_count; i++) {
            free(certs_grp->certs[i].name);
            free(certs_grp->certs[i].data);
        }
        certs_grp->cert_count = 0;
        free(certs_grp->certs);
        certs_grp->certs = NULL;
    } else if (certs_grp->store == NC_STORE_TRUSTSTORE) {
        free(certs_grp->ts_ref);
        certs_grp->ts_ref = NULL;
    }

    /* reset to the default */
    certs_grp->store = NC_STORE_LOCAL;
}

static void
nc_server_config_del_ctn(struct nc_server_tls_opts *opts, struct nc_ctn *ctn)
{
    struct nc_ctn *iter;

    free(ctn->name);
    free(ctn->fingerprint);

    if (opts->ctn == ctn) {
        /* it's the first in the list */
        opts->ctn = ctn->next;
        free(ctn);
        return;
    }

    for (iter = opts->ctn; iter; iter = iter->next) {
        if (iter->next == ctn) {
            /* found the ctn */
            break;
        }
    }

    if (!iter) {
        ERRINT;
        return;
    }

    iter->next = ctn->next;
    free(ctn);
}

static void
nc_server_config_del_ctns(struct nc_server_tls_opts *opts)
{
    struct nc_ctn *cur, *next;

    for (cur = opts->ctn; cur; cur = next) {
        next = cur->next;
        free(cur->name);
        free(cur->fingerprint);
        free(cur);
    }

    opts->ctn = NULL;
}

static void
nc_server_config_del_tls_opts(struct nc_bind *bind, struct nc_server_tls_opts *opts)
{
    if (bind) {
        free(bind->address);
        if (bind->sock > -1) {
            close(bind->sock);
        }
    }

    if (opts->store == NC_STORE_LOCAL) {
        free(opts->pubkey_data);
        free(opts->privkey_data);
        free(opts->cert_data);
    } else if (opts->store == NC_STORE_KEYSTORE) {
        free(opts->key_ref);
        free(opts->cert_ref);
    }

    nc_server_config_del_certs(&opts->ca_certs);
    nc_server_config_del_certs(&opts->ee_certs);

    nc_server_config_del_ctns(opts);
    free(opts->ciphers);
    free(opts);
}

static void
nc_server_config_del_endpt_tls(struct nc_endpt *endpt, struct nc_bind *bind)
{
    /* delete any references to this endpoint */
    nc_server_config_del_endpt_references(endpt->name);
    free(endpt->name);

    free(endpt->referenced_endpt_name);

    nc_server_config_del_tls_opts(bind, endpt->opts.tls);

    server_opts.endpt_count--;
    if (!server_opts.endpt_count) {
        free(server_opts.endpts);
        free(server_opts.binds);
        server_opts.endpts = NULL;
        server_opts.binds = NULL;
    } else if (endpt != &server_opts.endpts[server_opts.endpt_count]) {
        memcpy(endpt, &server_opts.endpts[server_opts.endpt_count], sizeof *server_opts.endpts);
        memcpy(bind, &server_opts.binds[server_opts.endpt_count], sizeof *server_opts.binds);
    }
}

#endif /* NC_ENABLED_SSH_TLS */

static void
nc_server_config_ch_del_endpt(struct nc_ch_client *ch_client, struct nc_ch_endpt *ch_endpt)
{
    free(ch_endpt->name);

#ifdef NC_ENABLED_SSH_TLS
    free(ch_endpt->src_addr);
    free(ch_endpt->dst_addr);
    if (ch_endpt->sock_pending > -1) {
        close(ch_endpt->sock_pending);
        ch_endpt->sock_pending = -1;
    }
    free(ch_endpt->referenced_endpt_name);
#endif /* NC_ENABLED_SSH_TLS */

    switch (ch_endpt->ti) {
#ifdef NC_ENABLED_SSH_TLS
    case NC_TI_SSH:
        nc_server_config_del_ssh_opts(NULL, ch_endpt->opts.ssh);
        break;
    case NC_TI_TLS:
        nc_server_config_del_tls_opts(NULL, ch_endpt->opts.tls);
        break;
#endif /* NC_ENABLED_SSH_TLS */
    default:
        ERRINT;
        break;
    }

    ch_client->ch_endpt_count--;
    if (!ch_client->ch_endpt_count) {
        free(ch_client->ch_endpts);
        ch_client->ch_endpts = NULL;
    }
}

static void
nc_server_config_destroy_ch_client(struct nc_ch_client *ch_client)
{
    pthread_t tid;
    uint16_t i, ch_endpt_count;

    /* CH COND LOCK */
    pthread_mutex_lock(&ch_client->thread_data->cond_lock);
    if (ch_client->thread_data->thread_running) {
        ch_client->thread_data->thread_running = 0;
        pthread_cond_signal(&ch_client->thread_data->cond);
        /* CH COND UNLOCK */
        pthread_mutex_unlock(&ch_client->thread_data->cond_lock);

        /* get tid */
        tid = ch_client->tid;

        /* wait for the thread to terminate */
        pthread_join(tid, NULL);
    } else {
        /* CH COND UNLOCK */
        pthread_mutex_unlock(&ch_client->thread_data->cond_lock);
    }

    /* free its members */
    free(ch_client->name);

    ch_endpt_count = ch_client->ch_endpt_count;
    for (i = 0; i < ch_endpt_count; i++) {
        nc_server_config_ch_del_endpt(ch_client, &ch_client->ch_endpts[i]);
    }
}

static void
nc_server_config_ch_del_client(const struct lyd_node *node)
{
    struct nc_ch_client client, *ch_client;

    /* WR LOCK */
    pthread_rwlock_wrlock(&server_opts.ch_client_lock);

    if (nc_server_config_get_ch_client(node, &ch_client)) {
        /* WR UNLOCK */
        pthread_rwlock_unlock(&server_opts.ch_client_lock);
        ERR(NULL, "Call-home client \"%s\" not found.", lyd_get_value(lyd_child(node)));
        return;
    }

    /* copy the client we want to delete into a local variable */
    memcpy(&client, ch_client, sizeof *ch_client);

    /* delete the client */
    server_opts.ch_client_count--;
    if (!server_opts.ch_client_count) {
        free(server_opts.ch_clients);
        server_opts.ch_clients = NULL;
    } else {
        memcpy(ch_client, &server_opts.ch_clients[server_opts.ch_client_count], sizeof *server_opts.ch_clients);
    }

    /* WR UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);

    nc_server_config_destroy_ch_client(&client);
}

/* presence container */
int
nc_server_config_listen(const struct lyd_node *node, NC_OPERATION op)
{
    uint16_t i, endpt_count;

    (void) node;

    assert(op == NC_OP_CREATE || op == NC_OP_DELETE);

    if (op == NC_OP_DELETE) {
        endpt_count = server_opts.endpt_count;
        for (i = 0; i < endpt_count; i++) {
            switch (server_opts.endpts[i].ti) {
#ifdef NC_ENABLED_SSH_TLS
            case NC_TI_SSH:
                nc_server_config_del_endpt_ssh(&server_opts.endpts[i], &server_opts.binds[i]);
                break;
            case NC_TI_TLS:
                nc_server_config_del_endpt_tls(&server_opts.endpts[i], &server_opts.binds[i]);
                break;
#endif /* NC_ENABLED_SSH_TLS */
            case NC_TI_UNIX:
                break;
            case NC_TI_NONE:
            case NC_TI_FD:
                ERRINT;
                return 1;
            }
        }
    }

    return 0;
}

int
nc_server_config_ch(const struct lyd_node *node, NC_OPERATION op)
{
    uint16_t i, ch_client_count;
    struct nc_ch_client *ch_clients;

    (void) node;

    /* don't do anything if we're not deleting */
    if (op != NC_OP_DELETE) {
        return 0;
    }

    /* WR LOCK */
    pthread_rwlock_wrlock(&server_opts.ch_client_lock);

    ch_client_count = server_opts.ch_client_count;
    ch_clients = server_opts.ch_clients;

    /* remove them from the server opts */
    server_opts.ch_client_count = 0;
    server_opts.ch_clients = NULL;

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);

    for (i = 0; i < ch_client_count; i++) {
        /* now destroy each client */
        nc_server_config_destroy_ch_client(&ch_clients[i]);
    }

    free(ch_clients);
    return 0;
}

/* default leaf */
static int
nc_server_config_idle_timeout(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "idle-timeout"));

    if (is_ch(node)) {
        /* call-home idle timeout */
        if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
            /* to avoid unlock on fail */
            return 1;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ch_client->idle_timeout = ((struct lyd_node_term *)node)->value.uint16;
        } else if (op == NC_OP_DELETE) {
            ch_client->idle_timeout = 180;
        }

        nc_ch_client_unlock(ch_client);
    } else {
        /* listen idle timeout */
        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            server_opts.idle_timeout = ((struct lyd_node_term *)node)->value.uint16;
        } else {
            /* default value */
            server_opts.idle_timeout = 180;
        }
    }

    return 0;
}

static int
nc_server_config_create_bind(void)
{
    int ret = 0;
    void *tmp;

    tmp = realloc(server_opts.binds, (server_opts.endpt_count + 1) * sizeof *server_opts.binds);
    NC_CHECK_ERRMEM_GOTO(!tmp, ret = 1, cleanup);
    server_opts.binds = tmp;
    memset(&server_opts.binds[server_opts.endpt_count], 0, sizeof *server_opts.binds);

    server_opts.binds[server_opts.endpt_count].sock = -1;

cleanup:
    return ret;
}

static int
nc_server_config_create_endpoint(const struct lyd_node *node)
{
    if (nc_server_config_create_bind()) {
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&server_opts.endpts, sizeof *server_opts.endpts,
            &server_opts.endpt_count);
}

static int
nc_server_config_ch_create_endpoint(const struct lyd_node *node, struct nc_ch_client *ch_client)
{
    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&ch_client->ch_endpts, sizeof *ch_client->ch_endpts,
            &ch_client->ch_endpt_count);
}

/* list */
static int
nc_server_config_endpoint(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    struct nc_ch_endpt *ch_endpt;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "endpoint"));

    if (is_listen(node)) {
        /* listen */
        if (op == NC_OP_CREATE) {
            ret = nc_server_config_create_endpoint(node);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            /* free all children */
            if (nc_server_config_get_endpt(node, &endpt, &bind)) {
                ret = 1;
                goto cleanup;
            }

            switch (endpt->ti) {
#ifdef NC_ENABLED_SSH_TLS
            case NC_TI_SSH:
                nc_server_config_del_endpt_ssh(endpt, bind);
                break;
            case NC_TI_TLS:
                nc_server_config_del_endpt_tls(endpt, bind);
                break;
#endif /* NC_ENABLED_SSH_TLS */
            case NC_TI_UNIX:
                break;
            case NC_TI_NONE:
            case NC_TI_FD:
                ERRINT;
                ret = 1;
                goto cleanup;
            }
        }
    } else if (is_ch(node)) {
        /* LOCK */
        if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
            /* to avoid unlock on fail */
            return 1;
        }

        if (op == NC_OP_CREATE) {
            ret = nc_server_config_ch_create_endpoint(node, ch_client);
            if (ret) {
                goto cleanup;
            }

            /* init ch sock */
            ch_client->ch_endpts[ch_client->ch_endpt_count - 1].sock_pending = -1;
        } else if (op == NC_OP_DELETE) {
            if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
                ret = 1;
                goto cleanup;
            }

            nc_server_config_ch_del_endpt(ch_client, ch_endpt);
        }
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

#ifdef NC_ENABLED_SSH_TLS

static int
nc_server_config_create_ssh(struct nc_endpt *endpt)
{
    endpt->ti = NC_TI_SSH;
    endpt->opts.ssh = calloc(1, sizeof(struct nc_server_ssh_opts));
    NC_CHECK_ERRMEM_RET(!endpt->opts.ssh, 1);

    return 0;
}

static int
nc_server_config_ch_create_ssh(struct nc_ch_endpt *ch_endpt)
{
    ch_endpt->ti = NC_TI_SSH;
    ch_endpt->opts.ssh = calloc(1, sizeof(struct nc_server_ssh_opts));
    NC_CHECK_ERRMEM_RET(!ch_endpt->opts.ssh, 1);

    return 0;
}

/* NP container */
static int
nc_server_config_ssh(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    struct nc_ch_endpt *ch_endpt;
    struct nc_ch_client *ch_client = NULL;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "ssh"));

    if (is_listen(node)) {
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            ret = nc_server_config_create_ssh(endpt);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            nc_server_config_del_ssh_opts(bind, endpt->opts.ssh);
        }
    } else {
        /* LOCK */
        if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
            /* to avoid unlock on fail */
            return 1;
        }

        if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            ret = nc_server_config_ch_create_ssh(ch_endpt);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            nc_server_config_del_ssh_opts(NULL, ch_endpt->opts.ssh);
        }
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_create_tls(struct nc_endpt *endpt)
{
    endpt->ti = NC_TI_TLS;
    endpt->opts.tls = calloc(1, sizeof *endpt->opts.tls);
    NC_CHECK_ERRMEM_RET(!endpt->opts.tls, 1);

    return 0;
}

static int
nc_server_config_ch_create_tls(struct nc_ch_endpt *ch_endpt)
{
    ch_endpt->ti = NC_TI_TLS;
    ch_endpt->opts.tls = calloc(1, sizeof(struct nc_server_tls_opts));
    NC_CHECK_ERRMEM_RET(!ch_endpt->opts.tls, 1);

    return 0;
}

static int
nc_server_config_tls(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    struct nc_ch_endpt *ch_endpt;
    struct nc_ch_client *ch_client = NULL;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "tls"));

    if (is_listen(node)) {
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            ret = nc_server_config_create_tls(endpt);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            nc_server_config_del_tls_opts(bind, endpt->opts.tls);
        }
    } else {
        /* LOCK */
        if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
            /* to avoid unlock on fail */
            return 1;
        }

        if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            ret = nc_server_config_ch_create_tls(ch_endpt);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            nc_server_config_del_tls_opts(NULL, ch_endpt->opts.tls);
        }
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf */
static int
nc_server_config_local_address(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    struct nc_ch_client *ch_client = NULL;
    struct nc_ch_endpt *ch_endpt;

    assert(!strcmp(LYD_NAME(node), "local-address"));

    if (is_listen(node) && equal_parent_name(node, 1, "tcp-server-parameters")) {
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        free(bind->address);
        bind->address = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_GOTO(!bind->address, ret = 1, cleanup);

        ret = nc_server_set_address_port(endpt, bind, lyd_get_value(node), 0);
        if (ret) {
            goto cleanup;
        }
    } else if (is_ch(node) && equal_parent_name(node, 1, "tcp-client-parameters")) {
        /* LOCK */
        if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
            /* to avoid unlock on fail */
            return 1;
        }

        if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            free(ch_endpt->src_addr);
            ch_endpt->src_addr = strdup(lyd_get_value(node));
            NC_CHECK_ERRMEM_GOTO(!ch_endpt->src_addr, ret = 1, cleanup);
        } else if (op == NC_OP_DELETE) {
            free(ch_endpt->src_addr);
            ch_endpt->src_addr = NULL;
        }
    }

cleanup:
    if (is_ch(node) && equal_parent_name(node, 1, "tcp-client-parameters")) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf with default value */
static int
nc_server_config_local_port(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    struct nc_ch_client *ch_client = NULL;
    struct nc_ch_endpt *ch_endpt;

    assert(!strcmp(LYD_NAME(node), "local-port"));

    if (is_listen(node) && equal_parent_name(node, 1, "tcp-server-parameters")) {
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            bind->port = ((struct lyd_node_term *)node)->value.uint16;
        } else {
            /* delete -> set to default */
            bind->port = 0;
        }

        ret = nc_server_set_address_port(endpt, bind, NULL, bind->port);
        if (ret) {
            goto cleanup;
        }
    } else if (is_ch(node) && equal_parent_name(node, 1, "tcp-client-parameters")) {
        /* LOCK */
        if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
            /* to avoid unlock on fail */
            return 1;
        }

        if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ch_endpt->src_port = ((struct lyd_node_term *)node)->value.uint16;
        } else if (op == NC_OP_DELETE) {
            /* delete -> set to default */
            ch_endpt->src_port = 0;
        }
    }

cleanup:
    if (is_ch(node) && equal_parent_name(node, 1, "tcp-client-parameters")) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* NP container */
static int
nc_server_config_keepalives(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    struct nc_ch_endpt *ch_endpt;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "keepalives"));

    if (is_listen(node) && equal_parent_name(node, 1, "tcp-server-parameters")) {
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            endpt->ka.enabled = 1;
        } else {
            endpt->ka.enabled = 0;
        }
    } else if (is_ch(node) && equal_parent_name(node, 1, "tcp-client-parameters")) {
        /* LOCK */
        if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
            /* to avoid unlock on fail */
            return 1;
        }

        if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            ch_endpt->ka.enabled = 1;
        } else {
            ch_endpt->ka.enabled = 0;
        }
    }

cleanup:
    if (is_ch(node) && equal_parent_name(node, 1, "tcp-client-parameters")) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf with default value */
static int
nc_server_config_idle_time(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    struct nc_ch_endpt *ch_endpt;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "idle-time"));

    if (is_listen(node) && equal_parent_name(node, 2, "tcp-server-parameters")) {
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            endpt->ka.idle_time = ((struct lyd_node_term *)node)->value.uint16;
        } else {
            /* delete -> set to default */
            endpt->ka.idle_time = 7200;
        }
    } else if (is_ch(node) && equal_parent_name(node, 2, "tcp-client-parameters")) {
        /* LOCK */
        if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
            /* to avoid unlock on fail */
            return 1;
        }

        if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ch_endpt->ka.idle_time = ((struct lyd_node_term *)node)->value.uint16;
        } else {
            /* delete -> set to default */
            ch_endpt->ka.idle_time = 7200;
        }
    }

cleanup:
    if (is_ch(node) && equal_parent_name(node, 2, "tcp-client-parameters")) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf with default value */
static int
nc_server_config_max_probes(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    struct nc_ch_endpt *ch_endpt;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "max-probes"));

    if (is_listen(node) && equal_parent_name(node, 2, "tcp-server-parameters")) {
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            endpt->ka.max_probes = ((struct lyd_node_term *)node)->value.uint16;
        } else {
            /* delete -> set to default */
            endpt->ka.max_probes = 9;
        }
    } else if (is_ch(node) && equal_parent_name(node, 2, "tcp-client-parameters")) {
        /* LOCK */
        if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
            /* to avoid unlock on fail */
            return 1;
        }

        if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ch_endpt->ka.max_probes = ((struct lyd_node_term *)node)->value.uint16;
        } else {
            /* delete -> set to default */
            ch_endpt->ka.max_probes = 9;
        }
    }

cleanup:
    if (is_ch(node) && equal_parent_name(node, 2, "tcp-client-parameters")) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf with default value */
static int
nc_server_config_probe_interval(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    struct nc_ch_endpt *ch_endpt;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "probe-interval"));

    if (is_listen(node) && equal_parent_name(node, 2, "tcp-server-parameters")) {
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            endpt->ka.probe_interval = ((struct lyd_node_term *)node)->value.uint16;
        } else {
            /* delete -> set to default */
            endpt->ka.probe_interval = 75;
        }
    } else if (is_ch(node) && equal_parent_name(node, 2, "tcp-client-parameters")) {
        /* LOCK */
        if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
            /* to avoid unlock on fail */
            return 1;
        }

        if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ch_endpt->ka.probe_interval = ((struct lyd_node_term *)node)->value.uint16;
        } else {
            /* delete -> set to default */
            ch_endpt->ka.probe_interval = 75;
        }
    }

cleanup:
    if (is_ch(node) && equal_parent_name(node, 2, "tcp-client-parameters")) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_create_host_key(const struct lyd_node *node, struct nc_server_ssh_opts *opts)
{
    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&opts->hostkeys, sizeof *opts->hostkeys, &opts->hostkey_count);
}

/* list */
static int
nc_server_config_host_key(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_hostkey *hostkey;
    struct nc_server_ssh_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "host-key"));

    if (equal_parent_name(node, 1, "server-identity")) {
        /* LOCK */
        if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
            /* to avoid unlock on fail */
            return 1;
        }

        if (nc_server_config_get_ssh_opts(node, ch_client, &opts)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            ret = nc_server_config_create_host_key(node, opts);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            if (nc_server_config_get_hostkey(node, ch_client, &hostkey)) {
                ret = 1;
                goto cleanup;
            }
            nc_server_config_del_hostkey(opts, hostkey);
        }
    }

cleanup:
    if (is_ch(node) && equal_parent_name(node, 1, "server-identity")) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* mandatory leaf */
static int
nc_server_config_public_key_format(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    const char *format;
    NC_PUBKEY_FORMAT pubkey_type;
    struct nc_public_key *pubkey;
    struct nc_hostkey *hostkey;
    struct nc_server_tls_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "public-key-format"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    format = ((struct lyd_node_term *)node)->value.ident->name;
    if (!strcmp(format, "ssh-public-key-format")) {
        pubkey_type = NC_PUBKEY_FORMAT_SSH;
    } else if (!strcmp(format, "subject-public-key-info-format")) {
        pubkey_type = NC_PUBKEY_FORMAT_X509;
    } else {
        ERR(NULL, "Public key format (%s) not supported.", format);
        ret = 1;
        goto cleanup;
    }

    if (is_ssh(node) && equal_parent_name(node, 4, "server-identity")) {
        /* SSH hostkey public key fmt */
        if (nc_server_config_get_hostkey(node, ch_client, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            hostkey->key.pubkey_type = pubkey_type;
        }
    } else if (is_ssh(node) && equal_parent_name(node, 6, "client-authentication")) {
        /* SSH client auth public key fmt */
        if (nc_server_config_get_pubkey(node, ch_client, &pubkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            pubkey->type = pubkey_type;
        }
    } else if (is_tls(node) && equal_parent_name(node, 3, "server-identity")) {
        /* TLS server-identity */
        if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            opts->pubkey_type = pubkey_type;
        }
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_create_auth_key_public_key_list(const struct lyd_node *node, struct nc_auth_client *auth_client)
{
    assert(!strcmp(LYD_NAME(node), "public-key"));

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&auth_client->pubkeys, sizeof *auth_client->pubkeys,
            &auth_client->pubkey_count);
}

static int
nc_server_config_replace_auth_key_public_key_leaf(const struct lyd_node *node, struct nc_public_key *pubkey)
{
    free(pubkey->data);
    pubkey->data = strdup(lyd_get_value(node));
    NC_CHECK_ERRMEM_RET(!pubkey->data, 1);

    return 0;
}

static int
nc_server_config_replace_host_key_public_key(const struct lyd_node *node, struct nc_hostkey *hostkey)
{
    free(hostkey->key.pubkey_data);
    hostkey->key.pubkey_data = strdup(lyd_get_value(node));
    NC_CHECK_ERRMEM_RET(!hostkey->key.pubkey_data, 1);

    return 0;
}

static int
nc_server_config_tls_replace_server_public_key(const struct lyd_node *node, struct nc_server_tls_opts *opts)
{
    free(opts->pubkey_data);
    opts->pubkey_data = strdup(lyd_get_value(node));
    NC_CHECK_ERRMEM_RET(!opts->pubkey_data, 1);

    return 0;
}

static int
nc_server_config_public_key(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_hostkey *hostkey;
    struct nc_auth_client *auth_client;
    struct nc_public_key *pubkey;
    struct nc_server_tls_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "public-key"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (is_ssh(node) && equal_parent_name(node, 3, "host-key")) {
        /* server's public-key, mandatory leaf */
        if (nc_server_config_get_hostkey(node, ch_client, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        /* the public key must not be SubjectPublicKeyInfoFormat, as per the ietf-netconf-server model */
        if (nc_is_pk_subject_public_key_info(lyd_get_value(node))) {
            ERR(NULL, "Using Public Key in the SubjectPublicKeyInfo format as an SSH hostkey is forbidden!");
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to local */
            hostkey->store = NC_STORE_LOCAL;

            ret = nc_server_config_replace_host_key_public_key(node, hostkey);
            if (ret) {
                goto cleanup;
            }
        }
    } else if (is_ssh(node) && equal_parent_name(node, 5, "client-authentication")) {
        /* client auth pubkeys, list */
        if (nc_server_config_get_auth_client(node, ch_client, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            /* set to local */
            auth_client->store = NC_STORE_LOCAL;

            ret = nc_server_config_create_auth_key_public_key_list(node, auth_client);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            if (nc_server_config_get_pubkey(node, ch_client, &pubkey)) {
                ret = 1;
                goto cleanup;
            }

            nc_server_config_del_auth_client_pubkey(auth_client, pubkey);
        }
    } else if (is_ssh(node) && equal_parent_name(node, 6, "client-authentication")) {
        /* client auth pubkey, leaf */
        if (nc_server_config_get_pubkey(node, ch_client, &pubkey)) {
            ret = 1;
            goto cleanup;
        }

        /* the public key must not be SubjectPublicKeyInfoFormat, as per the ietf-netconf-server model */
        if (nc_is_pk_subject_public_key_info(lyd_get_value(node))) {
            ERR(NULL, "Using Public Key in the SubjectPublicKeyInfo format as an SSH user's key is forbidden!");
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_replace_auth_key_public_key_leaf(node, pubkey);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            free(pubkey->data);
            pubkey->data = NULL;
        }
    } else if (is_tls(node) && equal_parent_name(node, 3, "server-identity")) {
        /* TLS server-identity */
        if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
            ret = 1;
            goto cleanup;
        }

        /* the public key must be SubjectPublicKeyInfoFormat, as per the ietf-netconf-server model */
        if (!nc_is_pk_subject_public_key_info(lyd_get_value(node))) {
            ERR(NULL, "TLS server certificate's Public Key must be in the SubjectPublicKeyInfo format!");
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to local */
            opts->store = NC_STORE_LOCAL;

            ret = nc_server_config_tls_replace_server_public_key(node, opts);
            if (ret) {
                goto cleanup;
            }
        }
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf */
static int
nc_server_config_private_key_format(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    const char *format;
    NC_PRIVKEY_FORMAT privkey_type;
    struct nc_hostkey *hostkey;
    struct nc_server_tls_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    (void) op;

    assert(!strcmp(LYD_NAME(node), "private-key-format"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    format = ((struct lyd_node_term *)node)->value.ident->name;
    if (!format) {
        ret = 1;
        goto cleanup;
    }

    privkey_type = nc_server_config_get_private_key_type(format);
    if (privkey_type == NC_PRIVKEY_FORMAT_UNKNOWN) {
        ERR(NULL, "Unknown private key format.");
        ret = 1;
        goto cleanup;
    }

    if (is_ssh(node)) {
        /* ssh */
        if (nc_server_config_get_hostkey(node, ch_client, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        hostkey->key.privkey_type = privkey_type;
    } else if (is_tls(node)) {
        /* tls */
        if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
            ret = 1;
            goto cleanup;
        }

        opts->privkey_type = privkey_type;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_cleartext_private_key(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_hostkey *hostkey;
    struct nc_server_tls_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "cleartext-private-key"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (is_ssh(node)) {
        /* ssh */
        if (nc_server_config_get_hostkey(node, ch_client, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            free(hostkey->key.privkey_data);
            hostkey->key.privkey_data = strdup(lyd_get_value(node));
            NC_CHECK_ERRMEM_GOTO(!hostkey->key.privkey_data, ret = 1, cleanup);
        } else {
            free(hostkey->key.privkey_data);
            hostkey->key.privkey_data = NULL;
        }
    } else if (is_tls(node)) {
        /* tls */
        if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            free(opts->privkey_data);
            opts->privkey_data = strdup(lyd_get_value(node));
            NC_CHECK_ERRMEM_GOTO(!opts->privkey_data, ret = 1, cleanup);
        } else {
            free(opts->privkey_data);
            opts->privkey_data = NULL;
        }
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf */
static int
nc_server_config_keystore_reference(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_hostkey *hostkey;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "central-keystore-reference"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (is_ssh(node) && equal_parent_name(node, 3, "server-identity")) {
        if (nc_server_config_get_hostkey(node, ch_client, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to keystore */
            hostkey->store = NC_STORE_KEYSTORE;

            free(hostkey->ks_ref);
            hostkey->ks_ref = strdup(lyd_get_value(node));
            NC_CHECK_ERRMEM_GOTO(!hostkey->ks_ref, ret = 1, cleanup);
        } else if (op == NC_OP_DELETE) {
            free(hostkey->ks_ref);
            hostkey->ks_ref = NULL;
        }
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_create_auth_client(const struct lyd_node *node, struct nc_server_ssh_opts *opts)
{
    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&opts->auth_clients, sizeof *opts->auth_clients, &opts->client_count);
}

/* list */
static int
nc_server_config_user(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_auth_client *auth_client;
    struct nc_server_ssh_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "user"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_ssh_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    if (op == NC_OP_CREATE) {
        ret = nc_server_config_create_auth_client(node, opts);
        if (ret) {
            goto cleanup;
        }
    } else if (op == NC_OP_DELETE) {
        if (nc_server_config_get_auth_client(node, ch_client, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        nc_server_config_del_auth_client(opts, auth_client);
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_auth_timeout(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_server_ssh_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "auth-timeout"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_ssh_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        opts->auth_timeout = ((struct lyd_node_term *)node)->value.uint16;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf */
static int
nc_server_config_truststore_reference(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_auth_client *auth_client;
    struct nc_ch_client *ch_client = NULL;
    struct nc_server_tls_opts *opts;
    struct nc_cert_grouping *certs_grp;

    assert(!strcmp(LYD_NAME(node), "central-truststore-reference"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (is_ssh(node) && equal_parent_name(node, 1, "public-keys")) {
        if (nc_server_config_get_auth_client(node, ch_client, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to truststore */
            auth_client->store = NC_STORE_TRUSTSTORE;

            free(auth_client->ts_ref);
            auth_client->ts_ref = strdup(lyd_get_value(node));
            NC_CHECK_ERRMEM_GOTO(!auth_client->ts_ref, ret = 1, cleanup);
        } else if (op == NC_OP_DELETE) {
            free(auth_client->ts_ref);
            auth_client->ts_ref = NULL;
        }
    } else if (is_tls(node) && (equal_parent_name(node, 1, "ca-certs") || equal_parent_name(node, 1, "ee-certs"))) {
        /* ee-certs or ca-certs */
        if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
            ret = 1;
            goto cleanup;
        }

        if (equal_parent_name(node, 1, "ca-certs")) {
            certs_grp = &opts->ca_certs;
        } else {
            certs_grp = &opts->ee_certs;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to truststore */
            certs_grp->store = NC_STORE_TRUSTSTORE;

            free(certs_grp->ts_ref);
            certs_grp->ts_ref = strdup(lyd_get_value(node));
            NC_CHECK_ERRMEM_GOTO(!certs_grp->ts_ref, ret = 1, cleanup);
        } else if (op == NC_OP_DELETE) {
            free(certs_grp->ts_ref);
            certs_grp->ts_ref = NULL;
        }
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_use_system_keys(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_auth_client *auth_client;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "use-system-keys"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_auth_client(node, ch_client, &auth_client)) {
        ret = 1;
        goto cleanup;
    }

    if (op == NC_OP_CREATE) {
        auth_client->store = NC_STORE_SYSTEM;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_public_keys(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_auth_client *auth_client;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "public-keys"));

    /* only do something on delete */
    if (op != NC_OP_DELETE) {
        return 0;
    }

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_auth_client(node, ch_client, &auth_client)) {
        ret = 1;
        goto cleanup;
    }

    nc_server_config_del_auth_client_pubkeys(auth_client);

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf */
static int
nc_server_config_password(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_auth_client *auth_client;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "password"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_auth_client(node, ch_client, &auth_client)) {
        ret = 1;
        goto cleanup;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(auth_client->password);
        auth_client->password = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_GOTO(!auth_client->password, ret = 1, cleanup);
    } else {
        free(auth_client->password);
        auth_client->password = NULL;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_use_system_auth(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_auth_client *auth_client;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "use-system-auth"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_auth_client(node, ch_client, &auth_client)) {
        ret = 1;
        goto cleanup;
    }

    if (op == NC_OP_CREATE) {
        auth_client->kb_int_enabled = 1;
    } else {
        auth_client->kb_int_enabled = 0;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf */
static int
nc_server_config_none(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_auth_client *auth_client;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "none"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_auth_client(node, ch_client, &auth_client)) {
        ret = 1;
        goto cleanup;
    }

    if (op == NC_OP_CREATE) {
        auth_client->none_enabled = 1;
    } else {
        auth_client->none_enabled = 0;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_delete_substring(const char *haystack, const char *needle, const char delim)
{
    size_t needle_len = strlen(needle);
    char *substr;
    int substr_found = 0, ret = 0;

    while ((substr = strstr(haystack, needle))) {
        /* iterate over all the substrings */
        if (((substr == haystack) && (*(substr + needle_len) == delim)) ||
                ((substr != haystack) && (*(substr - 1) == delim) && (*(substr + needle_len) == delim))) {
            /* either the first element of the string or somewhere in the middle */
            memmove(substr, substr + needle_len + 1, strlen(substr + needle_len + 1));
            substr_found = 1;
            break;
        } else if ((*(substr - 1) == delim) && (*(substr + needle_len) == '\0')) {
            /* the last element of the string */
            *(substr - 1) = '\0';
            substr_found = 1;
            break;
        }
        haystack = substr + 1;
    }
    if (!substr_found) {
        ret = 1;
    }

    return ret;
}

static int
nc_server_config_transport_params(const char *algorithm, char **alg_store, NC_OPERATION op)
{
    int ret = 0;
    char *alg = NULL;

    if (!strncmp(algorithm, "openssh-", 8)) {
        /* if the name starts with openssh, convert it to it's original libssh accepted form */
        ret = asprintf(&alg, "%s@openssh.com", algorithm + 8);
        NC_CHECK_ERRMEM_GOTO(ret == -1, ret = 1; alg = NULL, cleanup);
    } else if (!strncmp(algorithm, "libssh-", 7)) {
        /* if the name starts with libssh, convert it to it's original libssh accepted form */
        ret = asprintf(&alg, "%s@libssh.org", algorithm + 7);
        NC_CHECK_ERRMEM_GOTO(ret == -1, ret = 1; alg = NULL, cleanup);
    } else {
        alg = strdup(algorithm);
        NC_CHECK_ERRMEM_GOTO(!alg, ret = 1, cleanup);
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        if (!*alg_store) {
            /* first call */
            *alg_store = strdup(alg);
            NC_CHECK_ERRMEM_GOTO(!*alg_store, ret = 1, cleanup);
        } else {
            /* +1 because of ',' between algorithms */
            *alg_store = nc_realloc(*alg_store, strlen(*alg_store) + strlen(alg) + 1 + 1);
            NC_CHECK_ERRMEM_GOTO(!*alg_store, ret = 1, cleanup);
            strcat(*alg_store, ",");
            strcat(*alg_store, alg);
        }
    } else {
        /* delete */
        ret = nc_server_config_delete_substring(*alg_store, alg, ',');
        if (ret) {
            ERR(NULL, "Unable to delete an algorithm (%s), which was not previously added.", alg);
            goto cleanup;
        }
    }

cleanup:
    free(alg);
    return ret;
}

/* leaf-list */
static int
nc_server_config_host_key_alg(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    const char *alg;
    struct nc_server_ssh_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "host-key-alg"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_ssh_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    /* get the algorithm name and append it to supported algs */
    alg = ((struct lyd_node_term *)node)->value.ident->name;
    if (nc_server_config_transport_params(alg, &opts->hostkey_algs, op)) {
        ret = 1;
        goto cleanup;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf-list */
static int
nc_server_config_kex_alg(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    const char *alg;
    struct nc_server_ssh_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "key-exchange-alg"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_ssh_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    /* get the algorithm name and append it to supported algs */
    alg = ((struct lyd_node_term *)node)->value.ident->name;
    if (nc_server_config_transport_params(alg, &opts->kex_algs, op)) {
        ret = 1;
        goto cleanup;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf-list */
static int
nc_server_config_encryption_alg(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    const char *alg;
    struct nc_server_ssh_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "encryption-alg"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_ssh_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    /* get the algorithm name and append it to supported algs */
    alg = ((struct lyd_node_term *)node)->value.ident->name;
    if (nc_server_config_transport_params(alg, &opts->encryption_algs, op)) {
        ret = 1;
        goto cleanup;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

/* leaf-list */
static int
nc_server_config_mac_alg(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    const char *alg;
    struct nc_server_ssh_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "mac-alg"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_ssh_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    /* get the algorithm name and append it to supported algs */
    alg = ((struct lyd_node_term *)node)->value.ident->name;
    if (nc_server_config_transport_params(alg, &opts->mac_algs, op)) {
        ret = 1;
        goto cleanup;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_check_endpt_reference_cycle(struct nc_endpt *original, struct nc_endpt *next)
{
    if (!next->referenced_endpt_name) {
        /* no further reference -> no cycle */
        return 0;
    }

    if (!strcmp(original->name, next->referenced_endpt_name)) {
        /* found cycle */
        return 1;
    } else {
        if (nc_server_get_referenced_endpt(next->referenced_endpt_name, &next)) {
            /* referenced endpoint does not exist */
            return 1;
        }

        /* continue further */
        return nc_server_config_check_endpt_reference_cycle(original, next);
    }
}

/**
 * @brief Set all endpoint references.
 *
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_check_endpt_references(void)
{
    uint16_t i, j;
    struct nc_endpt *referenced_endpt = NULL;

    /* first do listen endpoints */
    for (i = 0; i < server_opts.endpt_count; i++) {
        /* go through all the endpoints */
        if (server_opts.endpts[i].referenced_endpt_name) {
            /* get referenced endpt */
            if (nc_server_get_referenced_endpt(server_opts.endpts[i].referenced_endpt_name, &referenced_endpt)) {
                ERR(NULL, "Endpoint \"%s\" referenced by endpoint \"%s\" does not exist.",
                        server_opts.endpts[i].referenced_endpt_name, server_opts.endpts[i].name);
                return 1;
            }

            /* check if the endpoint references itself */
            if (&server_opts.endpts[i] == referenced_endpt) {
                ERR(NULL, "Endpoint \"%s\" references itself.", server_opts.endpts[i].name);
                return 1;
            }

            /* check transport */
            if ((server_opts.endpts[i].ti != referenced_endpt->ti)) {
                ERR(NULL, "Endpoint \"%s\" referenced by endpoint \"%s\" has different transport type.",
                        server_opts.endpts[i].referenced_endpt_name, server_opts.endpts[i].name);
                return 1;
            } else if ((referenced_endpt->ti != NC_TI_SSH) && (referenced_endpt->ti != NC_TI_TLS)) {
                ERR(NULL, "Endpoint \"%s\" referenced by endpoint \"%s\" has unsupported transport type.",
                        server_opts.endpts[i].referenced_endpt_name, server_opts.endpts[i].name);
                return 1;
            }

            /* check cyclic reference */
            if (nc_server_config_check_endpt_reference_cycle(&server_opts.endpts[i], referenced_endpt)) {
                ERR(NULL, "Endpoint \"%s\" referenced by endpoint \"%s\" creates a cycle.",
                        server_opts.endpts[i].referenced_endpt_name, server_opts.endpts[i].name);
                return 1;
            }

            /* all went well, assign the name to the opts, so we can access it for auth */
            if (server_opts.endpts[i].ti == NC_TI_SSH) {
                server_opts.endpts[i].opts.ssh->referenced_endpt_name = referenced_endpt->name;
            } else {
                server_opts.endpts[i].opts.tls->referenced_endpt_name = referenced_endpt->name;
            }
        }
    }

    /* now check all the call home endpoints */
    /* LOCK */
    pthread_rwlock_rdlock(&server_opts.ch_client_lock);
    for (i = 0; i < server_opts.ch_client_count; i++) {
        /* LOCK */
        pthread_mutex_lock(&server_opts.ch_clients[i].lock);
        for (j = 0; j < server_opts.ch_clients[i].ch_endpt_count; j++) {
            if (server_opts.ch_clients[i].ch_endpts[j].referenced_endpt_name) {
                /* get referenced endpt */
                if (nc_server_get_referenced_endpt(server_opts.ch_clients[i].ch_endpts[j].referenced_endpt_name, &referenced_endpt)) {
                    ERR(NULL, "Endpoint \"%s\" referenced by call home endpoint \"%s\" does not exist.",
                            server_opts.ch_clients[i].ch_endpts[j].referenced_endpt_name, server_opts.ch_clients[i].ch_endpts[j].name);
                    goto ch_fail;
                }

                /* check transport */
                if (server_opts.ch_clients[i].ch_endpts[j].ti != referenced_endpt->ti) {
                    ERR(NULL, "Endpoint \"%s\" referenced by call home endpoint \"%s\" has different transport type.",
                            server_opts.ch_clients[i].ch_endpts[j].referenced_endpt_name, server_opts.ch_clients[i].ch_endpts[j].name);
                    goto ch_fail;
                } else if ((referenced_endpt->ti != NC_TI_SSH) && (referenced_endpt->ti != NC_TI_TLS)) {
                    ERR(NULL, "Endpoint \"%s\" referenced by call home endpoint \"%s\" has unsupported transport type.",
                            server_opts.ch_clients[i].ch_endpts[j].referenced_endpt_name, server_opts.ch_clients[i].ch_endpts[j].name);
                    goto ch_fail;
                }

                /* check cyclic reference */
                if (nc_server_config_check_endpt_reference_cycle(referenced_endpt, referenced_endpt)) {
                    ERR(NULL, "Endpoint \"%s\" referenced by call home endpoint \"%s\" creates a cycle.",
                            server_opts.ch_clients[i].ch_endpts[j].referenced_endpt_name, server_opts.ch_clients[i].ch_endpts[j].name);
                    goto ch_fail;
                }

                /* all went well, assign the name to the opts, so we can access it for auth */
                if (server_opts.ch_clients[i].ch_endpts[j].ti == NC_TI_SSH) {
                    server_opts.ch_clients[i].ch_endpts[j].opts.ssh->referenced_endpt_name = referenced_endpt->name;
                } else {
                    server_opts.ch_clients[i].ch_endpts[j].opts.tls->referenced_endpt_name = referenced_endpt->name;
                }
            }
        }
        /* UNLOCK */
        pthread_mutex_unlock(&server_opts.ch_clients[i].lock);
    }

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);
    return 0;

ch_fail:
    /* UNLOCK */
    pthread_mutex_unlock(&server_opts.ch_clients[i].lock);
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);
    return 1;
}

static int
nc_server_config_endpoint_reference(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt = NULL;
    struct nc_ch_client *ch_client = NULL;
    struct nc_ch_endpt *ch_endpt = NULL;
    struct nc_server_ssh_opts *ssh = NULL;
    struct nc_server_tls_opts *tls = NULL;

    assert(!strcmp(LYD_NAME(node), "endpoint-reference"));

    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    /* get endpt */
    if (is_listen(node)) {
        ret = nc_server_config_get_endpt(node, &endpt, NULL);
    } else {
        ret = nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt);
    }
    if (ret) {
        goto cleanup;
    }

    if (op == NC_OP_DELETE) {
        if (endpt) {
            /* listen */
            free(endpt->referenced_endpt_name);
            endpt->referenced_endpt_name = NULL;
        } else {
            /* call home */
            free(ch_endpt->referenced_endpt_name);
            ch_endpt->referenced_endpt_name = NULL;
        }
        if (is_ssh(node)) {
            if (nc_server_config_get_ssh_opts(node, ch_client, &ssh)) {
                ret = 1;
                goto cleanup;
            }

            ssh->referenced_endpt_name = NULL;
        } else {
            if (nc_server_config_get_tls_opts(node, ch_client, &tls)) {
                ret = 1;
                goto cleanup;
            }

            tls->referenced_endpt_name = NULL;
        }

        goto cleanup;
    } else {
        /* just set the name, check it once configuring of all nodes is done */
        if (endpt) {
            free(endpt->referenced_endpt_name);
            endpt->referenced_endpt_name = strdup(lyd_get_value(node));
            NC_CHECK_ERRMEM_GOTO(!endpt->referenced_endpt_name, ret = 1, cleanup);
        } else {
            free(ch_endpt->referenced_endpt_name);
            ch_endpt->referenced_endpt_name = strdup(lyd_get_value(node));
            NC_CHECK_ERRMEM_GOTO(!ch_endpt->referenced_endpt_name, ret = 1, cleanup);
        }

        goto cleanup;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }

    return ret;
}

static int
nc_server_config_cert_data(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_certificate *cert;
    struct nc_server_tls_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "cert-data"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (equal_parent_name(node, 3, "server-identity")) {
        if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            free(opts->cert_data);
            opts->cert_data = strdup(lyd_get_value(node));
            NC_CHECK_ERRMEM_GOTO(!opts->cert_data, ret = 1, cleanup);
        }
    } else if (equal_parent_name(node, 3, "ca-certs") || equal_parent_name(node, 3, "ee-certs")) {
        if (nc_server_config_get_cert(node, ch_client, &cert)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            free(cert->data);
            cert->data = strdup(lyd_get_value(node));
            NC_CHECK_ERRMEM_GOTO(!cert->data, ret = 1, cleanup);
        } else {
            free(cert->data);
            cert->data = NULL;
        }
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_asymmetric_key(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_server_tls_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "asymmetric-key"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* set to keystore */
        opts->store = NC_STORE_KEYSTORE;

        free(opts->key_ref);
        opts->key_ref = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_GOTO(!opts->key_ref, ret = 1, cleanup);
    } else {
        free(opts->key_ref);
        opts->key_ref = NULL;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_client_authentication(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_server_tls_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "client-authentication"));

    /* only do something on delete and if we're in the TLS subtree,
     * because this is a presence container unlike its SSH counterpart */
    if (!is_tls(node) || (op != NC_OP_DELETE)) {
        return 0;
    }

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    nc_server_config_del_certs(&opts->ca_certs);
    nc_server_config_del_certs(&opts->ee_certs);

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_ca_certs(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_server_tls_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "ca-certs"));

    /* only do something on delete and if we're in the TLS subtree,
     * because SSH certs are not yet supported */
    if (!is_tls(node) || (op != NC_OP_DELETE)) {
        return 0;
    }

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    nc_server_config_del_certs(&opts->ca_certs);

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_ee_certs(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_server_tls_opts *opts;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "ee-certs"));

    /* only do something on delete and if we're in the TLS subtree,
     * because SSH certs are not yet supported */
    if (!is_tls(node) || (op != NC_OP_DELETE)) {
        return 0;
    }

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    nc_server_config_del_certs(&opts->ee_certs);

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_create_ca_certs_certificate(const struct lyd_node *node, struct nc_server_tls_opts *opts)
{
    assert(!strcmp(LYD_NAME(node), "certificate"));

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&opts->ca_certs.certs, sizeof *opts->ca_certs.certs,
            &opts->ca_certs.cert_count);
}

static int
nc_server_config_create_ee_certs_certificate(const struct lyd_node *node, struct nc_server_tls_opts *opts)
{
    assert(!strcmp(LYD_NAME(node), "certificate"));

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&opts->ee_certs.certs, sizeof *opts->ee_certs.certs,
            &opts->ee_certs.cert_count);
}

static int
nc_server_config_certificate(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_server_tls_opts *opts;
    struct nc_ch_client *ch_client = NULL;
    struct nc_certificate *cert;

    assert(!strcmp(LYD_NAME(node), "certificate"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    if (equal_parent_name(node, 1, "central-keystore-reference")) {
        /* TLS server-identity */
        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to keystore */
            opts->store = NC_STORE_KEYSTORE;

            free(opts->cert_ref);
            opts->cert_ref = strdup(lyd_get_value(node));
            NC_CHECK_ERRMEM_GOTO(!opts->cert_ref, ret = 1, cleanup);
        } else {
            free(opts->cert_ref);
            opts->cert_ref = NULL;
        }
    } else if (equal_parent_name(node, 2, "ca-certs")) {
        /* TLS client auth certificate authority */
        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_create_ca_certs_certificate(node, opts);
            if (ret) {
                goto cleanup;
            }
        } else {
            if (nc_server_config_get_cert(node, ch_client, &cert)) {
                ret = 1;
                goto cleanup;
            }
            nc_server_config_del_cert(&opts->ca_certs, cert);
        }
    } else if (equal_parent_name(node, 2, "ee-certs")) {
        /* TLS client auth end entity */
        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_create_ee_certs_certificate(node, opts);
            if (ret) {
                goto cleanup;
            }
        } else {
            if (nc_server_config_get_cert(node, ch_client, &cert)) {
                ret = 1;
                goto cleanup;
            }
            nc_server_config_del_cert(&opts->ee_certs, cert);
        }
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_create_cert_to_name(const struct lyd_node *node, struct nc_server_tls_opts *opts)
{
    int ret = 0;
    struct lyd_node *n;
    struct nc_ctn *new, *iter;
    const char *map_type, *name = NULL;
    uint32_t id;
    NC_TLS_CTN_MAPTYPE m_type;

    assert(!strcmp(LYD_NAME(node), "cert-to-name"));

    /* find the list's key */
    lyd_find_path(node, "id", 0, &n);
    assert(n);
    id = ((struct lyd_node_term *)n)->value.uint32;

    /* get CTN map-type */
    if (lyd_find_path(node, "map-type", 0, &n)) {
        ERR(NULL, "Missing CTN map-type.");
        ret = 1;
        goto cleanup;
    }
    map_type = ((struct lyd_node_term *)n)->value.ident->name;
    if (!strcmp(map_type, "specified")) {
        m_type = NC_TLS_CTN_SPECIFIED;

        /* get CTN name */
        if (lyd_find_path(node, "name", 0, &n)) {
            ERR(NULL, "Missing CTN \"specified\" user name.");
            ret = 1;
            goto cleanup;
        }
        name = lyd_get_value(n);
    } else if (!strcmp(map_type, "san-rfc822-name")) {
        m_type = NC_TLS_CTN_SAN_RFC822_NAME;
    } else if (!strcmp(map_type, "san-dns-name")) {
        m_type = NC_TLS_CTN_SAN_DNS_NAME;
    } else if (!strcmp(map_type, "san-ip-address")) {
        m_type = NC_TLS_CTN_SAN_IP_ADDRESS;
    } else if (!strcmp(map_type, "san-any")) {
        m_type = NC_TLS_CTN_SAN_ANY;
    } else if (!strcmp(map_type, "common-name")) {
        m_type = NC_TLS_CTN_COMMON_NAME;
    } else {
        ERR(NULL, "CTN map-type \"%s\" not supported.", map_type);
        ret = 1;
        goto cleanup;
    }

    /* create new ctn */
    new = calloc(1, sizeof *new);
    NC_CHECK_ERRMEM_GOTO(!new, ret = 1, cleanup);

    /* find the right place for insertion */
    if (!opts->ctn) {
        /* inserting the first one */
        opts->ctn = new;
    } else if (opts->ctn->id > id) {
        /* insert at the beginning */
        new->next = opts->ctn;
        opts->ctn = new;
    } else {
        /* have to find the right place */
        for (iter = opts->ctn; iter->next && iter->next->id <= id; iter = iter->next) {}
        if (iter->id == id) {
            /* collision, replace */
            free(new);
            new = iter;
            free(new->name);
            new->name = NULL;
        } else {
            new->next = iter->next;
            iter->next = new;
        }
    }

    /* insert the right data */
    new->id = id;
    if (name) {
        new->name = strdup(name);
        NC_CHECK_ERRMEM_GOTO(!new->name, ret = 1, cleanup);
    }
    new->map_type = m_type;

cleanup:
    return ret;
}

static int
nc_server_config_cert_to_name(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_server_tls_opts *opts;
    struct nc_ctn *ctn;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "cert-to-name"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ret = nc_server_config_create_cert_to_name(node, opts);
        if (ret) {
            goto cleanup;
        }
    } else {
        /* find the given ctn entry */
        if (nc_server_config_get_ctn(node, ch_client, &ctn)) {
            ret = 1;
            goto cleanup;
        }
        nc_server_config_del_ctn(opts, ctn);
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_fingerprint(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_ctn *ctn;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "fingerprint"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_ctn(node, ch_client, &ctn)) {
        ret = 1;
        goto cleanup;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(ctn->fingerprint);
        ctn->fingerprint = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_GOTO(!ctn->fingerprint, ret = 1, cleanup);
    } else {
        free(ctn->fingerprint);
        ctn->fingerprint = NULL;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_tls_version(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_server_tls_opts *opts;
    const char *version = NULL;
    struct nc_ch_client *ch_client = NULL;
    NC_TLS_VERSION tls_version;

    assert(!strcmp(LYD_NAME(node), "tls-version"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    /* str to tls_version */
    version = ((struct lyd_node_term *)node)->value.ident->name;
    if (!strcmp(version, "tls10")) {
        tls_version = NC_TLS_VERSION_10;
    } else if (!strcmp(version, "tls11")) {
        tls_version = NC_TLS_VERSION_11;
    } else if (!strcmp(version, "tls12")) {
        tls_version = NC_TLS_VERSION_12;
    } else if (!strcmp(version, "tls13")) {
        tls_version = NC_TLS_VERSION_13;
    } else {
        ERR(NULL, "TLS version \"%s\" not supported.", version);
        ret = 1;
        goto cleanup;
    }

    if (op == NC_OP_CREATE) {
        /* add the version if it isn't there already */
        opts->tls_versions |= tls_version;
    } else if ((op == NC_OP_DELETE) && (opts->tls_versions & tls_version)) {
        /* delete the version if it is there */
        opts->tls_versions &= ~tls_version;
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

static int
nc_server_config_create_cipher_suite(struct nc_server_tls_opts *opts, const char *cipher)
{
    int ret = 0;
    char *processed_cipher = NULL;

    ret = nc_tls_process_cipher_suite_wrap(cipher, &processed_cipher);
    if (ret) {
        ERR(NULL, "Failed to process the cipher suite \"%s\".", cipher);
        goto cleanup;
    }

    ret = nc_tls_append_cipher_suite_wrap(opts, processed_cipher);
    if (ret) {
        ERR(NULL, "Failed to append the cipher suite \"%s\".", cipher);
        goto cleanup;
    }

cleanup:
    free(processed_cipher);
    return ret;
}

static int
nc_server_config_del_cipher_suite(struct nc_server_tls_opts *opts, const char *cipher)
{
    int ret = 0;

    ret = nc_server_config_delete_substring(opts->ciphers, cipher, ':');
    if (ret) {
        ERR(NULL, "Unable to delete a cipher (%s), which was not previously added.", cipher);
        return 1;
    }

    return 0;
}

static int
nc_server_config_cipher_suite(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_server_tls_opts *opts;
    const char *cipher = NULL;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "cipher-suite"));

    /* LOCK */
    if (is_ch(node) && nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_tls_opts(node, ch_client, &opts)) {
        ret = 1;
        goto cleanup;
    }

    cipher = ((struct lyd_node_term *)node)->value.ident->name;
    if (op == NC_OP_CREATE) {
        ret = nc_server_config_create_cipher_suite(opts, cipher);
        if (ret) {
            goto cleanup;
        }
    } else if (op == NC_OP_DELETE) {
        ret = nc_server_config_del_cipher_suite(opts, cipher);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    if (is_ch(node)) {
        /* UNLOCK */
        nc_ch_client_unlock(ch_client);
    }
    return ret;
}

#endif /* NC_ENABLED_SSH_TLS */

static int
nc_server_config_create_netconf_client(const struct lyd_node *node)
{
    int ret = 0;

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    /* LOCK */
    pthread_rwlock_wrlock(&server_opts.ch_client_lock);

    ret = nc_server_config_realloc(lyd_get_value(node), (void **)&server_opts.ch_clients, sizeof *server_opts.ch_clients, &server_opts.ch_client_count);
    if (ret) {
        goto cleanup;
    }

    server_opts.ch_clients[server_opts.ch_client_count - 1].id = ATOMIC_INC_RELAXED(server_opts.new_client_id);
    server_opts.ch_clients[server_opts.ch_client_count - 1].start_with = NC_CH_FIRST_LISTED;
    server_opts.ch_clients[server_opts.ch_client_count - 1].max_attempts = 3;

    pthread_mutex_init(&server_opts.ch_clients[server_opts.ch_client_count - 1].lock, NULL);

cleanup:
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.ch_client_lock);
    return ret;
}

static int
nc_server_config_netconf_client(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "netconf-client"));

    if (op == NC_OP_CREATE) {
        ret = nc_server_config_create_netconf_client(node);
        if (ret) {
            goto cleanup;
        }

#ifdef NC_ENABLED_SSH_TLS
        if (server_opts.ch_dispatch_data.acquire_ctx_cb && server_opts.ch_dispatch_data.release_ctx_cb &&
                server_opts.ch_dispatch_data.new_session_cb) {
            /* we have all we need for dispatching a new call home thread */
            ret = nc_connect_ch_client_dispatch(lyd_get_value(lyd_child(node)), server_opts.ch_dispatch_data.acquire_ctx_cb,
                    server_opts.ch_dispatch_data.release_ctx_cb, server_opts.ch_dispatch_data.ctx_cb_data,
                    server_opts.ch_dispatch_data.new_session_cb, server_opts.ch_dispatch_data.new_session_cb_data);
            if (ret) {
                ERR(NULL, "Dispatching a new Call Home thread failed for Call Home client \"%s\".", lyd_get_value(lyd_child(node)));
                goto cleanup;
            }
        }
#endif /* NC_ENABLED_SSH_TLS */
    } else if (op == NC_OP_DELETE) {
        nc_server_config_ch_del_client(node);
    }

cleanup:
    return ret;
}

#ifdef NC_ENABLED_SSH_TLS

static int
nc_server_config_remote_address(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_ch_endpt *ch_endpt;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "remote-address"));

    /* LOCK */
    if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
        ret = 1;
        goto cleanup;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(ch_endpt->dst_addr);
        ch_endpt->dst_addr = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_GOTO(!ch_endpt->dst_addr, ret = 1, cleanup);
    } else {
        free(ch_endpt->dst_addr);
        ch_endpt->dst_addr = NULL;
    }

cleanup:
    /* UNLOCK */
    nc_ch_client_unlock(ch_client);
    return ret;
}

static int
nc_server_config_remote_port(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_ch_endpt *ch_endpt;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "remote-port"));

    /* LOCK */
    if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (nc_server_config_get_ch_endpt(node, ch_client, &ch_endpt)) {
        ret = 1;
        goto cleanup;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ch_endpt->dst_port = ((struct lyd_node_term *)node)->value.uint16;
    } else {
        ch_endpt->dst_port = 0;
    }

cleanup:
    /* UNLOCK */
    nc_ch_client_unlock(ch_client);
    return ret;
}

#endif /* NC_ENABLED_SSH_TLS */

static int
nc_server_config_persistent(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "persistent"));

    /* switch to periodic, don't do anything */
    if (op == NC_OP_DELETE) {
        return 0;
    }

    /* LOCK */
    if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    ch_client->conn_type = NC_CH_PERSIST;

    /* UNLOCK */
    nc_ch_client_unlock(ch_client);

    return ret;
}

static int
nc_server_config_periodic(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "periodic"));

    /* switch to persistent, don't do anything */
    if (op == NC_OP_DELETE) {
        return 0;
    }

    /* LOCK */
    if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    ch_client->conn_type = NC_CH_PERIOD;
    /* set default values */
    ch_client->period = 60;
    ch_client->anchor_time = 0;
    ch_client->idle_timeout = 180;

    /* UNLOCK */
    nc_ch_client_unlock(ch_client);

    return ret;
}

static int
nc_server_config_period(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "period"));

    /* LOCK */
    if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ch_client->period = ((struct lyd_node_term *)node)->value.uint16;
    } else if (op == NC_OP_DELETE) {
        ch_client->period = 60;
    }

    /* UNLOCK */
    nc_ch_client_unlock(ch_client);

    return ret;
}

static int
nc_server_config_anchor_time(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_ch_client *ch_client = NULL;
    struct lyd_value_date_and_time *anchor_time;

    assert(!strcmp(LYD_NAME(node), "anchor-time"));

    /* LOCK */
    if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    /* get the value of time from the node directly */
    LYD_VALUE_GET(&((struct lyd_node_term *)node)->value, anchor_time);

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ch_client->anchor_time = anchor_time->time;
    } else if (op == NC_OP_DELETE) {
        ch_client->anchor_time = 0;
    }

    /* UNLOCK */
    nc_ch_client_unlock(ch_client);
    return ret;
}

static int
nc_server_config_reconnect_strategy(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "reconnect-strategy"));

    (void) op;

    /* LOCK */
    if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    /* set to default values */
    ch_client->start_with = NC_CH_FIRST_LISTED;
    ch_client->max_wait = 5;
    ch_client->max_attempts = 3;

    /* UNLOCK */
    nc_ch_client_unlock(ch_client);

    return ret;
}

static int
nc_server_config_start_with(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_ch_client *ch_client = NULL;
    const char *value;

    assert(!strcmp(LYD_NAME(node), "start-with"));

    /* LOCK */
    if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if (op == NC_OP_DELETE) {
        ch_client->start_with = NC_CH_FIRST_LISTED;
        goto cleanup;
    }

    value = lyd_get_value(node);
    if (!strcmp(value, "first-listed")) {
        ch_client->start_with = NC_CH_FIRST_LISTED;
    } else if (!strcmp(value, "last-connected")) {
        ch_client->start_with = NC_CH_LAST_CONNECTED;
    } else if (!strcmp(value, "random-selection")) {
        ch_client->start_with = NC_CH_RANDOM;
    } else {
        ERR(NULL, "Unexpected start-with value \"%s\".", value);
        ret = 1;
        goto cleanup;
    }

cleanup:
    /* UNLOCK */
    nc_ch_client_unlock(ch_client);
    return ret;
}

static int
nc_server_config_max_wait(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "max-wait"));

    /* LOCK */
    if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ch_client->max_wait = ((struct lyd_node_term *)node)->value.uint16;
    } else {
        ch_client->max_wait = 5;
    }

    /* UNLOCK */
    nc_ch_client_unlock(ch_client);

    return ret;
}

static int
nc_server_config_max_attempts(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_ch_client *ch_client = NULL;

    assert(!strcmp(LYD_NAME(node), "max-attempts"));

    /* LOCK */
    if (nc_server_config_get_ch_client_with_lock(node, &ch_client)) {
        /* to avoid unlock on fail */
        return 1;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ch_client->max_attempts = ((struct lyd_node_term *)node)->value.uint8;
    } else {
        ch_client->max_attempts = 3;
    }

    /* UNLOCK */
    nc_ch_client_unlock(ch_client);

    return ret;
}

static int
nc_server_config_parse_netconf_server(const struct lyd_node *node, NC_OPERATION op)
{
    const char *name = LYD_NAME(node);
    int ret = 0;

    if (!strcmp(name, "anchor-time")) {
        ret = nc_server_config_anchor_time(node, op);
    } else if (!strcmp(name, "call-home")) {
        ret = nc_server_config_ch(node, op);
    } else if (!strcmp(name, "endpoint")) {
        ret = nc_server_config_endpoint(node, op);
    } else if (!strcmp(name, "idle-timeout")) {
        ret = nc_server_config_idle_timeout(node, op);
    } else if (!strcmp(name, "listen")) {
        ret = nc_server_config_listen(node, op);
    } else if (!strcmp(name, "max-attempts")) {
        ret = nc_server_config_max_attempts(node, op);
    } else if (!strcmp(name, "max-wait")) {
        ret = nc_server_config_max_wait(node, op);
    } else if (!strcmp(name, "netconf-client")) {
        ret = nc_server_config_netconf_client(node, op);
    } else if (!strcmp(name, "period")) {
        ret = nc_server_config_period(node, op);
    } else if (!strcmp(name, "periodic")) {
        ret = nc_server_config_periodic(node, op);
    } else if (!strcmp(name, "persistent")) {
        ret = nc_server_config_persistent(node, op);
    } else if (!strcmp(name, "reconnect-strategy")) {
        ret = nc_server_config_reconnect_strategy(node, op);
    } else if (!strcmp(name, "start-with")) {
        ret = nc_server_config_start_with(node, op);
    }
#ifdef NC_ENABLED_SSH_TLS
    else if (!strcmp(name, "auth-timeout")) {
        ret = nc_server_config_auth_timeout(node, op);
    } else if (!strcmp(name, "asymmetric-key")) {
        ret = nc_server_config_asymmetric_key(node, op);
    } else if (!strcmp(name, "ca-certs")) {
        ret = nc_server_config_ca_certs(node, op);
    } else if (!strcmp(name, "central-keystore-reference")) {
        ret = nc_server_config_keystore_reference(node, op);
    } else if (!strcmp(name, "central-truststore-reference")) {
        ret = nc_server_config_truststore_reference(node, op);
    } else if (!strcmp(name, "cert-data")) {
        ret = nc_server_config_cert_data(node, op);
    } else if (!strcmp(name, "certificate")) {
        ret = nc_server_config_certificate(node, op);
    } else if (!strcmp(name, "cert-to-name")) {
        ret = nc_server_config_cert_to_name(node, op);
    } else if (!strcmp(name, "cipher-suite")) {
        ret = nc_server_config_cipher_suite(node, op);
    } else if (!strcmp(name, "cleartext-private-key")) {
        ret = nc_server_config_cleartext_private_key(node, op);
    } else if (!strcmp(name, "client-authentication")) {
        ret = nc_server_config_client_authentication(node, op);
    } else if (!strcmp(name, "ee-certs")) {
        ret = nc_server_config_ee_certs(node, op);
    } else if (!strcmp(name, "encryption-alg")) {
        ret = nc_server_config_encryption_alg(node, op);
    } else if (!strcmp(name, "endpoint-reference")) {
        ret = nc_server_config_endpoint_reference(node, op);
    } else if (!strcmp(name, "fingerprint")) {
        ret = nc_server_config_fingerprint(node, op);
    } else if (!strcmp(name, "host-key")) {
        ret = nc_server_config_host_key(node, op);
    } else if (!strcmp(name, "host-key-alg")) {
        ret = nc_server_config_host_key_alg(node, op);
    } else if (!strcmp(name, "idle-time")) {
        ret = nc_server_config_idle_time(node, op);
    } else if (!strcmp(name, "keepalives")) {
        ret = nc_server_config_keepalives(node, op);
    } else if (!strcmp(name, "key-exchange-alg")) {
        ret = nc_server_config_kex_alg(node, op);
    } else if (!strcmp(name, "local-address")) {
        ret = nc_server_config_local_address(node, op);
    } else if (!strcmp(name, "local-port")) {
        ret = nc_server_config_local_port(node, op);
    } else if (!strcmp(name, "mac-alg")) {
        ret = nc_server_config_mac_alg(node, op);
    } else if (!strcmp(name, "max-probes")) {
        ret = nc_server_config_max_probes(node, op);
    } else if (!strcmp(name, "none")) {
        ret = nc_server_config_none(node, op);
    } else if (!strcmp(name, "password")) {
        ret = nc_server_config_password(node, op);
    } else if (!strcmp(name, "private-key-format")) {
        ret = nc_server_config_private_key_format(node, op);
    } else if (!strcmp(name, "probe-interval")) {
        ret = nc_server_config_probe_interval(node, op);
    } else if (!strcmp(name, "public-key")) {
        ret = nc_server_config_public_key(node, op);
    } else if (!strcmp(name, "public-key-format")) {
        ret = nc_server_config_public_key_format(node, op);
    } else if (!strcmp(name, "public-keys")) {
        ret = nc_server_config_public_keys(node, op);
    } else if (!strcmp(name, "remote-address")) {
        ret = nc_server_config_remote_address(node, op);
    } else if (!strcmp(name, "remote-port")) {
        ret = nc_server_config_remote_port(node, op);
    } else if (!strcmp(name, "ssh")) {
        ret = nc_server_config_ssh(node, op);
    } else if (!strcmp(name, "tls")) {
        ret = nc_server_config_tls(node, op);
    } else if (!strcmp(name, "tls-version")) {
        ret = nc_server_config_tls_version(node, op);
    } else if (!strcmp(name, "user")) {
        ret = nc_server_config_user(node, op);
    } else if (!strcmp(name, "use-system-auth")) {
        ret = nc_server_config_use_system_auth(node, op);
    } else if (!strcmp(name, "use-system-keys")) {
        ret = nc_server_config_use_system_keys(node, op);
    }
#endif /* NC_ENABLED_SSH_TLS */

    if (ret) {
        ERR(NULL, "Configuring node \"%s\" failed.", LYD_NAME(node));
        return 1;
    }

    return 0;
}

int
nc_server_config_ln2_netconf_server(const struct lyd_node *node, NC_OPERATION op)
{
    (void) node;

    assert((op == NC_OP_CREATE) || (op == NC_OP_DELETE));

    if (op == NC_OP_DELETE) {

#ifdef NC_ENABLED_SSH_TLS
        /* delete the intervals */
        pthread_mutex_lock(&server_opts.cert_exp_notif.lock);
        free(server_opts.cert_exp_notif.intervals);
        server_opts.cert_exp_notif.intervals = NULL;
        server_opts.cert_exp_notif.interval_count = 0;
        pthread_mutex_unlock(&server_opts.cert_exp_notif.lock);
#endif /* NC_ENABLED_SSH_TLS */

    }

    return 0;
}

#ifdef NC_ENABLED_SSH_TLS

static int
nc_server_config_yang_value2cert_exp_time(const char *value, struct nc_cert_exp_time *cert_exp_time)
{
    char unit;
    long val;

    unit = value[strlen(value) - 1];
    val = strtol(value, NULL, 10);
    switch (unit) {
    case 'm':
        cert_exp_time->months = val;
        break;
    case 'w':
        cert_exp_time->weeks = val;
        break;
    case 'd':
        cert_exp_time->days = val;
        break;
    case 'h':
        cert_exp_time->hours = val;
        break;
    default:
        ERR(NULL, "Unexpected unit in the certificate expiration time \"%s\".", value);
        return 1;
    }

    return 0;
}

static int
nc_server_config_create_interval(const char *anchor, const char *period)
{
    int ret = 0;
    struct nc_cert_exp_time anchor_time = {0}, period_time = {0};

    server_opts.cert_exp_notif.intervals = nc_realloc(server_opts.cert_exp_notif.intervals,
            (server_opts.cert_exp_notif.interval_count + 1) * sizeof *server_opts.cert_exp_notif.intervals);
    NC_CHECK_ERRMEM_RET(!server_opts.cert_exp_notif.intervals, 1);

    /* convert and set the anchor */
    ret = nc_server_config_yang_value2cert_exp_time(anchor, &anchor_time);
    if (ret) {
        goto cleanup;
    }
    server_opts.cert_exp_notif.intervals[server_opts.cert_exp_notif.interval_count].anchor = anchor_time;

    /* convert and set the period */
    ret = nc_server_config_yang_value2cert_exp_time(period, &period_time);
    if (ret) {
        goto cleanup;
    }
    server_opts.cert_exp_notif.intervals[server_opts.cert_exp_notif.interval_count].period = period_time;

    ++server_opts.cert_exp_notif.interval_count;

cleanup:
    return ret;
}

static void
nc_server_config_del_interval(const char *anchor, const char *period)
{
    int i;
    struct nc_cert_exp_time anchor_time = {0}, period_time = {0};

    if (nc_server_config_yang_value2cert_exp_time(anchor, &anchor_time)) {
        return;
    }
    if (nc_server_config_yang_value2cert_exp_time(period, &period_time)) {
        return;
    }

    for (i = 0; i < server_opts.cert_exp_notif.interval_count; ++i) {
        if (!memcmp(&server_opts.cert_exp_notif.intervals[i].anchor, &anchor_time, sizeof anchor_time) &&
                !memcmp(&server_opts.cert_exp_notif.intervals[i].period, &period_time, sizeof period_time)) {
            break;
        }
    }
    if (i == server_opts.cert_exp_notif.interval_count) {
        ERR(NULL, "Interval \"%s %s\" not found.", anchor, period);
        return;
    }

    server_opts.cert_exp_notif.interval_count--;
    if (!server_opts.cert_exp_notif.interval_count) {
        free(server_opts.cert_exp_notif.intervals);
        server_opts.cert_exp_notif.intervals = NULL;
    } else if (i != server_opts.cert_exp_notif.interval_count) {
        server_opts.cert_exp_notif.intervals[i] =
                server_opts.cert_exp_notif.intervals[server_opts.cert_exp_notif.interval_count];
    }
}

static int
nc_server_config_interval(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct lyd_node *anchor, *period;

    assert(!strcmp(LYD_NAME(node), "interval"));

    anchor = lyd_child(node);
    assert(anchor);
    period = anchor->next;
    assert(period);

    /* LOCK */
    pthread_mutex_lock(&server_opts.cert_exp_notif.lock);

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ret = nc_server_config_create_interval(lyd_get_value(anchor), lyd_get_value(period));
        if (ret) {
            goto cleanup;
        }
    } else {
        nc_server_config_del_interval(lyd_get_value(anchor), lyd_get_value(period));
    }

cleanup:
    pthread_mutex_unlock(&server_opts.cert_exp_notif.lock);
    return ret;
}

#endif /* NC_ENABLED_SSH_TLS */

static int
nc_server_config_parse_libnetconf2_netconf_server(const struct lyd_node *node, NC_OPERATION op)
{
    const char *name = LYD_NAME(node);
    int ret = 0;

    if (!strcmp(name, "ln2-netconf-server")) {
        ret = nc_server_config_ln2_netconf_server(node, op);
    }
#ifdef NC_ENABLED_SSH_TLS
    else if (!strcmp(name, "interval")) {
        ret = nc_server_config_interval(node, op);
    }
#endif /* NC_ENABLED_SSH_TLS */

    if (ret) {
        ERR(NULL, "Configuring node \"%s\" failed.", LYD_NAME(node));
        return 1;
    }

    return 0;
}

int
nc_server_config_parse_tree(const struct lyd_node *node, NC_OPERATION parent_op, NC_MODULE module)
{
    struct lyd_node *child;
    struct lyd_meta *m;
    NC_OPERATION current_op = NC_OP_UNKNOWN;
    int ret;

    assert(node);

    /* get current op if there is any */
    if ((m = lyd_find_meta(node->meta, NULL, "yang:operation"))) {
        if (!strcmp(lyd_get_meta_value(m), "create")) {
            current_op = NC_OP_CREATE;
        } else if (!strcmp(lyd_get_meta_value(m), "delete")) {
            current_op = NC_OP_DELETE;
        } else if (!strcmp(lyd_get_meta_value(m), "replace")) {
            current_op = NC_OP_REPLACE;
        } else if (!strcmp(lyd_get_meta_value(m), "none")) {
            current_op = NC_OP_NONE;
        }
    }

    /* node has no op, inherit from the parent */
    if (!current_op) {
        if (!parent_op) {
            ERR(NULL, "Unknown operation for node \"%s\".", LYD_NAME(node));
            return 1;
        }

        current_op = parent_op;
    }

    switch (current_op) {
    case NC_OP_NONE:
        break;
    case NC_OP_CREATE:
    case NC_OP_DELETE:
    case NC_OP_REPLACE:
#ifdef NC_ENABLED_SSH_TLS
        if (module == NC_MODULE_KEYSTORE) {
            ret = nc_server_config_parse_keystore(node, current_op);
        } else if (module == NC_MODULE_TRUSTSTORE) {
            ret = nc_server_config_parse_truststore(node, current_op);
        } else
#endif /* NC_ENABLED_SSH_TLS */
        if (module == NC_MODULE_LIBNETCONF2_NETCONF_SERVER) {
            ret = nc_server_config_parse_libnetconf2_netconf_server(node, current_op);
        } else if (module == NC_MODULE_NETCONF_SERVER) {
            ret = nc_server_config_parse_netconf_server(node, current_op);
        } else {
            ERRINT;
            ret = 1;
        }
        if (ret) {
            return ret;
        }
        break;
    default:
        break;
    }

    if (current_op != NC_OP_DELETE) {
        LY_LIST_FOR(lyd_child(node), child) {
            if (nc_server_config_parse_tree(child, current_op, module)) {
                return 1;
            }
        }
    }
    return 0;
}

API int
nc_server_config_load_modules(struct ly_ctx **ctx)
{
    int i, new_ctx = 0;

    if (!*ctx) {
        if (ly_ctx_new(NC_SERVER_SEARCH_DIR, 0, ctx)) {
            ERR(NULL, "Couldn't create new libyang context.\n");
            goto error;
        }
        new_ctx = 1;
    }

    /* all features */
    const char *ietf_nectonf_server[] = {"ssh-listen", "tls-listen", "ssh-call-home", "tls-call-home", "central-netconf-server-supported", NULL};
    /* all features */
    const char *ietf_x509_cert_to_name[] = {NULL};
    /* no private-key-encryption, csr-generation, p10-csr-format, certificate-expiration-notification,
     * encrypted-passwords, hidden-symmetric-keys, encrypted-symmetric-keys, hidden-private-keys, encrypted-private-keys,
     * one-symmetric-key-format, one-asymmetric-key-format, symmetrically-encrypted-value-format,
     * asymmetrically-encrypted-value-format, cms-enveloped-data-format, cms-encrypted-data-format,
     * cleartext-symmetric-keys */
    const char *ietf_crypto_types[] = {"cleartext-passwords", "cleartext-private-keys", NULL};
    /* all features */
    const char *ietf_tcp_common[] = {"keepalives-supported", NULL};
    /* all features */
    const char *ietf_tcp_server[] = {"tcp-server-keepalives", NULL};
    /* no proxy-connect, socks5-gss-api, socks5-username-password */
    const char *ietf_tcp_client[] = {"local-binding-supported", "tcp-client-keepalives", NULL};
    /* no ssh-x509-certs, public-key-generation */
    const char *ietf_ssh_common[] = {"transport-params", NULL};
    /* no ssh-server-keepalives and local-user-auth-hostbased */
    const char *ietf_ssh_server[] = {"local-users-supported", "local-user-auth-publickey", "local-user-auth-password", "local-user-auth-none", NULL};
    /* all features */
    const char *iana_ssh_encryption_algs[] = {NULL};
    /* all features */
    const char *iana_ssh_key_exchange_algs[] = {NULL};
    /* all features */
    const char *iana_ssh_mac_algs[] = {NULL};
    /* all features */
    const char *iana_ssh_public_key_algs[] = {NULL};
    /* all features */
    const char *iana_crypt_hash[] = {"crypt-hash-md5", "crypt-hash-sha-256", "crypt-hash-sha-512", NULL};
    /* no symmetric-keys */
    const char *ietf_keystore[] = {"central-keystore-supported", "inline-definitions-supported", "asymmetric-keys", NULL};
    /* all features */
    const char *ietf_truststore[] = {"central-truststore-supported", "inline-definitions-supported", "certificates", "public-keys", NULL};
    /* no public-key-generation */
    const char *ietf_tls_common[] = {"tls10", "tls11", "tls12", "tls13", "hello-params", NULL};
    /* no tls-server-keepalives, server-ident-raw-public-key, server-ident-tls12-psk, server-ident-tls13-epsk,
     * client-auth-raw-public-key, client-auth-tls12-psk, client-auth-tls13-epsk */
    const char *ietf_tls_server[] = {"server-ident-x509-cert", "client-auth-supported", "client-auth-x509-cert", NULL};
    /* all features */
    const char *iana_tls_cipher_suite_algs[] = {NULL};
    /* all features */
    const char *libnetconf2_netconf_server[] = {NULL};

    const char *module_names[] = {
        "ietf-netconf-server", "ietf-x509-cert-to-name", "ietf-crypto-types", "ietf-tcp-common", "ietf-tcp-server",
        "ietf-tcp-client", "ietf-ssh-common", "ietf-ssh-server", "iana-ssh-encryption-algs",
        "iana-ssh-key-exchange-algs", "iana-ssh-mac-algs", "iana-ssh-public-key-algs", "iana-crypt-hash",
        "ietf-keystore", "ietf-truststore", "ietf-tls-common", "ietf-tls-server", "iana-tls-cipher-suite-algs",
        "libnetconf2-netconf-server", NULL
    };

    const char **module_features[] = {
        ietf_nectonf_server, ietf_x509_cert_to_name, ietf_crypto_types, ietf_tcp_common,
        ietf_tcp_server, ietf_tcp_client, ietf_ssh_common, ietf_ssh_server, iana_ssh_encryption_algs,
        iana_ssh_key_exchange_algs, iana_ssh_mac_algs, iana_ssh_public_key_algs, iana_crypt_hash,
        ietf_keystore, ietf_truststore, ietf_tls_common, ietf_tls_server, iana_tls_cipher_suite_algs,
        libnetconf2_netconf_server, NULL
    };

    for (i = 0; module_names[i] != NULL; i++) {
        if (!ly_ctx_load_module(*ctx, module_names[i], NULL, module_features[i])) {
            ERR(NULL, "Loading module \"%s\" failed.\n", module_names[i]);
            goto error;
        }
    }

    return 0;

error:
    if (new_ctx) {
        ly_ctx_destroy(*ctx);
        *ctx = NULL;
    }
    return 1;
}

static int
nc_server_config_fill_netconf_server(const struct lyd_node *data, NC_OPERATION op)
{
    int ret = 0;
    uint32_t log_options = 0;
    struct lyd_node *tree;

    /* silently search for ietf-netconf-server, it may not be present */
    ly_temp_log_options(&log_options);

    ret = lyd_find_path(data, "/ietf-netconf-server:netconf-server", 0, &tree);
    if (ret || (tree->flags & LYD_DEFAULT)) {
        /* not found */
        ret = 0;
        goto cleanup;
    }

    if (nc_server_config_parse_tree(tree, op, NC_MODULE_NETCONF_SERVER)) {
        ret = 1;
        goto cleanup;
    }

#ifdef NC_ENABLED_SSH_TLS
    /* check and set all endpoint references */
    if (nc_server_config_check_endpt_references()) {
        ret = 1;
        goto cleanup;
    }
#endif /* NC_ENABLED_SSH_TLS */

cleanup:
    /* reset the logging options back to what they were */
    ly_temp_log_options(NULL);
    return ret;
}

static int
nc_server_config_fill_libnetconf2_netconf_server(const struct lyd_node *data, NC_OPERATION op)
{
    int ret = 0;
    struct lyd_node *tree;
    uint32_t log_options = 0;

    /* silently search for ln2-netconf-server, it may not be present */
    ly_temp_log_options(&log_options);

    ret = lyd_find_path(data, "/libnetconf2-netconf-server:ln2-netconf-server", 0, &tree);
    if (ret || (tree->flags & LYD_DEFAULT)) {
        /* not found */
        ret = 0;
        goto cleanup;
    }

    if (nc_server_config_parse_tree(tree, op, NC_MODULE_LIBNETCONF2_NETCONF_SERVER)) {
        ret = 1;
        goto cleanup;
    }

cleanup:
    /* reset the logging options back to what they were */
    ly_temp_log_options(NULL);
    return ret;
}

API int
nc_server_config_setup_diff(const struct lyd_node *data)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, data, 1);

    /* LOCK */
    pthread_rwlock_wrlock(&server_opts.config_lock);

#ifdef NC_ENABLED_SSH_TLS
    /* configure keystore */
    ret = nc_server_config_fill_keystore(data, NC_OP_UNKNOWN);
    if (ret) {
        ERR(NULL, "Applying ietf-keystore configuration failed.");
        goto cleanup;
    }

    /* configure truststore */
    ret = nc_server_config_fill_truststore(data, NC_OP_UNKNOWN);
    if (ret) {
        ERR(NULL, "Applying ietf-truststore configuration failed.");
        goto cleanup;
    }
#endif /* NC_ENABLED_SSH_TLS */

    /* configure netconf-server */
    ret = nc_server_config_fill_netconf_server(data, NC_OP_UNKNOWN);
    if (ret) {
        ERR(NULL, "Applying ietf-netconf-server configuration failed.");
        goto cleanup;
    }

    /* configure libnetconf2-netconf-server */
    ret = nc_server_config_fill_libnetconf2_netconf_server(data, NC_OP_UNKNOWN);
    if (ret) {
        ERR(NULL, "Applying libnetconf2-netconf-server configuration failed.");
        goto cleanup;
    }

#ifdef NC_ENABLED_SSH_TLS
    /* wake up the cert expiration notif thread if it's running */
    pthread_mutex_lock(&server_opts.cert_exp_notif.lock);
    if (server_opts.cert_exp_notif.thread_running) {
        pthread_cond_signal(&server_opts.cert_exp_notif.cond);
    }
    pthread_mutex_unlock(&server_opts.cert_exp_notif.lock);
#endif /* NC_ENABLED_SSH_TLS */

cleanup:
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);
    return ret;
}

API int
nc_server_config_setup_data(const struct lyd_node *data)
{
    int ret = 0;
    struct lyd_node *tree, *iter, *root;

    NC_CHECK_ARG_RET(NULL, data, 1);

    /* LOCK */
    pthread_rwlock_wrlock(&server_opts.config_lock);

    /* find the netconf-server node */
    ret = lyd_find_path(data, "/ietf-netconf-server:netconf-server", 0, &root);
    if (ret) {
        ERR(NULL, "Unable to find the netconf-server container in the YANG data.");
        goto cleanup;
    }

    /* iterate through all the nodes and make sure there is no operation attribute */
    LY_LIST_FOR(root, tree) {
        LYD_TREE_DFS_BEGIN(tree, iter) {
            if (lyd_find_meta(iter->meta, NULL, "yang:operation")) {
                ERR(NULL, "Unexpected operation attribute in the YANG data.");
                ret = 1;
                goto cleanup;
            }
            LYD_TREE_DFS_END(tree, iter);
        }
    }

    /* delete the current configuration */
    nc_server_config_listen(NULL, NC_OP_DELETE);
    nc_server_config_ch(NULL, NC_OP_DELETE);
#ifdef NC_ENABLED_SSH_TLS
    nc_server_config_ks_keystore(NULL, NC_OP_DELETE);
    nc_server_config_ts_truststore(NULL, NC_OP_DELETE);

    /* configure keystore */
    ret = nc_server_config_fill_keystore(data, NC_OP_CREATE);
    if (ret) {
        ERR(NULL, "Applying ietf-keystore configuration failed.");
        goto cleanup;
    }

    /* configure truststore */
    ret = nc_server_config_fill_truststore(data, NC_OP_CREATE);
    if (ret) {
        ERR(NULL, "Applying ietf-truststore configuration failed.");
        goto cleanup;
    }
#endif /* NC_ENABLED_SSH_TLS */

    /* configure netconf-server */
    ret = nc_server_config_fill_netconf_server(data, NC_OP_CREATE);
    if (ret) {
        ERR(NULL, "Applying ietf-netconf-server configuration failed.");
        goto cleanup;
    }

    /* configure libnetconf2-netconf-server */
    ret = nc_server_config_fill_libnetconf2_netconf_server(data, NC_OP_CREATE);
    if (ret) {
        ERR(NULL, "Applying libnetconf2-netconf-server configuration failed.");
        goto cleanup;
    }

#ifdef NC_ENABLED_SSH_TLS
    /* wake up the cert expiration notif thread if it's running */
    pthread_mutex_lock(&server_opts.cert_exp_notif.lock);
    if (server_opts.cert_exp_notif.thread_running) {
        pthread_cond_signal(&server_opts.cert_exp_notif.cond);
    }
    pthread_mutex_unlock(&server_opts.cert_exp_notif.lock);
#endif /* NC_ENABLED_SSH_TLS */

cleanup:
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);
    return ret;
}

API int
nc_server_config_setup_path(const struct ly_ctx *ctx, const char *path)
{
    struct lyd_node *tree = NULL;
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, path, 1);

    ret = lyd_parse_data_path(ctx, path, LYD_UNKNOWN, LYD_PARSE_NO_STATE | LYD_PARSE_STRICT, LYD_VALIDATE_NO_STATE, &tree);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_setup_data(tree);
    if (ret) {
        goto cleanup;
    }

cleanup:
    lyd_free_all(tree);
    return ret;
}

#ifdef NC_ENABLED_SSH_TLS

static int
nc_server_config_oper_get_algs(const struct ly_ctx *ctx, const char *mod_name, const char *ln2_algs[],
        const char *mod_algs[], struct lyd_node **algs)
{
    int ret, r, i;
    struct lyd_node *parent = NULL;
    char *path = NULL;

    NC_CHECK_ARG_RET(NULL, ctx, mod_name, ln2_algs, mod_algs, algs, 1);

    *algs = NULL;

    r = asprintf(&path, "/%s:supported-algorithms", mod_name);
    NC_CHECK_ERRMEM_RET(r == -1, 1);

    /* create supported algorithms container */
    ret = lyd_new_path(NULL, ctx, path, NULL, 0, &parent);
    free(path);
    if (ret) {
        ERR(NULL, "Creating supported algorithms container failed.");
        goto cleanup;
    }

    /* append algs from libnetconf2-netconf-server */
    for (i = 0; ln2_algs[i]; i++) {
        r = asprintf(&path, "libnetconf2-netconf-server:%s", ln2_algs[i]);
        NC_CHECK_ERRMEM_GOTO(r == -1, ret = 1, cleanup);
        ret = lyd_new_term(parent, NULL, "supported-algorithm", path, 0, NULL);
        free(path);
        if (ret) {
            ERR(NULL, "Creating new supported algorithm failed.");
            goto cleanup;
        }
    }

    /* append algs from mod_name module */
    for (i = 0; mod_algs[i]; i++) {
        r = asprintf(&path, "%s:%s", mod_name, mod_algs[i]);
        NC_CHECK_ERRMEM_GOTO(r == -1, ret = 1, cleanup);
        ret = lyd_new_term(parent, NULL, "supported-algorithm", path, 0, NULL);
        free(path);
        if (ret) {
            ERR(NULL, "Creating new supported algorithm failed.");
            goto cleanup;
        }
    }

cleanup:
    if (ret) {
        lyd_free_tree(parent);
    } else {
        *algs = parent;
    }
    return ret;
}

API int
nc_server_config_oper_get_hostkey_algs(const struct ly_ctx *ctx, struct lyd_node **hostkey_algs)
{
    /* identities of hostkey algs supported by libssh (v0.10.5) defined in libnetconf2-netconf-server yang module */
    const char *libnetconf2_hostkey_algs[] = {
        "openssh-ssh-ed25519-cert-v01", "openssh-ecdsa-sha2-nistp521-cert-v01",
        "openssh-ecdsa-sha2-nistp384-cert-v01", "openssh-ecdsa-sha2-nistp256-cert-v01",
        "openssh-rsa-sha2-512-cert-v01", "openssh-rsa-sha2-256-cert-v01",
        "openssh-ssh-rsa-cert-v01", "openssh-ssh-dss-cert-v01", NULL
    };

    /* identities of hostkey algs supported by libssh (v0.10.5) defined in iana-ssh-public-key-algs yang module */
    const char *iana_hostkey_algs[] = {
        "ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256",
        "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss", NULL
    };

    NC_CHECK_ARG_RET(NULL, ctx, hostkey_algs, 1);

    return nc_server_config_oper_get_algs(ctx, "iana-ssh-public-key-algs", libnetconf2_hostkey_algs,
            iana_hostkey_algs, hostkey_algs);
}

API int
nc_server_config_oper_get_kex_algs(const struct ly_ctx *ctx, struct lyd_node **kex_algs)
{
    /* identities of kex algs supported by libssh (v0.10.5) defined in libnetconf2-netconf-server yang module */
    const char *libnetconf2_kex_algs[] = {
        "libssh-curve25519-sha256", NULL
    };

    /* identities of kex algs supported by libssh (v0.10.5) defined in iana-ssh-key-exchange-algs yang module */
    const char *iana_kex_algs[] = {
        "diffie-hellman-group-exchange-sha1", "curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521", "diffie-hellman-group18-sha512", "diffie-hellman-group16-sha512",
        "diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha256", NULL
    };

    NC_CHECK_ARG_RET(NULL, ctx, kex_algs, 1);

    return nc_server_config_oper_get_algs(ctx, "iana-ssh-key-exchange-algs", libnetconf2_kex_algs,
            iana_kex_algs, kex_algs);
}

API int
nc_server_config_oper_get_encryption_algs(const struct ly_ctx *ctx, struct lyd_node **encryption_algs)
{
    /* identities of encryption algs supported by libssh (v0.10.5) defined in libnetconf2-netconf-server yang module */
    const char *libnetconf2_encryption_algs[] = {
        "openssh-chacha20-poly1305", "openssh-aes256-gcm", "openssh-aes128-gcm", NULL
    };

    /* identities of encryption algs supported by libssh (v0.10.5) defined in iana-ssh-encryption-algs yang module */
    const char *iana_encryption_algs[] = {
        "aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc",
        "blowfish-cbc", "triple-des-cbc", "none", NULL
    };

    NC_CHECK_ARG_RET(NULL, ctx, encryption_algs, 1);

    return nc_server_config_oper_get_algs(ctx, "iana-ssh-encryption-algs", libnetconf2_encryption_algs,
            iana_encryption_algs, encryption_algs);
}

API int
nc_server_config_oper_get_mac_algs(const struct ly_ctx *ctx, struct lyd_node **mac_algs)
{
    /* identities of mac algs supported by libssh (v0.10.5) defined in libnetconf2-netconf-server yang module */
    const char *libnetconf2_mac_algs[] = {
        "openssh-hmac-sha2-256-etm", "openssh-hmac-sha2-512-etm", "openssh-hmac-sha1-etm", NULL
    };

    /* identities of mac algs supported by libssh (v0.10.5) defined in iana-ssh-mac-algs yang module */
    const char *iana_mac_algs[] = {
        "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", NULL
    };

    NC_CHECK_ARG_RET(NULL, ctx, mac_algs, 1);

    return nc_server_config_oper_get_algs(ctx, "iana-ssh-mac-algs", libnetconf2_mac_algs,
            iana_mac_algs, mac_algs);
}

#endif /* NC_ENABLED_SSH_TLS */
