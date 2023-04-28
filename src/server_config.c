/**
 * @file server_config.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server configuration functions
 *
 * @copyright
 * Copyright (c) 2015 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "libnetconf.h"
#include "server_config.h"
#include "session_server.h"
#include "session_server_ch.h"

/* All libssh supported host-key, key-exchange, encryption and mac algorithms as of version 0.10.90 */

static const char *supported_hostkey_algs[] = {
    "ssh-ed25519-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
    "ssh-rsa-cert-v01@openssh.com", "ssh-dss-cert-v01@openssh.com",
    "ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256",
    "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss", NULL
};

static const char *supported_kex_algs[] = {
    "diffie-hellman-group-exchange-sha1", "curve25519-sha256", "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group18-sha512",
    "diffie-hellman-group16-sha512", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha256", NULL
};

static const char *supported_encryption_algs[] = {
    "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
    "aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc",
    "blowfish-cbc", "triple-des-cbc", "none", NULL
};

static const char *supported_mac_algs[] = {
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com",
    "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", NULL
};

extern struct nc_server_opts server_opts;

/**
 * @brief Get the pointer to an endpoint structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the endpoint containing this node is derived.
 * @param[out] endpt Endpoint containing the node.
 * @param[out] bind Bind corresponding to the endpoint. Optional.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_get_endpt(const struct lyd_node *node, struct nc_endpt **endpt, struct nc_bind **bind)
{
    uint16_t i;
    const char *endpt_name;

    assert(node);

    while (node) {
        if (!strcmp(LYD_NAME(node), "endpoint")) {
            break;
        }
        node = lyd_parent(node);
    }

    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in an endpoint subtree.", LYD_NAME(node));
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));
    endpt_name = lyd_get_value(node);

    for (i = 0; i < server_opts.endpt_count; i++) {
        if (!strcmp(server_opts.endpts[i].name, endpt_name)) {
            *endpt = &server_opts.endpts[i];
            if (bind) {
                *bind = &server_opts.binds[i];
            }
            return 0;
        }
    }

    ERR(NULL, "Endpoint \"%s\" was not found.", endpt_name);
    return 1;
}

/**
 * @brief Get the pointer to a hostkey structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the hotkey containing this node is derived.
 * @param[in] opts Server SSH opts storing the array of the hostkey structures.
 * @param[out] hostkey Hostkey containing the node.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_get_hostkey(const struct lyd_node *node, const struct nc_server_ssh_opts *opts, struct nc_hostkey **hostkey)
{
    uint16_t i;
    const char *hostkey_name;

    assert(node && opts);

    while (node) {
        if (!strcmp(LYD_NAME(node), "host-key")) {
            break;
        }
        node = lyd_parent(node);
    }

    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in a host-key subtree.", LYD_NAME(node));
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));
    hostkey_name = lyd_get_value(node);

    for (i = 0; i < opts->hostkey_count; i++) {
        if (!strcmp(opts->hostkeys[i].name, hostkey_name)) {
            *hostkey = &opts->hostkeys[i];
            return 0;
        }
    }

    ERR(NULL, "Host-key \"%s\" was not found.", hostkey_name);
    return 1;
}

/**
 * @brief Get the pointer to a client authentication structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the client-authentication structure containing this node is derived.
 * @param[in] opts Server SSH opts storing the array of the client authentication structures.
 * @param[out] auth_client Client authentication structure containing the node.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_get_auth_client(const struct lyd_node *node, const struct nc_server_ssh_opts *opts, struct nc_client_auth **auth_client)
{
    uint16_t i;
    const char *authkey_name;

    assert(node && opts);

    while (node) {
        if (!strcmp(LYD_NAME(node), "user")) {
            break;
        }
        node = lyd_parent(node);
    }

    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in a client-authentication subtree.", LYD_NAME(node));
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));
    authkey_name = lyd_get_value(node);

    for (i = 0; i < opts->client_count; i++) {
        if (!strcmp(opts->auth_clients[i].username, authkey_name)) {
            *auth_client = &opts->auth_clients[i];
            return 0;
        }
    }

    ERR(NULL, "Authorized key \"%s\" was not found.", authkey_name);
    return 1;
}

/**
 * @brief Get the pointer to a client authentication public key structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the ca-public key structure containing this node is derived.
 * @param[in] auth_client Client authentication structure storing the array of the public key structures.
 * @param[out] pubkey Public key structure containing the node.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_get_pubkey(const struct lyd_node *node, const struct nc_client_auth *auth_client, struct nc_public_key **pubkey)
{
    uint16_t i;
    const char *pubkey_name;

    assert(node && auth_client);

    node = lyd_parent(node);
    while (node) {
        if (!strcmp(LYD_NAME(node), "public-key")) {
            break;
        }
        node = lyd_parent(node);
    }

    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in a public-key subtree.", LYD_NAME(node));
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));
    pubkey_name = lyd_get_value(node);

    for (i = 0; i < auth_client->pubkey_count; i++) {
        if (!strcmp(auth_client->pubkeys[i].name, pubkey_name)) {
            *pubkey = &auth_client->pubkeys[i];
            return 0;
        }
    }

    ERR(NULL, "Public key \"%s\" was not found.", pubkey_name);
    return 1;
}

/**
 * @brief Compares the nth-parent name.
 *
 * @param[in] node Node of which nth-parent to compare.
 * @param[in] parent_count Count of parents.
 * @param[in] parent_name Expected name of the parent.
 * @return 1 if the name matches, 0 otherwise.
 */
static int
equal_parent_name(const struct lyd_node *node, uint16_t parent_count, const char *parent_name)
{
    uint16_t i;

    assert(node && parent_count > 0 && parent_name);

    node = lyd_parent(node);
    for (i = 1; i < parent_count; i++) {
        node = lyd_parent(node);
    }

    if (!strcmp(LYD_NAME(node), parent_name)) {
        return 1;
    }

    return 0;
}

static void
nc_server_del_auth_client_pam_name(struct nc_client_auth *auth_client)
{
    free(auth_client->pam_config_name);
    auth_client->pam_config_name = NULL;
}

static void
nc_server_del_auth_client_pam_dir(struct nc_client_auth *auth_client)
{
    free(auth_client->pam_config_dir);
    auth_client->pam_config_dir = NULL;
}

static void
nc_server_del_endpt_name(struct nc_endpt *endpt)
{
    free(endpt->name);
    endpt->name = NULL;
}

static void
nc_server_del_local_address(struct nc_bind *bind)
{
    free(bind->address);
    bind->address = NULL;
}

static void
nc_server_del_hostkey_name(struct nc_hostkey *hostkey)
{
    free(hostkey->name);
    hostkey->name = NULL;
}

static void
nc_server_del_public_key(struct nc_hostkey *hostkey)
{
    free(hostkey->key.pub_base64);
    hostkey->key.pub_base64 = NULL;
}

static void
nc_server_del_private_key(struct nc_hostkey *hostkey)
{
    free(hostkey->key.priv_base64);
    hostkey->key.priv_base64 = NULL;
}

static void
nc_server_del_auth_client_username(struct nc_client_auth *auth_client)
{
    free(auth_client->username);
    auth_client->username = NULL;
}

static void
nc_server_del_auth_client_pubkey_name(struct nc_public_key *pubkey)
{
    free(pubkey->name);
    pubkey->name = NULL;
}

static void
nc_server_del_auth_client_pubkey_pub_base64(struct nc_public_key *pubkey)
{
    free(pubkey->pub_base64);
    pubkey->pub_base64 = NULL;
}

static void
nc_server_del_auth_client_password(struct nc_client_auth *auth_client)
{
    free(auth_client->password);
    auth_client->password = NULL;
}

static void
nc_server_del_hostkey_algs(struct nc_server_ssh_opts *opts)
{
    free(opts->hostkey_algs);
    opts->hostkey_algs = NULL;
}

static void
nc_server_del_kex_algs(struct nc_server_ssh_opts *opts)
{
    free(opts->kex_algs);
    opts->kex_algs = NULL;
}

static void
nc_server_del_encryption_algs(struct nc_server_ssh_opts *opts)
{
    free(opts->encryption_algs);
    opts->encryption_algs = NULL;
}

static void
nc_server_del_mac_algs(struct nc_server_ssh_opts *opts)
{
    free(opts->mac_algs);
    opts->mac_algs = NULL;
}

static void
nc_server_del_hostkey(struct nc_server_ssh_opts *opts, struct nc_hostkey *hostkey)
{
    assert(hostkey->ks_type == NC_STORE_LOCAL || hostkey->ks_type == NC_STORE_KEYSTORE);

    if (hostkey->ks_type == NC_STORE_LOCAL) {
        nc_server_del_public_key(hostkey);
        nc_server_del_private_key(hostkey);
    }

    nc_server_del_hostkey_name(hostkey);
    opts->hostkey_count--;
    if (!opts->hostkey_count) {
        free(opts->hostkeys);
        opts->hostkeys = NULL;
    }
}

static void
nc_server_del_auth_client_pubkey(struct nc_client_auth *auth_client, struct nc_public_key *pubkey)
{
    nc_server_del_auth_client_pubkey_name(pubkey);
    nc_server_del_auth_client_pubkey_pub_base64(pubkey);

    auth_client->pubkey_count--;
    if (!auth_client->pubkey_count) {
        free(auth_client->pubkeys);
        auth_client->pubkeys = NULL;
    }
}

static void
nc_server_del_auth_client(struct nc_server_ssh_opts *opts, struct nc_client_auth *auth_client)
{
    uint16_t i, pubkey_count;

    if (auth_client->ks_type == NC_STORE_LOCAL) {
        pubkey_count = auth_client->pubkey_count;
        for (i = 0; i < pubkey_count; i++) {
            nc_server_del_auth_client_pubkey(auth_client, &auth_client->pubkeys[i]);
        }
    }

    nc_server_del_auth_client_password(auth_client);
    nc_server_del_auth_client_pam_name(auth_client);
    nc_server_del_auth_client_pam_dir(auth_client);
    nc_server_del_auth_client_username(auth_client);

    opts->client_count--;
    if (!opts->client_count) {
        free(opts->auth_clients);
        opts->auth_clients = NULL;
    }
}

static void
nc_server_del_ssh(struct nc_bind *bind, struct nc_server_ssh_opts *opts)
{
    uint16_t i, hostkey_count, client_count;

    nc_server_del_local_address(bind);
    if (bind->sock > -1) {
        close(bind->sock);
    }

    /* store in variable because it gets decremented in the function call */
    hostkey_count = opts->hostkey_count;
    for (i = 0; i < hostkey_count; i++) {
        nc_server_del_hostkey(opts, &opts->hostkeys[i]);
    }

    client_count = opts->client_count;
    for (i = 0; i < client_count; i++) {
        nc_server_del_auth_client(opts, &opts->auth_clients[i]);
    }

    nc_server_del_hostkey_algs(opts);
    nc_server_del_kex_algs(opts);
    nc_server_del_encryption_algs(opts);
    nc_server_del_mac_algs(opts);

    free(opts);
    opts = NULL;
}

void
nc_server_del_endpt_ssh(struct nc_endpt *endpt, struct nc_bind *bind)
{
    nc_server_del_endpt_name(endpt);
    nc_server_del_ssh(bind, endpt->opts.ssh);

    server_opts.endpt_count--;
    if (!server_opts.endpt_count) {
        free(server_opts.endpts);
        free(server_opts.binds);
        server_opts.endpts = NULL;
        server_opts.binds = NULL;
    }
}

void
nc_server_del_unix_socket(struct nc_bind *bind, struct nc_server_unix_opts *opts)
{
    if (bind->sock > -1) {
        close(bind->sock);
    }

    free(bind->address);
    free(opts->address);

    free(opts);
    opts = NULL;
}

void
nc_server_del_endpt_unix_socket(struct nc_endpt *endpt, struct nc_bind *bind)
{
    nc_server_del_endpt_name(endpt);
    nc_server_del_unix_socket(bind, endpt->opts.unixsock);

    server_opts.endpt_count--;
    if (!server_opts.endpt_count) {
        free(server_opts.endpts);
        free(server_opts.binds);
        server_opts.endpts = NULL;
        server_opts.binds = NULL;
    }
}

void
nc_server_config_del_keystore(void)
{
    int i, j;
    struct nc_keystore *ks = &server_opts.keystore;

    /* delete all asymmetric keys */
    for (i = 0; i < ks->asym_key_count; i++) {
        free(ks->asym_keys[i].name);
        free(ks->asym_keys[i].pub_base64);
        free(ks->asym_keys[i].priv_base64);

        for (j = 0; j < ks->asym_keys[i].cert_count; j++) {
            /* free associated certificates */
            free(ks->asym_keys[i].certs[j].name);
            free(ks->asym_keys[i].certs[j].cert_base64);
        }
        free(ks->asym_keys[i].certs);
        ks->asym_keys[i].certs = NULL;
        ks->asym_keys[i].cert_count = 0;
    }
    free(ks->asym_keys);
    ks->asym_keys = NULL;
    ks->asym_key_count = 0;

    /* delete all symmetric keys */
    for (i = 0; i < ks->sym_key_count; i++) {
        free(ks->sym_keys[i].name);
        free(ks->sym_keys[i].base64);
    }
    free(ks->sym_keys);
    ks->sym_keys = NULL;
    ks->sym_key_count = 0;
}

void
nc_server_config_del_trustore(void)
{
    int i, j;
    struct nc_truststore *ts = &server_opts.truststore;

    /* delete all cert bags */
    for (i = 0; i < ts->cert_bag_count; i++) {
        free(ts->cert_bags[i].name);
        for (j = 0; j < ts->cert_bags[i].cert_count; j++) {
            /* free associated certificates */
            free(ts->cert_bags[i].certs[j].name);
            free(ts->cert_bags[i].certs[j].cert_base64);
        }
        free(ts->cert_bags[i].certs);
        ts->cert_bags[i].certs = NULL;
        ts->cert_bags[i].cert_count = 0;
    }
    free(ts->cert_bags);
    ts->cert_bags = NULL;
    ts->cert_bag_count = 0;

    /* delete all pubkey bags */
    for (i = 0; i < ts->pub_bag_count; i++) {
        free(ts->pub_bags[i].name);
        for (j = 0; j < ts->pub_bags[i].pubkey_count; j++) {
            /* free associated pubkeys */
            free(ts->pub_bags[i].pubkeys[j].name);
            free(ts->pub_bags[i].pubkeys[j].pub_base64);
        }
        free(ts->pub_bags[i].pubkeys);
        ts->pub_bags[i].pubkeys = NULL;
        ts->pub_bags[i].pubkey_count = 0;
    }
    free(ts->pub_bags);
    ts->pub_bags = NULL;
    ts->pub_bag_count = 0;
}

/* presence container */
int
nc_server_config_listen(NC_OPERATION op)
{
    uint16_t i;

    assert(op == NC_OP_CREATE || op == NC_OP_DELETE);

    if (op == NC_OP_DELETE) {
        for (i = 0; i < server_opts.endpt_count; i++) {
            switch (server_opts.endpts[i].ti) {
#ifdef NC_ENABLED_SSH
            case NC_TI_LIBSSH:
                nc_server_del_endpt_ssh(&server_opts.endpts[i], &server_opts.binds[i]);
                break;
#endif
#ifdef NC_ENABLED_TLS
            case NC_TI_OPENSSL:
                /* todo */
                break;
#endif
            case NC_TI_UNIX:
                nc_server_del_endpt_unix_socket(&server_opts.endpts[i], &server_opts.binds[i]);
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

/* default leaf */
static int
nc_server_config_idle_timeout(const struct lyd_node *node, NC_OPERATION op)
{
    assert(!strcmp(LYD_NAME(node), "idle-timeout"));

    if (equal_parent_name(node, 1, "listen")) {
        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            server_opts.idle_timeout = strtoul(lyd_get_value(node), NULL, 10);
        } else {
            /* default value */
            server_opts.idle_timeout = 3600;
        }
    }

    return 0;
}

static int
nc_server_create_bind(void)
{
    int ret = 0;
    void *tmp;

    tmp = realloc(server_opts.binds, (server_opts.endpt_count + 1) * sizeof *server_opts.binds);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    server_opts.binds = tmp;
    memset(&server_opts.binds[server_opts.endpt_count], 0, sizeof *server_opts.binds);

    server_opts.binds[server_opts.endpt_count].sock = -1;

cleanup:
    return ret;
}

static int
nc_server_create_endpoint(const struct lyd_node *node)
{
    int ret = 0;
    void *tmp;

    tmp = realloc(server_opts.endpts, (server_opts.endpt_count + 1) * sizeof *server_opts.endpts);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    server_opts.endpts = tmp;
    memset(&server_opts.endpts[server_opts.endpt_count], 0, sizeof *server_opts.endpts);

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    server_opts.endpts[server_opts.endpt_count].name = strdup(lyd_get_value(node));
    if (!server_opts.endpts[server_opts.endpt_count].name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    if (nc_server_create_bind()) {
        ret = 1;
        goto cleanup;
    }

    server_opts.endpt_count++;

cleanup:
    return ret;
}

/* list */
static int
nc_server_config_endpoint(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct nc_bind *bind;

    assert(!strcmp(LYD_NAME(node), "endpoint"));

    if (op == NC_OP_CREATE) {
        ret = nc_server_create_endpoint(node);
        if (ret) {
            goto cleanup;
        }
    } else if (op == NC_OP_DELETE) {
        /* free all children */
        if (nc_server_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }
        nc_server_del_endpt_ssh(endpt, bind);
    }

cleanup:
    return ret;
}

static int
nc_server_create_ssh(struct nc_endpt *endpt)
{
    endpt->ti = NC_TI_LIBSSH;
    endpt->opts.ssh = calloc(1, sizeof(struct nc_server_ssh_opts));
    if (!endpt->opts.ssh) {
        ERRMEM;
        return 1;
    }

    return 0;
}

/* NP container */
static int
nc_server_config_ssh(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "ssh"));

    if (nc_server_get_endpt(node, &endpt, &bind)) {
        ret = 1;
        goto cleanup;
    }

    if (op == NC_OP_CREATE) {
        ret = nc_server_create_ssh(endpt);
        if (ret) {
            goto cleanup;
        }
    } else if (op == NC_OP_DELETE) {
        nc_server_del_ssh(bind, endpt->opts.ssh);
    }

cleanup:
    return ret;
}

static int
nc_server_config_set_address_port(struct nc_endpt *endpt, struct nc_bind *bind, const char *address, uint16_t port)
{
    int sock = -1, set_addr, ret = 0;

    assert((address && !port) || (!address && port) || (endpt->ti == NC_TI_UNIX));

    if (address) {
        set_addr = 1;
    } else {
        set_addr = 0;
    }

    if (set_addr) {
        port = bind->port;
    } else {
        address = bind->address;
    }

    /* we have all the information we need to create a listening socket */
    if ((address && port) || (endpt->ti == NC_TI_UNIX)) {
        /* create new socket, close the old one */
        if (endpt->ti == NC_TI_UNIX) {
            sock = nc_sock_listen_unix(endpt->opts.unixsock);
        } else {
            sock = nc_sock_listen_inet(address, port, &endpt->ka);
        }

        if (sock == -1) {
            ret = 1;
            goto cleanup;
        }

        if (bind->sock > -1) {
            close(bind->sock);
        }
        bind->sock = sock;
    }

    if (sock > -1) {
        switch (endpt->ti) {
        case NC_TI_UNIX:
            VRB(NULL, "Listening on %s for UNIX connections.", endpt->opts.unixsock->address);
            break;
#ifdef NC_ENABLED_SSH
        case NC_TI_LIBSSH:
            VRB(NULL, "Listening on %s:%u for SSH connections.", address, port);
            break;
#endif
#ifdef NC_ENABLED_TLS
        case NC_TI_OPENSSL:
            VRB(NULL, "Listening on %s:%u for TLS connections.", address, port);
            break;
#endif
        default:
            ERRINT;
            ret = 1;
            break;
        }
    }

cleanup:
    return ret;
}

/* mandatory leaf */
static int
nc_server_config_local_address(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    int ret = 0;

    (void) op;

    assert(!strcmp(LYD_NAME(node), "local-address"));

    if (equal_parent_name(node, 4, "listen")) {
        if (nc_server_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        nc_server_del_local_address(bind);
        bind->address = strdup(lyd_get_value(node));
        if (!bind->address) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }

        ret = nc_server_config_set_address_port(endpt, bind, lyd_get_value(node), 0);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

/* leaf with default value */
static int
nc_server_config_local_port(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "local-port"));

    if (equal_parent_name(node, 4, "listen")) {
        if (nc_server_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            bind->port = strtoul(lyd_get_value(node), NULL, 10);
        } else {
            /* delete -> set to default */
            bind->port = 0;
        }

        ret = nc_server_config_set_address_port(endpt, bind, NULL, bind->port);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

/* P container */
static int
nc_server_config_keepalives(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "keepalives"));

    if (equal_parent_name(node, 4, "listen")) {
        if (nc_server_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            endpt->ka.enabled = 1;
        } else {
            endpt->ka.enabled = 0;
        }
        ret = nc_sock_configure_keepalive(bind->sock, &endpt->ka);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

/* mandatory leaf */
static int
nc_server_config_idle_time(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "idle-time"));

    if (equal_parent_name(node, 4, "listen")) {
        if (nc_server_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            endpt->ka.idle_time = strtoul(lyd_get_value(node), NULL, 10);
        } else {
            endpt->ka.idle_time = 0;
        }
        ret = nc_sock_configure_keepalive(bind->sock, &endpt->ka);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

/* mandatory leaf */
static int
nc_server_config_max_probes(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "max-probes"));

    if (equal_parent_name(node, 4, "listen")) {
        if (nc_server_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            endpt->ka.max_probes = strtoul(lyd_get_value(node), NULL, 10);
        } else {
            endpt->ka.max_probes = 0;
        }
        ret = nc_sock_configure_keepalive(bind->sock, &endpt->ka);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

/* mandatory leaf */
static int
nc_server_config_probe_interval(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "probe-interval"));

    if (equal_parent_name(node, 4, "listen")) {
        if (nc_server_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            endpt->ka.probe_interval = strtoul(lyd_get_value(node), NULL, 10);
        } else {
            endpt->ka.probe_interval = 0;
        }
        ret = nc_sock_configure_keepalive(bind->sock, &endpt->ka);
        if (ret) {
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

static int
nc_server_create_host_key(const struct lyd_node *node, struct nc_server_ssh_opts *opts)
{
    int ret = 0;
    void *tmp;

    tmp = realloc(opts->hostkeys,
            (opts->hostkey_count + 1) * sizeof *opts->hostkeys);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    opts->hostkeys = tmp;

    memset(&opts->hostkeys[opts->hostkey_count], 0, sizeof *opts->hostkeys);

    opts->hostkeys[opts->hostkey_count].name = strdup(lyd_get_value(lyd_child(node)));
    if (!opts->hostkeys[opts->hostkey_count].name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* set union selector */
    lyd_find_path(node, "public-key", 0, (struct lyd_node **)&node);
    assert(node);

    if (!lyd_find_path(node, "local-definition", 0, NULL)) {
        opts->hostkeys[opts->hostkey_count].ks_type = NC_STORE_LOCAL;
    } else {
        opts->hostkeys[opts->hostkey_count].ks_type = NC_STORE_KEYSTORE;
    }

    opts->hostkey_count++;

cleanup:
    return ret;
}

/* list */
static int
nc_server_config_host_key(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_hostkey *hostkey;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "host-key"));

    if ((equal_parent_name(node, 1, "server-identity")) && (equal_parent_name(node, 5, "listen"))) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            ret = nc_server_create_host_key(node, endpt->opts.ssh);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            if (nc_server_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
                ret = 1;
                goto cleanup;
            }

            nc_server_del_hostkey(endpt->opts.ssh, hostkey);
        }
    } else if (equal_parent_name(node, 1, "transport-params")) {
        /* just a container with the name host-key, nothing to be done */
        goto cleanup;
    } else {
        ERRINT;
        ret = 1;
        goto cleanup;
    }

cleanup:
    return ret;
}

/* mandatory leaf */
static int
nc_server_config_public_key_format(const struct lyd_node *node, NC_OPERATION op)
{
    const char *format;
    struct nc_endpt *endpt;
    struct nc_client_auth *auth_client;
    struct nc_public_key *pubkey;
    struct nc_hostkey *hostkey;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "public-key-format"));

    format = ((struct lyd_node_term *)node)->value.ident->name;

    if ((equal_parent_name(node, 6, "client-authentication")) && (equal_parent_name(node, 10, "listen"))) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_pubkey(node, auth_client, &pubkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            if (!strcmp(format, "ssh-public-key-format")) {
                pubkey->pubkey_type = NC_SSH_PUBKEY_X509;
            } else if (!strcmp(format, "subject-public-key-info-format")) {
                pubkey->pubkey_type = NC_SSH_PUBKEY_SSH2;
            } else {
                ERR(NULL, "Public key format (%s) not supported.", format);
            }
        }
    } else if ((equal_parent_name(node, 5, "server-identity")) && (equal_parent_name(node, 11, "listen"))) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            if (!strcmp(format, "ssh-public-key-format")) {
                hostkey->key.pubkey_type = NC_SSH_PUBKEY_SSH2;
            } else if (!strcmp(format, "subject-public-key-info-format")) {
                hostkey->key.pubkey_type = NC_SSH_PUBKEY_X509;
            } else {
                ERR(NULL, "Public key format (%s) not supported.", format);
            }
        }
    }

cleanup:
    return ret;
}

/* leaf */
static int
nc_server_config_private_key_format(const struct lyd_node *node, NC_OPERATION op)
{
    const char *format;
    struct nc_endpt *endpt;
    struct nc_hostkey *hostkey;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "private-key-format"));

    if (nc_server_get_endpt(node, &endpt, NULL)) {
        ret = 1;
        goto cleanup;
    }

    if (nc_server_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
        ret = 1;
        goto cleanup;
    }

    format = ((struct lyd_node_term *)node)->value.ident->name;
    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        if (!strcmp(format, "rsa-private-key-format")) {
            hostkey->key.privkey_type = NC_SSH_KEY_RSA;
        } else if (!strcmp(format, "ec-private-key-format")) {
            hostkey->key.privkey_type = NC_SSH_KEY_ECDSA;
        } else if (!strcmp(format, "ed25519-private-key-format")) {
            hostkey->key.privkey_type = NC_SSH_KEY_ED25519;
        } else {
            ERR(NULL, "Private key format (%s) not supported.", format);
        }
    }

cleanup:
    return ret;
}

static int
nc_server_replace_cleartext_private_key(const struct lyd_node *node, struct nc_hostkey *hostkey)
{
    nc_server_del_private_key(hostkey);
    hostkey->key.priv_base64 = strdup(lyd_get_value(node));
    if (!hostkey->key.priv_base64) {
        ERRMEM;
        return 1;
    }

    return 0;
}

static int
nc_server_config_cleartext_private_key(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_hostkey *hostkey;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "cleartext-private-key"));

    if ((equal_parent_name(node, 6, "ssh")) && (equal_parent_name(node, 8, "listen"))) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }
        if (nc_server_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_replace_cleartext_private_key(node, hostkey);
            if (ret) {
                goto cleanup;
            }
        } else {
            nc_server_del_private_key(hostkey);
        }
    }

cleanup:
    return ret;
}

static int
nc_server_create_keystore_reference(const struct lyd_node *node, struct nc_hostkey *hostkey)
{
    uint16_t i;
    struct nc_keystore *ks = &server_opts.keystore;

    /* lookup name */
    for (i = 0; i < ks->asym_key_count; i++) {
        if (!strcmp(lyd_get_value(node), ks->asym_keys[i].name)) {
            break;
        }
    }

    if (i == ks->asym_key_count) {
        ERR(NULL, "Keystore \"%s\" not found.", lyd_get_value(node));
        return 1;
    }

    hostkey->ks_ref = &ks->asym_keys[i];

    return 0;
}

/* leaf */
static int
nc_server_config_keystore_reference(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_hostkey *hostkey;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "keystore-reference"));

    if ((equal_parent_name(node, 3, "server-identity")) && (equal_parent_name(node, 7, "listen"))) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }
        if (nc_server_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_create_keystore_reference(node, hostkey);
            if (ret) {
                goto cleanup;
            }
        } else {
            hostkey->ks_ref = NULL;
        }
    }

cleanup:
    return ret;
}

static int
nc_server_create_auth_key_public_key_list(const struct lyd_node *node, struct nc_client_auth *auth_client)
{
    int ret = 0;
    void *tmp;

    assert(!strcmp(LYD_NAME(node), "public-key"));

    tmp = realloc(auth_client->pubkeys, (auth_client->pubkey_count + 1) * sizeof *auth_client->pubkeys);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    auth_client->pubkeys = tmp;

    memset(&auth_client->pubkeys[auth_client->pubkey_count], 0, sizeof *auth_client->pubkeys);

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    auth_client->pubkeys[auth_client->pubkey_count].name = strdup(lyd_get_value(node));
    if (!auth_client->pubkeys[auth_client->pubkey_count].name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    ++auth_client->pubkey_count;

cleanup:
    return ret;
}

static int
nc_server_replace_auth_key_public_key_leaf(const struct lyd_node *node, struct nc_public_key *pubkey)
{
    nc_server_del_auth_client_pubkey_pub_base64(pubkey);

    pubkey->pub_base64 = strdup(lyd_get_value(node));
    if (!pubkey->pub_base64) {
        ERRMEM;
        return 1;
    }

    return 0;
}

static int
nc_server_replace_host_key_public_key(const struct lyd_node *node, struct nc_hostkey *hostkey)
{
    nc_server_del_public_key(hostkey);

    hostkey->key.pub_base64 = strdup(lyd_get_value(node));
    if (!hostkey->key.pub_base64) {
        ERRMEM;
        return 1;
    }

    return 0;
}

static int
nc_server_config_public_key(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_hostkey *hostkey;
    struct nc_client_auth *auth_client;
    struct nc_public_key *pubkey;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "public-key"));

    if ((equal_parent_name(node, 3, "host-key")) && (equal_parent_name(node, 8, "listen"))) {
        /* server's public-key, mandatory leaf */
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_replace_host_key_public_key(node, hostkey);
            if (ret) {
                goto cleanup;
            }
        }
    } else if ((equal_parent_name(node, 5, "client-authentication")) && (equal_parent_name(node, 9, "listen"))) {
        /* client auth pubkeys, list */
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            ret = nc_server_create_auth_key_public_key_list(node, auth_client);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            if (nc_server_get_pubkey(node, auth_client, &pubkey)) {
                ret = 1;
                goto cleanup;
            }

            nc_server_del_auth_client_pubkey(auth_client, pubkey);
        }
    } else if ((equal_parent_name(node, 6, "client-authentication")) && (equal_parent_name(node, 10, "listen"))) {
        /* client auth pubkey, leaf */
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_pubkey(node, auth_client, &pubkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_replace_auth_key_public_key_leaf(node, pubkey);
            if (ret) {
                goto cleanup;
            }
        } else {
            nc_server_del_auth_client_pubkey_pub_base64(pubkey);
        }
    }

cleanup:
    return ret;
}

static int
nc_server_create_user(const struct lyd_node *node, struct nc_server_ssh_opts *opts)
{
    int ret = 0;
    void *tmp;

    tmp = realloc(opts->auth_clients, (opts->client_count + 1) * sizeof *opts->auth_clients);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    opts->auth_clients = tmp;

    memset(&opts->auth_clients[opts->client_count], 0, sizeof *opts->auth_clients);

    opts->auth_clients[opts->client_count].username = strdup(lyd_get_value(lyd_child(node)));
    if (!opts->auth_clients[opts->client_count].username) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    lyd_find_path(node, "public-keys", 0, (struct lyd_node **)&node);

    if (node) {
        /* set union selector */
        if (!lyd_find_path(node, "local-definition", 0, NULL)) {
            opts->auth_clients[opts->client_count].ks_type = NC_STORE_LOCAL;
        } else {
            opts->auth_clients[opts->client_count].ks_type = NC_STORE_TRUSTSTORE;
        }
    }

    ++opts->client_count;

cleanup:
    return ret;
}

/* list */
static int
nc_server_config_user(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_client_auth *auth_client;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "user"));

    if (equal_parent_name(node, 6, "listen")) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            ret = nc_server_create_user(node, endpt->opts.ssh);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            if (nc_server_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
                ret = 1;
                goto cleanup;
            }

            nc_server_del_auth_client(endpt->opts.ssh, auth_client);
        }
    }

cleanup:
    return ret;
}

static int
nc_server_config_auth_attempts(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "auth-attempts"));

    if (equal_parent_name(node, 5, "listen")) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            endpt->opts.ssh->auth_attempts = strtoul(lyd_get_value(node), NULL, 10);
        }
    }

cleanup:
    return ret;
}

static int
nc_server_config_auth_timeout(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "auth-timeout"));

    if (equal_parent_name(node, 5, "listen")) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            endpt->opts.ssh->auth_timeout = strtoul(lyd_get_value(node), NULL, 10);
        }
    }

cleanup:
    return ret;
}

static int
nc_server_replace_truststore_reference(const struct lyd_node *node, struct nc_client_auth *client_auth)
{
    uint16_t i;
    struct nc_truststore *ts = &server_opts.truststore;

    /* lookup name */
    for (i = 0; i < ts->pub_bag_count; i++) {
        if (!strcmp(lyd_get_value(node), ts->pub_bags[i].name)) {
            break;
        }
    }

    if (i == ts->pub_bag_count) {
        ERR(NULL, "Truststore \"%s\" not found.", lyd_get_value(node));
        return 1;
    }

    client_auth->ts_ref = &ts->pub_bags[i];

    return 0;
}

/* leaf */
static int
nc_server_config_truststore_reference(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_client_auth *auth_client;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "truststore-reference"));

    if ((equal_parent_name(node, 1, "public-keys")) && (equal_parent_name(node, 8, "listen"))) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_replace_truststore_reference(node, auth_client);
            if (ret) {
                goto cleanup;
            }
        } else {
            auth_client->ts_ref = NULL;
        }
    }

cleanup:
    return ret;
}

static int
nc_server_replace_password(const struct lyd_node *node, struct nc_client_auth *auth_client)
{
    nc_server_del_auth_client_password(auth_client);

    auth_client->password = strdup(lyd_get_value(node));
    if (!auth_client->password) {
        ERRMEM;
        return 1;
    }

    return 0;
}

/* leaf */
static int
nc_server_config_password(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_client_auth *auth_client;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "password"));

    if (equal_parent_name(node, 7, "listen")) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_replace_password(node, auth_client);
            if (ret) {
                goto cleanup;
            }
        } else {
            nc_server_del_auth_client_password(auth_client);
        }
    }

cleanup:
    return ret;
}

static int
nc_server_config_pam_name(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_client_auth *auth_client;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "pam-config-file-name"));

    if (equal_parent_name(node, 8, "listen")) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            nc_server_del_auth_client_pam_name(auth_client);

            auth_client->pam_config_name = strdup(lyd_get_value(node));
            if (!auth_client->pam_config_name) {
                ERRMEM;
                ret = 1;
                goto cleanup;
            }
        }
    }

cleanup:
    return ret;
}

static int
nc_server_config_pam_dir(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_client_auth *auth_client;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "pam-config-file-dir"));

    if (equal_parent_name(node, 8, "listen")) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            nc_server_del_auth_client_pam_dir(auth_client);
            auth_client->pam_config_dir = strdup(lyd_get_value(node));
            if (!auth_client->pam_config_dir) {
                ERRMEM;
                ret = 1;
                goto cleanup;
            }
        }
    }

cleanup:
    return ret;
}

/* leaf */
static int
nc_server_config_none(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_client_auth *auth_client;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "none"));

    if (equal_parent_name(node, 7, "listen")) {
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            auth_client->supports_none = 1;
        } else {
            auth_client->supports_none = 0;
        }
    }

cleanup:
    return ret;
}

static int
nc_server_config_transport_params(const char *alg, char **alg_store, NC_OPERATION op)
{
    int ret = 0, alg_found = 0;
    char *substr, *haystack;
    size_t alg_len = strlen(alg);

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        if (!*alg_store) {
            /* first call */
            *alg_store = strdup(alg);
            if (!*alg_store) {
                ERRMEM;
                ret = 1;
                goto cleanup;
            }
        } else {
            /* +1 because of ',' between algorithms */
            *alg_store = nc_realloc(*alg_store, strlen(*alg_store) + alg_len + 1 + 1);
            if (!*alg_store) {
                ERRMEM;
                ret = 1;
                goto cleanup;
            }
            sprintf(*alg_store, "%s,%s", *alg_store, alg);
        }
    } else {
        /* delete */
        haystack = *alg_store;
        while ((substr = strstr(haystack, alg))) {
            /* iterate over all the substrings */
            if (((substr == haystack) && (*(substr + alg_len) == ',')) ||
                    ((substr != haystack) && (*(substr - 1) == ',') && (*(substr + alg_len) == ','))) {
                /* either the first element of the string or somewhere in the middle */
                memmove(substr, substr + alg_len + 1, strlen(substr + alg_len + 1));
                alg_found = 1;
                break;
            } else if ((*(substr - 1) == ',') && (*(substr + alg_len) == '\0')) {
                /* the last element of the string */
                *(substr - 1) = '\0';
                alg_found = 1;
                break;
            }
            haystack++;
        }
        if (!alg_found) {
            ERR(NULL, "Unable to delete an algorithm (%s), which was not previously added.", alg);
            ret = 1;
        }
    }

cleanup:
    return ret;
}

/* leaf-list */
static int
nc_server_config_host_key_alg(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    int ret = 0, listen = 0;
    const char *alg;
    uint8_t i;

    /* get the algorithm name and compare it with algs supported by libssh */
    alg = ((struct lyd_node_term *)node)->value.ident->name;

    if (equal_parent_name(node, 6, "listen")) {
        listen = 1;
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }
    }

    i = 0;
    while (supported_hostkey_algs[i]) {
        if (!strcmp(supported_hostkey_algs[i], alg)) {
            if (listen) {
                if (nc_server_config_transport_params(alg, &endpt->opts.ssh->hostkey_algs, op)) {
                    ret = 1;
                    goto cleanup;
                }
            }
            break;
        }
        i++;
    }
    if (!supported_hostkey_algs[i]) {
        /* algorithm not supported */
        ERR(NULL, "Public key algorithm (%s) not supported by libssh.", alg);
        ret = 1;
    }

cleanup:
    return ret;
}

/* leaf-list */
static int
nc_server_config_kex_alg(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    int ret = 0, listen = 0;
    const char *alg;
    uint8_t i;

    /* get the algorithm name and compare it with algs supported by libssh */
    alg = ((struct lyd_node_term *)node)->value.ident->name;

    if (equal_parent_name(node, 6, "listen")) {
        listen = 1;
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }
    }

    i = 0;
    while (supported_kex_algs[i]) {
        if (!strcmp(supported_kex_algs[i], alg)) {
            if (listen) {
                if (nc_server_config_transport_params(alg, &endpt->opts.ssh->kex_algs, op)) {
                    ret = 1;
                    goto cleanup;
                }
            }
            break;
        }
        i++;
    }
    if (!supported_kex_algs[i]) {
        /* algorithm not supported */
        ERR(NULL, "Key exchange algorithm (%s) not supported by libssh.", alg);
        ret = 1;
    }

cleanup:
    return ret;
}

/* leaf-list */
static int
nc_server_config_encryption_alg(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    int ret = 0, listen = 0;
    const char *alg;
    uint8_t i;

    /* get the algorithm name and compare it with algs supported by libssh */
    alg = ((struct lyd_node_term *)node)->value.ident->name;

    if (equal_parent_name(node, 6, "listen")) {
        listen = 1;
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }
    }

    i = 0;
    while (supported_encryption_algs[i]) {
        if (!strcmp(supported_encryption_algs[i], alg)) {
            if (listen) {
                if (nc_server_config_transport_params(alg, &endpt->opts.ssh->encryption_algs, op)) {
                    ret = 1;
                    goto cleanup;
                }
            }
            break;
        }
        i++;
    }
    if (!supported_encryption_algs[i]) {
        /* algorithm not supported */
        ERR(NULL, "Encryption algorithm (%s) not supported by libssh.", alg);
        ret = 1;
    }

cleanup:
    return ret;
}

/* leaf-list */
static int
nc_server_config_mac_alg(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    int ret = 0, listen = 0;
    const char *alg;
    uint8_t i;

    /* get the algorithm name and compare it with algs supported by libssh */
    alg = ((struct lyd_node_term *)node)->value.ident->name;

    if (equal_parent_name(node, 6, "listen")) {
        listen = 1;
        if (nc_server_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }
    }

    i = 0;
    while (supported_mac_algs[i]) {
        if (!strcmp(supported_mac_algs[i], alg)) {
            if (listen) {
                if (nc_server_config_transport_params(alg, &endpt->opts.ssh->mac_algs, op)) {
                    ret = 1;
                    goto cleanup;
                }
            }
            break;
        }
        i++;
    }
    if (!supported_mac_algs[i]) {
        /* algorithm not supported */
        ERR(NULL, "MAC algorithm (%s) not supported by libssh.", alg);
        ret = 1;
    }

cleanup:
    return ret;
}

static int
nc_server_create_unix_socket(struct nc_endpt *endpt)
{
    endpt->ti = NC_TI_UNIX;
    endpt->opts.unixsock = calloc(1, sizeof *endpt->opts.unixsock);
    if (!endpt->opts.unixsock) {
        ERRMEM;
        return 1;
    }

    /* set default values */
    endpt->opts.unixsock->mode = -1;
    endpt->opts.unixsock->uid = -1;
    endpt->opts.unixsock->gid = -1;

    return 0;
}

static int
nc_server_config_unix_socket(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    uint32_t prev_lo;
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    struct nc_server_unix_opts *opts;
    struct lyd_node *data = NULL;

    assert(!strcmp(LYD_NAME(node), "unix-socket"));

    if (nc_server_get_endpt(node, &endpt, &bind)) {
        ret = 1;
        goto cleanup;
    }

    if (op == NC_OP_CREATE) {
        if (nc_server_create_unix_socket(endpt)) {
            ret = 1;
            goto cleanup;
        }

        opts = endpt->opts.unixsock;

        lyd_find_path(node, "path", 0, &data);
        assert(data);

        opts->address = strdup(lyd_get_value(data));
        bind->address = strdup(lyd_get_value(data));
        if (!opts->address || !bind->address) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }

        /* silently search for non-mandatory parameters */
        prev_lo = ly_log_options(0);
        ret = lyd_find_path(node, "mode", 0, &data);
        if (!ret) {
            opts->mode = strtol(lyd_get_value(data), NULL, 8);
        }

        ret = lyd_find_path(node, "uid", 0, &data);
        if (!ret) {
            opts->uid = strtol(lyd_get_value(data), NULL, 10);
        }

        ret = lyd_find_path(node, "gid", 0, &data);
        if (!ret) {
            opts->gid = strtol(lyd_get_value(data), NULL, 10);
        }

        /* reset the logging options */
        ly_log_options(prev_lo);

        ret = nc_server_config_set_address_port(endpt, bind, NULL, 0);
        if (ret) {
            goto cleanup;
        }
    } else if (op == NC_OP_DELETE) {
        nc_server_del_unix_socket(bind, endpt->opts.unixsock);
    }

cleanup:
    return ret;
}

static int
nc_server_configure(const struct lyd_node *node, NC_OPERATION op)
{
    const char *name = LYD_NAME(node);

    if (!strcmp(name, "listen")) {
        if (nc_server_config_listen(op)) {
            goto error;
        }
    } else if (!strcmp(name, "idle-timeout")) {
        if (nc_server_config_idle_timeout(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "endpoint")) {
        if (nc_server_config_endpoint(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "ssh")) {
        if (nc_server_config_ssh(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "local-address")) {
        if (nc_server_config_local_address(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "local-port")) {
        if (nc_server_config_local_port(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "keepalives")) {
        if (nc_server_config_keepalives(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "idle-time")) {
        if (nc_server_config_idle_time(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "max-probes")) {
        if (nc_server_config_max_probes(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "probe-interval")) {
        if (nc_server_config_probe_interval(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "host-key")) {
        if (nc_server_config_host_key(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "public-key-format")) {
        if (nc_server_config_public_key_format(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "public-key")) {
        if (nc_server_config_public_key(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "private-key-format")) {
        if (nc_server_config_private_key_format(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "cleartext-private-key")) {
        if (nc_server_config_cleartext_private_key(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "keystore-reference")) {
        if (nc_server_config_keystore_reference(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "user")) {
        if (nc_server_config_user(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "auth-attempts")) {
        if (nc_server_config_auth_attempts(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "auth-timeout")) {
        if (nc_server_config_auth_timeout(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "truststore-reference")) {
        if (nc_server_config_truststore_reference(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "password")) {
        if (nc_server_config_password(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "pam-config-file-name")) {
        if (nc_server_config_pam_name(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "pam-config-file-dir")) {
        if (nc_server_config_pam_dir(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "none")) {
        if (nc_server_config_none(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "host-key-alg")) {
        if (nc_server_config_host_key_alg(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "key-exchange-alg")) {
        if (nc_server_config_kex_alg(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "encryption-alg")) {
        if (nc_server_config_encryption_alg(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "mac-alg")) {
        if (nc_server_config_mac_alg(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "unix-socket")) {
        if (nc_server_config_unix_socket(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "cert-data")) {} else if (!strcmp(name, "expiration-date")) {} else if (!strcmp(name, "asymmetric-key")) {} else if (!strcmp(name, "certificate")) {} else if (!strcmp(name, "key-format")) {} else if (!strcmp(name,
            "cleartext-key")) {} else if (!strcmp(name, "hidden-key")) {} else if (!strcmp(name, "id_hint")) {} else if (!strcmp(name, "external-identity")) {} else if (!strcmp(name, "hash")) {} else if (!strcmp(name, "context")) {} else if (!strcmp(name,
            "target-protocol")) {} else if (!strcmp(name, "target-kdf")) {} else if (!strcmp(name, "client-authentication")) {} else if (!strcmp(name, "ca-certs")) {} else if (!strcmp(name, "ee-certs")) {} else if (!strcmp(name,
            "raw-public-keys")) {} else if (!strcmp(name, "tls12-psks")) {} else if (!strcmp(name, "tls13-epsks")) {} else if (!strcmp(name, "tls-version")) {} else if (!strcmp(name, "cipher-suite")) {} else if (!strcmp(name,
            "peer-allowed-to-send")) {} else if (!strcmp(name, "test-peer-aliveness")) {} else if (!strcmp(name, "max-wait")) {} else if (!strcmp(name, "max-attempts")) {} else if (!strcmp(name, "cert-to-name")) {} else if (!strcmp(name,
            "id")) {} else if (!strcmp(name, "fingerprint")) {} else if (!strcmp(name, "map-type")) {}

    return 0;

error:
    ERR(NULL, "Configuring (%s) failed.", LYD_NAME(node));
    return 1;
}

int
nc_session_server_parse_tree(const struct lyd_node *node, NC_OPERATION parent_op)
{
    struct lyd_node *child;
    struct lyd_meta *m;
    NC_OPERATION current_op;

    assert(node);

    /* get current op */
    LY_LIST_FOR(node->meta, m) {
        if (!strcmp(m->name, "operation")) {
            if (!strcmp(lyd_get_meta_value(m), "create")) {
                current_op = NC_OP_CREATE;
            } else if (!strcmp(lyd_get_meta_value(m), "delete")) {
                current_op = NC_OP_DELETE;
            } else if (!strcmp(lyd_get_meta_value(m), "replace")) {
                current_op = NC_OP_REPLACE;
            } else if (!strcmp(lyd_get_meta_value(m), "none")) {
                current_op = NC_OP_NONE;
            }
            break;
        }
    }

    /* node has no op, inherit from the parent */
    if (!m) {
        current_op = parent_op;
    }

    switch (current_op) {
    case NC_OP_NONE:
        break;
    case NC_OP_CREATE:
    case NC_OP_DELETE:
    case NC_OP_REPLACE:
        if (nc_server_configure(node, current_op)) {
            return 1;
        }
        break;
    default:
        break;
    }

    if (current_op != NC_OP_DELETE) {
        LY_LIST_FOR(lyd_child(node), child) {
            if (nc_session_server_parse_tree(child, current_op)) {
                return 1;
            }
        }
    }
    return 0;
}

static int
nc_server_config_asymmetric_key_certificate(const struct lyd_node *tree, struct nc_asymmetric_key *key)
{
    int ret = 0;
    struct lyd_node *node;
    void *tmp;

    /* create new certificate */
    tmp = realloc(key->certs, (key->cert_count + 1) * sizeof *key->certs);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    key->certs = tmp;
    key->cert_count++;

    /* set name */
    lyd_find_path(tree, "name", 0, &node);
    assert(node);

    key->certs[key->cert_count - 1].name = strdup(lyd_get_value(node));
    if (!key->certs[key->cert_count - 1].name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* set certificate data */
    lyd_find_path(tree, "cert-data", 0, &node);
    assert(node);

    key->certs[key->cert_count - 1].cert_base64 = strdup(lyd_get_value(node));
    if (!key->certs[key->cert_count - 1].cert_base64) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

cleanup:
    return ret;
}

static int
nc_server_config_asymmetric_key(const struct lyd_node *tree)
{
    int ret = 0;
    struct lyd_node *node = NULL, *iter;
    void *tmp;
    struct nc_keystore *ks = &server_opts.keystore;
    struct nc_asymmetric_key *key;
    const char *format;

    /* create new asymmetric key */
    tmp = realloc(ks->asym_keys, (ks->asym_key_count + 1) * sizeof *ks->asym_keys);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    ks->asym_keys = tmp;
    memset(&ks->asym_keys[ks->asym_key_count], 0, sizeof *ks->asym_keys);
    key = &ks->asym_keys[ks->asym_key_count];
    ks->asym_key_count++;

    /* set name */
    lyd_find_path(tree, "name", 0, &node);
    assert(node);

    key->name = strdup(lyd_get_value(node));
    if (!key->name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* set public-key-format, mandatory */
    lyd_find_path(tree, "public-key-format", 0, &node);
    assert(node);

    format = ((struct lyd_node_term *)node)->value.ident->name;
    if (!strcmp(format, "ssh-public-key-format")) {
        key->pubkey_type = NC_SSH_PUBKEY_SSH2;
    } else if (!strcmp(format, "subject-public-key-info-format")) {
        key->pubkey_type = NC_SSH_PUBKEY_X509;
    } else {
        ERR(NULL, "Public key format \"%s\" not supported.", format);
        ret = 1;
        goto cleanup;
    }

    /* set public-key, mandatory */
    lyd_find_path(tree, "public-key", 0, &node);
    assert(node);

    key->pub_base64 = strdup(lyd_get_value(node));
    if (!key->pub_base64) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* set private-key-format */
    ret = lyd_find_path(tree, "private-key-format", 0, &node);
    if (!ret) {
        format = ((struct lyd_node_term *)node)->value.ident->name;
        if (!strcmp(format, "rsa-private-key-format")) {
            key->privkey_type = NC_SSH_KEY_RSA;
        } else if (!strcmp(format, "ec-private-key-format")) {
            key->privkey_type = NC_SSH_KEY_ECDSA;
        } else {
            ERR(NULL, "Private key format (%s) not supported.", format);
            ret = 1;
            goto cleanup;
        }
    }

    /* set private key, mandatory */
    lyd_find_path(tree, "cleartext-private-key", 0, &node);
    assert(node);

    key->priv_base64 = strdup(lyd_get_value(node));
    if (!key->priv_base64) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* set certificates associated with the key pair */
    ret = lyd_find_path(tree, "certificates", 0, &node);
    if (!ret) {
        node = lyd_child(node);
        if (node) {
            /* certificate list instance */
            LY_LIST_FOR(node, iter) {
                if (nc_server_config_asymmetric_key_certificate(iter, key)) {
                    ret = 1;
                    goto cleanup;
                }
            }
        }
    } else if (ret == LY_ENOTFOUND) {
        /* certificates container not present, but it's ok */
        ret = 0;
    }

cleanup:
    return ret;
}

static int
nc_server_config_symmetric_key(const struct lyd_node *tree)
{
    int ret = 0;
    const char *format;
    struct lyd_node *node;
    struct nc_keystore *ks = &server_opts.keystore;
    struct nc_symmetric_key *key;
    void *tmp;

    /* create new symmetric key */
    tmp = realloc(ks->sym_keys, (ks->sym_key_count + 1) * sizeof *ks->sym_keys);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    memset(&ks->sym_keys[ks->sym_key_count], 0, sizeof *ks->sym_keys);
    ks->sym_keys = tmp;
    key = &ks->sym_keys[ks->sym_key_count];
    ks->sym_key_count++;

    /* set name */
    lyd_find_path(tree, "name", 0, &node);
    assert(node);

    key->name = strdup(lyd_get_value(node));
    if (!key->name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* check if the identity matches with the supported one */
    lyd_find_path(tree, "key-format", 0, &node);
    assert(node);

    format = ((struct lyd_node_term *)node)->value.ident->name;
    if (strcmp(format, "symmetric-key-format")) {
        ret = 1;
        goto cleanup;
    }

    /* set key data */
    lyd_find_path(tree, "cleartext-key", 0, &node);
    assert(node);

    key->base64 = strdup(lyd_get_value(node));
    if (!key->base64) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

cleanup:
    return ret;
}

static int
nc_fill_keystore(const struct lyd_node *data)
{
    int ret = 0;
    uint32_t prev_lo;
    struct lyd_node *tree, *as_keys, *s_keys, *iter;

    /* silently search for nodes, some of them may not be present */
    prev_lo = ly_log_options(0);

    ret = lyd_find_path(data, "/ietf-keystore:keystore", 0, &tree);
    if (ret) {
        VRB(NULL, "Keystore container not found in the YANG data.");
        ret = 0;
        goto cleanup;
    }

    ret = lyd_find_path(tree, "asymmetric-keys", 0, &as_keys);
    if (!ret) {
        /* asymmetric keys container is present */
        as_keys = lyd_child(as_keys);
        if (as_keys && !strcmp(LYD_NAME(as_keys), "asymmetric-key")) {
            /* asymmetric key list */
            LY_LIST_FOR(as_keys, iter) {
                if (nc_server_config_asymmetric_key(iter)) {
                    ret = 1;
                    goto cleanup;
                }
            }
        }
    }

    ret = lyd_find_path(tree, "symmetric-keys", 0, &s_keys);
    if (!ret) {
        /* symmetric keys container is present */
        s_keys = lyd_child(s_keys);
        if (s_keys && !strcmp(LYD_NAME(s_keys), "symmetric-key")) {
            /* symmetric key list */
            LY_LIST_FOR(s_keys, iter) {
                if (nc_server_config_symmetric_key(iter)) {
                    ret = 1;
                    goto cleanup;
                }
            }
        }
    }

cleanup:
    /* reset the logging options back to what they were */
    ly_log_options(prev_lo);
    return ret;
}

static int
nc_server_config_create_truststore_certificate(const struct lyd_node *tree, struct nc_certificate_bag *bag)
{
    int ret = 0;
    struct lyd_node *node;
    void *tmp;
    struct nc_certificate *cert;

    /* create new certificate */
    tmp = realloc(bag->certs, (bag->cert_count + 1) * sizeof *bag->certs);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    memset(&bag->certs[bag->cert_count], 0, sizeof *bag->certs);
    bag->certs = tmp;
    cert = &bag->certs[bag->cert_count];
    bag->cert_count++;

    /* set name */
    lyd_find_path(tree, "name", 0, &node);
    assert(node);

    cert->name = strdup(lyd_get_value(node));
    if (!cert->name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* set cert data */
    lyd_find_path(tree, "cert-data", 0, &node);
    assert(node);

    cert->cert_base64 = strdup(lyd_get_value(node));
    if (!cert->cert_base64) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

cleanup:
    return ret;
}

static int
nc_server_config_certificate_bag(const struct lyd_node *tree)
{
    int ret = 0;
    struct lyd_node *node = NULL, *iter;
    void *tmp;
    struct nc_truststore *ts = &server_opts.truststore;
    struct nc_certificate_bag *bag;

    /* create new certificate bag */
    tmp = realloc(ts->cert_bags, (ts->cert_bag_count + 1) * sizeof *ts->cert_bags);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    ts->cert_bags = tmp;
    memset(&ts->cert_bags[ts->cert_bag_count], 0, sizeof *ts->cert_bags);
    bag = &ts->cert_bags[ts->cert_bag_count];
    ts->cert_bag_count++;

    /* set name */
    lyd_find_path(tree, "name", 0, &node);
    assert(node);

    bag->name = strdup(lyd_get_value(node));
    if (!bag->name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* set certificates associated with this bag */
    ret = lyd_find_path(tree, "certificate", 0, &node);
    if (!ret) {
        LY_LIST_FOR(node, iter) {
            if (nc_server_config_create_truststore_certificate(iter, bag)) {
                ret = 1;
                goto cleanup;
            }
        }
    } else if (ret == LY_ENOTFOUND) {
        /* certificate list not present, but it's ok */
        ret = 0;
    }

cleanup:
    return ret;
}

static int
nc_server_config_create_truststore_public_key(const struct lyd_node *tree, struct nc_public_key_bag *bag)
{
    int ret = 0;
    struct lyd_node *node;
    void *tmp;
    struct nc_public_key *key;
    const char *format;

    /* create new public key */
    tmp = realloc(bag->pubkeys, (bag->pubkey_count + 1) * sizeof *bag->pubkeys);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    bag->pubkeys = tmp;
    memset(&bag->pubkeys[bag->pubkey_count], 0, sizeof *bag->pubkeys);
    key = &bag->pubkeys[bag->pubkey_count];
    bag->pubkey_count++;

    /* set name */
    lyd_find_path(tree, "name", 0, &node);
    assert(node);

    key->name = strdup(lyd_get_value(node));
    if (!key->name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* set public-key-format, mandatory */
    lyd_find_path(tree, "public-key-format", 0, &node);
    assert(node);

    format = ((struct lyd_node_term *)node)->value.ident->name;
    if (!strcmp(format, "ssh-public-key-format")) {
        key->pubkey_type = NC_SSH_PUBKEY_SSH2;
    } else if (!strcmp(format, "subject-public-key-info-format")) {
        key->pubkey_type = NC_SSH_PUBKEY_X509;
    } else {
        ERR(NULL, "Public key format \"%s\" not supported.", format);
        ret = 1;
        goto cleanup;
    }

    /* set public key data */
    lyd_find_path(tree, "public-key", 0, &node);
    assert(node);

    key->pub_base64 = strdup(lyd_get_value(node));
    if (!key->pub_base64) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

cleanup:
    return ret;
}

static int
nc_server_config_public_key_bag(const struct lyd_node *tree)
{
    int ret = 0;
    struct lyd_node *node = NULL, *iter;
    void *tmp;
    struct nc_truststore *ts = &server_opts.truststore;
    struct nc_public_key_bag *bag;
    const struct lysc_node *schema;

    /* create new public key bag */
    tmp = realloc(ts->pub_bags, (ts->pub_bag_count + 1) * sizeof *ts->pub_bags);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    ts->pub_bags = tmp;
    memset(&ts->pub_bags[ts->pub_bag_count], 0, sizeof *ts->pub_bags);
    bag = &ts->pub_bags[ts->pub_bag_count];
    ts->pub_bag_count++;

    /* set name */
    lyd_find_path(tree, "name", 0, &node);
    assert(node);

    bag->name = strdup(lyd_get_value(node));
    if (!bag->name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* get the schema node of public key so we can iterate over it's list */
    schema = lys_find_path(NULL, tree->schema, "public-key", 0);
    LYD_LIST_FOR_INST(node, schema, iter) {
        /* set public keys associated with this bag */
        if (nc_server_config_create_truststore_public_key(iter, bag)) {
            ret = 1;
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

static int
nc_fill_truststore(const struct lyd_node *data)
{
    int ret = 0;
    struct lyd_node *tree, *cert_bags, *pub_bags, *iter;
    uint32_t prev_lo;

    /* silently search for nodes, some of them may not be present */
    prev_lo = ly_log_options(0);

    ret = lyd_find_path(data, "/ietf-truststore:truststore", 0, &tree);
    if (ret) {
        VRB(NULL, "Truststore container not found in the YANG data.");
        ret = 0;
        goto cleanup;
    }

    ret = lyd_find_path(tree, "certificate-bags", 0, &cert_bags);
    if (!ret) {
        /* certificate bags container is present */
        cert_bags = lyd_child(cert_bags);
        if (cert_bags && !strcmp(LYD_NAME(cert_bags), "certificate-bag")) {
            /* certificate bag list */
            LY_LIST_FOR(cert_bags, iter) {
                if (nc_server_config_certificate_bag(iter)) {
                    ret = 1;
                    goto cleanup;
                }
            }
        }
    }

    ret = lyd_find_path(tree, "public-key-bags", 0, &pub_bags);
    if (!ret) {
        /* public key bags container is present */
        pub_bags = lyd_child(pub_bags);
        if (pub_bags && !strcmp(LYD_NAME(pub_bags), "public-key-bag")) {
            /* public key bag list */
            LY_LIST_FOR(pub_bags, iter) {
                if (nc_server_config_public_key_bag(iter)) {
                    ret = 1;
                    goto cleanup;
                }
            }
        }
    } else if (ret == LY_ENOTFOUND) {
        /* it's not mandatory so it's ok */
        ret = 0;
    }

cleanup:
    /* reset the logging options back to what they were */
    ly_log_options(prev_lo);
    return ret;
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
    /* no private-key-encryption and csr-generation */
    const char *ietf_crypto_types[] = {
        "one-symmetric-key-format", "one-asymmetric-key-format", "symmetrically-encrypted-value-format",
        "asymmetrically-encrypted-value-format", "cms-enveloped-data-format", "cms-encrypted-data-format",
        "p10-based-csrs", "certificate-expiration-notification", "hidden-keys", "password-encryption",
        "symmetric-key-encryption", NULL
    };
    /* all features */
    const char *ietf_tcp_common[] = {"keepalives-supported", NULL};
    /* no ssh-x509-certs */
    const char *ietf_ssh_common[] = {"transport-params", "public-key-generation", NULL};
    /* all features */
    const char *iana_ssh_encryption_algs[] = {NULL};
    /* all features */
    const char *iana_ssh_key_exchange_algs[] = {NULL};
    /* all features */
    const char *iana_ssh_mac_algs[] = {NULL};
    /* all features */
    const char *iana_ssh_public_key_algs[] = {NULL};
    /* all features */
    const char *ietf_keystore[] = {"central-keystore-supported", "local-definitions-supported", "asymmetric-keys", "symmetric-keys", NULL};
    /* no ssh-server-keepalives and local-user-auth-hostbased */
    const char *ietf_ssh_server[] = {"local-users-supported", "local-user-auth-publickey", "local-user-auth-password", "local-user-auth-none", NULL};
    /* all features */
    const char *ietf_truststore[] = {"central-truststore-supported", "local-definitions-supported", "certificates", "public-keys", NULL};
    /* all features */
    const char *ietf_tls_server[] = {
        "tls-server-keepalives", "server-ident-x509-cert", "server-ident-raw-public-key", "server-ident-tls12-psk",
        "server-ident-tls13-epsk", "client-auth-supported", "client-auth-x509-cert", "client-auth-raw-public-key",
        "client-auth-tls12-psk", "client-auth-tls13-epsk", NULL
    };
    /* all features */
    const char *libnetconf2_netconf_server[] = {NULL};

    const char *module_names[] = {
        "ietf-netconf-server", "ietf-x509-cert-to-name", "ietf-crypto-types",
        "ietf-tcp-common", "ietf-ssh-common", "iana-ssh-encryption-algs",
        "iana-ssh-key-exchange-algs", "iana-ssh-mac-algs", "iana-ssh-public-key-algs",
        "ietf-keystore", "ietf-ssh-server", "ietf-truststore",
        "ietf-tls-server", "libnetconf2-netconf-server", NULL
    };

    const char **module_features[] = {
        ietf_nectonf_server, ietf_x509_cert_to_name, ietf_crypto_types,
        ietf_tcp_common, ietf_ssh_common, iana_ssh_encryption_algs,
        iana_ssh_key_exchange_algs, iana_ssh_mac_algs, iana_ssh_public_key_algs,
        ietf_keystore, ietf_ssh_server, ietf_truststore,
        ietf_tls_server, libnetconf2_netconf_server, NULL
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

API int
nc_server_config_setup_path(const struct ly_ctx *ctx, const char *path)
{
    struct lyd_node *tree = NULL;
    int ret = 0;

    if (!path) {
        ERRARG("Missing path parameter.");
        ret = 1;
        goto cleanup;
    }

    ret = lyd_parse_data_path(ctx, path, LYD_XML, LYD_PARSE_NO_STATE | LYD_PARSE_STRICT, LYD_VALIDATE_NO_STATE, &tree);
    if (ret) {
        goto cleanup;
    }

    ret = nc_server_config_setup(tree);
    if (ret) {
        goto cleanup;
    }

cleanup:
    lyd_free_all(tree);
    return ret;
}

API int
nc_server_config_setup(const struct lyd_node *data)
{
    int ret = 0;
    struct lyd_node *tree;
    struct lyd_meta *m;
    NC_OPERATION op = NC_OP_NONE;

    /* LOCK */
    pthread_rwlock_wrlock(&server_opts.config_lock);

    ret = nc_fill_keystore(data);
    if (ret) {
        ERR(NULL, "Filling keystore failed.");
        goto cleanup;
    }

    ret = nc_fill_truststore(data);
    if (ret) {
        ERR(NULL, "Filling truststore failed.");
        goto cleanup;
    }

    ret = lyd_find_path(data, "/ietf-netconf-server:netconf-server", 0, &tree);
    if (ret) {
        ERR(NULL, "Unable to find the netconf-server container in the YANG data.");
        goto cleanup;
    }

    LY_LIST_FOR(tree->meta, m) {
        if (!strcmp(m->name, "operation")) {
            if (!strcmp(lyd_get_meta_value(m), "create")) {
                op = NC_OP_CREATE;
            } else if (!strcmp(lyd_get_meta_value(m), "delete")) {
                op = NC_OP_DELETE;
            } else if (!strcmp(lyd_get_meta_value(m), "replace")) {
                op = NC_OP_REPLACE;
            } else if (!strcmp(lyd_get_meta_value(m), "none")) {
                op = NC_OP_NONE;
            } else {
                ERR(NULL, "Unexpected operation (%s).", lyd_get_meta_value(m));
                ret = 1;
                goto cleanup;
            }
        }
    }

    if (nc_session_server_parse_tree(tree, op)) {
        ret = 1;
        goto cleanup;
    }

cleanup:
    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);
    return ret;
}
