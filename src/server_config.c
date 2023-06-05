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
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "server_config.h"
#include "server_config_p.h"
#include "session_p.h"

#ifdef NC_ENABLED_SSH

/* All libssh supported host-key, key-exchange, encryption and mac algorithms as of version 0.10.90 */

static const char *supported_hostkey_algs[] = {
    "openssh-ssh-ed25519-cert-v01", "openssh-ecdsa-sha2-nistp521-cert-v01",
    "openssh-ecdsa-sha2-nistp384-cert-v01", "openssh-ecdsa-sha2-nistp256-cert-v01",
    "openssh-rsa-sha2-512-cert-v01", "openssh-rsa-sha2-256-cert-v01",
    "openssh-ssh-rsa-cert-v01", "openssh-ssh-dss-cert-v01",
    "ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256",
    "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss", NULL
};

static const char *supported_kex_algs[] = {
    "diffie-hellman-group-exchange-sha1", "curve25519-sha256", "libssh-curve25519-sha256",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group18-sha512",
    "diffie-hellman-group16-sha512", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha256", NULL
};

static const char *supported_encryption_algs[] = {
    "openssh-chacha20-poly1305", "openssh-aes256-gcm", "openssh-aes128-gcm",
    "aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc",
    "blowfish-cbc", "triple-des-cbc", "none", NULL
};

static const char *supported_mac_algs[] = {
    "openssh-hmac-sha2-256-etm", "openssh-hmac-sha2-512-etm", "openssh-hmac-sha1-etm",
    "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", NULL
};

#endif /* NC_ENABLED_SSH */

extern struct nc_server_opts server_opts;

int
nc_server_config_get_endpt(const struct lyd_node *node, struct nc_endpt **endpt, struct nc_bind **bind)
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

#ifdef NC_ENABLED_SSH

int
nc_server_config_get_hostkey(const struct lyd_node *node, const struct nc_server_ssh_opts *opts, struct nc_hostkey **hostkey)
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

int
nc_server_config_get_auth_client(const struct lyd_node *node, const struct nc_server_ssh_opts *opts, struct nc_client_auth **auth_client)
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

int
nc_server_config_get_pubkey(const struct lyd_node *node, const struct nc_client_auth *auth_client, struct nc_public_key **pubkey)
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

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

int
nc_server_config_get_cert(const struct lyd_node *node, struct nc_cert_grouping *auth_client, struct nc_certificate **cert)
{
    uint16_t i;
    const char *cert_name;

    assert(node && auth_client);

    while (node) {
        if (!strcmp(LYD_NAME(node), "certificate")) {
            break;
        }
        node = lyd_parent(node);
    }

    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in a certificate subtree.", LYD_NAME(node));
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));
    cert_name = lyd_get_value(node);

    for (i = 0; i < auth_client->cert_count; i++) {
        if (!strcmp(auth_client->certs[i].name, cert_name)) {
            *cert = &auth_client->certs[i];
            return 0;
        }
    }

    ERR(NULL, "Certificate \"%s\" was not found.", cert_name);
    return 1;
}

static int
nc_server_config_get_ctn(const struct lyd_node *node, struct nc_endpt *endpt, struct nc_ctn **ctn)
{
    uint32_t id;
    struct nc_ctn *iter;

    assert(node && endpt);

    node = lyd_parent(node);
    while (node) {
        if (!strcmp(LYD_NAME(node), "cert-to-name")) {
            break;
        }
        node = lyd_parent(node);
    }

    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in a cert-to-name subtree.", LYD_NAME(node));
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "id"));
    id = strtoul(lyd_get_value(node), NULL, 10);

    iter = endpt->opts.tls->ctn;
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

#endif /* NC_ENABLED_TLS */

int
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

NC_PRIVKEY_FORMAT
nc_server_config_get_private_key_type(const char *format)
{
    if (!strcmp(format, "rsa-private-key-format")) {
        return NC_PRIVKEY_FORMAT_RSA;
    } else if (!strcmp(format, "ec-private-key-format")) {
        return NC_PRIVKEY_FORMAT_EC;
    } else if (!strcmp(format, "subject-private-key-info-format")) {
        return NC_PRIVKEY_FORMAT_X509;
    } else if (!strcmp(format, "openssh-private-key-format")) {
        return NC_PRIVKEY_FORMAT_OPENSSH;
    } else {
        ERR(NULL, "Private key format (%s) not supported.", format);
        return NC_PRIVKEY_FORMAT_UNKNOWN;
    }
}

int
nc_server_config_realloc(const char *key_value, void **ptr, size_t size, uint16_t *count)
{
    int ret = 0;
    void *tmp;
    char **name;

    tmp = realloc(*ptr, (*count + 1) * size);
    if (!tmp) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    *ptr = tmp;

    /* set the newly allocated memory to 0 */
    memset((char *)(*ptr) + (*count * size), 0, size);
    (*count)++;

    /* access the first member of the supposed structure */
    name = (char **)((*ptr) + ((*count - 1) * size));

    /* and set it's value */
    *name = strdup(key_value);
    if (!*name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

cleanup:
    return ret;
}

static int
is_listen(const struct lyd_node *node)
{
    assert(node);

    while (node) {
        if (!strcmp(LYD_NAME(node), "listen")) {
            break;
        }
        node = lyd_parent(node);
    }

    return node != NULL;
}

// static int
// is_ch(const struct lyd_node *node)
// {
// assert(node);

// while (node) {
// if (!strcmp(LYD_NAME(node), "call-home")) {
// break;
// }
// node = lyd_parent(node);
// }

// return node != NULL;
// }

#ifdef NC_ENABLED_SSH

static int
is_ssh(const struct lyd_node *node)
{
    assert(node);

    while (node) {
        if (!strcmp(LYD_NAME(node), "ssh")) {
            break;
        }
        node = lyd_parent(node);
    }

    return node != NULL;
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS
static int
is_tls(const struct lyd_node *node)
{
    assert(node);

    while (node) {
        if (!strcmp(LYD_NAME(node), "tls")) {
            break;
        }
        node = lyd_parent(node);
    }

    return node != NULL;
}

#endif /* NC_ENABLED_TLS */

static void
nc_server_config_del_endpt_name(struct nc_endpt *endpt)
{
    free(endpt->name);
    endpt->name = NULL;
}

static void
nc_server_config_del_local_address(struct nc_bind *bind)
{
    free(bind->address);
    bind->address = NULL;
}

#ifdef NC_ENABLED_SSH

static void
nc_server_config_del_auth_client_pam_name(struct nc_client_auth *auth_client)
{
    free(auth_client->pam_config_name);
    auth_client->pam_config_name = NULL;
}

static void
nc_server_config_del_auth_client_pam_dir(struct nc_client_auth *auth_client)
{
    free(auth_client->pam_config_dir);
    auth_client->pam_config_dir = NULL;
}

static void
nc_server_config_del_endpt_reference(struct nc_endpt *endpt)
{
    free(endpt->referenced_endpt_name);
    endpt->referenced_endpt_name = NULL;
}

static void
nc_server_config_del_hostkey_name(struct nc_hostkey *hostkey)
{
    free(hostkey->name);
    hostkey->name = NULL;
}

static void
nc_server_config_del_public_key(struct nc_hostkey *hostkey)
{
    free(hostkey->key.pubkey_data);
    hostkey->key.pubkey_data = NULL;
}

static void
nc_server_config_del_private_key(struct nc_hostkey *hostkey)
{
    free(hostkey->key.privkey_data);
    hostkey->key.privkey_data = NULL;
}

static void
nc_server_config_del_auth_client_username(struct nc_client_auth *auth_client)
{
    free(auth_client->username);
    auth_client->username = NULL;
}

static void
nc_server_config_del_auth_client_pubkey_name(struct nc_public_key *pubkey)
{
    free(pubkey->name);
    pubkey->name = NULL;
}

static void
nc_server_config_del_auth_client_pubkey_pub_base64(struct nc_public_key *pubkey)
{
    free(pubkey->data);
    pubkey->data = NULL;
}

static void
nc_server_config_del_auth_client_password(struct nc_client_auth *auth_client)
{
    free(auth_client->password);
    auth_client->password = NULL;
}

static void
nc_server_config_del_hostkey_algs(struct nc_server_ssh_opts *opts)
{
    free(opts->hostkey_algs);
    opts->hostkey_algs = NULL;
}

static void
nc_server_config_del_kex_algs(struct nc_server_ssh_opts *opts)
{
    free(opts->kex_algs);
    opts->kex_algs = NULL;
}

static void
nc_server_config_del_encryption_algs(struct nc_server_ssh_opts *opts)
{
    free(opts->encryption_algs);
    opts->encryption_algs = NULL;
}

static void
nc_server_config_del_mac_algs(struct nc_server_ssh_opts *opts)
{
    free(opts->mac_algs);
    opts->mac_algs = NULL;
}

static void
nc_server_config_del_hostkey(struct nc_server_ssh_opts *opts, struct nc_hostkey *hostkey)
{
    assert(hostkey->store == NC_STORE_LOCAL || hostkey->store == NC_STORE_KEYSTORE);

    if (hostkey->store == NC_STORE_LOCAL) {
        nc_server_config_del_public_key(hostkey);
        nc_server_config_del_private_key(hostkey);
    }

    nc_server_config_del_hostkey_name(hostkey);
    opts->hostkey_count--;
    if (!opts->hostkey_count) {
        free(opts->hostkeys);
        opts->hostkeys = NULL;
    }
}

static void
nc_server_config_del_auth_client_pubkey(struct nc_client_auth *auth_client, struct nc_public_key *pubkey)
{
    nc_server_config_del_auth_client_pubkey_name(pubkey);
    nc_server_config_del_auth_client_pubkey_pub_base64(pubkey);

    auth_client->pubkey_count--;
    if (!auth_client->pubkey_count) {
        free(auth_client->pubkeys);
        auth_client->pubkeys = NULL;
    }
}

static void
nc_server_config_del_auth_client(struct nc_server_ssh_opts *opts, struct nc_client_auth *auth_client)
{
    uint16_t i, pubkey_count;

    if (auth_client->store == NC_STORE_LOCAL) {
        pubkey_count = auth_client->pubkey_count;
        for (i = 0; i < pubkey_count; i++) {
            nc_server_config_del_auth_client_pubkey(auth_client, &auth_client->pubkeys[i]);
        }
    }

    nc_server_config_del_auth_client_password(auth_client);
    nc_server_config_del_auth_client_pam_name(auth_client);
    nc_server_config_del_auth_client_pam_dir(auth_client);
    nc_server_config_del_auth_client_username(auth_client);

    opts->client_count--;
    if (!opts->client_count) {
        free(opts->auth_clients);
        opts->auth_clients = NULL;
    }
}

static void
nc_server_config_del_ssh(struct nc_bind *bind, struct nc_server_ssh_opts *opts)
{
    uint16_t i, hostkey_count, client_count;

    nc_server_config_del_local_address(bind);
    if (bind->sock > -1) {
        close(bind->sock);
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

    nc_server_config_del_hostkey_algs(opts);
    nc_server_config_del_kex_algs(opts);
    nc_server_config_del_encryption_algs(opts);
    nc_server_config_del_mac_algs(opts);

    free(opts);
    opts = NULL;
}

void
nc_server_config_del_endpt_ssh(struct nc_endpt *endpt, struct nc_bind *bind)
{
    nc_server_config_del_endpt_name(endpt);
    nc_server_config_del_endpt_reference(endpt);
    nc_server_config_del_ssh(bind, endpt->opts.ssh);

    server_opts.endpt_count--;
    if (!server_opts.endpt_count) {
        free(server_opts.endpts);
        free(server_opts.binds);
        server_opts.endpts = NULL;
        server_opts.binds = NULL;
    }
}

#endif /* NC_ENABLED_SSH */

void
nc_server_config_del_unix_socket(struct nc_bind *bind, struct nc_server_unix_opts *opts)
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
nc_server_config_del_endpt_unix_socket(struct nc_endpt *endpt, struct nc_bind *bind)
{
    nc_server_config_del_endpt_name(endpt);
    nc_server_config_del_unix_socket(bind, endpt->opts.unixsock);

    server_opts.endpt_count--;
    if (!server_opts.endpt_count) {
        free(server_opts.endpts);
        free(server_opts.binds);
        server_opts.endpts = NULL;
        server_opts.binds = NULL;
    }
}

#ifdef NC_ENABLED_TLS

static void
nc_server_config_tls_del_public_key(struct nc_server_tls_opts *opts)
{
    free(opts->pubkey_data);
    opts->pubkey_data = NULL;
}

static void
nc_server_config_tls_del_cleartext_private_key(struct nc_server_tls_opts *opts)
{
    free(opts->privkey_data);
    opts->privkey_data = NULL;
}

static void
nc_server_config_tls_del_cert_data(struct nc_server_tls_opts *opts)
{
    free(opts->cert_data);
    opts->cert_data = NULL;
}

static void
nc_server_config_tls_del_cert_data_certificate(struct nc_certificate *cert)
{
    free(cert->data);
    cert->data = NULL;
}

static void
nc_server_config_del_fingerprint(struct nc_ctn *ctn)
{
    free(ctn->fingerprint);
    ctn->fingerprint = NULL;
}

static void
nc_server_config_del_cert(struct nc_cert_grouping *certs, struct nc_certificate *cert)
{
    free(cert->name);
    cert->name = NULL;

    free(cert->data);
    cert->data = NULL;

    certs->cert_count--;
    if (!certs->cert_count) {
        free(certs->certs);
        certs->certs = NULL;
    }
}

static void
nc_server_config_tls_del_certs(struct nc_cert_grouping *ca)
{
    uint16_t i, cert_count;

    if (ca->store == NC_STORE_LOCAL) {
        cert_count = ca->cert_count;
        for (i = 0; i < cert_count; i++) {
            nc_server_config_del_cert(ca, &ca->certs[i]);
        }
    }
}

static void
nc_server_config_del_ctn(struct nc_server_tls_opts *opts, struct nc_ctn *ctn)
{
    struct nc_ctn *iter;

    free(ctn->fingerprint);
    ctn->fingerprint = NULL;

    free(ctn->name);
    ctn->name = NULL;

    if (opts->ctn == ctn) {
        /* it's the first in the list */
        opts->ctn = ctn->next;
        free(ctn);
        return;
    }

    iter = opts->ctn;
    while (iter) {
        if (iter->next == ctn) {
            /* found the ctn */
            break;
        }
        iter = iter->next;
    }

    iter->next = ctn->next;
    free(ctn);
}

static void
nc_server_config_del_ctns(struct nc_server_tls_opts *opts)
{
    struct nc_ctn *cur, *next;

    cur = opts->ctn;
    while (cur) {
        next = cur->next;
        free(cur->fingerprint);
        free(cur->name);
        free(cur);
        cur = next;
    }
    opts->ctn = NULL;
}

static void
nc_server_config_del_tls(struct nc_bind *bind, struct nc_server_tls_opts *opts)
{
    nc_server_config_del_local_address(bind);
    if (bind->sock > -1) {
        close(bind->sock);
    }

    if (opts->store == NC_STORE_LOCAL) {
        nc_server_config_tls_del_public_key(opts);
        nc_server_config_tls_del_cleartext_private_key(opts);
        nc_server_config_tls_del_cert_data(opts);
    }

    nc_server_config_tls_del_certs(&opts->ca_certs);
    nc_server_config_tls_del_certs(&opts->ee_certs);

    nc_server_config_del_ctns(opts);

    free(opts);
}

static void
nc_server_config_del_endpt_tls(struct nc_endpt *endpt, struct nc_bind *bind)
{
    nc_server_config_del_endpt_name(endpt);
    nc_server_config_del_tls(bind, endpt->opts.tls);

    server_opts.endpt_count--;
    if (!server_opts.endpt_count) {
        free(server_opts.endpts);
        free(server_opts.binds);
        server_opts.endpts = NULL;
        server_opts.binds = NULL;
    }
}

#endif /* NC_ENABLED_TLS */

/* presence container */
int
nc_server_config_listen(struct lyd_node *node, NC_OPERATION op)
{
    uint16_t i, endpt_count;

    (void) node;

    assert(op == NC_OP_CREATE || op == NC_OP_DELETE);

    if (op == NC_OP_DELETE) {
        endpt_count = server_opts.endpt_count;
        for (i = 0; i < endpt_count; i++) {
            switch (server_opts.endpts[i].ti) {
#ifdef NC_ENABLED_SSH
            case NC_TI_LIBSSH:
                nc_server_config_del_endpt_ssh(&server_opts.endpts[i], &server_opts.binds[i]);
                break;
#endif /* NC_ENABLED_SSH */
#ifdef NC_ENABLED_TLS
            case NC_TI_OPENSSL:
                nc_server_config_del_endpt_tls(&server_opts.endpts[i], &server_opts.binds[i]);
                break;
#endif /* NC_ENABLED_TLS */
            case NC_TI_UNIX:
                nc_server_config_del_endpt_unix_socket(&server_opts.endpts[i], &server_opts.binds[i]);
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
nc_server_config_create_bind(void)
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
nc_server_config_create_endpoint(const struct lyd_node *node)
{
    if (nc_server_config_create_bind()) {
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&server_opts.endpts, sizeof *server_opts.endpts, &server_opts.endpt_count);
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
#ifdef NC_ENABLED_SSH
        case NC_TI_LIBSSH:
            nc_server_config_del_endpt_ssh(endpt, bind);
            break;
#endif /* NC_ENABLED_SSH */
#ifdef NC_ENABLED_TLS
        case NC_TI_OPENSSL:
            nc_server_config_del_endpt_tls(endpt, bind);
            break;
#endif /* NC_ENABLED_TLS */
        case NC_TI_UNIX:
            nc_server_config_del_endpt_unix_socket(endpt, bind);
            break;
        case NC_TI_NONE:
        case NC_TI_FD:
            ERRINT;
            ret = 1;
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

#ifdef NC_ENABLED_SSH

static int
nc_server_config_create_ssh(struct nc_endpt *endpt)
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
        nc_server_config_del_ssh(bind, endpt->opts.ssh);
    }

cleanup:
    return ret;
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

static int
nc_server_config_create_tls(struct nc_endpt *endpt)
{
    endpt->ti = NC_TI_OPENSSL;
    endpt->opts.tls = calloc(1, sizeof *endpt->opts.tls);
    if (!endpt->opts.tls) {
        ERRMEM;
        return 1;
    }

    return 0;
}

static int
nc_server_config_tls(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_endpt *endpt;
    struct nc_bind *bind;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "tls"));

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
        nc_server_config_del_tls(bind, endpt->opts.tls);
    }

cleanup:
    return ret;
}

#endif /* NC_ENABLED_TLS */

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
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
            ret = 1;
            goto cleanup;
        }

        nc_server_config_del_local_address(bind);
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
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
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

    if (equal_parent_name(node, 1, "tcp-server-parameters")) {
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
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
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
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
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
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
        if (nc_server_config_get_endpt(node, &endpt, &bind)) {
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

#ifdef NC_ENABLED_SSH

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
    struct nc_endpt *endpt;
    struct nc_hostkey *hostkey;
    int ret = 0;

    assert(!strcmp(LYD_NAME(node), "host-key"));

    if ((equal_parent_name(node, 1, "server-identity")) && (equal_parent_name(node, 5, "listen"))) {
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            ret = nc_server_config_create_host_key(node, endpt->opts.ssh);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            if (nc_server_config_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
                ret = 1;
                goto cleanup;
            }

            nc_server_config_del_hostkey(endpt->opts.ssh, hostkey);
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

#endif /* NC_ENABLED_SSH */

/* mandatory leaf */
static int
nc_server_config_public_key_format(const struct lyd_node *node, NC_OPERATION op)
{
    const char *format;
    int ret = 0;
    NC_PUBKEY_FORMAT pubkey_type;
    struct nc_endpt *endpt;

#ifdef NC_ENABLED_SSH
    struct nc_client_auth *auth_client;
    struct nc_public_key *pubkey;
    struct nc_hostkey *hostkey;
#endif /* NC_ENABLED_SSH */

    assert(!strcmp(LYD_NAME(node), "public-key-format"));

    format = ((struct lyd_node_term *)node)->value.ident->name;
    if (!strcmp(format, "ssh-public-key-format")) {
        pubkey_type = NC_PUBKEY_FORMAT_SSH2;
    } else if (!strcmp(format, "subject-public-key-info-format")) {
        pubkey_type = NC_PUBKEY_FORMAT_X509;
    } else {
        ERR(NULL, "Public key format (%s) not supported.", format);
        ret = 1;
        goto cleanup;
    }

#ifdef NC_ENABLED_SSH
    if ((equal_parent_name(node, 6, "client-authentication")) && (is_ssh(node)) && (is_listen(node))) {
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_config_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_config_get_pubkey(node, auth_client, &pubkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            pubkey->type = pubkey_type;
        }
    } else if (equal_parent_name(node, 5, "server-identity") && is_ssh(node) && is_listen(node)) {
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_config_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            hostkey->key.pubkey_type = pubkey_type;
        }
    }
#endif /* NC_ENABLED_SSH */
#ifdef NC_ENABLED_TLS
    if (equal_parent_name(node, 3, "server-identity") && is_tls(node) && is_listen(node)) {
        /* TLS listen server-identity */
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            endpt->opts.tls->pubkey_type = pubkey_type;
        }
    }
#endif /* NC_ENABLED_TLS */

cleanup:
    return ret;
}

/* leaf */
static int
nc_server_config_private_key_format(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    const char *format;
    struct nc_endpt *endpt;
    NC_PRIVKEY_FORMAT privkey_type;

#ifdef NC_ENABLED_SSH
    struct nc_hostkey *hostkey;
#endif /* NC_ENABLED_SSH */

    (void) op;

    assert(!strcmp(LYD_NAME(node), "private-key-format"));

    if (nc_server_config_get_endpt(node, &endpt, NULL)) {
        ret = 1;
        goto cleanup;
    }

    format = ((struct lyd_node_term *)node)->value.ident->name;
    if (!format) {
        ret = 1;
        goto cleanup;
    }

    privkey_type = nc_server_config_get_private_key_type(format);
    if (privkey_type == NC_PRIVKEY_FORMAT_UNKNOWN) {
        ret = 1;
        goto cleanup;
    }

#ifdef NC_ENABLED_SSH
    if ((is_ssh(node)) && (is_listen(node))) {
        /* listen ssh */
        if (nc_server_config_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        hostkey->key.privkey_type = privkey_type;
    }
#endif /* NC_ENABLED_SSH */
#ifdef NC_ENABLED_TLS
    if ((is_tls(node)) && (is_listen(node))) {
        /* listen tls */

        endpt->opts.tls->privkey_type = privkey_type;
    }
#endif /* NC_ENABLED_TLS */

cleanup:
    return ret;
}

#ifdef NC_ENABLED_SSH

static int
nc_server_config_replace_cleartext_private_key(const struct lyd_node *node, struct nc_hostkey *hostkey)
{
    nc_server_config_del_private_key(hostkey);
    hostkey->key.privkey_data = strdup(lyd_get_value(node));
    if (!hostkey->key.privkey_data) {
        ERRMEM;
        return 1;
    }

    return 0;
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS
static int
nc_server_config_tls_replace_cleartext_private_key(const struct lyd_node *node, struct nc_server_tls_opts *opts)
{
    nc_server_config_tls_del_cleartext_private_key(opts);
    opts->privkey_data = strdup(lyd_get_value(node));
    if (!opts->privkey_data) {
        ERRMEM;
        return 1;
    }

    return 0;
}

#endif /* NC_ENABLED_TLS */

static int
nc_server_config_cleartext_private_key(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;

#ifdef NC_ENABLED_SSH
    struct nc_hostkey *hostkey;
#endif /* NC_ENABLED_SSH */

    assert(!strcmp(LYD_NAME(node), "cleartext-private-key"));

    if (nc_server_config_get_endpt(node, &endpt, NULL)) {
        ret = 1;
        goto cleanup;
    }

#ifdef NC_ENABLED_SSH
    if ((is_ssh(node)) && (is_listen(node))) {
        if (nc_server_config_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_replace_cleartext_private_key(node, hostkey);
            if (ret) {
                goto cleanup;
            }
        } else {
            nc_server_config_del_private_key(hostkey);
        }
    }
#endif /* NC_ENABLED_SSH */
#ifdef NC_ENABLED_TLS
    if ((is_tls(node)) && (is_listen(node))) {
        /* listen tls */

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_tls_replace_cleartext_private_key(node, endpt->opts.tls);
            if (ret) {
                goto cleanup;
            }
        } else {
            nc_server_config_tls_del_cleartext_private_key(endpt->opts.tls);
        }
    }
#endif /* NC_ENABLED_TLS */

cleanup:
    return ret;
}

#ifdef NC_ENABLED_SSH

static int
nc_server_config_create_keystore_reference(const struct lyd_node *node, struct nc_hostkey *hostkey)
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

    if ((equal_parent_name(node, 3, "server-identity")) && (is_ssh(node)) && (is_listen(node))) {
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }
        if (nc_server_config_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to keystore */
            hostkey->store = NC_STORE_KEYSTORE;

            ret = nc_server_config_create_keystore_reference(node, hostkey);
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
nc_server_config_create_auth_key_public_key_list(const struct lyd_node *node, struct nc_client_auth *auth_client)
{
    assert(!strcmp(LYD_NAME(node), "public-key"));

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&auth_client->pubkeys, sizeof *auth_client->pubkeys, &auth_client->pubkey_count);
}

static int
nc_server_config_replace_auth_key_public_key_leaf(const struct lyd_node *node, struct nc_public_key *pubkey)
{
    nc_server_config_del_auth_client_pubkey_pub_base64(pubkey);

    pubkey->data = strdup(lyd_get_value(node));
    if (!pubkey->data) {
        ERRMEM;
        return 1;
    }

    return 0;
}

static int
nc_server_config_replace_host_key_public_key(const struct lyd_node *node, struct nc_hostkey *hostkey)
{
    nc_server_config_del_public_key(hostkey);

    hostkey->key.pubkey_data = strdup(lyd_get_value(node));
    if (!hostkey->key.pubkey_data) {
        ERRMEM;
        return 1;
    }

    return 0;
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS
static int
nc_server_config_tls_replace_server_public_key(const struct lyd_node *node, struct nc_server_tls_opts *opts)
{
    nc_server_config_tls_del_public_key(opts);

    opts->pubkey_data = strdup(lyd_get_value(node));
    if (!opts->pubkey_data) {
        ERRMEM;
        return 1;
    }

    return 0;
}

#endif /* NC_ENABLED_TLS */

static int
nc_server_config_public_key(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;

#ifdef NC_ENABLED_SSH
    struct nc_hostkey *hostkey;
    struct nc_client_auth *auth_client;
    struct nc_public_key *pubkey;
#endif /* NC_ENABLED_SSH */

    assert(!strcmp(LYD_NAME(node), "public-key"));

    if (nc_server_config_get_endpt(node, &endpt, NULL)) {
        ret = 1;
        goto cleanup;
    }

#ifdef NC_ENABLED_SSH
    if ((equal_parent_name(node, 3, "host-key")) && (is_ssh(node)) && (is_listen(node))) {
        /* server's public-key, mandatory leaf */
        if (nc_server_config_get_hostkey(node, endpt->opts.ssh, &hostkey)) {
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
    } else if ((equal_parent_name(node, 5, "client-authentication")) && (is_ssh(node)) && (is_listen(node))) {
        /* client auth pubkeys, list */
        if (nc_server_config_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
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
            if (nc_server_config_get_pubkey(node, auth_client, &pubkey)) {
                ret = 1;
                goto cleanup;
            }

            nc_server_config_del_auth_client_pubkey(auth_client, pubkey);
        }
    } else if ((equal_parent_name(node, 6, "client-authentication")) && (is_ssh(node)) && (is_listen(node))) {
        /* client auth pubkey, leaf */
        if (nc_server_config_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_config_get_pubkey(node, auth_client, &pubkey)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_replace_auth_key_public_key_leaf(node, pubkey);
            if (ret) {
                goto cleanup;
            }
        } else {
            nc_server_config_del_auth_client_pubkey_pub_base64(pubkey);
        }
    }
#endif /* NC_ENABLED_SSH */
#ifdef NC_ENABLED_TLS
    if ((equal_parent_name(node, 3, "server-identity")) && (is_tls(node)) && (is_listen(node))) {
        /* tls listen server-identity */

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to local */
            endpt->opts.tls->store = NC_STORE_LOCAL;

            ret = nc_server_config_tls_replace_server_public_key(node, endpt->opts.tls);
            if (ret) {
                goto cleanup;
            }
        }
    }
#endif /* NC_ENABLED_TLS */

cleanup:
    return ret;
}

#ifdef NC_ENABLED_SSH

static int
nc_server_config_create_user(const struct lyd_node *node, struct nc_server_ssh_opts *opts)
{
    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&opts->auth_clients, sizeof *opts->auth_clients, &opts->client_count);
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
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (op == NC_OP_CREATE) {
            ret = nc_server_config_create_user(node, endpt->opts.ssh);
            if (ret) {
                goto cleanup;
            }
        } else if (op == NC_OP_DELETE) {
            if (nc_server_config_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
                ret = 1;
                goto cleanup;
            }

            nc_server_config_del_auth_client(endpt->opts.ssh, auth_client);
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
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
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
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
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
nc_server_config_replace_truststore_reference(const struct lyd_node *node, struct nc_client_auth *client_auth)
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
        ERR(NULL, "Public-key bag \"%s\" not found in truststore.", lyd_get_value(node));
        return 1;
    }

    client_auth->ts_ref = &ts->pub_bags[i];

    return 0;
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS
static int
nc_server_config_tls_replace_truststore_reference(const struct lyd_node *node, struct nc_cert_grouping *auth_client)
{
    uint16_t i;
    struct nc_truststore *ts = &server_opts.truststore;

    /* lookup name */
    for (i = 0; i < ts->cert_bag_count; i++) {
        if (!strcmp(lyd_get_value(node), ts->cert_bags[i].name)) {
            break;
        }
    }

    if (i == ts->cert_bag_count) {
        ERR(NULL, "Certificate bag \"%s\" not found in truststore.", lyd_get_value(node));
        return 1;
    }

    auth_client->ts_ref = &ts->cert_bags[i];

    return 0;
}

#endif /* NC_ENABLED_TLS */

/* leaf */
static int
nc_server_config_truststore_reference(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;

#ifdef NC_ENABLED_SSH
    struct nc_client_auth *auth_client;
#endif /* NC_ENABLED_SSH */

    assert(!strcmp(LYD_NAME(node), "truststore-reference"));

    if (nc_server_config_get_endpt(node, &endpt, NULL)) {
        ret = 1;
        goto cleanup;
    }

#ifdef NC_ENABLED_SSH
    if ((equal_parent_name(node, 1, "public-keys")) && (is_ssh(node)) && (is_listen(node))) {
        if (nc_server_config_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to truststore */
            auth_client->store = NC_STORE_TRUSTSTORE;

            ret = nc_server_config_replace_truststore_reference(node, auth_client);
            if (ret) {
                goto cleanup;
            }
        } else {
            auth_client->ts_ref = NULL;
        }
    }
#endif /* NC_ENABLED_SSH */
#ifdef NC_ENABLED_TLS
    if ((equal_parent_name(node, 1, "ca-certs")) && (is_listen(node))) {
        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to truststore */
            endpt->opts.tls->ca_certs.store = NC_STORE_TRUSTSTORE;

            ret = nc_server_config_tls_replace_truststore_reference(node, &endpt->opts.tls->ca_certs);
            if (ret) {
                goto cleanup;
            }
        } else {
            endpt->opts.tls->ca_certs.ts_ref = NULL;
        }
    } else if ((equal_parent_name(node, 1, "ee-certs")) && (is_listen(node))) {
        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to truststore */
            endpt->opts.tls->ee_certs.store = NC_STORE_TRUSTSTORE;

            ret = nc_server_config_tls_replace_truststore_reference(node, &endpt->opts.tls->ee_certs);
            if (ret) {
                goto cleanup;
            }
        } else {
            endpt->opts.tls->ee_certs.ts_ref = NULL;
        }
    }
#endif /* NC_ENABLED_TLS */

cleanup:
    return ret;
}

#ifdef NC_ENABLED_SSH

static int
nc_server_config_replace_password(const struct lyd_node *node, struct nc_client_auth *auth_client)
{
    nc_server_config_del_auth_client_password(auth_client);

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
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_config_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_replace_password(node, auth_client);
            if (ret) {
                goto cleanup;
            }
        } else {
            nc_server_config_del_auth_client_password(auth_client);
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
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_config_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            nc_server_config_del_auth_client_pam_name(auth_client);

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
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_config_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            nc_server_config_del_auth_client_pam_dir(auth_client);
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
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
            ret = 1;
            goto cleanup;
        }

        if (nc_server_config_get_auth_client(node, endpt->opts.ssh, &auth_client)) {
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
nc_server_config_transport_params(const char *algorithm, char **alg_store, NC_OPERATION op)
{
    int ret = 0, alg_found = 0;
    char *substr, *haystack, *alg = NULL;
    size_t alg_len;

    if (!strncmp(algorithm, "openssh-", 8)) {
        /* if the name starts with openssh, convert it to it's original libssh accepted form */
        asprintf(&alg, "%s@openssh.com", algorithm + 8);
        if (!alg) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }
    } else if (!strncmp(algorithm, "libssh-", 7)) {
        /* if the name starts with libssh, convert it to it's original libssh accepted form */
        asprintf(&alg, "%s@libssh.org", algorithm + 7);
        if (!alg) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }
    } else {
        alg = strdup(algorithm);
        if (!alg) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }
    }

    alg_len = strlen(alg);

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
    free(alg);
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
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
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
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
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
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
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
        if (nc_server_config_get_endpt(node, &endpt, NULL)) {
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

#endif /* NC_ENABLED_SSH */

static int
nc_server_config_create_unix_socket(struct nc_endpt *endpt)
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

    if (nc_server_config_get_endpt(node, &endpt, &bind)) {
        ret = 1;
        goto cleanup;
    }

    if (op == NC_OP_CREATE) {
        if (nc_server_config_create_unix_socket(endpt)) {
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
        nc_server_config_del_unix_socket(bind, endpt->opts.unixsock);
    }

cleanup:
    return ret;
}

#ifdef NC_ENABLED_SSH

/**
 * @brief Set all endpoint client auth references, which couldn't be set beforehand.
 *
 * The references that could not be set are those, which reference endpoints, which
 * lie below the given endpoint in the YANG data (because of DFS tree parsing).
 *
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_fill_endpt_client_auth(void)
{
    uint16_t i, j;

    for (i = 0; i < server_opts.endpt_count; i++) {
        /* go through all the endpoint */
        if (server_opts.endpts[i].referenced_endpt_name) {
            /* endpt has a reference, that hasn't been set yet */
            for (j = i + 1; j < server_opts.endpt_count; j++) {
                /* go through all the remaining endpts */
                if (!strcmp(server_opts.endpts[i].referenced_endpt_name, server_opts.endpts[j].name)) {
                    /* found the endpoint we were looking for */
                    if (server_opts.endpts[i].ti == NC_TI_LIBSSH) {
                        server_opts.endpts[i].opts.ssh->endpt_client_ref = &server_opts.endpts[j];
                        break;
                    } else {
                        ERRINT;
                        return 1;
                    }
                }
            }

            /* didn't find the endpoint */
            if (j == server_opts.endpt_count) {
                ERR(NULL, "Endpoint \"%s\" referenced by \"%s\" not found.",
                        server_opts.endpts[i].referenced_endpt_name, server_opts.endpts[i].name);
                return 1;
            }
        }
    }

    return 0;
}

static int
nc_server_config_endpoint_client_auth_has_cycle(struct nc_endpt *original, struct nc_endpt *next, NC_TRANSPORT_IMPL transport)
{
    if (transport == NC_TI_LIBSSH) {
        if (next->opts.ssh->endpt_client_ref) {
            if (next->opts.ssh->endpt_client_ref == original) {
                return 1;
            } else {
                return nc_server_config_endpoint_client_auth_has_cycle(original, next->opts.ssh->endpt_client_ref, NC_TI_LIBSSH);
            }
        } else {
            return 0;
        }
    } else {
        ERRINT;
        return 1;
    }
}

static int
nc_server_config_endpoint_client_auth(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    uint16_t i;
    const char *endpt_name;
    struct nc_endpt *endpt;

    assert(!strcmp(LYD_NAME(node), "endpoint-client-auth"));

    /* get current endpoint */
    ret = nc_server_config_get_endpt(node, &endpt, NULL);
    if (ret) {
        goto cleanup;
    }

    if (op == NC_OP_DELETE) {
        endpt->opts.ssh->endpt_client_ref = NULL;
        goto cleanup;
    }

    /* find the endpoint leafref is referring to */
    endpt_name = lyd_get_value(node);
    for (i = 0; i < server_opts.endpt_count; i++) {
        if (!strcmp(endpt_name, server_opts.endpts[i].name)) {
            break;
        }
    }

    if (i == server_opts.endpt_count) {
        /* endpt not found, save the name and try to look it up later */
        endpt->referenced_endpt_name = strdup(endpt_name);
        if (!endpt->referenced_endpt_name) {
            ERRMEM;
            ret = 1;
            goto cleanup;
        }
        goto cleanup;
    }

    /* check for self reference */
    if (endpt == &server_opts.endpts[i]) {
        ERR(NULL, "Self client authentication reference detected.");
        ret = 1;
        goto cleanup;
    }

    /* check for cyclic references */
    ret = nc_server_config_endpoint_client_auth_has_cycle(endpt, &server_opts.endpts[i], endpt->ti);
    if (ret) {
        ERR(NULL, "Cyclic client authentication reference detected.");
        goto cleanup;
    }

    /* assign the current endpt the referrenced endpt */
    endpt->opts.ssh->endpt_client_ref = &server_opts.endpts[i];

cleanup:
    return ret;
}

#endif /* NC_ENABLED_SSH */

#ifdef NC_ENABLED_TLS

static int
nc_server_config_tls_replace_cert_data(const struct lyd_node *node, struct nc_server_tls_opts *opts)
{
    nc_server_config_tls_del_cert_data(opts);
    opts->cert_data = strdup(lyd_get_value(node));
    if (!opts->cert_data) {
        ERRMEM;
        return 1;
    }

    return 0;
}

static int
nc_server_config_tls_replace_cert_data_client_auth(const struct lyd_node *node, struct nc_certificate *cert)
{
    nc_server_config_tls_del_cert_data_certificate(cert);
    cert->data = strdup(lyd_get_value(node));
    if (!cert->data) {
        ERRMEM;
        return 1;
    }

    return 0;
}

static int
nc_server_config_cert_data(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct nc_certificate *cert;

    assert(!strcmp(LYD_NAME(node), "cert-data"));

    if (nc_server_config_get_endpt(node, &endpt, NULL)) {
        ret = 1;
        goto cleanup;
    }

    if ((equal_parent_name(node, 3, "server-identity")) && (is_listen(node))) {
        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_tls_replace_cert_data(node, endpt->opts.tls);
            if (ret) {
                goto cleanup;
            }
        }
    } else if ((equal_parent_name(node, 3, "ca-certs")) && (is_listen(node))) {
        if (nc_server_config_get_cert(node, &endpt->opts.tls->ca_certs, &cert)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_tls_replace_cert_data_client_auth(node, cert);
            if (ret) {
                goto cleanup;
            }
        } else {
            nc_server_config_tls_del_cert_data_certificate(cert);
        }
    } else if ((equal_parent_name(node, 3, "ee-certs")) && (is_listen(node))) {
        if (nc_server_config_get_cert(node, &endpt->opts.tls->ee_certs, &cert)) {
            ret = 1;
            goto cleanup;
        }

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_tls_replace_cert_data_client_auth(node, cert);
            if (ret) {
                goto cleanup;
            }
        } else {
            nc_server_config_tls_del_cert_data_certificate(cert);
        }
    }

cleanup:
    return ret;
}

static int
nc_server_config_tls_create_asymmetric_key_ref(const struct lyd_node *node, struct nc_endpt *endpt)
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
        ERR(NULL, "Asymmetric key \"%s\" not found in the keystore.", lyd_get_value(node));
        return 1;
    }

    endpt->opts.tls->key_ref = &ks->asym_keys[i];

    return 0;
}

static int
nc_server_config_asymmetric_key(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;

    assert(!strcmp(LYD_NAME(node), "asymmetric-key"));

    if (nc_server_config_get_endpt(node, &endpt, NULL)) {
        ret = 1;
        goto cleanup;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* set to keystore */
        endpt->opts.tls->store = NC_STORE_KEYSTORE;

        ret = nc_server_config_tls_create_asymmetric_key_ref(node, endpt);
        if (ret) {
            goto cleanup;
        }
    } else {
        endpt->opts.tls->key_ref = NULL;
    }

cleanup:
    return ret;
}

static int
nc_server_config_tls_create_certificate_ref(const struct lyd_node *node, struct nc_endpt *endpt, struct nc_asymmetric_key *key)
{
    uint16_t i;

    /* lookup name */
    for (i = 0; i < key->cert_count; i++) {
        if (!strcmp(lyd_get_value(node), key->certs[i].name)) {
            break;
        }
    }

    if (i == key->cert_count) {
        ERR(NULL, "Certificate \"%s\" not found in the asymmetric key \"%s\".", lyd_get_value(node), key->name);
        return 1;
    }

    endpt->opts.tls->cert_ref = &key->certs[i];

    return 0;
}

static struct nc_asymmetric_key *
cert_get_asymmetric_key(const struct lyd_node *node)
{
    uint16_t i;
    struct nc_keystore *ks = &server_opts.keystore;

    /* starting with certificate node */
    assert(!strcmp(LYD_NAME(node), "certificate"));

    /* switch to it's only sibling, must be asymmetric-key */
    node = node->prev;
    assert(!strcmp(LYD_NAME(node), "asymmetric-key"));

    /* find the given asymmetric key */
    for (i = 0; i < ks->asym_key_count; i++) {
        if (!strcmp(lyd_get_value(node), ks->asym_keys[i].name)) {
            return &ks->asym_keys[i];
        }
    }

    /* didn't find it */
    ERR(NULL, "Asymmetric key \"%s\" not found in the keystore.", lyd_get_value(node));
    return NULL;
}

static int
nc_server_config_create_ca_certs_certificate(const struct lyd_node *node, struct nc_server_tls_opts *opts)
{
    assert(!strcmp(LYD_NAME(node), "certificate"));

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&opts->ca_certs.certs, sizeof *opts->ca_certs.certs, &opts->ca_certs.cert_count);
}

static int
nc_server_config_create_ee_certs_certificate(const struct lyd_node *node, struct nc_server_tls_opts *opts)
{
    assert(!strcmp(LYD_NAME(node), "certificate"));

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&opts->ee_certs.certs, sizeof *opts->ee_certs.certs, &opts->ee_certs.cert_count);
}

static int
nc_server_config_certificate(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct nc_asymmetric_key *key;

    assert(!strcmp(LYD_NAME(node), "certificate"));

    if (nc_server_config_get_endpt(node, &endpt, NULL)) {
        ret = 1;
        goto cleanup;
    }

    if ((equal_parent_name(node, 1, "keystore-reference")) && (is_listen(node))) {
        /* server-identity TLS listen */

        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            /* set to keystore */
            endpt->opts.tls->store = NC_STORE_KEYSTORE;

            if (!endpt->opts.tls->key_ref) {
                /* we don't have a key from which we need the cert yet */
                key = cert_get_asymmetric_key(node);
                if (!key) {
                    ret = 1;
                    goto cleanup;
                }
            } else {
                /* we have the key */
                key = endpt->opts.tls->key_ref;
            }

            /* find the given cert in the key and set it */
            ret = nc_server_config_tls_create_certificate_ref(node, endpt, key);
            if (ret) {
                goto cleanup;
            }
        } else {
            endpt->opts.tls->cert_ref = NULL;
        }
    } else if ((equal_parent_name(node, 2, "ca-certs")) && (is_listen(node))) {
        /* client auth TLS listen */
        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_create_ca_certs_certificate(node, endpt->opts.tls);
            if (ret) {
                goto cleanup;
            }
        } else {
            nc_server_config_tls_del_certs(&endpt->opts.tls->ca_certs);
        }
    } else if ((equal_parent_name(node, 2, "ee-certs")) && (is_listen(node))) {
        /* client auth TLS listen */
        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_create_ee_certs_certificate(node, endpt->opts.tls);
            if (ret) {
                goto cleanup;
            }
        } else {
            nc_server_config_tls_del_certs(&endpt->opts.tls->ee_certs);
        }
    }

cleanup:
    return ret;
}

static int
nc_server_config_create_cert_to_name(const struct lyd_node *node, struct nc_server_tls_opts *opts)
{
    int ret = 0;
    struct lyd_node *n;
    struct nc_ctn *new, *iter;
    const char *map_type, *name;
    uint32_t id;
    NC_TLS_CTN_MAPTYPE m_type;

    assert(!strcmp(LYD_NAME(node), "cert-to-name"));

    /* create new ctn */
    new = calloc(1, sizeof *new);
    if (!new) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }

    /* get all the data */
    /* find the list's key */
    lyd_find_path(node, "id", 0, &n);
    assert(n);
    id = strtoul(lyd_get_value(n), NULL, 10);

    /* find the ctn's name */
    lyd_find_path(node, "name", 0, &n);
    assert(n);
    name = lyd_get_value(n);

    /* find the ctn's map-type */
    lyd_find_path(node, "map-type", 0, &n);
    assert(n);
    map_type = ((struct lyd_node_term *)n)->value.ident->name;
    if (!strcmp(map_type, "specified")) {
        m_type = NC_TLS_CTN_SPECIFIED;
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
        ERR(NULL, "Map-type identity \"%s\" not supported.", map_type);
        ret = 1;
        goto cleanup;
    }

    /* find the right place for insertion */
    if (!opts->ctn) {
        /* inserting the first one */
        opts->ctn = new;
    } else if (opts->ctn->id > new->id) {
        /* insert at the beginning */
        new->next = opts->ctn;
        opts->ctn = new;
    } else {
        /* have to find the right place */
        for (iter = opts->ctn; iter->next && iter->next->id <= new->id; iter = iter->next) {}
        if (iter->id == new->id) {
            /* collision */
            new = iter;
        } else {
            new->next = iter->next;
            iter->next = new;
        }
    }

    /* insert the right data */
    new->id = id;
    if (new->name) {
        free(new->name);
    }
    new->name = strdup(name);
    if (!new->name) {
        ERRMEM;
        ret = 1;
        goto cleanup;
    }
    new->map_type = m_type;

cleanup:
    return ret;
}

static int
nc_server_config_cert_to_name(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct lyd_node *key;
    struct nc_ctn *ctn;

    assert(!strcmp(LYD_NAME(node), "cert-to-name"));

    if (nc_server_config_get_endpt(node, &endpt, NULL)) {
        ret = 1;
        goto cleanup;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ret = nc_server_config_create_cert_to_name(node, endpt->opts.tls);
        if (ret) {
            goto cleanup;
        }
    } else {
        /* find the given ctn entry */
        lyd_find_path(node, "id", 0, &key);
        assert(key);
        if (nc_server_config_get_ctn(node, endpt, &ctn)) {
            ret = 1;
            goto cleanup;
        }
        nc_server_config_del_ctn(endpt->opts.tls, ctn);
    }

cleanup:
    return ret;
}

static int
nc_server_config_replace_fingerprint(const struct lyd_node *node, struct nc_ctn *ctn)
{
    nc_server_config_del_fingerprint(ctn);

    ctn->fingerprint = strdup(lyd_get_value(node));
    if (!ctn->fingerprint) {
        ERRMEM;
        return 1;
    }

    return 0;
}

static int
nc_server_config_fingerprint(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_endpt *endpt;
    struct nc_ctn *ctn;

    if (nc_server_config_get_endpt(node, &endpt, NULL)) {
        ret = 1;
        goto cleanup;
    }

    if (nc_server_config_get_ctn(node, endpt, &ctn)) {
        ret = 1;
        goto cleanup;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ret = nc_server_config_replace_fingerprint(node, ctn);
        if (ret) {
            goto cleanup;
        }
    } else {
        nc_server_config_del_fingerprint(ctn);
    }

cleanup:
    return ret;
}

#endif /* NC_ENABLED_TLS */

static int
nc_server_config_parse_netconf_server(const struct lyd_node *node, NC_OPERATION op)
{
    const char *name = LYD_NAME(node);

    if (!strcmp(name, "listen")) {
        if (nc_server_config_listen(NULL, op)) {
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
    }
#ifdef NC_ENABLED_SSH
    else if (!strcmp(name, "ssh")) {
        if (nc_server_config_ssh(node, op)) {
            goto error;
        }
    }
#endif /* NC_ENABLED_SSH */
    else if (!strcmp(name, "local-address")) {
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
    }
#ifdef NC_ENABLED_SSH
    else if (!strcmp(name, "host-key")) {
        if (nc_server_config_host_key(node, op)) {
            goto error;
        }
    }
#endif /* NC_ENABLED_SSH */
    else if (!strcmp(name, "public-key-format")) {
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
    }
#ifdef NC_ENABLED_SSH
    else if (!strcmp(name, "keystore-reference")) {
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
    }
#endif /* NC_ENABLED_SSH */
    else if (!strcmp(name, "truststore-reference")) {
        if (nc_server_config_truststore_reference(node, op)) {
            goto error;
        }
    }
#ifdef NC_ENABLED_SSH
    else if (!strcmp(name, "password")) {
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
    }
#endif /* NC_ENABLED_SSH */
    else if (!strcmp(name, "unix-socket")) {
        if (nc_server_config_unix_socket(node, op)) {
            goto error;
        }
    }
#ifdef NC_ENABLED_SSH
    else if (!strcmp(name, "endpoint-client-auth")) {
        if (nc_server_config_endpoint_client_auth(node, op)) {
            goto error;
        }
    }
#endif /* NC_ENABLED_SSH */
#ifdef NC_ENABLED_TLS
    else if (!strcmp(name, "tls")) {
        if (nc_server_config_tls(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "cert-data")) {
        if (nc_server_config_cert_data(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "asymmetric-key")) {
        if (nc_server_config_asymmetric_key(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "certificate")) {
        if (nc_server_config_certificate(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "cert-to-name")) {
        if (nc_server_config_cert_to_name(node, op)) {
            goto error;
        }
    } else if (!strcmp(name, "fingerprint")) {
        if (nc_server_config_fingerprint(node, op)) {
            goto error;
        }
    }
#endif /* NC_ENABLED_TLS */

    return 0;

error:
    ERR(NULL, "Configuring (%s) failed.", LYD_NAME(node));
    return 1;
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
        if (module == NC_MODULE_NETCONF_SERVER) {
            ret = nc_server_config_parse_netconf_server(node, current_op);
        } else if (module == NC_MODULE_KEYSTORE) {
            ret = nc_server_config_parse_keystore(node, current_op);
        } else {
            ret = nc_server_config_parse_truststore(node, current_op);
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
    /* no symmetric-keys */
    const char *ietf_keystore[] = {"central-keystore-supported", "local-definitions-supported", "asymmetric-keys", NULL};
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

static int
nc_server_config_fill_nectonf_server(const struct lyd_node *data, NC_OPERATION op)
{
    int ret = 0;
    struct lyd_node *tree;

    ret = lyd_find_path(data, "/ietf-netconf-server:netconf-server", 0, &tree);
    if (ret) {
        ERR(NULL, "Unable to find the netconf-server container in the YANG data.");
        goto cleanup;
    }

    if (nc_server_config_parse_tree(tree, op, NC_MODULE_NETCONF_SERVER)) {
        ret = 1;
        goto cleanup;
    }

#ifdef NC_ENABLED_SSH
    if (nc_server_config_fill_endpt_client_auth()) {
        ret = 1;
        goto cleanup;
    }
#endif /* NC_ENABLED_SSH */

cleanup:
    return ret;
}

API int
nc_server_config_setup_diff(const struct lyd_node *data)
{
    int ret = 0;

    /* LOCK */
    pthread_rwlock_wrlock(&server_opts.config_lock);

    /* configure keystore */
    ret = nc_server_config_fill_keystore(data, NC_OP_UNKNOWN);
    if (ret) {
        ERR(NULL, "Filling keystore failed.");
        goto cleanup;
    }

    /* configure truststore */
    ret = nc_server_config_fill_truststore(data, NC_OP_UNKNOWN);
    if (ret) {
        ERR(NULL, "Filling truststore failed.");
        goto cleanup;
    }

    /* configure netconf-server */
    ret = nc_server_config_fill_nectonf_server(data, NC_OP_UNKNOWN);
    if (ret) {
        ERR(NULL, "Filling netconf-server failed.");
        goto cleanup;
    }

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
    nc_server_config_ks_keystore(NULL, NC_OP_DELETE);
    nc_server_config_ts_truststore(NULL, NC_OP_DELETE);

    /* configure keystore */
    ret = nc_server_config_fill_keystore(data, NC_OP_CREATE);
    if (ret) {
        ERR(NULL, "Filling keystore failed.");
        goto cleanup;
    }

    /* configure truststore */
    ret = nc_server_config_fill_truststore(data, NC_OP_CREATE);
    if (ret) {
        ERR(NULL, "Filling truststore failed.");
        goto cleanup;
    }

    /* configure netconf-server */
    ret = nc_server_config_fill_nectonf_server(data, NC_OP_CREATE);
    if (ret) {
        ERR(NULL, "Filling netconf-server failed.");
        goto cleanup;
    }

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
