/**
 * @file server_config_ks.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 keystore configuration functions
 *
 * @copyright
 * Copyright (c) 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "log_p.h"
#include "server_config_p.h"
#include "session_p.h"

extern struct nc_server_opts server_opts;

/**
 * @brief Get the pointer to an asymmetric key structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the asymmetric key containing this node is derived.
 * @param[out] askey Asymmetric key containing the node.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_get_asymmetric_key(const struct lyd_node *node, struct nc_asymmetric_key **askey)
{
    uint16_t i;
    const char *askey_name;
    struct nc_keystore *ks;
    const char *node_name = LYD_NAME(node);

    assert(node && askey);

    while (node) {
        if (!strcmp(LYD_NAME(node), "asymmetric-key")) {
            break;
        }
        node = lyd_parent(node);
    }

    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in an asymmetric-key subtree.", node_name);
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));
    askey_name = lyd_get_value(node);

    ks = &server_opts.keystore;
    for (i = 0; i < ks->asym_key_count; i++) {
        if (!strcmp(ks->asym_keys[i].name, askey_name)) {
            *askey = &ks->asym_keys[i];
            return 0;
        }
    }

    ERR(NULL, "Asymmetric key \"%s\" was not found.", askey_name);
    return 1;
}

/**
 * @brief Get the pointer to a certificate structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the certificate containing this node is derived.
 * @param[out] cert Certificate containing the node.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_get_certificate(const struct lyd_node *node, struct nc_certificate **cert)
{
    uint16_t i;
    const char *cert_name;
    struct nc_asymmetric_key *askey;
    const char *node_name = LYD_NAME(node);

    assert(node && cert);

    if (nc_server_config_get_asymmetric_key(node, &askey)) {
        return 1;
    }

    while (node) {
        if (!strcmp(LYD_NAME(node), "certificate")) {
            break;
        }
        node = lyd_parent(node);
    }

    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in a certificate subtree.", node_name);
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));
    cert_name = lyd_get_value(node);

    for (i = 0; i < askey->cert_count; i++) {
        if (!strcmp(askey->certs[i].name, cert_name)) {
            *cert = &askey->certs[i];
            return 0;
        }
    }

    ERR(NULL, "Certificate \"%s\" was not found.", cert_name);
    return 1;
}

static void
nc_server_config_ks_del_asymmetric_key_cert(struct nc_asymmetric_key *key, struct nc_certificate *cert)
{
    free(cert->name);
    free(cert->data);

    key->cert_count--;
    if (!key->cert_count) {
        free(key->certs);
        key->certs = NULL;
    } else if (cert != &key->certs[key->cert_count]) {
        memcpy(cert, &key->certs[key->cert_count], sizeof *key->certs);
    }
}

static void
nc_server_config_ks_del_asymmetric_key(struct nc_asymmetric_key *key)
{
    uint16_t i, cert_count;
    struct nc_keystore *ks = &server_opts.keystore;

    free(key->name);
    free(key->pubkey_data);
    free(key->privkey_data);

    cert_count = key->cert_count;
    for (i = 0; i < cert_count; i++) {
        nc_server_config_ks_del_asymmetric_key_cert(key, &key->certs[i]);
    }

    ks->asym_key_count--;
    if (!ks->asym_key_count) {
        free(ks->asym_keys);
        ks->asym_keys = NULL;
    } else if (key != &ks->asym_keys[ks->asym_key_count]) {
        memcpy(key, &ks->asym_keys[ks->asym_key_count], sizeof *ks->asym_keys);
    }
}

static int
nc_server_config_ks_asymmetric_keys(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_keystore *ks = &server_opts.keystore;
    uint16_t i, asym_key_count;

    (void) node;

    if (op == NC_OP_DELETE) {
        asym_key_count = ks->asym_key_count;
        for (i = 0; i < asym_key_count; i++) {
            nc_server_config_ks_del_asymmetric_key(&ks->asym_keys[i]);
        }
    }

    return 0;
}

int
nc_server_config_ks_keystore(const struct lyd_node *node, NC_OPERATION op)
{
    (void) node;

    if (op == NC_OP_DELETE) {
        nc_server_config_ks_asymmetric_keys(NULL, NC_OP_DELETE);
    }

    return 0;
}

static int
nc_server_config_ks_create_asymmetric_key(const struct lyd_node *node)
{
    struct nc_keystore *ks = &server_opts.keystore;

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&ks->asym_keys, sizeof *ks->asym_keys, &ks->asym_key_count);
}

static int
nc_server_config_ks_asymmetric_key(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_asymmetric_key *key;

    assert(!strcmp(LYD_NAME(node), "asymmetric-key"));

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ret = nc_server_config_ks_create_asymmetric_key(node);
    } else {
        if (nc_server_config_get_asymmetric_key(node, &key)) {
            ret = 1;
            goto cleanup;
        }

        nc_server_config_ks_del_asymmetric_key(key);
    }

cleanup:
    return ret;
}

static int
nc_server_config_ks_public_key_format(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_asymmetric_key *key;
    const char *format;

    (void) op;

    assert(!strcmp(LYD_NAME(node), "public-key-format"));

    if (nc_server_config_get_asymmetric_key(node, &key)) {
        return 1;
    }

    format = ((struct lyd_node_term *)node)->value.ident->name;
    if (!strcmp(format, "ssh-public-key-format")) {
        key->pubkey_type = NC_PUBKEY_FORMAT_SSH;
    } else if (!strcmp(format, "subject-public-key-info-format")) {
        key->pubkey_type = NC_PUBKEY_FORMAT_X509;
    } else {
        ERR(NULL, "Public key format (%s) not supported.", format);
    }

    return 0;
}

static int
nc_server_config_ks_public_key(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_asymmetric_key *key;

    (void) op;

    assert(!strcmp(LYD_NAME(node), "public-key"));

    if (nc_server_config_get_asymmetric_key(node, &key)) {
        return 1;
    }

    /* replace the pubkey */
    free(key->pubkey_data);
    key->pubkey_data = strdup(lyd_get_value(node));
    NC_CHECK_ERRMEM_RET(!key->pubkey_data, 1);

    return 0;
}

static int
nc_server_config_ks_private_key_format(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_asymmetric_key *key;
    const char *format;
    NC_PRIVKEY_FORMAT privkey_type;

    (void) op;

    assert(!strcmp(LYD_NAME(node), "private-key-format"));

    if (nc_server_config_get_asymmetric_key(node, &key)) {
        return 1;
    }

    format = ((struct lyd_node_term *)node)->value.ident->name;
    if (!format) {
        return 1;
    }

    privkey_type = nc_server_config_get_private_key_type(format);
    if (privkey_type == NC_PRIVKEY_FORMAT_UNKNOWN) {
        return 1;
    }
    key->privkey_type = privkey_type;

    return 0;
}

static int
nc_server_config_ks_cleartext_private_key(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_asymmetric_key *key;

    assert(!strcmp(LYD_NAME(node), "cleartext-private-key"));

    if (nc_server_config_get_asymmetric_key(node, &key)) {
        return 1;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* replace the privkey */
        free(key->privkey_data);
        key->privkey_data = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!key->privkey_data, 1);
    } else if (op == NC_OP_DELETE) {
        free(key->privkey_data);
        key->privkey_data = NULL;
    }

    return 0;
}

static int
nc_server_config_ks_create_certificate(const struct lyd_node *node, struct nc_asymmetric_key *key)
{
    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&key->certs, sizeof *key->certs, &key->cert_count);
}

static int
nc_server_config_ks_certificate(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_asymmetric_key *key;
    struct nc_certificate *cert;

    assert(!strcmp(LYD_NAME(node), "certificate"));

    if (nc_server_config_get_asymmetric_key(node, &key)) {
        ret = 1;
        goto cleanup;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ret = nc_server_config_ks_create_certificate(node, key);
    } else {
        if (nc_server_config_get_certificate(node, &cert)) {
            ret = 1;
            goto cleanup;
        }

        nc_server_config_ks_del_asymmetric_key_cert(key, cert);
    }

cleanup:
    return ret;
}

static int
nc_server_config_ks_cert_data(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_certificate *cert;

    assert(!strcmp(LYD_NAME(node), "cert-data"));

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        if (nc_server_config_get_certificate(node, &cert)) {
            return 1;
        }

        /* replace the cert data */
        free(cert->data);
        cert->data = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!cert->data, 1);
    }

    return 0;
}

int
nc_server_config_parse_keystore(const struct lyd_node *node, NC_OPERATION op)
{
    const char *name = LYD_NAME(node);
    int ret = 0;

    if (!strcmp(name, "keystore")) {
        ret = nc_server_config_ks_keystore(node, op);
    } else if (!strcmp(name, "asymmetric-keys")) {
        ret = nc_server_config_ks_asymmetric_keys(node, op);
    } else if (!strcmp(name, "asymmetric-key")) {
        ret = nc_server_config_ks_asymmetric_key(node, op);
    } else if (!strcmp(name, "public-key-format")) {
        ret = nc_server_config_ks_public_key_format(node, op);
    } else if (!strcmp(name, "public-key")) {
        ret = nc_server_config_ks_public_key(node, op);
    } else if (!strcmp(name, "private-key-format")) {
        ret = nc_server_config_ks_private_key_format(node, op);
    } else if (!strcmp(name, "cleartext-private-key")) {
        ret = nc_server_config_ks_cleartext_private_key(node, op);
    } else if (!strcmp(name, "certificate")) {
        ret = nc_server_config_ks_certificate(node, op);
    } else if (!strcmp(name, "cert-data")) {
        ret = nc_server_config_ks_cert_data(node, op);
    }

    if (ret) {
        ERR(NULL, "Configuring (%s) failed.", name);
        return 1;
    }

    return 0;
}

int
nc_server_config_fill_keystore(const struct lyd_node *data, NC_OPERATION op)
{
    int ret = 0;
    uint32_t prev_lo;
    struct lyd_node *tree;

    /* silently search for nodes, some of them may not be present */
    prev_lo = ly_log_options(0);

    ret = lyd_find_path(data, "/ietf-keystore:keystore", 0, &tree);
    if (ret || (tree->flags & LYD_DEFAULT)) {
        /* not found */
        ret = 0;
        goto cleanup;
    }

    if (nc_server_config_parse_tree(tree, op, NC_MODULE_KEYSTORE)) {
        ret = 1;
        goto cleanup;
    }

cleanup:
    /* reset the logging options back to what they were */
    ly_log_options(prev_lo);
    return ret;
}
