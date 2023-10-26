/**
 * @file server_config_ts.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 truststore configuration functions
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
 * @brief Get the pointer to a certificate bag structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the certificate bag containing this node is derived.
 * @param[out] cbag Certificate bag containing the node.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_get_certificate_bag(const struct lyd_node *node, struct nc_certificate_bag **cbag)
{
    uint16_t i;
    const char *cbag_name;
    struct nc_truststore *ts;
    const char *node_name = LYD_NAME(node);

    assert(node && cbag);

    while (node) {
        if (!strcmp(LYD_NAME(node), "certificate-bag")) {
            break;
        }
        node = lyd_parent(node);
    }

    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in a certificate-bag subtree.", node_name);
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));
    cbag_name = lyd_get_value(node);

    ts = &server_opts.truststore;
    for (i = 0; i < ts->cert_bag_count; i++) {
        if (!strcmp(ts->cert_bags[i].name, cbag_name)) {
            *cbag = &ts->cert_bags[i];
            return 0;
        }
    }

    ERR(NULL, "Certificate bag \"%s\" was not found.", cbag_name);
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
    struct nc_certificate_bag *cbag;
    const char *node_name = LYD_NAME(node);

    assert(node && cert);

    if (nc_server_config_get_certificate_bag(node, &cbag)) {
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

    for (i = 0; i < cbag->cert_count; i++) {
        if (!strcmp(cbag->certs[i].name, cert_name)) {
            *cert = &cbag->certs[i];
            return 0;
        }
    }

    ERR(NULL, "Certificate \"%s\" was not found.", cert_name);
    return 1;
}

/**
 * @brief Get the pointer to a public key bag structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the public key bag containing this node is derived.
 * @param[out] pbag Public key bag containing the node.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_get_public_key_bag(const struct lyd_node *node, struct nc_public_key_bag **pbag)
{
    uint16_t i;
    const char *pbag_name;
    struct nc_truststore *ts;
    const char *node_name = LYD_NAME(node);

    assert(node && pbag);

    while (node) {
        if (!strcmp(LYD_NAME(node), "public-key-bag")) {
            break;
        }
        node = lyd_parent(node);
    }

    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in a public-key-bag subtree.", node_name);
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));
    pbag_name = lyd_get_value(node);

    ts = &server_opts.truststore;
    for (i = 0; i < ts->pub_bag_count; i++) {
        if (!strcmp(ts->pub_bags[i].name, pbag_name)) {
            *pbag = &ts->pub_bags[i];
            return 0;
        }
    }

    ERR(NULL, "Public key bag \"%s\" was not found.", pbag_name);
    return 1;
}

/**
 * @brief Get the pointer to a public key structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the public key containing this node is derived.
 * @param[out] pkey Public key containing the node.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_get_public_key(const struct lyd_node *node, struct nc_public_key **pkey)
{
    uint16_t i;
    const char *pkey_name;
    struct nc_public_key_bag *pbag;
    const char *node_name = LYD_NAME(node);

    assert(node && pkey);

    if (nc_server_config_get_public_key_bag(node, &pbag)) {
        return 1;
    }

    while (node) {
        if (!strcmp(LYD_NAME(node), "public-key")) {
            if (lyd_child(node)) {
                /* check if it's not the leaf public-key, only case about the list */
                break;
            }
        }

        node = lyd_parent(node);
    }

    if (!node) {
        ERR(NULL, "Node \"%s\" is not contained in a public-key subtree.", node_name);
        return 1;
    }

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));
    pkey_name = lyd_get_value(node);

    for (i = 0; i < pbag->pubkey_count; i++) {
        if (!strcmp(pbag->pubkeys[i].name, pkey_name)) {
            *pkey = &pbag->pubkeys[i];
            return 0;
        }
    }

    ERR(NULL, "Public key \"%s\" was not found.", pkey_name);
    return 1;
}

static void
nc_server_config_ts_del_certificate(struct nc_certificate_bag *cbag, struct nc_certificate *cert)
{
    free(cert->name);
    free(cert->data);

    cbag->cert_count--;
    if (!cbag->cert_count) {
        free(cbag->certs);
        cbag->certs = NULL;
    } else if (cert != &cbag->certs[cbag->cert_count]) {
        memcpy(cert, &cbag->certs[cbag->cert_count], sizeof *cbag->certs);
    }
}

static void
nc_server_config_ts_del_public_key(struct nc_public_key_bag *pbag, struct nc_public_key *pkey)
{
    free(pkey->name);
    free(pkey->data);

    pbag->pubkey_count--;
    if (!pbag->pubkey_count) {
        free(pbag->pubkeys);
        pbag->pubkeys = NULL;
    } else if (pkey != &pbag->pubkeys[pbag->pubkey_count]) {
        memcpy(pkey, &pbag->pubkeys[pbag->pubkey_count], sizeof *pbag->pubkeys);
    }
}

static void
nc_server_config_ts_del_certificate_bag(struct nc_certificate_bag *cbag)
{
    uint16_t i, cert_count;
    struct nc_truststore *ts = &server_opts.truststore;

    free(cbag->name);

    cert_count = cbag->cert_count;
    for (i = 0; i < cert_count; i++) {
        nc_server_config_ts_del_certificate(cbag, &cbag->certs[i]);
    }

    ts->cert_bag_count--;
    if (!ts->cert_bag_count) {
        free(ts->cert_bags);
        ts->cert_bags = NULL;
    } else if (cbag != &ts->cert_bags[ts->cert_bag_count]) {
        memcpy(cbag, &ts->cert_bags[ts->cert_bag_count], sizeof *ts->cert_bags);
    }
}

static void
nc_server_config_ts_del_public_key_bag(struct nc_public_key_bag *pbag)
{
    uint16_t i, pubkey_count;
    struct nc_truststore *ts = &server_opts.truststore;

    free(pbag->name);

    pubkey_count = pbag->pubkey_count;
    for (i = 0; i < pubkey_count; i++) {
        nc_server_config_ts_del_public_key(pbag, &pbag->pubkeys[i]);
    }

    ts->pub_bag_count--;
    if (!ts->pub_bag_count) {
        free(ts->pub_bags);
        ts->pub_bags = NULL;
    } else if (pbag != &ts->pub_bags[ts->pub_bag_count]) {
        memcpy(pbag, &ts->pub_bags[ts->pub_bag_count], sizeof *ts->pub_bags);
    }
}

static int
nc_server_config_ts_certificate_bags(const struct lyd_node *node, NC_OPERATION op)
{
    uint16_t i, cert_bag_count;
    struct nc_truststore *ts = &server_opts.truststore;

    (void) node;

    if (op == NC_OP_DELETE) {
        cert_bag_count = ts->cert_bag_count;
        for (i = 0; i < cert_bag_count; i++) {
            nc_server_config_ts_del_certificate_bag(&ts->cert_bags[i]);
        }
    }

    return 0;
}

static int
nc_server_config_ts_public_key_bags(const struct lyd_node *node, NC_OPERATION op)
{
    uint16_t i, pub_bag_count;
    struct nc_truststore *ts = &server_opts.truststore;

    (void) node;

    if (op == NC_OP_DELETE) {
        pub_bag_count = ts->pub_bag_count;
        for (i = 0; i < pub_bag_count; i++) {
            nc_server_config_ts_del_public_key_bag(&ts->pub_bags[i]);
        }
    }

    return 0;
}

int
nc_server_config_ts_truststore(const struct lyd_node *node, NC_OPERATION op)
{
    (void) node;

    if (op == NC_OP_DELETE) {
        nc_server_config_ts_certificate_bags(NULL, NC_OP_DELETE);
        nc_server_config_ts_public_key_bags(NULL, NC_OP_DELETE);
    }

    return 0;
}

static int
nc_server_config_ts_create_certificate_bag(const struct lyd_node *node)
{
    struct nc_truststore *ts = &server_opts.truststore;

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&ts->cert_bags, sizeof *ts->cert_bags, &ts->cert_bag_count);
}

static int
nc_server_config_ts_certificate_bag(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_certificate_bag *bag;

    assert(!strcmp(LYD_NAME(node), "certificate-bag"));

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        if (nc_server_config_ts_create_certificate_bag(node)) {
            return 1;
        }
    } else {
        if (nc_server_config_get_certificate_bag(node, &bag)) {
            return 1;
        }

        nc_server_config_ts_del_certificate_bag(bag);
    }

    return 0;
}

static int
nc_server_config_ts_create_certificate(const struct lyd_node *node, struct nc_certificate_bag *bag)
{
    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&bag->certs, sizeof *bag->certs, &bag->cert_count);
}

static int
nc_server_config_ts_certificate(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_certificate_bag *bag;
    struct nc_certificate *cert;

    assert(!strcmp(LYD_NAME(node), "certificate"));

    if (nc_server_config_get_certificate_bag(node, &bag)) {
        return 1;
    }

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        if (nc_server_config_ts_create_certificate(node, bag)) {
            return 1;
        }
    } else {
        if (nc_server_config_get_certificate(node, &cert)) {
            return 1;
        }

        nc_server_config_ts_del_certificate(bag, cert);
    }

    return 0;
}

static int
nc_server_config_ts_cert_data(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_certificate *cert;

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        if (nc_server_config_get_certificate(node, &cert)) {
            return 1;
        }

        free(cert->data);
        cert->data = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!cert->data, 1);
    }

    return 0;
}

static int
nc_server_config_ts_create_public_key_bag(const struct lyd_node *node)
{
    struct nc_truststore *ts = &server_opts.truststore;

    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&ts->pub_bags, sizeof *ts->pub_bags, &ts->pub_bag_count);
}

static int
nc_server_config_ts_public_key_bag(const struct lyd_node *node, NC_OPERATION op)
{
    struct nc_public_key_bag *pbag;

    assert(!strcmp(LYD_NAME(node), "public-key-bag"));

    if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        if (nc_server_config_ts_create_public_key_bag(node)) {
            return 1;
        }
    } else {
        if (nc_server_config_get_public_key_bag(node, &pbag)) {
            return 1;
        }

        nc_server_config_ts_del_public_key_bag(pbag);
    }

    return 0;
}

static int
nc_server_config_ts_create_public_key(const struct lyd_node *node, struct nc_public_key_bag *bag)
{
    node = lyd_child(node);
    assert(!strcmp(LYD_NAME(node), "name"));

    return nc_server_config_realloc(lyd_get_value(node), (void **)&bag->pubkeys, sizeof *bag->pubkeys, &bag->pubkey_count);
}

static int
nc_server_config_ts_public_key(const struct lyd_node *node, NC_OPERATION op)
{
    int ret = 0;
    struct nc_public_key_bag *bag;
    struct nc_public_key *pkey;

    if (nc_server_config_get_public_key_bag(node, &bag)) {
        ret = 1;
        goto cleanup;
    }

    if (equal_parent_name(node, 1, "public-key-bag")) {
        /* public-key list */
        if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
            ret = nc_server_config_ts_create_public_key(node, bag);
            if (ret) {
                goto cleanup;
            }
        } else {
            if (nc_server_config_get_public_key(node, &pkey)) {
                ret = 1;
                goto cleanup;
            }

            nc_server_config_ts_del_public_key(bag, pkey);
        }
    } else {
        /* public-key leaf */
        if (nc_server_config_get_public_key(node, &pkey)) {
            ret = 1;
            goto cleanup;
        }

        /* replace the public key */
        free(pkey->data);
        pkey->data = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_GOTO(!pkey->data, ret = 1, cleanup);
    }

cleanup:
    return ret;
}

static int
nc_server_config_ts_public_key_format(const struct lyd_node *node, NC_OPERATION op)
{
    const char *format;
    struct nc_public_key *pkey;

    (void) op;

    if (nc_server_config_get_public_key(node, &pkey)) {
        return 1;
    }

    format = ((struct lyd_node_term *)node)->value.ident->name;
    if (!strcmp(format, "ssh-public-key-format")) {
        pkey->type = NC_PUBKEY_FORMAT_SSH;
    } else if (!strcmp(format, "subject-public-key-info-format")) {
        pkey->type = NC_PUBKEY_FORMAT_X509;
    } else {
        ERR(NULL, "Public key format (%s) not supported.", format);
    }

    return 0;
}

int
nc_server_config_parse_truststore(const struct lyd_node *node, NC_OPERATION op)
{
    const char *name = LYD_NAME(node);
    int ret = 0;

    if (!strcmp(name, "truststore")) {
        ret = nc_server_config_ts_truststore(node, op);
    } else if (!strcmp(name, "certificate-bags")) {
        ret = nc_server_config_ts_certificate_bags(node, op);
    } else if (!strcmp(name, "certificate-bag")) {
        ret = nc_server_config_ts_certificate_bag(node, op);
    } else if (!strcmp(name, "certificate")) {
        ret = nc_server_config_ts_certificate(node, op);
    } else if (!strcmp(name, "cert-data")) {
        ret = nc_server_config_ts_cert_data(node, op);
    } else if (!strcmp(name, "public-key-bags")) {
        ret = nc_server_config_ts_public_key_bags(node, op);
    } else if (!strcmp(name, "public-key-bag")) {
        ret = nc_server_config_ts_public_key_bag(node, op);
    } else if (!strcmp(name, "public-key")) {
        ret = nc_server_config_ts_public_key(node, op);
    } else if (!strcmp(name, "public-key-format")) {
        ret = nc_server_config_ts_public_key_format(node, op);
    }

    if (ret) {
        ERR(NULL, "Configuring (%s) failed.", name);
        return 1;
    }

    return 0;
}

int
nc_server_config_fill_truststore(const struct lyd_node *data, NC_OPERATION op)
{
    int ret = 0;
    uint32_t prev_lo;
    struct lyd_node *tree;

    /* silently search for nodes, some of them may not be present */
    prev_lo = ly_log_options(0);

    ret = lyd_find_path(data, "/ietf-truststore:truststore", 0, &tree);
    if (ret || (tree->flags & LYD_DEFAULT)) {
        /* not found */
        ret = 0;
        goto cleanup;
    }

    if (nc_server_config_parse_tree(tree, op, NC_MODULE_TRUSTSTORE)) {
        ret = 1;
        goto cleanup;
    }

cleanup:
    /* reset the logging options back to what they were */
    ly_log_options(prev_lo);
    return ret;
}
