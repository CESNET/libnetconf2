/**
 * @file server_config.c
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server configuration through YANG data implementation
 *
 * @copyright
 * Copyright (c) 2022-2025 CESNET, z.s.p.o.
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
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <libyang/tree_data.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "server_config.h"
#include "session_p.h"

/**
 * @brief Macro to get the diff operation of a node, defaulting to the parent's operation if not present.
 *
 * @note Returns 1 on error.
 *
 * @param[in] node Node to get the operation from.
 * @param[in] parent_op Parent node's operation.
 * @param[out] op Diff operation of the node.
 */
#define NC_NODE_GET_OP(node, parent_op, op) \
    { \
        struct lyd_meta *_meta = lyd_find_meta(node->meta, NULL, "yang:operation"); \
        if (_meta) { \
            const char *_meta_val = lyd_get_meta_value(_meta); \
            if (!strcmp(_meta_val, "create")) { \
                *(op) = NC_OP_CREATE; \
            } else if (!strcmp(_meta_val, "delete")) { \
                *(op) = NC_OP_DELETE; \
            } else if (!strcmp(_meta_val, "replace")) { \
                *(op) = NC_OP_REPLACE; \
            } else if (!strcmp(_meta_val, "none")) { \
                *(op) = NC_OP_NONE; \
            } else { \
                ERR(NULL, "Unknown operation \"%s\" of node \"%s\".", _meta_val, LYD_NAME(node)); \
                return 1; \
            } \
        } else { \
            *(op) = parent_op; \
        } \
    }

/**
 * @brief Macro to log unsupported configuration nodes.
 *
 * @param[in] node Node that is unsupported.
 */
#define CONFIG_LOG_UNSUPPORTED(node) \
    WRN(NULL, "Unsupported node \"%s\" in the configuration, ignoring.", LYD_NAME(node))

/**
 * @brief Wrapper macro for LY_ARRAY_CREATE_GOTO to disallow zero-size arrays.
 */
#define LN2_LY_ARRAY_CREATE_GOTO_WRAP(ARRAY, SIZE, RET, GOTO) \
    if (!(SIZE)) { \
        (ARRAY) = NULL; \
    } else { \
        LY_ARRAY_CREATE_GOTO(NULL, ARRAY, SIZE, RET, GOTO); \
    }

/**
 * @brief Find a child node of a given node and optionally don't fail if not found.
 *
 * @note Implicit nodes, such as NP containers/leafs with default values, are always expected to be present.
 *
 * @param[in] node Context (parent) node.
 * @param[in] child Name of the child node to find.
 * @param[in] fail_if_not_found Whether to fail if the node is not present.
 * @param[out] match Found node.
 * @return 0 on success, 1 if mandatory and not found.
 */
static int
nc_lyd_find_child(const struct lyd_node *node, const char *child, int fail_if_not_found, struct lyd_node **match)
{
    *match = NULL;

    lyd_find_path(node, child, 0, match);
    if (fail_if_not_found && !*match) {
        ERR(NULL, "Implicit child node \"%s\" of node \"%s\" missing.", child, LYD_NAME(node));
        return 1;
    }

    return 0;
}

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Free SSH server options.
 *
 * @param[in] opts SSH server options to free.
 */
static void
nc_server_config_ssh_opts_free(struct nc_server_ssh_opts *opts)
{
    struct nc_hostkey *hostkey;
    struct nc_auth_client *auth_client;
    struct nc_public_key *pubkey;
    LY_ARRAY_COUNT_TYPE i, j;

    if (!opts) {
        return;
    }

    /* free hostkeys */
    LY_ARRAY_FOR(opts->hostkeys, i) {
        hostkey = &opts->hostkeys[i];
        free(hostkey->name);
        if (hostkey->store == NC_STORE_LOCAL) {
            free(hostkey->key.name);
            free(hostkey->key.pubkey.data);
            free(hostkey->key.privkey.data);
        } else if (hostkey->store == NC_STORE_KEYSTORE) {
            free(hostkey->ks_ref);
        }
    }
    LY_ARRAY_FREE(opts->hostkeys);

    /* free authorized clients */
    LY_ARRAY_FOR(opts->auth_clients, i) {
        auth_client = &opts->auth_clients[i];
        free(auth_client->username);
        if (auth_client->pubkey_store == NC_STORE_LOCAL) {
            LY_ARRAY_FOR(auth_client->pubkeys, j) {
                pubkey = &auth_client->pubkeys[j];
                free(pubkey->name);
                free(pubkey->data);
            }
            LY_ARRAY_FREE(auth_client->pubkeys);
        } else if (auth_client->pubkey_store == NC_STORE_TRUSTSTORE) {
            free(auth_client->ts_ref);
        }
        free(auth_client->password);
    }
    LY_ARRAY_FREE(opts->auth_clients);

    free(opts->referenced_endpt_name);
    free(opts->hostkey_algs);
    free(opts->encryption_algs);
    free(opts->kex_algs);
    free(opts->mac_algs);
    free(opts->banner);
    free(opts);
}

/**
 * @brief Free TLS server options.
 *
 * @param[in] opts TLS server options to free.
 */
static void
nc_server_config_tls_opts_free(struct nc_server_tls_opts *opts)
{
    struct nc_ctn *ctn, *next;
    LY_ARRAY_COUNT_TYPE i;

    if (!opts) {
        return;
    }

    /* free server identity */
    if (opts->cert_store == NC_STORE_LOCAL) {
        free(opts->local.key.name);
        free(opts->local.key.pubkey.data);
        free(opts->local.key.privkey.data);
        free(opts->local.cert.name);
        free(opts->local.cert.data);
    } else if (opts->cert_store == NC_STORE_KEYSTORE) {
        free(opts->keystore.asym_key_ref);
        free(opts->keystore.cert_ref);
    }

    /* free ca certificates */
    if (opts->client_auth.ca_certs_store == NC_STORE_LOCAL) {
        LY_ARRAY_FOR(opts->client_auth.ca_certs, i) {
            free(opts->client_auth.ca_certs[i].name);
            free(opts->client_auth.ca_certs[i].data);
        }
        LY_ARRAY_FREE(opts->client_auth.ca_certs);
    } else if (opts->client_auth.ca_certs_store == NC_STORE_TRUSTSTORE) {
        free(opts->client_auth.ca_cert_bag_ts_ref);
    }

    /* free end-entity certificates */
    if (opts->client_auth.ee_certs_store == NC_STORE_LOCAL) {
        LY_ARRAY_FOR(opts->client_auth.ee_certs, i) {
            free(opts->client_auth.ee_certs[i].name);
            free(opts->client_auth.ee_certs[i].data);
        }
        LY_ARRAY_FREE(opts->client_auth.ee_certs);
    } else if (opts->client_auth.ee_certs_store == NC_STORE_TRUSTSTORE) {
        free(opts->client_auth.ee_cert_bag_ts_ref);
    }

    /* free cert-to-name entries */
    for (ctn = opts->ctn; ctn; ctn = next) {
        next = ctn->next;
        free(ctn->fingerprint);
        free(ctn->name);
        free(ctn);
    }

    free(opts->referenced_endpt_name);
    free(opts->cipher_suites);
    free(opts);
}

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Free UNIX server options.
 *
 * @param[in] opts UNIX server options to free.
 */
static void
nc_server_config_unix_opts_free(struct nc_server_unix_opts *opts)
{
    struct nc_server_unix_user_mapping *mapping;
    LY_ARRAY_COUNT_TYPE i, j;

    if (!opts) {
        return;
    }

    /* free user mappings */
    LY_ARRAY_FOR(opts->user_mappings, i) {
        mapping = &opts->user_mappings[i];
        free(mapping->system_user);

        LY_ARRAY_FOR(mapping->allowed_users, j) {
            free(mapping->allowed_users[j]);
        }
        LY_ARRAY_FREE(mapping->allowed_users);
    }
    LY_ARRAY_FREE(opts->user_mappings);

    free(opts);
}

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Free keystore configuration data.
 *
 * @param[in] ks Keystore to free (it's not dynamically allocated).
 */
static void
nc_server_config_keystore_free(struct nc_keystore *ks)
{
    struct nc_keystore_entry *entry;
    LY_ARRAY_COUNT_TYPE i, j;

    if (!ks) {
        return;
    }

    LY_ARRAY_FOR(ks->entries, i) {
        entry = &ks->entries[i];
        free(entry->asym_key.name);
        free(entry->asym_key.pubkey.data);
        free(entry->asym_key.privkey.data);

        /* free certificates */
        LY_ARRAY_FOR(entry->certs, j) {
            free(entry->certs[j].name);
            free(entry->certs[j].data);
        }
        LY_ARRAY_FREE(entry->certs);
    }
    LY_ARRAY_FREE(ks->entries);

    memset(ks, 0, sizeof(*ks));
}

/**
 * @brief Free truststore configuration data.
 *
 * @param[in] ts Truststore to free (it's not dynamically allocated).
 */
static void
nc_server_config_truststore_free(struct nc_truststore *ts)
{
    struct nc_certificate_bag *cbag;
    struct nc_public_key_bag *pkbag;
    LY_ARRAY_COUNT_TYPE i, j;

    if (!ts) {
        return;
    }

    /* free certificate bags */
    LY_ARRAY_FOR(ts->cert_bags, i) {
        cbag = &ts->cert_bags[i];

        free(cbag->name);
        free(cbag->description);
        LY_ARRAY_FOR(cbag->certs, j) {
            free(cbag->certs[j].name);
            free(cbag->certs[j].data);
        }
        LY_ARRAY_FREE(cbag->certs);
    }
    LY_ARRAY_FREE(ts->cert_bags);

    /* free public key bags */
    LY_ARRAY_FOR(ts->pubkey_bags, i) {
        pkbag = &ts->pubkey_bags[i];

        free(pkbag->name);
        free(pkbag->description);
        LY_ARRAY_FOR(pkbag->pubkeys, j) {
            free(pkbag->pubkeys[j].name);
            free(pkbag->pubkeys[j].data);
        }
        LY_ARRAY_FREE(pkbag->pubkeys);
    }
    LY_ARRAY_FREE(ts->pubkey_bags);

    memset(ts, 0, sizeof(*ts));
}

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Free server configuration data.
 *
 * @param[in] config Server configuration to free.
 */
void
nc_server_config_free(struct nc_server_config *config)
{
    struct nc_endpt *endpt;
    struct nc_ch_client *ch_client;
    struct nc_ch_endpt *ch_endpt;
    LY_ARRAY_COUNT_TYPE i, j;

    if (!config) {
        return;
    }

    /* free ignored hello modules */
    LY_ARRAY_FOR(config->ignored_modules, i) {
        free(config->ignored_modules[i]);
    }
    LY_ARRAY_FREE(config->ignored_modules);

    /* free listen endpoints */
    LY_ARRAY_FOR(config->endpts, i) {
        endpt = &config->endpts[i];

        free(endpt->name);

        /* free binds */
        LY_ARRAY_FOR(endpt->binds, j) {
            free(endpt->binds[j].address);
            if (endpt->binds[j].sock != -1) {
                close(endpt->binds[j].sock);
            }
            pthread_mutex_destroy(&endpt->bind_lock);
        }
        LY_ARRAY_FREE(endpt->binds);

        /* free transport specific options */
        switch (endpt->ti) {
#ifdef NC_ENABLED_SSH_TLS
        case NC_TI_SSH:
            nc_server_config_ssh_opts_free(endpt->opts.ssh);
            break;
        case NC_TI_TLS:
            nc_server_config_tls_opts_free(endpt->opts.tls);
            break;
#endif /* NC_ENABLED_SSH_TLS */
        case NC_TI_UNIX:
            nc_server_config_unix_opts_free(endpt->opts.unix);
            break;
        default:
            ERRINT;
            break;
        }
    }
    LY_ARRAY_FREE(config->endpts);

    /* free call home clients */
    LY_ARRAY_FOR(config->ch_clients, i) {
        ch_client = &config->ch_clients[i];

        free(ch_client->name);

        /* free call home endpoints */
        LY_ARRAY_FOR(ch_client->ch_endpts, j) {
            ch_endpt = &ch_client->ch_endpts[j];

            free(ch_endpt->name);
            free(ch_endpt->src_addr);
            free(ch_endpt->dst_addr);

            /* free transport specific options */
            switch (ch_endpt->ti) {
#ifdef NC_ENABLED_SSH_TLS
            case NC_TI_SSH:
                nc_server_config_ssh_opts_free(ch_endpt->opts.ssh);
                break;
            case NC_TI_TLS:
                nc_server_config_tls_opts_free(ch_endpt->opts.tls);
                break;
#endif /* NC_ENABLED_SSH_TLS */
            default:
                ERRINT;
                break;
            }
        }
        LY_ARRAY_FREE(ch_client->ch_endpts);
    }
    LY_ARRAY_FREE(config->ch_clients);

#ifdef NC_ENABLED_SSH_TLS
    /* free keystore and truststore */
    nc_server_config_keystore_free(&config->keystore);
    nc_server_config_truststore_free(&config->truststore);

    /* free certificate expiration intervals */
    LY_ARRAY_FREE(config->cert_exp_notif_intervals);
#endif /* NC_ENABLED_SSH_TLS */

    memset(config, 0, sizeof(*config));
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
    /* no ssh-x509-certs, asymmetric-key-pair-generation */
    const char *ietf_ssh_common[] = {"algorithm-discovery", "transport-params", NULL};
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
    const char *ietf_tls_common[] = {"algorithm-discovery", "tls12", "tls13", "hello-params", NULL};
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

    for (i = 0; module_names[i]; i++) {
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

/*
 * =====================================================================================
 * ietf-netconf-server handlers
 * =====================================================================================
 */

#ifdef NC_ENABLED_SSH_TLS

static int
config_local_address(const struct lyd_node *node, enum nc_operation parent_op, struct nc_bind *bind)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(bind->address);
        bind->address = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(bind->address);
        bind->address = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!bind->address, 1);
    }

    return 0;
}

static int
config_local_port(const struct lyd_node *node, enum nc_operation UNUSED(parent_op), struct nc_bind *bind)
{
    /* default value always present */
    bind->port = strtoul(lyd_get_value(node), NULL, 10);
    return 0;
}

static int
config_local_bind(const struct lyd_node *node, enum nc_operation parent_op, struct nc_endpt *endpt)
{
    struct lyd_node *n;
    enum nc_operation op;
    struct nc_bind *bind = NULL;
    const char *local_addr;
    LY_ARRAY_COUNT_TYPE i;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* local address (local-bind list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "local-address", 1, &n));
    local_addr = lyd_get_value(n);
    assert(local_addr);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the bind we are deleting/modifying */
        LY_ARRAY_FOR(endpt->binds, i) {
            if (!strcmp(endpt->binds[i].address, local_addr)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(endpt->binds));
        bind = &endpt->binds[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new bind */
        LY_ARRAY_NEW_RET(LYD_CTX(node), endpt->binds, bind, 1);
        /* init the new bind */
        bind->sock = -1;
    }

    /* config local address */
    NC_CHECK_RET(config_local_address(n, op, bind));

    /* config local port (default value => always present) */
    NC_CHECK_RET(nc_lyd_find_child(node, "local-port", 1, &n));
    NC_CHECK_RET(config_local_port(n, op, bind));

    /* all children processed, we can now delete the bind */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(endpt->binds) - 1) {
            endpt->binds[i] = endpt->binds[LY_ARRAY_COUNT(endpt->binds) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(endpt->binds);
    }

    return 0;
}

static int
config_idle_time(const struct lyd_node *node, enum nc_operation UNUSED(parent_op), struct nc_keepalives *ka)
{
    /* default value always present */
    ka->idle_time = strtoul(lyd_get_value(node), NULL, 10);
    return 0;
}

static int
config_max_probes(const struct lyd_node *node, enum nc_operation UNUSED(parent_op), struct nc_keepalives *ka)
{
    /* default value always present */
    ka->max_probes = strtoul(lyd_get_value(node), NULL, 10);
    return 0;
}

static int
config_probe_interval(const struct lyd_node *node, enum nc_operation UNUSED(parent_op), struct nc_keepalives *ka)
{
    /* default value always present */
    ka->probe_interval = strtoul(lyd_get_value(node), NULL, 10);
    return 0;
}

static int
config_tcp_keepalives(const struct lyd_node *node, enum nc_operation parent_op, struct nc_keepalives *ka)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config idle-time (default value) */
    NC_CHECK_RET(nc_lyd_find_child(node, "idle-time", 1, &n));
    config_idle_time(n, op, ka);

    /* config max-probes (default value) */
    NC_CHECK_RET(nc_lyd_find_child(node, "max-probes", 1, &n));
    config_max_probes(n, op, ka);

    /* config probe-interval (default value) */
    NC_CHECK_RET(nc_lyd_find_child(node, "probe-interval", 1, &n));
    config_probe_interval(n, op, ka);

    /* all children processed */
    if (op == NC_OP_DELETE) {
        ka->enabled = 0;
    } else if (op == NC_OP_CREATE) {
        ka->enabled = 1;
    }

    return 0;
}

static int
config_tcp_server_params(const struct lyd_node *node, enum nc_operation parent_op, struct nc_endpt *endpt)
{
    struct lyd_node *n;
    enum nc_operation op;
    struct ly_set *set = NULL;
    uint32_t i;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all the local binds */
    NC_CHECK_RET(lyd_find_xpath(node, "local-bind", &set), 1);
    for (i = 0; i < set->count; i++) {
        NC_CHECK_GOTO(config_local_bind(set->dnodes[i], op, endpt), cleanup);
    }

    /* keepalives (presence container) */
    NC_CHECK_GOTO(nc_lyd_find_child(node, "keepalives", 0, &n), cleanup);
    if (n) {
        NC_CHECK_GOTO(config_tcp_keepalives(n, op, &endpt->ka), cleanup);
    }

cleanup:
    ly_set_free(set, NULL);
    return 0;
}

static int
config_hostkey_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_hostkey *hostkey)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(hostkey->name);
        hostkey->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(hostkey->name);
        hostkey->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!hostkey->name, 1);
    }

    return 0;
}

static int
config_pubkey_format(const struct lyd_node *node, enum nc_operation parent_op, struct nc_public_key *pubkey)
{
    enum nc_operation op;
    const char *format;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        pubkey->type = NC_PUBKEY_FORMAT_UNKNOWN;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        format = ((struct lyd_node_term *)node)->value.ident->name;
        assert(format);
        if (!strcmp(format, "ssh-public-key-format")) {
            pubkey->type = NC_PUBKEY_FORMAT_SSH;
        } else if (!strcmp(format, "subject-public-key-info-format")) {
            pubkey->type = NC_PUBKEY_FORMAT_X509;
        } else {
            /* do not fail, the key may still be usable, or it may have come from a keystore/truststore
             * and have a different purpose other than NETCONF */
            WRN(NULL, "Public key format \"%s\" not supported. The key may not be usable.", format);
            pubkey->type = NC_PUBKEY_FORMAT_UNKNOWN;
        }
    }

    return 0;
}

static int
config_pubkey_data(const struct lyd_node *node, enum nc_operation parent_op, struct nc_public_key *pubkey)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(pubkey->data);
        pubkey->data = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(pubkey->data);
        pubkey->data = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!pubkey->data, 1);
    }

    return 0;
}

static int
config_privkey_format(const struct lyd_node *node, enum nc_operation parent_op, struct nc_private_key *privkey)
{
    enum nc_operation op;
    const char *format;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        privkey->type = NC_PRIVKEY_FORMAT_UNKNOWN;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        format = ((struct lyd_node_term *)node)->value.ident->name;
        assert(format);

        if (!strcmp(format, "rsa-private-key-format")) {
            privkey->type = NC_PRIVKEY_FORMAT_RSA;
        } else if (!strcmp(format, "ec-private-key-format")) {
            privkey->type = NC_PRIVKEY_FORMAT_EC;
        } else if (!strcmp(format, "private-key-info-format")) {
            privkey->type = NC_PRIVKEY_FORMAT_X509;
        } else if (!strcmp(format, "openssh-private-key-format")) {
            privkey->type = NC_PRIVKEY_FORMAT_OPENSSH;
        } else {
            /* do not fail, the key may still be usable, or it may have come from a keystore/truststore
             * and have a different purpose other than NETCONF */
            WRN(NULL, "Private key format \"%s\" not supported. The key may not be usable.", format);
            privkey->type = NC_PRIVKEY_FORMAT_UNKNOWN;
        }
    }

    return 0;
}

static int
config_cleartext_privkey_data(const struct lyd_node *node, enum nc_operation parent_op, struct nc_private_key *privkey)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(privkey->data);
        privkey->data = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(privkey->data);
        privkey->data = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!privkey->data, 1);
    }

    return 0;
}

static int
config_hidden_privkey_data(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_encrypted_privkey_data(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_hostkey_pubkey_inline(const struct lyd_node *node, enum nc_operation parent_op, struct nc_hostkey *hostkey)
{
    struct lyd_node *n, *cleartext = NULL, *hidden = NULL, *encrypted = NULL;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config pubkey format */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key-format", 0, &n));
    if (n) {
        NC_CHECK_RET(config_pubkey_format(n, op, &hostkey->key.pubkey));
    }

    /* config pubkey data */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key", 0, &n));
    if (n) {
        NC_CHECK_RET(config_pubkey_data(n, op, &hostkey->key.pubkey));
    }

    /* config private key format */
    NC_CHECK_RET(nc_lyd_find_child(node, "private-key-format", 0, &n));
    if (n) {
        NC_CHECK_RET(config_privkey_format(n, op, &hostkey->key.privkey));
    }

    /* config privkey data, mandatory case/choice node => only one can be present */
    NC_CHECK_RET(nc_lyd_find_child(node, "cleartext-private-key", 0, &cleartext));
    NC_CHECK_RET(nc_lyd_find_child(node, "hidden-private-key", 0, &hidden));
    NC_CHECK_RET(nc_lyd_find_child(node, "encrypted-private-key", 0, &encrypted));
    if (cleartext) {
        NC_CHECK_RET(config_cleartext_privkey_data(cleartext, op, &hostkey->key.privkey));
    } else if (hidden) {
        NC_CHECK_RET(config_hidden_privkey_data(hidden, op));
    } else {
        assert(encrypted);
        NC_CHECK_RET(config_encrypted_privkey_data(encrypted, op));
    }

    if (op == NC_OP_DELETE) {
        hostkey->store = NC_STORE_UNKNOWN;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        hostkey->store = NC_STORE_LOCAL;
    }

    return 0;
}

static int
config_hostkey_pubkey_keystore(const struct lyd_node *node, enum nc_operation parent_op, struct nc_hostkey *hostkey)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(hostkey->ks_ref);
        hostkey->ks_ref = NULL;
        hostkey->store = NC_STORE_UNKNOWN;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(hostkey->ks_ref);
        hostkey->ks_ref = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!hostkey->ks_ref, 1);
        hostkey->store = NC_STORE_KEYSTORE;
    }

    return 0;
}

static int
config_hostkey_public_key(const struct lyd_node *node, enum nc_operation parent_op, struct nc_hostkey *hostkey)
{
    enum nc_operation op;
    struct lyd_node *inline_def = NULL, *keystore_ref = NULL;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config inline-definition / keystore ref */
    NC_CHECK_RET(nc_lyd_find_child(node, "inline-definition", 0, &inline_def));
    NC_CHECK_RET(nc_lyd_find_child(node, "central-keystore-reference", 0, &keystore_ref));
    if (inline_def) {
        NC_CHECK_RET(config_hostkey_pubkey_inline(inline_def, op, hostkey));
    } else {
        assert(keystore_ref);
        NC_CHECK_RET(config_hostkey_pubkey_keystore(keystore_ref, op, hostkey));
    }

    return 0;
}

static int
config_hostkey_certificate(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_ssh_hostkey(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    struct lyd_node *n, *public_key = NULL, *certificate = NULL;
    enum nc_operation op;
    struct nc_hostkey *hostkey = NULL;
    const char *name;
    LY_ARRAY_COUNT_TYPE i;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* hostkey name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the hostkey we are deleting/modifying */
        LY_ARRAY_FOR(ssh->hostkeys, i) {
            if (!strcmp(ssh->hostkeys[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(ssh->hostkeys));
        hostkey = &ssh->hostkeys[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new hostkey */
        LY_ARRAY_NEW_RET(LYD_CTX(node), ssh->hostkeys, hostkey, 1);
    }

    /* config hostkey name */
    NC_CHECK_RET(config_hostkey_name(n, op, hostkey));

    /* config public-key / certificate */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key", 0, &public_key));
    NC_CHECK_RET(nc_lyd_find_child(node, "certificate", 0, &certificate));
    if (public_key) {
        /* config public key */
        NC_CHECK_RET(config_hostkey_public_key(public_key, op, hostkey));
    } else {
        /* config certificate */
        assert(certificate);
        NC_CHECK_RET(config_hostkey_certificate(certificate, op));
    }

    /* all children processed, we can now delete the hostkey */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(ssh->hostkeys) - 1) {
            ssh->hostkeys[i] = ssh->hostkeys[LY_ARRAY_COUNT(ssh->hostkeys) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(ssh->hostkeys);
    }

    return 0;
}

static int
config_ssh_banner(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(ssh->banner);
        ssh->banner = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(ssh->banner);
        ssh->banner = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!ssh->banner, 1);
    }

    return 0;
}

static int
config_ssh_server_identity(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    struct lyd_node *n;
    enum nc_operation op;
    struct ly_set *set = NULL;
    uint32_t i;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all the hostkeys */
    NC_CHECK_RET(lyd_find_xpath(node, "host-key", &set), 1);
    for (i = 0; i < set->count; i++) {
        NC_CHECK_GOTO(config_ssh_hostkey(set->dnodes[i], op, ssh), cleanup);
    }

    /* config ssh banner (augment) */
    NC_CHECK_GOTO(nc_lyd_find_child(node, "libnetconf2-netconf-server:banner", 0, &n), cleanup);
    if (n) {
        NC_CHECK_GOTO(config_ssh_banner(n, op, ssh), cleanup);
    }

cleanup:
    ly_set_free(set, NULL);
    return 0;
}

static int
config_ssh_user_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_auth_client *user)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(user->username);
        user->username = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(user->username);
        user->username = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!user->username, 1);
    }

    return 0;
}

static int
config_pubkey_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_public_key *key)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(key->name);
        key->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(key->name);
        key->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!key->name, 1);
    }

    return 0;
}

static int
config_ssh_user_public_key(const struct lyd_node *node, enum nc_operation parent_op, struct nc_auth_client *user)
{
    enum nc_operation op;
    struct lyd_node *n;
    struct nc_public_key *key = NULL;
    LY_ARRAY_COUNT_TYPE i;
    const char *name;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* public key name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the public key we are deleting/modifying */
        LY_ARRAY_FOR(user->pubkeys, i) {
            if (!strcmp(user->pubkeys[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(user->pubkeys));
        key = &user->pubkeys[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new public key */
        LY_ARRAY_NEW_RET(LYD_CTX(node), user->pubkeys, key, 1);
    }

    /* config public key name */
    NC_CHECK_RET(config_pubkey_name(n, op, key));

    /* config public key format */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key-format", 1, &n));
    NC_CHECK_RET(config_pubkey_format(n, op, key), 1);

    /* config public key data */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key", 1, &n));
    NC_CHECK_RET(config_pubkey_data(n, op, key), 1);

    /* all children processed, we can now delete the public key */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(user->pubkeys) - 1) {
            user->pubkeys[i] = user->pubkeys[LY_ARRAY_COUNT(user->pubkeys) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(user->pubkeys);
    }

    return 0;
}

static int
config_ssh_user_pubkey_inline(const struct lyd_node *node, enum nc_operation parent_op, struct nc_auth_client *user)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config all inline public keys */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_ssh_user_public_key(n, op, user));
    }

    if (op == NC_OP_DELETE) {
        user->pubkey_store = NC_STORE_UNKNOWN;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        user->pubkey_store = NC_STORE_LOCAL;
    }

    return 0;
}

static int
config_ssh_user_pubkey_truststore(const struct lyd_node *node, enum nc_operation parent_op, struct nc_auth_client *user)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(user->ts_ref);
        user->ts_ref = NULL;
        user->pubkey_store = NC_STORE_UNKNOWN;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(user->ts_ref);
        user->ts_ref = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!user->ts_ref, 1);
        user->pubkey_store = NC_STORE_TRUSTSTORE;
    }

    return 0;
}

static int
config_ssh_user_pubkey_system(const struct lyd_node *node, enum nc_operation parent_op, struct nc_auth_client *user)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        user->pubkey_store = NC_STORE_UNKNOWN;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        user->pubkey_store = NC_STORE_SYSTEM;
    }

    return 0;
}

static int
config_ssh_user_public_keys(const struct lyd_node *node, enum nc_operation parent_op, struct nc_auth_client *user)
{
    struct lyd_node *inline_def = NULL, *truststore_ref = NULL, *system = NULL;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config inline-definition / truststore reference / system (augment) */
    NC_CHECK_RET(nc_lyd_find_child(node, "inline-definition", 0, &inline_def), 1);
    NC_CHECK_RET(nc_lyd_find_child(node, "central-truststore-reference", 0, &truststore_ref), 1);
    NC_CHECK_RET(nc_lyd_find_child(node, "libnetconf2-netconf-server:use-system-keys", 0, &system), 1);
    if (inline_def) {
        NC_CHECK_RET(config_ssh_user_pubkey_inline(inline_def, op, user));
    } else if (truststore_ref) {
        NC_CHECK_RET(config_ssh_user_pubkey_truststore(truststore_ref, op, user));
    } else {
        assert(system);
        NC_CHECK_RET(config_ssh_user_pubkey_system(system, op, user));
    }

    return 0;
}

static int
config_ssh_user_hashed_password(const struct lyd_node *node, enum nc_operation parent_op, struct nc_auth_client *user)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(user->password);
        user->password = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(user->password);
        user->password = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!user->password, 1);
    }

    user->password_last_modified = time(NULL);
    return 0;
}

static int
config_ssh_user_password(const struct lyd_node *node, enum nc_operation parent_op, struct nc_auth_client *user)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure hashed password */
    NC_CHECK_RET(nc_lyd_find_child(node, "hashed-password", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ssh_user_hashed_password(n, op, user));
    }

    /* last modified leaf is config false, we can end */
    return 0;
}

static int
config_ssh_user_hostbased(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_ssh_user_none(const struct lyd_node *node, enum nc_operation parent_op, struct nc_auth_client *user)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        user->none_enabled = 0;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        user->none_enabled = 1;
    }

    return 0;
}

static int
config_ssh_user_keyboard_interactive_system(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_auth_client *user)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        user->kbdint_method = NC_KBDINT_AUTH_METHOD_NONE;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        user->kbdint_method = NC_KBDINT_AUTH_METHOD_SYSTEM;
    }

    return 0;
}

static int
config_ssh_user_keyboard_interactive(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_auth_client *user)
{
    struct lyd_node *system = NULL;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config method choice, currently only use-system-auth is supported */
    NC_CHECK_RET(nc_lyd_find_child(node, "use-system-auth", 0, &system));
    if (system) {
        NC_CHECK_RET(config_ssh_user_keyboard_interactive_system(system, op, user));
    }

    return 0;
}

static int
config_ssh_user(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    struct lyd_node *n;
    struct nc_auth_client *user = NULL;
    const char *name;
    uint32_t i;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* user name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the user we are deleting */
        LY_ARRAY_FOR(ssh->auth_clients, i) {
            if (!strcmp(ssh->auth_clients[i].username, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(ssh->auth_clients));
        user = &ssh->auth_clients[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new user */
        LY_ARRAY_NEW_RET(LYD_CTX(node), ssh->auth_clients, user, 1);
    }

    /* config user name */
    NC_CHECK_RET(config_ssh_user_name(n, op, user));

    /* config public keys */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-keys", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ssh_user_public_keys(n, op, user));
    }

    /* config password */
    NC_CHECK_RET(nc_lyd_find_child(node, "password", 1, &n));
    NC_CHECK_RET(config_ssh_user_password(n, op, user));

    /* config hostbased */
    NC_CHECK_RET(nc_lyd_find_child(node, "hostbased", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ssh_user_hostbased(n, op));
    }

    /* config none */
    NC_CHECK_RET(nc_lyd_find_child(node, "none", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ssh_user_none(n, op, user));
    }

    /* config keyboard-interactive (augment) */
    NC_CHECK_RET(nc_lyd_find_child(node, "libnetconf2-netconf-server:keyboard-interactive", 1, &n));
    NC_CHECK_RET(config_ssh_user_keyboard_interactive(n, op, user));

    /* all children processed, we can now delete the user */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(ssh->auth_clients) - 1) {
            ssh->auth_clients[i] = ssh->auth_clients[LY_ARRAY_COUNT(ssh->auth_clients) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(ssh->auth_clients);
    }

    return 0;
}

static int
config_ssh_users(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config all users */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_ssh_user(n, op, ssh));
    }

    return 0;
}

static int
config_ssh_ca_certs(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_ssh_ee_certs(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_ssh_auth_timeout(const struct lyd_node *node, enum nc_operation UNUSED(parent_op),
        struct nc_server_ssh_opts *ssh)
{
    /* default value always present */
    ssh->auth_timeout = strtoul(lyd_get_value(node), NULL, 10);
    return 0;
}

static int
config_endpt_reference(const struct lyd_node *node, enum nc_operation parent_op, char **endpt_ref)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(*endpt_ref);
        *endpt_ref = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(*endpt_ref);
        *endpt_ref = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!*endpt_ref, 1);
    }

    return 0;
}

static int
config_ssh_client_auth(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config users */
    NC_CHECK_RET(nc_lyd_find_child(node, "users", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ssh_users(n, op, ssh));
    }

    /* config ca-certs */
    NC_CHECK_RET(nc_lyd_find_child(node, "ca-certs", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ssh_ca_certs(n, op));
    }

    /* config ee-certs */
    NC_CHECK_RET(nc_lyd_find_child(node, "ee-certs", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ssh_ee_certs(n, op));
    }

    /* config auth timeout (augment) */
    NC_CHECK_RET(nc_lyd_find_child(node, "libnetconf2-netconf-server:auth-timeout", 1, &n));
    NC_CHECK_RET(config_ssh_auth_timeout(n, op, ssh));

    /* config endpoint reference (augment) */
    NC_CHECK_RET(nc_lyd_find_child(node, "libnetconf2-netconf-server:endpoint-reference", 0, &n));
    if (n) {
        NC_CHECK_RET(config_endpt_reference(n, op, &ssh->referenced_endpt_name));
    }

    return 0;
}

/**
 * @brief Delete an algorithm from a @p sep separated list of algorithms.
 *
 * @param[in,out] list @p sep separated list of algorithms.
 * @param[in] alg Algorithm to delete.
 * @param[in] sep Separator character.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_del_alg(char *list, const char *alg, const char sep)
{
    char *pos, *next;
    size_t alg_len = strlen(alg);
    int found = 0;

    if (!list) {
        ERR(NULL, "No algorithms previously configured, cannot delete \"%s\".", alg);
        return 1;
    }

    /* find the algorithm in the list */
    pos = list;
    while ((next = strchr(pos, sep))) {
        if (((size_t)(next - pos) == alg_len) && !strncmp(pos, alg, alg_len)) {
            /* found the algorithm */
            found = 1;
            break;
        }
        pos = next + 1;
    }

    if (!found) {
        /* check the last element */
        if (!strcmp(pos, alg)) {
            found = 1;
        }
    }

    if (!found) {
        ERR(NULL, "Algorithm \"%s\" not previously configured, cannot be deleted.", alg);
        return 1;
    }

    /* delete the algorithm */
    if (next) {
        /* not the last element, move the rest of the string to the left */
        memmove(pos, next + 1, strlen(next + 1) + 1);
    } else {
        /* the last element, just terminate the string here */
        *pos = '\0';
    }

    return 0;
}

/**
 * @brief Add an algorithm to a @p sep separated list of algorithms.
 *
 * @param[in,out] list Pointer to a @p sep separated list of algorithms. Will be allocated if NULL.
 * @param[in] alg Algorithm to add.
 * @param[in] sep Separator character.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_add_alg(char **list, const char *alg, const char sep)
{
    char *pos;
    size_t alg_len = strlen(alg);

    if (*list) {
        /* check for duplicates */
        pos = *list;
        while ((pos = strchr(pos, sep))) {
            if (((size_t)(pos - *list) == alg_len) && !strncmp(*list, alg, alg_len)) {
                /* found the algorithm */
                WRN(NULL, "Algorithm \"%s\" already configured.", alg);
                return 0;
            }
            pos++;
        }
        /* check the last element */
        if (!strcmp(*list, alg)) {
            WRN(NULL, "Algorithm \"%s\" already configured.", alg);
            return 0;
        }

        /* add the algorithm to the end of the list */
        *list = nc_realloc(*list, strlen(*list) + 1 + alg_len + 1);
        NC_CHECK_ERRMEM_RET(!*list, 1);
        sprintf(*list + strlen(*list), "%c%s", sep, alg);
    } else {
        /* create a new list with the algorithm */
        *list = strdup(alg);
        NC_CHECK_ERRMEM_RET(!*list, 1);
    }

    return 0;
}

static int
config_hostkey_alg(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    const char *alg;

    NC_NODE_GET_OP(node, parent_op, &op);

    alg = lyd_get_value(node);
    assert(alg);

    if (op == NC_OP_DELETE) {
        /* delete the alg from the comma separated list */
        NC_CHECK_RET(nc_server_config_del_alg(ssh->hostkey_algs, alg, ','));
        if (!ssh->hostkey_algs[0]) {
            /* the list is now empty, free it */
            free(ssh->hostkey_algs);
            ssh->hostkey_algs = NULL;
        }
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* add the alg to the comma separated list,
         * the value is either one of the enums from iana-ssh-pk-algs or
         * it can contain a '@' character for custom algorithms.
         * We can store their names just as they are and let libssh handle it later. */
        NC_CHECK_RET(nc_server_config_add_alg(&ssh->hostkey_algs, alg, ','));
    }

    return 0;
}

static int
config_transport_param_hkalgs(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all host-key algorithms (leaf-lists) */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_hostkey_alg(n, op, ssh));
    }

    return 0;
}

static int
config_kex_alg(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    const char *alg;

    NC_NODE_GET_OP(node, parent_op, &op);

    alg = lyd_get_value(node);
    assert(alg);

    if (op == NC_OP_DELETE) {
        /* delete the alg from the comma separated list */
        NC_CHECK_RET(nc_server_config_del_alg(ssh->kex_algs, alg, ','));
        if (!ssh->kex_algs[0]) {
            /* the list is now empty, free it */
            free(ssh->kex_algs);
            ssh->kex_algs = NULL;
        }
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* add the alg to the comma separated list */
        NC_CHECK_RET(nc_server_config_add_alg(&ssh->kex_algs, alg, ','));
    }

    return 0;
}

static int
config_transport_param_kexalgs(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all kex algorithms (leaf-lists) */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_kex_alg(n, op, ssh));
    }

    return 0;
}

static int
config_enc_alg(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    const char *alg;

    NC_NODE_GET_OP(node, parent_op, &op);

    alg = lyd_get_value(node);
    assert(alg);

    if (op == NC_OP_DELETE) {
        /* delete the alg from the comma separated list */
        NC_CHECK_RET(nc_server_config_del_alg(ssh->encryption_algs, alg, ','));
        if (!ssh->encryption_algs[0]) {
            /* the list is now empty, free it */
            free(ssh->encryption_algs);
            ssh->encryption_algs = NULL;
        }
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* add the alg to the comma separated list */
        NC_CHECK_RET(nc_server_config_add_alg(&ssh->encryption_algs, alg, ','));
    }

    return 0;
}

static int
config_transport_param_encalgs(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all encryption algorithms (leaf-lists) */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_enc_alg(n, op, ssh));
    }

    return 0;
}

static int
config_mac_alg(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    const char *alg;

    NC_NODE_GET_OP(node, parent_op, &op);

    alg = lyd_get_value(node);
    assert(alg);

    if (op == NC_OP_DELETE) {
        /* delete the alg from the comma separated list */
        NC_CHECK_RET(nc_server_config_del_alg(ssh->mac_algs, alg, ','));
        if (!ssh->mac_algs[0]) {
            /* the list is now empty, free it */
            free(ssh->mac_algs);
            ssh->mac_algs = NULL;
        }
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* add the alg to the comma separated list */
        NC_CHECK_RET(nc_server_config_add_alg(&ssh->mac_algs, alg, ','));
    }

    return 0;
}

static int
config_transport_param_macalgs(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all mac algorithms (leaf-lists) */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_mac_alg(n, op, ssh));
    }

    return 0;
}

static int
config_ssh_transport_params(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config host-key */
    NC_CHECK_RET(nc_lyd_find_child(node, "host-key", 1, &n));
    NC_CHECK_RET(config_transport_param_hkalgs(n, op, ssh));

    /* config kex-algorithms */
    NC_CHECK_RET(nc_lyd_find_child(node, "key-exchange", 1, &n));
    NC_CHECK_RET(config_transport_param_kexalgs(n, op, ssh));

    /* config encryption-algorithms */
    NC_CHECK_RET(nc_lyd_find_child(node, "encryption", 1, &n));
    NC_CHECK_RET(config_transport_param_encalgs(n, op, ssh));

    /* config mac-algorithms */
    NC_CHECK_RET(nc_lyd_find_child(node, "mac", 1, &n));
    NC_CHECK_RET(config_transport_param_macalgs(n, op, ssh));

    return 0;
}

static int
config_ssh_keepalives(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_ssh_server_params(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_ssh_opts *ssh)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* server identity */
    NC_CHECK_RET(nc_lyd_find_child(node, "server-identity", 1, &n));
    NC_CHECK_RET(config_ssh_server_identity(n, op, ssh));

    /* client authentication */
    NC_CHECK_RET(nc_lyd_find_child(node, "client-authentication", 1, &n));
    NC_CHECK_RET(config_ssh_client_auth(n, op, ssh));

    /* transport parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "transport-params", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ssh_transport_params(n, op, ssh));
    }

    /* keepalives */
    NC_CHECK_RET(nc_lyd_find_child(node, "keepalives", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ssh_keepalives(n, op));
    }

    return 0;
}

static int
config_ssh_netconf_server_params(const struct lyd_node *UNUSED(node), enum nc_operation UNUSED(parent_op))
{
    /* nothing to do, this is just a container, its children are not supported in SSH yet */
    return 0;
}

static int
config_ssh(const struct lyd_node *node, enum nc_operation parent_op, struct nc_endpt *endpt)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* create the ssh opts */
    if (!endpt->opts.ssh) {
        /* op should not be NC_OP_DELETE if the diff is valid, otherwise this would have already been created */
        endpt->opts.ssh = calloc(1, sizeof *endpt->opts.ssh);
        NC_CHECK_ERRMEM_RET(!endpt->opts.ssh, 1);
        endpt->ti = NC_TI_SSH;
    }

    /* tcp server parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "tcp-server-parameters", 1, &n));
    NC_CHECK_RET(config_tcp_server_params(n, op, endpt));

    /* ssh server parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "ssh-server-parameters", 1, &n));
    NC_CHECK_RET(config_ssh_server_params(n, op, endpt->opts.ssh));

    /* netconf server parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "netconf-server-parameters", 1, &n));
    NC_CHECK_RET(config_ssh_netconf_server_params(n, op));

    if (op == NC_OP_DELETE) {
        free(endpt->opts.ssh);
        endpt->opts.ssh = NULL;
        endpt->ti = NC_TI_NONE;
    }

    return 0;
}

static int
config_cert_data(const struct lyd_node *node, enum nc_operation parent_op, struct nc_certificate *cert)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(cert->data);
        cert->data = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(cert->data);
        cert->data = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!cert->data, 1);
    }

    return 0;
}

static int
config_generate_csr(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_cert_expiration(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_tls_server_ident_cert_inline(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *opts)
{
    enum nc_operation op;
    struct lyd_node *n, *cleartext, *hidden, *encrypted;

    NC_NODE_GET_OP(node, parent_op, &op);

    opts->cert_store = NC_STORE_LOCAL;

    /* config public key format */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key-format", 0, &n));
    if (n) {
        NC_CHECK_RET(config_pubkey_format(n, op, &opts->local.key.pubkey), 1);
    }

    /* config public key data */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key", 0, &n));
    if (n) {
        NC_CHECK_RET(config_pubkey_data(n, op, &opts->local.key.pubkey), 1);
    }

    /* config private key format */
    NC_CHECK_RET(nc_lyd_find_child(node, "private-key-format", 0, &n));
    if (n) {
        NC_CHECK_RET(config_privkey_format(n, op, &opts->local.key.privkey), 1);
    }

    /* config private key data choice */
    NC_CHECK_RET(nc_lyd_find_child(node, "cleartext-private-key", 0, &cleartext));
    NC_CHECK_RET(nc_lyd_find_child(node, "hidden-private-key", 0, &hidden));
    NC_CHECK_RET(nc_lyd_find_child(node, "encrypted-private-key", 0, &encrypted));
    if (cleartext) {
        NC_CHECK_RET(config_cleartext_privkey_data(cleartext, op, &opts->local.key.privkey), 1);
    } else if (hidden) {
        NC_CHECK_RET(config_hidden_privkey_data(hidden, op), 1);
    } else {
        assert(encrypted);
        NC_CHECK_RET(config_encrypted_privkey_data(encrypted, op), 1);
    }

    /* config certificate data */
    NC_CHECK_RET(nc_lyd_find_child(node, "cert-data", 0, &n));
    if (n) {
        NC_CHECK_RET(config_cert_data(n, op, &opts->local.cert), 1);
    }

    /* config generate csr */
    NC_CHECK_RET(nc_lyd_find_child(node, "generate-csr", 0, &n));
    if (n) {
        NC_CHECK_RET(config_generate_csr(n, op), 1);
    }

    /* config certificate expiration */
    NC_CHECK_RET(nc_lyd_find_child(node, "certificate-expiration", 0, &n));
    if (n) {
        NC_CHECK_RET(config_cert_expiration(n, op), 1);
    }

    if (op == NC_OP_DELETE) {
        opts->cert_store = NC_STORE_UNKNOWN;
    }

    return 0;
}

static int
config_tls_server_ident_cert_keystore_asym_key_ref(const struct lyd_node *node,
        enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(tls->keystore.asym_key_ref);
        tls->keystore.asym_key_ref = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(tls->keystore.asym_key_ref);
        tls->keystore.asym_key_ref = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!tls->keystore.asym_key_ref, 1);
    }

    return 0;
}

static int
config_tls_server_ident_cert_keystore_cert_ref(const struct lyd_node *node,
        enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(tls->keystore.cert_ref);
        tls->keystore.cert_ref = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(tls->keystore.cert_ref);
        tls->keystore.cert_ref = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!tls->keystore.cert_ref, 1);
    }

    return 0;
}

static int
config_tls_server_ident_cert_keystore(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_server_tls_opts *tls)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    tls->cert_store = NC_STORE_KEYSTORE;

    /* config asymmetric key reference */
    NC_CHECK_RET(nc_lyd_find_child(node, "asymmetric-key", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_server_ident_cert_keystore_asym_key_ref(n, op, tls), 1);
    }

    /* config certificate reference */
    NC_CHECK_RET(nc_lyd_find_child(node, "certificate", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_server_ident_cert_keystore_cert_ref(n, op, tls), 1);
    }

    if (op == NC_OP_DELETE) {
        tls->cert_store = NC_STORE_UNKNOWN;
    }

    return 0;
}

static int
config_tls_server_ident_certificate(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    struct lyd_node *inline_def, *keystore_ref;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config inline-definition / keystore ref choice */
    NC_CHECK_RET(nc_lyd_find_child(node, "inline-definition", 0, &inline_def));
    NC_CHECK_RET(nc_lyd_find_child(node, "central-keystore-reference", 0, &keystore_ref));
    if (inline_def) {
        NC_CHECK_RET(config_tls_server_ident_cert_inline(inline_def, op, tls));
    } else {
        assert(keystore_ref);
        NC_CHECK_RET(config_tls_server_ident_cert_keystore(keystore_ref, op, tls));
    }

    return 0;
}

static int
config_tls_server_ident_raw_key(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_tls_server_ident_tls12_psk(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_tls_server_ident_tls13_epsk(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_tls_server_identity(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    struct lyd_node *certificate, *raw_private_key, *tls12_psk, *tls13_epsk;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config authentication type choice node */
    NC_CHECK_RET(nc_lyd_find_child(node, "certificate", 0, &certificate));
    NC_CHECK_RET(nc_lyd_find_child(node, "raw-private-key", 0, &raw_private_key));
    NC_CHECK_RET(nc_lyd_find_child(node, "tls12-psk", 0, &tls12_psk));
    NC_CHECK_RET(nc_lyd_find_child(node, "tls13-epsk", 0, &tls13_epsk));
    if (certificate) {
        NC_CHECK_RET(config_tls_server_ident_certificate(certificate, op, tls));
    } else if (raw_private_key) {
        NC_CHECK_RET(config_tls_server_ident_raw_key(raw_private_key, op));
    } else if (tls12_psk) {
        NC_CHECK_RET(config_tls_server_ident_tls12_psk(tls12_psk, op));
    } else {
        assert(tls13_epsk);
        NC_CHECK_RET(config_tls_server_ident_tls13_epsk(tls13_epsk, op));
    }

    return 0;
}

static int
config_cert_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_certificate *cert)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(cert->name);
        cert->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(cert->name);
        cert->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!cert->name, 1);
    }

    return 0;
}

static int
config_tls_client_auth_ca_cert(const struct lyd_node *node,
        enum nc_operation parent_op, struct nc_server_tls_client_auth *client_auth)
{
    enum nc_operation op;
    struct lyd_node *n;
    const char *name;
    LY_ARRAY_COUNT_TYPE i;
    struct nc_certificate *cert = NULL;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config ca-cert name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the ca-cert we are deleting/modifying */
        LY_ARRAY_FOR(client_auth->ca_certs, i) {
            if (!strcmp(client_auth->ca_certs[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(client_auth->ca_certs));
        cert = &client_auth->ca_certs[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new ca-cert */
        LY_ARRAY_NEW_RET(LYD_CTX(node), client_auth->ca_certs, cert, 1);
    }

    /* config ca-cert name */
    NC_CHECK_RET(config_cert_name(n, op, cert));

    /* config ca-cert data */
    NC_CHECK_RET(nc_lyd_find_child(node, "cert-data", 1, &n));
    NC_CHECK_RET(config_cert_data(n, op, cert));

    /* config certificate expiration */
    NC_CHECK_RET(nc_lyd_find_child(node, "certificate-expiration", 0, &n));
    if (n) {
        NC_CHECK_RET(config_cert_expiration(n, op), 1);
    }

    /* all children processed, we can now delete the ca-cert */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(client_auth->ca_certs) - 1) {
            client_auth->ca_certs[i] = client_auth->ca_certs[LY_ARRAY_COUNT(client_auth->ca_certs) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(client_auth->ca_certs);
    }

    return 0;
}

static int
config_tls_client_auth_ca_certs_inline(const struct lyd_node *node,
        enum nc_operation parent_op, struct nc_server_tls_client_auth *client_auth)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    client_auth->ca_certs_store = NC_STORE_LOCAL;

    /* configure all the ca-certs */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_tls_client_auth_ca_cert(n, op, client_auth));
    }

    if (op == NC_OP_DELETE) {
        client_auth->ca_certs_store = NC_STORE_UNKNOWN;
    }

    return 0;
}

static int
config_tls_client_auth_ca_certs_truststore(const struct lyd_node *node,
        enum nc_operation parent_op, struct nc_server_tls_client_auth *client_auth)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(client_auth->ca_cert_bag_ts_ref);
        client_auth->ca_cert_bag_ts_ref = NULL;
        client_auth->ca_certs_store = NC_STORE_UNKNOWN;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(client_auth->ca_cert_bag_ts_ref);
        client_auth->ca_cert_bag_ts_ref = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!client_auth->ca_cert_bag_ts_ref, 1);
        client_auth->ca_certs_store = NC_STORE_TRUSTSTORE;
    }

    return 0;
}

static int
config_tls_client_auth_ca_certs(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_client_auth *client_auth)
{
    struct lyd_node *inline_def, *truststore_ref;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config inline-definition / truststore reference choice */
    NC_CHECK_RET(nc_lyd_find_child(node, "inline-definition", 0, &inline_def), 1);
    NC_CHECK_RET(nc_lyd_find_child(node, "central-truststore-reference", 0, &truststore_ref), 1);
    if (inline_def) {
        NC_CHECK_RET(config_tls_client_auth_ca_certs_inline(inline_def, op, client_auth));
    } else {
        assert(truststore_ref);
        NC_CHECK_RET(config_tls_client_auth_ca_certs_truststore(truststore_ref, op, client_auth));
    }

    return 0;
}

static int
config_tls_client_auth_ee_cert(const struct lyd_node *node,
        enum nc_operation parent_op, struct nc_server_tls_client_auth *client_auth)
{
    enum nc_operation op;
    struct lyd_node *n;
    const char *name;
    LY_ARRAY_COUNT_TYPE i;
    struct nc_certificate *cert = NULL;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* ee-cert name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the ee-cert we are deleting/modifying */
        LY_ARRAY_FOR(client_auth->ee_certs, i) {
            if (!strcmp(client_auth->ee_certs[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(client_auth->ee_certs));
        cert = &client_auth->ee_certs[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new ee-cert */
        LY_ARRAY_NEW_RET(LYD_CTX(node), client_auth->ee_certs, cert, 1);
    }

    /* config ee-cert name */
    NC_CHECK_RET(config_cert_name(n, op, cert));

    /* config ee-cert data */
    NC_CHECK_RET(nc_lyd_find_child(node, "cert-data", 0, &n));
    NC_CHECK_RET(config_cert_data(n, op, cert));

    /* config certificate expiration */
    NC_CHECK_RET(nc_lyd_find_child(node, "certificate-expiration", 0, &n));
    if (n) {
        NC_CHECK_RET(config_cert_expiration(n, op), 1);
    }

    /* all children processed, we can now delete the ee-cert */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(client_auth->ee_certs) - 1) {
            client_auth->ee_certs[i] = client_auth->ee_certs[LY_ARRAY_COUNT(client_auth->ee_certs) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(client_auth->ee_certs);
    }

    return 0;
}

static int
config_tls_client_auth_ee_certs_inline(const struct lyd_node *node,
        enum nc_operation parent_op, struct nc_server_tls_client_auth *client_auth)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    client_auth->ee_certs_store = NC_STORE_LOCAL;

    /* configure all the ee-certs */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_tls_client_auth_ee_cert(n, op, client_auth));
    }

    if (op == NC_OP_DELETE) {
        client_auth->ee_certs_store = NC_STORE_UNKNOWN;
    }

    return 0;
}

static int
config_tls_client_auth_ee_certs_truststore(const struct lyd_node *node,
        enum nc_operation parent_op, struct nc_server_tls_client_auth *client_auth)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(client_auth->ee_cert_bag_ts_ref);
        client_auth->ee_cert_bag_ts_ref = NULL;
        client_auth->ee_certs_store = NC_STORE_UNKNOWN;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(client_auth->ee_cert_bag_ts_ref);
        client_auth->ee_cert_bag_ts_ref = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!client_auth->ee_cert_bag_ts_ref, 1);
        client_auth->ee_certs_store = NC_STORE_TRUSTSTORE;
    }

    return 0;
}

static int
config_tls_client_auth_ee_certs(const struct lyd_node *node,
        enum nc_operation parent_op, struct nc_server_tls_client_auth *client_auth)
{
    struct lyd_node *inline_def, *truststore_ref;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config inline-definition / truststore reference choice */
    NC_CHECK_RET(nc_lyd_find_child(node, "inline-definition", 0, &inline_def), 1);
    NC_CHECK_RET(nc_lyd_find_child(node, "central-truststore-reference", 0, &truststore_ref), 1);
    if (inline_def) {
        NC_CHECK_RET(config_tls_client_auth_ee_certs_inline(inline_def, op, client_auth));
    } else {
        assert(truststore_ref);
        NC_CHECK_RET(config_tls_client_auth_ee_certs_truststore(truststore_ref, op, client_auth));
    }

    return 0;
}

static int
config_tls_client_auth_raw_public_keys(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_tls_client_auth_tls12_psks(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_tls_client_auth_tls13_epsks(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_tls_client_auth(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config certificate authority certs */
    NC_CHECK_RET(nc_lyd_find_child(node, "ca-certs", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_client_auth_ca_certs(n, op, &tls->client_auth));
    }

    /* config end entity certs */
    NC_CHECK_RET(nc_lyd_find_child(node, "ee-certs", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_client_auth_ee_certs(n, op, &tls->client_auth));
    }

    /* config raw public keys */
    NC_CHECK_RET(nc_lyd_find_child(node, "raw-public-keys", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_client_auth_raw_public_keys(n, op));
    }

    /* config tls12-psks */
    NC_CHECK_RET(nc_lyd_find_child(node, "tls12-psks", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_client_auth_tls12_psks(n, op));
    }

    /* config tls13-epsks */
    NC_CHECK_RET(nc_lyd_find_child(node, "tls13-epsks", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_client_auth_tls13_epsks(n, op));
    }

    /* config endpoint reference (augment) */
    NC_CHECK_RET(nc_lyd_find_child(node, "libnetconf2-netconf-server:endpoint-reference", 0, &n));
    if (n) {
        NC_CHECK_RET(config_endpt_reference(n, op, &tls->referenced_endpt_name));
    }

    return 0;
}

/**
 * @brief Convert string representation of TLS version YANG identity to enum value.
 *
 * @param[in] str String representation of TLS version YANG identity.
 * @param[out] version Corresponding enum value.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_str2tls_version(const char *str, enum nc_tls_version *version)
{
    *version = NC_TLS_VERSION_NONE;

    if (!strcmp(str, "tls12")) {
        *version = NC_TLS_VERSION_1_2;
    } else if (!strcmp(str, "tls13")) {
        *version = NC_TLS_VERSION_1_3;
    } else {
        ERR(NULL, "Unknown TLS version \"%s\".", str);
        return 1;
    }

    return 0;
}

static int
config_tls_version_min(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    enum nc_operation op;
    const char *ver;
    enum nc_tls_version v;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        tls->min_version = NC_TLS_VERSION_NONE;
    } else {
        ver = ((struct lyd_node_term *)node)->value.ident->name;
        assert(ver);

        NC_CHECK_RET(nc_server_config_str2tls_version(ver, &v));
        tls->min_version = v;
    }

    return 0;
}

static int
config_tls_version_max(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    enum nc_operation op;
    const char *ver;
    enum nc_tls_version v;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        tls->max_version = NC_TLS_VERSION_NONE;
    } else {
        ver = ((struct lyd_node_term *)node)->value.ident->name;
        assert(ver);

        NC_CHECK_RET(nc_server_config_str2tls_version(ver, &v));
        tls->max_version = v;
    }

    return 0;
}

static int
config_tls_versions(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config min tls version */
    NC_CHECK_RET(nc_lyd_find_child(node, "min", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_version_min(n, op, tls));
    }

    /* config max tls version */
    NC_CHECK_RET(nc_lyd_find_child(node, "max", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_version_max(n, op, tls));
    }

    return 0;
}

static int
config_tls_cipher_suite(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    enum nc_operation op;
    const char *suite;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* get the original cipher suite string */
    suite = lyd_get_value(node);
    assert(suite);

    /* convert it to the TLS' backend's format */
    suite = nc_server_tls_cipher_suite_name_to_internal_wrap(suite);
    if (!suite) {
        WRN(NULL, "Unsupported TLS cipher suite \"%s\", ignoring.", lyd_get_value(node));
        return 0;
    }

    if (op == NC_OP_DELETE) {
        /* delete the suite from the colon separated list */
        NC_CHECK_RET(nc_server_config_del_alg(tls->cipher_suites, suite, ':'));
        if (!tls->cipher_suites[0]) {
            /* the list is now empty, free it */
            free(tls->cipher_suites);
            tls->cipher_suites = NULL;
        }
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* add the suite to the colon separated list */
        NC_CHECK_RET(nc_server_config_add_alg(&tls->cipher_suites, suite, ':'));
    }

    return 0;
}

static int
config_tls_cipher_suites(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config all the cipher suites (leaf-lists) */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_tls_cipher_suite(n, op, tls));
    }

    return 0;
}

static int
config_tls_hello_params(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config tls versions */
    NC_CHECK_RET(nc_lyd_find_child(node, "tls-versions", 1, &n));
    NC_CHECK_RET(config_tls_versions(n, op, tls));

    /* config cipher suites */
    NC_CHECK_RET(nc_lyd_find_child(node, "cipher-suites", 1, &n));
    NC_CHECK_RET(config_tls_cipher_suites(n, op, tls));

    return 0;
}

static int
config_tls_keepalives(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_tls_server_params(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config server identity */
    NC_CHECK_RET(nc_lyd_find_child(node, "server-identity", 1, &n));
    NC_CHECK_RET(config_tls_server_identity(n, op, tls));

    /* config client-authentication */
    NC_CHECK_RET(nc_lyd_find_child(node, "client-authentication", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_client_auth(n, op, tls));
    }

    /* config hello parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "hello-params", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_hello_params(n, op, tls));
    }

    /* config tls keepalives */
    NC_CHECK_RET(nc_lyd_find_child(node, "keepalives", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tls_keepalives(n, op));
    }

    return 0;
}

static int
config_fingerprint(const struct lyd_node *node, enum nc_operation parent_op, struct nc_ctn *ctn)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(ctn->fingerprint);
        ctn->fingerprint = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(ctn->fingerprint);
        ctn->fingerprint = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!ctn->fingerprint, 1);
    }

    return 0;
}

static int
config_map_type(const struct lyd_node *node, enum nc_operation parent_op, struct nc_ctn *ctn)
{
    enum nc_operation op;
    const char *type;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        ctn->map_type = NC_TLS_CTN_UNKNOWN;
    } else {
        type = ((struct lyd_node_term *)node)->value.ident->name;
        assert(type);

        if (!strcmp(type, "specified")) {
            ctn->map_type = NC_TLS_CTN_SPECIFIED;
        } else if (!strcmp(type, "san-rfc822-name")) {
            ctn->map_type = NC_TLS_CTN_SAN_RFC822_NAME;
        } else if (!strcmp(type, "san-dns-name")) {
            ctn->map_type = NC_TLS_CTN_SAN_DNS_NAME;
        } else if (!strcmp(type, "san-ip-address")) {
            ctn->map_type = NC_TLS_CTN_SAN_IP_ADDRESS;
        } else if (!strcmp(type, "san-any")) {
            ctn->map_type = NC_TLS_CTN_SAN_ANY;
        } else if (!strcmp(type, "common-name")) {
            ctn->map_type = NC_TLS_CTN_COMMON_NAME;
        } else {
            ERR(NULL, "Unknown cert-to-name mapping type \"%s\".", type);
            return 1;
        }
    }

    return 0;
}

static int
config_ctn_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_ctn *ctn)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(ctn->name);
        ctn->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(ctn->name);
        ctn->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!ctn->name, 1);
    }

    return 0;
}

static int
config_cert_to_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    struct lyd_node *n;
    enum nc_operation op;
    uint32_t id;
    struct nc_ctn *ctn, *iter, *prev;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* get the ctn id (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "id", 1, &n));
    id = strtoul(lyd_get_value(n), NULL, 10);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the ctn we are deleting/modifying */
        if (!tls->ctn) {
            ERR(NULL, "Trying to modify/delete a non-existing cert-to-name mapping with ID %" PRIu32 ".", id);
            return 1;
        }

        iter = tls->ctn;
        prev = NULL;
        while (iter && (iter->id != id)) {
            prev = iter;
            iter = iter->next;
        }
        assert(iter);
        ctn = iter;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* create a new ctn */
        ctn = calloc(1, sizeof *ctn);
        NC_CHECK_ERRMEM_RET(!ctn, 1);
        ctn->id = id;

        /* find the correct place to insert the new ctn (keep the list sorted by id) */
        if (!tls->ctn || (tls->ctn->id > id)) {
            ctn->next = tls->ctn;
            tls->ctn = ctn;
        } else {
            iter = tls->ctn;
            while (iter->next && (iter->next->id < id)) {
                iter = iter->next;
            }
            ctn->next = iter->next;
            iter->next = ctn;
        }
    }

    /* config fingerprint */
    NC_CHECK_RET(nc_lyd_find_child(node, "fingerprint", 0, &n));
    if (n) {
        NC_CHECK_RET(config_fingerprint(n, op, ctn));
    }

    /* config map type */
    NC_CHECK_RET(nc_lyd_find_child(node, "map-type", 1, &n));
    NC_CHECK_RET(config_map_type(n, op, ctn));

    /* config name */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ctn_name(n, op, ctn));
    }

    /* all children processed, we can now delete the ctn */
    if (op == NC_OP_DELETE) {
        if (tls->ctn == ctn) {
            /* ctn is the first in the list */
            tls->ctn = ctn->next;
        } else {
            /* otherwise we have prev from the search above */
            prev->next = ctn->next;
        }
        free(ctn);
    }

    return 0;
}

static int
config_client_identity_mappings(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config all cert to name mappings */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_cert_to_name(n, op, tls));
    }

    return 0;
}

static int
config_tls_netconf_server_params(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_tls_opts *tls)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config client identity mappings */
    NC_CHECK_RET(nc_lyd_find_child(node, "client-identity-mappings", 1, &n));
    NC_CHECK_RET(config_client_identity_mappings(n, op, tls));

    return 0;
}

static int
config_tls(const struct lyd_node *node, enum nc_operation parent_op, struct nc_endpt *endpt)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* create the tls opts */
    if (!endpt->opts.tls) {
        /* op should not be NC_OP_DELETE if the diff is valid, otherwise this would have already been created */
        endpt->opts.tls = calloc(1, sizeof *endpt->opts.tls);
        NC_CHECK_ERRMEM_RET(!endpt->opts.tls, 1);
        endpt->ti = NC_TI_TLS;
    }

    /* tcp server parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "tcp-server-parameters", 1, &n));
    NC_CHECK_RET(config_tcp_server_params(n, op, endpt));

    /* tls server parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "tls-server-parameters", 1, &n));
    NC_CHECK_RET(config_tls_server_params(n, op, endpt->opts.tls));

    /* netconf server parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "netconf-server-parameters", 1, &n));
    NC_CHECK_RET(config_tls_netconf_server_params(n, op, endpt->opts.tls));

    if (op == NC_OP_DELETE) {
        free(endpt->opts.tls);
        endpt->opts.tls = NULL;
        endpt->ti = NC_TI_NONE;
    }

    return 0;
}

#endif /* NC_ENABLED_SSH_TLS */

static int
config_unix_path(const struct lyd_node *node, enum nc_operation parent_op, struct nc_endpt *endpt)
{
    enum nc_operation op;
    struct nc_bind *bind;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        /* the endpoint must have a single binding, so we can just free it,
         * the socket will be closed in ::nc_server_config_free() */
        assert(endpt->binds);
        free(endpt->binds[0].address);
        LY_ARRAY_FREE(endpt->binds);
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* the endpoint must not have any bindings yet, so we can just create one */
        assert(!endpt->binds);
        LY_ARRAY_NEW_RET(LYD_CTX(node), endpt->binds, bind, 1);
        bind->address = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!bind->address, 1);
        bind->sock = -1;
    }

    return 0;
}

static int
config_unix_socket_perms_mode(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_unix_opts *unix)
{
    enum nc_operation op;
    char *endptr;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        unix->mode = (mode_t)-1;
    } else {
        unix->mode = strtol(lyd_get_value(node), &endptr, 8);
        if (*endptr || (unix->mode > 0777)) {
            ERR(NULL, "Invalid UNIX socket mode \"%s\".", lyd_get_value(node));
            return 1;
        }
    }

    return 0;
}

static int
config_unix_socket_perms_owner(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_unix_opts *unix)
{
    enum nc_operation op;
    struct passwd *pw, pwbuf;
    char *buf = NULL;
    size_t buflen = 0;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        unix->uid = (uid_t)-1;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* get uid from the name */
        pw = nc_getpw(0, lyd_get_value(node), &pwbuf, &buf, &buflen);
        NC_CHECK_RET(!pw, 1);
        unix->uid = pw->pw_uid;
        free(buf);
    }

    return 0;
}

static int
config_unix_socket_perms_group(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_unix_opts *unix)
{
    enum nc_operation op;
    struct group *gr, grbuf;
    char *buf = NULL;
    size_t buflen = 0;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        unix->gid = (gid_t)-1;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* get gid from the name */
        gr = nc_getgr(0, lyd_get_value(node), &grbuf, &buf, &buflen);
        NC_CHECK_RET(!gr, 1);
        unix->gid = gr->gr_gid;
        free(buf);
    }

    return 0;
}

static int
config_unix_socket_perms(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_unix_opts *unix)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config mode */
    NC_CHECK_RET(nc_lyd_find_child(node, "mode", 1, &n));
    NC_CHECK_RET(config_unix_socket_perms_mode(n, op, unix));

    /* config owner */
    NC_CHECK_RET(nc_lyd_find_child(node, "owner", 0, &n));
    if (n) {
        NC_CHECK_RET(config_unix_socket_perms_owner(n, op, unix));
    }

    /* config group */
    NC_CHECK_RET(nc_lyd_find_child(node, "group", 0, &n));
    if (n) {
        NC_CHECK_RET(config_unix_socket_perms_group(n, op, unix));
    }

    return 0;
}

static int
config_unix_user_mapping_system_user(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_unix_user_mapping *mapping)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(mapping->system_user);
        mapping->system_user = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(mapping->system_user);
        mapping->system_user = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!mapping->system_user, 1);
    }

    return 0;
}

static int
config_unix_user_mapping_netconf_user(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_unix_user_mapping *mapping)
{
    enum nc_operation op;
    LY_ARRAY_COUNT_TYPE i;
    const char *user;
    char **allowed_user;

    NC_NODE_GET_OP(node, parent_op, &op);

    user = lyd_get_value(node);
    assert(user);

    if (op == NC_OP_DELETE) {
        /* delete the user from the list */
        LY_ARRAY_FOR(mapping->allowed_users, i) {
            if (!strcmp(mapping->allowed_users[i], user)) {
                break;
            }
        }

        if (i == LY_ARRAY_COUNT(mapping->allowed_users)) {
            ERR(NULL, "Trying to delete a non-existing NETCONF user \"%s\" from the UNIX user mapping \"%s\".",
                    user, mapping->system_user);
            return 1;
        }

        /* free the user and replace it with the last one */
        free(mapping->allowed_users[i]);
        if (i < LY_ARRAY_COUNT(mapping->allowed_users) - 1) {
            mapping->allowed_users[i] = mapping->allowed_users[LY_ARRAY_COUNT(mapping->allowed_users) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(mapping->allowed_users);
    } else if (op == NC_OP_CREATE) {
        /* add the user to the list, if it does not already exist */
        LY_ARRAY_FOR(mapping->allowed_users, i) {
            if (!strcmp(mapping->allowed_users[i], user)) {
                break;
            }
        }

        if (i < LY_ARRAY_COUNT(mapping->allowed_users)) {
            ERR(NULL, "Trying to create an already existing NETCONF user \"%s\" in the UNIX user mapping \"%s\".",
                    user, mapping->system_user);
            return 1;
        }

        LY_ARRAY_NEW_RET(LYD_CTX(node), mapping->allowed_users, allowed_user, 1);
        *allowed_user = strdup(user);
        NC_CHECK_ERRMEM_RET(!*allowed_user, 1);
    }

    return 0;
}

static int
config_unix_user_mapping(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_unix_opts *unix)
{
    struct lyd_node *n;
    enum nc_operation op;
    struct nc_server_unix_user_mapping *mapping = NULL;
    const char *system_user;
    LY_ARRAY_COUNT_TYPE i;
    struct ly_set *set = NULL;
    uint32_t j;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* get the system-user (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "system-user", 1, &n));
    system_user = lyd_get_value(n);
    assert(system_user);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the user mapping we are deleting/modifying */
        LY_ARRAY_FOR(unix->user_mappings, i) {
            if (!strcmp(unix->user_mappings[i].system_user, system_user)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(unix->user_mappings));
        mapping = &unix->user_mappings[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new user mapping */
        LY_ARRAY_NEW_RET(LYD_CTX(node), unix->user_mappings, mapping, 1);
    }

    /* config system-user */
    NC_CHECK_RET(config_unix_user_mapping_system_user(n, op, mapping));

    /* configure all netconf-users (leaf-list) */
    NC_CHECK_RET(lyd_find_xpath(node, "netconf-user", &set), 1);
    for (j = 0; j < set->count; ++j) {
        NC_CHECK_GOTO(config_unix_user_mapping_netconf_user(set->dnodes[j], op, mapping), cleanup);
    }

    /* all children processed, we can now delete the user mapping */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(unix->user_mappings) - 1) {
            unix->user_mappings[i] = unix->user_mappings[LY_ARRAY_COUNT(unix->user_mappings) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(unix->user_mappings);
    }

cleanup:
    ly_set_free(set, NULL);
    return 0;
}

static int
config_unix_client_auth(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_unix_opts *unix)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all user mappings */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_unix_user_mapping(n, op, unix));
    }

    return 0;
}

static int
config_unix(const struct lyd_node *node, enum nc_operation parent_op, struct nc_endpt *endpt)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* create the unix opts */
    if (!endpt->opts.unix) {
        /* op should not be NC_OP_DELETE if the diff is valid, otherwise this would have already been created */
        endpt->opts.unix = calloc(1, sizeof *endpt->opts.unix);
        NC_CHECK_ERRMEM_RET(!endpt->opts.unix, 1);
        endpt->ti = NC_TI_UNIX;

        /* set default values */
        endpt->opts.unix->mode = (mode_t)-1;
        endpt->opts.unix->uid = (uid_t)-1;
        endpt->opts.unix->gid = (gid_t)-1;
    }

    /* config path */
    NC_CHECK_RET(nc_lyd_find_child(node, "path", 1, &n));
    NC_CHECK_RET(config_unix_path(n, op, endpt));

    /* config socket permissions */
    NC_CHECK_RET(nc_lyd_find_child(node, "socket-permissions", 1, &n));
    NC_CHECK_RET(config_unix_socket_perms(n, op, endpt->opts.unix));

    /* config client authentication */
    NC_CHECK_RET(nc_lyd_find_child(node, "client-authentication", 1, &n));
    NC_CHECK_RET(config_unix_client_auth(n, op, endpt->opts.unix));

    if (op == NC_OP_DELETE) {
        free(endpt->opts.unix);
        endpt->opts.unix = NULL;
        endpt->ti = NC_TI_NONE;
    }

    return 0;
}

static int
config_endpoint_name(const struct lyd_node *node, enum nc_operation op, struct nc_endpt *endpt)
{
    if (op == NC_OP_DELETE) {
        free(endpt->name);
        endpt->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(endpt->name);
        endpt->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!endpt->name, 1);
    }

    return 0;
}

static int
config_endpoint(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_server_config *config)
{
    struct lyd_node *n, *ssh, *tls, *unix;
    enum nc_operation op;
    struct nc_endpt *endpt = NULL;
    const char *name;
    LY_ARRAY_COUNT_TYPE i;
    int r;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* get the key of this list instance */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* get the endpoint we are deleting/modifying */
        LY_ARRAY_FOR(config->endpts, i) {
            if (!strcmp(config->endpts[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(config->endpts));
        endpt = &config->endpts[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new endpoint */
        LY_ARRAY_NEW_RET(LYD_CTX(node), config->endpts, endpt, 1);

        /* init the new endpoint */
        if ((r = pthread_mutex_init(&endpt->bind_lock, NULL))) {
            ERR(NULL, "Mutex init failed (%s).", strerror(r));
            return 1;
        }
    }

    /* config name */
    NC_CHECK_RET(config_endpoint_name(n, op, endpt));

    /* config ssh/tls/unix (augment) choice */
    NC_CHECK_RET(nc_lyd_find_child(node, "ssh", 0, &ssh));
    NC_CHECK_RET(nc_lyd_find_child(node, "tls", 0, &tls));
    NC_CHECK_RET(nc_lyd_find_child(node, "libnetconf2-netconf-server:unix", 0, &unix));
    assert(ssh || tls || unix);

#ifdef NC_ENABLED_SSH_TLS
    if (ssh) {
        NC_CHECK_RET(config_ssh(ssh, op, endpt));
    } else if (tls) {
        NC_CHECK_RET(config_tls(tls, op, endpt));
    } else
#endif /* NC_ENABLED_SSH_TLS */
    if (unix) {
        NC_CHECK_RET(config_unix(unix, op, endpt));
    }

    /* all children processed, we can now delete the endpoint */
    if (op == NC_OP_DELETE) {
        pthread_mutex_destroy(&endpt->bind_lock);
        if (i < LY_ARRAY_COUNT(config->endpts) - 1) {
            config->endpts[i] = config->endpts[LY_ARRAY_COUNT(config->endpts) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(config->endpts);
    }

    return 0;
}

static int
config_endpoints(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_server_config *config)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure each endpoint */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_endpoint(n, op, config));
    }

    return 0;
}

static int
config_idle_timeout(const struct lyd_node *node, enum nc_operation UNUSED(parent_op),
        struct nc_server_config *config)
{
    /* default value => value always present */
    config->idle_timeout = strtoul(lyd_get_value(node), NULL, 10);
    return 0;
}

static int
config_listen(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_server_config *config)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure idle-timeout */
    NC_CHECK_RET(nc_lyd_find_child(node, "idle-timeout", 1, &n));
    NC_CHECK_RET(config_idle_timeout(n, op, config));

    /* configure endpoints */
    NC_CHECK_RET(nc_lyd_find_child(node, "endpoints", 1, &n));
    NC_CHECK_RET(config_endpoints(n, op, config));

    return 0;
}

static int
config_ch_client_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_ch_client *client)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(client->name);
        client->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(client->name);
        client->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!client->name, 1);
    }

    return 0;
}

#ifdef NC_ENABLED_SSH_TLS

static int
config_remote_address(const struct lyd_node *node, enum nc_operation parent_op, struct nc_ch_endpt *endpt)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(endpt->dst_addr);
        endpt->dst_addr = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(endpt->dst_addr);
        endpt->dst_addr = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!endpt->dst_addr, 1);
    }

    return 0;
}

static int
config_remote_port(const struct lyd_node *node, enum nc_operation UNUSED(parent_op), struct nc_ch_endpt *endpt)
{
    /* default value => value always present */
    endpt->dst_port = strtoul(lyd_get_value(node), NULL, 10);
    return 0;
}

static int
config_ch_local_address(const struct lyd_node *node, enum nc_operation parent_op, struct nc_ch_endpt *endpt)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(endpt->src_addr);
        endpt->src_addr = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(endpt->src_addr);
        endpt->src_addr = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!endpt->src_addr, 1);
    }

    return 0;
}

static int
config_ch_local_port(const struct lyd_node *node, enum nc_operation parent_op, struct nc_ch_endpt *endpt)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        endpt->src_port = 0;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        endpt->src_port = strtoul(lyd_get_value(node), NULL, 10);
    }

    return 0;
}

static int
config_proxy_server(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_tcp_client_params(const struct lyd_node *node, enum nc_operation parent_op, struct nc_ch_endpt *endpt)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config remote address */
    NC_CHECK_RET(nc_lyd_find_child(node, "remote-address", 1, &n));
    NC_CHECK_RET(config_remote_address(n, op, endpt));

    /* config remote port */
    NC_CHECK_RET(nc_lyd_find_child(node, "remote-port", 1, &n));
    if (n) {
        NC_CHECK_RET(config_remote_port(n, op, endpt));
    }

    /* config local address */
    NC_CHECK_RET(nc_lyd_find_child(node, "local-address", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ch_local_address(n, op, endpt));
    }

    /* config local port */
    NC_CHECK_RET(nc_lyd_find_child(node, "local-port", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ch_local_port(n, op, endpt));
    }

    /* config proxy server */
    NC_CHECK_RET(nc_lyd_find_child(node, "proxy-server", 0, &n));
    if (n) {
        NC_CHECK_RET(config_proxy_server(n, op));
    }

    /* config keepalives */
    NC_CHECK_RET(nc_lyd_find_child(node, "keepalives", 0, &n));
    if (n) {
        NC_CHECK_RET(config_tcp_keepalives(n, op, &endpt->ka));
    }

    return 0;
}

static int
config_ch_endpoint_ssh(const struct lyd_node *node, enum nc_operation parent_op, struct nc_ch_endpt *endpt)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (!endpt->opts.ssh) {
        /* op should not be NC_OP_DELETE if the diff is valid, otherwise this would have already been created */
        endpt->opts.ssh = calloc(1, sizeof *endpt->opts.ssh);
        NC_CHECK_ERRMEM_RET(!endpt->opts.ssh, 1);
        endpt->ti = NC_TI_SSH;
    }

    /* config tcp client parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "tcp-client-parameters", 1, &n));
    NC_CHECK_RET(config_tcp_client_params(n, op, endpt));

    /* config ssh server parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "ssh-server-parameters", 1, &n));
    NC_CHECK_RET(config_ssh_server_params(n, op, endpt->opts.ssh));

    /* config netconf server parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "netconf-server-parameters", 1, &n));
    NC_CHECK_RET(config_ssh_netconf_server_params(n, op));

    if (op == NC_OP_DELETE) {
        free(endpt->opts.ssh);
        endpt->opts.ssh = NULL;
        endpt->ti = NC_TI_NONE;
    }

    return 0;
}

static int
config_ch_endpoint_tls(const struct lyd_node *node, enum nc_operation parent_op, struct nc_ch_endpt *endpt)
{
    enum nc_operation op;
    struct lyd_node *n;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (!endpt->opts.tls) {
        /* op should not be NC_OP_DELETE if the diff is valid, otherwise this would have already been created */
        endpt->opts.tls = calloc(1, sizeof *endpt->opts.tls);
        NC_CHECK_ERRMEM_RET(!endpt->opts.tls, 1);
        endpt->ti = NC_TI_TLS;
    }

    /* config tcp client parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "tcp-client-parameters", 1, &n));
    NC_CHECK_RET(config_tcp_client_params(n, op, endpt));

    /* config tls server parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "tls-server-parameters", 1, &n));
    NC_CHECK_RET(config_tls_server_params(n, op, endpt->opts.tls));

    /* config netconf server parameters */
    NC_CHECK_RET(nc_lyd_find_child(node, "netconf-server-parameters", 1, &n));
    NC_CHECK_RET(config_tls_netconf_server_params(n, op, endpt->opts.tls));

    if (op == NC_OP_DELETE) {
        free(endpt->opts.tls);
        endpt->opts.tls = NULL;
        endpt->ti = NC_TI_NONE;
    }

    return 0;
}

#endif /* NC_ENABLED_SSH_TLS */

static int
config_ch_endpoint_name(const struct lyd_node *node, enum nc_operation op,
        struct nc_ch_endpt *endpt)
{
    if (op == NC_OP_DELETE) {
        free(endpt->name);
        endpt->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(endpt->name);
        endpt->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!endpt->name, 1);
    }

    return 0;
}

static int
config_ch_client_endpoint(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_ch_client *ch_client)
{
    struct lyd_node *n;
    enum nc_operation op;
    const char *name;
    LY_ARRAY_COUNT_TYPE i;
    struct nc_ch_endpt *endpt = NULL;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* get the name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the endpoint we are deleting/modifying */
        LY_ARRAY_FOR(ch_client->ch_endpts, i) {
            if (!strcmp(ch_client->ch_endpts[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(ch_client->ch_endpts));
        endpt = &ch_client->ch_endpts[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new endpoint and init it */
        LY_ARRAY_NEW_RET(LYD_CTX(node), ch_client->ch_endpts, endpt, 1);
        endpt->sock_pending = -1;
    }

    /* config name */
    NC_CHECK_RET(config_ch_endpoint_name(n, op, endpt));

#ifdef NC_ENABLED_SSH_TLS
    struct lyd_node *ssh, *tls;

    /* config ssh/tls choice */
    NC_CHECK_RET(nc_lyd_find_child(node, "ssh", 0, &ssh));
    NC_CHECK_RET(nc_lyd_find_child(node, "tls", 0, &tls));
    if (ssh) {
        NC_CHECK_RET(config_ch_endpoint_ssh(ssh, op, endpt));
    } else {
        assert(tls);
        NC_CHECK_RET(config_ch_endpoint_tls(tls, op, endpt));
    }
#endif /* NC_ENABLED_SSH_TLS */

    /* all children processed, we can now delete the endpoint */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(ch_client->ch_endpts) - 1) {
            ch_client->ch_endpts[i] = ch_client->ch_endpts[LY_ARRAY_COUNT(ch_client->ch_endpts) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(ch_client->ch_endpts);
    }

    return 0;
}

static int
config_ch_client_endpoints(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_ch_client *ch_client)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config all the endpoints */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_ch_client_endpoint(n, op, ch_client));
    }

    return 0;
}

static int
config_ch_conn_type_persistent(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_ch_client *ch_client)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        ch_client->conn_type = NC_CH_CT_NOT_SET;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        ch_client->conn_type = NC_CH_PERSIST;
    }

    return 0;
}

static int
config_ch_periodic_period(const struct lyd_node *node, enum nc_operation UNUSED(parent_op),
        struct nc_ch_client *ch_client)
{
    /* default value => value always present */
    ch_client->period = strtoul(lyd_get_value(node), NULL, 10);
    return 0;
}

static int
config_ch_periodic_anchor_time(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_ch_client *ch_client)
{
    enum nc_operation op;
    struct lyd_value_date_and_time *anchor_time;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        ch_client->anchor_time = 0;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* get the date and time value from the node directly */
        LYD_VALUE_GET(&((struct lyd_node_term *)node)->value, anchor_time);
    }

    return 0;
}

static int
config_ch_periodic_idle_timeout(const struct lyd_node *node, enum nc_operation UNUSED(parent_op),
        struct nc_ch_client *ch_client)
{
    /* default value => value always present */
    ch_client->idle_timeout = strtoul(lyd_get_value(node), NULL, 10);
    return 0;
}

static int
config_ch_conn_type_periodic(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_ch_client *ch_client)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    ch_client->conn_type = NC_CH_PERIOD;

    /* config period */
    NC_CHECK_RET(nc_lyd_find_child(node, "period", 1, &n));
    NC_CHECK_RET(config_ch_periodic_period(n, op, ch_client));

    /* config anchor time */
    NC_CHECK_RET(nc_lyd_find_child(node, "anchor-time", 0, &n));
    if (n) {
        NC_CHECK_RET(config_ch_periodic_anchor_time(n, op, ch_client));
    }

    /* config idle timeout */
    NC_CHECK_RET(nc_lyd_find_child(node, "idle-timeout", 1, &n));
    NC_CHECK_RET(config_ch_periodic_idle_timeout(n, op, ch_client));

    /* all children processed, we can now delete the connection type */
    if (op == NC_OP_DELETE) {
        ch_client->conn_type = NC_CH_CT_NOT_SET;
    }

    return 0;
}

static int
config_ch_client_connection_type(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_ch_client *ch_client)
{
    struct lyd_node *persistent, *periodic;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config persistent / periodic choice,
     * the choice itself is mandatory, but both containers are presence, so need to check explicitly */
    NC_CHECK_RET(nc_lyd_find_child(node, "persistent", 0, &persistent));
    NC_CHECK_RET(nc_lyd_find_child(node, "periodic", 0, &periodic));
    if (persistent) {
        NC_CHECK_RET(config_ch_conn_type_persistent(persistent, op, ch_client));
    } else if (periodic) {
        NC_CHECK_RET(config_ch_conn_type_periodic(periodic, op, ch_client));
    }

    return 0;
}

static int
config_ch_reconnect_start_with(const struct lyd_node *node, enum nc_operation UNUSED(parent_op),
        struct nc_ch_client *ch_client)
{
    const char *start_with;

    /* default value => value always present */
    start_with = lyd_get_value(node);
    assert(start_with);

    if (!strcmp(start_with, "first-listed")) {
        ch_client->start_with = NC_CH_FIRST_LISTED;
    } else if (!strcmp(start_with, "last-connected")) {
        ch_client->start_with = NC_CH_LAST_CONNECTED;
    } else if (!strcmp(start_with, "random-selection")) {
        ch_client->start_with = NC_CH_RANDOM;
    } else {
        ERR(NULL, "Unknown call-home reconnect start-with value \"%s\".", start_with);
        return 1;
    }

    return 0;
}

static int
config_ch_reconnect_max_wait(const struct lyd_node *node, enum nc_operation UNUSED(parent_op),
        struct nc_ch_client *ch_client)
{
    /* default value => value always present */
    ch_client->max_wait = strtoul(lyd_get_value(node), NULL, 10);
    return 0;
}

static int
config_ch_reconnect_max_attempts(const struct lyd_node *node, enum nc_operation UNUSED(parent_op),
        struct nc_ch_client *ch_client)
{
    /* default value => value always present */
    ch_client->max_attempts = strtoul(lyd_get_value(node), NULL, 10);
    return 0;
}

static int
config_ch_client_reconnect_strategy(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_ch_client *ch_client)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config start with */
    NC_CHECK_RET(nc_lyd_find_child(node, "start-with", 1, &n));
    NC_CHECK_RET(config_ch_reconnect_start_with(n, op, ch_client));

    /* config max wait */
    NC_CHECK_RET(nc_lyd_find_child(node, "max-wait", 1, &n));
    NC_CHECK_RET(config_ch_reconnect_max_wait(n, op, ch_client));

    /* config max attempts */
    NC_CHECK_RET(nc_lyd_find_child(node, "max-attempts", 1, &n));
    NC_CHECK_RET(config_ch_reconnect_max_attempts(n, op, ch_client));

    return 0;
}

static int
config_netconf_client(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_server_config *config)
{
    struct lyd_node *n;
    enum nc_operation op;
    const char *name;
    LY_ARRAY_COUNT_TYPE i, j;
    struct nc_ch_client *ch_client = NULL;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* get the name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the client we are deleting/modifying */
        LY_ARRAY_FOR(config->ch_clients, i) {
            if (!strcmp(config->ch_clients[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(config->ch_clients));
        ch_client = &config->ch_clients[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new client */
        LY_ARRAY_NEW_RET(LYD_CTX(node), config->ch_clients, ch_client, 1);
    }

    /* config name */
    NC_CHECK_RET(config_ch_client_name(n, op, ch_client));

    /* config endpoints */
    NC_CHECK_RET(nc_lyd_find_child(node, "endpoints", 1, &n));
    NC_CHECK_RET(config_ch_client_endpoints(n, op, ch_client));

    /* config connection type */
    NC_CHECK_RET(nc_lyd_find_child(node, "connection-type", 1, &n));
    NC_CHECK_RET(config_ch_client_connection_type(n, op, ch_client));

    /* config reconnect strategy */
    NC_CHECK_RET(nc_lyd_find_child(node, "reconnect-strategy", 1, &n));
    NC_CHECK_RET(config_ch_client_reconnect_strategy(n, op, ch_client));

    /* all children processed, we can now delete the client */
    if (op == NC_OP_DELETE) {
        /* CH THREADS DATA RD LOCK */
        NC_CHECK_RET(pthread_rwlock_rdlock(&server_opts.ch_threads_lock), 1);

        /* find the thread data for this CH client, not found <==> CH thread not running */
        LY_ARRAY_FOR(server_opts.ch_threads, j) {
            if (!strcmp(server_opts.ch_threads[j]->client_name, name)) {
                break;
            }
        }

        if (j < LY_ARRAY_COUNT(server_opts.ch_threads)) {
            /* the CH thread is running, notify it to stop */
            pthread_mutex_lock(&server_opts.ch_threads[j]->cond_lock);
            server_opts.ch_threads[j]->thread_running = 0;
            pthread_cond_signal(&server_opts.ch_threads[j]->cond);
            pthread_mutex_unlock(&server_opts.ch_threads[j]->cond_lock);
        }

        /* CH THREADS DATA UNLOCK */
        pthread_rwlock_unlock(&server_opts.ch_threads_lock);

        /* we can use 'i' from above */
        if (i < LY_ARRAY_COUNT(config->ch_clients) - 1) {
            config->ch_clients[i] = config->ch_clients[LY_ARRAY_COUNT(config->ch_clients) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(config->ch_clients);
    }

    return 0;
}

static int
config_call_home(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_server_config *config)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all netconf clients */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_netconf_client(n, op, config));
    }

    return 0;
}

/**
 * @brief Handler for the /ietf-netconf-server:netconf-server configuration subtree.
 *
 * This function, and all the other config_* functions, traverse the tree in a post-order manner.
 * All the children are processed before the parent node.
 * In case of a delete operation, the config handlers of the children are called first,
 * and only when all children are processed, the parent node's handler may free any configuration associated
 * with the given parent node, recursively.
 */
static int
config_netconf_server(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_server_config *config)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure listen */
    NC_CHECK_RET(nc_lyd_find_child(node, "listen", 0, &n));
    if (n) {
        NC_CHECK_RET(config_listen(n, op, config));
    }

    /* configure call-home */
    NC_CHECK_RET(nc_lyd_find_child(node, "call-home", 0, &n));
    if (n) {
        NC_CHECK_RET(config_call_home(n, op, config));
    }

    return 0;
}

/**
 * @brief Find and configure the /ietf-netconf-server:netconf-server subtree.
 *
 * Does nothing if the subtree is not present.
 *
 * @param[in] tree Configuration YANG data tree to search in.
 * @param[in] is_diff Flag indicating if the operation is a diff.
 * @param[in,out] config Server configuration to modify.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_netconf_server(const struct lyd_node *tree, int is_diff, struct nc_server_config *config)
{
    int r, rc = 0;
    uint32_t prev_lo;
    struct lyd_node *subtree;
    enum nc_operation initial_op;

    prev_lo = ly_log_options(0);

    /* try to find the netconf-server subtree */
    r = lyd_find_path(tree, "/ietf-netconf-server:netconf-server", 0, &subtree);
    if (r) {
        if (r == LY_ENOTFOUND) {
            /* netconf-server not present, nothing to configure */
            goto cleanup;
        }
        ERR(NULL, "Unable to find the netconf-server subtree in the YANG data.");
        rc = 1;
        goto cleanup;
    }

    /* configure the netconf-server */
    initial_op = is_diff ? NC_OP_UNKNOWN : NC_OP_CREATE;
    rc = config_netconf_server(subtree, initial_op, config);

cleanup:
    ly_log_options(prev_lo);
    return rc;
}

#ifdef NC_ENABLED_SSH_TLS

/*
 * =====================================================================================
 * ietf-keystore handlers
 * =====================================================================================
 */

static int
config_asymmetric_key_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_asymmetric_key *key)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(key->name);
        key->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(key->name);
        key->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!key->name, 1);
    }

    return 0;
}

static int
config_certificate_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_certificate *cert)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(cert->name);
        cert->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(cert->name);
        cert->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!cert->name, 1);
    }

    return 0;
}

static int
config_certificate_data(const struct lyd_node *node, enum nc_operation parent_op, struct nc_certificate *cert)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(cert->data);
        cert->data = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(cert->data);
        cert->data = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!cert->data, 1);
    }

    return 0;
}

static int
config_certificate_expiration(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_asymmetric_key_cert(const struct lyd_node *node, enum nc_operation parent_op, struct nc_keystore_entry *entry)
{
    struct lyd_node *n;
    enum nc_operation op;
    struct nc_certificate *cert = NULL;
    const char *name;
    LY_ARRAY_COUNT_TYPE i;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the certificate we are deleting */
        LY_ARRAY_FOR(entry->certs, i) {
            if (!strcmp(entry->certs[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(entry->certs));
        cert = &entry->certs[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new certificate */
        LY_ARRAY_NEW_RET(LYD_CTX(node), entry->certs, cert, 1);
    }

    /* config certificate name */
    NC_CHECK_RET(config_certificate_name(n, op, cert));

    /* config certificate data */
    NC_CHECK_RET(nc_lyd_find_child(node, "cert-data", 1, &n));
    NC_CHECK_RET(config_certificate_data(n, op, cert));

    /* config certificate expiration */
    NC_CHECK_RET(nc_lyd_find_child(node, "certificate-expiration", 0, &n));
    if (n) {
        NC_CHECK_RET(config_certificate_expiration(n, op));
    }

    /* all children processed, we can now delete the certificate */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(entry->certs) - 1) {
            entry->certs[i] = entry->certs[LY_ARRAY_COUNT(entry->certs) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(entry->certs);
    }

    return 0;
}

static int
config_asymmetric_key_certs(const struct lyd_node *node, enum nc_operation parent_op, struct nc_keystore_entry *entry)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all certificates */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_asymmetric_key_cert(n, op, entry));
    }

    return 0;
}

static int
config_asymmetric_key(const struct lyd_node *node, enum nc_operation parent_op, struct nc_keystore *keystore)
{
    struct lyd_node *n, *cleartext = NULL, *hidden = NULL, *encrypted = NULL;
    enum nc_operation op;
    const char *name;
    struct nc_keystore_entry *entry = NULL;
    LY_ARRAY_COUNT_TYPE i;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the asymmetric key (keystore entry) we are deleting */
        LY_ARRAY_FOR(keystore->entries, i) {
            if (!strcmp(keystore->entries[i].asym_key.name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(keystore->entries));
        entry = &keystore->entries[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new asymmetric key entry */
        LY_ARRAY_NEW_RET(LYD_CTX(node), keystore->entries, entry, 1);
    }

    /* config asymmetric key name */
    NC_CHECK_RET(config_asymmetric_key_name(n, op, &entry->asym_key));

    /* config asymmetric key public key format */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key-format", 0, &n));
    if (n) {
        NC_CHECK_RET(config_pubkey_format(n, op, &entry->asym_key.pubkey));
    }

    /* config asymmetric key public key */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key", 0, &n));
    if (n) {
        NC_CHECK_RET(config_pubkey_data(n, op, &entry->asym_key.pubkey));
    }

    /* config asymmetric key private key format */
    NC_CHECK_RET(nc_lyd_find_child(node, "private-key-format", 0, &n));
    if (n) {
        NC_CHECK_RET(config_privkey_format(n, op, &entry->asym_key.privkey));
    }

    /* config privkey data, case/choice node => only one can be present */
    NC_CHECK_RET(nc_lyd_find_child(node, "cleartext-private-key", 0, &cleartext));
    NC_CHECK_RET(nc_lyd_find_child(node, "hidden-private-key", 0, &hidden));
    NC_CHECK_RET(nc_lyd_find_child(node, "encrypted-private-key", 0, &encrypted));
    if (cleartext) {
        NC_CHECK_RET(config_cleartext_privkey_data(cleartext, op, &entry->asym_key.privkey));
    } else if (hidden) {
        NC_CHECK_RET(config_hidden_privkey_data(hidden, op));
    } else if (encrypted) {
        NC_CHECK_RET(config_encrypted_privkey_data(encrypted, op));
    }

    /* config asymmetric key certificates */
    NC_CHECK_RET(nc_lyd_find_child(node, "certificates", 1, &n));
    NC_CHECK_RET(config_asymmetric_key_certs(n, op, entry));

    /* config generate csr */
    NC_CHECK_RET(nc_lyd_find_child(node, "generate-csr", 0, &n));
    if (n) {
        NC_CHECK_RET(config_generate_csr(n, op));
    }

    /* all children processed, we can now delete the asymmetric key entry */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(keystore->entries) - 1) {
            keystore->entries[i] = keystore->entries[LY_ARRAY_COUNT(keystore->entries) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(keystore->entries);
    }

    return 0;
}

static int
config_asymmetric_keys(const struct lyd_node *node, enum nc_operation parent_op, struct nc_keystore *keystore)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all asymmetric keys */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_asymmetric_key(n, op, keystore));
    }

    return 0;
}

static int
config_symmetric_keys(const struct lyd_node *node, enum nc_operation UNUSED(parent_op))
{
    CONFIG_LOG_UNSUPPORTED(node);
    return 0;
}

static int
config_keystore(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_config *config)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure asymmetric keys */
    NC_CHECK_RET(nc_lyd_find_child(node, "asymmetric-keys", 0, &n));
    if (n) {
        NC_CHECK_RET(config_asymmetric_keys(n, op, &config->keystore));
    }

    /* configure symmetric keys */
    NC_CHECK_RET(nc_lyd_find_child(node, "symmetric-keys", 0, &n));
    if (n) {
        NC_CHECK_RET(config_symmetric_keys(n, op));
    }

    return 0;
}

/**
 * @brief Find and configure the /ietf-keystore:keystore subtree.
 *
 * Does nothing if the subtree is not present.
 *
 * @param[in] tree Configuration YANG data tree to search in.
 * @param[in] is_diff Flag indicating if the operation is a diff.
 * @param[in,out] config Server configuration to modify.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_keystore(const struct lyd_node *tree, int is_diff, struct nc_server_config *config)
{
    int r, rc = 0;
    uint32_t prev_lo;
    struct lyd_node *subtree;
    enum nc_operation initial_op;

    prev_lo = ly_log_options(0);

    /* try to find the keystore subtree */
    r = lyd_find_path(tree, "/ietf-keystore:keystore", 0, &subtree);
    if (r) {
        if (r == LY_ENOTFOUND) {
            /* keystore not present, nothing to configure */
            goto cleanup;
        }
        ERR(NULL, "Unable to find the keystore subtree in the YANG data.");
        rc = 1;
        goto cleanup;
    }

    /* configure the keystore */
    initial_op = is_diff ? NC_OP_UNKNOWN : NC_OP_CREATE;
    rc = config_keystore(subtree, initial_op, config);

cleanup:
    ly_log_options(prev_lo);
    return rc;
}

/*
 * =====================================================================================
 * ietf-truststore handlers
 * =====================================================================================
 */

static int
config_certificate_bag_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_certificate_bag *bag)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(bag->name);
        bag->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(bag->name);
        bag->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!bag->name, 1);
    }

    return 0;
}

static int
config_certificate_bag_description(const struct lyd_node *node, enum nc_operation parent_op, struct nc_certificate_bag *bag)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(bag->description);
        bag->description = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(bag->description);
        bag->description = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!bag->description, 1);
    }

    return 0;
}

static int
config_certificate_bag_cert(const struct lyd_node *node, enum nc_operation parent_op, struct nc_certificate_bag *bag)
{
    struct lyd_node *n;
    enum nc_operation op;
    struct nc_certificate *cert = NULL;
    const char *name;
    LY_ARRAY_COUNT_TYPE i;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the certificate we are deleting */
        LY_ARRAY_FOR(bag->certs, i) {
            if (!strcmp(bag->certs[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(bag->certs));
        cert = &bag->certs[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new certificate */
        LY_ARRAY_NEW_RET(LYD_CTX(node), bag->certs, cert, 1);
    }

    /* config certificate name */
    NC_CHECK_RET(config_certificate_name(n, op, cert));

    /* config certificate data */
    NC_CHECK_RET(nc_lyd_find_child(node, "cert-data", 1, &n));
    NC_CHECK_RET(config_certificate_data(n, op, cert));

    /* config certificate expiration */
    NC_CHECK_RET(nc_lyd_find_child(node, "certificate-expiration", 0, &n));
    if (n) {
        NC_CHECK_RET(config_certificate_expiration(n, op));
    }

    /* all children processed, we can now delete the certificate */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(bag->certs) - 1) {
            bag->certs[i] = bag->certs[LY_ARRAY_COUNT(bag->certs) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(bag->certs);
    }

    return 0;
}

static int
config_certificate_bag(const struct lyd_node *node, enum nc_operation parent_op, struct nc_truststore *truststore)
{
    struct lyd_node *n;
    enum nc_operation op;
    const char *name;
    struct nc_certificate_bag *bag = NULL;
    LY_ARRAY_COUNT_TYPE i;
    uint32_t j;
    struct ly_set *set = NULL;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the certificate bag we are deleting */
        LY_ARRAY_FOR(truststore->cert_bags, i) {
            if (!strcmp(truststore->cert_bags[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(truststore->cert_bags));
        bag = &truststore->cert_bags[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new certificate bag */
        LY_ARRAY_NEW_RET(LYD_CTX(node), truststore->cert_bags, bag, 1);
    }

    /* config certificate bag name */
    NC_CHECK_RET(config_certificate_bag_name(n, op, bag));

    /* config certificate bag description */
    NC_CHECK_RET(nc_lyd_find_child(node, "description", 0, &n));
    if (n) {
        NC_CHECK_RET(config_certificate_bag_description(n, op, bag));
    }

    /* config certificate bag certificates */
    NC_CHECK_RET(lyd_find_xpath(node, "certificate", &set), 1);
    for (j = 0; j < set->count; ++j) {
        NC_CHECK_GOTO(config_certificate_bag_cert(set->dnodes[j], op, bag), cleanup);
    }

    /* all children processed, we can now delete the certificate bag */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(truststore->cert_bags) - 1) {
            truststore->cert_bags[i] = truststore->cert_bags[LY_ARRAY_COUNT(truststore->cert_bags) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(truststore->cert_bags);
    }

cleanup:
    ly_set_free(set, NULL);
    return 0;
}

static int
config_certificate_bags(const struct lyd_node *node, enum nc_operation parent_op, struct nc_truststore *truststore)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all certificate bags */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_certificate_bag(n, op, truststore));
    }

    return 0;
}

static int
config_public_key_bag_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_public_key_bag *bag)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(bag->name);
        bag->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(bag->name);
        bag->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!bag->name, 1);
    }

    return 0;
}

static int
config_public_key_bag_description(const struct lyd_node *node, enum nc_operation parent_op, struct nc_public_key_bag *bag)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(bag->description);
        bag->description = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(bag->description);
        bag->description = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!bag->description, 1);
    }

    return 0;
}

static int
config_public_key_bag_pubkey_name(const struct lyd_node *node, enum nc_operation parent_op, struct nc_public_key *pubkey)
{
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        free(pubkey->name);
        pubkey->name = NULL;
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        free(pubkey->name);
        pubkey->name = strdup(lyd_get_value(node));
        NC_CHECK_ERRMEM_RET(!pubkey->name, 1);
    }

    return 0;
}

static int
config_public_key_bag_pubkey(const struct lyd_node *node, enum nc_operation parent_op, struct nc_public_key_bag *bag)
{
    struct lyd_node *n;
    enum nc_operation op;
    const char *name;
    struct nc_public_key *pubkey = NULL;
    LY_ARRAY_COUNT_TYPE i;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the public key we are deleting */
        LY_ARRAY_FOR(bag->pubkeys, i) {
            if (!strcmp(bag->pubkeys[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(bag->pubkeys));
        pubkey = &bag->pubkeys[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new public key */
        LY_ARRAY_NEW_RET(LYD_CTX(node), bag->pubkeys, pubkey, 1);
    }

    /* config public key name */
    NC_CHECK_RET(config_public_key_bag_pubkey_name(n, op, pubkey));

    /* config public key format */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key-format", 1, &n));
    NC_CHECK_RET(config_pubkey_format(n, op, pubkey));

    /* config public key data */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key", 1, &n));
    NC_CHECK_RET(config_pubkey_data(n, op, pubkey));

    /* all children processed, we can now delete the public key */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(bag->pubkeys) - 1) {
            bag->pubkeys[i] = bag->pubkeys[LY_ARRAY_COUNT(bag->pubkeys) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(bag->pubkeys);
    }

    return 0;
}

static int
config_public_key_bag(const struct lyd_node *node, enum nc_operation parent_op, struct nc_truststore *truststore)
{
    struct lyd_node *n;
    enum nc_operation op;
    const char *name;
    struct nc_public_key_bag *bag = NULL;
    LY_ARRAY_COUNT_TYPE i;
    struct ly_set *set = NULL;
    uint32_t j;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* name (list key) */
    NC_CHECK_RET(nc_lyd_find_child(node, "name", 1, &n));
    name = lyd_get_value(n);
    assert(name);

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* find the public key bag we are deleting */
        LY_ARRAY_FOR(truststore->pubkey_bags, i) {
            if (!strcmp(truststore->pubkey_bags[i].name, name)) {
                break;
            }
        }
        assert(i < LY_ARRAY_COUNT(truststore->pubkey_bags));
        bag = &truststore->pubkey_bags[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new public key bag */
        LY_ARRAY_NEW_RET(LYD_CTX(node), truststore->pubkey_bags, bag, 1);
    }

    /* config public key bag name */
    NC_CHECK_RET(config_public_key_bag_name(n, op, bag));

    /* config public key bag description */
    NC_CHECK_RET(nc_lyd_find_child(node, "description", 0, &n));
    if (n) {
        NC_CHECK_RET(config_public_key_bag_description(n, op, bag));
    }

    /* config public key bag public keys */
    NC_CHECK_RET(lyd_find_xpath(node, "public-key", &set), 1);
    for (j = 0; j < set->count; ++j) {
        NC_CHECK_GOTO(config_public_key_bag_pubkey(set->dnodes[j], op, bag), cleanup);
    }

    /* all children processed, we can now delete the public key bag */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(truststore->pubkey_bags) - 1) {
            truststore->pubkey_bags[i] = truststore->pubkey_bags[LY_ARRAY_COUNT(truststore->pubkey_bags) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(truststore->pubkey_bags);
    }

cleanup:
    ly_set_free(set, NULL);
    return 0;
}

static int
config_public_key_bags(const struct lyd_node *node, enum nc_operation parent_op, struct nc_truststore *truststore)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure all public key bags */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_public_key_bag(n, op, truststore));
    }

    return 0;
}

static int
config_truststore(const struct lyd_node *node, enum nc_operation parent_op, struct nc_server_config *config)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* configure certificate bags */
    NC_CHECK_RET(nc_lyd_find_child(node, "certificate-bags", 0, &n));
    if (n) {
        NC_CHECK_RET(config_certificate_bags(n, op, &config->truststore));
    }

    /* configure public key bags */
    NC_CHECK_RET(nc_lyd_find_child(node, "public-key-bags", 0, &n));
    if (n) {
        NC_CHECK_RET(config_public_key_bags(n, op, &config->truststore));
    }

    return 0;
}

/**
 * @brief Find and configure the /ietf-truststore:truststore subtree.
 *
 * Does nothing if the subtree is not present.
 *
 * @param[in] tree Configuration YANG data tree to search in.
 * @param[in] is_diff Flag indicating if the operation is a diff.
 * @param[in] config Server configuration to update.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_truststore(const struct lyd_node *tree, int is_diff, struct nc_server_config *config)
{
    int r, rc = 0;
    uint32_t prev_lo;
    struct lyd_node *subtree;
    enum nc_operation initial_op;

    prev_lo = ly_log_options(0);

    /* try to find the truststore subtree */
    r = lyd_find_path(tree, "/ietf-truststore:truststore", 0, &subtree);
    if (r) {
        if (r == LY_ENOTFOUND) {
            /* truststore not present, nothing to configure */
            goto cleanup;
        }
        ERR(NULL, "Unable to find the truststore subtree in the YANG data.");
        rc = 1;
        goto cleanup;
    }

    /* configure the truststore */
    initial_op = is_diff ? NC_OP_UNKNOWN : NC_OP_CREATE;
    rc = config_truststore(subtree, initial_op, config);

cleanup:
    ly_log_options(prev_lo);
    return rc;
}

#endif /* NC_ENABLED_SSH_TLS */

/*
 * =====================================================================================
 * libnetconf2-netconf-server handlers
 * =====================================================================================
 */

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Convert a string representation of certificate expiration time to struct.
 *
 * @note See libnetconf2-netconf-server.yang for the format of the string.
 *
 * @param[in] str String representation of the certificate expiration time.
 * @param[out] cert_exp_time Converted certificate expiration time struct.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_cert_exp_time_from_str(const char *str, struct nc_cert_exp_time *cert_exp_time)
{
    char unit;
    long value;

    unit = str[strlen(str) - 1];
    value = strtol(str, NULL, 10);

    switch (unit) {
    case 'm':
        cert_exp_time->months = value;
        break;
    case 'w':
        cert_exp_time->weeks = value;
        break;
    case 'd':
        cert_exp_time->days = value;
        break;
    case 'h':
        cert_exp_time->hours = value;
        break;
    default:
        ERR(NULL, "Invalid time interval unit '%c' in the certificate expiration time \"%s\".", unit, str);
        return 1;
    }

    return 0;
}

static int
config_cert_exp_notif_anchor(const struct lyd_node *node, enum nc_operation parent_op, struct nc_cert_exp_time *anchor)
{
    enum nc_operation op;
    const char *value;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        memset(anchor, 0, sizeof *anchor);
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        value = lyd_get_value(node);
        assert(value);
        NC_CHECK_RET(nc_server_config_cert_exp_time_from_str(value, anchor));
    }

    return 0;
}

static int
config_cert_exp_notif_period(const struct lyd_node *node, enum nc_operation parent_op, struct nc_cert_exp_time *period)
{
    enum nc_operation op;
    const char *value;

    NC_NODE_GET_OP(node, parent_op, &op);

    if (op == NC_OP_DELETE) {
        memset(period, 0, sizeof *period);
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        value = lyd_get_value(node);
        assert(value);
        NC_CHECK_RET(nc_server_config_cert_exp_time_from_str(value, period));
    }

    return 0;
}

static int
config_cert_exp_notif_interval(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_server_config *config)
{
    struct lyd_node *anchor_node, *period_node;
    enum nc_operation op;
    const char *anchor_str, *period_str;
    uint32_t i;
    struct nc_cert_exp_time anchor = {0}, period = {0};
    struct nc_cert_exp_time_interval *interval = NULL;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* anchor and period (list keys) */
    NC_CHECK_RET(nc_lyd_find_child(node, "anchor", 1, &anchor_node));
    anchor_str = lyd_get_value(anchor_node);
    assert(anchor_str);
    NC_CHECK_RET(nc_lyd_find_child(node, "period", 1, &period_node));
    period_str = lyd_get_value(period_node);
    assert(period_str);

    /* convert anchor and period from str to time interval */
    NC_CHECK_RET(nc_server_config_cert_exp_time_from_str(anchor_str, &anchor));
    NC_CHECK_RET(nc_server_config_cert_exp_time_from_str(period_str, &period));

    if ((op == NC_OP_DELETE) || (op == NC_OP_NONE)) {
        /* get the interval we are deleting/modifying */
        LY_ARRAY_FOR(config->cert_exp_notif_intervals, i) {
            if (!memcmp(&config->cert_exp_notif_intervals[i].anchor, &anchor, sizeof anchor) &&
                    !memcmp(&config->cert_exp_notif_intervals[i].period, &period, sizeof period)) {
                break;
            }
        }

        if (i == LY_ARRAY_COUNT(config->cert_exp_notif_intervals)) {
            ERR(NULL, "Trying to delete a non-existing certificate expiration notification interval.");
            return 1;
        }
        interval = &config->cert_exp_notif_intervals[i];
    } else if (op == NC_OP_CREATE) {
        /* create a new interval */
        LY_ARRAY_NEW_RET(LYD_CTX(node), config->cert_exp_notif_intervals, interval, 1);
    }

    /* config anchor */
    NC_CHECK_RET(config_cert_exp_notif_anchor(anchor_node, op, &interval->anchor));

    /* config period */
    NC_CHECK_RET(config_cert_exp_notif_period(period_node, op, &interval->period));

    /* all children processed, we can now delete the interval */
    if (op == NC_OP_DELETE) {
        if (i < LY_ARRAY_COUNT(config->cert_exp_notif_intervals) - 1) {
            config->cert_exp_notif_intervals[i] =
                    config->cert_exp_notif_intervals[LY_ARRAY_COUNT(config->cert_exp_notif_intervals) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(config->cert_exp_notif_intervals);
    }

    return 0;
}

static int
config_cert_exp_notif_intervals(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_server_config *config)
{
    struct lyd_node *n;
    enum nc_operation op;

    NC_NODE_GET_OP(node, parent_op, &op);

    /* config all intervals */
    LY_LIST_FOR(lyd_child(node), n) {
        NC_CHECK_RET(config_cert_exp_notif_interval(n, op, config));
    }

    return 0;
}

#endif /* NC_ENABLED_SSH_TLS */

static int
config_ignored_hello_module(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_server_config *config)
{
    enum nc_operation op;
    const char *module;
    uint32_t i;
    char **new_ignored_module;

    NC_NODE_GET_OP(node, parent_op, &op);

    module = lyd_get_value(node);
    assert(module);

    if (op == NC_OP_DELETE) {
        /* find the module we are deleting */
        LY_ARRAY_FOR(config->ignored_modules, i) {
            if (!strcmp(config->ignored_modules[i], module)) {
                break;
            }
        }
        if (i == LY_ARRAY_COUNT(config->ignored_modules)) {
            ERR(NULL, "Trying to delete a non-existing ignored-hello-module \"%s\".", module);
            return 1;
        }
        free(config->ignored_modules[i]);
        if (i < LY_ARRAY_COUNT(config->ignored_modules) - 1) {
            config->ignored_modules[i] = config->ignored_modules[LY_ARRAY_COUNT(config->ignored_modules) - 1];
        }
        LY_ARRAY_DECREMENT_FREE(config->ignored_modules);
    } else if ((op == NC_OP_CREATE) || (op == NC_OP_REPLACE)) {
        /* check if the module is not already present */
        LY_ARRAY_FOR(config->ignored_modules, i) {
            if (!strcmp(config->ignored_modules[i], module)) {
                break;
            }
        }
        if (i < LY_ARRAY_COUNT(config->ignored_modules)) {
            ERR(NULL, "Trying to add an already existing ignored-hello-module \"%s\".", module);
            return 1;
        }

        /* add the new module */
        LY_ARRAY_NEW_RET(LYD_CTX(node), config->ignored_modules, new_ignored_module, 1);
        *new_ignored_module = strdup(module);
        NC_CHECK_ERRMEM_RET(!*new_ignored_module, 1);
    }

    return 0;
}

static int
config_ln2_netconf_server(const struct lyd_node *node, enum nc_operation parent_op,
        struct nc_server_config *config)
{
    enum nc_operation op;
    struct ly_set *set = NULL;
    uint32_t i;

    NC_NODE_GET_OP(node, parent_op, &op);

#ifdef NC_ENABLED_SSH_TLS
    struct lyd_node *n;

    /* config certificate-expiration-notif-intervals */
    NC_CHECK_RET(nc_lyd_find_child(node, "certificate-expiration-notif-intervals", 0, &n));
    if (n) {
        NC_CHECK_RET(config_cert_exp_notif_intervals(n, op, config));
    }
#endif /* NC_ENABLED_SSH_TLS */

    /* config all ignored-hello-modules */
    NC_CHECK_RET(lyd_find_xpath(node, "ignored-hello-module", &set), 1);
    for (i = 0; i < set->count; ++i) {
        NC_CHECK_GOTO(config_ignored_hello_module(set->dnodes[i], op, config), cleanup);
    }

cleanup:
    ly_set_free(set, NULL);
    return 0;
}

/**
 * @brief Find and configure the /libnetconf2-netconf-server:ln2-netconf-server subtree.
 *
 * Does nothing if the subtree is not present.
 *
 * @param[in] tree Configuration YANG data tree to search in.
 * @param[in] is_diff Flag indicating if the operation is a diff.
 * @param[in,out] config Server configuration to modify.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_libnetconf2_netconf_server(const struct lyd_node *tree, int is_diff,
        struct nc_server_config *config)
{
    int r, rc = 0;
    uint32_t prev_lo;
    struct lyd_node *subtree;
    enum nc_operation initial_op;

    prev_lo = ly_log_options(0);

    /* try to find the ln2-netconf-server subtree */
    r = lyd_find_path(tree, "/libnetconf2-netconf-server:ln2-netconf-server", 0, &subtree);
    if (r) {
        if (r == LY_ENOTFOUND) {
            /* ln2-netconf-server not present, nothing to configure */
            goto cleanup;
        }
        ERR(NULL, "Unable to find the ln2-netconf-server subtree in the YANG data.");
        rc = 1;
        goto cleanup;
    }

    /* configure the ln2-netconf-server */
    initial_op = is_diff ? NC_OP_UNKNOWN : NC_OP_CREATE;
    rc = config_ln2_netconf_server(subtree, initial_op, config);

cleanup:
    ly_log_options(prev_lo);
    return rc;
}

/**
 * @brief Atomically starts listening on new sockets and reuses existing ones.
 *
 * @param[in,out] old_cfg Old, currently active server configuration.
 * @param[in,out] new_cfg New server configuration currently being applied.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_reconcile_sockets_listen(struct nc_server_config *old_cfg,
        struct nc_server_config *new_cfg)
{
    int rc = 0, found;
    struct nc_endpt *old_endpt, *new_endpt;
    struct nc_bind *new_bind, *old_bind;

    /*
     * == PHASE 1: RECONCILE OLD AND NEW SOCKETS ==
     * Match existing sockets from old_cfg to new_cfg to reuse them,
     * then create new sockets for new binds.
     */

    /* reuse existing sockets from old_cfg */
    LY_ARRAY_FOR(new_cfg->endpts, struct nc_endpt, new_endpt) {
        LY_ARRAY_FOR(new_endpt->binds, struct nc_bind, new_bind) {
            found = 0;
            LY_ARRAY_FOR(old_cfg->endpts, struct nc_endpt, old_endpt) {
                LY_ARRAY_FOR(old_endpt->binds, struct nc_bind, old_bind) {
                    if (!strcmp(new_bind->address, old_bind->address) && (new_bind->port == old_bind->port)) {
                        /* match found, reuse the socket */
                        new_bind->sock = old_bind->sock;
                        found = 1;
                        break;
                    }
                }
                if (found) {
                    /* break the outer loop as well, we already found a match for this bind */
                    break;
                }
            }
        }
    }

    /* create new sockets for new binds */
    LY_ARRAY_FOR(new_cfg->endpts, struct nc_endpt, new_endpt) {
        LY_ARRAY_FOR(new_endpt->binds, struct nc_bind, new_bind) {
            if (new_bind->sock == -1) {
                /* this bind is new, create a listening socket */
                if (nc_server_bind_and_listen(new_endpt, new_bind)) {
                    /* FAILURE! trigger rollback */
                    rc = 1;
                    goto rollback;
                }
            }
        }
    }

    /*
     * == PHASE 2: COMMIT CHANGES (WRITE TO old_cfg) ==
     * new_cfg is now fully valid. We can safely modify old_cfg to prevent
     * reused sockets from being closed by the caller.
     */
    LY_ARRAY_FOR(old_cfg->endpts, struct nc_endpt, old_endpt) {
        LY_ARRAY_FOR(old_endpt->binds, struct nc_bind, old_bind) {
            found = 0;
            if (old_bind->sock == -1) {
                /* already handled or was never active */
                continue;
            }

            /* check if this old_bind's socket was reused in the new_cfg */
            LY_ARRAY_FOR(new_cfg->endpts, struct nc_endpt, new_endpt) {
                LY_ARRAY_FOR(new_endpt->binds, struct nc_bind, new_bind) {
                    if (old_bind->sock == new_bind->sock) {
                        /* match found, invalidate the socket in the old config (dont want to close it) */
                        old_bind->sock = -1;
                        found = 1;
                        break;
                    }
                }
                if (found) {
                    /* break the outer loop as well, we already found a match for this bind */
                    break;
                }
            }
        }
    }

    return 0;

rollback:
    /*
     * == ROLLBACK LOGIC ==
     * An error occurred. We do not want to close the reused sockets, so we can roll back to old_cfg.
     * So we invalidate all reused sockets in new_cfg, the rest will be closed by the caller later.
     */
    LY_ARRAY_FOR(new_cfg->endpts, struct nc_endpt, new_endpt) {
        LY_ARRAY_FOR(new_endpt->binds, struct nc_bind, new_bind) {
            found = 0;
            if (new_bind->sock == -1) {
                /* this bind was never assigned a socket */
                continue;
            }

            /* was this socket reused from the old config? */
            LY_ARRAY_FOR(old_cfg->endpts, struct nc_endpt, old_endpt) {
                LY_ARRAY_FOR(old_endpt->binds, struct nc_bind, old_bind) {
                    if (new_bind->sock == old_bind->sock) {
                        /* match found, invalidate the socket in the new config */
                        new_bind->sock = -1;
                        found = 1;
                        break;
                    }
                }
                if (found) {
                    /* break the outer loop as well, we already found a match for this bind */
                    break;
                }
            }
        }
    }

    return rc;
}

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Atomically dispatch new Call Home clients and reuse existing ones.
 *
 * @param[in,out] old_cfg Old, currently active server configuration.
 * @param[in,out] new_cfg New server configuration currently being applied.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_reconcile_chclients_dispatch(struct nc_server_config *old_cfg,
        struct nc_server_config *new_cfg)
{
    int rc = 0;
    struct nc_ch_client *old_ch_client, *new_ch_client;
    struct nc_server_ch_thread_arg **ch_thread_arg;
    int found;
    LY_ARRAY_COUNT_TYPE i;
    char **started_clients = NULL, **client_name = NULL;

    if (!server_opts.ch_dispatch_data.acquire_ctx_cb || !server_opts.ch_dispatch_data.release_ctx_cb ||
            !server_opts.ch_dispatch_data.new_session_cb) {
        /* Call Home dispatch callbacks not set, nothing to do */
        return 0;
    }

    /*
     * == PHASE 1: START NEW CLIENTS ==
     * Start clients present in new_cfg that are not already running.
     * Track successfully started clients for potential rollback.
     */
    LY_ARRAY_FOR(new_cfg->ch_clients, struct nc_ch_client, new_ch_client) {
        found = 0;

        /* CH THREADS LOCK (reading server_opts.ch_threads) */
        pthread_rwlock_rdlock(&server_opts.ch_threads_lock);

        LY_ARRAY_FOR(server_opts.ch_threads, struct nc_server_ch_thread_arg *, ch_thread_arg) {
            if (!strcmp(new_ch_client->name, (*ch_thread_arg)->client_name)) {
                /* already running, do not start again */
                found = 1;
                break;
            }
        }

        /* CH THREADS UNLOCK */
        pthread_rwlock_unlock(&server_opts.ch_threads_lock);

        if (!found) {
            /* this is a new Call Home client, dispatch it */
            rc = _nc_connect_ch_client_dispatch(new_ch_client, server_opts.ch_dispatch_data.acquire_ctx_cb,
                    server_opts.ch_dispatch_data.release_ctx_cb, server_opts.ch_dispatch_data.ctx_cb_data,
                    server_opts.ch_dispatch_data.new_session_cb, server_opts.ch_dispatch_data.new_session_cb_data);
            if (rc) {
                /* FAILURE! trigger rollback */
                goto rollback;
            }

            /* successfully started, track it for potential rollback */
            LY_ARRAY_NEW_GOTO(NULL, started_clients, client_name, rc, rollback);
            *client_name = strdup(new_ch_client->name);
            NC_CHECK_ERRMEM_GOTO(!*client_name, rc = 1, rollback);

            /* ownership transferred to array */
            client_name = NULL;
        }
    }

    /*
     * == PHASE 2: STOP DELETED CLIENTS (COMMIT) ==
     * All new clients started successfully. Now stop old clients
     * that are not present in the new configuration.
     */
    LY_ARRAY_FOR(old_cfg->ch_clients, struct nc_ch_client, old_ch_client) {
        found = 0;
        LY_ARRAY_FOR(new_cfg->ch_clients, struct nc_ch_client, new_ch_client) {
            if (!strcmp(old_ch_client->name, new_ch_client->name)) {
                found = 1;
                break;
            }
        }

        if (!found) {
            /* this Call Home client was deleted, notify it to stop */
            ch_thread_arg = NULL;

            /* CH THREADS LOCK (reading server_opts.ch_threads) */
            pthread_rwlock_rdlock(&server_opts.ch_threads_lock);
            LY_ARRAY_FOR(server_opts.ch_threads, struct nc_server_ch_thread_arg *, ch_thread_arg) {
                if (!strcmp(old_ch_client->name, (*ch_thread_arg)->client_name)) {
                    /* notify the thread to stop */
                    pthread_mutex_lock(&(*ch_thread_arg)->cond_lock);
                    (*ch_thread_arg)->thread_running = 0;
                    pthread_cond_signal(&(*ch_thread_arg)->cond);
                    pthread_mutex_unlock(&(*ch_thread_arg)->cond_lock);
                    break;
                }
            }
            /* CH THREADS UNLOCK */
            pthread_rwlock_unlock(&server_opts.ch_threads_lock);
            /* Note: if ch_thread_arg is NULL here, the thread wasn't running. That's fine. */
        }
    }

    /* success */
    rc = 0;
    goto cleanup;

rollback:
    /*
     * == ROLLBACK LOGIC ==
     * An error occurred during PHASE 1. Stop any new threads we *just* started
     * to return to the pre-call state.
     */
    LY_ARRAY_FOR(started_clients, i) {
        ch_thread_arg = NULL;

        /* CH THREADS LOCK (reading server_opts.ch_threads) */
        pthread_rwlock_rdlock(&server_opts.ch_threads_lock);
        LY_ARRAY_FOR(server_opts.ch_threads, struct nc_server_ch_thread_arg *, ch_thread_arg) {
            if (!strcmp(started_clients[i], (*ch_thread_arg)->client_name)) {
                /* notify the newly started thread to stop */
                pthread_mutex_lock(&(*ch_thread_arg)->cond_lock);
                (*ch_thread_arg)->thread_running = 0;
                pthread_cond_signal(&(*ch_thread_arg)->cond);
                pthread_mutex_unlock(&(*ch_thread_arg)->cond_lock);
                break;
            }
        }
        /* CH THREADS UNLOCK */
        pthread_rwlock_unlock(&server_opts.ch_threads_lock);
    }
    /* rc is already set to non-zero from the failure point */

cleanup:
    /* free the tracking list and its contents */
    LY_ARRAY_FOR(started_clients, i) {
        free(started_clients[i]);
    }
    LY_ARRAY_FREE(started_clients);
    return rc;
}

/**
 * @brief Create a deep copy of the SSH server options.
 *
 * @param[in] src Source SSH server options to copy from.
 * @param[out] dst SSH server options copy.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_ssh_dup(const struct nc_server_ssh_opts *src, struct nc_server_ssh_opts **dst)
{
    int rc = 0;
    uint32_t i, j;
    const struct nc_hostkey *src_hostkey;
    struct nc_hostkey *dst_hostkey;
    const struct nc_auth_client *src_auth_client;
    struct nc_auth_client *dst_auth_client;

    *dst = calloc(1, sizeof **dst);
    NC_CHECK_ERRMEM_RET(!*dst, 1);

    /* dup host keys */
    LN2_LY_ARRAY_CREATE_GOTO_WRAP((*dst)->hostkeys, LY_ARRAY_COUNT(src->hostkeys), rc, cleanup);
    LY_ARRAY_FOR(src->hostkeys, i) {
        src_hostkey = &src->hostkeys[i];
        dst_hostkey = &(*dst)->hostkeys[i];

        dst_hostkey->name = strdup(src_hostkey->name);
        NC_CHECK_ERRMEM_GOTO(!dst_hostkey->name, rc = 1, cleanup);

        dst_hostkey->store = src_hostkey->store;
        if (src_hostkey->store == NC_STORE_LOCAL) {
            if (src_hostkey->key.name) {
                /* hostkey's key name is optional */
                dst_hostkey->key.name = strdup(src_hostkey->key.name);
                NC_CHECK_ERRMEM_GOTO(!dst_hostkey->key.name, rc = 1, cleanup);
            }

            dst_hostkey->key.privkey.type = src_hostkey->key.privkey.type;
            dst_hostkey->key.privkey.data = strdup(src_hostkey->key.privkey.data);
            NC_CHECK_ERRMEM_GOTO(!dst_hostkey->key.privkey.data, rc = 1, cleanup);

            dst_hostkey->key.pubkey.type = src_hostkey->key.pubkey.type;
            if (src_hostkey->key.pubkey.data) {
                dst_hostkey->key.pubkey.data = strdup(src_hostkey->key.pubkey.data);
                NC_CHECK_ERRMEM_GOTO(!dst_hostkey->key.pubkey.data, rc = 1, cleanup);
            }
        } else {
            dst_hostkey->ks_ref = strdup(src_hostkey->ks_ref);
            NC_CHECK_ERRMEM_GOTO(!dst_hostkey->ks_ref, rc = 1, cleanup);
        }

        LY_ARRAY_INCREMENT((*dst)->hostkeys);
    }

    /* dup auth clients */
    LN2_LY_ARRAY_CREATE_GOTO_WRAP((*dst)->auth_clients, LY_ARRAY_COUNT(src->auth_clients), rc, cleanup);
    LY_ARRAY_FOR(src->auth_clients, i) {
        src_auth_client = &src->auth_clients[i];
        dst_auth_client = &(*dst)->auth_clients[i];

        dst_auth_client->username = strdup(src_auth_client->username);
        NC_CHECK_ERRMEM_GOTO(!dst_auth_client->username, rc = 1, cleanup);

        dst_auth_client->pubkey_store = src_auth_client->pubkey_store;
        if (src_auth_client->pubkey_store == NC_STORE_LOCAL) {
            LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst_auth_client->pubkeys,
                    LY_ARRAY_COUNT(src_auth_client->pubkeys), rc, cleanup);
            LY_ARRAY_FOR(src_auth_client->pubkeys, j) {
                dst_auth_client->pubkeys[j].name = strdup(src_auth_client->pubkeys[j].name);
                NC_CHECK_ERRMEM_GOTO(!dst_auth_client->pubkeys[j].name, rc = 1, cleanup);
                dst_auth_client->pubkeys[j].type = src_auth_client->pubkeys[j].type;
                dst_auth_client->pubkeys[j].data = strdup(src_auth_client->pubkeys[j].data);
                NC_CHECK_ERRMEM_GOTO(!dst_auth_client->pubkeys[j].data, rc = 1, cleanup);
                LY_ARRAY_INCREMENT(dst_auth_client->pubkeys);
            }
        } else if (src_auth_client->pubkey_store == NC_STORE_TRUSTSTORE) {
            dst_auth_client->ts_ref = strdup(src_auth_client->ts_ref);
            NC_CHECK_ERRMEM_GOTO(!dst_auth_client->ts_ref, rc = 1, cleanup);
        }

        if (src_auth_client->password) {
            dst_auth_client->password = strdup(src_auth_client->password);
            NC_CHECK_ERRMEM_GOTO(!dst_auth_client->password, rc = 1, cleanup);
        }
        dst_auth_client->password_last_modified = src_auth_client->password_last_modified;
        dst_auth_client->kbdint_method = src_auth_client->kbdint_method;
        dst_auth_client->none_enabled = src_auth_client->none_enabled;

        LY_ARRAY_INCREMENT((*dst)->auth_clients);
    }

    if (src->referenced_endpt_name) {
        (*dst)->referenced_endpt_name = strdup(src->referenced_endpt_name);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->referenced_endpt_name, rc = 1, cleanup);
    }

    if (src->hostkey_algs) {
        (*dst)->hostkey_algs = strdup(src->hostkey_algs);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->hostkey_algs, rc = 1, cleanup);
    }
    if (src->encryption_algs) {
        (*dst)->encryption_algs = strdup(src->encryption_algs);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->encryption_algs, rc = 1, cleanup);
    }
    if (src->kex_algs) {
        (*dst)->kex_algs = strdup(src->kex_algs);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->kex_algs, rc = 1, cleanup);
    }
    if (src->mac_algs) {
        (*dst)->mac_algs = strdup(src->mac_algs);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->mac_algs, rc = 1, cleanup);
    }

    if (src->banner) {
        (*dst)->banner = strdup(src->banner);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->banner, rc = 1, cleanup);
    }

    (*dst)->auth_timeout = src->auth_timeout;

cleanup:
    if (rc) {
        nc_server_config_ssh_opts_free(*dst);
        *dst = NULL;
    }
    return rc;
}

/**
 * @brief Create a deep copy of the TLS server options.
 *
 * @param[in] src Source TLS server options to copy from.
 * @param[out] dst TLS server options copy.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_tls_dup(const struct nc_server_tls_opts *src, struct nc_server_tls_opts **dst)
{
    int rc = 0;
    uint32_t i;
    const struct nc_server_tls_client_auth *src_ca;
    struct nc_server_tls_client_auth *dst_ca;
    const struct nc_ctn *src_ctn;
    struct nc_ctn *dst_ctn, *prev_ctn;

    *dst = calloc(1, sizeof **dst);
    NC_CHECK_ERRMEM_RET(!*dst, 1);

    (*dst)->cert_store = src->cert_store;
    if (src->cert_store == NC_STORE_LOCAL) {
        (*dst)->local.key.privkey.type = src->local.key.privkey.type;
        (*dst)->local.key.privkey.data = strdup(src->local.key.privkey.data);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->local.key.privkey.data, rc = 1, cleanup);
        (*dst)->local.key.pubkey.type = src->local.key.pubkey.type;
        (*dst)->local.key.pubkey.data = strdup(src->local.key.pubkey.data);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->local.key.pubkey.data, rc = 1, cleanup);
        (*dst)->local.cert.data = strdup(src->local.cert.data);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->local.cert.data, rc = 1, cleanup);
    } else {
        (*dst)->keystore.asym_key_ref = strdup(src->keystore.asym_key_ref);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->keystore.asym_key_ref, rc = 1, cleanup);
        (*dst)->keystore.cert_ref = strdup(src->keystore.cert_ref);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->keystore.cert_ref, rc = 1, cleanup);
    }

    /* dup client auths */
    src_ca = &src->client_auth;
    dst_ca = &(*dst)->client_auth;

    dst_ca->ca_certs_store = src_ca->ca_certs_store;
    if (src_ca->ca_certs_store == NC_STORE_LOCAL) {
        LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst_ca->ca_certs, LY_ARRAY_COUNT(src_ca->ca_certs), rc, cleanup);
        LY_ARRAY_FOR(src_ca->ca_certs, i) {
            dst_ca->ca_certs[i].name = strdup(src_ca->ca_certs[i].name);
            NC_CHECK_ERRMEM_GOTO(!dst_ca->ca_certs[i].name, rc = 1, cleanup);
            dst_ca->ca_certs[i].data = strdup(src_ca->ca_certs[i].data);
            NC_CHECK_ERRMEM_GOTO(!dst_ca->ca_certs[i].data, rc = 1, cleanup);
            LY_ARRAY_INCREMENT(dst_ca->ca_certs);
        }
    } else {
        dst_ca->ca_cert_bag_ts_ref = strdup(src_ca->ca_cert_bag_ts_ref);
        NC_CHECK_ERRMEM_GOTO(!dst_ca->ca_cert_bag_ts_ref, rc = 1, cleanup);
    }

    dst_ca->ee_certs_store = src_ca->ee_certs_store;
    if (src_ca->ee_certs_store == NC_STORE_LOCAL) {
        LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst_ca->ee_certs, LY_ARRAY_COUNT(src_ca->ee_certs), rc, cleanup);
        LY_ARRAY_FOR(src_ca->ee_certs, i) {
            dst_ca->ee_certs[i].name = strdup(src_ca->ee_certs[i].name);
            NC_CHECK_ERRMEM_GOTO(!dst_ca->ee_certs[i].name, rc = 1, cleanup);
            dst_ca->ee_certs[i].data = strdup(src_ca->ee_certs[i].data);
            NC_CHECK_ERRMEM_GOTO(!dst_ca->ee_certs[i].data, rc = 1, cleanup);
            LY_ARRAY_INCREMENT(dst_ca->ee_certs);
        }
    } else {
        dst_ca->ee_cert_bag_ts_ref = strdup(src_ca->ee_cert_bag_ts_ref);
        NC_CHECK_ERRMEM_GOTO(!dst_ca->ee_cert_bag_ts_ref, rc = 1, cleanup);
    }

    /* dup cert to name entries (linked list) */
    src_ctn = src->ctn;
    prev_ctn = NULL;
    while (src_ctn) {
        dst_ctn = calloc(1, sizeof *dst_ctn);
        NC_CHECK_ERRMEM_GOTO(!dst_ctn, rc = 1, cleanup);

        dst_ctn->id = src_ctn->id;
        if (src_ctn->fingerprint) {
            dst_ctn->fingerprint = strdup(src_ctn->fingerprint);
            NC_CHECK_ERRMEM_GOTO(!dst_ctn->fingerprint, rc = 1, cleanup);
        }
        dst_ctn->map_type = src_ctn->map_type;
        if (src_ctn->name) {
            dst_ctn->name = strdup(src_ctn->name);
            NC_CHECK_ERRMEM_GOTO(!dst_ctn->name, rc = 1, cleanup);
        }

        if (prev_ctn) {
            prev_ctn->next = dst_ctn;
        } else {
            (*dst)->ctn = dst_ctn;
        }

        prev_ctn = dst_ctn;
        src_ctn = src_ctn->next;
    }

    if (src->referenced_endpt_name) {
        (*dst)->referenced_endpt_name = strdup(src->referenced_endpt_name);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->referenced_endpt_name, rc = 1, cleanup);
    }

    (*dst)->min_version = src->min_version;
    (*dst)->max_version = src->max_version;

    if (src->cipher_suites) {
        (*dst)->cipher_suites = strdup(src->cipher_suites);
        NC_CHECK_ERRMEM_GOTO(!(*dst)->cipher_suites, rc = 1, cleanup);
    }

cleanup:
    if (rc) {
        nc_server_config_tls_opts_free(*dst);
        *dst = NULL;
    }
    return rc;
}

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Create a deep copy of the UNIX server options.
 *
 * @param[in] src Source UNIX server options to copy from.
 * @param[out] dst UNIX server options copy.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_unix_dup(const struct nc_server_unix_opts *src, struct nc_server_unix_opts **dst)
{
    int rc = 0;
    uint32_t i, j;
    const struct nc_server_unix_user_mapping *src_um;
    struct nc_server_unix_user_mapping *dst_um;

    *dst = calloc(1, sizeof **dst);
    NC_CHECK_ERRMEM_RET(!*dst, 1);

    (*dst)->mode = src->mode;
    (*dst)->uid = src->uid;
    (*dst)->gid = src->gid;

    LN2_LY_ARRAY_CREATE_GOTO_WRAP((*dst)->user_mappings, LY_ARRAY_COUNT(src->user_mappings), rc, cleanup);
    LY_ARRAY_FOR(src->user_mappings, i) {
        src_um = &src->user_mappings[i];
        dst_um = &(*dst)->user_mappings[i];

        dst_um->system_user = strdup(src_um->system_user);
        NC_CHECK_ERRMEM_GOTO(!dst_um->system_user, rc = 1, cleanup);

        LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst_um->allowed_users, LY_ARRAY_COUNT(src_um->allowed_users), rc, cleanup);
        LY_ARRAY_FOR(src_um->allowed_users, j) {
            dst_um->allowed_users[j] = strdup(src_um->allowed_users[j]);
            NC_CHECK_ERRMEM_GOTO(!dst_um->allowed_users[j], rc = 1, cleanup);
            LY_ARRAY_INCREMENT(dst_um->allowed_users);
        }
        LY_ARRAY_INCREMENT((*dst)->user_mappings);
    }

cleanup:
    if (rc) {
        nc_server_config_unix_opts_free(*dst);
        *dst = NULL;
    }
    return rc;
}

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Create a deep copy of the keystore.
 *
 * @param[in] src Source keystore to copy from.
 * @param[out] dst Keystore copy.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_keystore_dup(const struct nc_keystore *src, struct nc_keystore *dst)
{
    int rc = 0;
    uint32_t i, j;
    const struct nc_keystore_entry *src_entry;
    struct nc_keystore_entry *dst_entry;
    const struct nc_certificate *src_cert;
    struct nc_certificate *dst_cert;

    LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst->entries, LY_ARRAY_COUNT(src->entries), rc, cleanup);
    LY_ARRAY_FOR(src->entries, i) {
        src_entry = &src->entries[i];
        dst_entry = &dst->entries[i];

        dst_entry->asym_key.name = strdup(src_entry->asym_key.name);
        NC_CHECK_ERRMEM_GOTO(!dst_entry->asym_key.name, rc = 1, cleanup);

        dst_entry->asym_key.privkey.type = src_entry->asym_key.privkey.type;
        if (src_entry->asym_key.privkey.data) {
            dst_entry->asym_key.privkey.data = strdup(src_entry->asym_key.privkey.data);
            NC_CHECK_ERRMEM_GOTO(!dst_entry->asym_key.privkey.data, rc = 1, cleanup);
        }

        dst_entry->asym_key.pubkey.type = src_entry->asym_key.pubkey.type;
        if (src_entry->asym_key.pubkey.data) {
            dst_entry->asym_key.pubkey.data = strdup(src_entry->asym_key.pubkey.data);
            NC_CHECK_ERRMEM_GOTO(!dst_entry->asym_key.pubkey.data, rc = 1, cleanup);
        }

        LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst_entry->certs, LY_ARRAY_COUNT(src_entry->certs), rc, cleanup);
        LY_ARRAY_FOR(src_entry->certs, j) {
            src_cert = &src_entry->certs[j];
            dst_cert = &dst_entry->certs[j];

            dst_cert->name = strdup(src_cert->name);
            NC_CHECK_ERRMEM_GOTO(!dst_cert->name, rc = 1, cleanup);

            if (src_cert->data) {
                dst_cert->data = strdup(src_cert->data);
                NC_CHECK_ERRMEM_GOTO(!dst_cert->data, rc = 1, cleanup);
            }

            LY_ARRAY_INCREMENT(dst_entry->certs);
        }

        LY_ARRAY_INCREMENT(dst->entries);
    }

cleanup:
    if (rc) {
        nc_server_config_keystore_free(dst);
    }
    return rc;
}

/**
 * @brief Create a deep copy of the truststore.
 *
 * @param[in] src Source truststore to copy from.
 * @param[out] dst Truststore copy.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_truststore_dup(const struct nc_truststore *src, struct nc_truststore *dst)
{
    int rc = 0;
    LY_ARRAY_COUNT_TYPE i, j;
    const struct nc_certificate_bag *src_cbag;
    struct nc_certificate_bag *dst_cbag;
    const struct nc_certificate *src_cert;
    struct nc_certificate *dst_cert;
    const struct nc_public_key_bag *src_pkbag;
    struct nc_public_key_bag *dst_pkbag;
    const struct nc_public_key *src_pk;
    struct nc_public_key *dst_pk;

    /* copy certificate bags */
    LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst->cert_bags, LY_ARRAY_COUNT(src->cert_bags), rc, cleanup);
    LY_ARRAY_FOR(src->cert_bags, i) {
        src_cbag = &src->cert_bags[i];
        dst_cbag = &dst->cert_bags[i];

        dst_cbag->name = strdup(src_cbag->name);
        NC_CHECK_ERRMEM_GOTO(!dst_cbag->name, rc = 1, cleanup);

        if (src_cbag->description) {
            dst_cbag->description = strdup(src_cbag->description);
            NC_CHECK_ERRMEM_GOTO(!dst_cbag->description, rc = 1, cleanup);
        }

        LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst_cbag->certs, LY_ARRAY_COUNT(src_cbag->certs), rc, cleanup);
        LY_ARRAY_FOR(src_cbag->certs, j) {
            src_cert = &src_cbag->certs[j];
            dst_cert = &dst_cbag->certs[j];

            dst_cert->name = strdup(src_cert->name);
            NC_CHECK_ERRMEM_GOTO(!dst_cert->name, rc = 1, cleanup);

            if (src_cert->data) {
                dst_cert->data = strdup(src_cert->data);
                NC_CHECK_ERRMEM_GOTO(!dst_cert->data, rc = 1, cleanup);
            }

            LY_ARRAY_INCREMENT(dst_cbag->certs);
        }

        LY_ARRAY_INCREMENT(dst->cert_bags);
    }

    /* copy public key bags */
    LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst->pubkey_bags, LY_ARRAY_COUNT(src->pubkey_bags), rc, cleanup);
    LY_ARRAY_FOR(src->pubkey_bags, i) {
        src_pkbag = &src->pubkey_bags[i];
        dst_pkbag = &dst->pubkey_bags[i];

        dst_pkbag->name = strdup(src_pkbag->name);
        NC_CHECK_ERRMEM_GOTO(!dst_pkbag->name, rc = 1, cleanup);

        if (src_pkbag->description) {
            dst_pkbag->description = strdup(src_pkbag->description);
            NC_CHECK_ERRMEM_GOTO(!dst_pkbag->description, rc = 1, cleanup);
        }

        LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst_pkbag->pubkeys, LY_ARRAY_COUNT(src_pkbag->pubkeys), rc, cleanup);
        LY_ARRAY_FOR(src_pkbag->pubkeys, j) {
            src_pk = &src_pkbag->pubkeys[j];
            dst_pk = &dst_pkbag->pubkeys[j];

            dst_pk->name = strdup(src_pk->name);
            NC_CHECK_ERRMEM_GOTO(!dst_pk->name, rc = 1, cleanup);
            dst_pk->type = src_pk->type;
            if (src_pk->data) {
                dst_pk->data = strdup(src_pk->data);
                NC_CHECK_ERRMEM_GOTO(!dst_pk->data, rc = 1, cleanup);
            }

            LY_ARRAY_INCREMENT(dst_pkbag->pubkeys);
        }

        LY_ARRAY_INCREMENT(dst->pubkey_bags);
    }

cleanup:
    if (rc) {
        nc_server_config_truststore_free(dst);
    }
    return rc;
}

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Create a deep copy of the server configuration.
 *
 * @param[in] src Source server configuration to copy from.
 * @param[out] dst Server configuration copy.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_dup(const struct nc_server_config *src, struct nc_server_config *dst)
{
    int rc = 0;
    uint32_t i, j;
    const struct nc_endpt *src_endpt;
    struct nc_endpt *dst_endpt;
    const struct nc_ch_client *src_ch_client;
    struct nc_ch_client *dst_ch_client;
    const struct nc_ch_endpt *src_ch_endpt;
    struct nc_ch_endpt *dst_ch_endpt;

    dst->idle_timeout = src->idle_timeout;
    LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst->ignored_modules, LY_ARRAY_COUNT(src->ignored_modules), rc, cleanup);
    LY_ARRAY_FOR(src->ignored_modules, i) {
        dst->ignored_modules[i] = strdup(src->ignored_modules[i]);
        NC_CHECK_ERRMEM_GOTO(!dst->ignored_modules[i], rc = 1, cleanup);
        LY_ARRAY_INCREMENT(dst->ignored_modules);
    }

    /* endpoints */
    LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst->endpts, LY_ARRAY_COUNT(src->endpts), rc, cleanup);
    LY_ARRAY_FOR(src->endpts, i) {
        src_endpt = &src->endpts[i];
        dst_endpt = &dst->endpts[i];

        dst_endpt->name = strdup(src_endpt->name);
        NC_CHECK_ERRMEM_GOTO(!dst_endpt->name, rc = 1, cleanup);

        /* binds */
        LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst_endpt->binds, LY_ARRAY_COUNT(src_endpt->binds), rc, cleanup);
        LY_ARRAY_FOR(src_endpt->binds, j) {
            dst_endpt->binds[j].address = strdup(src_endpt->binds[j].address);
            NC_CHECK_ERRMEM_GOTO(!dst_endpt->binds[j].address, rc = 1, cleanup);
            dst_endpt->binds[j].port = src_endpt->binds[j].port;

            /* mark the socket as uninitialized, it will be reassigned in ::nc_server_config_reconcile_sockets_listen() */
            dst_endpt->binds[j].sock = -1;
            LY_ARRAY_INCREMENT(dst_endpt->binds);
        }
        pthread_mutex_init(&dst_endpt->bind_lock, NULL);

        dst_endpt->ka = src_endpt->ka;

        dst_endpt->ti = src_endpt->ti;
        switch (src_endpt->ti) {
#ifdef NC_ENABLED_SSH_TLS
        case NC_TI_SSH:
            NC_CHECK_ERR_GOTO(rc = nc_server_config_ssh_dup(src_endpt->opts.ssh, &dst_endpt->opts.ssh),
                    ERR(NULL, "Duplicating SSH transport information failed."), cleanup);
            break;
        case NC_TI_TLS:
            NC_CHECK_ERR_GOTO(rc = nc_server_config_tls_dup(src_endpt->opts.tls, &dst_endpt->opts.tls),
                    ERR(NULL, "Duplicating TLS transport information failed."), cleanup);
            break;
#endif /* NC_ENABLED_SSH_TLS */
        case NC_TI_UNIX:
            NC_CHECK_ERR_GOTO(rc = nc_server_config_unix_dup(src_endpt->opts.unix, &dst_endpt->opts.unix),
                    ERR(NULL, "Duplicating UNIX transport information failed."), cleanup);
            break;
        default:
            break;
        }

        LY_ARRAY_INCREMENT(dst->endpts);
    }

    /* call-home clients */
    LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst->ch_clients, LY_ARRAY_COUNT(src->ch_clients), rc, cleanup);
    LY_ARRAY_FOR(src->ch_clients, i) {
        src_ch_client = &src->ch_clients[i];
        dst_ch_client = &dst->ch_clients[i];

        dst_ch_client->name = strdup(src_ch_client->name);
        NC_CHECK_ERRMEM_GOTO(!dst_ch_client->name, rc = 1, cleanup);

        /* ch endpoints */
        LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst_ch_client->ch_endpts,
                LY_ARRAY_COUNT(src_ch_client->ch_endpts), rc, cleanup);
        LY_ARRAY_FOR(src_ch_client->ch_endpts, j) {
            src_ch_endpt = &src_ch_client->ch_endpts[j];
            dst_ch_endpt = &dst_ch_client->ch_endpts[j];

            dst_ch_endpt->name = strdup(src_ch_endpt->name);
            NC_CHECK_ERRMEM_GOTO(!dst_ch_endpt->name, rc = 1, cleanup);

            if (src_ch_endpt->src_addr) {
                dst_ch_endpt->src_addr = strdup(src_ch_endpt->src_addr);
                NC_CHECK_ERRMEM_GOTO(!dst_ch_endpt->src_addr, rc = 1, cleanup);
            }
            dst_ch_endpt->src_port = src_ch_endpt->src_port;

            if (src_ch_endpt->dst_addr) {
                dst_ch_endpt->dst_addr = strdup(src_ch_endpt->dst_addr);
                NC_CHECK_ERRMEM_GOTO(!dst_ch_endpt->dst_addr, rc = 1, cleanup);
            }
            dst_ch_endpt->dst_port = src_ch_endpt->dst_port;
            dst_ch_endpt->sock_pending = -1;

            dst_ch_endpt->ka = src_ch_endpt->ka;

            dst_ch_endpt->ti = src_ch_endpt->ti;
            switch (src_ch_endpt->ti) {
#ifdef NC_ENABLED_SSH_TLS
            case NC_TI_SSH:
                NC_CHECK_ERR_GOTO(rc = nc_server_config_ssh_dup(src_ch_endpt->opts.ssh, &dst_ch_endpt->opts.ssh),
                        ERR(NULL, "Duplicating SSH transport information failed."), cleanup);
                break;
            case NC_TI_TLS:
                NC_CHECK_ERR_GOTO(rc = nc_server_config_tls_dup(src_ch_endpt->opts.tls, &dst_ch_endpt->opts.tls),
                        ERR(NULL, "Duplicating TLS transport information failed."), cleanup);
                break;
#endif /* NC_ENABLED_SSH_TLS */
            default:
                break;
            }

            LY_ARRAY_INCREMENT(dst_ch_client->ch_endpts);
        }

        dst_ch_client->conn_type = src_ch_client->conn_type;
        if (src_ch_client->conn_type == NC_CH_PERIOD) {
            dst_ch_client->period = src_ch_client->period;
            dst_ch_client->anchor_time = src_ch_client->anchor_time;
            dst_ch_client->idle_timeout = src_ch_client->idle_timeout;
        }

        dst_ch_client->start_with = src_ch_client->start_with;
        dst_ch_client->max_attempts = src_ch_client->max_attempts;
        dst_ch_client->max_wait = src_ch_client->max_wait;

        LY_ARRAY_INCREMENT(dst->ch_clients);
    }

#ifdef NC_ENABLED_SSH_TLS
    /* dup keystore */
    NC_CHECK_ERR_GOTO(rc = nc_server_config_keystore_dup(&src->keystore, &dst->keystore),
            ERR(NULL, "Duplicating keystore failed."), cleanup);

    /* dup truststore */
    NC_CHECK_ERR_GOTO(rc = nc_server_config_truststore_dup(&src->truststore, &dst->truststore),
            ERR(NULL, "Duplicating truststore failed."), cleanup);

    /* dup cert expiration notif intervals */
    LN2_LY_ARRAY_CREATE_GOTO_WRAP(dst->cert_exp_notif_intervals,
            LY_ARRAY_COUNT(src->cert_exp_notif_intervals), rc, cleanup);
    LY_ARRAY_FOR(src->cert_exp_notif_intervals, i) {
        dst->cert_exp_notif_intervals[i] = src->cert_exp_notif_intervals[i];
        LY_ARRAY_INCREMENT(dst->cert_exp_notif_intervals);
    }
#endif /* NC_ENABLED_SSH_TLS */

cleanup:
    if (rc) {
        nc_server_config_free(dst);
    }

    return rc;
}

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Wake up the certificate expiration notification thread to update its data.
 */
static void
nc_server_config_cert_exp_notif_thread_wakeup(void)
{
    pthread_mutex_lock(&server_opts.cert_exp_notif.lock);
    if (server_opts.cert_exp_notif.thread_running) {
        pthread_cond_signal(&server_opts.cert_exp_notif.cond);
    }
    pthread_mutex_unlock(&server_opts.cert_exp_notif.lock);
}

#endif /* NC_ENABLED_SSH_TLS */

API int
nc_server_config_setup_diff(const struct lyd_node *data)
{
    int ret = 0;
    struct nc_server_config config_copy = {0};

    NC_CHECK_ARG_RET(NULL, data, 1);

    /* CONFIG RD LOCK */
    pthread_rwlock_rdlock(&server_opts.config_lock);

    /* create a copy of the current config to work with, so that we can revert to it in case of error */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_dup(&server_opts.config, &config_copy),
            ERR(NULL, "Duplicating current server configuration failed."), cleanup_unlock);

    /* UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);

#ifdef NC_ENABLED_SSH_TLS
    /* configure keystore */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_keystore(data, 1, &config_copy),
            ERR(NULL, "Applying ietf-keystore configuration failed."), cleanup);

    /* configure truststore */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_truststore(data, 1, &config_copy),
            ERR(NULL, "Applying ietf-truststore configuration failed."), cleanup);
#endif /* NC_ENABLED_SSH_TLS */

    /* configure netconf-server */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_netconf_server(data, 1, &config_copy),
            ERR(NULL, "Applying ietf-netconf-server configuration failed."), cleanup);

    /* configure libnetconf2-netconf-server */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_libnetconf2_netconf_server(data, NC_OP_UNKNOWN, &config_copy),
            ERR(NULL, "Applying libnetconf2-netconf-server configuration failed."), cleanup);

    /* CONFIG WR LOCK */
    pthread_rwlock_wrlock(&server_opts.config_lock);

    /* start listening on new endpoints */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_reconcile_sockets_listen(&server_opts.config, &config_copy),
            ERR(NULL, "Starting to listen on new endpoints failed."), cleanup_unlock);

#ifdef NC_ENABLED_SSH_TLS
    /* dispatch new call-home threads */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_reconcile_chclients_dispatch(&server_opts.config, &config_copy),
            ERR(NULL, "Dispatching new call-home threads failed."), cleanup_unlock);
#endif /* NC_ENABLED_SSH_TLS */

    /* free the old config */
    nc_server_config_free(&server_opts.config);

    /* replace it with the new one */
    server_opts.config = config_copy;

#ifdef NC_ENABLED_SSH_TLS
    /* wake up the cert expiration notif thread */
    nc_server_config_cert_exp_notif_thread_wakeup();
#endif /* NC_ENABLED_SSH_TLS */

cleanup_unlock:
    /* CONFIG UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);

cleanup:
    if (ret) {
        /* free the new config in case of error */
        nc_server_config_free(&config_copy);
    }

    return ret;
}

API int
nc_server_config_setup_data(const struct lyd_node *data)
{
    int ret = 0;
    const struct lyd_node *tree, *iter;
    struct nc_server_config config = {0};

    NC_CHECK_ARG_RET(NULL, data, 1);

    /* check that the config data are not diff (no op attr) */
    LY_LIST_FOR(data, tree) {
        LYD_TREE_DFS_BEGIN(tree, iter) {
            if (lyd_find_meta(iter->meta, NULL, "yang:operation")) {
                ERR(NULL, "Unexpected operation attribute in the YANG data.");
                ret = 1;
                goto cleanup;
            }
            LYD_TREE_DFS_END(tree, iter);
        }
    }

    /* create a new empty config, we can use it to fill it with new data, 2 main benefits:
     * - if something fails, the old config is still intact
     * - not having to hold the config_lock for a long time while applying the new config
    */

#ifdef NC_ENABLED_SSH_TLS
    /* configure keystore */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_keystore(data, 0, &config),
            ERR(NULL, "Applying ietf-keystore configuration failed."), cleanup);

    /* configure truststore */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_truststore(data, 0, &config),
            ERR(NULL, "Applying ietf-truststore configuration failed."), cleanup);
#endif /* NC_ENABLED_SSH_TLS */

    /* configure netconf-server */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_netconf_server(data, 0, &config),
            ERR(NULL, "Applying ietf-netconf-server configuration failed."), cleanup);

    /* configure libnetconf2-netconf-server */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_libnetconf2_netconf_server(data, NC_OP_UNKNOWN, &config),
            ERR(NULL, "Applying libnetconf2-netconf-server configuration failed."), cleanup);

    /* CONFIG LOCK */
    pthread_rwlock_wrlock(&server_opts.config_lock);

    /* start listening on new endpoints */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_reconcile_sockets_listen(&server_opts.config, &config),
            ERR(NULL, "Starting to listen on new endpoints failed."), cleanup_unlock);

#ifdef NC_ENABLED_SSH_TLS
    /* dispatch new call-home connections */
    NC_CHECK_ERR_GOTO(ret = nc_server_config_reconcile_chclients_dispatch(&server_opts.config, &config),
            ERR(NULL, "Dispatching new call-home connections failed."), cleanup_unlock);
#endif /* NC_ENABLED_SSH_TLS */

    /* free the old config */
    nc_server_config_free(&server_opts.config);

    /* replace it with the new one */
    server_opts.config = config;

#ifdef NC_ENABLED_SSH_TLS
    /* wake up the cert expiration notif thread */
    nc_server_config_cert_exp_notif_thread_wakeup();
#endif /* NC_ENABLED_SSH_TLS */

cleanup_unlock:
    /* CONFIG UNLOCK */
    pthread_rwlock_unlock(&server_opts.config_lock);

cleanup:
    if (ret) {
        /* free the new config in case of error */
        nc_server_config_free(&config);
    }

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

/**
 * @brief Create operational data for supported algorithms.
 *
 * @param[in] ctx libyang context.
 * @param[in] mod Module name.
 * @param[in] alg_type Optional algorithm type (container name).
 * @param[in] supported_algs Array of supported algorithms.
 * @param[out] algs Created operational data tree.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_oper_get_algs(const struct ly_ctx *ctx, const char *mod, const char *alg_type,
        const char *supported_algs[], struct lyd_node **algs)
{
    int rc = 0, r, i;
    struct lyd_node *parent = NULL, *node = NULL;
    char *path = NULL;

    *algs = NULL;

    /* prepare path to supported-algorithms container */
    if (alg_type) {
        r = asprintf(&path, "/%s:supported-algorithms/%s", mod, alg_type);
    } else {
        r = asprintf(&path, "/%s:supported-algorithms", mod);
    }
    NC_CHECK_ERRMEM_RET(r == -1, 1);

    /* create supported algorithms container */
    NC_CHECK_ERR_GOTO(lyd_new_path(NULL, ctx, path, NULL, 0, &node), rc = 1, cleanup);

    if (alg_type) {
        /* we need to go one level deeper because of the alg_type container */
        parent = lyd_child(node);
    } else {
        parent = node;
    }

    /* create supported-algorithm leaf-list entries */
    for (i = 0; supported_algs[i]; i++) {
        NC_CHECK_ERR_GOTO(lyd_new_term(parent, NULL, "supported-algorithm", supported_algs[i], 0, NULL), rc = 1, cleanup);
    }

    /* success */
    *algs = parent;
cleanup:
    if (rc) {
        lyd_free_tree(node);
    }
    if (!rc && alg_type) {
        /* success, we need to unlink and free the node we don't want to return */
        lyd_unlink_tree(parent);
        lyd_free_tree(node);
    }
    free(path);
    return rc;
}

/**
 * @brief Get operational data for supported hostkey algorithms.
 *
 * @param[in] ctx libyang context.
 * @param[out] hostkey_algs Created operational data tree.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_oper_get_hostkey_algs(const struct ly_ctx *ctx, struct lyd_node **hostkey_algs)
{
    /* hostkey algs supported by libssh (v0.11.0) */
    const char *supported_algs[] = {
        "ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256",
        "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa",
        "ssh-ed25519-cert-v01@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "rsa-sha2-512-cert-v01@openssh.com", "rsa-sha2-256-cert-v01@openssh.com",
        "ssh-rsa-cert-v01@openssh.com", NULL
    };
    const char *mod = "ietf-ssh-common", *alg_type = "public-key-algorithms";

    return nc_server_config_oper_get_algs(ctx, mod, alg_type, supported_algs, hostkey_algs);
}

/**
 * @brief Get operational data for supported key exchange algorithms.
 *
 * @param[in] ctx libyang context.
 * @param[out] kex_algs Created operational data tree.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_oper_get_kex_algs(const struct ly_ctx *ctx, struct lyd_node **kex_algs)
{
    /* kex algs supported by libssh (v0.11.0) */
    const char *supported_algs[] = {
        "diffie-hellman-group-exchange-sha1", "curve25519-sha256", "curve25519-sha256@libssh.org",
        "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521", "diffie-hellman-group18-sha512", "diffie-hellman-group16-sha512",
        "diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", NULL
    };
    const char *mod = "ietf-ssh-common", *alg_type = "key-exchange-algorithms";

    return nc_server_config_oper_get_algs(ctx, mod, alg_type, supported_algs, kex_algs);
}

/**
 * @brief Get operational data for supported encryption algorithms.
 *
 * @param[in] ctx libyang context.
 * @param[out] encryption_algs Created operational data tree.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_oper_get_encryption_algs(const struct ly_ctx *ctx, struct lyd_node **encryption_algs)
{
    /* encryption algs supported by libssh (v0.11.0) */
    const char *supported_algs[] = {
        "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
        "aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc",
        "blowfish-cbc", "3des-cbc", "none", NULL
    };
    const char *mod = "ietf-ssh-common", *alg_type = "encryption-algorithms";

    return nc_server_config_oper_get_algs(ctx, mod, alg_type, supported_algs, encryption_algs);
}

/**
 * @brief Get operational data for supported MAC algorithms.
 *
 * @param[in] ctx libyang context.
 * @param[out] mac_algs Created operational data tree.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_config_oper_get_mac_algs(const struct ly_ctx *ctx, struct lyd_node **mac_algs)
{
    /* mac algs supported by libssh (v0.11.0) */
    const char *supported_algs[] = {
        "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com",
        "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1", "none", NULL
    };
    const char *mod = "ietf-ssh-common", *alg_type = "mac-algorithms";

    return nc_server_config_oper_get_algs(ctx, mod, alg_type, supported_algs, mac_algs);
}

API int
nc_server_config_oper_get_supported_ssh_algs(const struct ly_ctx *ctx, struct lyd_node **supported_algs)
{
    int rc = 0;
    struct lyd_node *parent, *hostkey_algs, *kex_algs, *encryption_algs, *mac_algs;

    NC_CHECK_ARG_RET(NULL, ctx, supported_algs, 1);

    parent = hostkey_algs = kex_algs = encryption_algs = mac_algs = NULL;

    /* hostkey algorithms */
    NC_CHECK_ERR_GOTO(rc = nc_server_config_oper_get_hostkey_algs(ctx, &hostkey_algs),
            ERR(NULL, "Getting supported hostkey algorithms failed."), cleanup);

    /* key exchange algorithms */
    NC_CHECK_ERR_GOTO(rc = nc_server_config_oper_get_kex_algs(ctx, &kex_algs),
            ERR(NULL, "Getting supported key exchange algorithms failed."), cleanup);

    /* encryption algorithms */
    NC_CHECK_ERR_GOTO(rc = nc_server_config_oper_get_encryption_algs(ctx, &encryption_algs),
            ERR(NULL, "Getting supported encryption algorithms failed."), cleanup);

    /* MAC algorithms */
    NC_CHECK_ERR_GOTO(rc = nc_server_config_oper_get_mac_algs(ctx, &mac_algs),
            ERR(NULL, "Getting supported MAC algorithms failed."), cleanup);

    /* create supported-algorithms container */
    NC_CHECK_ERR_GOTO(lyd_new_path(NULL, ctx, "/ietf-ssh-common:supported-algorithms", NULL, 0, &parent),
            rc = 1, cleanup);

    /* insert all algorithm containers */
    if (lyd_insert_child(parent, hostkey_algs) ||
            lyd_insert_child(parent, kex_algs) ||
            lyd_insert_child(parent, encryption_algs) ||
            lyd_insert_child(parent, mac_algs)) {
        rc = 1;
        goto cleanup;
    }

    /* success */
    *supported_algs = parent;
    parent = hostkey_algs = kex_algs = encryption_algs = mac_algs = NULL;
cleanup:
    lyd_free_tree(parent);
    lyd_free_tree(hostkey_algs);
    lyd_free_tree(kex_algs);
    lyd_free_tree(encryption_algs);
    lyd_free_tree(mac_algs);
    return rc;
}

API int
nc_server_config_oper_get_supported_tls_algs(const struct ly_ctx *ctx, struct lyd_node **supported_algs)
{
    const char *mod = "ietf-tls-common";

    NC_CHECK_ARG_RET(NULL, ctx, supported_algs, 1);

    /* cipher suites are based on the used TLS library */
    return nc_server_config_oper_get_algs(ctx, mod, NULL, nc_tls_supported_cipher_suites, supported_algs);
}

#endif /* NC_ENABLED_SSH_TLS */
