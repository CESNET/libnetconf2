/**
 * @file config_server.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server configuration
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

#ifndef NC_CONFIG_SERVER_H_
#define NC_CONFIG_SERVER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <libyang/libyang.h>
#include <stdint.h>

#include "netconf.h"
#include "session.h"
#include "session_p.h"

/**
 * @brief Configure server based on the given data.
 *
 * Expected data is a validated instance of a ietf-netconf-server YANG data.
 * The data must be in the diff format and supported operations are: create, replace,
 * delete and none. Context must already have implemented the required modules, see
 * ::nc_config_load_modules().
 *
 * @param[in] data ietf-netconf-server YANG data.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup(const struct lyd_node *data);

/**
 * @brief Configure server based on the given ietf-netconf-server YANG data.
 * Wrapper around ::nc_config_setup_server() hiding work with parsing the data.
 *
 * @param[in] ctx libyang context.
 * @param[in] path Path to the file with YANG data in XML format.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_setup_path(const struct ly_ctx *ctx, const char *path);

/**
 * @brief Implements all the required modules and their features in the context.
 * Needs to be called before any other configuration functions.
 *
 * If ctx is :
 *      - NULL: a new context will be created and if the call is successful you have to free it,
 *      - non NULL: modules will simply be implemented.
 *
 * Implemented modules: ietf-netconf-server, ietf-x509-cert-to-name, ietf-crypto-types,
 * ietf-tcp-common, ietf-ssh-common, iana-ssh-encryption-algs, iana-ssh-key-exchange-algs,
 * iana-ssh-mac-algs, iana-ssh-public-key-algs, ietf-keystore, ietf-ssh-server, ietf-truststore,
 * ietf-tls-server and libnetconf2-netconf-server.
 *
 * @param[in, out] ctx Optional context in which the modules will be implemented. Created if ctx is null.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_load_modules(struct ly_ctx **ctx);

/**
 * @brief Configures the listen subtree in the ietf-netconf-server module.
 *
 * @param[in] op Operation to be done on the subtree. Only does something if the operation is NC_OP_DELETE.
 * @return 0 on success, 1 on error.
 */
int nc_server_configure_listen(NC_OPERATION op);

#ifdef __cplusplus
}
#endif

#endif /* NC_SESSION_SERVER_H_ */
