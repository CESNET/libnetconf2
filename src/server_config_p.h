/**
 * @file server_config_p.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server configuration
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

#ifndef NC_CONFIG_SERVER_P_H_
#define NC_CONFIG_SERVER_P_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <libyang/libyang.h>
#include <stdint.h>

#include "compat.h"
#include "libnetconf.h"
#include "netconf.h"
#include "session_p.h"

/**
 * Enumeration of ietf-netconf-server's modules/trees (top-level containers)
 */
typedef enum {
    NC_MODULE_NETCONF_SERVER,
    NC_MODULE_KEYSTORE,
    NC_MODULE_TRUSTSTORE
} NC_MODULE;

/**
 * @brief Get the pointer to an endpoint structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the endpoint containing this node is derived.
 * @param[out] endpt Endpoint containing the node.
 * @param[out] bind Bind corresponding to the endpoint. Optional.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_get_endpt(const struct lyd_node *node, struct nc_endpt **endpt, struct nc_bind **bind);

/**
 * @brief Get the pointer to a hostkey structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the hotkey containing this node is derived.
 * @param[in] opts Server SSH opts storing the array of the hostkey structures.
 * @param[out] hostkey Hostkey containing the node.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_get_hostkey(const struct lyd_node *node, const struct nc_server_ssh_opts *opts, struct nc_hostkey **hostkey);

/**
 * @brief Get the pointer to a client authentication structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the client-authentication structure containing this node is derived.
 * @param[in] opts Server SSH opts storing the array of the client authentication structures.
 * @param[out] auth_client Client authentication structure containing the node.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_get_auth_client(const struct lyd_node *node, const struct nc_server_ssh_opts *opts, struct nc_client_auth **auth_client);

/**
 * @brief Get the pointer to a client authentication public key structure based on node's location in the YANG data.
 *
 * @param[in] node Node from which the ca-public key structure containing this node is derived.
 * @param[in] auth_client Client authentication structure storing the array of the public key structures.
 * @param[out] pubkey Public key structure containing the node.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_get_pubkey(const struct lyd_node *node, const struct nc_client_auth *auth_client, struct nc_public_key **pubkey);

/**
 * @brief Compares the nth-parent name.
 *
 * @param[in] node Node of which nth-parent to compare.
 * @param[in] parent_count Count of parents.
 * @param[in] parent_name Expected name of the parent.
 * @return 1 if the name matches, 0 otherwise.
 */
int equal_parent_name(const struct lyd_node *node, uint16_t parent_count, const char *parent_name);

/**
 * @brief Generic realloc function for arrays of structures representing YANG lists whose first member is the key (char *)
 *
 * @param[in] key_value Value of the key, which will be assigned to the first member of the given struct.
 * @param[in] size Size of a member of the array.
 * @param[in,out] ptr Pointer to the beginning of the given array, which will be reallocated.
 * @param[in,out] count Count of members in the array, incremented at the end.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_realloc(const char *key_value, void **ptr, size_t size, uint16_t *count);

/**
 * @brief Recursively parse the given tree and apply it's data to the server's configuration.
 *
 * @param[in] node YANG data tree.
 * @param[in] parent_op Operation of the parent.
 * @param[in] module Module for which to parse the data - either ietf-netconf-server, ietf-keystore or ietf-truststore
 * @return 0 on success, 1 on error.
 */
int nc_server_config_parse_tree(const struct lyd_node *node, NC_OPERATION parent_op, NC_MODULE module);

/**
 * @brief Configures the listen subtree in the ietf-netconf-server module.
 *
 * @param[in] node Listen YANG data node.
 * @param[in] op Operation to be done on the subtree. Only does something if the operation is NC_OP_DELETE.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_listen(struct lyd_node *node, NC_OPERATION op);

/** KEYSTORE **/

/**
 * @brief Checks if keystore tree is present in the data and if yes, tries to apply it's data.
 *
 * @param[in] data YANG data tree.
 * @param[in] op Operation saying what to do with the top-level node.
 * @return 0 either if keystore is not present or if it is and application was successful, 1 on error.
 */
int nc_server_config_fill_keystore(const struct lyd_node *data, NC_OPERATION op);

/**
 * @brief Parse the given node, which belongs to the ietf-keystore subtree, and apply it's data to the server's configuration.
 *
 * @param[in] node YANG data node.
 * @param[in] op Operation saying what to do with the node.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_parse_keystore(const struct lyd_node *node, NC_OPERATION op);

/**
 * @brief Configures the keystore subtree in the ietf-keystore module.
 *
 * @param[in] node Keystore YANG data node.
 * @param[in] op Operation to be done on the subtree. Only does something if the operation is NC_OP_DELETE.
 * @return 0.
 */
int nc_server_config_ks_keystore(const struct lyd_node *node, NC_OPERATION op);

/** TRUSTSTORE **/

/**
 * @brief Checks if truststore tree is present in the data and if yes, tries to apply it's data.
 *
 * @param[in] data YANG data tree.
 * @param[in] op Operation saying what to do with the top-level node.
 * @return 0 either if truststore is not present or if it is and application was successful, 1 on error.
 */
int nc_server_config_fill_truststore(const struct lyd_node *data, NC_OPERATION op);

/**
 * @brief Parse the given node, which belongs to the ietf-truststore subtree, and apply it's data to the server's configuration.
 *
 * @param[in] node YANG data node.
 * @param[in] op Operation saying what to do with the node.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_parse_truststore(const struct lyd_node *node, NC_OPERATION op);

/**
 * @brief Configures the truststore subtree in the ietf-truststore module.
 *
 * @param[in] node Truststore YANG data node.
 * @param[in] op Operation to be done on the subtree. Only does something if the operation is NC_OP_DELETE.
 * @return 0.
 */
int nc_server_config_ts_truststore(const struct lyd_node *node, NC_OPERATION op);

#ifdef __cplusplus
}
#endif

#endif /* NC_CONFIG_SERVER_P_H_ */
