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

#include <libyang/libyang.h>
#include <stdint.h>
#include <stdlib.h>

#include "session_p.h"

/**
 * Enumeration of ietf-netconf-server's modules/trees (top-level containers)
 */
typedef enum {
    NC_MODULE_NETCONF_SERVER,
    NC_MODULE_KEYSTORE,
    NC_MODULE_TRUSTSTORE,
    NC_MODULE_LIBNETCONF2_NETCONF_SERVER
} NC_MODULE;

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Get private key type from YANG identity stored in a string.
 *
 * @param[in] format Value of the YANG identityref.
 * @return Private key format on success, NC_PRIVKEY_FORMAT_UNKNOWN otherwise.
 */
NC_PRIVKEY_FORMAT nc_server_config_get_private_key_type(const char *format);

#endif /* NC_ENABLED_SSH_TLS */

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
int nc_server_config_listen(const struct lyd_node *node, NC_OPERATION op);

/**
 * @brief Configures the Call Home subtree in the ietf-netconf-server module.
 *
 * @param[in] node call-home YANG data node.
 * @param[in] op Operation to be done on the subtree. Only does something if the operation is NC_OP_DELETE.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_ch(const struct lyd_node *node, NC_OPERATION op);

#ifdef NC_ENABLED_SSH_TLS

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

/** LIBNETCONF2-NETCONF-SERVER **/

/**
 * @brief Configures the ln2-netconf-server subtree in the libnetconf2-netconf-server module.
 *
 * @param[in] node Optional ln2-netconf-server YANG data node.
 * @param[in] op Operation to be done on the subtree. Only does something if the operation is NC_OP_DELETE.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_ln2_netconf_server(const struct lyd_node *node, NC_OPERATION op);

#endif /* NC_ENABLED_SSH_TLS */

#endif /* NC_CONFIG_SERVER_P_H_ */
