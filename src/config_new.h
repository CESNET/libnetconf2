/**
 * @file config_new.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 server new configuration creation
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

#ifndef NC_CONFIG_NEW_H_
#define NC_CONFIG_NEW_H_

#include <libyang/libyang.h>

#include "session_p.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NC_ALG_HOSTKEY,
    NC_ALG_KEY_EXCHANGE,
    NC_ALG_ENCRYPTION,
    NC_ALG_MAC
} NC_ALG_TYPE;

/**
 * @brief Configures the listen subtree in the ietf-netconf-server module.
 *
 * @param[in] op Operation to be done on the subtree. Only does something if the operation is NC_OP_DELETE.
 * @return 0 on success, 1 on error.
 */
int nc_server_config_listen(NC_OPERATION op);

/**
 * @brief Deletes everything stored in the keystore.
 */
void nc_server_config_del_keystore(void);

/**
 * @brief Deletes everything stored in the truststore.
 */
void nc_server_config_del_trustore(void);

#ifdef __cplusplus
}
#endif

#endif /* NC_CONFIG_NEW_H_ */
