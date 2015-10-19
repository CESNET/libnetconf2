/**
 * \file messages.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2's public functions and structures of NETCONF messages.
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 */

#ifndef NC_MESSAGES_H_
#define NC_MESSAGES_H_

/**
 * @brief NETCONF RPC object
 */
struct nc_rpc;

/**
 * @brief NETCONF RPC reply object
 */
struct nc_reply;

/**
 * @brief NETCONF Notification object
 */
struct nc_notif;

/**
 * @brief Free the NETCONF RPC object.
 * @param[in] rpc Object to free.
 */
void nc_rpc_free(struct nc_rpc *rpc);

/**
 * @brief Free the NETCONF RPC reply object.
 * @param[in] rpc Object to free.
 */
void nc_reply_free(struct nc_reply *reply);

/**
 * @brief Free the NETCONF Notification object.
 * @param[in] rpc Object to free.
 */
void nc_notif_free(struct nc_notif *notif);

#endif /* NC_MESSAGES_H_ */
