/**
 * \file session.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 session manipulation
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

#ifndef NC_SESSION_H_
#define NC_SESSION_H_

#include "messages.h"

/**
 * @brief NETCONF session object
 */
struct nc_session;

/**
 * @brief Receive NETCONF RPC
 */
NC_MSG_TYPE nc_recv_rpc(struct nc_session* session, int timeout, struct nc_rpc **rpc);

/**
 * @brief Receive NETCONF RPC reply
 */
NC_MSG_TYPE nc_recv_reply(struct nc_session* session, int timeout, struct nc_reply **reply);

/**
 * @brief Receive NETCONF Notification
 */
NC_MSG_TYPE nc_recv_notif(struct nc_session* session, int timeout, struct nc_notif **notif);

#endif /* NC_SESSION_H_ */
