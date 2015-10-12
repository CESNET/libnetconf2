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

#include <stdint.h>

#include "messages.h"

/**
 * @brief NETCONF session object
 */
struct nc_session;

/**
 * @brief Receive NETCONF RPC.
 *
 * @param[in] session NETCONF session from which the function gets data. It must be the
 *            server side session object.
 * @param[in] timeout Timeout for reading in milliseconds. Use negative value for infinite
 *            waiting and 0 for immediate return if data are not available on wire.
 * @param[out] notif Resulting object of NETCONF RPC.
 * @return NC_MSG_RPC for success, NC_MSG_WOULDBLOCK if timeout reached and NC_MSG_ERROR
 *         when reading has failed.
 */
NC_MSG_TYPE nc_recv_rpc(struct nc_session* session, int timeout, struct nc_rpc **rpc);

/**
 * @brief Receive NETCONF RPC reply.
 *
 * @param[in] session NETCONF session from which the function gets data. It must be the
 *            client side session object.
 * @param[in] timeout Timeout for reading in milliseconds. Use negative value for infinite
 *            waiting and 0 for immediate return if data are not available on wire.
 * @param[out] reply Resulting object of NETCONF RPC reply.
 * @return NC_MSG_REPLY for success, NC_MSG_WOULDBLOCK if timeout reached and NC_MSG_ERROR
 *         when reading has failed.
 */
NC_MSG_TYPE nc_recv_reply(struct nc_session* session, int timeout, struct nc_reply **reply);

/**
 * @brief Receive NETCONF Notification.
 *
 * @param[in] session NETCONF session from which the function gets data. It must be the
 *            client side session object.
 * @param[in] timeout Timeout for reading in milliseconds. Use negative value for infinite
 *            waiting and 0 for immediate return if data are not available on wire.
 * @param[out] notif Resulting object of NETCONF Notification.
 * @return NC_MSG_NOTIF for success, NC_MSG_WOULDBLOCK if timeout reached and NC_MSG_ERROR
 *         when reading has failed.
 */
NC_MSG_TYPE nc_recv_notif(struct nc_session* session, int timeout, struct nc_notif **notif);

/**
 * @brief Send NETCONF RPC message via the session.
 *
 * @param[in] session NETCONF session where the RPC will be written.
 * @param[in] op NETCONF RPC operation to be sent.
 * @param[in] attrs Additional (optional) XML attributes to be added into the \<rpc\> element.
 *            Note, that "message-id" attribute is added automatically.
 * @return #NC_MSG_RPC on success, #NC_MSG_WOULDBLOCK in case of busy session
 * (try to repeat the function call) and #NC_MSG_ERROR in case of error.
 */
NC_MSG_TYPE nc_send_rpc(struct nc_session* session, struct lyd_node *op, const char *attrs);

#endif /* NC_SESSION_H_ */
