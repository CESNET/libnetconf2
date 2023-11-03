/**
 * @file session_server_ch.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 Call Home session server manipulation
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

#ifndef NC_SESSION_SERVER_CH_H_
#define NC_SESSION_SERVER_CH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <libyang/libyang.h>
#include <stdint.h>
#include <time.h>

#include "netconf.h"
#include "session.h"

#ifdef NC_ENABLED_SSH_TLS

/**
 * @defgroup server_ch Server-side Call Home
 * @ingroup server
 *
 * @brief Call Home functionality for server-side applications.
 * @{
 */

/** @} Server-side Call Home */

/**
 * @defgroup server_ch_functions Server-side Call Home Functions
 * @ingroup server_ch
 *
 * @brief Server-side Call Home functions.
 * @{
 */

/**
 * @brief Check if a Call Home client exists.
 *
 * @param[in] name Client name.
 * @return 0 if does not exists, non-zero otherwise.
 */
int nc_server_ch_is_client(const char *name);

/**
 * @brief Check if an endpoint of a Call Home client exists.
 *
 * @param[in] client_name Client name.
 * @param[in] endpt_name Endpoint name.
 * @return 0 if does not exists, non-zero otherwise.
 */
int nc_server_ch_client_is_endpt(const char *client_name, const char *endpt_name);

/**
 * @brief Callback for getting a locked context for new Call Home sessions.
 *
 * @param[in] cb_data Arbitrary ctx callback data.
 * @return Context for the session to use during its lifetime;
 * @return NULL on error and session fails to be created.
 */
typedef const struct ly_ctx *(*nc_server_ch_session_acquire_ctx_cb)(void *cb_data);

/**
 * @brief Callback for releasing a locked context for Call Home sessions.
 *
 * @param[in] cb_data Arbitrary ctx callback data.
 */
typedef void (*nc_server_ch_session_release_ctx_cb)(void *cb_data);

/**
 * @brief Callback for new Call Home sessions.
 *
 * @param[in] client_name Name of the CH client which established the session.
 * @param[in] new_session New established CH session, the pointer is internally discarded afterwards.
 * @param[in] user_data Arbitrary new session callback data.
 * @return 0 on success;
 * @return non-zero on error and @p new_session is freed.
 */
typedef int (*nc_server_ch_new_session_cb)(const char *client_name, struct nc_session *new_session, void *user_data);

/**
 * @brief Dispatch a thread connecting to a listening NETCONF client and creating Call Home sessions.
 *
 * @param[in] client_name Existing client name.
 * @param[in] acquire_ctx_cb Callback for acquiring new session context.
 * @param[in] release_ctx_cb Callback for releasing session context.
 * @param[in] ctx_cb_data Arbitrary user data passed to @p acquire_ctx_cb and @p release_ctx_cb.
 * @param[in] new_session_cb Callback called for every established session on the client.
 * @param[in] new_session_cb_data Arbitrary user data passed to @p new_session_cb.
 * @return 0 if the thread was successfully created, -1 on error.
 */
int nc_connect_ch_client_dispatch(const char *client_name, nc_server_ch_session_acquire_ctx_cb acquire_ctx_cb,
        nc_server_ch_session_release_ctx_cb release_ctx_cb, void *ctx_cb_data, nc_server_ch_new_session_cb new_session_cb,
        void *new_session_cb_data);

/**
 * @brief Set callbacks and their data for Call Home threads.
 *
 * If set, Call Home threads will be dispatched automatically upon creation of new Call Home clients.
 *
 * @param[in] acquire_ctx_cb Callback for acquiring new session context.
 * @param[in] release_ctx_cb Callback for releasing session context.
 * @param[in] ctx_cb_data Arbitrary user data passed to @p acquire_ctx_cb and @p release_ctx_cb.
 * @param[in] new_session_cb Callback called for every established Call Home session.
 * @param[in] new_session_cb_data Arbitrary user data passed to @p new_session_cb.
 */
void nc_server_ch_set_dispatch_data(nc_server_ch_session_acquire_ctx_cb acquire_ctx_cb,
        nc_server_ch_session_release_ctx_cb release_ctx_cb, void *ctx_cb_data, nc_server_ch_new_session_cb new_session_cb,
        void *new_session_cb_data);

/** @} Server-side Call Home Functions */

#endif /* NC_ENABLED_SSH_TLS */

#ifdef __cplusplus
}
#endif

#endif /* NC_SESSION_SERVER_CH_H_ */
