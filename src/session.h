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

#ifdef ENABLE_SSH

typedef enum {
    NC_SSH_AUTH_PUBLICKEY = 0x01,
    NC_SSH_AUTH_PASSWORD = 0x02,
    NC_SSH_AUTH_INTERACTIVE = 0x04
} NC_SSH_AUTH_TYPE;

#endif /* ENABLE_SSH */

#ifdef ENABLE_TLS

typedef enum {
    NC_TLS_CTN_UNKNOWN,
    NC_TLS_CTN_SPECIFIED,
    NC_TLS_CTN_SAN_RFC822_NAME,
    NC_TLS_CTN_SAN_DNS_NAME,
    NC_TLS_CTN_SAN_IP_ADDRESS,
    NC_TLS_CTN_SAN_ANY,
    NC_TLS_CTN_COMMON_NAME
} NC_TLS_CTN_MAPTYPE;

#endif /* ENABLE_TLS */

/**
 * @brief Enumeration of possible session statuses
 */
typedef enum {
    NC_STATUS_STARTING = 0, /**< session is not yet fully initiated */
    NC_STATUS_CLOSING,      /**< session is being closed */
    NC_STATUS_INVALID,      /**< session is not running and is supposed to be closed (nc_session_free()) */
    NC_STATUS_RUNNING       /**< up and running */
} NC_STATUS;

/**
 * @brief Enumeration of transport implementations (ways how libnetconf implements NETCONF transport protocol)
 */
typedef enum {
    NC_TI_NONE = 0,   /**< none - session is not connected yet */
    NC_TI_FD,         /**< file descriptors - use standard input/output, transport protocol is implemented
                           outside the current application */
#ifdef ENABLE_SSH
    NC_TI_LIBSSH,     /**< libssh - use libssh library, only for NETCONF over SSH transport */
#endif
#ifdef ENABLE_TLS
    NC_TI_OPENSSL     /**< OpenSSL - use OpenSSL library, only for NETCONF over TLS transport */
#endif
} NC_TRANSPORT_IMPL;

/**
 * @brief NETCONF session object
 */
struct nc_session;

/**
 * @brief Free the NETCONF session object.
 *
 * @param[in] session Object to free.
 */
void nc_session_free(struct nc_session *session);

#ifdef ENABLE_SSH

/**
 * @brief Initialize libssh so that libnetconf2 can safely use it in a multi-threaded environment.
 *
 * Must be called before using any other functions. Afterwards can libssh be used in an application
 * as well.
 */
void nc_ssh_init(void);

/**
 * @brief Free all the resources allocated by libssh.
 *
 * Must be called before nc_tls_destroy() as libssh uses libcrypto as well.
 */
void nc_ssh_destroy(void);

#endif /* ENABLE_SSH */

#ifdef ENABLE_TLS

void nc_tls_init(void);

void nc_tls_destroy(void);

#endif /* ENABLE_TLS */

#endif /* NC_SESSION_H_ */
