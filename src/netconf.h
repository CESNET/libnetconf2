/**
 * \file netconf.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2's general public functions and structures definitions.
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

#ifndef NC_NETCONF_H_
#define NC_NETCONF_H_

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NC_NS_BASE  "urn:ietf:params:xml:ns:netconf:base:1.0"
#define NC_NS_NOTIF "urn:ietf:params:xml:ns:netconf:notification:1.0"

/** @brief Default NETCONF over SSH port */
#define NC_PORT_SSH 830
/** @brief Default NETCONF over SSH Call Home port */
#define NC_PORT_CH_SSH 6666

/** @brief Default NETCONF over TLS port */
#define NC_PORT_TLS 6513
/** @brief Default NETCONF over TLS Call Home port */
#define NC_PORT_CH_TLS 6667

/** @brief Microseconds after which tasks are repeated until the full timeout elapses */
#define NC_TIMEOUT_STEP 10

/**
 * @brief Enumeration of reasons of the NETCONF session termination as defined in RFC 6470.
 */
typedef enum NC_SESSION_TERM_REASON {
    NC_SESSION_TERM_NONE = 0,     /**< session still running */
    NC_SESSION_TERM_CLOSED,       /**< closed by client in a normal fashion */
    NC_SESSION_TERM_KILLED,       /**< session was terminated by \<kill-session\> operation */
    NC_SESSION_TERM_DROPPED,      /**< transport layer connection was unexpectedly closed */
    NC_SESSION_TERM_TIMEOUT,      /**< terminated because of inactivity */
    NC_SESSION_TERM_BADHELLO,     /**< \<hello\> message was invalid */
    NC_SESSION_TERM_OTHER         /**< terminated for some other reason */
} NC_SESSION_TERM_REASON;

/**
 * @brief Enumeration of NETCONF message types.
 */
typedef enum NC_MSG_TYPE {
    NC_MSG_ERROR,       /**< error return value */
    NC_MSG_WOULDBLOCK,  /**< timeout return value */
    NC_MSG_NONE,        /**< no message at input or message was processed internally */
    NC_MSG_HELLO,       /**< \<hello\> message */
    NC_MSG_RPC,         /**< \<rpc\> message */
    NC_MSG_REPLY,       /**< \<rpc-reply\> message */
    NC_MSG_NOTIF        /**< \<notification\> message */
} NC_MSG_TYPE;

/**
 * @brief Enumeration of the supported types of datastores defined by NETCONF
 */
typedef enum NC_DATASTORE_TYPE {
    NC_DATASTORE_ERROR,    /**< error state of functions returning the datastore type */
    NC_DATASTORE_CONFIG,   /**< value describing that the datastore is set as config */
    NC_DATASTORE_URL,      /**< value describing that the datastore data should be given from the URL */
    NC_DATASTORE_RUNNING,  /**< base NETCONF's datastore containing the current device configuration */
    NC_DATASTORE_STARTUP,  /**< separated startup datastore as defined in Distinct Startup Capability */
    NC_DATASTORE_CANDIDATE /**< separated working datastore as defined in Candidate Configuration Capability */
} NC_DATASTORE;

typedef enum NC_WITHDEFAULTS_MODE {
    NC_WD_UNKNOWN = 0,
    NC_WD_ALL = 0x01,
    NC_WD_ALL_TAG = 0x02,
    NC_WD_TRIM = 0x04,
    NC_WD_EXPLICIT = 0x08
} NC_WD_MODE;

typedef enum NC_PARAMTYPE {
    NC_PARAMTYPE_CONST,
    NC_PARAMTYPE_FREE,
    NC_PARAMTYPE_DUP_AND_FREE
} NC_PARAMTYPE;

typedef enum NC_REPLY {
    NC_RPL_OK,
    NC_RPL_DATA,
    NC_RPL_ERROR,
    NC_RPL_NOTIF
} NC_RPL;

/**
 * @brief Transform given time_t (seconds since the epoch) into the RFC 3339 format
 * accepted by NETCONF functions.
 *
 * This is a reverse function to nc_datetime2time().
 *
 * @param[in] time time_t type value returned e.g. by time().
 * @param[in] tz timezone name for the result. See tzselect(1) for list of
 * correct values. If not specified (NULL), the result is provided in UTC (Zulu).
 * @return Printed string in a format compliant to RFC 3339. It is up to the
 * caller to free the returned string.
 */
char* nc_time2datetime(time_t time, const char* tz);

/**
 * @brief Transform given string in RFC 3339 compliant format to the time_t
 * (seconds since the epoch) accepted by most Linux functions.
 *
 * This is a reverse function to nc_time2datetime().
 *
 * @param[in] datetime Time structure returned e.g. by localtime().
 * @return time_t value of the given string.
 */
time_t nc_datetime2time(const char* datetime);

#ifdef __cplusplus
}
#endif

#endif /* NC_NETCONF_H_ */
