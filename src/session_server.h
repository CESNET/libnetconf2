/**
 * \file session_server.h
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 session server manipulation
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

#ifndef NC_SESSION_SERVER_H_
#define NC_SESSION_SERVER_H_

#include <stdint.h>

#include "session.h"
#include "messages.h"
#include "netconf.h"

int nc_server_init(struct ly_ctx *ctx);

int nc_server_set_capab_withdefaults(NC_WD_MODE basic_mode, int also_supported);

int nc_server_set_capab_interleave(int interleave_support);

int nc_server_set_hello_timeout(uint16_t hello_timeout);

int nc_server_set_idle_timeout(uint16_t idle_timeout);

int nc_server_set_max_sessions(uint16_t max_sessions);

struct nc_session *nc_accept_inout(int fdin, int fdout, const char *username);

struct nc_pollsession *nc_pollsession_new(void);

void nc_pollsession_free(struct nc_pollsession *ps);

int nc_pollsession_add_session(struct nc_pollsession *ps, struct nc_session *session);

int nc_pollsession_poll(struct nc_pollsession *ps, int timeout);

#if defined(ENABLE_SSH) || defined(ENABLE_TLS)

int nc_server_add_bind_listen(const char *address, uint16_t port, NC_TRANSPORT_IMPL ti);

int nc_server_del_bind(const char *address, uint16_t port, NC_TRANSPORT_IMPL ti);

void nc_server_destroy_binds(void);

struct nc_session *nc_accept(int timeout);

#endif /* ENABLE_SSH || ENABLE_TLS */

#ifdef ENABLE_SSH

/* one for each key */
int nc_ssh_server_set_hostkey(const char *key_path);

int nc_ssh_server_set_banner(const char *banner);

int nc_ssh_server_set_auth_methods(int auth_methods);

int nc_ssh_server_set_auth_attempts(uint16_t auth_attempts);

int nc_ssh_server_set_auth_timeout(uint16_t auth_timeout);

int nc_ssh_server_add_authkey(const char *keypath, const char *username);

int nc_ssh_server_del_authkey(const char *keypath, const char *username);

void nc_ssh_server_free_opts(void);

struct nc_session *nc_accept_ssh_channel(struct nc_session *session, int timeout);

#endif /* ENABLE_SSH */

#ifdef ENABLE_TLS

int nc_tls_server_set_cert(const char *cert);

int nc_tls_server_set_cert_path(const char *cert_path);

int nc_tls_server_set_key(const char *privkey, int is_rsa);

int nc_tls_server_set_key_path(const char *privkey_path);

int nc_tls_server_add_trusted_cert(const char *cert);

int nc_tls_server_add_trusted_cert_path(const char *cert_path);

int nc_tls_server_set_trusted_cacert_locations(const char *cacert_file_path, const char *cacert_dir_path);

void nc_tls_server_destroy_certs(void);

int nc_tls_server_set_crl_locations(const char *crl_file_path, const char *crl_dir_path);

void nc_tls_server_destroy_crls(void);

int nc_tls_server_add_ctn(uint32_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name);

int nc_tls_server_del_ctn(int64_t id, const char *fingerprint, NC_TLS_CTN_MAPTYPE map_type, const char *name);

void nc_tls_server_free_opts(void);

#endif /* ENABLE_TLS */

#endif /* NC_SESSION_SERVER_H_ */
