/**
 * \file libnetconf.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 main internal header.
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_LIBNETCONF_H_
#define NC_LIBNETCONF_H_

#include "config.h"
#include "netconf.h"
#include "log_p.h"
#include "session_p.h"
#include "messages_p.h"

/* Tests whether string is empty or non-empty. */
#define strisempty(str) ((str)[0] == '\0')
#define strnonempty(str) ((str)[0] != '\0')

/**
 * @mainpage About
 *
 * libnetconf2 is a NETCONF library in C handling NETCONF authentication and all NETCONF
 * RPC communication both server and client-side. NETCONF datastore and session management is not a part of this library,
 * but it helps a lot with the sessions.
 *
 * @section about-features Main Features
 *
 * - Creating SSH (using libssh) or TLS (using OpenSSL) authenticated NETCONF sessions.
 * - Creating NETCONF sessions with a pre-established transport protocol
 *   (using this mechanism the communication can be tunneled through sshd(8), for instance).
 * - Creating NETCONF Call Home sessions.
 * - Creating, sending, receiving, and replying to RPCs.
 * - Receiving notifications.
 *
 * - \todo Creating and sending notifications.
 *
 * @section about-license License
 *
 * Copyright (c) 2015-2016 CESNET, z.s.p.o.
 *
 * (The BSD 3-Clause License)
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
 */

/**
 * @page howto How To ...
 *
 * - @subpage howtoinit
 * - @subpage howtoclient
 * - @subpage howtoserver
 * - @subpage howtoclientcomm
 * - @subpage howtoservercomm
 */

/**
 * @page howtoinit Init and Thread-safety Information
 *
 * Before working with the library, it must be initialized using nc_client_init()
 * or nc_server_init(). Based on how the library was compiled, also libssh and/or
 * libssh/libcrypto are initialized (for multi-threaded use) too. It is advised
 * to compile libnetconf2, for instance, with TLS support even if you do not want
 * to use lnc2 TLS functions, but only use libssl/libcrypto functions in your
 * application. You can then use libnetconf2 cleanup function and do not
 * trouble yourself with the cleanup.
 *
 * To prevent any reachable memory at the end of your application, there
 * are complementary destroy functions available. If your application is
 * multi-threaded, call the destroy functions in the last thread, after all
 * the other threads have ended. In every other thread you should call
 * nc_thread_destroy() just before it exits.
 *
 * If libnetconf2 is used in accordance with this information, there should
 * not be memory leaks of any kind at program exit. For thread-safety details
 * of libssh, libssl, and libcrypto please refer to the corresponding project
 * documentation. libnetconf2 thread-safety information is below.
 *
 * Client is NOT thread-safe and there is no access control in the client
 * functions at all. Server is MOSTLY thread-safe meaning you can set all the
 * options simultaneously while listening for or accepting new sessions or
 * polling the existing ones. It should even be safe to poll one session in
 * several threads, but it is definitely discouraged. Generally, servers can
 * use more threads without any problems as long as they keep their workflow sane
 * (behavior such as freeing sessions only after no thread uses them or similar).
 *
 * Functions List
 * --------------
 *
 * Available in __nc_client.h__.
 *
 * - nc_client_init()
 * - nc_client_destroy()
 *
 * Available in __nc_server.h__.
 *
 * - nc_server_init()
 * - nc_server_destroy()
 *
 * Available in both __nc_client.h__ and __nc_server.h__.
 *
 * - nc_thread_destroy()
 */

/**
 * @page howtoclient Client sessions
 *
 * There are a lot of options for both an SSH and a TLS client. All of them
 * have setters and getters so that there is no need to duplicate them in
 * a client.
 *
 * SSH
 * ===
 *
 * It is mostly required to set any SSH options and then simply connect to
 * a NETCONF server. Optionally, some authetication callbacks can be set,
 * which are particulary useful in automated clients (passwords cannot be
 * asked a user) or simply if any additional information is retrieved some
 * other way than from standard terminal input.
 *
 * Afterwards, there are 2 functions to use for a new server connection
 * and an additional one for creating a new SSH channel on an existing
 * NETCONF session. The libssh variant enables to customize the SSH session
 * in every way the libssh allows, although that should not normally be needed.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_client.h__.
 *
 * - nc_client_ssh_set_auth_hostkey_check_clb()
 * - nc_client_ssh_set_auth_password_clb()
 * - nc_client_ssh_set_auth_interactive_clb()
 * - nc_client_ssh_set_auth_privkey_passphrase_clb()
 * - nc_client_ssh_add_keypair()
 * - nc_client_ssh_del_keypair()
 * - nc_client_ssh_get_keypair_count()
 * - nc_client_ssh_get_keypair()
 * - nc_client_ssh_set_auth_pref()
 * - nc_client_ssh_get_auth_pref()
 * - nc_client_ssh_set_username()
 * - nc_client_ssh_get_username()
 *
 * - nc_connect_ssh()
 * - nc_connect_libssh()
 * - nc_connect_ssh_channel()
 *
 *
 * TLS
 * ===
 *
 * With TLS authentication, is is mandatory to set the client certificate
 * with a private key and additional trusted certificates and revocation lists.
 *
 * Then there are again 2 functions for connecting, the libssl variant enables
 * to customize the TLS session in every way the libssl allows.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_client.h__.
 *
 * - nc_client_tls_set_cert_key_paths()
 * - nc_client_tls_get_cert_key_paths()
 * - nc_client_tls_set_trusted_ca_paths()
 * - nc_client_tls_get_trusted_ca_paths()
 * - nc_client_tls_set_crl_paths()
 * - nc_client_tls_get_crl_paths()
 *
 * - nc_connect_tls()
 * - nc_connect_libssl()
 *
 *
 * FD
 * ==
 *
 * If you authenticated the connection using some tunneling software, you
 * can pass its file descriptors to libnetconf2, which will continue to
 * establish a full NETCONF session.
 *
 * Funtions List
 * -------------
 *
 * Available in __nc_client.h__.
 *
 * - nc_connect_inout()
 *
 *
 * Call Home
 * =========
 *
 * Call Home needs the same options set as standard SSH or TLS and the functions
 * reflect it exactly. However, to accept a connection, the client must first
 * specify addresses and ports, which to listen on. Then connections can be
 * accepted.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_client.h__.
 *
 * - nc_client_ssh_ch_set_auth_hostkey_check_clb()
 * - nc_client_ssh_ch_set_auth_password_clb()
 * - nc_client_ssh_ch_set_auth_interactive_clb()
 * - nc_client_ssh_ch_set_auth_privkey_passphrase_clb()
 * - nc_client_ssh_ch_add_bind_listen()
 * - nc_client_ssh_ch_del_bind()
 * - nc_client_ssh_ch_add_keypair()
 * - nc_client_ssh_ch_del_keypair()
 * - nc_client_ssh_ch_get_keypair_count()
 * - nc_client_ssh_ch_get_keypair()
 * - nc_client_ssh_ch_set_auth_pref()
 * - nc_client_ssh_ch_get_auth_pref()
 * - nc_client_ssh_ch_set_username()
 * - nc_client_ssh_ch_get_username()
 *
 * - nc_client_tls_ch_add_bind_listen()
 * - nc_client_tls_ch_del_bind()
 * - nc_client_tls_ch_set_cert_key_paths()
 * - nc_client_tls_ch_get_cert_key_paths()
 * - nc_client_tls_ch_set_trusted_ca_paths()
 * - nc_client_tls_ch_get_trusted_ca_paths()
 * - nc_client_tls_ch_set_crl_paths()
 * - nc_client_tls_ch_get_crl_paths()
 *
 * - nc_accept_callhome()
 *
 *
 * Cleanup
 * =======
 *
 * These options and the schema searchpath are stored in dynamically
 * allocated memory. To free it, destroy the client, it cleans up all
 * the options
 *
 * Functions List
 * --------------
 *
 * Available in __nc_client.h__.
 *
 * - nc_client_destroy()
 */

/**
 * @page howtoserver Server sessions
 *
 * Init
 * ====
 *
 * Server takes an argument for its [initialization function](@ref howtoinit).
 * In it, you set the server context, which determines what modules it
 * supports and what capabilities to advertise. Few capabilities that
 * cannot be learnt from the context are set with separate functions.
 * So are several general options.
 *
 * Context does not only determine server modules, but its overall
 * functionality as well. For every RPC the server should support,
 * an nc_rpc_clb callback should be set on that node in the context.
 * Server then calls these as appropriate [during poll](@ref howtoservercomm).
 *
 * Server options can be only set, there are no getters.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_server_set_capab_withdefaults()
 * - nc_server_set_capab_interleave()
 * - nc_server_set_hello_timeout()
 * - nc_server_set_idle_timeout()
 *
 *
 * SSH
 * ===
 *
 * To be able to accept SSH connections, an endpoint must be added
 * and its options set.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_server_ssh_add_endpt_listen()
 * - nc_server_ssh_endpt_set_address()
 * - nc_server_ssh_endpt_set_port()
 * - nc_server_ssh_del_endpt()
 *
 * - nc_server_ssh_endpt_set_hostkey()
 * - nc_server_ssh_endpt_set_banner()
 * - nc_server_ssh_endpt_set_auth_methods()
 * - nc_server_ssh_endpt_set_auth_attempts()
 * - nc_server_ssh_endpt_set_auth_timeout()
 * - nc_server_ssh_endpt_add_authkey()
 * - nc_server_ssh_endpt_del_authkey()
 *
 *
 * TLS
 * ===
 *
 * TLS requires at least one endpoint too, but its options differ
 * significantly from the SSH ones, especially in the cert-to-name
 * options that TLS uses to derive usernames from client certificates.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_server_tls_add_endpt_listen()
 * - nc_server_tls_endpt_set_address()
 * - nc_server_tls_endpt_set_port()
 * - nc_server_tls_del_endpt()
 *
 * - nc_server_tls_endpt_set_cert()
 * - nc_server_tls_endpt_set_cert_path()
 * - nc_server_tls_endpt_set_key()
 * - nc_server_tls_endpt_set_key_path()
 * - nc_server_tls_endpt_add_trusted_cert()
 * - nc_server_tls_endpt_add_trusted_cert_path()
 * - nc_server_tls_endpt_set_trusted_ca_paths()
 * - nc_server_tls_endpt_clear_certs()
 * - nc_server_tls_endpt_set_crl_paths()
 * - nc_server_tls_endpt_clear_crls()
 * - nc_server_tls_endpt_add_ctn()
 * - nc_server_tls_endpt_del_ctn()
 *
 * FD
 * ==
 *
 * If you used a tunneling software, which does its own authentication,
 * you can accept a NETCONF session on its file descriptors.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_accept_inout()
 *
 *
 * Call Home
 * =========
 *
 * Call Home does not work with endpoints like standard sessions.
 * The options must be reset manually after another Call Home session
 * (with different options than the previous one) is to be established.
 * Also, monitoring of these sessions is up to the application.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_connect_callhome_ssh()
 * - nc_connect_callhome_tls()
 *
 * - nc_server_ssh_ch_set_hostkey()
 * - nc_server_ssh_ch_set_banner()
 * - nc_server_ssh_ch_set_auth_methods()
 * - nc_server_ssh_ch_set_auth_attempts()
 * - nc_server_ssh_ch_set_auth_timeout()
 * - nc_server_ssh_ch_add_authkey()
 * - nc_server_ssh_ch_del_authkey()
 * - nc_server_ssh_ch_clear_opts()
 *
 * - nc_server_tls_ch_set_cert()
 * - nc_server_tls_ch_set_cert_path()
 * - nc_server_tls_ch_set_key()
 * - nc_server_tls_ch_set_key_path()
 * - nc_server_tls_ch_add_trusted_cert()
 * - nc_server_tls_ch_add_trusted_cert_path()
 * - nc_server_tls_ch_set_trusted_ca_paths()
 * - nc_server_tls_ch_clear_certs()
 * - nc_server_tls_ch_set_crl_paths()
 * - nc_server_tls_ch_clear_crls()
 * - nc_server_tls_ch_add_ctn()
 * - nc_server_tls_ch_del_ctn()
 * - nc_server_tls_ch_clear_opts()
 *
 *
 * Connecting And Cleanup
 * ======================
 *
 * When accepting connections, all the endpoints are examined
 * and the first with a pending connection is used. To remove all
 * the endpoints and free any used dynamic memory, destroy the server.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_accept()
 *
 * - nc_server_destroy()
 */

/**
 * @page howtoclientcomm Client communication
 *
 * To send RPCs on a session, you simply create an RPC, send it,
 * and then wait for a reply. If you are subscribed, there are 2 ways
 * of receiving notifications. Either you wait for them the same way
 * as for standard replies or you create a dispatcher that asynchronously
 * (in a separate thread) reads notifications and passes them to your
 * callback.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_client.h__.
 *
 * - nc_rpc_generic()
 * - nc_rpc_generic_xml()
 * - nc_rpc_getconfig()
 * - nc_rpc_edit()
 * - nc_rpc_copy()
 * - nc_rpc_delete()
 * - nc_rpc_lock()
 * - nc_rpc_unlock()
 * - nc_rpc_get()
 * - nc_rpc_kill()
 * - nc_rpc_commit()
 * - nc_rpc_discard()
 * - nc_rpc_cancel()
 * - nc_rpc_validate()
 * - nc_rpc_getschema()
 * - nc_rpc_subscribe()
 *
 * - nc_send_rpc()
 * - nc_recv_reply()
 * - nc_recv_notif()
 * - nc_recv_notif_dispatch()
 */

/**
 * @page howtoservercomm Server communication
 *
 * Once at least one session is established, an nc_pollsession structure
 * should be created, filled with the session and polled. Based on
 * the return value from the poll further actions can be taken. More
 * sessions can be polled at the same time. Any requests received on
 * the sessions are [handled internally](@ref howtoserver).
 *
 * Functions List
 * --------------
 *
 * Available in __nc_client.h__.
 *
 * - nc_ps_new()
 * - nc_ps_add_session()
 * - nc_ps_del_session()
 * - nc_ps_session_count()
 * - nc_ps_free()
 *
 * - nc_ps_poll()
 * - nc_ps_clear()
 * - nc_ps_accept_ssh_channel()
 */

#endif /* NC_LIBNETCONF_H_ */
