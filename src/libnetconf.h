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
 * RPC communication both server and client-side. Note that NETCONF datastore implementation
 * is not a part of this library. The library supports both NETCONF 1.0
 * ([RFC 4741](https://tools.ietf.org/html/rfc4741)) as well as NETCONF 1.1
 * ([RFC 6241](https://tools.ietf.org/html/rfc6241)).
 *
 * @section about-features Main Features
 *
 * - Creating SSH ([RFC 4742](https://tools.ietf.org/html/rfc4742), [RFC 6242](https://tools.ietf.org/html/rfc6242)),
 *   using [libssh](https://www.libssh.org/), or TLS ([RFC 7589](https://tools.ietf.org/html/rfc7589)),
 *   using [OpenSSL](https://www.openssl.org/), authenticated NETCONF sessions.
 * - Creating NETCONF sessions with a pre-established transport protocol
 *   (using this mechanism the communication can be tunneled through sshd(8), for instance).
 * - Creating NETCONF Call Home sessions ([RFC 8071](https://tools.ietf.org/html/rfc8071)).
 * - Creating, sending, receiving, and replying to RPCs ([RFC 4741](https://tools.ietf.org/html/rfc4741),
 *   [RFC 6241](https://tools.ietf.org/html/rfc6241)).
 * - Creating, sending and receiving NETCONF Event Notifications ([RFC 5277](https://tools.ietf.org/html/rfc5277)),
 *
 * @section about-license License
 *
 * Copyright (c) 2015-2017 CESNET, z.s.p.o.
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
 * - @subpage howtotimeouts
 */

/**
 * @page howtoinit Init and Thread-safety Information
 *
 * Before working with the library, it must be initialized using nc_client_init()
 * or nc_server_init(). Based on how the library was compiled, also _libssh_ and/or
 * _libssh_/_libcrypto_ are initialized (for multi-threaded use) too. To prevent
 * any reachable memory at the end of your application, there are complementary
 * destroy functions (nc_server_destroy() and nc_client_destroy() available. If your
 * application is multi-threaded, call the destroy functions in the main thread,
 * after all the other threads have ended. In every other thread you should call
 * nc_thread_destroy() just before it exits.
 *
 * If _libnetconf2_ is used in accordance with this information, there should
 * not be memory leaks of any kind at program exit. For thread-safety details
 * of _libssh_, _libssl_, and _libcrypto_, please refer to the corresponding project
 * documentation. _libnetconf2_ thread-safety information is below.
 *
 * Client
 * ------
 *
 * Optionally, a client can specify two alternative ways to get schemas needed when connecting
 * with a server. The primary way is to read local files in searchpath (and its subdirectories)
 * specified via nc_client_set_schema_searchpath(). Alternatively, _libnetconf2_ can use callback
 * provided via nc_client_set_schema_callback(). If these ways do not succeed and the server
 * implements NETCONF \<get-schema\> operation, the schema is retrieved from the server and stored
 * localy into the searchpath (if specified) for a future use. If none of these methods succeed to
 * load particular schema, the data from this schema are ignored during the communication with the
 * server.
 *
 * Besides the mentioned setters, there are many other @ref howtoclientssh "SSH", @ref howtoclienttls "TLS"
 * and @ref howtoclientch "Call Home" getter/setter functions to manipulate with various settings. All these
 * settings are internally placed in a thread-specific context so they are independent and
 * initialized to the default values within each new thread. However, the context can be shared among
 * the threads using nc_client_get_thread_context() and nc_client_set_thread_context() functions. In such
 * a case, be careful and avoid concurrent execution of the mentioned setters/getters and functions
 * creating connection (no matter if it is a standard NETCONF connection or Call Home).
 *
 * In the client, it is thread-safe to work with distinguish NETCONF sessions since the client
 * settings are thread-specific as described above.
 *
 * Server
 * ------
 *
 * Server is __FULLY__ thread-safe meaning you can set all the (thread-shared in contrast to
 * client) options simultaneously while listening for or accepting new sessions or
 * polling the existing ones. It is even safe to poll one session in several
 * pollsession structures or one pollsession structure in several threads. Generally,
 * servers can use more threads without any problems as long as they keep their workflow sane
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
 * - nc_client_get_schema_searchpath()
 * - nc_client_set_schema_searchpath()
 * - nc_client_get_schema_callback()
 * - nc_client_set_schema_callback()
 *
 * - nc_client_get_thread_context()
 * - nc_client_set_thread_context()
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
 * To connect to a NETCONF server, a NETCONF session must be established,
 * which requires a working transport session. It is possible to create
 * NETCONF sessions with SSH (using _libssh_) or TLS (using _libssl/libcrypto_)
 * as the underlying transport protocol. It is also possible to establish
 * the transport protocol outside _libnetconf2_ and then provide these file
 * descriptors (FD) for full NETCONF session creation.
 *
 * There are a lot of options for both an SSH and a TLS client. All of them
 * have setters and getters so that there is no need to duplicate them in
 * a client.
 *
 * @anchor howtoclientssh
 * SSH
 * ===
 *
 * Connecting to a server using SSH does not strictly require to set any
 * options, there are sensible default values for all the basic ones.
 * Except all the SSH options, optionally some authetication callbacks can be set,
 * which are particulary useful in automated clients (passwords cannot be
 * asked a user) or simply if any additional information is retrieved some
 * other way than from standard terminal input.
 *
 * Having the default options or changing any unsuitable ones, there are 2 functions
 * to use for a new server connection. nc_connect_ssh() is the standard function
 * that creates sessions using the set options. If there are some options, which
 * cannot be changed with the provided API, there is nc_connect_libssh() available.
 * It requires a _libssh_ session, in which all the SSH options can be modified
 * and even the connection established. This allows for full customization and
 * should fit any specific situation.
 *
 * New NETCONF sessions can also be created on existing authenticated SSH sessions.
 * There is a new SSH channel needed, on which the NETCONF session is then created.
 * Use nc_connect_ssh_channel() for this purpose.
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
 * @anchor howtoclienttls
 * TLS
 * ===
 *
 * To connect to a server using TLS, there must be some client identification
 * options set. Client must specify its certificate with a private key using
 * nc_client_tls_set_cert_key_paths(). Also, the Certificate Authority of
 * a server certificate must be considered trusted. Paths to all the trusted
 * CA certificates can be set by nc_client_tls_set_trusted_ca_paths().
 *
 * Then there are again 2 functions for connecting, nc_connect_tls() being
 * the standard way of connecting. nc_connect_libssl() again enables
 * to customize the TLS session in every way _libssl_ allows.
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
 * can pass its file descriptors to _libnetconf2_ using nc_connect_inout(),
 * which will continue to establish a full NETCONF session.
 *
 * Funtions List
 * -------------
 *
 * Available in __nc_client.h__.
 *
 * - nc_connect_inout()
 *
 *
 * @anchor howtoclientch
 * Call Home
 * =========
 *
 * Call Home needs the same options set as standard SSH or TLS and the functions
 * reflect it exactly. However, to accept a connection, the client must first
 * specify addresses and ports, which to listen on by nc_client_ssh_ch_add_bind_listen()
 * and nc_client_tls_ch_add_bind_listen(). Then connections can be
 * accepted using nc_accept_callhome().
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
 * allocated memory. They are freed as a part of [destroying the client](@ref howtoinit).
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
 * cannot be learnt from the context are set with separate functions
 * nc_server_set_capab_withdefaults() and generally nc_server_set_capability().
 * Timeout for receiving the _hello_ message on a new session can be set
 * by nc_server_set_hello_timeout() and the timeout for disconnecting
 * an inactive session by nc_server_set_idle_timeout().
 *
 * Context does not only determine server modules, but its overall
 * functionality as well. For every RPC the server should support,
 * an nc_rpc_clb callback should be set on that node in the context using nc_set_rpc_callback().
 * Server then calls these as appropriate [during poll](@ref howtoservercomm).
 *
 * Just like in the [client](@ref howtoclient), you can let _libnetconf2_
 * establish SSH or TLS transport or do it yourself and only provide the file
 * descriptors of the connection.
 *
 * Server options can be only set, there are no getters.
 *
 * To be able to accept any connections, endpoints must first be added
 * with nc_server_add_endpt() and configured with nc_server_endpt_set_address()
 * and nc_server_endpt_set_port().
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_server_set_capab_withdefaults()
 * - nc_server_set_capability()
 * - nc_server_set_hello_timeout()
 * - nc_server_set_idle_timeout()
 *
 * - nc_server_add_endpt()
 * - nc_server_del_endpt()
 * - nc_server_endpt_set_address()
 * - nc_server_endpt_set_port()
 *
 *
 * SSH
 * ===
 *
 * To successfully accept an SSH session you must set at least the host key using
 * nc_server_ssh_endpt_add_hostkey(), which are ordered. This way you simply add
 * some hostkey identifier, but the key itself will be retrieved always when needed
 * by calling the callback set by nc_server_ssh_set_hostkey_clb().
 *
 * There are also some other optional settings. Note that authorized
 * public keys are set for the server as a whole, not endpoint-specifically.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_server_ssh_endpt_add_hostkey()
 * - nc_server_ssh_endpt_del_hostkey()
 * - nc_server_ssh_endpt_mov_hostkey()
 * - nc_server_ssh_endpt_mod_hostkey()
 * - nc_server_ssh_endpt_set_banner()
 * - nc_server_ssh_endpt_set_auth_methods()
 * - nc_server_ssh_endpt_set_auth_attempts()
 * - nc_server_ssh_endpt_set_auth_timeout()
 *
 * - nc_server_ssh_set_hostkey_clb()
 *
 * - nc_server_ssh_add_authkey()
 * - nc_server_ssh_add_authkey_path()
 * - nc_server_ssh_del_authkey()
 *
 *
 * TLS
 * ===
 *
 * TLS works with endpoints too, but its options differ
 * significantly from the SSH ones, especially in the _cert-to-name_
 * options that TLS uses to derive usernames from client certificates.
 * So, after starting listening on an endpoint  you need to set the server
 * certificate (nc_server_tls_endpt_set_server_cert()). Its actual content
 * together with the matching private key will be loaded using a callback
 * from nc_server_tls_set_server_cert_clb(). Additional certificates needed
 * for the client to verify the server's certificate chain can be loaded using
 * a callback from nc_server_tls_set_server_cert_chain_clb().
 *
 * To accept client certificates, they must first be considered trusted,
 * which you have three ways of achieving. You can add each of their Certificate Authority
 * certificates to the trusted ones or mark a specific client certificate
 * as trusted. Lastly, you can set paths with all the trusted CA certificates
 * with nc_server_tls_endpt_set_trusted_ca_paths(). Adding specific certificates
 * is also performed only as an arbitrary identificator and later retrieved from
 * callback set by nc_server_tls_set_trusted_cert_list_clb(). But, you can add
 * certficates as whole lists, not one-by-one.
 *
 * Then, from each trusted client certificate a username must be derived
 * for the NETCONF session. This is accomplished by finding a matching
 * _cert-to-name_ entry. They are added using nc_server_tls_endpt_add_ctn().
 *
 * If you need to remove trusted certificates, you can do so with nc_server_tls_endpt_del_trusted_cert_list().
 * To clear all Certificate Revocation Lists use nc_server_tls_endpt_clear_crls().
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_server_tls_endpt_set_server_cert()
 * - nc_server_tls_endpt_add_trusted_cert_list()
 * - nc_server_tls_endpt_del_trusted_cert_list()
 * - nc_server_tls_endpt_set_trusted_ca_paths()
 * - nc_server_tls_endpt_set_crl_paths()
 * - nc_server_tls_endpt_clear_crls()
 * - nc_server_tls_endpt_add_ctn()
 * - nc_server_tls_endpt_del_ctn()
 * - nc_server_tls_endpt_get_ctn()
 *
 * - nc_server_tls_set_server_cert_clb()
 * - nc_server_tls_set_server_cert_chain_clb()
 * - nc_server_tls_set_trusted_cert_list_clb()
 *
 * FD
 * ==
 *
 * If you used a tunneling software, which does its own authentication,
 * you can accept a NETCONF session on its file descriptors with
 * nc_accept_inout().
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
 * _Call Home_ works with endpoints just like standard sessions, but
 * the options are organized a bit differently and endpoints are added
 * for CH clients. However, one important difference is that
 * once all the mandatory options are set, _libnetconf2_ __will not__
 * immediately start connecting to a client. It will do so only after
 * calling nc_connect_ch_client_dispatch() in a separate thread.
 *
 * Lastly, monitoring of these sessions is up to the application.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_server_ch_add_client()
 * - nc_server_ch_del_client()
 * - nc_server_ch_client_add_endpt()
 * - nc_server_ch_client_del_endpt()
 * - nc_server_ch_client_endpt_set_address()
 * - nc_server_ch_client_endpt_set_port()
 * - nc_server_ch_client_set_conn_type()
 * - nc_server_ch_client_persist_set_idle_timeout()
 * - nc_server_ch_client_persist_set_keep_alive_max_wait()
 * - nc_server_ch_client_persist_set_keep_alive_max_attempts()
 * - nc_server_ch_client_period_set_idle_timeout()
 * - nc_server_ch_client_period_set_reconnect_timeout()
 * - nc_server_ch_client_set_start_with()
 * - nc_server_ch_client_set_max_attempts()
 * - nc_connect_ch_client_dispatch()
 *
 * - nc_server_ssh_ch_client_add_hostkey()
 * - nc_server_ssh_ch_client_del_hostkey()
 * - nc_server_ssh_ch_client_mov_hostkey()
 * - nc_server_ssh_ch_client_mod_hostkey()
 * - nc_server_ssh_ch_client_set_banner()
 * - nc_server_ssh_ch_client_set_auth_methods()
 * - nc_server_ssh_ch_client_set_auth_attempts()
 * - nc_server_ssh_ch_client_set_auth_timeout()
 *
 * - nc_server_tls_ch_client_set_server_cert()
 * - nc_server_tls_ch_client_add_trusted_cert_list()
 * - nc_server_tls_ch_client_del_trusted_cert_list()
 * - nc_server_tls_ch_client_set_trusted_ca_paths()
 * - nc_server_tls_ch_client_set_crl_paths()
 * - nc_server_tls_ch_client_clear_crls()
 * - nc_server_tls_ch_client_add_ctn()
 * - nc_server_tls_ch_client_del_ctn()
 * - nc_server_tls_ch_client_get_ctn()
 *
 *
 * Connecting And Cleanup
 * ======================
 *
 * When accepting connections with nc_accept(), all the endpoints are examined
 * and the first with a pending connection is used. To remove all CH clients,
 * endpoints, and free any used dynamic memory, [destroy](@ref howtoinit) the server.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_accept()
 */

/**
 * @page howtoclientcomm Client communication
 *
 * To send RPCs on a session, you simply create an RPC, send it using nc_send_rpc(),
 * and then wait for a reply using nc_recv_reply(). If you are subscribed, there are 2 ways
 * of receiving notifications. Either you wait for them the same way
 * as for standard replies with nc_recv_notif() or you create a dispatcher
 * with nc_recv_notif_dispatch() that asynchronously (in a separate thread)
 * reads notifications and passes them to your callback.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_client.h__.
 *
 * - nc_rpc_act_generic()
 * - nc_rpc_act_generic_xml()
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
 * should be created with nc_ps_new(), filled with the session using
 * nc_ps_add_session() and finally polled with nc_ps_poll(). Based on
 * the return value from the poll, further actions can be taken. More
 * sessions can be polled at the same time and any requests received on
 * the sessions are [handled internally](@ref howtoserver).
 *
 * If an SSH NETCONF session asks for a new channel, you can accept
 * this request with nc_ps_accept_ssh_channel() or nc_session_accept_ssh_channel()
 * depending on the structure you want to use as the argument.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
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
 * - nc_session_accept_ssh_channel()
 */

/**
 * @page howtotimeouts Timeouts
 *
 * There are several timeouts which are used throughout _libnetconf2_ to
 * assure that it will never indefinitely hang on any operation. Normally,
 * you should not need to worry about them much necause they are set by
 * default to reasonable values for common systems. However, if your
 * platform is not common (embedded, ...), adjusting these timeouts may
 * save a lot of debugging and time.
 *
 * Compile Options
 * ---------------
 *
 * You can adjust active and inactive read timeout using `cmake` variables.
 * For details look into `README.md`.
 *
 * API Functions
 * -------------
 *
 * Once a new connection is established including transport protocol negotiations,
 * _hello_ message is exchanged. You can set how long will the server wait for
 * receiving this message from a client before dropping it.
 *
 * Having a NETCONF session working, it may not communicate for a longer time.
 * To free up some resources, it is possible to adjust the maximum idle period
 * of a session before it is disconnected. In _Call Home_, for both a persistent
 * and periodic connection can this idle timeout be specified separately for each
 * client using corresponding functions.
 *
 * Lastly, SSH user authentication timeout can be also modified. It is the time
 * a client has to successfully authenticate after connecting before it is disconnected.
 *
 * Functions List
 * --------------
 *
 * Available in __nc_server.h__.
 *
 * - nc_server_set_hello_timeout()
 * - nc_server_set_idle_timeout()
 * - nc_server_ch_client_persist_set_idle_timeout()
 * - nc_server_ch_client_period_set_idle_timeout()
 * - nc_server_ch_client_period_set_reconnect_timeout()
 * - nc_server_ssh_endpt_set_auth_timeout()
 * - nc_server_ssh_ch_client_set_auth_timeout()
 */

/**
 * @defgroup misc Miscellaneous
 * @brief Miscellaneous macros, types, structure and functions for a generic use by both server and client applications.
 */

/**
 * @defgroup client Client
 * @brief NETCONF client functionality.
 */

/**
 * @defgroup server Server
 * @brief NETCONF server functionality.
 */

#endif /* NC_LIBNETCONF_H_ */
