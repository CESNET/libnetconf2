/**
 * @file session_wrapper.h
 * @author Roman Janota <janota@cesnet.cz>
 * @brief libnetconf2 - header for wrapped TLS library function calls (currently OpenSSL and MbedTLS)
 *
 * @copyright
 * Copyright (c) 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _SESSION_WRAPPER_H_
#define _SESSION_WRAPPER_H_

#include <stdlib.h>

#include "config.h"

#ifdef HAVE_MBEDTLS

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt.h>

/**
 * @brief Context from which a TLS session may be created.
 */
struct nc_tls_ctx {
    int *sock;                          /**< Socket FD. */
    mbedtls_entropy_context *entropy;   /**< Entropy. */
    mbedtls_ctr_drbg_context *ctr_drbg; /**< Random bit generator. */
    mbedtls_x509_crt *cert;             /**< Certificate. */
    mbedtls_pk_context *pkey;           /**< Private key. */
    mbedtls_x509_crt *cert_store;       /**< CA certificates store. */
    mbedtls_x509_crl *crl_store;        /**< CRL store. */
};

#else

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/**
 * @brief Context from which a TLS session may be created.
 */
struct nc_tls_ctx {
    X509 *cert;             /**< Certificate. */
    EVP_PKEY *pkey;         /**< Private key. */
    X509_STORE *cert_store; /**< CA certificate store. */
    X509_STORE *crl_store;  /**< CRL store. */
};

#endif

/**
 * @brief Server side TLS verify callback data.
 */
struct nc_tls_verify_cb_data {
    struct nc_session *session;         /**< NETCONF session. */
    struct nc_server_tls_opts *opts;    /**< TLS server options. */
    void *chain;                        /**< Certificate chain used to verify the client cert. */
};

/**
 * @brief Creates a new TLS session from the given configuration.
 *
 * @param[in] tls_cfg TLS configuration.
 * @return New TLS session on success, NULL on fail.
 */
void * nc_tls_session_new_wrap(void *tls_cfg);

/**
 * @brief Destroys a TLS session.
 *
 * @param[in] tls_session TLS session to destroy.
 */
void nc_tls_session_destroy_wrap(void *tls_session);

/**
 * @brief Creates a new TLS configuration.
 *
 * @param[in] side Side of the TLS connection.
 * @return New TLS configuration on success, NULL on fail.
 */
void * nc_tls_config_new_wrap(int side);

/**
 * @brief Destroys a TLS configuration.
 *
 * @param[in] tls_cfg TLS configuration to destroy.
 */
void nc_tls_config_destroy_wrap(void *tls_cfg);

/**
 * @brief Creates a new TLS certificate.
 *
 * @return New TLS certificate on success, NULL on fail.
 */
void * nc_tls_cert_new_wrap(void);

/**
 * @brief Destroys a TLS certificate.
 *
 * @param[in] cert TLS certificate to destroy.
 */
void nc_tls_cert_destroy_wrap(void *cert);

/**
 * @brief Destroys a TLS private key.
 *
 * @param[in] pkey TLS private key to destroy.
 */
void nc_tls_privkey_destroy_wrap(void *pkey);

/**
 * @brief Creates a new TLS certificate store.
 *
 * @return New TLS certificate store on success, NULL on fail.
 */
void * nc_tls_cert_store_new_wrap(void);

/**
 * @brief Destroys a TLS certificate store.
 *
 * @param[in] cert_store TLS certificate store to destroy.
 */
void nc_tls_cert_store_destroy_wrap(void *cert_store);

/**
 * @brief Creates a new CRL store.
 *
 * @return New CRL store on success, NULL on fail.
 */
void * nc_tls_crl_store_new_wrap(void);

/**
 * @brief Destroys a CRL store.
 *
 * @param[in] crl_store CRL store to destroy.
 */
void nc_tls_crl_store_destroy_wrap(void *crl_store);

/**
 * @brief Converts PEM certificate data to a certificate.
 *
 * @param[in] cert_data PEM certificate data.
 * @return New certificate on success, NULL on fail.
 */
void * nc_tls_pem_to_cert_wrap(const char *cert_data);

/**
 * @brief Adds a certificate to a certificate store.
 *
 * @param[in] cert Certificate to add.
 * @param[in] cert_store Certificate store to add the certificate to.
 * @return 0 on success and the memory belongs to cert_store, non-zero on fail.
 */
int nc_tls_add_cert_to_store_wrap(void *cert, void *cert_store);

/**
 * @brief Converts PEM private key data to a private key.
 *
 * @param[in] privkey_data PEM private key data.
 * @return New private key on success, NULL on fail.
 */
void * nc_tls_pem_to_privkey_wrap(const char *privkey_data);

/**
 * @brief Parses and adds a CRL to a CRL store.
 *
 * @param[in] crl_data CRL data.
 * @param[in] size Size of the CRL data.
 * @param[in] crl_store CRL store to add the CRL to.
 * @return 0 on success, non-zero on fail.
 */
int nc_server_tls_add_crl_to_store_wrap(const unsigned char *crl_data, size_t size, void *crl_store);

/**
 * @brief Sets the TLS version.
 *
 * @param[in] tls_cfg TLS configuration.
 * @param[in] tls_versions Bit-field of supported TLS versions.
 *
 * @return 0 on success, non-zero on fail.
 */
int nc_server_tls_set_tls_versions_wrap(void *tls_cfg, unsigned int tls_versions);

/**
 * @brief Set TLS server's verify flags, verify cb and its data.
 *
 * @param[in] tls_cfg TLS configuration.
 * @param[in] cb_data Verify callback data.
 */
void nc_server_tls_set_verify_wrap(void *tls_cfg, struct nc_tls_verify_cb_data *cb_data);

/**
 * @brief Set TLS client's verify flags.
 *
 * @param[in] tls_cfg TLS configuration.
 */
void nc_client_tls_set_verify_wrap(void *tls_cfg);

/**
 * @brief Verify the certificate.
 *
 * @param[in] cert Certificate to verify.
 * @param[in] depth Certificate depth.
 * @param[in] trusted Boolean flag representing whether the certificate is trusted.
 * @param[in] cb_data Data for the verify callback.
 * @return 0 on success, 1 on verify fail, -1 on fatal error.
 */
int nc_server_tls_verify_cert(void *cert, int depth, int trusted, struct nc_tls_verify_cb_data *cb_data);

/**
 * @brief Check if the peer certificate matches any configured ee certs.
 *
 * @param[in] peer_cert Peer certificate.
 * @param[in] opts TLS options.
 * @return 0 on success, non-zero on fail.
 */
int nc_server_tls_verify_peer_cert(void *peer_cert, struct nc_server_tls_opts *opts);

/**
 * @brief Get the subject of the certificate.
 *
 * @param[in] cert Certificate.
 * @return Subject of the certificate on success, NULL on fail.
 */
char * nc_server_tls_get_subject_wrap(void *cert);

/**
 * @brief Get the issuer of the certificate.
 *
 * @param[in] cert Certificate.
 * @return Issuer of the certificate on success, NULL on fail.
 */
char * nc_server_tls_get_issuer_wrap(void *cert);

/**
 * @brief Get the Subject Alternative Names of the certificate.
 *
 * @param[in] cert Certificate.
 * @return SANs on success, NULL on fail.
 */
void * nc_tls_get_sans_wrap(void *cert);

/**
 * @brief Destroy the SANs.
 *
 * @param[in] sans SANs to destroy.
 */
void nc_tls_sans_destroy_wrap(void *sans);

/**
 * @brief Get the number of SANs.
 *
 * @param[in] sans SANs.
 * @return Number of SANs.
 */
int nc_tls_get_num_sans_wrap(void *sans);

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Get the SAN value and type in the context of CTN.
 *
 * @param[in] sans SANs.
 * @param[in] idx Index of the SAN.
 * @param[out] san_value SAN value.
 * @param[out] san_type SAN type.
 * @return 0 on success, non-zero on fail.
 */
int nc_tls_get_san_value_type_wrap(void *sans, int idx, char **san_value, NC_TLS_CTN_MAPTYPE *san_type);

#endif

/**
 * @brief Get the number of certificates in a certificate chain.
 *
 * @param[in] chain Certificate chain.
 * @return Number of certificates in the chain.
 */
int nc_tls_get_num_certs_wrap(void *chain);

/**
 * @brief Get a certificate from a certificate chain.
 *
 * @param[in] chain Certificate chain.
 * @param[in] idx Index of the certificate to get.
 * @param[out] cert Certificate.
 */
void nc_tls_get_cert_wrap(void *chain, int idx, void **cert);

/**
 * @brief Compare two certificates.
 *
 * @param[in] cert1 Certificate 1.
 * @param[in] cert2 Certificate 2.
 * @return 1 if the certificates match, 0 otherwise.
 */
int nc_server_tls_certs_match_wrap(void *cert1, void *cert2);

/**
 * @brief Get the MD5 digest of the certificate.
 *
 * @param[in] cert Certificate.
 * @param[out] buf Buffer for the digest.
 * @return 0 on success, non-zero on fail.
 */
int nc_server_tls_md5_wrap(void *cert, unsigned char *buf);

/**
 * @brief Get the SHA1 digest of the certificate.
 *
 * @param[in] cert Certificate.
 * @param[out] buf Buffer for the digest.
 * @return 0 on success, non-zero on fail.
 */
int nc_server_tls_sha1_wrap(void *cert, unsigned char *buf);

/**
 * @brief Get the SHA224 digest of the certificate.
 *
 * @param[in] cert Certificate.
 * @param[out] buf Buffer for the digest.
 * @return 0 on success, non-zero on fail.
 */
int nc_server_tls_sha224_wrap(void *cert, unsigned char *buf);

/**
 * @brief Get the SHA256 digest of the certificate.
 *
 * @param[in] cert Certificate.
 * @param[out] buf Buffer for the digest.
 * @return 0 on success, non-zero on fail.
 */
int nc_server_tls_sha256_wrap(void *cert, unsigned char *buf);

/**
 * @brief Get the SHA384 digest of the certificate.
 *
 * @param[in] cert Certificate.
 * @param[out] buf Buffer for the digest.
 * @return 0 on success, non-zero on fail.
 */
int nc_server_tls_sha384_wrap(void *cert, unsigned char *buf);

/**
 * @brief Get the SHA512 digest of the certificate.
 *
 * @param[in] cert Certificate.
 * @param[out] buf Buffer for the digest.
 * @return 0 on success, non-zero on fail.
 */
int nc_server_tls_sha512_wrap(void *cert, unsigned char *buf);

/**
 * @brief Set the FD for a TLS session.
 *
 * @param[in] tls_session TLS session.
 * @param[in] sock Socket FD.
 * @param[in] tls_ctx TLS context.
 */
void nc_server_tls_set_fd_wrap(void *tls_session, int sock, struct nc_tls_ctx *tls_ctx);

/**
 * @brief Perform a server-side step of the TLS handshake.
 *
 * @param[in] tls_session TLS session.
 * @return 1 on success, 0 if the handshake is not finished, negative number on error.
 */
int nc_server_tls_handshake_step_wrap(void *tls_session);

/**
 * @brief Perform a client-side step of the TLS handshake.
 *
 * @param[in] tls_session TLS session.
 * @param[in] sock Socket FD.
 * @return 1 on success, 0 if the handshake is not finished, negative number on error.
 */
int nc_client_tls_handshake_step_wrap(void *tls_session, int sock);

/**
 * @brief Destroy a TLS context.
 *
 * @param[in] tls_ctx TLS context.
 */
void nc_tls_ctx_destroy_wrap(struct nc_tls_ctx *tls_ctx);

/**
 * @brief Load client's certificate and a private key.
 *
 * @param[in] cert_path Path to the certificate.
 * @param[in] key_path Path to the private key.
 * @param[out] cert Certificate.
 * @param[out] pkey Private key.
 * @return 0 on success, non-zero on fail.
 */
int nc_client_tls_load_cert_key_wrap(const char *cert_path, const char *key_path, void **cert, void **pkey);

/**
 * @brief Load client's trusted certificates.
 *
 * @param[in] cert_store Certificate store.
 * @param[in] file_path Path to the file with trusted certificates.
 * @param[in] dir_path Path to the directory with trusted certificates.
 * @return 0 on success, non-zero on fail.
 */
int nc_client_tls_load_trusted_certs_wrap(void *cert_store, const char *file_path, const char *dir_path);

/**
 * @brief Set the hostname for the TLS session.
 *
 * @param[in] tls_session TLS session.
 * @param[in] hostname Hostname.
 * @return 0 on success, non-zero on fail.
 */
int nc_client_tls_set_hostname_wrap(void *tls_session, const char *hostname);

/**
 * @brief Initialize a TLS context.
 *
 * @param[in] sock Socket FD.
 * @param[in] cert Certificate.
 * @param[in] pkey Private key.
 * @param[in] cert_store Certificate store.
 * @param[in] crl_store CRL store.
 * @param[in,out] tls_ctx TLS context.
 * @return 0 on success, non-zero on fail.
 */
int nc_tls_init_ctx_wrap(int sock, void *cert, void *pkey, void *cert_store, void *crl_store, struct nc_tls_ctx *tls_ctx);

/**
 * @brief Setup a TLS configuration from a TLS context.
 *
 * @param[in] tls_ctx TLS context.
 * @param[in] side Side of the TLS connection.
 * @param[in,out] tls_cfg TLS configuration.
 * @return 0 on success, non-zero on fail.
 */
int nc_tls_setup_config_from_ctx_wrap(struct nc_tls_ctx *tls_ctx, int side, void *tls_cfg);

/**
 * @brief Get the error code from a TLS session's verification.
 *
 * @param[in] tls_session TLS session.
 * @return Error code, 0 indicates success.
 */
uint32_t nc_tls_get_verify_result_wrap(void *tls_session);

/**
 * @brief Get the error string from a TLS session's verification.
 *
 * @param[in] err_code Error code.
 * @return Error string.
 */
char * nc_tls_verify_error_string_wrap(uint32_t err_code);

/**
 * @brief Print the TLS session's connection error.
 *
 * @param[in] connect_ret Error code.
 * @param[in] peername Peername.
 * @param[in] tls_session TLS session.
 */
void nc_client_tls_print_connect_err_wrap(int connect_ret, const char *peername, void *tls_session);

/**
 * @brief Print the TLS session's accept error.
 *
 * @param[in] accept_ret Error code.
 * @param[in] tls_session TLS session.
 */
void nc_server_tls_print_accept_err_wrap(int accept_ret, void *tls_session);

/**
 * @brief Checks if the DER data is a SubjectPublicKeyInfo public key.
 *
 * @param[in] der DER data.
 * @param[in] len Length of the DER data.
 *
 * @return 1 if the data is a SubjectPublicKeyInfo public key, 0 if not, -1 on error.
 */
int nc_tls_is_der_subpubkey_wrap(unsigned char *der, long len);

/**
 * @brief Decodes base64 to binary.
 *
 * @param[in] base64 Base64 string.
 * @param[out] bin Binary result, memory managed by the caller.
 * @return Length of the binary data on success, -1 on error.
 */
int nc_base64_decode_wrap(const char *base64, unsigned char **bin);

/**
 * @brief Encodes binary to base64.
 *
 * @param[in] bin Binary data.
 * @param[in] len Length of the binary data.
 * @param[out] base64 NULL terminated Base64 result, memory managed by the caller.
 * @return 0 on success, -1 on error.
 */
int nc_base64_encode_wrap(const unsigned char *bin, size_t len, char **base64);

/**
 * @brief Reads data from a TLS session.
 *
 * @param[in] session NETCONF session.
 * @param[out] buf Buffer for the data.
 * @param[in] size Size of the buffer.
 * @return Number of bytes read on success, -1 on error.
 */
int nc_tls_read_wrap(struct nc_session *session, unsigned char *buf, size_t size);

/**
 * @brief Writes data to a TLS session.
 *
 * @param[in] session NETCONF session.
 * @param[in] buf Data to write.
 * @param[in] size Size of the data.
 * @return Number of bytes written on success, -1 on error.
 */
int nc_tls_write_wrap(struct nc_session *session, const unsigned char *buf, size_t size);

/**
 * @brief Get the number of pending bytes in a TLS session.
 *
 * @param[in] tls_session TLS session.
 * @return Number of pending bytes.
 */
int nc_tls_get_num_pending_bytes_wrap(void *tls_session);

/**
 * @brief Get the file descriptor of a TLS session.
 *
 * @param[in] session NETCONF session.
 * @return File descriptor, -1 on error.
 */
int nc_tls_get_fd_wrap(const struct nc_session *session);

/**
 * @brief Close a TLS session.
 *
 * @param[in] tls_session TLS session.
 */
void nc_tls_close_notify_wrap(void *tls_session);

/**
 * @brief Import a private key from a file.
 *
 * @param[in] privkey_path Path to the private key file.
 * @return Imported private key on success, NULL on fail.
 */
void * nc_tls_import_privkey_file_wrap(const char *privkey_path);

/**
 * @brief Import a certificate from a file.
 *
 * @param[in] cert_path Path to the certificate file.
 * @return Imported certificate on success, NULL on fail.
 */
void * nc_tls_import_cert_file_wrap(const char *cert_path);

/**
 * @brief Export a private key to a PEM string.
 *
 * @param[in] pkey Private key.
 * @return PEM string on success, NULL on fail.
 */
char * nc_tls_export_privkey_pem_wrap(void *pkey);

/**
 * @brief Export a certificate to a PEM string.
 *
 * @param[in] cert Certificate.
 * @return PEM string on success, NULL on fail.
 */
char * nc_tls_export_cert_pem_wrap(void *cert);

/**
 * @brief Export a public key to a PEM string.
 *
 * @param[in] pkey Public key.
 * @return PEM string on success, NULL on fail.
 */
char * nc_tls_export_pubkey_pem_wrap(void *pkey);

/**
 * @brief Check if a private key is RSA.
 *
 * @param[in] pkey Private key.
 * @return 1 if the private key is RSA, 0 if not.
 */
int nc_tls_privkey_is_rsa_wrap(void *pkey);

/**
 * @brief Get the RSA public key parameters from a private key.
 *
 * @param[in] pkey Private key.
 * @param[out] e Exponent.
 * @param[out] n Modulus.
 * @return 0 on success, non-zero on fail.
 */
int nc_tls_get_rsa_pubkey_params_wrap(void *pkey, void **e, void **n);

/**
 * @brief Destroy an MPI.
 *
 * @param[in] mpi MPI.
 */
void nc_tls_destroy_mpi_wrap(void *mpi);

/**
 * @brief Check if a private key is EC.
 *
 * @param[in] pkey Private key.
 * @return 1 if the private key is EC, 0 if not.
 */
int nc_tls_privkey_is_ec_wrap(void *pkey);

/**
 * @brief Get the group name of an EC private key.
 *
 * @param[in] pkey Private key.
 * @return Group name on success, NULL on fail.
 */
char * nc_tls_get_ec_group_wrap(void *pkey);

/**
 * @brief Get the EC public key parameters from a private key.
 *
 * @param[in] pkey Private key.
 * @param[out] q Public key point.
 * @param[out] q_grp Public key group.
 * @return 0 on success, non-zero on fail.
 */
int nc_tls_get_ec_pubkey_params_wrap(void *pkey, void **q, void **q_grp);

/**
 * @brief Convert an EC point to binary.
 *
 * @param[in] q EC point.
 * @param[in] q_grp EC group.
 * @param[out] bin Binary point.
 * @param[out] bin_len Length of the binary point.
 * @return 0 on success, non-zero on fail.
 */
int nc_tls_ec_point_to_bin_wrap(void *q, void *q_grp, unsigned char **bin, int *bin_len);

/**
 * @brief Destroy an EC point.
 *
 * @param[in] p EC point.
 */
void nc_tls_ec_point_destroy_wrap(void *p);

/**
 * @brief Destroy an EC group.
 *
 * @param[in] grp EC group.
 */
void nc_tls_ec_group_destroy_wrap(void *grp);

/**
 * @brief Convert an MPI to binary.
 *
 * @param[in] mpi MPI.
 * @param[out] bin Binary buffer.
 * @param[out] bin_len Length of the binary.
 * @return 0 on success, 1 on error.
 */
int nc_tls_mpi2bin_wrap(void *mpi, unsigned char **bin, int *bin_len);

/**
 * @brief Import a public key from a file.
 *
 * @param[in] pubkey_path Path to the public key file.
 * @return Imported public key on success, NULL on fail.
 */
void * nc_tls_import_pubkey_file_wrap(const char *pubkey_path);

/**
 * @brief Get all the URIs from the CRLDistributionPoints x509v3 extensions.
 *
 * @param[in] leaf_cert Server/client certificate.
 * @param[in] cert_store Certificate store.
 * @param[out] uris URIs to download the CRLs from.
 * @param[out] uri_count Number of URIs found.
 * @return 0 on success, non-zero on fail.
 */
int nc_server_tls_get_crl_distpoint_uris_wrap(void *leaf_cert, void *cert_store, char ***uris, int *uri_count);

/**
 * @brief Process a cipher suite so that it can be set by the underlying TLS lib.
 *
 * @param[in] cipher Cipher suite identity value.
 * @param[out] out Processed cipher suite.
 * @return 0 on success, 1 on fail.
 */
int nc_tls_process_cipher_suite_wrap(const char *cipher, char **out);

/**
 * @brief Append a cipher suite to the list of cipher suites.
 *
 * @param[in] opts TLS options.
 * @param[in] cipher_suite Cipher suite to append.
 * @return 0 on success, 1 on fail.
 */
int nc_tls_append_cipher_suite_wrap(struct nc_server_tls_opts *opts, const char *cipher_suite);

/**
 * @brief Set the list of cipher suites for the TLS configuration.
 *
 * @param[in] tls_cfg TLS configuration.
 * @param[in] cipher_suites List of cipher suites.
 */
void nc_server_tls_set_cipher_suites_wrap(void *tls_cfg, void *cipher_suites);

/**
 * @brief Get the certificate's expiration time.
 *
 * @param[in] cert Certificate.
 *
 * @return Calendar time of the expiration (it is in GMT) or -1 on error.
 */
time_t nc_tls_get_cert_exp_time_wrap(void *cert);

#endif
