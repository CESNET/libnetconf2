
#ifndef _SESSION_WRAPPER_H_
#define _SESSION_WRAPPER_H_

#include <stdlib.h>

#include "config.h"

#ifdef HAVE_LIBMBEDTLS

#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>

struct nc_tls_ctx {
	int *sock;
    mbedtls_entropy_context *entropy;
    mbedtls_ctr_drbg_context *ctr_drbg;
    mbedtls_x509_crt *cert;
    mbedtls_pk_context *pkey;
    mbedtls_x509_crt *cert_store;
    mbedtls_x509_crl *crl_store;
};

#else

#include <openssl/ssh.h>

struct nc_tls_ctx {
	char dummy[0];
};

#endif

struct nc_server_opts;

struct nc_tls_verify_cb_data {
    struct nc_session *session;
    struct nc_cert_grouping *ee_certs;
    struct nc_cert_grouping *referenced_ee_certs;
    struct nc_server_tls_opts *opts;
    struct nc_ctn_data {
    	char *username;
    	int matched_ctns;
    	int matched_ctn_type[6];
    	int matched_ctn_count;
    } ctn_data;
};

void * nc_tls_session_new_wrap(void *tls_cfg);

void nc_tls_session_destroy_wrap(void *tls_session);

void * nc_server_tls_config_new_wrap();

void * nc_client_tls_config_new_wrap();

void nc_tls_config_destroy_wrap(void *tls_cfg);

void * nc_tls_cert_new_wrap();

void nc_tls_cert_destroy_wrap(void *cert);

void * nc_tls_privkey_new_wrap();

void nc_tls_privkey_destroy_wrap(void *pkey);

void * nc_tls_cert_store_new_wrap();

void nc_tls_cert_store_destroy_wrap(void *cert_store);

void * nc_tls_crl_store_new_wrap();

void nc_tls_crl_store_destroy_wrap(void *crl);

void nc_tls_set_authmode_wrap(void *tls_cfg);

int nc_server_tls_set_config_defaults_wrap(void *tls_cfg);

void * nc_tls_pem_to_cert_wrap(const char *cert_data);

void * nc_tls_base64_to_cert_wrap(const char *cert_data);

int nc_tls_pem_to_cert_add_to_store_wrap(const char *cert_data, void *cert_store);

void * nc_tls_pem_to_privkey_wrap(const char *privkey_data);

int nc_tls_load_cert_private_key_wrap(void *tls_cfg, void *cert, void *pkey);

int nc_server_tls_crl_path_wrap(const char *crl_path, void *cert_store, void *crl_store);

int nc_server_tls_add_crl_to_store_wrap(const unsigned char *crl_data, size_t size, void *cert_store, void *crl_store);

void nc_server_tls_set_certs_wrap(void *tls_cfg, void *cert_store, void *crl_store);

int nc_server_tls_set_tls_versions_wrap(void *tls_cfg, unsigned int tls_versions);

void nc_server_tls_set_verify_cb_wrap(void *tls_session, struct nc_tls_verify_cb_data *cb_data);

int nc_server_tls_verify_cert(void *cert, int depth, int self_signed, struct nc_tls_verify_cb_data *cb_data);

char * nc_server_tls_get_subject_wrap(void *cert);

char * nc_server_tls_get_issuer_wrap(void *cert);

int nc_server_tls_get_username_from_cert_wrap(void *cert, NC_TLS_CTN_MAPTYPE map_type, char **username);

int nc_server_tls_certs_match_wrap(void *cert1, void *cert2);

int nc_server_tls_md5_wrap(void *cert, unsigned char *buf);

int nc_server_tls_sha1_wrap(void *cert, unsigned char *buf);

int nc_server_tls_sha224_wrap(void *cert, unsigned char *buf);

int nc_server_tls_sha256_wrap(void *cert, unsigned char *buf);

int nc_server_tls_sha384_wrap(void *cert, unsigned char *buf);

int nc_server_tls_sha512_wrap(void *cert, unsigned char *buf);

void nc_server_tls_set_fd_wrap(void *tls_session, int sock, struct nc_tls_ctx *tls_ctx);

int nc_server_tls_handshake_step_wrap(void *tls_session);

int nc_server_tls_fill_config_wrap(void *tls_cfg, void *srv_cert, void *srv_pkey, void *cert_store, void *crl_store, struct nc_tls_ctx *tls_ctx);

int nc_server_tls_setup_config_fill_ctx_wrap(void *tls_cfg, struct nc_tls_ctx *tls_ctx, void *srv_cert, void *srv_pkey, void *cert_store, void *crl_store, int sock);

void nc_tls_ctx_destroy_wrap(struct nc_tls_ctx *tls_ctx);

int nc_client_tls_load_cert_key_wrap(const char *cert_path, const char *key_path, void **cert, void **pkey);

int nc_client_tls_load_trusted_certs_wrap(void *cert_store, const char *file_path, const char *dir_path);

int nc_client_tls_load_crl_wrap(void *cert_store, void *crl_store, const char *file_path, const char *dir_path);

int nc_client_tls_set_hostname_wrap(void *tls_session, const char *hostname);

int nc_client_tls_handshake_step_wrap(void *tls_session);

uint32_t nc_tls_get_verify_result_wrap(void *tls_session);

const char * nc_tls_verify_error_string_wrap(uint32_t err_code);

void nc_tls_print_error_string_wrap(int connect_ret, const char *peername, void *tls_session);

void nc_server_tls_print_accept_error_wrap(int accept_ret, void *tls_session);

int nc_tls_init_ctx_wrap(struct nc_tls_ctx *tls_ctx, int sock, void *cli_cert, void *cli_pkey, void *cert_store, void *crl_store);

int nc_tls_setup_config_wrap(void *tls_cfg, int side, struct nc_tls_ctx *tls_ctx);

void nc_tls_session_new_cleanup_wrap(void *tls_cfg, void *cli_cert, void *cli_pkey, void *cert_store, void *crl_store);

int nc_der_to_pubkey_wrap(const unsigned char *der, long len);

/**
 * @brief Decodes base64 to binary.
 *
 * @param[in] base64 Base64 string.
 * @param[out] bin Binary result, memory managed by the caller.
 * @return Length of the binary data on success, -1 on error.
 */
int nc_base64_decode_wrap(const char *base64, char **bin);

int nc_base64_encode_wrap(const unsigned char *bin, size_t len, char **base64);

int nc_tls_read_wrap(struct nc_session *session, unsigned char *buf, size_t size);

int nc_tls_write_wrap(struct nc_session *session, const unsigned char *buf, size_t size);

int nc_tls_have_pending_wrap(void *tls_session);

int nc_tls_get_fd_wrap(const struct nc_session *session);

void nc_tls_close_notify_wrap(void *tls_session);

void * nc_tls_import_key_file_wrap(const char *key_path, FILE *file);

void * nc_tls_import_cert_file_wrap(const char *cert_path);

char * nc_tls_export_key_wrap(void *pkey);

char * nc_tls_export_cert_wrap(void *cert);

int nc_tls_export_key_der_wrap(void *pkey, unsigned char **der, size_t *size);

int nc_tls_privkey_is_rsa_wrap(void *pkey);

int nc_tls_get_rsa_pubkey_params_wrap(void *pkey, void **e, void **n);

int nc_tls_privkey_is_ec_wrap(void *pkey);

char * nc_tls_get_ec_group_wrap(void *pkey);

int nc_tls_get_ec_pubkey_param_wrap(void *pkey, unsigned char **bin, int *bin_len);

int nc_tls_get_bn_num_bytes_wrap(void *bn);

void nc_tls_bn_bn2bin_wrap(void *bn, unsigned char *bin);

void * nc_tls_import_pubkey_file_wrap(const char *pubkey_path);

char * nc_tls_export_pubkey_wrap(void *pkey);

int nc_server_tls_get_crl_distpoint_uris_wrap(void *cert_store, char ***uris, int *uri_count);

#endif
