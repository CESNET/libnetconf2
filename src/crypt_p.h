/**
 * @file crypt_p.h
 * @author Petr Hanzlik <Petr.Hanzlik@cesnet.cz>
 * @brief libnetconf2 - password hashing core header
 *
 * @copyright
 * Copyright (c) 2026 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_CRYPT_P_H_
#define NC_CRYPT_P_H_

#include <stddef.h>

/**
 * @brief Recommended output buffer size.
 *
 * The longest possible output is "$6$rounds=999999999$" + 16 salt chars +
 * '$' + 86 digest chars + NUL = 124 bytes.
 */
#define NC_CRYPT_BUFSIZE 128

/**
 * @brief Actions for ::nc_crypt().
 */
enum nc_crypt_action {
    NC_CRYPT_CREATE,  /**< create a new hash from password and the setting salt */
    NC_CRYPT_VERIFY   /**< compare password against a full stored hash in setting */
};

/**
 * @brief Caller-owned input/output data for ::nc_crypt().
 */
struct nc_crypt {
    enum nc_crypt_action action; /**< action to perform */
    char *output;                 /**< caller-provided output buffer (may be NULL for VERIFY) */
    size_t output_len;            /**< capacity of output including terminating NUL */
    int match;                    /**< VERIFY result: 0 if password matches, 1 otherwise (always set, even on failure) */
};

/**
 * @brief Hash or verify a password in the "$<id>$" password hash format.
 *
 * Supported ids are "$1$" (MD5-crypt), "$5$" (SHA-256-crypt) and "$6$"
 * (SHA-512-crypt).
 *
 * The salt (CREATE and VERIFY) as well as the stored digest (VERIFY) must
 * consist only of the crypt base64 alphabet characters [a-zA-Z0-9./], the
 * same restriction the iana-crypt-hash YANG type puts on them. Any digest
 * stored in the setting is ignored for CREATE.
 *
 * @param[in] password Clear-text password.
 * @param[in] setting Setting string. For CREATE a salt prefix such as
 * "$6$[rounds=N$]<salt>$" (rounds only for "$5$"/"$6$"), for VERIFY the complete
 * stored hash "$6$[rounds=N$]<salt>$<digest>".
 * @param[in,out] crypt Operation selector and output data.
 * @return 0 on success.
 * @return -1 on invalid arguments.
 * @return -2 on unsupported hash id.
 * @return -3 on malformed setting (including invalid salt/digest characters).
 * @return -4 if the output buffer is too small.
 * @return -5 on internal (digest backend) failure.
 *
 * Note that some inputs accepted by the crypt(3) implementations are
 * deliberately rejected:
 * - salt characters outside the crypt base64 alphabet [a-zA-Z0-9./]
 *   (e.g. '=', which glibc tolerates in MD5-crypt salts), in line with
 *   the iana-crypt-hash YANG type;
 * - "rounds=" outside [1000, 999999999], the range defined by the
 *   SHA-crypt format (glibc clamps instead, but it always prints the
 *   clamped value, so glibc-generated hashes are never affected);
 * - settings without a "$<id>$" prefix (e.g. legacy DES hashes), which
 *   do not match any form allowed by the iana-crypt-hash YANG type.
 */
int nc_crypt(const char *password, const char *setting, struct nc_crypt *crypt);

/**
 * @brief Get a static description of an ::nc_crypt() error code.
 *
 * @param[in] err Error code returned by ::nc_crypt().
 * @return Static string describing the error.
 */
const char *nc_crypt_strerr(int err);

/**
 * @brief Digest algorithms of the supported schemes.
 */
enum nc_crypt_alg {
    NC_CRYPT_ALG_MD5,     /**< MD5, 16-byte digest */
    NC_CRYPT_ALG_SHA256,  /**< SHA-256, 32-byte digest */
    NC_CRYPT_ALG_SHA512   /**< SHA-512, 64-byte digest */
};

/**
 * @brief Digest context for one streaming hash computation.
 *
 * Implemented by the crypto backend (OpenSSL, mbedTLS), the algorithm core
 * uses it exclusively through ::nc_crypt_digest_init() and other functions.
 */
struct nc_crypt_digest {
    enum nc_crypt_alg alg; /**< algorithm to compute */
    size_t size;            /**< digest length in bytes */
    void *ctx;              /* backend-private state */
};

/**
 * @brief Start (or restart) a digest computation.
 *
 * @param[in,out] digest_ctx Digest with ::alg set. May be reused after a final.
 * @return 0 on success, non-zero on failure.
 */
int nc_crypt_digest_init(struct nc_crypt_digest *digest_ctx);

/**
 * @brief Append data to a digest computation.
 *
 * @param[in,out] digest_ctx Initialized digest.
 * @param[in] data Bytes to hash.
 * @param[in] len Number of bytes.
 * @return 0 on success, non-zero on failure.
 */
int nc_crypt_digest_update(struct nc_crypt_digest *digest_ctx, const void *data, size_t len);

/**
 * @brief Finish the computation and write the digest bytes.
 *
 * @param[in,out] digest_ctx Initialized digest.
 * @param[out] out Buffer for at least ::size bytes.
 * @return 0 on success, non-zero on failure.
 */
int nc_crypt_digest_final(struct nc_crypt_digest *digest_ctx, void *out);

/**
 * @brief Free all resources of a digest.
 *
 * @param[in,out] digest_ctx Digest to clean up.
 */
void nc_crypt_digest_cleanup(struct nc_crypt_digest *digest_ctx);

#endif /* NC_CRYPT_P_H_ */
