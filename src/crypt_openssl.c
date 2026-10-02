/**
 * @file crypt_openssl.c
 * @author Petr Hanzlik <Petr.Hanzlik@cesnet.cz>
 * @brief libnetconf2 - OpenSSL digest backend for password hashing
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

#include <openssl/evp.h>

#include "crypt_p.h"

/**
 * @brief Get the EVP message digest for an algorithm.
 *
 * @param[in] alg Algorithm.
 * @return EVP digest, NULL on unsupported algorithm.
 */
static const EVP_MD *
nc_crypt_digest_md(enum nc_crypt_alg alg)
{
    switch (alg) {
    case NC_CRYPT_ALG_MD5:
        return EVP_md5();
    case NC_CRYPT_ALG_SHA256:
        return EVP_sha256();
    case NC_CRYPT_ALG_SHA512:
        return EVP_sha512();
    }

    return NULL;
}

int
nc_crypt_digest_init(struct nc_crypt_digest *digest_ctx)
{
    const EVP_MD *md;

    /* Get the EVP digest for the algorithm */
    md = nc_crypt_digest_md(digest_ctx->alg);
    if (!md) {
        return 1;
    }

    /* Create a new EVP_MD_CTX if not already allocated */
    if (!digest_ctx->ctx) {
        digest_ctx->ctx = EVP_MD_CTX_new();
        if (!digest_ctx->ctx) {
            return 1;
        }
    }

    /* Initialize the digest context with the selected algorithm */
    digest_ctx->size = EVP_MD_get_size(md);
    if (!EVP_DigestInit_ex(digest_ctx->ctx, md, NULL)) {
        return 1;
    }

    return 0;
}

int
nc_crypt_digest_update(struct nc_crypt_digest *digest_ctx, const void *data, size_t len)
{
    if (!EVP_DigestUpdate(digest_ctx->ctx, data, len)) {
        return 1;
    }

    return 0;
}

int
nc_crypt_digest_final(struct nc_crypt_digest *digest_ctx, void *out)
{
    if (!EVP_DigestFinal_ex(digest_ctx->ctx, out, NULL)) {
        return 1;
    }

    return 0;
}

void
nc_crypt_digest_cleanup(struct nc_crypt_digest *digest_ctx)
{
    EVP_MD_CTX_free(digest_ctx->ctx);
    digest_ctx->ctx = NULL;
}
