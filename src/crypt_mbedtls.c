/**
 * @file crypt_mbedtls.c
 * @author Petr Hanzlik <Petr.Hanzlik@cesnet.cz>
 * @brief libnetconf2 - mbed TLS digest backend for password hashing
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

#include <mbedtls/md.h>
#include <stdlib.h>

#include "crypt_p.h"

/**
 * @brief Get the mbed TLS message digest for an algorithm.
 *
 * @param[in] alg Algorithm.
 * @return mbed TLS digest, MBEDTLS_MD_NONE on unsupported algorithm.
 */
static mbedtls_md_type_t
nc_crypt_digest_md(enum nc_crypt_alg alg)
{
    switch (alg) {
    case NC_CRYPT_ALG_MD5:
        return MBEDTLS_MD_MD5;
    case NC_CRYPT_ALG_SHA256:
        return MBEDTLS_MD_SHA256;
    case NC_CRYPT_ALG_SHA512:
        return MBEDTLS_MD_SHA512;
    }

    return MBEDTLS_MD_NONE;
}

/**
 * @brief mbed TLS digest context together with the algorithm it is set up for.
 */
struct nc_crypt_mbedtls_ctx {
    mbedtls_md_context_t md;
    mbedtls_md_type_t type;
};

int
nc_crypt_digest_init(struct nc_crypt_digest *digest_ctx)
{
    struct nc_crypt_mbedtls_ctx *ctx = digest_ctx->ctx;
    const mbedtls_md_info_t *info;
    mbedtls_md_type_t type;
    int owned = digest_ctx->ctx != NULL;

    /* Get the mbed TLS digest for the algorithm */
    type = nc_crypt_digest_md(digest_ctx->alg);
    info = mbedtls_md_info_from_type(type);
    if (!info) {
        return 1;
    }

    /* Create a new context if not already allocated */
    if (!owned) {
        /* Allocate memory for the context, use calloc instead of mbedtls_md_init */
        ctx = calloc(1, sizeof *ctx);
        if (!ctx) {
            return 1;
        }
    } else if (ctx->type != type) {
        /* The context is reused for a different algorithm, it must be set up again */
        mbedtls_md_free(&ctx->md);
        ctx->type = MBEDTLS_MD_NONE;
    }

    if (ctx->type == MBEDTLS_MD_NONE) {
        /* Setup the mbed TLS context with the selected algorithm */
        if (mbedtls_md_setup(&ctx->md, info, 0)) {
            mbedtls_md_free(&ctx->md);
            if (!owned) {
                free(ctx);
            }
            return 1;
        }
        ctx->type = type;
    }

    digest_ctx->size = mbedtls_md_get_size(info);
    digest_ctx->ctx = ctx;

    if (mbedtls_md_starts(&ctx->md)) {
        return 1;
    }

    return 0;
}

int
nc_crypt_digest_update(struct nc_crypt_digest *digest_ctx, const void *data, size_t len)
{
    struct nc_crypt_mbedtls_ctx *ctx = digest_ctx->ctx;

    if (mbedtls_md_update(&ctx->md, data, len)) {
        return 1;
    }

    return 0;
}

int
nc_crypt_digest_final(struct nc_crypt_digest *digest_ctx, void *out)
{
    struct nc_crypt_mbedtls_ctx *ctx = digest_ctx->ctx;

    if (mbedtls_md_finish(&ctx->md, out)) {
        return 1;
    }

    return 0;
}

void
nc_crypt_digest_cleanup(struct nc_crypt_digest *digest_ctx)
{
    struct nc_crypt_mbedtls_ctx *ctx = digest_ctx->ctx;

    if (ctx) {
        mbedtls_md_free(&ctx->md);
        free(ctx);
    }
    digest_ctx->ctx = NULL;
}
