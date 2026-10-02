/**
 * @file crypt.c
 * @author Petr Hanzlik <Petr.Hanzlik@cesnet.cz>
 * @brief libnetconf2 - password hashing core
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

#include <stdlib.h>
#include <string.h>

#include "compat.h"
#include "crypt_p.h"
#include "log_p.h"

/** salt length limits defined by the formats */
#define NC_CRYPT_MD5_SALT_MAX 8
#define NC_CRYPT_SHA_SALT_MAX 16

/** SHA-crypt "rounds=" limits, part of the format */
#define NC_CRYPT_SHA_ROUNDS_MIN 1000
#define NC_CRYPT_SHA_ROUNDS_MAX 999999999UL
#define NC_CRYPT_SHA_ROUNDS_DEFAULT 5000

/** number of MD5-crypt stretching rounds, fixed by the format */
#define NC_CRYPT_MD5_ROUNDS 1000

/** lengths of the base64-encoded digests */
#define NC_CRYPT_MD5_HASH_LEN 22
#define NC_CRYPT_SHA256_HASH_LEN 43
#define NC_CRYPT_SHA512_HASH_LEN 86

/**
 * @brief Base64 alphabet shared by the hashing schemes.
 */
static const char nc_crypt_b64tab[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/**
 * @brief Parsed setting string.
 */
struct nc_crypt_setting {
    enum nc_crypt_alg alg;                          /**< digest algorithm */
    unsigned long rounds;                           /**< SHA-crypt rounds */
    int rounds_custom;                              /**< "rounds=" was present in the setting */
    char salt[NC_CRYPT_SHA_SALT_MAX + 1];           /**< salt, truncated and NUL-terminated */
    size_t salt_len;                                /**< salt length */
    const char *stored;                             /**< stored digest part of the setting, NULL if absent */
};

/**
 * @brief Check that a string consists only of the crypt base64 alphabet characters.
 *
 * @param[in] str String to check.
 * @param[in] len Length of @p str.
 * @return 1 if all the characters are valid, 0 otherwise.
 */
static int
nc_crypt_valid_b64(const char *str, size_t len)
{
    size_t i;
    char c;

    for (i = 0; i < len; ++i) {
        c = str[i];
        if (((c < 'a') || (c > 'z')) && ((c < 'A') || (c > 'Z')) && ((c < '0') || (c > '9')) &&
                (c != '.') && (c != '/')) {
            return 0;
        }
    }

    return 1;
}

/**
 * @brief Zero a buffer in a way the compiler cannot optimize away.
 *
 * @param[in] p Buffer to zero.
 * @param[in] len Length of @p p.
 */
static void
nc_crypt_memzero(void *p, size_t len)
{
    volatile unsigned char *vp = p;
    size_t i;

    for (i = 0; i < len; ++i) {
        vp[i] = 0;
    }
}

/**
 * @brief Parse a setting string "$<id>$[rounds=N>$]<salt>[$<digest>]".
 *
 * @param[in] setting Setting to parse.
 * @param[out] set Parsed setting.
 * @return 0 on success.
 * @return -2 on unsupported hash id.
 * @return -3 on malformed setting.
 */
static int
nc_crypt_parse_setting(const char *setting, struct nc_crypt_setting *set)
{
    const char *p;
    char *end = NULL;
    unsigned long rounds;
    size_t salt_run_len, salt_max;

    if ((setting[0] != '$') || !setting[1] || !setting[2]) {
        WRN(NULL, "Setting is not a valid hash setting.");
        return -3;
    }
    if (setting[2] != '$') {
        WRN(NULL, "Hash id in the setting is not supported.");
        return -2;
    }

    /* parse the hash id */
    switch (setting[1]) {
    case '1':
        set->alg = NC_CRYPT_ALG_MD5;
        set->rounds = NC_CRYPT_MD5_ROUNDS;
        salt_max = NC_CRYPT_MD5_SALT_MAX;
        break;
    case '5':
        set->alg = NC_CRYPT_ALG_SHA256;
        set->rounds = NC_CRYPT_SHA_ROUNDS_DEFAULT;
        salt_max = NC_CRYPT_SHA_SALT_MAX;
        break;
    case '6':
        set->alg = NC_CRYPT_ALG_SHA512;
        set->rounds = NC_CRYPT_SHA_ROUNDS_DEFAULT;
        salt_max = NC_CRYPT_SHA_SALT_MAX;
        break;
    default:
        WRN(NULL, "Hash id \"$%c$\" is not supported.", setting[1]);
        return -2;
    }

    p = setting + 3;

    /* optional "rounds=<N>$" prefix of the SHA-crypt schemes */
    if (((set->alg == NC_CRYPT_ALG_SHA256) || (set->alg == NC_CRYPT_ALG_SHA512)) &&
            !strncmp(p, "rounds=", 7)) {

        rounds = strtoul(p + 7, &end, 10);
        if ((end == (p + 7)) || (*end != '$')) {
            WRN(NULL, "Invalid \"rounds=\" specification in the setting.");
            return -3;
        }
        if ((rounds < NC_CRYPT_SHA_ROUNDS_MIN) || (rounds > NC_CRYPT_SHA_ROUNDS_MAX)) {
            WRN(NULL, "\"rounds=%lu\" is out of range [%d, %lu].",
                    rounds, NC_CRYPT_SHA_ROUNDS_MIN, NC_CRYPT_SHA_ROUNDS_MAX);
            return -3;
        }
        set->rounds = rounds;
        set->rounds_custom = 1;
        p = end + 1;
    }

    /* parse the salt */
    salt_run_len = strcspn(p, "$");
    if ((salt_run_len > 0) && !nc_crypt_valid_b64(p, salt_run_len)) {
        WRN(NULL, "Invalid characters in the salt of the setting.");
        return -3;
    }
    set->salt_len = (salt_run_len < salt_max) ? salt_run_len : salt_max;
    memcpy(set->salt, p, set->salt_len);
    set->salt[set->salt_len] = '\0';

    if (p[salt_run_len] == '$') {
        /* everything after the salt is the stored digest (VERIFY target) */
        set->stored = p + salt_run_len + 1;
    }

    return 0;
}

/**
 * @brief Encode 3 bytes as up to 4 base64 characters.
 *
 * The 24 bits are consumed 6 at a time starting from the least significant
 * bit.
 *
 * @param[in,out] out Output position, advanced by @p nchars characters.
 * @param[in] b2 First byte, most significant in the 24-bit word.
 * @param[in] b1 Second byte.
 * @param[in] b0 Third byte, least significant in the 24-bit word.
 * @param[in] nchars Number of characters to emit (2-4).
 */
static void
nc_crypt_b64_group(char **out, unsigned char b2, unsigned char b1, unsigned char b0, int nchars)
{
    /* assemble one 24-bit word from the 3 bytes, b2 is the most significant
     * byte (the encode tables pass the first digest byte of a group as b2) */
    unsigned int w = ((unsigned int)b2 << 16) | ((unsigned int)b1 << 8) | b0;

    /* emit one character per 6 bits starting from the least significant bits,
     * the reverse of the standard base64 bit order; the final partial groups
     * pass their leftover bytes as b0/b1 so that all the significant bits
     * are covered by the emitted characters */
    while (nchars-- > 0) {
        *(*out)++ = nc_crypt_b64tab[w & 0x3f];
        w >>= 6;
    }
}

/**
 * @brief Encode a raw digest in the base64 variant of the given scheme.
 *
 * @param[in] alg Algorithm of the digest.
 * @param[in] digest Raw digest bytes.
 * @param[out] out Buffer for the encoded digest, NUL-terminated by the caller.
 */
static void
nc_crypt_encode(enum nc_crypt_alg alg, const unsigned char *digest, char *out)
{
    switch (alg) {
    case NC_CRYPT_ALG_MD5:
        nc_crypt_b64_group(&out, digest[0], digest[6], digest[12], 4);
        nc_crypt_b64_group(&out, digest[1], digest[7], digest[13], 4);
        nc_crypt_b64_group(&out, digest[2], digest[8], digest[14], 4);
        nc_crypt_b64_group(&out, digest[3], digest[9], digest[15], 4);
        nc_crypt_b64_group(&out, digest[4], digest[10], digest[5], 4);
        nc_crypt_b64_group(&out, 0, 0, digest[11], 2);
        break;
    case NC_CRYPT_ALG_SHA256:
        nc_crypt_b64_group(&out, digest[0], digest[10], digest[20], 4);
        nc_crypt_b64_group(&out, digest[21], digest[1], digest[11], 4);
        nc_crypt_b64_group(&out, digest[12], digest[22], digest[2], 4);
        nc_crypt_b64_group(&out, digest[3], digest[13], digest[23], 4);
        nc_crypt_b64_group(&out, digest[24], digest[4], digest[14], 4);
        nc_crypt_b64_group(&out, digest[15], digest[25], digest[5], 4);
        nc_crypt_b64_group(&out, digest[6], digest[16], digest[26], 4);
        nc_crypt_b64_group(&out, digest[27], digest[7], digest[17], 4);
        nc_crypt_b64_group(&out, digest[18], digest[28], digest[8], 4);
        nc_crypt_b64_group(&out, digest[9], digest[19], digest[29], 4);
        nc_crypt_b64_group(&out, 0, digest[31], digest[30], 3);
        break;
    case NC_CRYPT_ALG_SHA512:
        nc_crypt_b64_group(&out, digest[0], digest[21], digest[42], 4);
        nc_crypt_b64_group(&out, digest[22], digest[43], digest[1], 4);
        nc_crypt_b64_group(&out, digest[44], digest[2], digest[23], 4);
        nc_crypt_b64_group(&out, digest[3], digest[24], digest[45], 4);
        nc_crypt_b64_group(&out, digest[25], digest[46], digest[4], 4);
        nc_crypt_b64_group(&out, digest[47], digest[5], digest[26], 4);
        nc_crypt_b64_group(&out, digest[6], digest[27], digest[48], 4);
        nc_crypt_b64_group(&out, digest[28], digest[49], digest[7], 4);
        nc_crypt_b64_group(&out, digest[50], digest[8], digest[29], 4);
        nc_crypt_b64_group(&out, digest[9], digest[30], digest[51], 4);
        nc_crypt_b64_group(&out, digest[31], digest[52], digest[10], 4);
        nc_crypt_b64_group(&out, digest[53], digest[11], digest[32], 4);
        nc_crypt_b64_group(&out, digest[12], digest[33], digest[54], 4);
        nc_crypt_b64_group(&out, digest[34], digest[55], digest[13], 4);
        nc_crypt_b64_group(&out, digest[56], digest[14], digest[35], 4);
        nc_crypt_b64_group(&out, digest[15], digest[36], digest[57], 4);
        nc_crypt_b64_group(&out, digest[37], digest[58], digest[16], 4);
        nc_crypt_b64_group(&out, digest[59], digest[17], digest[38], 4);
        nc_crypt_b64_group(&out, digest[18], digest[39], digest[60], 4);
        nc_crypt_b64_group(&out, digest[40], digest[61], digest[19], 4);
        nc_crypt_b64_group(&out, digest[62], digest[20], digest[41], 4);
        nc_crypt_b64_group(&out, 0, 0, digest[63], 2);
        break;
    }
}

/**
 * @brief One operand of a stretching round.
 */
struct nc_crypt_feed {
    const void *data; /**< operand bytes */
    size_t len;       /**< operand length */
};

/**
 * @brief Run the stretching rounds.
 *
 * @param[in,out] digest_ctx Digest context with ::alg set, reused every round.
 * @param[in] pw_seq Password-derived byte sequence.
 * @param[in] pw_seq_len Length of @p pw_seq.
 * @param[in] salt_seq Salt-derived byte sequence.
 * @param[in] salt_seq_len Length of @p salt_seq.
 * @param[in,out] digest Digest from the preliminary phase, replaced every round.
 * @param[in] digest_len Digest length.
 * @param[in] rounds Number of rounds.
 * @return 0 on success, -5 on digest failure.
 */
static int
nc_crypt_stretch(struct nc_crypt_digest *digest_ctx, const void *pw_seq, size_t pw_seq_len,
        const void *salt_seq, size_t salt_seq_len, unsigned char *digest, size_t digest_len,
        unsigned long rounds)
{
    struct nc_crypt_feed feeds[4];
    int n;

    for (size_t i = 0; i < rounds; ++i) {
        feeds[0].data = (i & 1) ? pw_seq : digest;
        feeds[0].len = (i & 1) ? pw_seq_len : digest_len;

        n = 1;
        if (i % 3) {
            feeds[n].data = salt_seq;
            feeds[n].len = salt_seq_len;
            ++n;
        }
        if (i % 7) {
            feeds[n].data = pw_seq;
            feeds[n].len = pw_seq_len;
            ++n;
        }

        feeds[n].data = (i & 1) ? digest : pw_seq;
        feeds[n].len = (i & 1) ? digest_len : pw_seq_len;
        ++n;

        if (nc_crypt_digest_init(digest_ctx)) {
            return -5;
        }
        for (int j = 0; j < n; ++j) {
            if (nc_crypt_digest_update(digest_ctx, feeds[j].data, feeds[j].len)) {
                return -5;
            }
        }
        if (nc_crypt_digest_final(digest_ctx, digest)) {
            return -5;
        }
    }

    return 0;
}

/**
 * @brief Compute the raw MD5-crypt ("$1$") digest.
 *
 * @param[in] password Password.
 * @param[in] pw_len Password length.
 * @param[in] salt Salt, already truncated.
 * @param[in] salt_len Salt length.
 * @param[out] digest Resulting 16 bytes.
 * @return 0 on success, -5 on digest failure.
 */
static int
nc_crypt_md5_digest(const char *password, size_t pw_len, const char *salt, size_t salt_len,
        unsigned char digest[16])
{
    struct nc_crypt_digest digest_ctx = {0};
    unsigned char alt[16] = {0};
    int rc = 0;
    size_t n;

    digest_ctx.alg = NC_CRYPT_ALG_MD5;

    /* alternate sum B (password + salt + password) */
    if (nc_crypt_digest_init(&digest_ctx) ||
            nc_crypt_digest_update(&digest_ctx, password, pw_len) ||
            nc_crypt_digest_update(&digest_ctx, salt, salt_len) ||
            nc_crypt_digest_update(&digest_ctx, password, pw_len) ||
            nc_crypt_digest_final(&digest_ctx, alt)) {
        rc = -5;
        goto cleanup;
    }

    /* open digest A (password + "$1$" + salt) */
    if (nc_crypt_digest_init(&digest_ctx) ||
            nc_crypt_digest_update(&digest_ctx, password, pw_len) ||
            nc_crypt_digest_update(&digest_ctx, "$1$", 3) ||
            nc_crypt_digest_update(&digest_ctx, salt, salt_len)) {
        rc = -5;
        goto cleanup;
    }

    /* for every full 16 bytes of password length add B, then the first n bytes */
    for (n = pw_len; n > 16; n -= 16) {
        if (nc_crypt_digest_update(&digest_ctx, alt, 16)) {
            rc = -5;
            goto cleanup;
        }
    }
    if (nc_crypt_digest_update(&digest_ctx, alt, n)) {
        rc = -5;
        goto cleanup;
    }

    /* for every set bit of the password length a NUL byte, otherwise the first password byte */
    for (size_t i = pw_len; i; i >>= 1) {
        if (nc_crypt_digest_update(&digest_ctx, (i & 1) ? "" : password, 1)) {
            rc = -5;
            goto cleanup;
        }
    }

    if (nc_crypt_digest_final(&digest_ctx, digest)) {
        rc = -5;
        goto cleanup;
    }

    rc = nc_crypt_stretch(&digest_ctx, password, pw_len, salt, salt_len, digest, 16, NC_CRYPT_MD5_ROUNDS);

cleanup:
    /* the alternate sum is derived from the password */
    nc_crypt_memzero(alt, sizeof alt);
    nc_crypt_digest_cleanup(&digest_ctx);
    return rc;
}

/**
 * @brief Compute the raw SHA-crypt ("$5$"/"$6$") digest.
 *
 * @param[in] alg SHA256 or SHA512.
 * @param[in] password Password.
 * @param[in] pw_len Password length.
 * @param[in] salt Salt, already truncated.
 * @param[in] salt_len Salt length.
 * @param[in] rounds Number of rounds.
 * @param[out] digest Resulting 32 or 64 bytes.
 * @return 0 on success, -5 on digest failure.
 */
static int
nc_crypt_sha_digest(enum nc_crypt_alg alg, const char *password, size_t pw_len,
        const char *salt, size_t salt_len, unsigned long rounds, unsigned char *digest)
{
    struct nc_crypt_digest digest_ctx = {0};
    unsigned char alt[64] = {0}, dp[64] = {0}, ds[64] = {0};
    unsigned char *p_seq = NULL, *s_seq = NULL;
    size_t n, size, i;
    int rc = 0;

    size = (alg == NC_CRYPT_ALG_SHA256) ? 32 : 64;
    digest_ctx.alg = alg;

    /* alternate sum B = SHA(password + salt + password) */
    if (nc_crypt_digest_init(&digest_ctx) ||
            nc_crypt_digest_update(&digest_ctx, password, pw_len) ||
            nc_crypt_digest_update(&digest_ctx, salt, salt_len) ||
            nc_crypt_digest_update(&digest_ctx, password, pw_len) ||
            nc_crypt_digest_final(&digest_ctx, alt)) {
        rc = -5;
        goto cleanup;
    }

    /* open digest A (password + salt) */
    if (nc_crypt_digest_init(&digest_ctx) ||
            nc_crypt_digest_update(&digest_ctx, password, pw_len) ||
            nc_crypt_digest_update(&digest_ctx, salt, salt_len)) {
        rc = -5;
        goto cleanup;
    }

    /* for every full digest-sized block of password length add B, then the first n bytes */
    for (n = pw_len; n > size; n -= size) {
        if (nc_crypt_digest_update(&digest_ctx, alt, size)) {
            rc = -5;
            goto cleanup;
        }
    }
    if (nc_crypt_digest_update(&digest_ctx, alt, n)) {
        rc = -5;
        goto cleanup;
    }

    /* for every set bit of the password length the whole B, otherwise the whole password */
    for (i = pw_len; i; i >>= 1) {
        if (i & 1) {
            if (nc_crypt_digest_update(&digest_ctx, alt, size)) {
                rc = -5;
                goto cleanup;
            }
        } else if (nc_crypt_digest_update(&digest_ctx, password, pw_len)) {
            rc = -5;
            goto cleanup;
        }
    }

    if (nc_crypt_digest_final(&digest_ctx, digest)) {
        rc = -5;
        goto cleanup;
    }

    /* password precompression DP = SHA(password for every byte of the password) */
    if (nc_crypt_digest_init(&digest_ctx)) {
        rc = -5;
        goto cleanup;
    }
    for (i = 0; i < pw_len; ++i) {
        if (nc_crypt_digest_update(&digest_ctx, password, pw_len)) {
            rc = -5;
            goto cleanup;
        }
    }
    if (nc_crypt_digest_final(&digest_ctx, dp)) {
        rc = -5;
        goto cleanup;
    }

    /* salt precompression DS = SHA(salt repeated 16 + digest[0] times) */
    if (nc_crypt_digest_init(&digest_ctx)) {
        rc = -5;
        goto cleanup;
    }
    for (i = 0; i < (size_t)(16 + digest[0]); ++i) {
        if (nc_crypt_digest_update(&digest_ctx, salt, salt_len)) {
            rc = -5;
            goto cleanup;
        }
    }
    if (nc_crypt_digest_final(&digest_ctx, ds)) {
        rc = -5;
        goto cleanup;
    }

    /* P and S byte sequences: DP and DS cycled to the password and salt lengths */
    p_seq = calloc(pw_len ? pw_len : 1, sizeof *p_seq);
    if (p_seq) {
        s_seq = calloc(salt_len ? salt_len : 1, sizeof *s_seq);
    }
    if (!p_seq || !s_seq) {
        ERRMEM;
        rc = -5;
        goto cleanup;
    }
    for (i = 0; i < pw_len; ++i) {
        p_seq[i] = dp[i % size];
    }
    for (i = 0; i < salt_len; ++i) {
        s_seq[i] = ds[i % size];
    }

    rc = nc_crypt_stretch(&digest_ctx, p_seq, pw_len, s_seq, salt_len, digest, size, rounds);

cleanup:
    /* P, S and the alternate sums are derived from the password */
    if (p_seq) {
        nc_crypt_memzero(p_seq, pw_len ? pw_len : 1);
    }
    if (s_seq) {
        nc_crypt_memzero(s_seq, salt_len ? salt_len : 1);
    }
    free(p_seq);
    free(s_seq);
    nc_crypt_memzero(alt, sizeof alt);
    nc_crypt_memzero(dp, sizeof dp);
    nc_crypt_memzero(ds, sizeof ds);
    nc_crypt_digest_cleanup(&digest_ctx);
    return rc;
}

/**
 * @brief Compare two equal-length strings in constant time.
 *
 * @param[in] a First string.
 * @param[in] b Second string.
 * @param[in] len Length of both strings.
 * @return 0 if the strings are equal, 1 otherwise.
 */
static int
nc_crypt_ct_equal(const char *a, const char *b, size_t len)
{
    /* Volatile to prevent time-based attacks */
    volatile unsigned char diff = 0;
    size_t i;

    for (i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }

    return diff != 0;
}

int
nc_crypt(const char *password, const char *setting, struct nc_crypt *crypt)
{
    struct nc_crypt_setting set = {0};
    unsigned char digest[64] = {0};
    char b64[NC_CRYPT_SHA512_HASH_LEN + 1] = {0};
    size_t pw_len, hash_len, stored_len, needed, digits;
    char id;
    int rc;

    if (!password || !setting || !crypt) {
        ERR(NULL, "Invalid arguments for nc_crypt().");
        return -1;
    }
    if ((crypt->action != NC_CRYPT_CREATE) && (crypt->action != NC_CRYPT_VERIFY)) {
        ERR(NULL, "Invalid nc_crypt action (%d).", (int)crypt->action);
        return -1;
    }
    if (crypt->action == NC_CRYPT_VERIFY) {
        /* a failed verification must always report a mismatch */
        crypt->match = 1;
    }

    rc = nc_crypt_parse_setting(setting, &set);
    if (rc) {
        return rc;
    }

    if (crypt->action == NC_CRYPT_VERIFY) {
        if (!set.stored || !*set.stored) {
            WRN(NULL, "Setting has no stored digest to verify against.");
            return -3;
        }
        if (!nc_crypt_valid_b64(set.stored, strlen(set.stored))) {
            WRN(NULL, "Invalid characters in the stored digest of the setting.");
            return -3;
        }
    }

    /* learn the encoded digest length */
    switch (set.alg) {
    case NC_CRYPT_ALG_MD5:
        hash_len = NC_CRYPT_MD5_HASH_LEN;
        break;
    case NC_CRYPT_ALG_SHA256:
        hash_len = NC_CRYPT_SHA256_HASH_LEN;
        break;
    case NC_CRYPT_ALG_SHA512:
        hash_len = NC_CRYPT_SHA512_HASH_LEN;
        break;
    }

    /* validate the output parameters */
    if (crypt->action == NC_CRYPT_CREATE) {
        id = (set.alg == NC_CRYPT_ALG_MD5) ? '1' : (set.alg == NC_CRYPT_ALG_SHA256) ? '5' : '6';

        needed = 3 + set.salt_len + 1 + hash_len + 1;
        if (set.rounds_custom) {
            needed += 8; /* "rounds=" and the trailing '$' */
            digits = set.rounds;
            do {
                ++needed;
                digits /= 10;
            } while (digits);
        }

        if (!crypt->output) {
            ERR(NULL, "No output buffer provided for hash creation.");
            return -1;
        }
        if (crypt->output_len < needed) {
            ERR(NULL, "Output buffer too small (%zu bytes, at least %zu needed).", crypt->output_len, needed);
            return -4;
        }
    }

    pw_len = strlen(password);

    if (set.alg == NC_CRYPT_ALG_MD5) {
        rc = nc_crypt_md5_digest(password, pw_len, set.salt, set.salt_len, digest);
    } else {
        rc = nc_crypt_sha_digest(set.alg, password, pw_len, set.salt, set.salt_len, set.rounds, digest);
    }
    if (rc) {
        /* the digest may be partially computed */
        nc_crypt_memzero(digest, sizeof digest);
        return rc;
    }

    nc_crypt_encode(set.alg, digest, b64);
    b64[hash_len] = '\0';

    if (crypt->action == NC_CRYPT_CREATE) {
        if (set.rounds_custom) {
            snprintf(crypt->output, crypt->output_len, "$%c$rounds=%lu$%s$%s", id, set.rounds, set.salt, b64);
        } else {
            snprintf(crypt->output, crypt->output_len, "$%c$%s$%s", id, set.salt, b64);
        }
    } else {
        /* a mismatch is a valid outcome, not an error */
        stored_len = strlen(set.stored);
        if (stored_len == hash_len) {
            crypt->match = nc_crypt_ct_equal(set.stored, b64, hash_len);
        }
    }

    /* the digest and its encoding are derived from the password */
    nc_crypt_memzero(digest, sizeof digest);
    nc_crypt_memzero(b64, sizeof b64);

    return 0;
}

const char *
nc_crypt_strerr(int err)
{
    switch (err) {
    case -1:
        return "invalid arguments";
    case -2:
        return "unsupported hash id";
    case -3:
        return "malformed setting";
    case -4:
        return "output buffer too small";
    case -5:
        return "digest computation failed";
    default:
        return "unknown error";
    }
}
