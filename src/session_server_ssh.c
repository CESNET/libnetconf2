/**
 * @file session_server_ssh.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 SSH server session manipulation functions
 *
 * @copyright
 * Copyright (c) 2017 - 2026 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "config.h" /* Expose HAVE_LIBPAM and HAVE_SHADOW */

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libyang/libyang.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_LIBPAM
#   include <security/pam_appl.h>
#endif
#ifdef HAVE_SHADOW
#   include <shadow.h>
#endif

#include "compat.h"
#include "log_p.h"
#include "nc_version.h"
#include "session.h"
#include "session_p.h"
#include "session_server_ssh_wrapper.h"
#include "session_wrapper.h"

/*
 * Password authentication lockout.
 *
 * Consecutive failed password authentications are counted per (username, client address) pair
 * across connections, and the pair is refused password authentication for lock_time seconds once
 * max_fails is reached. The client address is part of the key because the username is entirely
 * attacker-controlled: keyed on the username alone, anyone able to reach the server could keep any
 * account permanently locked out by failing to authenticate as it.
 *
 * The policy is per SSH endpoint and off unless configured, see the lockout container in
 * libnetconf2-netconf-server. The tally is mirrored to a state file when one is configured, so that
 * restarting the server does not clear a lockout. Public key and certificate authentication are
 * deliberately left alone: the lockout is on guessing a password, and leaving key auth open keeps a
 * locked-out deployment recoverable.
 */
static struct {
    pthread_mutex_t lock;
    struct nc_authlock_entry entries[NC_AUTHLOCK_MAX_ENTRIES];
    uint32_t entry_count;
    char *path;                 /**< state file the tally is mirrored to, NULL to keep it in memory only */
    int path_set;               /**< whether @p path was resolved already */
    int loaded;                 /**< whether the state file was read already */
    ino_t loaded_ino;           /**< inode of the state file revision the tally came from */
    struct timespec loaded_mtim; /**< mtime of the state file revision the tally came from */
    int store_failed;           /**< whether the state file turned out to be unusable, disables persistence */
} authlock = {.lock = PTHREAD_MUTEX_INITIALIZER};

/**
 * @brief Drop the whole in-memory tally. Expects the lock to be held.
 */
static void
nc_authlock_clear(void)
{
    uint32_t i;

    for (i = 0; i < authlock.entry_count; ++i) {
        free(authlock.entries[i].username);
        free(authlock.entries[i].host);
    }
    authlock.entry_count = 0;
}

/**
 * @brief Get the path of the lockout state file. Expects the lock to be held.
 *
 * @return Path set by ::nc_server_ssh_set_authlock_path() or the compiled-in default, NULL if
 * neither is set or the file turned out to be unusable, in which case the tally is memory-only.
 */
static const char *
nc_authlock_path(void)
{
    if (authlock.store_failed) {
        return NULL;
    }

    if (!authlock.path_set) {
        authlock.path_set = 1;
        if (NC_AUTHLOCK_FILE_DEFAULT[0]) {
            authlock.path = strdup(NC_AUTHLOCK_FILE_DEFAULT);
            if (!authlock.path) {
                ERRMEM;
            }
        }
    }

    return authlock.path;
}

API int
nc_server_ssh_set_authlock_path(const char *path)
{
    char *dup = NULL;

    if (path && path[0]) {
        dup = strdup(path);
        NC_CHECK_ERRMEM_RET(!dup, 1);
    }

    pthread_mutex_lock(&authlock.lock);

    free(authlock.path);
    authlock.path = dup;
    authlock.path_set = 1;
    authlock.store_failed = 0;

    /* the tally in memory is the one of the previous file, re-read it from the new one */
    nc_authlock_clear();
    authlock.loaded = 0;
    authlock.loaded_ino = 0;
    memset(&authlock.loaded_mtim, 0, sizeof authlock.loaded_mtim);

    pthread_mutex_unlock(&authlock.lock);
    return 0;
}

/**
 * @brief Read the lockout state file into the tally. Expects the lock to be held.
 *
 * @param[in] path State file to read.
 */
static void
nc_authlock_load(const char *path)
{
    char line[512], host[256], *username;
    uint32_t fails;
    long long locked_until, last_fail;
    struct nc_authlock_entry *entry;
    struct stat st;
    int offset;
    FILE *f;

    authlock.loaded = 1;

    f = fopen(path, "r");
    if (!f) {
        return;
    }

    /* remember which revision of the file this tally is, so that a change made to it from the
     * outside is noticed */
    if (!fstat(fileno(f), &st)) {
        authlock.loaded_ino = st.st_ino;
        authlock.loaded_mtim = st.st_mtim;
    }

    /* the username is the rest of the line so that it may contain spaces */
    while ((authlock.entry_count < NC_AUTHLOCK_MAX_ENTRIES) && fgets(line, sizeof line, f)) {
        if (sscanf(line, "%" SCNu32 " %lld %lld %255s %n",
                &fails, &locked_until, &last_fail, host, &offset) != 4) {
            continue;
        }
        username = line + offset;
        username[strcspn(username, "\n")] = '\0';
        if (!username[0]) {
            continue;
        }

        entry = &authlock.entries[authlock.entry_count];
        memset(entry, 0, sizeof *entry);

        entry->username = strdup(username);
        if (!entry->username) {
            break;
        }
        /* "-" is what an entry with no known client address is written as */
        if (strcmp(host, "-")) {
            entry->host = strdup(host);
            if (!entry->host) {
                free(entry->username);
                break;
            }
        }
        entry->fails = fails;
        entry->locked_until = locked_until;
        entry->last_fail = last_fail;
        ++authlock.entry_count;
    }

    fclose(f);
}

/**
 * @brief Write the tally to the lockout state file. Expects the lock to be held.
 *
 * @param[in] path State file to write.
 */
static void
nc_authlock_store(const char *path)
{
    char *tmp_path = NULL;
    FILE *f = NULL;
    struct stat st;
    uint32_t i;
    int fd;

    if (asprintf(&tmp_path, "%s.tmp", path) == -1) {
        return;
    }

    /* 0600: the file lists account names */
    fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        goto fail;
    }
    f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        goto fail;
    }

    for (i = 0; i < authlock.entry_count; ++i) {
        /* only a lockout is worth persisting, a tally that has not reached one yet is not written
         * so that a failed authentication does not have to rewrite the file */
        if (!authlock.entries[i].locked_until) {
            continue;
        }
        /* a username with whitespace of its own would break the line format, keep that one in
         * memory only */
        if (strpbrk(authlock.entries[i].username, "\r\n")) {
            continue;
        }
        fprintf(f, "%" PRIu32 " %lld %lld %s %s\n", authlock.entries[i].fails,
                (long long)authlock.entries[i].locked_until, (long long)authlock.entries[i].last_fail,
                authlock.entries[i].host ? authlock.entries[i].host : "-", authlock.entries[i].username);
    }

    if (fclose(f)) {
        goto fail;
    }
    if (rename(tmp_path, path)) {
        goto fail;
    }

    if (!stat(path, &st)) {
        authlock.loaded_ino = st.st_ino;
        authlock.loaded_mtim = st.st_mtim;
    }

    free(tmp_path);
    return;

fail:
    /* the path is a deployment setting, so this is a misconfiguration rather than a transient
     * error; say so once and keep the tally in memory from here on */
    ERR(NULL, "Failed to store the authentication failure tally in \"%s\" (%s), its directory has to "
            "exist and be writable. Lockouts will not survive a restart.", path, strerror(errno));
    authlock.store_failed = 1;
    unlink(tmp_path);
    free(tmp_path);
}

/**
 * @brief Bring the in-memory tally in line with the state file. Expects the lock to be held.
 *
 * Reads the file when it has not been read yet, and re-reads it when it has changed since - which is
 * how an operator clears a lockout early: remove the file, or edit the account out of it. Writes
 * this code made itself are not read back.
 */
static void
nc_authlock_sync(void)
{
    const char *path = nc_authlock_path();
    struct stat st;

    if (!path) {
        /* no state file configured, the tally is memory-only */
        return;
    }

    if (stat(path, &st)) {
        if (errno != ENOENT) {
            /* the file may well be there and only be unreadable right now, dropping the tally on
             * that would unlock every account */
            return;
        }
        /* no state file, so nothing is locked out; it was either never written or removed to clear
         * the lockouts */
        nc_authlock_clear();
        authlock.loaded = 1;
        authlock.loaded_ino = 0;
        memset(&authlock.loaded_mtim, 0, sizeof authlock.loaded_mtim);
        return;
    }

    if (authlock.loaded && (st.st_ino == authlock.loaded_ino) &&
            (st.st_mtim.tv_sec == authlock.loaded_mtim.tv_sec) &&
            (st.st_mtim.tv_nsec == authlock.loaded_mtim.tv_nsec)) {
        /* the tally is that of the file as it is now */
        return;
    }

    nc_authlock_clear();
    nc_authlock_load(path);
}

/**
 * @brief Compare the client address of an entry with the one of a connection.
 *
 * @param[in] entry_host Client address of the entry, may be NULL.
 * @param[in] host Client address of the connection, may be NULL.
 * @return Non-zero if they are the same address, 0 otherwise.
 */
static int
nc_authlock_same_host(const char *entry_host, const char *host)
{
    if (!entry_host || !host) {
        return !entry_host && !host;
    }

    return !strcmp(entry_host, host);
}

/**
 * @brief Find the tally of a (username, client address) pair. Expects the lock to be held.
 *
 * @param[in] username Account to look for.
 * @param[in] host Client address to look for, may be NULL if it is not known.
 * @return Its entry, NULL if it has none.
 */
static struct nc_authlock_entry *
nc_authlock_find(const char *username, const char *host)
{
    uint32_t i;

    for (i = 0; i < authlock.entry_count; ++i) {
        if (!strcmp(authlock.entries[i].username, username) &&
                nc_authlock_same_host(authlock.entries[i].host, host)) {
            return &authlock.entries[i];
        }
    }

    return NULL;
}

/**
 * @brief Find or create the tally of a (username, client address) pair. Expects the lock to be held.
 *
 * @param[in] username Account to look for.
 * @param[in] host Client address to look for, may be NULL if it is not known.
 * @param[in] now Current time.
 * @return Its entry, NULL if the table is full of lockouts or on allocation failure.
 */
static struct nc_authlock_entry *
nc_authlock_get(const char *username, const char *host, time_t now)
{
    struct nc_authlock_entry *entry;
    uint32_t i, slot;
    char *name, *addr = NULL;

    entry = nc_authlock_find(username, host);
    if (entry) {
        return entry;
    }

    if (authlock.entry_count < NC_AUTHLOCK_MAX_ENTRIES) {
        slot = authlock.entry_count;
    } else {
        /* full, reuse the entry that failed longest ago among those that are not locked out. An
         * entry that is locked out is never evicted, otherwise filling the table would be all it
         * takes to lift a lockout. */
        slot = NC_AUTHLOCK_MAX_ENTRIES;
        for (i = 0; i < authlock.entry_count; ++i) {
            if (authlock.entries[i].locked_until > now) {
                continue;
            }
            if ((slot == NC_AUTHLOCK_MAX_ENTRIES) ||
                    (authlock.entries[i].last_fail < authlock.entries[slot].last_fail)) {
                slot = i;
            }
        }
        if (slot == NC_AUTHLOCK_MAX_ENTRIES) {
            /* every tracked pair is locked out, so refuse to track another one rather than drop a
             * lockout; the pairs that are locked out keep being refused either way */
            WRN(NULL, "Authentication failure tally full of locked out users, not counting the "
                    "failures of user \"%s\" for now.", username);
            return NULL;
        }
    }

    name = strdup(username);
    NC_CHECK_ERRMEM_RET(!name, NULL);
    if (host) {
        addr = strdup(host);
        if (!addr) {
            ERRMEM;
            free(name);
            return NULL;
        }
    }

    if (slot == authlock.entry_count) {
        ++authlock.entry_count;
    } else {
        free(authlock.entries[slot].username);
        free(authlock.entries[slot].host);
    }

    memset(&authlock.entries[slot], 0, sizeof authlock.entries[slot]);
    authlock.entries[slot].username = name;
    authlock.entries[slot].host = addr;

    return &authlock.entries[slot];
}

/**
 * @brief Get how much longer a client is locked out of password authentication.
 *
 * @param[in] username Account to check.
 * @param[in] host Client address to check, may be NULL if it is not known.
 * @return Seconds until it may authenticate again, 0 if it is not locked out.
 */
static time_t
nc_authlock_remaining(const char *username, const char *host)
{
    struct nc_authlock_entry *entry;
    time_t now = time(NULL), remaining = 0;

    pthread_mutex_lock(&authlock.lock);

    nc_authlock_sync();

    entry = nc_authlock_find(username, host);
    if (entry && (entry->locked_until > now)) {
        remaining = entry->locked_until - now;
    }

    pthread_mutex_unlock(&authlock.lock);

    return remaining;
}

/**
 * @brief Record the outcome of a password authentication.
 *
 * Does nothing unless the endpoint the session arrived on has the lockout configured.
 *
 * @param[in] session NETCONF session, for the policy, the client address and the log message.
 * @param[in] username Account that authenticated.
 * @param[in] success Whether it succeeded, which clears the tally.
 */
static void
nc_authlock_record(struct nc_session *session, const char *username, int success)
{
    const struct nc_authlock_opts *opts = &session->opts.server.authlock;
    struct nc_authlock_entry *entry;
    const char *path, *host = session->host;
    time_t now = time(NULL), was_locked_until;

    if (!opts->max_fails || !username) {
        /* the lockout is not configured for this endpoint */
        return;
    }

    pthread_mutex_lock(&authlock.lock);

    nc_authlock_sync();

    entry = nc_authlock_find(username, host);
    if (success) {
        if (!entry || (!entry->fails && !entry->locked_until)) {
            /* nothing recorded for this client, no need to rewrite the state file */
            goto cleanup;
        }
        was_locked_until = entry->locked_until;
        entry->fails = 0;
        entry->last_fail = 0;
        entry->locked_until = 0;
    } else {
        if (!entry) {
            entry = nc_authlock_get(username, host, now);
            if (!entry) {
                goto cleanup;
            }
        }
        was_locked_until = entry->locked_until;

        if (entry->locked_until && (entry->locked_until <= now)) {
            /* the lockout expired, this failure starts a fresh tally rather than immediately
             * locking the client out again */
            entry->fails = 0;
            entry->locked_until = 0;
        } else if (entry->fails && ((now - entry->last_fail) > opts->fail_window)) {
            /* the previous failures are too old to count towards this one */
            entry->fails = 0;
        }

        ++entry->fails;
        entry->last_fail = now;

        if (entry->fails >= opts->max_fails) {
            entry->locked_until = now + opts->lock_time;
            WRN(session, "User \"%s\" locked out of password authentication for %" PRIu16 " s after "
                    "%" PRIu32 " consecutive failed attempts.", username, opts->lock_time, entry->fails);
        }
    }

    /* the state file only holds lockouts, so it is only rewritten when one starts or ends; a tally
     * that has not reached a lockout yet is not worth making every failed attempt wait for a write */
    if (entry->locked_until != was_locked_until) {
        path = nc_authlock_path();
        if (path) {
            nc_authlock_store(path);
        }
    }

cleanup:
    pthread_mutex_unlock(&authlock.lock);
}

void
nc_server_ssh_authlock_free(void)
{
    pthread_mutex_lock(&authlock.lock);

    nc_authlock_clear();
    free(authlock.path);
    authlock.path = NULL;
    authlock.path_set = 0;
    authlock.store_failed = 0;
    authlock.loaded = 0;
    authlock.loaded_ino = 0;
    memset(&authlock.loaded_mtim, 0, sizeof authlock.loaded_mtim);

    pthread_mutex_unlock(&authlock.lock);
}

/**
 * @brief Check whether a client is locked out of password authentication and log it if it is.
 *
 * Always allows the authentication unless the endpoint the session arrived on has the lockout
 * configured.
 *
 * @param[in] session NETCONF session, for the policy, the client address and the log message.
 * @param[in] username Account to check.
 * @return 0 if it may authenticate, 1 if it is locked out.
 */
static int
nc_authlock_denied(struct nc_session *session, const char *username)
{
    time_t remaining;

    if (!session->opts.server.authlock.max_fails || !username) {
        return 0;
    }

    remaining = nc_authlock_remaining(username, session->host);
    if (!remaining) {
        return 0;
    }

    WRN(session, "User \"%s\" is locked out of password authentication for another %lld s.",
            username, (long long)remaining);
    return 1;
}

int
nc_ssh_check_local_user_support(struct nc_session *session)
{
    const struct ly_ctx *ctx;
    struct lys_module *mod;
    int rc;

    ctx = nc_session_get_ctx(session);
    mod = ly_ctx_get_module_latest(ctx, "ietf-ssh-server");
    if (!mod) {
        ERRINT;
        return -1;
    }

    rc = lys_feature_value(mod, "local-users-supported");
    if (rc == LY_SUCCESS) {
        return 1;
    } else if (rc == LY_ENOTFOUND) {
        return 0;
    } else {
        return -1;
    }
}

struct nc_auth_client *
nc_ssh_find_auth_client(struct nc_server_ssh_opts *opts, const char *user, struct nc_session *session)
{
    const struct nc_endpt *referenced_endpt;
    LY_ARRAY_COUNT_TYPE u;

    if (!user) {
        return NULL;
    }

    for (u = 0; u < LY_ARRAY_COUNT(opts->auth_clients); u++) {
        if (!strcmp(opts->auth_clients[u].username, user)) {
            return &opts->auth_clients[u];
        }
    }

    /* client not known by the endpt, but it references another one so try it */
    if (opts->referenced_endpt_name) {
        if (nc_server_endpt_get(session->opts.server.config, opts->referenced_endpt_name, &referenced_endpt)) {
            ERR(session, "Referenced endpoint \"%s\" not found.", opts->referenced_endpt_name);
            return NULL;
        }
        return nc_ssh_find_auth_client(referenced_endpt->opts.ssh, user, session);
    }
    return NULL;
}

void
nc_ssh_auth_state_init(struct nc_session *session, struct nc_auth_state *auth_state,
        int local_users_supported, struct nc_auth_client *auth_client)
{
    if (auth_state->method_count) {
        return;
    }

    if (local_users_supported) {
        if (auth_client->pubkey_store != NC_STORE_UNKNOWN) {
            auth_state->methods |= SSH_AUTH_METHOD_PUBLICKEY;
            auth_state->method_count++;
        }
        if (auth_client->password) {
            auth_state->methods |= SSH_AUTH_METHOD_PASSWORD;
            auth_state->method_count++;
        }
        if (auth_client->kbdint_method != NC_KBDINT_AUTH_METHOD_NONE) {
            auth_state->methods |= SSH_AUTH_METHOD_INTERACTIVE;
            auth_state->method_count++;
        }
        if (auth_client->none_enabled) {
            auth_state->methods |= SSH_AUTH_METHOD_NONE;
            auth_state->method_count++;
        }
    } else {
        /* no local users meaning pw, pubkey and kbdint methods are supported, method count is set to 1,
         * because only one method is needed for successful auth */
        auth_state->methods = SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE;
        auth_state->method_count = 1;
    }

    ssh_set_auth_methods(session->ti.libssh.session, auth_state->methods);
}

int
nc_ssh_auth_success(struct nc_session *session, struct nc_auth_state *auth_state, int method)
{
    auth_state->success_methods |= method;
    auth_state->success_count++;

    if (auth_state->success_count < auth_state->method_count) {
        /* success, but he needs to do another method */
        VRB(session, "User \"%s\" partially authenticated, but still needs to authenticate via the rest of his configured methods.",
                session->username);
        ssh_set_auth_methods(session->ti.libssh.session, auth_state->methods & ~auth_state->success_methods);
        return SSH_AUTH_PARTIAL;
    }

    /* authenticated */
    session->flags |= NC_SESSION_SSH_AUTHENTICATED;
    VRB(session, "User \"%s\" authenticated.", session->username);
    return SSH_AUTH_SUCCESS;
}

void
nc_server_ssh_auth_attempt_failed(struct nc_session *session)
{
    uint16_t max_fails = session->opts.server.authlock.session_max_fails;

    ++session->opts.server.ssh_auth_attempts;
    VRB(session, "Failed user \"%s\" authentication attempt (#%" PRIu16 ").",
            session->username ? session->username : "unknown", session->opts.server.ssh_auth_attempts);

    /* every rejected credential gets here, including every public key the client offers that is not
     * accepted, so the cap is off unless the endpoint configures max-auth-attempts */
    if (!max_fails || (session->opts.server.ssh_auth_attempts < max_fails)) {
        return;
    }

    /* the per-session cap, which bounds what a single connection may try; the accept loops end on a
     * session that is no longer connected */
    if (NC_SESSION_STATUS_GET(session) != NC_STATUS_INVALID) {
        ERR(session, "Too many failed authentication attempts (%" PRIu16 ") in a single session, disconnecting.",
                session->opts.server.ssh_auth_attempts);
        NC_SESSION_STATUS_SET(session, NC_STATUS_INVALID);
        NC_SESSION_TERM_REASON_SET(session, NC_SESSION_TERM_OTHER);
        ssh_disconnect(session->ti.libssh.session);
    }
}

int
nc_server_ssh_auth_password_check(struct nc_session *session, const char *user,
        const char *password, struct nc_auth_client *auth_client, int local_users_supported)
{
    int rc;
    char *stored_password = NULL;

    assert(!local_users_supported || auth_client);

    /* refuse an account that failed password authentication too many times */
    if (nc_authlock_denied(session, user)) {
        return 1;
    }

    /* Get the stored password */
    if (local_users_supported) {
        stored_password = auth_client->password;
        if (!stored_password) {
            /* client requested password auth, but it is not configured for this user, so just deny */
            DBG(session,
                    "User \"%s\" does not have password method configured, but a request was received.", user);
            return 1;
        }
    } else {
#ifdef HAVE_SHADOW
        stored_password = nc_server_ssh_get_pwd_hash(user);
        if (!stored_password) {
            return 1;
        }
#else
        ERR(session, "Obtaining password from system not supported.");
        return 1;
#endif
    }

    /* Compare the passwords */
    rc = nc_server_ssh_compare_password(stored_password, password);

    if (!local_users_supported) {
        free(stored_password);
    }

    /* a password that worked clears the account's tally, one that did not counts against it */
    nc_authlock_record(session, user, rc ? 0 : 1);

    return rc;
}

int
nc_server_ssh_kbdint_select_method(struct nc_session *session, int local_users_supported,
        struct nc_auth_client *auth_client, enum nc_kbdint_backend *backend)
{
    int custom_clb_set;

    assert(!local_users_supported || auth_client);

    if (!local_users_supported) {
        /* system users always authenticate against the system method */
        *backend = NC_KBDINT_BACKEND_SYSTEM;
        return 0;
    }

    if (auth_client->kbdint_method == NC_KBDINT_AUTH_METHOD_NONE) {
        /* client requested kbdint auth, but it is not configured for this user, so just deny */
        DBG(session,
                "User \"%s\" does not have kbdint method configured, but a request was received.", session->username);
        return 1;
    }

    /* OPTS READ LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_READ, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }
    custom_clb_set = server_opts.interactive_auth_clb ? 1 : 0;
    /* OPTS READ UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);

    if (custom_clb_set) {
        /* custom callback has higher priority */
        *backend = NC_KBDINT_BACKEND_CUSTOM_CLB;
        return 0;
    }

    if (auth_client->kbdint_method == NC_KBDINT_AUTH_METHOD_SYSTEM) {
        *backend = NC_KBDINT_BACKEND_SYSTEM;
        return 0;
    }

    /* add future methods here */
    ERR(session, "Keyboard-interactive authentication method not supported.");
    return 1;
}

int
nc_server_ssh_auth_pubkey_check(struct nc_session *session, ssh_key pubkey,
        struct nc_auth_client *auth_client, int local_users_supported)
{
    struct nc_public_key *pubkeys = NULL;
    uint32_t pubkey_count = 0, i;
    int ret = 0;

    assert(!local_users_supported || auth_client);

    /* get the public keys */
    if (!local_users_supported) {
        /* system user, get the keys from the system (these need to be free'd as they're not in the config) */
        ret = nc_server_ssh_get_system_keys(session->username, &pubkeys, &pubkey_count);
        if (ret) {
            goto cleanup;
        }
    } else {
        if (auth_client->pubkey_store == NC_STORE_UNKNOWN) {
            /* client requested pubkey auth, but it is not configured for this user, so just deny */
            DBG(session,
                    "User \"%s\" does not have public key method configured, but a request was received.", session->username);
            return 1;
        }

        if (auth_client->pubkey_store == NC_STORE_SYSTEM) {
            /* get the keys from the system (these need to be free'd as they're not in the config) */
            ret = nc_server_ssh_get_system_keys(session->username, &pubkeys, &pubkey_count);
            if (ret) {
                goto cleanup;
            }
        } else if (auth_client->pubkey_store == NC_STORE_LOCAL) {
            /* saved directly in the user's config */
            pubkeys = auth_client->pubkeys;
            pubkey_count = LY_ARRAY_COUNT(auth_client->pubkeys);
        } else if (auth_client->pubkey_store == NC_STORE_TRUSTSTORE) {
            /* need to fetch from the truststore */
            ret = nc_server_ssh_ts_ref_get_keys(session->opts.server.config, auth_client->ts_ref,
                    &pubkeys, &pubkey_count);
            if (ret) {
                goto cleanup;
            }
        } else {
            ERRINT;
            return 1;
        }
    }

    /* compare the received pubkey with the authorized ones */
    if (nc_server_ssh_auth_pubkey_compare_key(pubkey, pubkeys, pubkey_count)) {
        VRB(session, "User \"%s\" tried to use an unknown (unauthorized) public key.", session->username);
        ret = 1;
        goto cleanup;
    }

cleanup:
    if (!local_users_supported || (auth_client->pubkey_store == NC_STORE_SYSTEM)) {
        for (i = 0; i < pubkey_count; i++) {
            free(pubkeys[i].name);
            free(pubkeys[i].data);
        }
        free(pubkeys);
    }

    return ret;
}

#ifdef HAVE_LIBPAM

int
nc_server_ssh_pam_conv_parse(struct nc_session *session, int n_messages,
        const struct pam_message **msg, struct pam_response **resp,
        int *n_prompts, const char ***prompts, char **echo)
{
    int i, j, t, n_requests = n_messages;

    *resp = NULL;
    *n_prompts = 0;
    *prompts = NULL;
    *echo = NULL;

    /* PAM_MAX_NUM_MSG == 32 by default */
    if ((n_messages <= 0) || (n_messages >= PAM_MAX_NUM_MSG)) {
        ERR(session, "Bad number of PAM messages (#%d).", n_messages);
        return PAM_CONV_ERR;
    }

    /* only accepting these 4 types of messages */
    for (i = 0; i < n_messages; i++) {
        t = msg[i]->msg_style;
        if ((t != PAM_PROMPT_ECHO_OFF) && (t != PAM_PROMPT_ECHO_ON) &&
                (t != PAM_TEXT_INFO) && (t != PAM_ERROR_MSG)) {
            ERR(session, "PAM conversation callback received an unexpected type of message.");
            return PAM_CONV_ERR;
        }
    }

    /* handle info/error messages, count actual prompts */
    for (i = 0; i < n_messages; i++) {
        if (msg[i]->msg_style == PAM_TEXT_INFO) {
            VRB(session, "PAM conversation callback received a message with some information for the client (%s).", msg[i]->msg);
            n_requests--;
        }
        if (msg[i]->msg_style == PAM_ERROR_MSG) {
            ERR(session, "PAM conversation callback received an error message (%s).", msg[i]->msg);
            return PAM_CONV_ERR;
        }
    }

    /* no actual prompts */
    if (n_requests <= 0) {
        return PAM_SUCCESS;
    }

    /* build response, prompt and echo arrays */
    *resp = calloc(n_requests, sizeof **resp);
    *prompts = calloc(n_requests, sizeof **prompts);
    *echo = calloc(n_requests, sizeof **echo);
    if (!(*resp) || !(*prompts) || !(*echo)) {
        ERRMEM;
        free(*resp);
        *resp = NULL;
        free(*prompts);
        *prompts = NULL;
        free(*echo);
        *echo = NULL;
        return PAM_BUF_ERR;
    }

    j = 0;
    for (i = 0; i < n_messages; i++) {
        if ((msg[i]->msg_style == PAM_PROMPT_ECHO_ON) || (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF)) {
            (*prompts)[j] = msg[i]->msg;
            if (msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
                (*echo)[j] = 1;
            }
            j++;
        }
    }

    *n_prompts = n_requests;
    return PAM_SUCCESS;
}

int
nc_server_ssh_pam_conv_fill(struct nc_session *session, struct pam_response *resp,
        int n_prompts, int n_answers, const char **answers)
{
    int i, j;

    if (n_answers != n_prompts) {
        ERR(session, "Expected %d response(s), got %d.", n_prompts, n_answers);
        return PAM_CONV_ERR;
    }

    for (i = 0; i < n_answers; i++) {
        resp[i].resp = strdup(answers[i]);
        /* freeing the responses is the caller's responsibility, however on mem alloc failure
         * it is safer to free the already copied responses here and set them to NULL */
        if (!resp[i].resp) {
            for (j = 0; j < i; j++) {
                free(resp[j].resp);
                resp[j].resp = NULL;
            }
            ERRMEM;
            return PAM_BUF_ERR;
        }
    }

    return PAM_SUCCESS;
}

int
nc_server_ssh_get_pam_conf_filename(char **filename)
{
    int rc = 0;

    *filename = NULL;

    /* OPTS READ LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_READ, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    if (server_opts.pam_config_name) {
        *filename = strdup(server_opts.pam_config_name);
        NC_CHECK_ERRMEM_GOTO(!*filename, rc = 1, cleanup);
    }

cleanup:
    /* OPTS READ UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
    return rc;
}

int
nc_server_ssh_pam_authenticate(struct nc_session *session, const char *username,
        const struct pam_conv *conv)
{
    pam_handle_t *pam_h = NULL;
    char *pam_config_name = NULL;
    int ret;

    /* refuse an account that failed password authentication too many times; pam_faillock, where it
     * is configured, only sees the PAM methods, this tally is shared with the other ones */
    if (nc_authlock_denied(session, username)) {
        return 1;
    }

    /* get the PAM configuration, PAM must not be called with the lock held */
    if (nc_server_ssh_get_pam_conf_filename(&pam_config_name)) {
        return 1;
    }
    if (!pam_config_name) {
        ERR(session, "PAM configuration filename not set.");
        return 1;
    }

    /* initialize PAM and see if the given configuration file exists */
    ret = pam_start(pam_config_name, username, conv, &pam_h);
    if (ret != PAM_SUCCESS) {
        ERR(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
        goto cleanup;
    }

    /* authentication based on the modules listed in the configuration file */
    ret = pam_authenticate(pam_h, 0);
    if (ret != PAM_SUCCESS) {
        if (ret == PAM_ABORT) {
            ERR(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
        } else {
            VRB(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
        }

        /* only a rejected credential counts towards the lockout; an aborted, unavailable or
         * misconfigured PAM stack is not the client getting the password wrong */
        if ((ret == PAM_AUTH_ERR) || (ret == PAM_USER_UNKNOWN) || (ret == PAM_CRED_INSUFFICIENT) ||
                (ret == PAM_MAXTRIES)) {
            nc_authlock_record(session, username, 0);
        }
        goto cleanup;
    }

    /* the credential was accepted, which clears the tally whatever the account management below
     * has to say about the account */
    nc_authlock_record(session, username, 1);

    /* correct token entered, check other requirements (the time of the day, expired token, ...) */
    ret = pam_acct_mgmt(pam_h, 0);
    if ((ret != PAM_SUCCESS) && (ret != PAM_NEW_AUTHTOK_REQD)) {
        VRB(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
        goto cleanup;
    }

    /* if a token has expired a new one will be generated */
    if (ret == PAM_NEW_AUTHTOK_REQD) {
        VRB(session, "PAM warning occurred (%s).", pam_strerror(pam_h, ret));
        ret = pam_chauthtok(pam_h, PAM_CHANGE_EXPIRED_AUTHTOK);
        if (ret == PAM_SUCCESS) {
            VRB(session, "The authentication token of user \"%s\" updated successfully.", username);
        } else {
            ERR(session, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
        }
    }

cleanup:
    /* destroy the PAM context */
    if (pam_h && (pam_end(pam_h, ret) != PAM_SUCCESS)) {
        ERR(NULL, "PAM error occurred (%s).", pam_strerror(pam_h, ret));
    }
    free(pam_config_name);

    return ret;
}

#endif /* HAVE_LIBPAM */

int
nc_server_ssh_channel_subsys_check(struct nc_session *session, ssh_channel channel, const char *subsystem)
{
    struct nc_session *siter;

    if (strcmp(subsystem, "netconf")) {
        WRN(session, "Received an unknown subsystem \"%s\" request.", subsystem);
        return -1;
    }

    if (session->ti.libssh.channel == channel) {
        /* first channel requested */
        if (session->ti.libssh.next || (NC_SESSION_STATUS_GET(session) != NC_STATUS_STARTING)) {
            ERRINT;
            return -1;
        }
        if (session->flags & NC_SESSION_SSH_SUBSYS_NETCONF) {
            ERR(session, "Subsystem \"netconf\" requested for the second time.");
            return -1;
        }

        session->flags |= NC_SESSION_SSH_SUBSYS_NETCONF;
        return 0;
    }

    /* an additional channel must not be claimed by a session created by an earlier subsystem request */
    for (siter = session->ti.libssh.next; siter && (siter != session); siter = siter->ti.libssh.next) {
        if (siter->ti.libssh.channel == channel) {
            ERR(session, "Subsystem \"netconf\" requested for an already claimed channel.");
            return -1;
        }
    }

    /* an additional channel needs a new session */
    return 1;
}

struct nc_session *
nc_server_ssh_new_channel_session(struct nc_session *session, ssh_channel channel)
{
    struct nc_session *new_session;

    new_session = nc_new_session(NC_SERVER, 1);
    NC_CHECK_ERRMEM_RET(!new_session, NULL);

    NC_SESSION_STATUS_SET(new_session, NC_STATUS_STARTING);
    new_session->ti_type = NC_TI_SSH;
    new_session->io_lock = session->io_lock;
    new_session->ti.libssh.channel = channel;
    new_session->ti.libssh.session = session->ti.libssh.session;
    new_session->username = strdup(session->username);
    NC_CHECK_ERRMEM_GOTO(!new_session->username, , error);

    if (session->host) {
        new_session->host = strdup(session->host);
        NC_CHECK_ERRMEM_GOTO(!new_session->host, , error);
    }

    new_session->port = session->port;
    new_session->ctx = (struct ly_ctx *)session->ctx;
    new_session->flags = NC_SESSION_SSH_AUTHENTICATED | NC_SESSION_SSH_SUBSYS_NETCONF | NC_SESSION_SHAREDCTX;

    /* insert the new session into the ring now that it is fully constructed */
    if (!session->ti.libssh.next) {
        new_session->ti.libssh.next = session;
    } else {
        new_session->ti.libssh.next = session->ti.libssh.next;
    }
    session->ti.libssh.next = new_session;

    return new_session;

error:
    /* detach the state shared with the parent session, so that nc_session_free() does not free it */
    new_session->ti.libssh.session = NULL;
    new_session->io_lock = NULL;
    nc_session_free(new_session, NULL);
    return NULL;
}

/**
 * @brief Stores the private key data as a temporary file.
 *
 * @param[in] in Private key data.
 * @param[in] privkey_format String representation of the private key format.
 * @return Path to the created temporary file or NULL on fail.
 */
static char *
nc_server_ssh_privkey_data_to_tmp_file(const char *in, const char *privkey_format)
{
    char path[12] = "/tmp/XXXXXX";
    int fd, written;
    unsigned len;
    mode_t umode;
    FILE *file;

    NC_CHECK_ARG_RET(NULL, in, NULL);

    umode = umask(0177);
    fd = mkstemp(path);
    umask(umode);
    if (fd == -1) {
        return NULL;
    }

    file = fdopen(fd, "w");
    if (!file) {
        close(fd);
        return NULL;
    }

    /* write header */
    written = fwrite("-----BEGIN", 1, 10, file);
    if (privkey_format) {
        written += fwrite(privkey_format, 1, strlen(privkey_format), file);
        written += fwrite("PRIVATE KEY-----\n", 1, 17, file);
    } else {
        written += fwrite(" PRIVATE KEY-----\n", 1, 18, file);
    }

    /* write data */
    written += fwrite(in, 1, strlen(in), file);

    /* write footer */
    written += fwrite("\n-----END", 1, 9, file);
    if (privkey_format) {
        written += fwrite(privkey_format, 1, strlen(privkey_format), file);
        written += fwrite("PRIVATE KEY-----", 1, 16, file);
    } else {
        written += fwrite(" PRIVATE KEY-----", 1, 17, file);
    }

    fclose(file);

    /* checksum */
    if (privkey_format) {
        len = 10 + strlen(privkey_format) + 17 + strlen(in) + 9 + strlen(privkey_format) + 16;
    } else {
        len = 10 + 18 + strlen(in) + 9 + 17;
    }

    if ((unsigned)written != len) {
        unlink(path);
        return NULL;
    }

    return strdup(path);
}

/**
 * @brief Get asymmetric key from the keystore.
 *
 * @param[in] config Pinned server configuration to search.
 * @param[in] referenced_name Name of the asymmetric key in the keystore.
 * @param[out] askey Referenced asymmetric key.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_ssh_ks_ref_get_key(const struct nc_server_config *config, const char *referenced_name,
        struct nc_asymmetric_key **askey)
{
    LY_ARRAY_COUNT_TYPE i;
    const struct nc_keystore *ks;

    if (!config) {
        ERR(NULL, "No server configuration to get the keystore entry \"%s\" from.", referenced_name);
        return 1;
    }
    ks = &config->keystore;

    *askey = NULL;

    /* lookup name */
    LY_ARRAY_FOR(ks->entries, i) {
        if (!strcmp(referenced_name, ks->entries[i].asym_key.name)) {
            break;
        }
    }
    if (i == LY_ARRAY_COUNT(ks->entries)) {
        ERR(NULL, "Keystore entry \"%s\" not found.", referenced_name);
        return 1;
    }

    *askey = (struct nc_asymmetric_key *)&ks->entries[i].asym_key;

    /* check if the referenced public key is SubjectPublicKeyInfo */
    if ((*askey)->pubkey.data && nc_is_pk_subject_public_key_info((*askey)->pubkey.data)) {
        ERR(NULL, "The public key of the referenced hostkey \"%s\" is in the SubjectPublicKeyInfo format, "
                "which is not allowed in the SSH!", referenced_name);
        return 1;
    }

    return 0;
}

int
nc_server_ssh_ts_ref_get_keys(const struct nc_server_config *config, const char *referenced_name,
        struct nc_public_key **pubkeys, uint32_t *pubkey_count)
{
    LY_ARRAY_COUNT_TYPE i, u;
    const struct nc_truststore *ts;

    *pubkeys = NULL;
    *pubkey_count = 0;

    if (!config) {
        ERR(NULL, "No server configuration to get the truststore entry \"%s\" from.", referenced_name);
        return 1;
    }
    ts = &config->truststore;

    /* lookup name */
    LY_ARRAY_FOR(ts->pubkey_bags, i) {
        if (!strcmp(referenced_name, ts->pubkey_bags[i].name)) {
            break;
        }
    }
    if (i == LY_ARRAY_COUNT(ts->pubkey_bags)) {
        ERR(NULL, "Truststore entry \"%s\" not found.", referenced_name);
        return 1;
    }

    /* check if any of the referenced public keys is SubjectPublicKeyInfo */
    LY_ARRAY_FOR(ts->pubkey_bags[i].pubkeys, u) {
        if (nc_is_pk_subject_public_key_info(ts->pubkey_bags[i].pubkeys[u].data)) {
            ERR(NULL, "A public key of the referenced public key bag \"%s\" is in the SubjectPublicKeyInfo format, "
                    "which is not allowed in SSH!", referenced_name);
            return 1;
        }
    }

    *pubkeys = ts->pubkey_bags[i].pubkeys;
    *pubkey_count = LY_ARRAY_COUNT(ts->pubkey_bags[i].pubkeys);
    return 0;
}

/**
 * @brief Convert UID to string.
 *
 * @param[in] uid UID to convert.
 * @return UID converted to string or NULL on fail.
 */
static char *
nc_server_ssh_uid_to_str(uid_t uid)
{
    int buf_len;
    char *uid_str;

    /* get the number of digits and alloc */
    buf_len = snprintf(NULL, 0, "%u", uid);
    uid_str = malloc(buf_len + 1);
    NC_CHECK_ERRMEM_RET(!uid_str, NULL);

    /* convert to string */
    sprintf(uid_str, "%u", uid);
    uid_str[buf_len] = '\0';
    return uid_str;
}

/**
 * @brief Append a character or a string to a string.
 *
 * @param[in] src_c Source character.
 * @param[in] src_str Source string.
 * @param[in,out] size Size of the destination string.
 * @param[out] idx Index of the next character to write.
 * @param[out] dst Destination string.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_ssh_str_append(const char src_c, const char *src_str, int *size, int *idx, char **dst)
{
    int src_size, allocate = 0, ret;

    /* get size of char/string we want to append */
    if (src_str) {
        src_size = strlen(src_str);
    } else {
        src_size = 1;
    }

    /* check if we have enough space, if not realloc */
    while ((src_size + *idx) >= *size) {
        (*size) += 16;
        allocate = 1;
    }
    if (allocate) {
        *dst = nc_realloc(*dst, *size);
        NC_CHECK_ERRMEM_RET(!*dst, 1);
    }

    /* append the char/string */
    if (src_str) {
        ret = sprintf(*dst + *idx, "%s", src_str);
    } else {
        ret = sprintf(*dst + *idx, "%c", src_c);
    }
    if (ret < 0) {
        return 1;
    }

    *idx += ret;
    return 0;
}

/**
 * @brief Get the path to the system public keys from format set by an API.
 *
 * @param[in] username Username.
 * @param[out] out_path Path to the system public keys.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_ssh_get_system_keys_path(const char *username, char **out_path)
{
    int ret = 0, i, have_percent = 0, size = 0, idx = 0, fmt_set = 0;
    char *path_fmt = NULL;
    char *path = NULL, *buf = NULL, *uid = NULL;
    struct passwd *pw, pw_buf;
    size_t buf_len = 0;

    /* OPTS READ LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_READ, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }
    if (server_opts.authkey_path_fmt) {
        fmt_set = 1;
        path_fmt = strdup(server_opts.authkey_path_fmt);
    }
    /* OPTS READ UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);

    if (!fmt_set) {
        ERR(NULL, "System public keys path format not set.");
        return 1;
    }
    NC_CHECK_ERRMEM_RET(!path_fmt, 1);

    /* check if the path format contains any tokens */
    if (strstr(path_fmt, "%h") || strstr(path_fmt, "%U") || strstr(path_fmt, "%u") || strstr(path_fmt, "%%")) {
        /* get pw */
        pw = nc_getpw(0, username, &pw_buf, &buf, &buf_len);
        if (!pw) {
            ERR(NULL, "Unable to get passwd entry for user \"%s\".", username);
            ret = 1;
            goto cleanup;
        }

        /* convert UID to a string */
        uid = nc_server_ssh_uid_to_str(pw->pw_uid);
        if (!uid) {
            ret = 1;
            goto cleanup;
        }
    } else {
        /* no tokens, just copy the path and return */
        *out_path = strdup(path_fmt);
        NC_CHECK_ERRMEM_GOTO(!*out_path, ret = 1, cleanup);
        goto cleanup;
    }

    /* go over characters from format, copy them to path and interpret tokens correctly */
    for (i = 0; path_fmt[i]; i++) {
        if (have_percent) {
            /* special token, need to convert it */
            if (path_fmt[i] == '%') {
                ret = nc_server_ssh_str_append('%', NULL, &size, &idx, &path);
            } else if (path_fmt[i] == 'h') {
                /* user home */
                ret = nc_server_ssh_str_append(0, pw->pw_dir, &size, &idx, &path);
            } else if (path_fmt[i] == 'u') {
                /* username */
                ret = nc_server_ssh_str_append(0, username, &size, &idx, &path);
            } else if (path_fmt[i] == 'U') {
                /* UID */
                ret = nc_server_ssh_str_append(0, uid, &size, &idx, &path);
            } else {
                ERR(NULL, "Failed to parse system public keys path format \"%s\".", path_fmt);
                ret = 1;
            }

            have_percent = 0;
        } else {
            if (path_fmt[i] == '%') {
                have_percent = 1;
            } else {
                /* ordinary character with no meaning */
                ret = nc_server_ssh_str_append(path_fmt[i], NULL, &size, &idx, &path);
            }
        }

        if (ret) {
            goto cleanup;
        }
    }

    *out_path = path;
    path = NULL;

cleanup:
    free(path_fmt);
    free(uid);
    free(buf);
    free(path);
    return ret;
}

/**
 * @brief Read public keys from the authorized keys file.
 *
 * @param[in] path Path to the authorized keys file.
 * @param[out] pubkeys Public keys.
 * @param[out] pubkey_count Public key count.
 * @return 0 on success, 1 on error.
 */
static int
nc_server_ssh_read_authorized_keys_file(const char *path, struct nc_public_key **pubkeys, uint32_t *pubkey_count)
{
    int ret = 0, rc, line_num = 0;
    FILE *f = NULL;
    char *line = NULL, *ptr, *ptr2;
    size_t n;
    enum ssh_keytypes_e ktype;

    NC_CHECK_ARG_RET(NULL, path, pubkeys, 1);

    *pubkeys = NULL;
    *pubkey_count = 0;

    f = fopen(path, "r");
    if (!f) {
        ERR(NULL, "Unable to open \"%s\" (%s).", path, strerror(errno));
        ret = 1;
        goto cleanup;
    }

    while (getline(&line, &n, f) > -1) {
        ++line_num;
        if ((line[0] == '#') || (line[0] == '\n')) {
            /* comment or empty line */
            continue;
        }

        /* separate key type */
        ptr = line;
        for (ptr2 = ptr; ptr2[0] && !isspace(ptr2[0]); ptr2++) {}
        if (!ptr2[0]) {
            ERR(NULL, "Invalid format of authorized keys file \"%s\" on line %d.", path, line_num);
            ret = 1;
            goto cleanup;
        }
        ptr2[0] = '\0';

        /* detect key type */
        ktype = ssh_key_type_from_name(ptr);
        if ((ktype != SSH_KEYTYPE_RSA) && (ktype != SSH_KEYTYPE_ECDSA_P256) && (ktype != SSH_KEYTYPE_ECDSA_P384) &&
                (ktype != SSH_KEYTYPE_ECDSA_P521) && (ktype != SSH_KEYTYPE_ED25519)) {
            WRN(NULL, "Unsupported key type \"%s\" in authorized keys file \"%s\" on line %d.", ptr, path, line_num);
            continue;
        }

        /* get key data */
        ptr = ptr2 + 1;
        for (ptr2 = ptr; ptr2[0] && !isspace(ptr2[0]); ptr2++) {}
        ptr2[0] = '\0';

        /* add the key */
        *pubkeys = nc_realloc(*pubkeys, (*pubkey_count + 1) * sizeof **pubkeys);
        NC_CHECK_ERRMEM_GOTO(!(*pubkeys), ret = 1, cleanup);
        rc = asprintf(&(*pubkeys)[*pubkey_count].name, "authorized_key_%" PRIu32, *pubkey_count);
        NC_CHECK_ERRMEM_GOTO(rc == -1, (*pubkeys)[*pubkey_count].name = NULL; ret = 1, cleanup);
        (*pubkeys)[*pubkey_count].type = NC_PUBKEY_FORMAT_SSH;
        (*pubkeys)[*pubkey_count].data = strdup(ptr);
        NC_CHECK_ERRMEM_GOTO(!(*pubkeys)[*pubkey_count].data, ret = 1, cleanup);
        (*pubkey_count)++;
    }

    /* ok */
    ret = 0;
cleanup:
    if (f) {
        fclose(f);
    }
    free(line);
    return ret;
}

int
nc_server_ssh_get_system_keys(const char *username, struct nc_public_key **pubkeys, uint32_t *pubkey_count)
{
    int ret = 0;
    char *path = NULL;

    /* convert the path format to get the actual path */
    ret = nc_server_ssh_get_system_keys_path(username, &path);
    if (ret) {
        ERR(NULL, "Getting system keys path failed.");
        goto cleanup;
    }

    /* get the keys */
    ret = nc_server_ssh_read_authorized_keys_file(path, pubkeys, pubkey_count);
    if (ret) {
        ERR(NULL, "Reading system keys failed.");
        goto cleanup;
    }

cleanup:
    free(path);
    return ret;
}

#ifdef HAVE_SHADOW

/**
 * @brief Get the user's /etc/passwd entry.
 *
 * @param[in] username Username.
 * @param[out] pwd_buf Buffer for the passwd structure.
 * @param[out] buf Buffer for the pwd's strings.
 * @param[out] buf_size Size of the buffer.
 * @return User's passwd entry or NULL on error.
 */
static struct passwd *
nc_server_ssh_getpwnam(const char *username, struct passwd *pwd_buf, char **buf, size_t *buf_size)
{
    struct passwd *pwd = NULL;
    char *mem;
    int r = 0;

    do {
        r = getpwnam_r(username, pwd_buf, *buf, *buf_size, &pwd);
        if (pwd) {
            /* entry found */
            break;
        }

        if (r == ERANGE) {
            /* small buffer, enlarge */
            *buf_size <<= 2;
            mem = realloc(*buf, *buf_size);
            if (!mem) {
                ERRMEM;
                return NULL;
            }
            *buf = mem;
        }
    } while (r == ERANGE);

    return pwd;
}

/**
 * @brief Get the user's /etc/shadow entry.
 *
 * @param[in] username Username.
 * @param[out] spwd_buf Buffer for the spwd structure.
 * @param[out] buf Buffer for the spwd's strings.
 * @param[out] buf_size Size of the buffer.
 * @return User's shadow entry or NULL on error.
 */
static struct spwd *
nc_server_ssh_getspnam(const char *username, struct spwd *spwd_buf, char **buf, size_t *buf_size)
{
    struct spwd *spwd = NULL;
    char *mem;
    int r = 0;

    do {
# ifndef __QNXNTO__
        r = getspnam_r(username, spwd_buf, *buf, *buf_size, &spwd);
# else
        spwd = getspnam_r(username, spwd_buf, *buf, *buf_size);
        r = errno;
# endif
        if (spwd) {
            /* entry found */
            break;
        }

        if (r == ERANGE) {
            /* small buffer, enlarge */
            *buf_size <<= 2;
            mem = realloc(*buf, *buf_size);
            if (!mem) {
                ERRMEM;
                return NULL;
            }
            *buf = mem;
        }
    } while (r == ERANGE);

    return spwd;
}

char *
nc_server_ssh_get_pwd_hash(const char *username)
{
    struct passwd *pwd, pwd_buf;
    struct spwd *spwd, spwd_buf;
    char *pass_hash = NULL, *buf = NULL;
    size_t buf_size = 256;

    buf = malloc(buf_size);
    NC_CHECK_ERRMEM_GOTO(!buf, , error);

    pwd = nc_server_ssh_getpwnam(username, &pwd_buf, &buf, &buf_size);
    if (!pwd) {
        VRB(NULL, "User \"%s\" not found in the system.", username);
        goto error;
    }

    if (!strcmp(pwd->pw_passwd, "x")) {
        spwd = nc_server_ssh_getspnam(username, &spwd_buf, &buf, &buf_size);
        if (!spwd) {
            VRB(NULL, "Failed to retrieve the shadow entry for \"%s\".", username);
            goto error;
        } else if ((spwd->sp_expire > -1) && (spwd->sp_expire <= (time(NULL) / (60 * 60 * 24)))) {
            WRN(NULL, "User \"%s\" account has expired.", username);
            goto error;
        }

        pass_hash = spwd->sp_pwdp;
    } else {
        pass_hash = pwd->pw_passwd;
    }

    if (!pass_hash) {
        ERR(NULL, "No password could be retrieved for \"%s\".", username);
        goto error;
    }

    /* check the hash structure for special meaning */
    if (!strcmp(pass_hash, "*") || !strcmp(pass_hash, "!")) {
        VRB(NULL, "User \"%s\" is not allowed to authenticate using a password.", username);
        goto error;
    }
    if (!strcmp(pass_hash, "*NP*")) {
        VRB(NULL, "Retrieving password for \"%s\" from a NIS+ server not supported.", username);
        goto error;
    }

    pass_hash = strdup(pass_hash);
    free(buf);
    return pass_hash;

error:
    free(buf);
    return NULL;
}

int
nc_server_ssh_kbdint_send_passwd_prompt(struct nc_session *session, const char *username, ssh_message msg)
{
    const char *name = "Keyboard-Interactive Authentication";
    const char *instruction = "Please enter your authentication token";
    char *prompt = NULL;
    char echo[] = {0};
    int rc;

    rc = asprintf(&prompt, "%s's password:", username);
    NC_CHECK_ERRMEM_RET(rc == -1, 1);

    rc = ssh_message_auth_interactive_request(msg, name, instruction, 1, (const char **)&prompt, echo);
    free(prompt);
    if (rc) {
        ERR(session, "Failed to send an authentication request to client \"%s\".", username);
        return 1;
    }

    return 0;
}

int
nc_server_ssh_kbdint_verify_passwd(struct nc_session *session, const char *username, int n_answers)
{
    char *pw = NULL, *received_pw = NULL;
    const char *answer;
    int rc;

    if (nc_authlock_denied(session, username)) {
        return 1;
    }

    if (n_answers != 1) {
        ERR(session, "Unexpected amount of answers in system auth. Expected 1, got \"%d\".", n_answers);
        return 1;
    }

    pw = nc_server_ssh_get_pwd_hash(username);
    if (!pw) {
        return 1;
    }

    answer = ssh_userauth_kbdint_getanswer(session->ti.libssh.session, 0);
    if (!answer) {
        ERR(session, "Failed to get keyboard-interactive password answer.");
        free(pw);
        return 1;
    }
    received_pw = strdup(answer);
    if (!received_pw) {
        ERRMEM;
        free(pw);
        return 1;
    }

    rc = nc_server_ssh_compare_password(pw, received_pw);
    free(pw);
    free(received_pw);

    nc_authlock_record(session, username, rc ? 0 : 1);

    return rc;
}

#endif

int
nc_server_ssh_compare_password(const char *stored_pw, const char *received_pw)
{
    char *received_pw_hash = NULL;
    struct crypt_data *cdata;
    int ret;

    NC_CHECK_ARG_RET(NULL, stored_pw, received_pw, 1);

    if (!stored_pw[0]) {
        if (!received_pw[0]) {
            WRN(NULL, "User authentication successful with an empty password!");
            return 0;
        } else {
            /* the user did now know he does not need any password,
             * (which should not be used) so deny authentication */
            return 1;
        }
    }

    if (!strncmp(stored_pw, "$0$", 3)) {
        /* cleartext password, simply compare the values */
        return strcmp(stored_pw + 3, received_pw);
    }

    cdata = calloc(1, sizeof *cdata);
    NC_CHECK_ERRMEM_RET(!cdata, 1);

    received_pw_hash = crypt_r(received_pw, stored_pw, cdata);
    if (!received_pw_hash) {
        ERR(NULL, "Hashing the password failed (%s).", strerror(errno));
        free(cdata);
        return 1;
    }

    ret = strcmp(received_pw_hash, stored_pw);
    free(cdata);

    return ret;
}

API int
nc_server_ssh_kbdint_get_nanswers(const struct nc_session *session, ssh_session libssh_session)
{
    int ret = 0;
    struct timespec ts_timeout = {0};
    ssh_message reply = NULL;
    uint16_t auth_timeout = *((uint16_t *)session->data);

    NC_CHECK_ARG_RET(NULL, session, libssh_session, -1);

    if (auth_timeout) {
        nc_timeouttime_get(&ts_timeout, auth_timeout * 1000);
    }

    /* wait for answers from the client */
    do {
        if (!ssh_is_connected(session->ti.libssh.session)) {
            ERR(NULL, "SSH communication socket unexpectedly closed while waiting for keyboard-interactive authentication answers.");
            ret = -1;
            goto cleanup;
        }

        reply = ssh_message_get(libssh_session);
        if (reply) {
            break;
        }

        usleep(NC_TIMEOUT_STEP);
    } while (auth_timeout && (nc_timeouttime_cur_diff(&ts_timeout) >= 1));
    if (!reply) {
        ERR(NULL, "Authentication timeout.");
        ret = -1;
        goto cleanup;
    }

    ret = ssh_userauth_kbdint_getnanswers(libssh_session);

cleanup:
    ssh_message_free(reply);
    return ret;
}

API void
nc_server_ssh_set_interactive_auth_clb(int (*interactive_auth_clb)(const struct nc_session *session, ssh_session ssh_sess, ssh_message msg, void *user_data),
        void *user_data, void (*free_user_data)(void *user_data))
{
    /* OPTS WRITE LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_WRITE, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return;
    }

    server_opts.interactive_auth_clb = interactive_auth_clb;
    server_opts.interactive_auth_data = user_data;
    server_opts.interactive_auth_data_free = free_user_data;

    /* OPTS WRITE UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
}

int
nc_server_ssh_get_interactive_auth_clb(int (**clb)(const struct nc_session *session, ssh_session ssh_sess,
        ssh_message msg, void *user_data), void **user_data)
{
    *clb = NULL;
    *user_data = NULL;

    /* OPTS READ LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_READ, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    /* the callback and its data must be read as a pair */
    *clb = server_opts.interactive_auth_clb;
    *user_data = server_opts.interactive_auth_data;

    /* OPTS READ UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
    return 0;
}

#ifdef HAVE_LIBPAM

API int
nc_server_ssh_set_pam_conf_filename(const char *filename)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, filename, 1);

    /* OPTS WRITE LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_WRITE, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    free(server_opts.pam_config_name);
    server_opts.pam_config_name = strdup(filename);
    if (!server_opts.pam_config_name) {
        ERRMEM;
        ret = 1;
    }

    /* OPTS WRITE UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
    return ret;
}

#else

API int
nc_server_ssh_set_pam_conf_filename(const char *filename)
{
    /* LibPAM not supported */
    (void) filename;
    return 1;
}

#endif /* HAVE_LIBPAM */

API int
nc_server_ssh_set_authkey_path_format(const char *path)
{
    int ret = 0;

    NC_CHECK_ARG_RET(NULL, path, 1);

    /* OPTS WRITE LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_WRITE, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        return 1;
    }

    free(server_opts.authkey_path_fmt);
    server_opts.authkey_path_fmt = strdup(path);
    if (!server_opts.authkey_path_fmt) {
        ERRMEM;
        ret = 1;
    }

    /* OPTS WRITE UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);
    return ret;
}

/**
 * @brief Forge the SSH protocol identification string based on the given prefix and the library versions.
 *
 * @param[in] prefix Optional prefix to include in the protocol string, can be NULL.
 * @return Protocol string on success, NULL on error.
 */
static char *
nc_server_ssh_forge_protocol_string(const char *prefix)
{
    int r;
    char *protocol_str = NULL;

    if (prefix) {
        r = asprintf(&protocol_str, "%s-libnetconf2_%s-libssh_%d.%d.%d",
                prefix, NC_VERSION,
                LIBSSH_VERSION_MAJOR, LIBSSH_VERSION_MINOR, LIBSSH_VERSION_MICRO);
    } else {
        r = asprintf(&protocol_str, "libnetconf2_%s-libssh_%d.%d.%d",
                NC_VERSION,
                LIBSSH_VERSION_MAJOR, LIBSSH_VERSION_MINOR, LIBSSH_VERSION_MICRO);
    }
    NC_CHECK_ERRMEM_RET(r == -1, NULL);

    if (strlen(protocol_str) > 245) {
        ERR(NULL, "SSH protocol identification string too long (max 245 characters).");
        free(protocol_str);
        return NULL;
    }

    return protocol_str;
}

API int
nc_server_ssh_set_protocol_string(const char *prefix)
{
    int rc = 0;
    char *protocol_str = NULL;

    NC_CHECK_ARG_RET(NULL, prefix, 1);

    protocol_str = nc_server_ssh_forge_protocol_string(prefix);
    NC_CHECK_ERRMEM_GOTO(!protocol_str, rc = 1, cleanup);

    /* OPTS WRITE LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_WRITE, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        rc = 1;
        goto cleanup;
    }

    /* transfer ownership */
    free(server_opts.ssh_protocol_string);
    server_opts.ssh_protocol_string = protocol_str;
    protocol_str = NULL;

    /* OPTS WRITE UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);

cleanup:
    free(protocol_str);
    return rc;
}

/**
 * @brief Get the public key type from binary data.
 *
 * @param[in] buffer Binary key data, which is in the form of: 4 bytes = data length, then data of data length.
 * Data is in network byte order. The key has to be in the SSH2 format.
 * @param[out] len Length of the key type.
 * @return Pointer to where the key type starts in the buffer and is of the length @p len .
 */
static const char *
nc_server_ssh_get_pubkey_type(const unsigned char *buffer, uint32_t *len)
{
    uint32_t type_len;

    /* copy the 4 bytes */
    memcpy(&type_len, buffer, sizeof type_len);
    /* type_len now stores the length of the key type */
    type_len = ntohl(type_len);
    *len = type_len;

    /* move 4 bytes in the buffer, this is where the type should be */
    buffer += sizeof type_len;
    return (const char *)buffer;
}

/**
 * @brief Create ssh key from base64 pubkey data.
 *
 * @param[in] base64 base64 encoded public key.
 * @param[out] key created ssh key.
 * @return 0 on success, 1 otherwise.
 */
static int
nc_server_ssh_create_ssh_pubkey(const char *base64, ssh_key *key)
{
    int ret = 0;
    unsigned char *bin = NULL;
    const char *pub_type = NULL;
    uint32_t pub_type_len = 0;

    NC_CHECK_ARG_RET(NULL, base64, key, 1);

    *key = NULL;

    /* convert base64 to binary */
    if (nc_base64_decode_wrap(base64, &bin) == -1) {
        ret = 1;
        goto cleanup;
    }

    /* get the key type and try to import it if possible */
    pub_type = nc_server_ssh_get_pubkey_type(bin, &pub_type_len);
    if (!pub_type) {
        ret = 1;
        goto cleanup;
    } else if (!strncmp(pub_type, "ssh-dss", pub_type_len)) {
        ERR(NULL, "DSA keys are not supported.");
        ret = 1;
        goto cleanup;
    } else if (!strncmp(pub_type, "ssh-rsa", pub_type_len)) {
        ret = ssh_pki_import_pubkey_base64(base64, SSH_KEYTYPE_RSA, key);
    } else if (!strncmp(pub_type, "ecdsa-sha2-nistp256", pub_type_len)) {
        ret = ssh_pki_import_pubkey_base64(base64, SSH_KEYTYPE_ECDSA_P256, key);
    } else if (!strncmp(pub_type, "ecdsa-sha2-nistp384", pub_type_len)) {
        ret = ssh_pki_import_pubkey_base64(base64, SSH_KEYTYPE_ECDSA_P384, key);
    } else if (!strncmp(pub_type, "ecdsa-sha2-nistp521", pub_type_len)) {
        ret = ssh_pki_import_pubkey_base64(base64, SSH_KEYTYPE_ECDSA_P521, key);
    } else if (!strncmp(pub_type, "ssh-ed25519", pub_type_len)) {
        ret = ssh_pki_import_pubkey_base64(base64, SSH_KEYTYPE_ED25519, key);
    } else {
        ERR(NULL, "Public key type not recognised.");
        ret = 1;
        goto cleanup;
    }

cleanup:
    if (ret != SSH_OK) {
        ERR(NULL, "Error importing public key.");
    }
    free(bin);
    return ret;
}

int
nc_server_ssh_auth_pubkey_compare_key(ssh_key key, struct nc_public_key *pubkeys, uint16_t pubkey_count)
{
    uint16_t i;
    int ret = 0;
    ssh_key new_key = NULL;

    /* try to compare all of the client's keys with the key received in the SSH message */
    for (i = 0; i < pubkey_count; i++) {
        /* create the SSH key from the data */
        if (nc_server_ssh_create_ssh_pubkey(pubkeys[i].data, &new_key)) {
            /* skip */
            ssh_key_free(new_key);
            continue;
        }

        /* compare the keys */
        ret = ssh_key_cmp(key, new_key, SSH_KEY_CMP_PUBLIC);
        ssh_key_free(new_key);
        if (!ret) {
            /* found a match */
            break;
        }
    }
    if (i == pubkey_count) {
        ret = 1;
    }

    return ret;
}

void
nc_server_ssh_send_banner(struct nc_session *session, struct nc_server_ssh_opts *opts)
{
    if (!opts->banner) {
        return;
    }

#if (LIBSSH_VERSION_MAJOR > 0) || (LIBSSH_VERSION_MAJOR == 0 && LIBSSH_VERSION_MINOR >= 10)
    ssh_string ban;

    ban = ssh_string_from_char(opts->banner);
    if (ban) {
        if (ssh_send_issue_banner(session->ti.libssh.session, ban)) {
            ERR(session, "Failed to send SSH banner (%s).", ssh_get_error(session->ti.libssh.session));
        }
        ssh_string_free(ban);
    }
#else
    WRN(session, "SSH banner set but cannot be sent (libssh version 0.10.0 or later required).");
#endif
}

/* ret 1 on success, 0 on timeout, -1 on error */
static int
nc_accept_ssh_session_open_netconf_channel(struct nc_session *session, struct nc_server_ssh_opts *opts)
{
    struct timespec ts_timeout;

#if LIBSSH_0_12
    int32_t time_diff;
    int ret;
#else
    ssh_message msg;
#endif

    DBG(session, "Waiting for \"netconf\" SSH subsystem request...");

    nc_timeouttime_get(&ts_timeout, NC_TRANSPORT_MSG_TIMEOUT);

#if LIBSSH_0_12
    (void) opts;

    /* Run the event loop instead of ssh_message_get() */
    while (!(session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
        if (!ssh_is_connected(session->ti.libssh.session)) {
            ERR(session, "Communication SSH socket unexpectedly closed.");
            return -1;
        }

        if (nc_session_handshake_interrupted(session)) {
            VRB(session, "Waiting for the \"netconf\" SSH subsystem interrupted, the Call Home thread is terminating.");
            return 0;
        }

        time_diff = nc_timeouttime_cur_diff(&ts_timeout);
        if (time_diff < 1) {
            /* timeout */
            ERR(session, "Failed to start \"netconf\" SSH subsystem for too long, disconnecting.");
            break;
        }

        /* This functions listens to the network and automatically calls callback funcitons. */
        ret = ssh_event_dopoll(session->ti.libssh.event, nc_session_handshake_poll_timeout(session, time_diff));
        if (ret == SSH_ERROR) {
            ERR(session, "Failed to poll SSH event (%s).", ssh_get_error(session->ti.libssh.session));
            return -1;
        }
        /* SSH_AGAIN only means the poll timeout elapsed, which may have been shortened to notice an
         * interrupt, so ts_timeout checked at the top of the loop is the only authority */
    }

    if (session->flags & NC_SESSION_SSH_SUBSYS_NETCONF) {
        VRB(session, "NETCONF subsystem successfully opened.");
        return 1;
    }
#else
    while (1) {
        if (!ssh_is_connected(session->ti.libssh.session)) {
            ERR(session, "Communication SSH socket unexpectedly closed while waiting for \"netconf\" subsystem request.");
            return -1;
        }

        msg = ssh_message_get(session->ti.libssh.session);
        if (msg) {
            if (nc_session_ssh_msg(session, opts, msg, NULL)) {
                ssh_message_reply_default(msg);
            }
            ssh_message_free(msg);
        }

        if (session->ti.libssh.channel && session->flags & NC_SESSION_SSH_SUBSYS_NETCONF) {
            return 1;
        }

        if (nc_session_handshake_interrupted(session)) {
            VRB(session, "Waiting for the \"netconf\" SSH subsystem interrupted, the Call Home thread is terminating.");
            return 0;
        }

        usleep(NC_TIMEOUT_STEP);
        if (nc_timeouttime_cur_diff(&ts_timeout) < 1) {
            /* timeout */
            ERR(session, "Failed to start \"netconf\" SSH subsystem for too long, disconnecting.");
            break;
        }
    }
#endif
    return 0;
}

/**
 * @brief Set hostkeys to be used for an SSH bind.
 *
 * @param[in] config Pinned server configuration the options belong to.
 * @param[in] sbind SSH bind to use.
 * @param[in] opts SSH server options.
 * @return 0 on success, -1 on error.
 */
static int
nc_ssh_bind_add_hostkeys(const struct nc_server_config *config, ssh_bind sbind, struct nc_server_ssh_opts *opts)
{
    int rc;
    char *privkey_path;
    struct nc_hostkey *hostkey = NULL;
    struct nc_asymmetric_key *key = NULL;

    LY_ARRAY_FOR(opts->hostkeys, struct nc_hostkey, hostkey) {
        privkey_path = NULL;

        /* get the asymmetric key */
        if (hostkey->store == NC_STORE_LOCAL) {
            /* stored locally */
            key = &hostkey->key;
        } else {
            /* keystore reference, need to get it */
            NC_CHECK_RET(nc_server_ssh_ks_ref_get_key(config, hostkey->ks_ref, &key), -1);
        }

        privkey_path = nc_server_ssh_privkey_data_to_tmp_file(key->privkey.data, nc_privkey_format_to_str(key->privkey.type));
        NC_CHECK_ERR_RET(!privkey_path, ERR(NULL, "Temporarily storing a host key into a file failed."), -1);

        rc = ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HOSTKEY, privkey_path);
        if (unlink(privkey_path)) {
            WRN(NULL, "Removing a temporary host key file \"%s\" failed (%s).", privkey_path, strerror(errno));
        }
        free(privkey_path);
        NC_CHECK_ERR_RET(rc != SSH_OK, ERR(NULL, "Failed to set hostkey \"%s\".", hostkey->name), -1);
    }

    return 0;
}

static int
nc_accept_ssh_session_auth(struct nc_session *session, struct nc_server_ssh_opts *opts)
{
    struct timespec ts_timeout = {0};

#if LIBSSH_0_12
    ssh_event event;
    int32_t time_diff;
    int ret;
#else
    ssh_message msg;
    struct nc_auth_state auth_state = {0};
#endif

    DBG(session, "SSH authentication...");

    /* the credential checks are reached from libssh callbacks that are not given @p opts, so the
     * lockout policy of this endpoint has to be on the session before the first one runs */
    session->opts.server.authlock = opts->authlock;

    /* authenticate */
    if (opts->auth_timeout) {
        nc_timeouttime_get(&ts_timeout, opts->auth_timeout * 1000);
    }
#if LIBSSH_0_12
    /* Create an event loop */
    event = ssh_event_new();
    if (!event) {
        ERR(session, "Failed to create SSH event.");
        return -1;
    }

    if (ssh_event_add_session(event, session->ti.libssh.session) == SSH_ERROR) {
        ERR(session, "Failed to add SSH session to event.");
        ssh_event_free(event);
        return -1;
    }
    session->ti.libssh.event = event;

    /* Run the event loop instead of ssh_message_get() */
    while (!(session->flags & NC_SESSION_SSH_AUTHENTICATED)) {
        if (!ssh_is_connected(session->ti.libssh.session)) {
            ERR(session, "Communication SSH socket unexpectedly closed.");
            return -1;
        }

        if (nc_session_handshake_interrupted(session)) {
            VRB(session, "SSH authentication interrupted, the Call Home thread is terminating.");
            return 0;
        }

        if (opts->auth_timeout) {
            time_diff = nc_timeouttime_cur_diff(&ts_timeout);
            if (time_diff < 1) {
                /* timeout */
                break;
            }
        } else {
            /* no authentication timeout, wait indefinitely */
            time_diff = -1;
        }

        /* This functions listens to the network and automatically calls callback funcitons. */
        ret = ssh_event_dopoll(event, nc_session_handshake_poll_timeout(session, time_diff));
        if (ret == SSH_ERROR) {
            ERR(session, "Failed to poll SSH event (%s).", ssh_get_error(session->ti.libssh.session));
            return -1;
        }
        /* SSH_AGAIN only means the poll timeout elapsed, which may have been shortened to notice an
         * interrupt, so ts_timeout checked at the top of the loop is the only authority */
    }
#else
    while (1) {
        if (!ssh_is_connected(session->ti.libssh.session)) {
            ERR(session, "Communication SSH socket unexpectedly closed while waiting for authentication.");
            return -1;
        }

        msg = ssh_message_get(session->ti.libssh.session);
        if (msg) {
            if (nc_session_ssh_msg(session, opts, msg, &auth_state)) {
                ssh_message_reply_default(msg);
            }
            ssh_message_free(msg);
        }

        if (session->flags & NC_SESSION_SSH_AUTHENTICATED) {
            break;
        }

        if (nc_session_handshake_interrupted(session)) {
            VRB(session, "SSH authentication interrupted, the Call Home thread is terminating.");
            return 0;
        }

        usleep(NC_TIMEOUT_STEP);
        if (opts->auth_timeout && (nc_timeouttime_cur_diff(&ts_timeout) < 1)) {
            /* timeout */
            break;
        }
    }
#endif

    if (!(session->flags & NC_SESSION_SSH_AUTHENTICATED)) {
        /* timeout */
        if (session->username) {
            ERR(session, "User \"%s\" failed to authenticate for too long, disconnecting.", session->username);
        } else {
            ERR(session, "User failed to authenticate for too long, disconnecting.");
        }
        return 0;
    }

    return 1;
}

int
nc_accept_ssh_session(struct nc_session *session, struct nc_server_ssh_opts *opts, int sock)
{
    ssh_bind sbind = NULL;
    int rc = 1, r, proto_str_set = 0;
    struct timespec ts_timeout;
    const char *err_msg;
    char *proto_str = NULL;

#if LIBSSH_0_12
    struct nc_server_ssh_cb_data *cb_data = NULL;
#endif

    /* other transport-specific data */
    session->ti_type = NC_TI_SSH;
    session->ti.libssh.session = ssh_new();
    if (!session->ti.libssh.session) {
        ERR(NULL, "Failed to initialize a new SSH session.");
        rc = -1;
        goto cleanup;
    }

#if LIBSSH_0_12
    cb_data = calloc(1, sizeof *cb_data);
    NC_CHECK_ERRMEM_GOTO(!cb_data, rc = -1, cleanup);
    cb_data->session = session;
    cb_data->opts = opts;

    cb_data->server_cb.userdata = cb_data;
    cb_data->server_cb.auth_password_function = nc_server_ssh_cb_auth_password;
    cb_data->server_cb.auth_pubkey_function = nc_server_ssh_cb_auth_pubkey;
    cb_data->server_cb.auth_none_function = nc_server_ssh_cb_auth_none;
    cb_data->server_cb.auth_kbdint_function = nc_server_ssh_cb_auth_kbdint;
    cb_data->server_cb.channel_open_request_session_function = nc_server_ssh_cb_channel_open_request_session;

    ssh_callbacks_init(&cb_data->server_cb);
    ssh_set_server_callbacks(session->ti.libssh.session, &cb_data->server_cb);
    session->ti.libssh.cb_data = cb_data;
#endif /* LIBSSH_0_12 */

    sbind = ssh_bind_new();
    if (!sbind) {
        ERR(session, "Failed to create an SSH bind.");
        rc = -1;
        goto cleanup;
    }

    /* configure host keys */
    if (nc_ssh_bind_add_hostkeys(session->opts.server.config, sbind, opts)) {
        rc = -1;
        goto cleanup;
    }

    /* configure supported algorithms */
    if (opts->hostkey_algs && ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS, opts->hostkey_algs)) {
        ERR(session, "Failed to set hostkey algorithms (%s).", ssh_get_error(sbind));
        rc = -1;
        goto cleanup;
    }
    if (opts->encryption_algs) {
        /* both client->server and server->client directions set for the same reason as for MAC algorithms below */
        if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_CIPHERS_S_C, opts->encryption_algs) ||
                ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_CIPHERS_C_S, opts->encryption_algs)) {
            ERR(session, "Failed to set encryption algorithms (%s).", ssh_get_error(sbind));
            rc = -1;
            goto cleanup;
        }
    }
    if (opts->kex_algs && ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_KEY_EXCHANGE, opts->kex_algs)) {
        ERR(session, "Failed to set key exchange algorithms (%s).", ssh_get_error(sbind));
        rc = -1;
        goto cleanup;
    }
    if (opts->mac_algs) {
        /* * SSH negotiates MAC algorithms independently for each direction (Client->Server
         * and Server->Client). We must explicitly apply the configured algorithms to
         * both directions to ensure consistent security and avoid falling back to
         * libssh defaults for the unspecified direction.
         * Ref: https://github.com/CESNET/libnetconf2/issues/523
         */
        if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HMAC_S_C, opts->mac_algs) ||
                ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_HMAC_C_S, opts->mac_algs)) {
            ERR(session, "Failed to set MAC algorithms (%s).", ssh_get_error(sbind));
            rc = -1;
            goto cleanup;
        }
    }

    /* configure the ssh protocol identification string, copy it so that the lock is not held any longer */
    /* OPTS READ LOCK */
    if (nc_rwlock_lock(&server_opts.opts_lock, NC_RWLOCK_READ, NC_OPTS_LOCK_TIMEOUT, __func__) != 1) {
        rc = -1;
        goto cleanup;
    }
    if (server_opts.ssh_protocol_string) {
        proto_str_set = 1;
        proto_str = strdup(server_opts.ssh_protocol_string);
    }
    /* OPTS READ UNLOCK */
    nc_rwlock_unlock(&server_opts.opts_lock, __func__);

    if (!proto_str_set) {
        proto_str = nc_server_ssh_forge_protocol_string(NULL);
    }
    NC_CHECK_ERRMEM_GOTO(!proto_str, rc = -1, cleanup);

    if (ssh_bind_options_set(sbind, SSH_BIND_OPTIONS_BANNER, proto_str)) {
        rc = -1;
        goto cleanup;
    }

    /* accept new connection on the bind */
    if (ssh_bind_accept_fd(sbind, session->ti.libssh.session, sock) == SSH_ERROR) {
        ERR(session, "SSH failed to accept a new connection (%s).", ssh_get_error(sbind));
        rc = -1;

        /* Avoid closing the socket on failure to prevent a possible double close.
         * On failure, sock may or not be set to the session. In theory, we should
         * be able to compare sock with ssh_get_fd() and close it only if it was
         * not set, for example:
         *
         *     if (ssh_get_fd(session) == sock)
         *         sock = -1;
         *
         * However, if ssh_bind_accept_fd() fails to allocate the socket structure
         * internally, calling ssh_get_fd() will dereference a NULL pointer due to
         * a buggy behavior in libssh.
         */
        sock = -1;
        goto cleanup;
    }

    /* use SSH_OPTIONS_FD so libssh won't close the socket in ssh_disconnect() */
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_FD, &sock);
    sock = -1;

    /* set to non-blocking */
    ssh_set_blocking(session->ti.libssh.session, 0);

    DBG(session, "Performing SSH key exchange...");
    nc_timeouttime_get(&ts_timeout, NC_TRANSPORT_HANDSHAKE_TIMEOUT);
    while ((r = ssh_handle_key_exchange(session->ti.libssh.session)) == SSH_AGAIN) {
        if (nc_session_handshake_interrupted(session)) {
            VRB(session, "SSH key exchange interrupted, the Call Home thread is terminating.");
            rc = 0;
            goto cleanup;
        }

        /* this tends to take longer */
        usleep(NC_TIMEOUT_STEP * 20);
        if (nc_timeouttime_cur_diff(&ts_timeout) < 1) {
            break;
        }
    }
    if (r == SSH_AGAIN) {
        ERR(session, "SSH key exchange timeout.");
        rc = 0;
        goto cleanup;
    } else if (r != SSH_OK) {
        err_msg = ssh_get_error(session->ti.libssh.session);
        if (err_msg[0] == '\0') {
            err_msg = "hostkey algorithm generated from the hostkey most likely not found in the set of configured hostkey algorithms";
        }
        ERR(session, "SSH key exchange error (%s).", err_msg);
        rc = -1;
        goto cleanup;
    }

    /* authenticate, store auth_timeout in session so we can retrieve it in kb interactive API */
    session->data = &opts->auth_timeout;
    rc = nc_accept_ssh_session_auth(session, opts);
    session->data = NULL;

#if LIBSSH_0_12 && defined (HAVE_LIBPAM)
    /* if a PAM thread is still running (auth may have succeeded via another method), cancel and clean it up */
    if (cb_data) {
        nc_server_ssh_cb_pam_cancel(cb_data->pam_kbdint);
        cb_data->pam_kbdint = NULL;
    }
#endif

    if (rc != 1) {
        goto cleanup;
    }

    /* open channel and request 'netconf' subsystem */
    if ((rc = nc_accept_ssh_session_open_netconf_channel(session, opts)) != 1) {
        goto cleanup;
    }

cleanup:
#if LIBSSH_0_12
    /* the transport options belong to a configuration generation that is released once the handshake
     * is over, the callbacks running afterwards must not reach them */
    if (session->ti.libssh.cb_data) {
        ((struct nc_server_ssh_cb_data *)session->ti.libssh.cb_data)->opts = NULL;
    }
#endif /* LIBSSH_0_12 */

    if (sock > -1) {
        close(sock);
    }
    free(proto_str);
    ssh_bind_free(sbind);
    return rc;
}

API NC_MSG_TYPE
nc_session_accept_ssh_channel(struct nc_session *orig_session, struct nc_session **session)
{
    NC_MSG_TYPE msgtype;
    struct nc_session *new_session = NULL;
    struct timespec ts_cur;

    NC_CHECK_ARG_RET(orig_session, orig_session, session, NC_MSG_ERROR);

    if ((NC_SESSION_STATUS_GET(orig_session) == NC_STATUS_RUNNING) && (orig_session->ti_type == NC_TI_SSH) &&
            orig_session->ti.libssh.next) {
        for (new_session = orig_session->ti.libssh.next;
                new_session != orig_session;
                new_session = new_session->ti.libssh.next) {
            if ((NC_SESSION_STATUS_GET(new_session) == NC_STATUS_STARTING) && new_session->ti.libssh.channel &&
                    (new_session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
                /* we found our session */
                break;
            }
        }
        if (new_session == orig_session) {
            new_session = NULL;
        }
    }

    if (!new_session) {
        ERR(orig_session, "Session does not have a NETCONF SSH channel ready.");
        return NC_MSG_ERROR;
    }

    /* assign new SID atomically */
    new_session->id = ATOMIC_INC_RELAXED(server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(new_session);
    if (msgtype != NC_MSG_HELLO) {
        return msgtype;
    }

    nc_realtime_get(&ts_cur);
    new_session->opts.server.session_start = ts_cur;
    nc_timeouttime_get(&ts_cur, 0);
    new_session->opts.server.last_rpc = ts_cur.tv_sec;
    NC_SESSION_STATUS_SET(new_session, NC_STATUS_RUNNING);
    *session = new_session;

    return msgtype;
}

API NC_MSG_TYPE
nc_ps_accept_ssh_channel(struct nc_pollsession *ps, struct nc_session **session)
{
    uint8_t q_id;
    NC_MSG_TYPE msgtype;
    struct nc_session *new_session = NULL, *cur_session;
    struct timespec ts_cur;
    uint16_t i;

    NC_CHECK_ARG_RET(NULL, ps, session, NC_MSG_ERROR);

    /* LOCK */
    if (nc_ps_lock(ps, &q_id, __func__)) {
        return NC_MSG_ERROR;
    }

    for (i = 0; i < ps->session_count; ++i) {
        cur_session = ps->sessions[i]->session;
        if ((NC_SESSION_STATUS_GET(cur_session) == NC_STATUS_RUNNING) && (cur_session->ti_type == NC_TI_SSH) &&
                cur_session->ti.libssh.next) {
            /* an SSH session with more channels */
            for (new_session = cur_session->ti.libssh.next;
                    new_session != cur_session;
                    new_session = new_session->ti.libssh.next) {
                if ((NC_SESSION_STATUS_GET(new_session) == NC_STATUS_STARTING) && new_session->ti.libssh.channel &&
                        (new_session->flags & NC_SESSION_SSH_SUBSYS_NETCONF)) {
                    /* we found our session */
                    break;
                }
            }
            if (new_session != cur_session) {
                break;
            }

            new_session = NULL;
        }
    }

    /* UNLOCK */
    nc_ps_unlock(ps, q_id, __func__);

    if (!new_session) {
        ERR(NULL, "No session with a NETCONF SSH channel ready was found.");
        return NC_MSG_ERROR;
    }

    /* assign new SID atomically */
    new_session->id = ATOMIC_INC_RELAXED(server_opts.new_session_id);

    /* NETCONF handshake */
    msgtype = nc_handshake_io(new_session);
    if (msgtype != NC_MSG_HELLO) {
        return msgtype;
    }

    nc_realtime_get(&ts_cur);
    new_session->opts.server.session_start = ts_cur;
    nc_timeouttime_get(&ts_cur, 0);
    new_session->opts.server.last_rpc = ts_cur.tv_sec;
    NC_SESSION_STATUS_SET(new_session, NC_STATUS_RUNNING);
    *session = new_session;

    return msgtype;
}
