/**
 * \file session_client_ssh.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 - SSH specific client session transport functions
 *
 * This source is compiled only with libssh.
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#ifdef ENABLE_DNSSEC
#   include <validator/validator.h>
#   include <validator/resolver.h>
#   include <validator/validator-compat.h>
#endif

#include <libssh/libssh.h>
#include <libyang/libyang.h>

#include "session_client.h"
#include "session_client_ch.h"
#include "libnetconf.h"

struct nc_client_context *nc_client_context_location(void);
int nc_session_new_ctx(struct nc_session *session, struct ly_ctx *ctx);

#define client_opts nc_client_context_location()->opts
#define ssh_opts nc_client_context_location()->ssh_opts
#define ssh_ch_opts nc_client_context_location()->ssh_ch_opts

static FILE *
open_tty_noecho(const char *path, struct termios *oldterm)
{
    struct termios newterm;
    FILE *ret;

    if (!(ret = fopen(path, "r"))) {
        ERR("Unable to open terminal \"%s\" for reading (%s).", path, strerror(errno));
        return NULL;
    }

    if (tcgetattr(fileno(ret), oldterm)) {
        ERR("Unable to get terminal \"%s\" settings (%s).", path, strerror(errno));
        fclose(ret);
        return NULL;
    }

    newterm = *oldterm;
    newterm.c_lflag &= ~ECHO;
    newterm.c_lflag &= ~ICANON;
    tcflush(fileno(ret), TCIFLUSH);
    if (tcsetattr(fileno(ret), TCSANOW, &newterm)) {
        ERR("Unable to change terminal \"%s\" settings for hiding password (%s).", path, strerror(errno));
        fclose(ret);
        return NULL;
    }

    return ret;
}

static FILE *
nc_open_in(int echo, struct termios *oldterm)
{
    char buf[512];
    int buflen = 512, ret;
    FILE *in;

    if (!echo) {
        in = open_tty_noecho("/dev/tty", oldterm);
    } else {
        in = fopen("/dev/tty", "r");
        if (!in) {
            ERR("Unable to open terminal \"/dev/tty\" for reading (%s).", strerror(errno));
        }
    }

    if (!in) {
        if ((ret = ttyname_r(STDIN_FILENO, buf, buflen))) {
            ERR("ttyname_r failed (%s).", strerror(ret));
            return NULL;
        }

        if (!echo) {
            in = open_tty_noecho(buf, oldterm);
        } else {
            in = fopen(buf, "r");
            if (!in) {
                ERR("Unable to open terminal \"%s\" for reading (%s).", buf, strerror(errno));
            }
        }
    }

    return in;
}

static FILE *
nc_open_out(void)
{
    char buf[512];
    int buflen = 512, ret;
    FILE *out;

    out = fopen("/dev/tty", "w");
    if (!out) {
        ERR("Unable to open terminal \"/dev/tty\" for writing (%s).", strerror(errno));

        if ((ret = ttyname_r(STDOUT_FILENO, buf, buflen))) {
            ERR("ttyname_r failed (%s).", strerror(ret));
            return NULL;
        }

        out = fopen(buf, "w");
        if (!out) {
            ERR("Unable to open terminal \"%s\" for writing (%s).", buf, strerror(errno));
        }
    }

    return out;
}

static void
nc_close_inout(FILE *inout, int echo, struct termios *oldterm)
{
    if (inout) {
        if (!echo && (tcsetattr(fileno(inout), TCSANOW, oldterm) != 0)) {
            ERR("Unable to restore terminal settings (%s).", strerror(errno));
        }
        fclose(inout);
    }
}

static void
_nc_client_ssh_destroy_opts(struct nc_client_ssh_opts *opts)
{
    int i;

    for (i = 0; i < opts->key_count; ++i) {
        free(opts->keys[i].pubkey_path);
        free(opts->keys[i].privkey_path);
    }
    free(opts->keys);
    free(opts->username);
    opts->keys = NULL;
    opts->username = NULL;
}

void
nc_client_ssh_destroy_opts(void)
{
    _nc_client_ssh_destroy_opts(&ssh_opts);
    _nc_client_ssh_destroy_opts(&ssh_ch_opts);
}

#ifdef ENABLE_DNSSEC

/* return 0 (DNSSEC + key valid), 1 (unsecure DNS + key valid), 2 (key not found or an error) */
/* type - 1 (RSA), 2 (DSA), 3 (ECDSA); alg - 1 (SHA1), 2 (SHA-256) */
static int
sshauth_hostkey_hash_dnssec_check(const char *hostname, const unsigned char *sha1hash, int type, int alg) {
    ns_msg handle;
    ns_rr rr;
    val_status_t val_status;
    const unsigned char* rdata;
    unsigned char buf[4096];
    int buf_len = 4096;
    int ret = 0, i, j, len;

    /* class 1 - internet, type 44 - SSHFP */
    len = val_res_query(NULL, hostname, 1, 44, buf, buf_len, &val_status);

    if ((len < 0) || !val_istrusted(val_status)) {
        ret = 2;
        goto finish;
    }

    if (ns_initparse(buf, len, &handle) < 0) {
        ERR("Failed to initialize DNSSEC response parser.");
        ret = 2;
        goto finish;
    }

    if ((i = libsres_msg_getflag(handle, ns_f_rcode))) {
        ERR("DNSSEC query returned %d.", i);
        ret = 2;
        goto finish;
    }

    if (!libsres_msg_getflag(handle, ns_f_ad)) {
        /* response not secured by DNSSEC */
        ret = 1;
    }

    /* query section */
    if (ns_parserr(&handle, ns_s_qd, 0, &rr)) {
        ERR("DNSSEC query section parser fail.");
        ret = 2;
        goto finish;
    }

    if (strcmp(hostname, ns_rr_name(rr)) || (ns_rr_type(rr) != 44) || (ns_rr_class(rr) != 1)) {
        ERR("DNSSEC query in the answer does not match the original query.");
        ret = 2;
        goto finish;
    }

    /* answer section */
    i = 0;
    while (!ns_parserr(&handle, ns_s_an, i, &rr)) {
        if (ns_rr_type(rr) != 44) {
            ++i;
            continue;
        }

        rdata = ns_rr_rdata(rr);
        if (rdata[0] != type) {
            ++i;
            continue;
        }
        if (rdata[1] != alg) {
            ++i;
            continue;
        }

        /* we found the correct SSHFP entry */
        rdata += 2;
        for (j = 0; j < 20; ++j) {
            if (rdata[j] != (unsigned char)sha1hash[j]) {
                ret = 2;
                goto finish;
            }
        }

        /* server fingerprint is supported by a DNS entry,
        * we have already determined if DNSSEC was used or not
        */
        goto finish;
    }

    /* no match */
    ret = 2;

finish:
    val_free_validator_state();
    return ret;
}

#endif /* ENABLE_DNSSEC */

int
sshauth_hostkey_check(const char *hostname, ssh_session session, void *UNUSED(priv))
{
    char *hexa = NULL;
    int c, state, ret;
    ssh_key srv_pubkey;
    unsigned char *hash_sha1 = NULL;
    size_t hlen;
    enum ssh_keytypes_e srv_pubkey_type;
    char answer[5];
    FILE *out = NULL, *in = NULL;

    state = ssh_is_server_known(session);

    ret = ssh_get_publickey(session, &srv_pubkey);
    if (ret < 0) {
        ERR("Unable to get server public key.");
        return -1;
    }

    srv_pubkey_type = ssh_key_type(srv_pubkey);
    ret = ssh_get_publickey_hash(srv_pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash_sha1, &hlen);
    ssh_key_free(srv_pubkey);
    if (ret < 0) {
        ERR("Failed to calculate SHA1 hash of the server public key.");
        return -1;
    }

    hexa = ssh_get_hexa(hash_sha1, hlen);

    switch (state) {
    case SSH_SERVER_KNOWN_OK:
        break; /* ok */

    case SSH_SERVER_KNOWN_CHANGED:
        ERR("Remote host key changed, the connection will be terminated!");
        goto error;

    case SSH_SERVER_FOUND_OTHER:
        WRN("Remote host key is not known, but a key of another type for this host is known. Continue with caution.");
        goto hostkey_not_known;

    case SSH_SERVER_FILE_NOT_FOUND:
        WRN("Could not find the known hosts file.");
        goto hostkey_not_known;

    case SSH_SERVER_NOT_KNOWN:
hostkey_not_known:
#ifdef ENABLE_DNSSEC
        if ((srv_pubkey_type != SSH_KEYTYPE_UNKNOWN) || (srv_pubkey_type != SSH_KEYTYPE_RSA1)) {
            if (srv_pubkey_type == SSH_KEYTYPE_DSS) {
                ret = sshauth_hostkey_hash_dnssec_check(hostname, hash_sha1, 2, 1);
            } else if (srv_pubkey_type == SSH_KEYTYPE_RSA) {
                ret = sshauth_hostkey_hash_dnssec_check(hostname, hash_sha1, 1, 1);
            } else if (srv_pubkey_type == SSH_KEYTYPE_ECDSA) {
                ret = sshauth_hostkey_hash_dnssec_check(hostname, hash_sha1, 3, 1);
            }

            /* DNSSEC SSHFP check successful, that's enough */
            if (!ret) {
                VRB("DNSSEC SSHFP check successful.");
                ssh_write_knownhost(session);
                ssh_clean_pubkey_hash(&hash_sha1);
                ssh_string_free_char(hexa);
                return 0;
            }
        }
#endif

        if (!(in = nc_open_in(1, NULL))) {
            goto error;
        }
        if (!(out = nc_open_out())) {
            goto error;
        }

        /* try to get result from user */
        if (fprintf(out, "The authenticity of the host \'%s\' cannot be established.\n", hostname) < 1) {
            ERR("Writing into output failed (%s).", feof(out) ? "EOF" : strerror(errno));
            goto error;
        }
        if (fprintf(out, "%s key fingerprint is %s.\n", ssh_key_type_to_char(srv_pubkey_type), hexa) < 1) {
            ERR("Writing into output failed (%s).", feof(out) ? "EOF" : strerror(errno));
            goto error;
        }

#ifdef ENABLE_DNSSEC
        if (ret == 2) {
            if (fprintf(out, "No matching host key fingerprint found using DNS.\n") < 1) {
                ERR("Writing into output failed (%s).", feof(out) ? "EOF" : strerror(errno));
                goto error;
            }
        } else if (ret == 1) {
            if (fprintf(out, "Matching host key fingerprint found using DNS.\n") < 1) {
                ERR("Writing into output failed (%s).", feof(out) ? "EOF" : strerror(errno));
                goto error;
            }
        }
#endif

        if (fprintf(out, "Are you sure you want to continue connecting (yes/no)? ") < 1) {
            ERR("Writing into output failed (%s).", feof(out) ? "EOF" : strerror(errno));
            goto error;
        }
        fflush(out);

        do {
            if (fscanf(in, "%4s", answer) == EOF) {
                ERR("Reading from input failed (%s).", feof(in) ? "EOF" : strerror(errno));
                goto error;
            }
            while (((c = getc(in)) != EOF) && (c != '\n'));

            fflush(in);
            if (!strcmp("yes", answer)) {
                /* store the key into the host file */
                ret = ssh_write_knownhost(session);
                if (ret != SSH_OK) {
                    WRN("Adding the known host \"%s\" failed (%s).", hostname, ssh_get_error(session));
                }
            } else if (!strcmp("no", answer)) {
                goto error;
            } else {
                if (fprintf(out, "Please type 'yes' or 'no': ") < 1) {
                    ERR("Writing into output failed (%s).", feof(out) ? "EOF" : strerror(errno));
                    goto error;
                }
            }
        } while (strcmp(answer, "yes") && strcmp(answer, "no"));

        break;

    case SSH_SERVER_ERROR:
        ERR("SSH error: %s", ssh_get_error(session));
        goto error;
    }

    nc_close_inout(in, 1, NULL);
    nc_close_inout(out, 1, NULL);
    ssh_clean_pubkey_hash(&hash_sha1);
    ssh_string_free_char(hexa);
    return 0;

error:
    nc_close_inout(in, 1, NULL);
    nc_close_inout(out, 1, NULL);
    ssh_clean_pubkey_hash(&hash_sha1);
    ssh_string_free_char(hexa);
    return -1;
}

char *
sshauth_password(const char *username, const char *hostname, void *UNUSED(priv))
{
    char *buf = NULL;
    int c, buflen = 1024, len;
    struct termios oldterm;
    FILE *in = NULL, *out = NULL;

    buf = malloc(buflen * sizeof *buf);
    if (!buf) {
        ERRMEM;
        return NULL;
    }

    if (!(in = nc_open_in(0, &oldterm))) {
        goto error;
    }
    if (!(out = nc_open_out())) {
        goto error;
    }

    if (fprintf(out, "%s@%s password: ", username, hostname) < 1) {
        ERR("Writing into output failed (%s).", feof(out) ? "EOF" : strerror(errno));
        goto error;
    }
    fflush(out);

    len = 0;
    while (((c = fgetc(in)) != EOF) && (c != '\n')) {
        if (len >= buflen - 1) {
            buflen *= 2;
            buf = nc_realloc(buf, buflen * sizeof *buf);
            if (!buf) {
                ERRMEM;
                goto error;
            }
        }
        buf[len++] = (char)c;
    }
    buf[len++] = 0; /* terminating null byte */

    fprintf(out, "\n");

    nc_close_inout(in, 0, &oldterm);
    nc_close_inout(out, 1, NULL);
    return buf;

error:
    nc_close_inout(in, 0, &oldterm);
    nc_close_inout(out, 1, NULL);
    free(buf);
    return NULL;
}

char *
sshauth_interactive(const char *auth_name, const char *instruction, const char *prompt, int echo, void *UNUSED(priv))
{
    unsigned int buflen = 64, cur_len;
    int c;
    struct termios oldterm;
    char *buf = NULL;
    FILE *in = NULL, *out = NULL;

    buf = malloc(buflen * sizeof *buf);
    if (!buf) {
        ERRMEM;
        return NULL;
    }

    if (!(in = nc_open_in(echo, &oldterm))) {
        goto error;
    }
    if (!(out = nc_open_out())) {
        goto error;
    }

    if (auth_name && (fprintf(out, "%s\n", auth_name) < 1)) {
        ERR("Writing into output failed (%s).", feof(out) ? "EOF" : strerror(errno));
        goto error;
    }
    if (instruction && (fprintf(out, "%s\n", instruction) < 1)) {
        ERR("Writing into output failed (%s).", feof(out) ? "EOF" : strerror(errno));
        goto error;
    }
    if (fputs(prompt, out) == EOF) {
        ERR("Writing into output failed (%s).", feof(out) ? "EOF" : strerror(errno));
        goto error;
    }
    fflush(out);

    cur_len = 0;
    while (((c = fgetc(in)) != EOF) && (c != '\n')) {
        if (cur_len >= buflen - 1) {
            buflen *= 2;
            buf = nc_realloc(buf, buflen * sizeof *buf);
            if (!buf) {
                ERRMEM;
                goto error;
            }
        }
        buf[cur_len++] = (char)c;
    }
    /* terminating null byte */
    buf[cur_len] = '\0';

    fprintf(out, "\n");

    nc_close_inout(in, echo, &oldterm);
    nc_close_inout(out, 1, NULL);
    return buf;

error:
    nc_close_inout(in, echo, &oldterm);
    nc_close_inout(out, 1, NULL);
    free(buf);
    return NULL;
}

char *
sshauth_privkey_passphrase(const char* privkey_path, void *UNUSED(priv))
{
    char *buf = NULL;
    int c, buflen = 1024, len;
    struct termios oldterm;
    FILE *in = NULL, *out = NULL;

    buf = malloc(buflen * sizeof *buf);
    if (!buf) {
        ERRMEM;
        return NULL;
    }

    if (!(in = nc_open_in(0, &oldterm))) {
        goto error;
    }
    if (!(out = nc_open_out())) {
        goto error;
    }

    if (fprintf(out, "Enter passphrase for the key '%s': ", privkey_path) < 1) {
        ERR("Writing into output failed (%s).", feof(out) ? "EOF" : strerror(errno));
        goto error;
    }
    fflush(out);

    len = 0;
    while (((c = fgetc(in)) != EOF) && (c != '\n')) {
        if (len >= buflen - 1) {
            buflen *= 2;
            buf = nc_realloc(buf, buflen * sizeof *buf);
            if (!buf) {
                ERRMEM;
                goto error;
            }
        }
        buf[len++] = (char)c;
    }
    buf[len] = 0; /* terminating null byte */

    fprintf(out, "\n");

    nc_close_inout(in, 0, &oldterm);
    nc_close_inout(out, 1, NULL);
    return buf;

error:
    nc_close_inout(in, 0, &oldterm);
    nc_close_inout(out, 1, NULL);
    free(buf);
    return NULL;
}

static void
_nc_client_ssh_set_auth_hostkey_check_clb(int (*auth_hostkey_check)(const char *hostname, ssh_session session, void *priv),
                                          void *priv, struct nc_client_ssh_opts *opts)
{
    if (auth_hostkey_check) {
        opts->auth_hostkey_check = auth_hostkey_check;
        opts->auth_hostkey_check_priv = priv;
    } else {
        opts->auth_hostkey_check = sshauth_hostkey_check;
        opts->auth_hostkey_check_priv = NULL;
    }
}

static void
_nc_client_ssh_get_auth_hostkey_check_clb(int (**auth_hostkey_check)(const char *hostname, ssh_session session, void *priv),
                                         void **priv, struct nc_client_ssh_opts *opts)
{
    if (auth_hostkey_check) {
        (*auth_hostkey_check) = opts->auth_hostkey_check == sshauth_hostkey_check ? NULL : opts->auth_hostkey_check;
    }
    if (priv) {
        (*priv) = opts->auth_hostkey_check_priv;
    }
}


API void
nc_client_ssh_set_auth_hostkey_check_clb(int (*auth_hostkey_check)(const char *hostname, ssh_session session, void *priv),
                                         void *priv)
{
    _nc_client_ssh_set_auth_hostkey_check_clb(auth_hostkey_check, priv, &ssh_opts);
}

API void
nc_client_ssh_ch_set_auth_hostkey_check_clb(int (*auth_hostkey_check)(const char *hostname, ssh_session session, void *priv),
                                            void *priv)
{
    _nc_client_ssh_set_auth_hostkey_check_clb(auth_hostkey_check, priv, &ssh_ch_opts);
}

API void
nc_client_ssh_get_auth_hostkey_check_clb(int (**auth_hostkey_check)(const char *hostname, ssh_session session, void *priv),
                                         void **priv)
{
    _nc_client_ssh_get_auth_hostkey_check_clb(auth_hostkey_check, priv, &ssh_opts);
}

API void
nc_client_ssh_ch_get_auth_hostkey_check_clb(int (**auth_hostkey_check)(const char *hostname, ssh_session session, void *priv),
                                            void **priv)
{
    _nc_client_ssh_get_auth_hostkey_check_clb(auth_hostkey_check, priv, &ssh_ch_opts);
}

static void
_nc_client_ssh_set_auth_password_clb(char *(*auth_password)(const char *username, const char *hostname, void *priv),
                                     void *priv, struct nc_client_ssh_opts *opts)
{
    if (auth_password) {
        opts->auth_password = auth_password;
        opts->auth_password_priv = priv;
    } else {
        opts->auth_password = sshauth_password;
        opts->auth_password_priv = NULL;
    }
}

static void
_nc_client_ssh_get_auth_password_clb(char *(**auth_password)(const char *username, const char *hostname, void *priv),
                                     void **priv, struct nc_client_ssh_opts *opts)
{
    if (auth_password) {
        (*auth_password) = opts->auth_password == sshauth_password ? NULL : opts->auth_password;
    }
    if (priv) {
        (*priv) = opts->auth_password_priv;
    }
}

API void
nc_client_ssh_set_auth_password_clb(char *(*auth_password)(const char *username, const char *hostname, void *priv),
                                    void *priv)
{
    _nc_client_ssh_set_auth_password_clb(auth_password, priv, &ssh_opts);
}

API void
nc_client_ssh_ch_set_auth_password_clb(char *(*auth_password)(const char *username, const char *hostname, void *priv),
                                       void *priv)
{
    _nc_client_ssh_set_auth_password_clb(auth_password, priv, &ssh_ch_opts);
}

API void
nc_client_ssh_get_auth_password_clb(char *(**auth_password)(const char *username, const char *hostname, void *priv),
                                    void **priv)
{
    _nc_client_ssh_get_auth_password_clb(auth_password, priv, &ssh_opts);
}

API void
nc_client_ssh_ch_get_auth_password_clb(char *(**auth_password)(const char *username, const char *hostname, void *priv),
                                       void **priv)
{
    _nc_client_ssh_get_auth_password_clb(auth_password, priv, &ssh_ch_opts);
}

static void
_nc_client_ssh_set_auth_interactive_clb(char *(*auth_interactive)(const char *auth_name, const char *instruction,
                                                                  const char *prompt, int echo, void *priv),
                                        void *priv, struct nc_client_ssh_opts *opts)
{
    if (auth_interactive) {
        opts->auth_interactive = auth_interactive;
        opts->auth_interactive_priv = priv;
    } else {
        opts->auth_interactive = sshauth_interactive;
        opts->auth_interactive_priv = NULL;
    }
}

static void
_nc_client_ssh_get_auth_interactive_clb(char *(**auth_interactive)(const char *auth_name, const char *instruction,
                                                                  const char *prompt, int echo, void *priv),
                                        void **priv, struct nc_client_ssh_opts *opts)
{
    if (auth_interactive) {
        (*auth_interactive) = opts->auth_interactive == sshauth_interactive ? NULL : opts->auth_interactive;
    }
    if (priv) {
        (*priv) = opts->auth_interactive_priv;
    }
}

API void
nc_client_ssh_set_auth_interactive_clb(char *(*auth_interactive)(const char *auth_name, const char *instruction,
                                                                  const char *prompt, int echo, void *priv),
                                       void *priv)
{
    _nc_client_ssh_set_auth_interactive_clb(auth_interactive, priv, &ssh_opts);
}

API void
nc_client_ssh_ch_set_auth_interactive_clb(char *(*auth_interactive)(const char *auth_name, const char *instruction,
                                                                  const char *prompt, int echo, void *priv),
                                          void *priv)
{
    _nc_client_ssh_set_auth_interactive_clb(auth_interactive, priv, &ssh_ch_opts);
}

API void
nc_client_ssh_get_auth_interactive_clb(char *(**auth_interactive)(const char *auth_name, const char *instruction,
                                                                  const char *prompt, int echo, void *priv),
                                       void **priv)
{
    _nc_client_ssh_get_auth_interactive_clb(auth_interactive, priv, &ssh_opts);
}

API void
nc_client_ssh_ch_get_auth_interactive_clb(char *(**auth_interactive)(const char *auth_name, const char *instruction,
                                                                  const char *prompt, int echo, void *priv),
                                          void **priv)
{
    _nc_client_ssh_get_auth_interactive_clb(auth_interactive, priv, &ssh_ch_opts);
}

static void
_nc_client_ssh_set_auth_privkey_passphrase_clb(char *(*auth_privkey_passphrase)(const char *privkey_path, void *priv),
                                               void *priv, struct nc_client_ssh_opts *opts)
{
    if (auth_privkey_passphrase) {
        opts->auth_privkey_passphrase = auth_privkey_passphrase;
        opts->auth_privkey_passphrase_priv = priv;
    } else {
        opts->auth_privkey_passphrase = sshauth_privkey_passphrase;
        opts->auth_privkey_passphrase_priv = NULL;
    }
}

static void
_nc_client_ssh_get_auth_privkey_passphrase_clb(char *(**auth_privkey_passphrase)(const char *privkey_path, void *priv),
                                               void **priv, struct nc_client_ssh_opts *opts)
{
    if (auth_privkey_passphrase) {
        (*auth_privkey_passphrase) = opts->auth_privkey_passphrase == sshauth_privkey_passphrase ? NULL : opts->auth_privkey_passphrase;
    }
    if (priv) {
        (*priv) = opts->auth_privkey_passphrase_priv;
    }
}

API void
nc_client_ssh_set_auth_privkey_passphrase_clb(char *(*auth_privkey_passphrase)(const char *privkey_path, void *priv),
                                              void *priv)
{
    _nc_client_ssh_set_auth_privkey_passphrase_clb(auth_privkey_passphrase, priv, &ssh_opts);
}

API void
nc_client_ssh_ch_set_auth_privkey_passphrase_clb(char *(*auth_privkey_passphrase)(const char *privkey_path, void *priv),
                                                 void *priv)
{
    _nc_client_ssh_set_auth_privkey_passphrase_clb(auth_privkey_passphrase, priv, &ssh_ch_opts);
}

API void
nc_client_ssh_get_auth_privkey_passphrase_clb(char *(**auth_privkey_passphrase)(const char *privkey_path, void *priv),
                                              void **priv)
{
    _nc_client_ssh_get_auth_privkey_passphrase_clb(auth_privkey_passphrase, priv, &ssh_opts);
}

API void
nc_client_ssh_ch_get_auth_privkey_passphrase_clb(char *(**auth_privkey_passphrase)(const char *privkey_path, void *priv),
                                                 void **priv)
{
    _nc_client_ssh_get_auth_privkey_passphrase_clb(auth_privkey_passphrase, priv, &ssh_ch_opts);
}

static int
_nc_client_ssh_add_keypair(const char *pub_key, const char *priv_key, struct nc_client_ssh_opts *opts)
{
    int i;
    FILE *key;
    char line[128];

    if (!pub_key) {
        ERRARG("pub_key");
        return -1;
    } else if (!priv_key) {
        ERRARG("priv_key");
        return -1;
    }

    for (i = 0; i < opts->key_count; ++i) {
        if (!strcmp(opts->keys[i].pubkey_path, pub_key) || !strcmp(opts->keys[i].privkey_path, priv_key)) {
            if (strcmp(opts->keys[i].pubkey_path, pub_key)) {
                WRN("Private key \"%s\" found with another public key \"%s\".",
                    priv_key, opts->keys[i].pubkey_path);
                continue;
            } else if (strcmp(opts->keys[i].privkey_path, priv_key)) {
                WRN("Public key \"%s\" found with another private key \"%s\".",
                    pub_key, opts->keys[i].privkey_path);
                continue;
            }

            ERR("SSH key pair already set.");
            return -1;
        }
    }

    /* add the keys */
    ++opts->key_count;
    opts->keys = nc_realloc(opts->keys, opts->key_count * sizeof *opts->keys);
    if (!opts->keys) {
        ERRMEM;
        return -1;
    }
    opts->keys[opts->key_count - 1].pubkey_path = strdup(pub_key);
    opts->keys[opts->key_count - 1].privkey_path = strdup(priv_key);
    opts->keys[opts->key_count - 1].privkey_crypt = 0;

    if (!opts->keys[opts->key_count - 1].pubkey_path || !opts->keys[opts->key_count - 1].privkey_path) {
        ERRMEM;
        return -1;
    }

    /* check encryption */
    if ((key = fopen(priv_key, "r"))) {
        /* 1st line - key type */
        if (!fgets(line, sizeof line, key)) {
            fclose(key);
            ERR("fgets() on %s failed.", priv_key);
            return -1;
        }
        /* 2nd line - encryption information or key */
        if (!fgets(line, sizeof line, key)) {
            fclose(key);
            ERR("fgets() on %s failed.", priv_key);
            return -1;
        }
        fclose(key);
        if (strcasestr(line, "encrypted")) {
            opts->keys[opts->key_count - 1].privkey_crypt = 1;
        }
    }

    return 0;
}

API int
nc_client_ssh_add_keypair(const char *pub_key, const char *priv_key)
{
    return _nc_client_ssh_add_keypair(pub_key, priv_key, &ssh_opts);
}

API int
nc_client_ssh_ch_add_keypair(const char *pub_key, const char *priv_key)
{
    return _nc_client_ssh_add_keypair(pub_key, priv_key, &ssh_ch_opts);
}

static int
_nc_client_ssh_del_keypair(int idx, struct nc_client_ssh_opts *opts)
{
    if (idx >= opts->key_count) {
        ERRARG("idx");
        return -1;
    }

    free(opts->keys[idx].pubkey_path);
    free(opts->keys[idx].privkey_path);

    --opts->key_count;
    if (idx < opts->key_count) {
        memcpy(&opts->keys[idx], &opts->keys[opts->key_count], sizeof *opts->keys);
    }
    if (opts->key_count) {
        opts->keys = nc_realloc(opts->keys, opts->key_count * sizeof *opts->keys);
        if (!opts->keys) {
            ERRMEM;
            return -1;
        }
    } else {
        free(opts->keys);
        opts->keys = NULL;
    }

    return 0;
}

API int
nc_client_ssh_del_keypair(int idx)
{
    return _nc_client_ssh_del_keypair(idx, &ssh_opts);
}

API int
nc_client_ssh_ch_del_keypair(int idx)
{
    return _nc_client_ssh_del_keypair(idx, &ssh_ch_opts);
}

static int
_nc_client_ssh_get_keypair_count(struct nc_client_ssh_opts *opts)
{
    return opts->key_count;
}

API int
nc_client_ssh_get_keypair_count(void)
{
    return _nc_client_ssh_get_keypair_count(&ssh_opts);
}

API int
nc_client_ssh_ch_get_keypair_count(void)
{
    return _nc_client_ssh_get_keypair_count(&ssh_ch_opts);
}

static int
_nc_client_ssh_get_keypair(int idx, const char **pub_key, const char **priv_key, struct nc_client_ssh_opts *opts)
{
    if (idx >= opts->key_count) {
        ERRARG("idx");
        return -1;
    } else if (!pub_key && !priv_key) {
        ERRARG("pub_key and priv_key");
        return -1;
    }

    if (pub_key) {
        *pub_key = opts->keys[idx].pubkey_path;
    }
    if (priv_key) {
        *priv_key = opts->keys[idx].privkey_path;
    }

    return 0;
}

API int
nc_client_ssh_get_keypair(int idx, const char **pub_key, const char **priv_key)
{
    return _nc_client_ssh_get_keypair(idx, pub_key, priv_key, &ssh_opts);
}

API int
nc_client_ssh_ch_get_keypair(int idx, const char **pub_key, const char **priv_key)
{
    return _nc_client_ssh_get_keypair(idx, pub_key, priv_key, &ssh_ch_opts);
}

static void
_nc_client_ssh_set_auth_pref(NC_SSH_AUTH_TYPE auth_type, int16_t pref, struct nc_client_ssh_opts *opts)
{
    if (pref < 0) {
        pref = -1;
    }

    if (auth_type == NC_SSH_AUTH_INTERACTIVE) {
        opts->auth_pref[0].value = pref;
    } else if (auth_type == NC_SSH_AUTH_PASSWORD) {
        opts->auth_pref[1].value = pref;
    } else if (auth_type == NC_SSH_AUTH_PUBLICKEY) {
        opts->auth_pref[2].value = pref;
    }
}

API void
nc_client_ssh_set_auth_pref(NC_SSH_AUTH_TYPE auth_type, int16_t pref)
{
    _nc_client_ssh_set_auth_pref(auth_type, pref, &ssh_opts);
}

API void
nc_client_ssh_ch_set_auth_pref(NC_SSH_AUTH_TYPE auth_type, int16_t pref)
{
    _nc_client_ssh_set_auth_pref(auth_type, pref, &ssh_ch_opts);
}

static int16_t
_nc_client_ssh_get_auth_pref(NC_SSH_AUTH_TYPE auth_type, struct nc_client_ssh_opts *opts)
{
    int16_t pref = 0;

    if (auth_type == NC_SSH_AUTH_INTERACTIVE) {
        pref = opts->auth_pref[0].value;
    } else if (auth_type == NC_SSH_AUTH_PASSWORD) {
        pref = opts->auth_pref[1].value;
    } else if (auth_type == NC_SSH_AUTH_PUBLICKEY) {
        pref = opts->auth_pref[2].value;
    }

    return pref;
}

API int16_t
nc_client_ssh_get_auth_pref(NC_SSH_AUTH_TYPE auth_type)
{
    return _nc_client_ssh_get_auth_pref(auth_type, &ssh_opts);
}

API int16_t
nc_client_ssh_ch_get_auth_pref(NC_SSH_AUTH_TYPE auth_type)
{
    return _nc_client_ssh_get_auth_pref(auth_type, &ssh_ch_opts);
}

static int
_nc_client_ssh_set_username(const char *username, struct nc_client_ssh_opts *opts)
{
    if (opts->username) {
        free(opts->username);
    }
    if (username) {
        opts->username = strdup(username);
        if (!opts->username) {
            ERRMEM;
            return -1;
        }
    } else {
        opts->username = NULL;
    }

    return 0;
}

API int
nc_client_ssh_set_username(const char *username)
{
    return _nc_client_ssh_set_username(username, &ssh_opts);
}

API int
nc_client_ssh_ch_set_username(const char *username)
{
    return _nc_client_ssh_set_username(username, &ssh_ch_opts);
}

static const char *
_nc_client_ssh_get_username(struct nc_client_ssh_opts *opts)
{
    return opts->username;
}

API const char *
nc_client_ssh_get_username(void)
{
    return _nc_client_ssh_get_username(&ssh_opts);
}

API const char *
nc_client_ssh_ch_get_username(void)
{
    return _nc_client_ssh_get_username(&ssh_ch_opts);
}

API int
nc_client_ssh_ch_add_bind_listen(const char *address, uint16_t port)
{
    return nc_client_ch_add_bind_listen(address, port, NC_TI_LIBSSH);
}

API int
nc_client_ssh_ch_del_bind(const char *address, uint16_t port)
{
    return nc_client_ch_del_bind(address, port, NC_TI_LIBSSH);
}

/* Establish a secure SSH connection and authenticate.
 * Host, port, username, and a connected socket is expected to be set.
 *
 * return values
 *  -1  failure
 *   0  try again
 *   1  success
 */
static int
connect_ssh_session(struct nc_session *session, struct nc_client_ssh_opts *opts, int timeout)
{
    int j, ret_auth, userauthlist, ret, attempt = 0;
    NC_SSH_AUTH_TYPE auth;
    int16_t pref;
    const char* prompt;
    char *s, *answer, echo;
    ssh_key pubkey, privkey;
    ssh_session ssh_sess;
    struct timespec ts_timeout, ts_cur;

    ssh_sess = session->ti.libssh.session;

    nc_gettimespec_mono(&ts_timeout);
    nc_addtimespec(&ts_timeout, NC_TRANSPORT_TIMEOUT);
    while ((ret = ssh_connect(ssh_sess)) == SSH_AGAIN) {
        usleep(NC_TIMEOUT_STEP);
        nc_gettimespec_mono(&ts_cur);
        if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
            break;
        }
    }
    if (ret == SSH_AGAIN) {
        ERR("SSH connect timeout.");
        return 0;
    } else if (ret != SSH_OK) {
        ERR("Starting the SSH session failed (%s).", ssh_get_error(ssh_sess));
        DBG("Error code %d.", ssh_get_error_code(ssh_sess));
        return -1;
    }

    if (opts->auth_hostkey_check(session->host, ssh_sess, opts->auth_hostkey_check_priv)) {
        ERR("Checking the host key failed.");
        return -1;
    }

    if (timeout > -1) {
        nc_gettimespec_mono(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);
    }
    while ((ret_auth = ssh_userauth_none(ssh_sess, NULL)) == SSH_AUTH_AGAIN) {
        usleep(NC_TIMEOUT_STEP);
        if (timeout > -1) {
            nc_gettimespec_mono(&ts_cur);
            if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
                break;
            }
        }
    }
    if (ret_auth == SSH_AUTH_AGAIN) {
        ERR("Request authentication methods timeout.");
        return 0;
    } else if (ret_auth == SSH_AUTH_ERROR) {
        ERR("Authentication failed (%s).", ssh_get_error(ssh_sess));
        return -1;
    } else if (ret_auth == SSH_AUTH_SUCCESS) {
        WRN("Server accepts \"none\" authentication method.")
        return 1;
    }

    /* check what authentication methods are available */
    userauthlist = ssh_userauth_list(ssh_sess, NULL);

    /* remove those disabled */
    if (opts->auth_pref[0].value < 0) {
        VRB("Interactive SSH authentication method was disabled.");
        userauthlist &= ~SSH_AUTH_METHOD_INTERACTIVE;
    }
    if (opts->auth_pref[1].value < 0) {
        VRB("Password SSH authentication method was disabled.");
        userauthlist &= ~SSH_AUTH_METHOD_PASSWORD;
    }
    if (opts->auth_pref[2].value < 0) {
        VRB("Publickey SSH authentication method was disabled.");
        userauthlist &= ~SSH_AUTH_METHOD_PUBLICKEY;
    }

    do {
        auth = 0;
        pref = 0;
        if (userauthlist & SSH_AUTH_METHOD_INTERACTIVE) {
            auth = NC_SSH_AUTH_INTERACTIVE;
            pref = opts->auth_pref[0].value;
        }
        if ((userauthlist & SSH_AUTH_METHOD_PASSWORD) && (opts->auth_pref[1].value > pref)) {
            auth = NC_SSH_AUTH_PASSWORD;
            pref = opts->auth_pref[1].value;
        }
        if ((userauthlist & SSH_AUTH_METHOD_PUBLICKEY) && (opts->auth_pref[2].value > pref)) {
            auth = NC_SSH_AUTH_PUBLICKEY;
        }

        if (!auth) {
            if (!attempt) {
                ERR("Unable to authenticate to the remote server (no supported authentication methods detected).");
            } else {
                ERR("Unable to authenticate to the remote server (all attempts via supported authentication methods failed).");
            }
            return -1;
        }

        /* found common authentication method */
        switch (auth) {
        case NC_SSH_AUTH_PASSWORD:
            userauthlist &= ~SSH_AUTH_METHOD_PASSWORD;

            VRB("Password authentication (host \"%s\", user \"%s\").", session->host, session->username);
            s = opts->auth_password(session->username, session->host, opts->auth_password_priv);
            if (s == NULL) {
                ERR("Unable to get the password.");
                return -1;
            }

            if (timeout > -1) {
                nc_gettimespec_mono(&ts_timeout);
                nc_addtimespec(&ts_timeout, timeout);
            }
            while ((ret_auth = ssh_userauth_password(ssh_sess, session->username, s)) == SSH_AUTH_AGAIN) {
                usleep(NC_TIMEOUT_STEP);
                if (timeout > -1) {
                    nc_gettimespec_mono(&ts_cur);
                    if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
                        break;
                    }
                }
            }
            memset(s, 0, strlen(s));
            free(s);
            break;

        case NC_SSH_AUTH_INTERACTIVE:
            userauthlist &= ~SSH_AUTH_METHOD_INTERACTIVE;

            VRB("Keyboard-interactive authentication.");

            if (timeout > -1) {
                nc_gettimespec_mono(&ts_timeout);
                nc_addtimespec(&ts_timeout, timeout);
            }
            while (((ret_auth = ssh_userauth_kbdint(ssh_sess, NULL, NULL)) == SSH_AUTH_INFO)
                    || (ret_auth == SSH_AUTH_AGAIN)) {
                if (ret_auth == SSH_AUTH_AGAIN) {
                    usleep(NC_TIMEOUT_STEP);
                    if (timeout > -1) {
                        nc_gettimespec_mono(&ts_cur);
                        if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
                            break;
                        }
                    }
                    continue;
                }

                for (j = 0; j < ssh_userauth_kbdint_getnprompts(ssh_sess); ++j) {
                    prompt = ssh_userauth_kbdint_getprompt(ssh_sess, j, &echo);
                    if (!prompt) {
                        ret_auth = SSH_AUTH_ERROR;
                        break;
                    }

                    /* libssh BUG - echo is always 1 for some reason, assume always 0 */
                    echo = 0;

                    answer = opts->auth_interactive(ssh_userauth_kbdint_getname(ssh_sess),
                                                    ssh_userauth_kbdint_getinstruction(ssh_sess),
                                                    prompt, echo, opts->auth_interactive_priv);
                    if (ssh_userauth_kbdint_setanswer(ssh_sess, j, answer) < 0) {
                        free(answer);
                        ret_auth = SSH_AUTH_ERROR;
                        break;
                    }
                    free(answer);
                }
                if (ret_auth == SSH_AUTH_ERROR) {
                    break;
                }
                if (timeout > -1) {
                    nc_gettimespec_mono(&ts_timeout);
                    nc_addtimespec(&ts_timeout, timeout);
                }
            }
            break;

        case NC_SSH_AUTH_PUBLICKEY:
            userauthlist &= ~SSH_AUTH_METHOD_PUBLICKEY;

            VRB("Publickey athentication.");

            /* if publickeys path not provided, we cannot continue */
            if (!opts->key_count) {
                VRB("No key pair specified.");
                break;
            }

            for (j = 0; j < opts->key_count; j++) {
                VRB("Trying to authenticate using %spair \"%s\" \"%s\".",
                     opts->keys[j].privkey_crypt ? "password-protected " : "", opts->keys[j].privkey_path,
                     opts->keys[j].pubkey_path);

                ret = ssh_pki_import_pubkey_file(opts->keys[j].pubkey_path, &pubkey);
                if (ret == SSH_EOF) {
                    WRN("Failed to import the key \"%s\" (File access problem).", opts->keys[j].pubkey_path);
                    continue;
                } else if (ret == SSH_ERROR) {
                    WRN("Failed to import the key \"%s\" (SSH error).", opts->keys[j].pubkey_path);
                    continue;
                }

                if (timeout > -1) {
                    nc_gettimespec_mono(&ts_timeout);
                    nc_addtimespec(&ts_timeout, timeout);
                }
                while ((ret_auth = ssh_userauth_try_publickey(ssh_sess, NULL, pubkey)) == SSH_AUTH_AGAIN) {
                    usleep(NC_TIMEOUT_STEP);
                    if (timeout > -1) {
                        nc_gettimespec_mono(&ts_cur);
                        if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
                            break;
                        }
                    }
                }
                ssh_key_free(pubkey);

                if (ret_auth == SSH_AUTH_DENIED) {
                    continue;
                } else if (ret_auth != SSH_AUTH_SUCCESS) {
                    break;
                }

                if (opts->keys[j].privkey_crypt) {
                    s = opts->auth_privkey_passphrase(opts->keys[j].privkey_path, opts->auth_privkey_passphrase_priv);
                } else {
                    s = NULL;
                }

                ret = ssh_pki_import_privkey_file(opts->keys[j].privkey_path, s, NULL, NULL, &privkey);
                if (s) {
                    memset(s, 0, strlen(s));
                    free(s);
                }
                if (ret == SSH_EOF) {
                    WRN("Failed to import the key \"%s\" (File access problem).", opts->keys[j].privkey_path);
                    continue;
                } else if (ret == SSH_ERROR) {
                    WRN("Failed to import the key \"%s\" (SSH error).", opts->keys[j].privkey_path);
                    continue;
                }

                if (timeout > -1) {
                    nc_gettimespec_mono(&ts_timeout);
                    nc_addtimespec(&ts_timeout, timeout);
                }
                while ((ret_auth = ssh_userauth_publickey(ssh_sess, NULL, privkey)) == SSH_AUTH_AGAIN) {
                    usleep(NC_TIMEOUT_STEP);
                    if (timeout > -1) {
                        nc_gettimespec_mono(&ts_cur);
                        if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
                            break;
                        }
                    }
                }
                ssh_key_free(privkey);

                if (ret_auth != SSH_AUTH_DENIED) {
                    break;
                }
            }
            break;
        }

        switch (ret_auth) {
        case SSH_AUTH_AGAIN:
            ERR("Authentication response timeout.");
            return 0;
        case SSH_AUTH_ERROR:
            ERR("Authentication failed (%s).", ssh_get_error(ssh_sess));
            return -1;
        case SSH_AUTH_DENIED:
            WRN("Authentication denied.");
            break;
        case SSH_AUTH_PARTIAL:
            VRB("Partial authentication success.");
            break;
        case SSH_AUTH_SUCCESS:
            VRB("Authentication successful.");
            break;
        case SSH_AUTH_INFO:
            ERRINT;
            return -1;
        }

        attempt++;
    } while (ret_auth != SSH_AUTH_SUCCESS);

    return 1;
}

/* Open new SSH channel and request the 'netconf' subsystem.
 * SSH connection is expected to be established.
 */
static int
open_netconf_channel(struct nc_session *session, int timeout)
{
    ssh_session ssh_sess;
    int ret;
    struct timespec ts_timeout, ts_cur;

    ssh_sess = session->ti.libssh.session;

    if (!ssh_is_connected(ssh_sess)) {
        ERR("SSH session not connected.");
        return -1;
    }

    if (session->ti.libssh.channel) {
        ERR("SSH channel already created.");
        return -1;
    }

    /* open a channel */
    if (timeout > -1) {
        nc_gettimespec_mono(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);
    }
    session->ti.libssh.channel = ssh_channel_new(ssh_sess);
    while ((ret = ssh_channel_open_session(session->ti.libssh.channel)) == SSH_AGAIN) {
        usleep(NC_TIMEOUT_STEP);
        if (timeout > -1) {
            nc_gettimespec_mono(&ts_cur);
            if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
                break;
            }
        }
    }
    if (ret == SSH_AGAIN) {
        ERR("Opening an SSH channel timeout elapsed.");
        ssh_channel_free(session->ti.libssh.channel);
        session->ti.libssh.channel = NULL;
        return 0;
    } else if (ret == SSH_ERROR) {
        ERR("Opening an SSH channel failed (%s).", ssh_get_error(ssh_sess));
        ssh_channel_free(session->ti.libssh.channel);
        session->ti.libssh.channel = NULL;
        return -1;
    }

    /* execute the NETCONF subsystem on the channel */
    if (timeout > -1) {
        nc_gettimespec_mono(&ts_timeout);
        nc_addtimespec(&ts_timeout, timeout);
    }
    while ((ret = ssh_channel_request_subsystem(session->ti.libssh.channel, "netconf")) == SSH_AGAIN) {
        usleep(NC_TIMEOUT_STEP);
        if (timeout > -1) {
            nc_gettimespec_mono(&ts_cur);
            if (nc_difftimespec(&ts_cur, &ts_timeout) < 1) {
                break;
            }
        }
    }
    if (ret == SSH_AGAIN) {
        ERR("Starting the \"netconf\" SSH subsystem timeout elapsed.");
        ssh_channel_free(session->ti.libssh.channel);
        session->ti.libssh.channel = NULL;
        return 0;
    } else if (ret == SSH_ERROR) {
        ERR("Starting the \"netconf\" SSH subsystem failed (%s).", ssh_get_error(ssh_sess));
        ssh_channel_free(session->ti.libssh.channel);
        session->ti.libssh.channel = NULL;
        return -1;
    }

    return 1;
}

static struct nc_session *
_nc_connect_libssh(ssh_session ssh_session, struct ly_ctx *ctx, struct nc_client_ssh_opts *opts, int timeout)
{
    char *host = NULL, *username = NULL;
    unsigned short port = 0;
    int sock;
    struct passwd *pw;
    struct nc_session *session = NULL;

    if (!ssh_session) {
        ERRARG("ssh_session");
        return NULL;
    }

    /* prepare session structure */
    session = nc_new_session(NC_CLIENT, 0);
    if (!session) {
        ERRMEM;
        return NULL;
    }
    session->status = NC_STATUS_STARTING;
    session->ti_type = NC_TI_LIBSSH;
    session->ti.libssh.session = ssh_session;

    /* was port set? */
    ssh_options_get_port(ssh_session, (unsigned int *)&port);

    if (ssh_options_get(ssh_session, SSH_OPTIONS_HOST, &host) != SSH_OK) {
        /*
         * There is no file descriptor (detected based on the host, there is no way to check
         * the SSH_OPTIONS_FD directly :/), we need to create it. (TCP/IP layer)
         */

        /* remember host */
        host = strdup("localhost");
        if (!host) {
            ERRMEM;
            goto fail;
        }
        ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_HOST, host);

        /* create and connect socket */
        sock = nc_sock_connect(host, port, -1, NULL);
        if (sock == -1) {
            ERR("Unable to connect to %s:%u (%s).", host, port, strerror(errno));
            goto fail;
        }
        ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_FD, &sock);
        ssh_set_blocking(session->ti.libssh.session, 0);
    }

    /* was username set? */
    ssh_options_get(ssh_session, SSH_OPTIONS_USER, &username);

    if (!ssh_is_connected(ssh_session)) {
        /*
         * We are connected, but not SSH authenticated. (Transport layer)
         */

        /* remember username */
        if (!username) {
            if (!opts->username) {
                pw = getpwuid(getuid());
                if (!pw) {
                    ERR("Unknown username for the SSH connection (%s).", strerror(errno));
                    goto fail;
                }
                username = strdup(pw->pw_name);
            } else {
                username = strdup(opts->username);
            }
            if (!username) {
                ERRMEM;
                goto fail;
            }
            ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_USER, username);
        }

        /* connect and authenticate SSH session */
        session->host = host;
        session->username = username;
        if (connect_ssh_session(session, opts, timeout) != 1) {
            goto fail;
        }
    }

    /*
     * Almost done, open a netconf channel. (Transport layer / application layer)
     */
    if (open_netconf_channel(session, timeout) != 1) {
        goto fail;
    }

    /*
     * SSH session is established and netconf channel opened, create a NETCONF session. (Application layer)
     */

    if (nc_session_new_ctx(session, ctx) != EXIT_SUCCESS) {
        goto fail;
    }
    ctx = session->ctx;

    /* NETCONF handshake */
    if (nc_handshake_io(session) != NC_MSG_HELLO) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    if (nc_ctx_check_and_fill(session) == -1) {
        goto fail;
    }

    /* store information into the dictionary */
    if (host) {
        session->host = lydict_insert_zc(ctx, host);
    }
    if (port) {
        session->port = port;
    }
    if (username) {
        session->username = lydict_insert_zc(ctx, username);
    }

    return session;

fail:
    nc_session_free(session, NULL);
    return NULL;
}

API struct nc_session *
nc_connect_ssh(const char *host, uint16_t port, struct ly_ctx *ctx)
{
    const long timeout = NC_SSH_TIMEOUT;
    int sock;
    uint32_t port_uint;
    char *username;
    struct passwd *pw;
    struct nc_session *session = NULL;

    /* process parameters */
    if (!host || strisempty(host)) {
        host = "localhost";
    }

    if (!port) {
        port = NC_PORT_SSH;
    }
    port_uint = port;

    if (!ssh_opts.username) {
        pw = getpwuid(getuid());
        if (!pw) {
            ERR("Unknown username for the SSH connection (%s).", strerror(errno));
            return NULL;
        } else {
            username = pw->pw_name;
        }
    } else {
        username = ssh_opts.username;
    }

    /* prepare session structure */
    session = nc_new_session(NC_CLIENT, 0);
    if (!session) {
        ERRMEM;
        return NULL;
    }
    session->status = NC_STATUS_STARTING;

    /* transport-specific data */
    session->ti_type = NC_TI_LIBSSH;
    session->ti.libssh.session = ssh_new();
    if (!session->ti.libssh.session) {
        ERR("Unable to initialize SSH session.");
        goto fail;
    }

    /* set some basic SSH session options */
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_PORT, &port_uint);
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_USER, username);
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_TIMEOUT, &timeout);
    if (ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_HOSTKEYS,
                        "ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,"
                        "ecdsa-sha2-nistp256,ssh-rsa,ssh-dss,ssh-rsa1")) {
        /* ecdsa is probably not supported... */
        ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_HOSTKEYS, "ssh-ed25519,ssh-rsa,ssh-dss,ssh-rsa1");
    }

    /* create and assign communication socket */
    sock = nc_sock_connect(host, port, -1, NULL);
    if (sock == -1) {
        ERR("Unable to connect to %s:%u (%s).", host, port, strerror(errno));
        goto fail;
    }
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_FD, &sock);
    ssh_set_blocking(session->ti.libssh.session, 0);

    /* temporarily, for session connection */
    session->host = host;
    session->username = username;
    if ((connect_ssh_session(session, &ssh_opts, NC_TRANSPORT_TIMEOUT) != 1)
            || (open_netconf_channel(session, NC_TRANSPORT_TIMEOUT) != 1)) {
        goto fail;
    }

    if (nc_session_new_ctx(session, ctx) != EXIT_SUCCESS) {
        goto fail;
    }
    ctx = session->ctx;

    /* NETCONF handshake */
    if (nc_handshake_io(session) != NC_MSG_HELLO) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    if (nc_ctx_check_and_fill(session) == -1) {
        goto fail;
    }

    /* store information into the dictionary */
    session->host = lydict_insert(ctx, host, 0);
    session->port = port;
    session->username = lydict_insert(ctx, username, 0);

    return session;

fail:
    nc_session_free(session, NULL);
    return NULL;
}

API struct nc_session *
nc_connect_libssh(ssh_session ssh_session, struct ly_ctx *ctx)
{
    return _nc_connect_libssh(ssh_session, ctx, &ssh_opts, NC_TRANSPORT_TIMEOUT);
}

API struct nc_session *
nc_connect_ssh_channel(struct nc_session *session, struct ly_ctx *ctx)
{
    struct nc_session *new_session, *ptr;

    if (!session) {
        ERRARG("session");
        return NULL;
    }

    /* prepare session structure */
    new_session = nc_new_session(NC_CLIENT, 1);
    if (!new_session) {
        ERRMEM;
        return NULL;
    }
    new_session->status = NC_STATUS_STARTING;

    /* share some parameters including the IO lock (we are using one socket for both sessions) */
    new_session->ti_type = NC_TI_LIBSSH;
    new_session->ti.libssh.session = session->ti.libssh.session;
    new_session->io_lock = session->io_lock;

    /* create the channel safely */
    if (nc_session_io_lock(new_session, -1, __func__) != 1) {
        goto fail;
    }
    if (open_netconf_channel(new_session, NC_TRANSPORT_TIMEOUT) != 1) {
        goto fail;
    }
    nc_session_io_unlock(new_session, __func__);

    if (nc_session_new_ctx(new_session, ctx) != EXIT_SUCCESS) {
        goto fail;
    }
    ctx = session->ctx;

    /* NETCONF handshake */
    if (nc_handshake_io(new_session) != NC_MSG_HELLO) {
        goto fail;
    }
    new_session->status = NC_STATUS_RUNNING;

    if (nc_ctx_check_and_fill(new_session) == -1) {
        goto fail;
    }

    /* store information into session and the dictionary */
    new_session->host = lydict_insert(ctx, session->host, 0);
    new_session->port = session->port;
    new_session->username = lydict_insert(ctx, session->username, 0);

    /* append to the session ring list */
    if (!session->ti.libssh.next) {
        session->ti.libssh.next = new_session;
        new_session->ti.libssh.next = session;
    } else {
        ptr = session->ti.libssh.next;
        session->ti.libssh.next = new_session;
        new_session->ti.libssh.next = ptr;
    }

    return new_session;

fail:
    nc_session_free(new_session, NULL);
    return NULL;
}

struct nc_session *
nc_accept_callhome_ssh_sock(int sock, const char *host, uint16_t port, struct ly_ctx *ctx, int timeout)
{
    const long ssh_timeout = NC_SSH_TIMEOUT;
    unsigned int uint_port;
    struct passwd *pw;
    struct nc_session *session;
    ssh_session sess;

    sess = ssh_new();
    if (!sess) {
        ERR("Unable to initialize an SSH session.");
        close(sock);
        return NULL;
    }

    ssh_options_set(sess, SSH_OPTIONS_FD, &sock);
    ssh_set_blocking(sess, 0);
    ssh_options_set(sess, SSH_OPTIONS_HOST, host);
    uint_port = port;
    ssh_options_set(sess, SSH_OPTIONS_PORT, &uint_port);
    ssh_options_set(sess, SSH_OPTIONS_TIMEOUT, &ssh_timeout);
    if (!ssh_ch_opts.username) {
        pw = getpwuid(getuid());
        if (!pw) {
            ERR("Unknown username for the SSH connection (%s).", strerror(errno));
            return NULL;
        }
        ssh_options_set(sess, SSH_OPTIONS_USER, pw->pw_name);
    } else {
        ssh_options_set(sess, SSH_OPTIONS_USER, ssh_ch_opts.username);
    }
    if (ssh_options_set(sess, SSH_OPTIONS_HOSTKEYS,
                        "ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,"
                        "ecdsa-sha2-nistp256,ssh-rsa,ssh-dss,ssh-rsa1")) {
        /* ecdsa is probably not supported... */
        ssh_options_set(sess, SSH_OPTIONS_HOSTKEYS, "ssh-ed25519,ssh-rsa,ssh-dss,ssh-rsa1");
    }

    session = _nc_connect_libssh(sess, ctx, &ssh_ch_opts, timeout);
    if (session) {
        session->flags |= NC_SESSION_CALLHOME;
    }

    return session;
}
