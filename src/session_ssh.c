/**
 * \file session_ssh.c
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 - SSH specific session transport functions
 *
 * This source is compiled only with libssh.
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
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
 *
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

#ifdef ENABLE_DNSSEC
#   include <validator/validator.h>
#   include <validator/resolver.h>
#   include <validator/validator-compat.h>
#endif

#include <libyang/libyang.h>

#include "libnetconf.h"
#include "session.h"

static struct nc_ssh_auth_opts ssh_opts = {
    .auth_pref = {{NC_SSH_AUTH_INTERACTIVE, 3}, {NC_SSH_AUTH_PASSWORD, 2}, {NC_SSH_AUTH_PUBLIC_KEYS, 1}},
    .keys = NULL,
    .key_count = 0
};

/* internal functions from session.c */
struct nc_session *connect_init(struct ly_ctx *ctx);
int connect_getsocket(const char *host, unsigned short port);
int handshake(struct nc_session *session);

static char *
sshauth_password(const char *username, const char *hostname)
{
    char *buf, *newbuf;
    int buflen = 1024, len = 0;
    char c = 0;
    struct termios newterm, oldterm;
    FILE *tty;

    buf = malloc(buflen * sizeof *buf);
    if (!buf) {
        ERRMEM;
        return NULL;
    }

    if (!(tty = fopen("/dev/tty", "r+"))) {
        ERR("Unable to open the current terminal (%s:%d - %s).", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    if (tcgetattr(fileno(tty), &oldterm)) {
        ERR("Unable to get terminal settings (%d: %s).", __LINE__, strerror(errno));
        return NULL;
    }

    fprintf(tty, "%s@%s password: ", username, hostname);
    fflush(tty);

    /* system("stty -echo"); */
    newterm = oldterm;
    newterm.c_lflag &= ~ECHO;
    newterm.c_lflag &= ~ICANON;
    tcflush(fileno(tty), TCIFLUSH);
    if (tcsetattr(fileno(tty), TCSANOW, &newterm)) {
        ERR("Unable to change terminal settings for hiding password (%d: %s).", __LINE__, strerror(errno));
        return NULL;
    }

    while ((fread(&c, 1, 1, tty) == 1) && (c != '\n')) {
        if (len >= buflen - 1) {
            buflen *= 2;
            newbuf = realloc(buf, buflen * sizeof *newbuf);
            if (!newbuf) {
                ERR("Memory allocation failed (%s:%d - %s).", __FILE__, __LINE__, strerror(errno));

                /* remove content of the buffer */
                memset(buf, 0, len);
                free(buf);

                /* restore terminal settings */
                if (tcsetattr(fileno(tty), TCSANOW, &oldterm) != 0) {
                    ERR("Unable to restore terminal settings (%d: %s).", __LINE__, strerror(errno));
                }
                return NULL;
            } else {
                buf = newbuf;
            }
        }
        buf[len++] = c;
    }
    buf[len++] = 0; /* terminating null byte */

    /* system ("stty echo"); */
    if (tcsetattr(fileno(tty), TCSANOW, &oldterm)) {
        ERR("Unable to restore terminal settings (%d: %s).", __LINE__, strerror(errno));
        /*
         * terminal probably still hides input characters, but we have password
         * and anyway we are unable to set terminal to the previous state, so
         * just continue
         */
    }
    fprintf(tty, "\n");

    fclose(tty);
    return buf;
}

static char *
sshauth_interactive(const char *auth_name, const char *instruction, const char *prompt, int echo)
{
    unsigned int buflen = 8, response_len;
    char c = 0;
    struct termios newterm, oldterm;
    char *newtext, *response;
    FILE *tty;

    if (!(tty = fopen("/dev/tty", "r+"))) {
        ERR("Unable to open the current terminal (%s:%d - %s).", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    if (tcgetattr(fileno(tty), &oldterm) != 0) {
        ERR("Unable to get terminal settings (%d: %s).", __LINE__, strerror(errno));
        return NULL;
    }

    if (auth_name && (!fwrite(auth_name, sizeof(char), strlen(auth_name), tty)
            || !fwrite("\n", sizeof(char), 1, tty))) {
        ERR("Writing the auth method name into stdout failed.");
        return NULL;
    }

    if (instruction && (!fwrite(instruction, sizeof(char), strlen(instruction), tty)
            || !fwrite("\n", sizeof(char), 1, tty))) {
        ERR("Writing the instruction into stdout failed.");
        return NULL;
    }

    if (!fwrite(prompt, sizeof(char), strlen(prompt), tty)) {
        ERR("Writing the authentication prompt into stdout failed.");
        return NULL;
    }
    fflush(tty);
    if (!echo) {
        /* system("stty -echo"); */
        newterm = oldterm;
        newterm.c_lflag &= ~ECHO;
        tcflush(fileno(tty), TCIFLUSH);
        if (tcsetattr(fileno(tty), TCSANOW, &newterm)) {
            ERR("Unable to change terminal settings for hiding password (%d: %s).", __LINE__, strerror(errno));
            return NULL;
        }
    }

    response = malloc(buflen * sizeof *response);
    response_len = 0;
    if (!response) {
        ERRMEM;
        /* restore terminal settings */
        if (tcsetattr(fileno(tty), TCSANOW, &oldterm)) {
            ERR("Unable to restore terminal settings (%d: %s).", __LINE__, strerror(errno));
        }
        return NULL;
    }

    while ((fread(&c, 1, 1, tty) == 1) && (c != '\n')) {
        if (response_len >= buflen - 1) {
            buflen *= 2;
            newtext = realloc(response, buflen * sizeof *newtext);
            if (!newtext) {
                ERR("Memory allocation failed (%s:%d - %s).", __FILE__, __LINE__, strerror(errno));
                free(response);

                /* restore terminal settings */
                if (tcsetattr(fileno(tty), TCSANOW, &oldterm)) {
                    ERR("Unable to restore terminal settings (%d: %s).", __LINE__, strerror(errno));
                }
                return NULL;
            } else {
                response = newtext;
            }
        }
        response[response_len++] = c;
    }
    /* terminating null byte */
    response[response_len++] = '\0';

    /* system ("stty echo"); */
    if (tcsetattr(fileno(tty), TCSANOW, &oldterm)) {
        ERR("Unable to restore terminal settings (%d: %s).", __LINE__, strerror(errno));
        /*
         * terminal probably still hides input characters, but we have password
         * and anyway we are unable to set terminal to the previous state, so
         * just continue
         */
    }

    fprintf(tty, "\n");
    fclose(tty);
    return response;
}

static char *
sshauth_passphrase(const char* privkey_path)
{
    char c, *buf, *newbuf;
    int buflen = 1024, len = 0;
    struct termios newterm, oldterm;
    FILE *tty;

    buf = malloc(buflen * sizeof *buf);
    if (!buf) {
        ERR("Memory allocation failed (%s:%d - %s).", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    if (!(tty = fopen("/dev/tty", "r+"))) {
        ERR("Unable to open the current terminal (%s:%d - %s).", __FILE__, __LINE__, strerror(errno));
        return NULL;
    }

    if (tcgetattr(fileno(tty), &oldterm)) {
        ERR("Unable to get terminal settings (%d: %s).", __LINE__, strerror(errno));
        return NULL;
    }

    fprintf(tty, "Enter passphrase for the key '%s':", privkey_path);
    fflush(tty);

    /* system("stty -echo"); */
    newterm = oldterm;
    newterm.c_lflag &= ~ECHO;
    newterm.c_lflag &= ~ICANON;
    tcflush(fileno(tty), TCIFLUSH);
    if (tcsetattr(fileno(tty), TCSANOW, &newterm)) {
        ERR("Unable to change terminal settings for hiding password (%d: %s).", __LINE__, strerror(errno));
        return NULL;
    }

    while ((fread(&c, 1, 1, tty) == 1) && (c != '\n')) {
        if (len >= buflen - 1) {
            buflen *= 2;
            newbuf = realloc(buf, buflen * sizeof *newbuf);
            if (!newbuf) {
                ERRMEM;
                /* remove content of the buffer */
                memset(buf, 0, len);
                free(buf);

                /* restore terminal settings */
                if (tcsetattr(fileno(tty), TCSANOW, &oldterm)) {
                    ERR("Unable to restore terminal settings (%d: %s).", __LINE__, strerror(errno));
                }

                return NULL;
            }
            buf = newbuf;
        }
        buf[len++] = (char)c;
    }
    buf[len++] = 0; /* terminating null byte */

    /* system ("stty echo"); */
    if (tcsetattr(fileno(tty), TCSANOW, &oldterm)) {
        ERR("Unable to restore terminal settings (%d: %s).", __LINE__, strerror(errno));
        /*
         * terminal probably still hides input characters, but we have password
         * and anyway we are unable to set terminal to the previous state, so
         * just continue
         */
    }
    fprintf(tty, "\n");

    fclose(tty);
    return buf;
}

/* TODO define this switch */
#ifdef ENABLE_DNSSEC

/* return 0 (DNSSEC + key valid), 1 (unsecure DNS + key valid), 2 (key not found or an error) */
/* type - 1 (RSA), 2 (DSA), 3 (ECDSA); alg - 1 (SHA1), 2 (SHA-256) */
static int
sshauth_hostkey_hash_dnssec_check(const char *hostname, const char *sha1hash, int type, int alg) {
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
        ERROR("DNSSEC query section parser fail.");
        ret = 2;
        goto finish;
    }

    if (strcmp(hostname, ns_rr_name(rr)) || (ns_rr_type(rr) != 44) || (ns_rr_class(rr) != 1)) {
        ERROR("DNSSEC query in the answer does not match the original query.");
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

#endif

static int
sshauth_hostkey_check(const char *hostname, ssh_session session)
{
    char *hexa;
    int c, state, ret;
    ssh_key srv_pubkey;
    unsigned char *hash_sha1 = NULL;
    size_t hlen;
    enum ssh_keytypes_e srv_pubkey_type;
    char answer[5];

    state = ssh_is_server_known(session);

    ret = ssh_get_publickey(session, &srv_pubkey);
    if (ret < 0) {
        ERR("Unable to get server public key.");
        return EXIT_FAILURE;
    }

    srv_pubkey_type = ssh_key_type(srv_pubkey);
    ret = ssh_get_publickey_hash(srv_pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash_sha1, &hlen);
    ssh_key_free(srv_pubkey);
    if (ret < 0) {
        ERR("Failed to calculate SHA1 hash of the server public key.");
        return EXIT_FAILURE;
    }

    hexa = ssh_get_hexa(hash_sha1, hlen);

    switch (state) {
    case SSH_SERVER_KNOWN_OK:
        break; /* ok */

    case SSH_SERVER_KNOWN_CHANGED:
        ERR("Remote host key changed, the connection will be terminated!");
        goto fail;

    case SSH_SERVER_FOUND_OTHER:
        ERR("The remote host key was not found but another type of key was, the connection will be terminated.");
        goto fail;

    case SSH_SERVER_FILE_NOT_FOUND:
        WRN("Could not find the known hosts file.");
        /* fallback to SSH_SERVER_NOT_KNOWN behavior */

    case SSH_SERVER_NOT_KNOWN:
#ifdef ENABLE_DNSSEC
        if ((srv_pubkey_type != SSH_KEYTYPE_UNKNOWN) || (srv_pubkey_type != SSH_KEYTYPE_RSA1)) {
            if (srv_pubkey_type == SSH_KEYTYPE_DSS) {
                ret = callback_ssh_hostkey_hash_dnssec_check(hostname, hash_sha1, 2, 1);
            } else if (srv_pubkey_type == SSH_KEYTYPE_RSA) {
                ret = callback_ssh_hostkey_hash_dnssec_check(hostname, hash_sha1, 1, 1);
            } else if (srv_pubkey_type == SSH_KEYTYPE_ECDSA) {
                ret = callback_ssh_hostkey_hash_dnssec_check(hostname, hash_sha1, 3, 1);
            }

            /* DNSSEC SSHFP check successful, that's enough */
            if (!ret) {
                DBG("DNSSEC SSHFP check successful");
                ssh_write_knownhost(session);
                ssh_clean_pubkey_hash(&hash_sha1);
                ssh_string_free_char(hexa);
                return EXIT_SUCCESS;
            }
        }
#endif

        /* try to get result from user */
        fprintf(stdout, "The authenticity of the host \'%s\' cannot be established.\n", hostname);
        fprintf(stdout, "%s key fingerprint is %s.\n", ssh_key_type_to_char(srv_pubkey_type), hexa);

#ifdef ENABLE_DNSSEC
        if (ret == 2) {
            fprintf(stdout, "No matching host key fingerprint found in DNS.\n");
        } else if (ret == 1) {
            fprintf(stdout, "Matching host key fingerprint found in DNS.\n");
        }
#endif

        fprintf(stdout, "Are you sure you want to continue connecting (yes/no)? ");

        do {
            if (fscanf(stdin, "%4s", answer) == EOF) {
                ERR("fscanf() failed (%s).", strerror(errno));
                goto fail;
            }
            while (((c = getchar()) != EOF) && (c != '\n'));

            fflush(stdin);
            if (!strcmp("yes", answer)) {
                /* store the key into the host file */
                ret = ssh_write_knownhost(session);
                if (ret < 0) {
                    WRN("Adding the known host %s failed (%s).", hostname, strerror(errno));
                }
            } else if (!strcmp("no", answer)) {
                goto fail;
            } else {
                fprintf(stdout, "Please type 'yes' or 'no': ");
            }
        } while (strcmp(answer, "yes") && strcmp(answer, "no"));

        break;

    case SSH_SERVER_ERROR:
        ssh_clean_pubkey_hash(&hash_sha1);
        fprintf(stderr,"%s",ssh_get_error(session));
        return -1;
    }

    ssh_clean_pubkey_hash(&hash_sha1);
    ssh_string_free_char(hexa);
    return EXIT_SUCCESS;

fail:
    ssh_clean_pubkey_hash(&hash_sha1);
    ssh_string_free_char(hexa);
    return EXIT_FAILURE;
}

static int
keypair_path_op(const char *pub_path, const char *priv_path, int to_add)
{
    int i;
    FILE *key;
    char line[128];

    if (!pub_path || !priv_path) {
        return EXIT_FAILURE;
    }

    for (i = 0; i < ssh_opts.key_count; ++i) {
        if (!strcmp(ssh_opts.keys[i].pubkey_path, pub_path) || !strcmp(ssh_opts.keys[i].privkey_path, priv_path)) {
            if (strcmp(ssh_opts.keys[i].pubkey_path, pub_path)) {
                WRN("Private key \"%s\" found with another public key \"%s\".",
                    priv_path, ssh_opts.keys[i].pubkey_path);
                continue;
            } else if (strcmp(ssh_opts.keys[i].privkey_path, priv_path)) {
                WRN("Public key \"%s\" found with another private key \"%s\".",
                    pub_path, ssh_opts.keys[i].privkey_path);
                continue;
            }

            if (to_add) {
                ERR("SSH key pair already set.");
                return EXIT_FAILURE;
            } else {
                break;
            }
        }
    }

    if ((i == ssh_opts.key_count) && !to_add) {
        ERR("SSH key pair to delete not found.");
        return EXIT_FAILURE;
    }

    /* add the keys safely */
    if (to_add) {
        ++ssh_opts.key_count;
        ssh_opts.keys = realloc(ssh_opts.keys, ssh_opts.key_count * sizeof *ssh_opts.keys);
        ssh_opts.keys[ssh_opts.key_count - 1].pubkey_path = strdup(pub_path);
        ssh_opts.keys[ssh_opts.key_count - 1].privkey_path = strdup(priv_path);
        ssh_opts.keys[ssh_opts.key_count - 1].privkey_crypt = 0;

        /* check encryption */
        if ((key = fopen(priv_path, "r"))) {
            /* 1st line - key type */
            if (!fgets(line, sizeof line, key)) {
                fclose(key);
                ERR("fgets() on %s failed.", priv_path);
                return EXIT_FAILURE;
            }
            /* 2nd line - encryption information or key */
            if (!fgets(line, sizeof line, key)) {
                fclose(key);
                ERR("fgets() on %s failed.", priv_path);
                return EXIT_FAILURE;
            }
            fclose(key);
            if (strcasestr(line, "encrypted")) {
                ssh_opts.keys[ssh_opts.key_count - 1].privkey_crypt = 1;
            }
        }

    /* remove the keys safely */
    } else {
        free(ssh_opts.keys[i].pubkey_path);
        free(ssh_opts.keys[i].privkey_path);

        if (i + 1 < ssh_opts.key_count) {
            memmove(ssh_opts.keys + i, ssh_opts.keys + i + 1, ((ssh_opts.key_count - i) - 1) * sizeof *ssh_opts.keys);
        }
        --ssh_opts.key_count;
        ssh_opts.keys = realloc(ssh_opts.keys, ssh_opts.key_count * sizeof *ssh_opts.keys);
    }

    return EXIT_SUCCESS;
}

API int
nc_set_keypair_path(const char *pub_key, const char *priv_key)
{
    if (keypair_path_op(pub_key, priv_key, 1)) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

API int
nc_del_keypair_path(const char *pub_key, const char *priv_key)
{
    if (keypair_path_op(pub_key, priv_key, 0)) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/* Establish a secure SSH connection, authenticate, and create a channel with the 'netconf' subsystem.
 * Host, port, username, and a connected socket is expected to be set.
 */
static int
connect_ssh_session_netconf(struct nc_session *session)
{
    int i, j, ret_auth, userauthlist;
    int auth = 0;
    const char* prompt;
    char *s, *answer, echo;
    ssh_key pubkey, privkey;
    ssh_session ssh_sess;

    ssh_sess = session->ti.libssh.session;

    if (ssh_connect(ssh_sess) != SSH_OK) {
        ERR("Starting the SSH session failed (%s)", ssh_get_error(ssh_sess));
        DBG("Error code %d.", ssh_get_error_code(ssh_sess));
        return EXIT_FAILURE;
    }

    if (sshauth_hostkey_check(session->host, ssh_sess)) {
        ERR("Checking the host key failed.");
        return EXIT_FAILURE;
    }

    if ((ret_auth = ssh_userauth_none(ssh_sess, NULL)) == SSH_AUTH_ERROR) {
        ERR("Authentication failed (%s).", ssh_get_error(ssh_sess));
        return EXIT_FAILURE;
    }

    /* check what authentication methods are available */
    userauthlist = ssh_userauth_list(ssh_sess, NULL);
    if (userauthlist & SSH_AUTH_METHOD_PASSWORD) {
        auth |= NC_SSH_AUTH_PASSWORD;
    }
    if (userauthlist & SSH_AUTH_METHOD_PUBLICKEY) {
        auth |= NC_SSH_AUTH_PUBLIC_KEYS;
    }
    if (userauthlist & SSH_AUTH_METHOD_INTERACTIVE) {
        auth |= NC_SSH_AUTH_INTERACTIVE;
    }
    if (!auth && (ret_auth != SSH_AUTH_SUCCESS)) {
        ERR("Unable to authenticate to the remote server (Authentication methods not supported).");
        return EXIT_FAILURE;
    }

    /* select authentication according to preferences */
    for (i = 0; i < SSH_AUTH_COUNT; i++) {
        if (!(ssh_opts.auth_pref[i].type & auth)) {
            /* method not supported by server, skip */
            continue;
        }

        if (ssh_opts.auth_pref[i].value < 0) {
            /* all following auth methods are disabled via negative preference value */
            ERR("Unable to authenticate to the remote server (method disabled or permission denied).");
            return EXIT_FAILURE;
        }

        /* found common authentication method */
        switch (ssh_opts.auth_pref[i].type) {
        case NC_SSH_AUTH_PASSWORD:
            VRB("Password authentication (host %s, user %s)", session->host, session->username);
            s = sshauth_password(session->username, session->host);
            if ((ret_auth = ssh_userauth_password(ssh_sess, session->username, s)) != SSH_AUTH_SUCCESS) {
                memset(s, 0, strlen(s));
                VRB("Authentication failed (%s)", ssh_get_error(ssh_sess));
            }
            free(s);
            break;
        case NC_SSH_AUTH_INTERACTIVE:
            VRB("Keyboard-interactive authentication");
            while ((ret_auth = ssh_userauth_kbdint(ssh_sess, NULL, NULL)) == SSH_AUTH_INFO) {
                for (j = 0; j < ssh_userauth_kbdint_getnprompts(ssh_sess); ++j) {
                    prompt = ssh_userauth_kbdint_getprompt(ssh_sess, j, &echo);
                    if (prompt == NULL) {
                        break;
                    }
                    answer = sshauth_interactive(ssh_userauth_kbdint_getname(ssh_sess),
                                                 ssh_userauth_kbdint_getinstruction(ssh_sess),
                                                 prompt, echo);
                    if (ssh_userauth_kbdint_setanswer(ssh_sess, j, answer) < 0) {
                        free(answer);
                        break;
                    }
                    free(answer);
                }
            }

            if (ret_auth == SSH_AUTH_ERROR) {
                VRB("Authentication failed (%s)", ssh_get_error(ssh_sess));
            }

            break;
        case NC_SSH_AUTH_PUBLIC_KEYS:
            VRB("Publickey athentication");

            /* if publickeys path not provided, we cannot continue */
            if (!ssh_opts.key_count) {
                VRB("No key pair specified.");
                break;
            }

            for (j = 0; j < ssh_opts.key_count; j++) {
                VRB("Trying to authenticate using %spair %s %s",
                     ssh_opts.keys[j].privkey_crypt ? "password-protected " : "", ssh_opts.keys[j].privkey_path,
                     ssh_opts.keys[j].pubkey_path);

                if (ssh_pki_import_pubkey_file(ssh_opts.keys[j].pubkey_path, &pubkey) != SSH_OK) {
                    WRN("Failed to import the key \"%s\".", ssh_opts.keys[j].pubkey_path);
                    continue;
                }
                ret_auth = ssh_userauth_try_publickey(ssh_sess, NULL, pubkey);
                if ((ret_auth == SSH_AUTH_DENIED) || (ret_auth == SSH_AUTH_PARTIAL)) {
                    ssh_key_free(pubkey);
                    continue;
                }
                if (ret_auth == SSH_AUTH_ERROR) {
                    ERR("Authentication failed (%s)", ssh_get_error(ssh_sess));
                    ssh_key_free(pubkey);
                    break;
                }

                if (ssh_opts.keys[j].privkey_crypt) {
                    s = sshauth_passphrase(ssh_opts.keys[j].privkey_path);
                } else {
                    s = NULL;
                }

                if (ssh_pki_import_privkey_file(ssh_opts.keys[j].privkey_path, s, NULL, NULL, &privkey) != SSH_OK) {
                    WRN("Failed to import the key \"%s\".", ssh_opts.keys[j].privkey_path);
                    if (s) {
                        memset(s, 0, strlen(s));
                        free(s);
                    }
                    ssh_key_free(pubkey);
                    continue;
                }

                if (s) {
                    memset(s, 0, strlen(s));
                    free(s);
                }

                ret_auth = ssh_userauth_publickey(ssh_sess, NULL, privkey);
                ssh_key_free(pubkey);
                ssh_key_free(privkey);

                if (ret_auth == SSH_AUTH_ERROR) {
                    ERR("Authentication failed (%s)", ssh_get_error(ssh_sess));
                }
                if (ret_auth == SSH_AUTH_SUCCESS) {
                    break;
                }
            }
            break;
        }

        if (ret_auth == SSH_AUTH_SUCCESS) {
            break;
        }
    }

    /* check a state of authentication */
    if (ret_auth != SSH_AUTH_SUCCESS) {
        ERR("Authentication failed.");
        return EXIT_FAILURE;
    }

    /* open a channel */
    session->ti.libssh.channel = ssh_channel_new(ssh_sess);
    if (ssh_channel_open_session(session->ti.libssh.channel) != SSH_OK) {
        ssh_channel_free(session->ti.libssh.channel);
        session->ti.libssh.channel = NULL;
        ERR("Opening an SSH channel failed (%s)", ssh_get_error(ssh_sess));
        return EXIT_FAILURE;
    }

    /* execute the NETCONF subsystem on the channel */
    if (ssh_channel_request_subsystem(session->ti.libssh.channel, "netconf") != SSH_OK) {
        ssh_channel_free(session->ti.libssh.channel);
        session->ti.libssh.channel = NULL;
        ERR("Starting the \"netconf\" SSH subsystem failed (%s)", ssh_get_error(ssh_sess));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

API struct nc_session *
nc_connect_ssh(const char *host, unsigned short port, const char *username, struct ly_ctx *ctx)
{
    const int timeout = SSH_TIMEOUT;
    int sock;
    struct passwd *pw;
    struct nc_session *session = NULL;

    /* process parameters */
    if (!host || strisempty(host)) {
        host = "localhost";
    }

    if (!port) {
        port = NC_PORT_SSH;
    }

    if (!username) {
        pw = getpwuid(getuid());
        if (!pw) {
            ERR("Unknown username for the SSH connection (%s).", strerror(errno));
            return NULL;
        } else {
            username = pw->pw_name;
        }
    }

    /* prepare session structure */
    session = connect_init(ctx);
    if (!session) {
        return NULL;
    }
    session->ti_type = NC_TI_LIBSSH;

    /* transport lock */
    session->ti_lock = malloc(sizeof *session->ti_lock);
    if (!session->ti_lock) {
        ERRMEM;
        goto fail;
    }
    pthread_mutex_init(session->ti_lock, NULL);

    /* other transport-specific data */
    session->username = lydict_insert(session->ctx, username, 0);
    session->host = lydict_insert(session->ctx, host, 0);
    session->port = port;
    session->ti.libssh.session = ssh_new();
    if (!session->ti.libssh.session) {
        ERR("Unable to initialize SSH session.");
        goto fail;
    }

    /* set some basic SSH session options */
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_HOST, session->host);
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_PORT, &session->port);
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_USER, session->username);
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_TIMEOUT, &timeout);

    /* create and assign communication socket */
    sock = connect_getsocket(host, port);
    if (sock == -1) {
        goto fail;
    }
    ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_FD, &sock);

    if (connect_ssh_session_netconf(session)) {
        goto fail;
    }

    /* NETCONF handshake */
    if (handshake(session)) {
        goto fail;
    }

    session->status = NC_STATUS_RUNNING;
    return session;

fail:
    nc_session_free(session);
    return NULL;
}

API struct nc_session *
nc_connect_libssh(ssh_session ssh_session, struct ly_ctx *ctx)
{
    const char *host, *username;
    unsigned short port;
    int sock;
    struct passwd *pw;
    struct nc_session *session = NULL;

    /* prepare session structure */
    session = connect_init(ctx);
    if (!session) {
        return NULL;
    }
    session->ti_type = NC_TI_LIBSSH;

    /* transport lock */
    session->ti_lock = malloc(sizeof *session->ti_lock);
    if (!session->ti_lock) {
        ERRMEM;
        goto fail;
    }
    pthread_mutex_init(session->ti_lock, NULL);

    session->ti.libssh.session = ssh_session;

    if (!ctx) {
        ctx = session->ctx;
    }

    if (ssh_get_fd(ssh_session) == -1) {
        /*
         * There is no file descriptor, we need to create it. (TCP/IP layer)
         */

        /* was host, port set? */
        if (ssh_options_get(ssh_session, SSH_OPTIONS_HOST, (char **)&host) != SSH_OK) {
            host = NULL;
        }
        ssh_options_get_port(ssh_session, (unsigned int *)&port);

        /* remember host */
        if (!host) {
            host = lydict_insert(ctx, "localhost", 0);
            ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_HOST, host);
        } else {
            host = lydict_insert_zc(ctx, (char *)host);
        }
        session->host = host;

        /* remember port (even if not set, dumb libssh returns 22, no way to know if it was actually set) */
        session->port = port;

        /* create and connect socket */
        sock = connect_getsocket(host, port);
        if (sock == -1) {
            goto fail;
        }
        ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_FD, &sock);
    }

    if (!ssh_is_connected(ssh_session)) {
        /*
         * We are connected, but not SSH authenticated. (Transport layer)
         */

        /* was username set? */
        if (ssh_options_get(ssh_session, SSH_OPTIONS_USER, (char **)&username) != SSH_OK) {
            username = NULL;
        }

        /* remember username */
        if (!username) {
            pw = getpwuid(getuid());
            if (!pw) {
                ERR("Unknown username for the SSH connection (%s).", strerror(errno));
                goto fail;
            }

            username = lydict_insert(ctx, pw->pw_name, 0);
            ssh_options_set(session->ti.libssh.session, SSH_OPTIONS_USER, username);
        } else {
            username = lydict_insert_zc(ctx, (char *)username);
        }
        session->username = username;

        /* authenticate SSH session */
        if (connect_ssh_session_netconf(session)) {
            goto fail;
        }
    }

    /*
     * SSH session is established, create NETCONF session. (Application layer)
     */

    /* NETCONF handshake */
    if (handshake(session)) {
        goto fail;
    }

    session->status = NC_STATUS_RUNNING;
    return session;

fail:
    nc_session_free(session);
    return NULL;
}

API struct nc_session *
nc_connect_ssh_channel(struct nc_session *session, struct ly_ctx *ctx)
{
    struct nc_session *new_session, *ptr;

    /* prepare session structure */
    new_session = connect_init(ctx);
    if (!new_session) {
        return NULL;
    }
    if (!ctx) {
        ctx = new_session->ctx;
    }

    /* share some parameters including the session lock */
    new_session->ti_type = NC_TI_LIBSSH;
    new_session->ti_lock = session->ti_lock;
    new_session->host = lydict_insert(ctx, session->host, 0);
    new_session->port = session->port;
    new_session->username = lydict_insert(ctx, session->username, 0);
    new_session->ti.libssh.session = session->ti.libssh.session;

    /* create the channel safely */
    pthread_mutex_lock(new_session->ti_lock);

    /* open a channel */
    new_session->ti.libssh.channel = ssh_channel_new(new_session->ti.libssh.session);
    if (ssh_channel_open_session(new_session->ti.libssh.channel) != SSH_OK) {
        nc_session_free(new_session);
        ERR("Opening an SSH channel failed (%s)", ssh_get_error(session->ti.libssh.session));
        return NULL;
    }
    /* execute the NETCONF subsystem on the channel */
    if (ssh_channel_request_subsystem(new_session->ti.libssh.channel, "netconf") != SSH_OK) {
        nc_session_free(new_session);
        ERR("Starting the \"netconf\" SSH subsystem failed (%s)", ssh_get_error(session->ti.libssh.session));
        return NULL;
    }
    /* NETCONF handshake */
    if (handshake(new_session)) {
        nc_session_free(new_session);
        return NULL;
    }
    new_session->status = NC_STATUS_RUNNING;

    pthread_mutex_unlock(new_session->ti_lock);

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
}
