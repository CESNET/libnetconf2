/**
 * @file session_client.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libnetconf2 session client functions
 *
 * @copyright
 * Copyright (c) 2015 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#ifdef __linux__
# include <sys/syscall.h>
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef NC_ENABLED_SSH_TLS
#include <libssh/libssh.h>
#endif
#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "log_p.h"
#include "messages_p.h"
#include "session_client.h"
#include "session_client_ch.h"
#include "session_p.h"

#include "../modules/ietf_netconf@2013-09-29_yang.h"
#include "../modules/ietf_netconf_monitoring@2010-10-04_yang.h"

static const char *ncds2str[] = {NULL, "config", "url", "running", "startup", "candidate"};

#ifdef NC_ENABLED_SSH_TLS
char *sshauth_password(const char *username, const char *hostname, void *priv);
char *sshauth_interactive(const char *auth_name, const char *instruction, const char *prompt, int echo, void *priv);
char *sshauth_privkey_passphrase(const char *privkey_path, void *priv);
#endif /* NC_ENABLED_SSH_TLS */

static pthread_once_t nc_client_context_once = PTHREAD_ONCE_INIT;
static pthread_key_t nc_client_context_key;
#ifdef __linux__
static struct nc_client_context context_main = {
    .opts.ka = {
        .enabled = 1,
        .idle_time = 1,
        .max_probes = 10,
        .probe_interval = 5
    },
#ifdef NC_ENABLED_SSH_TLS
    .ssh_opts = {
        .auth_pref = {{NC_SSH_AUTH_INTERACTIVE, 1}, {NC_SSH_AUTH_PASSWORD, 2}, {NC_SSH_AUTH_PUBLICKEY, 3}},
        .auth_password = sshauth_password,
        .auth_interactive = sshauth_interactive,
        .auth_privkey_passphrase = sshauth_privkey_passphrase,
        .knownhosts_mode = NC_SSH_KNOWNHOSTS_ASK
    },
    .ssh_ch_opts = {
        .auth_pref = {{NC_SSH_AUTH_INTERACTIVE, 1}, {NC_SSH_AUTH_PASSWORD, 2}, {NC_SSH_AUTH_PUBLICKEY, 3}},
        .auth_password = sshauth_password,
        .auth_interactive = sshauth_interactive,
        .auth_privkey_passphrase = sshauth_privkey_passphrase,
        .knownhosts_mode = NC_SSH_KNOWNHOSTS_ASK
    },
#endif /* NC_ENABLED_SSH_TLS */
    /* .tls_ structures zeroed */
    .refcount = 0
};
#endif

static void
nc_client_context_free(void *ptr)
{
    struct nc_client_context *c = (struct nc_client_context *)ptr;

    if (--(c->refcount)) {
        /* still used */
        return;
    }

#ifdef __linux__
    /* in __linux__ we use static memory in the main thread,
     * so this check is for programs terminating the main()
     * function by pthread_exit() :)
     */
    if (c != &context_main)
#endif
    {
        /* for the main thread the same is done in nc_client_destroy() */
        free(c->opts.schema_searchpath);

#ifdef NC_ENABLED_SSH_TLS
        int i;

        for (i = 0; i < c->opts.ch_bind_count; ++i) {
            close(c->opts.ch_binds[i].sock);
            free((char *)c->opts.ch_binds[i].address);
        }
        free(c->opts.ch_binds);
        c->opts.ch_binds = NULL;
        c->opts.ch_bind_count = 0;

        _nc_client_ssh_destroy_opts(&c->ssh_opts);
        _nc_client_ssh_destroy_opts(&c->ssh_ch_opts);

        _nc_client_tls_destroy_opts(&c->tls_opts);
        _nc_client_tls_destroy_opts(&c->tls_ch_opts);
#endif /* NC_ENABLED_SSH_TLS */
        free(c);
    }
}

static void
nc_client_context_createkey(void)
{
    int r;

    /* initiate */
    while ((r = pthread_key_create(&nc_client_context_key, nc_client_context_free)) == EAGAIN) {}
    pthread_setspecific(nc_client_context_key, NULL);
}

struct nc_client_context *
nc_client_context_location(void)
{
    struct nc_client_context *e;

    pthread_once(&nc_client_context_once, nc_client_context_createkey);
    e = pthread_getspecific(nc_client_context_key);
    if (!e) {
        /* prepare ly_err storage */
#ifdef __linux__
        if (getpid() == syscall(SYS_gettid)) {
            /* main thread - use global variable instead of thread-specific variable. */
            e = &context_main;
        } else
#endif /* __linux__ */
        {
            e = calloc(1, sizeof *e);
            /* set default values */
            e->refcount = 1;
#ifdef NC_ENABLED_SSH_TLS
# ifdef HAVE_TERMIOS
            e->ssh_opts.knownhosts_mode = NC_SSH_KNOWNHOSTS_ASK;
# else
            e->ssh_opts.knownhosts_mode = NC_SSH_KNOWNHOSTS_ACCEPT;
# endif
            e->ssh_opts.auth_pref[0].type = NC_SSH_AUTH_INTERACTIVE;
            e->ssh_opts.auth_pref[0].value = 1;
            e->ssh_opts.auth_pref[1].type = NC_SSH_AUTH_PASSWORD;
            e->ssh_opts.auth_pref[1].value = 2;
            e->ssh_opts.auth_pref[2].type = NC_SSH_AUTH_PUBLICKEY;
            e->ssh_opts.auth_pref[2].value = 3;
            e->ssh_opts.auth_password = sshauth_password;
            e->ssh_opts.auth_interactive = sshauth_interactive;
            e->ssh_opts.auth_privkey_passphrase = sshauth_privkey_passphrase;

            /* callhome settings are the same */
            memcpy(&e->ssh_ch_opts, &e->ssh_opts, sizeof e->ssh_ch_opts);
            e->ssh_ch_opts.auth_pref[0].value = 1;
            e->ssh_ch_opts.auth_pref[1].value = 2;
            e->ssh_ch_opts.auth_pref[2].value = 3;
#endif /* NC_ENABLED_SSH_TLS */
        }
        pthread_setspecific(nc_client_context_key, e);
    }

    return e;
}

#define client_opts nc_client_context_location()->opts

API void *
nc_client_get_thread_context(void)
{
    return nc_client_context_location();
}

API void
nc_client_set_thread_context(void *context)
{
    struct nc_client_context *old, *new;

    if (!context) {
        ERRARG(NULL, "context");
        return;
    }

    new = (struct nc_client_context *)context;
    old = nc_client_context_location();
    if (old == new) {
        /* nothing to change */
        return;
    }

    /* replace old by new, increase reference counter in the newly set context */
    nc_client_context_free(old);
    new->refcount++;
    pthread_setspecific(nc_client_context_key, new);
}

/**
 * @brief Ext data callback for a context to provide schema mount data.
 */
static LY_ERR
nc_ly_ext_data_clb(const struct lysc_ext_instance *ext, void *user_data, void **ext_data, ly_bool *ext_data_free)
{
    struct nc_session *session = user_data;

    if (strcmp(ext->def->module->name, "ietf-yang-schema-mount") || strcmp(ext->def->name, "mount-point")) {
        return LY_EINVAL;
    }

    if (!session->opts.client.ext_data) {
        ERR(session, "Unable to parse mounted data, no operational schema-mounts data received from the server.");
        return LY_ENOTFOUND;
    }

    /* return ext data */
    *ext_data = session->opts.client.ext_data;
    *ext_data_free = 0;

    return LY_SUCCESS;
}

int
nc_client_session_new_ctx(struct nc_session *session, struct ly_ctx *ctx)
{
    /* assign context (dicionary needed for handshake) */
    if (!ctx) {
        if (ly_ctx_new(NULL, LY_CTX_NO_YANGLIBRARY, &ctx)) {
            return EXIT_FAILURE;
        }

        /* user path must be first, the first path is used to store modules retreived via get-schema */
        if (client_opts.schema_searchpath) {
            ly_ctx_set_searchdir(ctx, client_opts.schema_searchpath);
        }
        if (!access(NC_CLIENT_SEARCH_DIR, F_OK)) {
            ly_ctx_set_searchdir(ctx, NC_CLIENT_SEARCH_DIR);
        }

        /* set callback for getting modules, if provided */
        ly_ctx_set_module_imp_clb(ctx, client_opts.schema_clb, client_opts.schema_clb_data);

        /* set ext data callback to avoid errors that no callback is set, the data are stored later, if any */
        ly_ctx_set_ext_data_clb(ctx, nc_ly_ext_data_clb, session);
    } else {
        session->flags |= NC_SESSION_SHAREDCTX;
    }

    session->ctx = ctx;

    return EXIT_SUCCESS;
}

API int
nc_client_set_schema_searchpath(const char *path)
{
    if (client_opts.schema_searchpath) {
        free(client_opts.schema_searchpath);
    }

    if (path) {
        client_opts.schema_searchpath = strdup(path);
        NC_CHECK_ERRMEM_RET(!client_opts.schema_searchpath, 1);
    } else {
        client_opts.schema_searchpath = NULL;
    }

    return 0;
}

API const char *
nc_client_get_schema_searchpath(void)
{
    return client_opts.schema_searchpath;
}

API int
nc_client_set_schema_callback(ly_module_imp_clb clb, void *user_data)
{
    client_opts.schema_clb = clb;
    if (clb) {
        client_opts.schema_clb_data = user_data;
    } else {
        client_opts.schema_clb_data = NULL;
    }

    return 0;
}

API ly_module_imp_clb
nc_client_get_schema_callback(void **user_data)
{
    if (user_data) {
        (*user_data) = client_opts.schema_clb_data;
    }
    return client_opts.schema_clb;
}

API void
nc_client_set_new_session_context_autofill(int enabled)
{
    client_opts.auto_context_fill_disabled = !enabled;
}

struct module_info {
    char *name;
    char *revision;

    struct {
        char *name;
        char *revision;
    } *submodules;
    char **features;
    int implemented;
};

struct clb_data_s {
    void *user_data;
    ly_module_imp_clb user_clb;
    struct module_info *modules;
    struct nc_session *session;
    int has_get_schema;
};

/**
 * @brief Retrieve YANG module content from a local file.
 *
 * @param[in] name Module name.
 * @param[in] rev Module revision.
 * @param[in] clb_data get-schema callback data.
 * @param[out] format Module format.
 * @return Module content.
 */
static char *
retrieve_module_data_localfile(const char *name, const char *rev, struct clb_data_s *clb_data,
        LYS_INFORMAT *format)
{
    char *localfile = NULL, *model_data = NULL;
    const char *ptr;
    FILE *f;
    long length, l;

    if (lys_search_localfile(ly_ctx_get_searchdirs(clb_data->session->ctx),
            !(ly_ctx_get_options(clb_data->session->ctx) & LY_CTX_DISABLE_SEARCHDIR_CWD),
            name, rev, &localfile, format)) {
        return NULL;
    }
    if (localfile && rev) {
        ptr = strrchr(localfile, '/');
        if (!strchr(ptr, '@')) {
            /* we do not know the revision of the module and we require a specific one, so ignore this module */
            localfile = NULL;
        }
    }

    if (!localfile) {
        return NULL;
    }

    VRB(clb_data->session, "Reading module \"%s@%s\" from local file \"%s\".", name, rev ? rev : "<latest>",
            localfile);
    f = fopen(localfile, "r");
    if (!f) {
        ERR(clb_data->session, "Unable to open file \"%s\" (%s).", localfile, strerror(errno));
        free(localfile);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    length = ftell(f);
    if (length < 0) {
        ERR(clb_data->session, "Unable to get the size of module file \"%s\".", localfile);
        free(localfile);
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);

    model_data = malloc(length + 1);
    if (!model_data) {
        ERRMEM;
    } else if ((l = fread(model_data, 1, length, f)) != length) {
        ERR(clb_data->session, "Reading module from \"%s\" failed (%d bytes read, but %d expected).", localfile, l,
                length);
        free(model_data);
        model_data = NULL;
    } else {
        /* terminating NULL byte */
        model_data[length] = '\0';
    }
    fclose(f);
    free(localfile);

    return model_data;
}

/**
 * @brief Retrieve YANG module content from a reply to get-schema RPC.
 *
 * @param[in] name Module name.
 * @param[in] rev Module revision.
 * @param[in] clb_data get-schema callback data.
 * @param[out] format Module format.
 * @return Module content.
 */
static char *
retrieve_module_data_getschema(const char *name, const char *rev, struct clb_data_s *clb_data,
        LYS_INFORMAT *format)
{
    struct nc_rpc *rpc;
    struct lyd_node *envp = NULL, *op = NULL;
    struct lyd_node_any *get_schema_data;
    NC_MSG_TYPE msg;
    uint64_t msgid;
    char *localfile = NULL, *envp_str = NULL, *model_data = NULL;
    FILE *f;

    VRB(clb_data->session, "Reading module \"%s@%s\" from server via get-schema.", name, rev ? rev : "<latest>");
    rpc = nc_rpc_getschema(name, rev, "yang", NC_PARAMTYPE_CONST);

    while ((msg = nc_send_rpc(clb_data->session, rpc, 0, &msgid)) == NC_MSG_WOULDBLOCK) {
        usleep(1000);
    }
    if (msg == NC_MSG_ERROR) {
        ERR(clb_data->session, "Failed to send the <get-schema> RPC.");
        nc_rpc_free(rpc);
        return NULL;
    }

    do {
        msg = nc_recv_reply(clb_data->session, rpc, msgid, NC_READ_ACT_TIMEOUT * 1000, &envp, &op);
    } while (msg == NC_MSG_NOTIF || msg == NC_MSG_REPLY_ERR_MSGID);
    nc_rpc_free(rpc);
    if (msg == NC_MSG_WOULDBLOCK) {
        ERR(clb_data->session, "Timeout for receiving reply to a <get-schema> expired.");
        goto cleanup;
    } else if (msg == NC_MSG_ERROR) {
        ERR(clb_data->session, "Failed to receive a reply to <get-schema>.");
        goto cleanup;
    } else if (!op) {
        assert(envp);
        lyd_print_mem(&envp_str, envp, LYD_XML, 0);
        WRN(clb_data->session, "Received an unexpected reply to <get-schema>:\n%s", envp_str);
        free(envp_str);
        goto cleanup;
    }

    if (!lyd_child(op) || (lyd_child(op)->schema->nodetype != LYS_ANYXML)) {
        ERR(clb_data->session, "Unexpected data in reply to a <get-schema> RPC.");
        goto cleanup;
    }
    get_schema_data = (struct lyd_node_any *)lyd_child(op);
    switch (get_schema_data->value_type) {
    case LYD_ANYDATA_STRING:
    case LYD_ANYDATA_XML:
        model_data = strdup(get_schema_data->value.str);
        break;
    case LYD_ANYDATA_DATATREE:
        lyd_print_mem(&model_data, get_schema_data->value.tree, LYD_XML, LYD_PRINT_WITHSIBLINGS);
        break;
    case LYD_ANYDATA_JSON:
    case LYD_ANYDATA_LYB:
        ERRINT;
        break;
    }

    if (model_data && !model_data[0]) {
        /* empty data */
        free(model_data);
        model_data = NULL;
    }
    if (!model_data) {
        goto cleanup;
    }

    /* set format */
    *format = LYS_IN_YANG;

    /* try to store the model_data into local module repository */
    lys_search_localfile(ly_ctx_get_searchdirs(clb_data->session->ctx), 0, name, rev, &localfile, NULL);
    if (client_opts.schema_searchpath && !localfile) {
        if (asprintf(&localfile, "%s/%s%s%s.yang", client_opts.schema_searchpath, name, rev ? "@" : "",
                rev ? rev : "") == -1) {
            ERRMEM;
        } else {
            f = fopen(localfile, "w");
            if (!f) {
                WRN(clb_data->session, "Unable to store \"%s\" as a local copy of module retrieved via <get-schema> (%s).",
                        localfile, strerror(errno));
            } else {
                fputs(model_data, f);
                fclose(f);
            }
        }
    }
    free(localfile);

cleanup:
    lyd_free_tree(envp);
    lyd_free_tree(op);
    return model_data;
}

static void
free_with_user_data(void *data, void *user_data)
{
    free(data);
    (void)user_data;
}

/**
 * @brief Retrieve YANG module content.
 *
 * @param[in] mod_name Module name.
 * @param[in] mod_rev Module revision.
 * @param[in] user_data get-schema callback data.
 * @param[out] format Module format.
 * @param[out] module_data Module content.
 * @param[out] free_module_data Callback for freeing @p module_data.
 * @return LY_ERR value.
 */
static LY_ERR
retrieve_module_data(const char *mod_name, const char *mod_rev, void *user_data, LYS_INFORMAT *format,
        const char **module_data, void (**free_module_data)(void *model_data, void *user_data))
{
    struct clb_data_s *clb_data = (struct clb_data_s *)user_data;
    char *model_data = NULL;

    /* 1. try to get data locally */
    model_data = retrieve_module_data_localfile(mod_name, mod_rev, clb_data, format);

    /* 2. try to use <get-schema> */
    if (!model_data && clb_data->has_get_schema) {
        model_data = retrieve_module_data_getschema(mod_name, mod_rev, clb_data, format);
    }

    /* 3. try to use user callback */
    if (!model_data && clb_data->user_clb) {
        VRB(clb_data->session, "Reading module \"%s@%s\" via user callback.", mod_name, mod_rev ? mod_rev : "<latest>");
        clb_data->user_clb(mod_name, mod_rev, NULL, NULL, clb_data->user_data, format, (const char **)&model_data,
                free_module_data);
    }

    *free_module_data = free_with_user_data;
    *module_data = model_data;
    return *module_data ? LY_SUCCESS : LY_ENOTFOUND;
}

/**
 * @brief Retrieve YANG import module content.
 *
 * @param[in] mod_name Module name.
 * @param[in] mod_rev Module revision.
 * @param[in] submod_name Optional submodule name.
 * @param[in] sub_rev Submodule revision.
 * @param[in] user_data get-schema callback data.
 * @param[out] format Module format.
 * @param[out] module_data Module content.
 * @param[out] free_module_data Callback for freeing @p module_data.
 * @return LY_ERR value.
 */
static LY_ERR
retrieve_module_data_imp(const char *mod_name, const char *mod_rev, const char *submod_name, const char *sub_rev,
        void *user_data, LYS_INFORMAT *format, const char **module_data,
        void (**free_module_data)(void *model_data, void *user_data))
{
    struct clb_data_s *clb_data = (struct clb_data_s *)user_data;
    uint32_t u, v, match = 1;
    const char *name = NULL, *rev = NULL;
    char *model_data = NULL;

    /* get and check the final name and revision of the module to be retrieved */
    if (!mod_rev || !mod_rev[0]) {
        /* newest revision requested - get the newest revision from the list of available modules on server */
        match = 0;
        for (u = 0; clb_data->modules[u].name; ++u) {
            if (strcmp(mod_name, clb_data->modules[u].name)) {
                continue;
            }
            if (!match || (strcmp(mod_rev, clb_data->modules[u].revision) > 0)) {
                mod_rev = clb_data->modules[u].revision;
            }
            match = u + 1;
        }
        if (!match) {
            /* valid situation if we are retrieving YANG 1.1 module and have only capabilities for now
             * (when loading ietf-datastore for ietf-yang-library) */
            VRB(clb_data->session, "Unable to identify revision of the import module \"%s\" from "
                    "the available server side information.", mod_name);
        }
    }
    if (submod_name) {
        name = submod_name;
        if (sub_rev) {
            rev = sub_rev;
        } else if (match) {
            if (!clb_data->modules[match - 1].submodules) {
                VRB(clb_data->session, "Unable to identify revision of the requested submodule \"%s\", "
                        "in import module \"%s\", from the available server side information.", submod_name, mod_name);
            } else {
                for (v = 0; clb_data->modules[match - 1].submodules[v].name; ++v) {
                    if (!strcmp(submod_name, clb_data->modules[match - 1].submodules[v].name)) {
                        rev = sub_rev = clb_data->modules[match - 1].submodules[v].revision;
                    }
                }
                if (!rev) {
                    ERR(clb_data->session, "Requested submodule \"%s\" is not found in import module \"%s\" on server side.",
                            submod_name, mod_name);
                    return LY_ENOTFOUND;
                }
            }
        }
    } else {
        name = mod_name;
        rev = mod_rev;
    }

    if (match) {
        /* we have enough information to avoid communication with server and try to get the module locally */

        /* 1. try to get data locally */
        model_data = retrieve_module_data_localfile(name, rev, clb_data, format);

        /* 2. try to use <get-schema> */
        if (!model_data && clb_data->has_get_schema) {
            model_data = retrieve_module_data_getschema(name, rev, clb_data, format);
        }
    } else {
        /* we are unsure which revision of the module we should load, so first try to get
         * the newest revision from the server via get-schema and only if the server does not
         * implement get-schema, try to load the newest revision locally. This is imperfect
         * solution, but there are situation when a client does not know what revision is
         * actually implemented by the server. */

        /* 1. try to use <get-schema> */
        if (clb_data->has_get_schema) {
            model_data = retrieve_module_data_getschema(name, rev, clb_data, format);
        }

        /* 2. try to get data locally */
        if (!model_data) {
            model_data = retrieve_module_data_localfile(name, rev, clb_data, format);
        }
    }

    /* 3. try to use user callback */
    if (!model_data && clb_data->user_clb) {
        VRB(clb_data->session, "Reading module \"%s@%s\" via user callback.", name, rev ? rev : "<latest>");
        clb_data->user_clb(mod_name, mod_rev, submod_name, sub_rev, clb_data->user_data, format,
                (const char **)&model_data, free_module_data);
    }

    *free_module_data = free_with_user_data;
    *module_data = model_data;
    return *module_data ? LY_SUCCESS : LY_ENOTFOUND;
}

/**
 * @brief Load a YANG module into context.
 *
 * @param[in] session NC session.
 * @param[in] name Module name.
 * @param[in] revision Module revision.
 * @param[in] features Enabled module features.
 * @param[in] modules Server module info built from capabilities.
 * @param[in] user_clb User callback for retrieving module data.
 * @param[in] user_data User data for @p user_clb.
 * @param[in] has_get_schema Whether the server supports get-schema.
 * @param[out] mod Loaded module.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
nc_ctx_load_module(struct nc_session *session, const char *name, const char *revision, const char **features,
        struct module_info *modules, ly_module_imp_clb user_clb, void *user_data, int has_get_schema, struct lys_module **mod)
{
    int ret = 0;
    const struct ly_err_item *eitem;
    const char *module_data = NULL;
    struct ly_in *in;
    LYS_INFORMAT format;
    uint32_t temp_lo = LY_LOSTORE, *prev_lo;

    void (*free_module_data)(void *, void *) = NULL;
    struct clb_data_s clb_data;

    /* try to use a module from the context */
    *mod = ly_ctx_get_module_implemented(session->ctx, name);
    if (!*mod) {
        if (revision) {
            *mod = ly_ctx_get_module(session->ctx, name, revision);
        } else {
            *mod = ly_ctx_get_module_latest(session->ctx, name);
        }
    } else if (revision && (!(*mod)->revision || strcmp((*mod)->revision, revision))) {
        WRN(session, "Server implements module \"%s\" in revision \"%s\" but revision \"%s\" is already implemented"
                " and will be used instead.", name, revision, (*mod)->revision ? (*mod)->revision : "<none>");
    }

    if (*mod) {
        /* make the present module implemented and/or enable all its features */
        if (lys_set_implemented(*mod, features)) {
            ERR(session, "Failed to implement module \"%s\".", (*mod)->name);
            return -1;
        }
        return 0;
    }

    /* missing implemented module, load it ... */
    clb_data.has_get_schema = has_get_schema;
    clb_data.modules = modules;
    clb_data.session = session;
    clb_data.user_clb = user_clb;
    clb_data.user_data = user_data;

    /* clear all the errors and just collect them for now */
    ly_err_clean(session->ctx, NULL);
    prev_lo = ly_temp_log_options(&temp_lo);

    /* get module data */
    if (!retrieve_module_data(name, revision, &clb_data, &format, &module_data, &free_module_data)) {
        /* set import callback */
        ly_ctx_set_module_imp_clb(session->ctx, retrieve_module_data_imp, &clb_data);

        /* parse the module */
        ly_in_new_memory(module_data, &in);
        lys_parse(session->ctx, in, format, features, mod);
        ly_in_free(in, 0);
        if (free_module_data) {
            free_module_data((char *)module_data, user_data);
        }

        ly_ctx_set_module_imp_clb(session->ctx, NULL, NULL);
    }

    /* restore logging options, then print errors on definite failure */
    ly_temp_log_options(prev_lo);
    if (!(*mod)) {
        for (eitem = ly_err_first(session->ctx); eitem; eitem = eitem->next) {
            ly_err_print(session->ctx, eitem);
        }
        ret = -1;
    } else {
        /* print only warnings */
        for (eitem = ly_err_first(session->ctx); eitem; eitem = eitem->next) {
            if (eitem->level == LY_LLWRN) {
                ly_err_print(session->ctx, eitem);
            }
        }
    }

    /* clean the errors */
    ly_err_clean(session->ctx, NULL);

    return ret;
}

static void
free_module_info(struct module_info *list)
{
    uint32_t u, v;

    if (!list) {
        return;
    }

    for (u = 0; list[u].name; ++u) {
        free(list[u].name);
        free(list[u].revision);
        if (list[u].features) {
            for (v = 0; list[u].features[v]; ++v) {
                free(list[u].features[v]);
            }
            free(list[u].features);
        }
        if (list[u].submodules) {
            for (v = 0; list[u].submodules[v].name; ++v) {
                free(list[u].submodules[v].name);
                free(list[u].submodules[v].revision);
            }
            free(list[u].submodules);
        }
    }
    free(list);
}

/**
 * @brief Retrieve yang-library and schema-mounts operational data from the server.
 *
 * @param[in] session NC session.
 * @param[in] has_get_data Whether get-data RPC is available or only get.
 * @param[in] filter Filter to use.
 * @param[out] oper_data Received data.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
get_oper_data(struct nc_session *session, int has_get_data, const char *filter, struct lyd_node **oper_data)
{
    struct nc_rpc *rpc = NULL;
    struct lyd_node *op = NULL, *envp = NULL;
    struct lyd_node_any *data;
    NC_MSG_TYPE msg;
    uint64_t msgid;
    int ret = 0;
    const char *rpc_name;

    /* get data from the server */
    if (has_get_data) {
        rpc_name = "<get-data>";
        rpc = nc_rpc_getdata("ietf-datastores:operational", filter, "false", NULL, 0, 0, 0, 0, 0, NC_PARAMTYPE_CONST);
    } else {
        rpc_name = "<get>";
        rpc = nc_rpc_get(filter, 0, NC_PARAMTYPE_CONST);
    }
    if (!rpc) {
        goto cleanup;
    }

    while ((msg = nc_send_rpc(session, rpc, 0, &msgid)) == NC_MSG_WOULDBLOCK) {
        usleep(1000);
    }
    if (msg == NC_MSG_ERROR) {
        WRN(session, "Failed to send %s RPC.", rpc_name);
        goto cleanup;
    }

    do {
        lyd_free_tree(envp);
        lyd_free_tree(op);

        msg = nc_recv_reply(session, rpc, msgid, NC_READ_ACT_TIMEOUT * 1000, &envp, &op);
    } while (msg == NC_MSG_NOTIF || msg == NC_MSG_REPLY_ERR_MSGID);
    if (msg == NC_MSG_WOULDBLOCK) {
        WRN(session, "Timeout for receiving reply to a %s RPC expired.", rpc_name);
        goto cleanup;
    } else if (msg == NC_MSG_ERROR) {
        WRN(session, "Failed to receive a reply to %s RPC.", rpc_name);
        goto cleanup;
    } else if (!op || !lyd_child(op) || !lyd_child(op)->schema || strcmp(lyd_child(op)->schema->name, "data")) {
        WRN(session, "Unexpected reply without data to a %s RPC.", rpc_name);
        goto cleanup;
    }

    data = (struct lyd_node_any *)lyd_child(op);
    if (data->value_type != LYD_ANYDATA_DATATREE) {
        WRN(session, "Unexpected data in reply to a %s RPC.", rpc_name);
        goto cleanup;
    } else if (!data->value.tree) {
        WRN(session, "No data in reply to a %s RPC.", rpc_name);
        goto cleanup;
    }

    *oper_data = data->value.tree;
    data->value.tree = NULL;

cleanup:
    nc_rpc_free(rpc);
    lyd_free_tree(envp);
    lyd_free_tree(op);

    if (session->status != NC_STATUS_RUNNING) {
        /* something bad happened, discard the session */
        ERR(session, "Invalid session, discarding.");
        ret = -1;
    }

    return ret;
}

/**
 * @brief Build server module info from ietf-yang-library data.
 *
 * @param[in] session NC session.
 * @param[in] get_data_sup Whether get-data RPC is available or only get.
 * @param[in] xpath_sup Whether XPath filter is supported or only subtree filter.
 * @param[out] result Server modules.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
build_module_info_yl(struct nc_session *session, int get_data_sup, int xpath_sup, struct module_info **result)
{
    struct ly_set *modules = NULL;
    uint32_t u, v, submodules_count, feature_count;
    struct lyd_node *iter, *child, *oper_data = NULL;
    struct lys_module *mod;
    int ret = 0;
    uint8_t notifications_found = 0;
    uint8_t nc_notifications_found = 0;

    /* get yang-library operational data */
    if (xpath_sup) {
        if (get_oper_data(session, get_data_sup, "/ietf-yang-library:*", &oper_data)) {
            goto cleanup;
        }
    } else {
        if (get_oper_data(session, get_data_sup,
                "<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\"/>", &oper_data)) {
            goto cleanup;
        }
    }
    if (!oper_data) {
        goto cleanup;
    }

    if (lyd_find_xpath(oper_data, "/ietf-yang-library:modules-state/module", &modules)) {
        WRN(NULL, "No yang-library module information found.");
        goto cleanup;
    }

    (*result) = calloc(modules->count + 1, sizeof **result);
    NC_CHECK_ERRMEM_GOTO(!(*result), ret = -1, cleanup);

    for (u = 0; u < modules->count; ++u) {
        submodules_count = 0;
        feature_count = 0;
        mod = ((struct lyd_node *)modules->dnodes[u])->schema->module;
        LY_LIST_FOR(lyd_child(modules->dnodes[u]), iter) {
            if (!iter->schema || (iter->schema->module != mod)) {
                /* ignore node from other schemas (augments) */
                continue;
            }
            if (!lyd_get_value(iter) || !lyd_get_value(iter)[0]) {
                /* ignore empty nodes */
                continue;
            }
            if (!strcmp(iter->schema->name, "name")) {
                (*result)[u].name = strdup(lyd_get_value(iter));
                if (!strcmp((*result)[u].name, "notifications")) {
                    notifications_found = 1;
                } else if (!strcmp((*result)[u].name, "nc-notifications")) {
                    nc_notifications_found = 1;
                }
            } else if (!strcmp(iter->schema->name, "revision")) {
                (*result)[u].revision = strdup(lyd_get_value(iter));
            } else if (!strcmp(iter->schema->name, "conformance-type")) {
                (*result)[u].implemented = !strcmp(lyd_get_value(iter), "implement");
            } else if (!strcmp(iter->schema->name, "feature")) {
                (*result)[u].features = nc_realloc((*result)[u].features, (feature_count + 2) * sizeof *(*result)[u].features);
                NC_CHECK_ERRMEM_GOTO(!(*result)[u].features, free_module_info(*result); *result = NULL; ret = -1, cleanup);
                (*result)[u].features[feature_count] = strdup(lyd_get_value(iter));
                (*result)[u].features[feature_count + 1] = NULL;
                ++feature_count;
            } else if (!strcmp(iter->schema->name, "submodule")) {
                submodules_count++;
            }
        }

        if (submodules_count) {
            (*result)[u].submodules = calloc(submodules_count + 1, sizeof *(*result)[u].submodules);
            NC_CHECK_ERRMEM_GOTO(!(*result)[u].submodules, free_module_info(*result); *result = NULL; ret = -1, cleanup);
            v = 0;
            LY_LIST_FOR(lyd_child(modules->dnodes[u]), iter) {
                mod = modules->dnodes[u]->schema->module;
                if ((mod == iter->schema->module) && !strcmp(iter->schema->name, "submodule")) {
                    LY_LIST_FOR(lyd_child(iter), child) {
                        if (mod != child->schema->module) {
                            continue;
                        } else if (!strcmp(child->schema->name, "name")) {
                            (*result)[u].submodules[v].name = strdup(lyd_get_value(child));
                        } else if (!strcmp(child->schema->name, "revision")) {
                            (*result)[u].submodules[v].revision = strdup(lyd_get_value(child));
                        }
                    }
                }
            }
        }
    }

    /* If NETCONF server supports RFC5277 notification capability and libnetconf2
     * required notifications and nc-notifications are not present on the NETCONF
     * server (which it is not obligated to support), then the libyang context
     * needs to be initialized using client side local YANG schema files */
    if (nc_session_cpblt(session, "urn:ietf:params:netconf:capability:notification:1.0") &&
            !notifications_found && !nc_notifications_found) {

        (*result) = nc_realloc(*result, (modules->count + 3) * sizeof **result);
        NC_CHECK_ERRMEM_GOTO(!(*result), ret = -1, cleanup);

        (*result)[u].name = strdup("notifications");
        (*result)[u].revision = strdup("2008-07-14");
        (*result)[u].implemented = 1;
        u++;

        (*result)[u].name = strdup("nc-notifications");
        (*result)[u].revision = strdup("2008-07-14");
        (*result)[u].implemented = 1;
    }

cleanup:
    lyd_free_siblings(oper_data);
    ly_set_free(modules, NULL);
    return ret;
}

/**
 * @brief Build server module info from received capabilities.
 *
 * @param[in] cpblts Server capabilities.
 * @param[out] result Server modules.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
build_module_info_cpblts(char **cpblts, struct module_info **result)
{
    uint32_t u, v, feature_count;
    char *module_cpblt, *ptr, *ptr2;

    for (u = 0; cpblts[u]; ++u) {}
    (*result) = calloc(u + 1, sizeof **result);
    NC_CHECK_ERRMEM_RET(!(*result), -1);

    for (u = v = 0; cpblts[u]; ++u) {
        module_cpblt = strstr(cpblts[u], "module=");
        /* this capability requires a module */
        if (!module_cpblt) {
            continue;
        }

        /* get module's name */
        ptr = (char *)module_cpblt + 7;
        ptr2 = strchr(ptr, '&');
        if (!ptr2) {
            ptr2 = ptr + strlen(ptr);
        }
        (*result)[v].name = strndup(ptr, ptr2 - ptr);

        /* get module's revision */
        ptr = strstr(module_cpblt, "revision=");
        if (ptr) {
            ptr += 9;
            ptr2 = strchr(ptr, '&');
            if (!ptr2) {
                ptr2 = ptr + strlen(ptr);
            }
            (*result)[v].revision = strndup(ptr, ptr2 - ptr);
        }

        /* all are implemented since there is no better information in capabilities list */
        (*result)[v].implemented = 1;

        /* get module's features */
        ptr = strstr(module_cpblt, "features=");
        if (ptr) {
            ptr += 9;
            feature_count = 0;
            for (ptr2 = ptr; *ptr && *ptr != '&'; ++ptr) {
                if (*ptr == ',') {
                    (*result)[v].features = nc_realloc((*result)[v].features, (feature_count + 2) * sizeof *(*result)[v].features);
                    (*result)[v].features[feature_count] = strndup(ptr2, ptr - ptr2);
                    (*result)[v].features[feature_count + 1] = NULL;
                    ++feature_count;

                    ptr2 = ptr + 1;
                }
            }
            /* the last one */
            (*result)[v].features = nc_realloc((*result)[v].features, (feature_count + 2) * sizeof *(*result)[v].features);
            (*result)[v].features[feature_count] = strndup(ptr2, ptr - ptr2);
            (*result)[v].features[feature_count + 1] = NULL;
            ++feature_count;
        }
        ++v;
    }

    return 0;
}

/**
 * @brief Fill client context based on server modules info.
 *
 * @param[in] session NC session with the context to modify.
 * @param[in] modules Server modules info.
 * @param[in] user_clb User callback for retrieving specific modules.
 * @param[in] user_data User data for @p user_clb.
 * @param[in] has_get_schema Whether server supports get-schema RPC.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
nc_ctx_fill(struct nc_session *session, struct module_info *modules, ly_module_imp_clb user_clb, void *user_data,
        int has_get_schema)
{
    int ret = -1;
    struct lys_module *mod;
    uint32_t u;

    for (u = 0; modules[u].name; ++u) {
        /* skip import-only modules */
        if (!modules[u].implemented) {
            continue;
        }

        /* we can continue even if it fails */
        nc_ctx_load_module(session, modules[u].name, modules[u].revision, (const char **)modules[u].features, modules,
                user_clb, user_data, has_get_schema, &mod);

        if (!mod) {
            if (session->status != NC_STATUS_RUNNING) {
                /* something bad heppened, discard the session */
                ERR(session, "Invalid session, discarding.");
                goto cleanup;
            }

            /* all loading ways failed, the module will be ignored in the received data */
            WRN(session, "Failed to load module \"%s@%s\".", modules[u].name, modules[u].revision ?
                    modules[u].revision : "<latest>");
            session->flags |= NC_SESSION_CLIENT_NOT_STRICT;
        }
    }

    /* success */
    ret = 0;

cleanup:
    return ret;
}

/**
 * @brief Fill client context with ietf-netconf module.
 *
 * @param[in] session NC session with the context to modify.
 * @param[in] modules Server module info.
 * @param[in] user_clb User callback for retrieving specific modules.
 * @param[in] user_data User data for @p user_clb.
 * @param[in] has_get_schema Whether server supports get-schema RPC.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
nc_ctx_fill_ietf_netconf(struct nc_session *session, struct module_info *modules, ly_module_imp_clb user_clb,
        void *user_data, int has_get_schema)
{
    uint32_t u;
    const char **features = NULL;
    struct ly_in *in;
    struct lys_module *ietfnc;

    /* find supported features (capabilities) in ietf-netconf */
    for (u = 0; modules[u].name; ++u) {
        if (!strcmp(modules[u].name, "ietf-netconf")) {
            assert(modules[u].implemented);
            features = (const char **)modules[u].features;
            break;
        }
    }
    if (!modules[u].name) {
        ERR(session, "Base NETCONF module not supported by the server.");
        return -1;
    }

    ietfnc = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf");
    if (ietfnc) {
        /* make sure to enable all the features if already loaded */
        lys_set_implemented(ietfnc, features);
    } else {
        /* load the module */
        nc_ctx_load_module(session, "ietf-netconf", NULL, features, modules, user_clb, user_data, has_get_schema, &ietfnc);
        if (!ietfnc) {
            ly_in_new_memory(ietf_netconf_2013_09_29_yang, &in);
            lys_parse(session->ctx, in, LYS_IN_YANG, features, &ietfnc);
            ly_in_free(in, 0);
        }
    }
    if (!ietfnc) {
        ERR(session, "Loading base NETCONF module failed.");
        return -1;
    }

    return 0;
}

API int
nc_client_set_new_session_context_schema_mount(struct nc_session *session)
{
    int rc = 0, yanglib_support = 0, xpath_support = 0, nmda_support = 0;
    struct lyd_node *oper_data = NULL;
    const struct lys_module *mod;

    if (session->flags & NC_SESSION_SHAREDCTX) {
        /* context is already fully set up */
        goto cleanup;
    }

    /* check all useful capabilities */
    if (ly_ctx_get_module_implemented(session->ctx, "ietf-yang-library")) {
        yanglib_support = 1;
    }
    if ((mod = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf")) && !lys_feature_value(mod, "xpath")) {
        xpath_support = 1;
    }
    if (ly_ctx_get_module_implemented(session->ctx, "ietf-netconf-nmda")) {
        nmda_support = 1;
    }

    if (!yanglib_support) {
        ERR(session, "Module \"ietf-yang-library\" missing to retrieve schema-mount data.");
        rc = -1;
        goto cleanup;
    }

    /* get yang-library and schema-mounts operational data */
    if (xpath_support) {
        if ((rc = get_oper_data(session, nmda_support, "/ietf-yang-library:* | /ietf-yang-schema-mount:*", &oper_data))) {
            goto cleanup;
        }
    } else {
        if ((rc = get_oper_data(session, nmda_support,
                "<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\"/>"
                "<schema-mounts xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-schema-mount\"/>", &oper_data))) {
            goto cleanup;
        }
    }

    if (!oper_data || lyd_find_path(oper_data, "/ietf-yang-schema-mount:schema-mounts", 0, NULL)) {
        /* no schema-mounts operational data */
        goto cleanup;
    }

    /* validate the data for the parent reference prefixes to be resolved */
    if (lyd_validate_all(&oper_data, NULL, LYD_VALIDATE_PRESENT, NULL)) {
        ERR(session, "Invalid operational data received from the server (%s).", ly_err_last(LYD_CTX(oper_data))->msg);
        rc = -1;
        goto cleanup;
    }

    /* store the data in the session */
    lyd_free_siblings(session->opts.client.ext_data);
    session->opts.client.ext_data = oper_data;
    oper_data = NULL;

cleanup:
    lyd_free_siblings(oper_data);
    return rc;
}

int
nc_ctx_check_and_fill(struct nc_session *session)
{
    int i, get_schema_support = 0, yanglib_support = 0, xpath_support = 0, nmda_support = 0, ret = -1;
    ly_module_imp_clb old_clb = NULL;
    void *old_data = NULL;
    struct lys_module *mod = NULL;
    char *revision;
    struct module_info *server_modules = NULL, *sm = NULL;

    assert(session->opts.client.cpblts && session->ctx);

    if (client_opts.auto_context_fill_disabled) {
        VRB(session, "Context of the new session is left only with the default YANG modules.");
        return 0;
    }

    /* store the original user's callback, we will be switching between local search, get-schema and user callback */
    old_clb = ly_ctx_get_module_imp_clb(session->ctx, &old_data);

    /* switch off default searchpath to use only our callback integrating modifying searchpath algorithm to limit
     * modules only to those present on the server side */
    ly_ctx_set_options(session->ctx, LY_CTX_DISABLE_SEARCHDIRS);

    /* our callback is set later with appropriate data */
    ly_ctx_set_module_imp_clb(session->ctx, NULL, NULL);

    /* check if get-schema and yang-library is supported */
    for (i = 0; session->opts.client.cpblts[i]; ++i) {
        if (!strncmp(session->opts.client.cpblts[i], "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?", 52)) {
            get_schema_support = 1 + i;
        } else if (!strncmp(session->opts.client.cpblts[i], "urn:ietf:params:netconf:capability:yang-library:", 48)) {
            yanglib_support = 1 + i;
        } else if (!strncmp(session->opts.client.cpblts[i], "urn:ietf:params:netconf:capability:xpath:1.0", 44)) {
            xpath_support = 1 + i;
        }
        /* NMDA is YANG 1.1 module, which is not present in the capabilities */
    }
    VRB(session, "Capability for <get-schema> support%s found.", get_schema_support ? "" : " not");
    VRB(session, "Capability for yang-library support%s found.", yanglib_support ? "" : " not");
    VRB(session, "Capability for XPath filter support%s found.", xpath_support ? "" : " not");

    /* get information about server's modules from capabilities list until we will have yang-library */
    if (build_module_info_cpblts(session->opts.client.cpblts, &server_modules) || !server_modules) {
        ERR(session, "Unable to get server module information from the <hello>'s capabilities.");
        goto cleanup;
    }

    /* get-schema is supported, load local ietf-netconf-monitoring so we can create <get-schema> RPCs */
    if (get_schema_support && lys_parse_mem(session->ctx, ietf_netconf_monitoring_2010_10_04_yang, LYS_IN_YANG, NULL)) {
        WRN(session, "Loading NETCONF monitoring module failed, cannot use <get-schema>.");
        get_schema_support = 0;
    }

    /* load base model disregarding whether it's in capabilities (but NETCONF capabilities are used to enable features) */
    if (nc_ctx_fill_ietf_netconf(session, server_modules, old_clb, old_data, get_schema_support)) {
        goto cleanup;
    }

    /* get correct version of ietf-yang-library into context */
    if (yanglib_support) {
        /* use get-schema to get server's ietf-yang-library */
        revision = strstr(session->opts.client.cpblts[yanglib_support - 1], "revision=");
        if (!revision) {
            WRN(session, "Loading NETCONF ietf-yang-library module failed, missing revision in NETCONF <hello> message.");
            WRN(session, "Unable to automatically use <get-schema>.");
            yanglib_support = 0;
        } else {
            revision = strndup(&revision[9], 10);
            if (nc_ctx_load_module(session, "ietf-yang-library", revision, NULL, server_modules, old_clb, old_data,
                    get_schema_support, &mod)) {
                WRN(session, "Loading NETCONF ietf-yang-library module failed, unable to use it to learn all "
                        "the supported modules.");
                yanglib_support = 0;
            }
            if (strcmp(revision, "2019-01-04") >= 0) {
                /* we also need ietf-datastores to be implemented */
                if (nc_ctx_load_module(session, "ietf-datastores", NULL, NULL, server_modules, old_clb, old_data,
                        get_schema_support, &mod)) {
                    WRN(session, "Loading NETCONF ietf-datastores module failed, unable to use yang-library "
                            "to learn all the supported modules.");
                    yanglib_support = 0;
                }
            }
            free(revision);
        }
    }

    /* prepare structured information about server's modules */
    if (yanglib_support) {
        if (build_module_info_yl(session, 0, xpath_support, &sm)) {
            goto cleanup;
        } else if (!sm) {
            VRB(session, "Trying to use capabilities instead of ietf-yang-library data.");
        } else {
            /* prefer yang-library information, currently we have it from capabilities used for getting correct
             * yang-library module */
            free_module_info(server_modules);
            server_modules = sm;

            /* check for NMDA support */
            for (i = 0; server_modules[i].name; ++i) {
                if (!strcmp(server_modules[i].name, "ietf-netconf-nmda") && server_modules[i].implemented) {
                    nmda_support = 1;
                    break;
                }
            }

            /* ietf-netconf-nmda is needed to issue get-data */
            if (nmda_support && nc_ctx_load_module(session, "ietf-netconf-nmda", NULL, NULL, server_modules, old_clb,
                    old_data, get_schema_support, &mod)) {
                WRN(session, "Loading NMDA module failed, unable to use <get-data>.");
            }
        }
    }

    /* compile all modules at once to avoid invalid errors or warnings */
    ly_ctx_set_options(session->ctx, LY_CTX_EXPLICIT_COMPILE);

    /* fill the context */
    if (nc_ctx_fill(session, server_modules, old_clb, old_data, get_schema_support)) {
        goto cleanup;
    }

    /* compile it */
    if (ly_ctx_compile(session->ctx)) {
        goto cleanup;
    }

    /* set support for schema-mount, if possible (requires ietf-yang-library support) */
    if (yanglib_support && nc_client_set_new_session_context_schema_mount(session)) {
        goto cleanup;
    }

    /* success */
    ret = 0;

    if (session->flags & NC_SESSION_CLIENT_NOT_STRICT) {
        WRN(session, "Some modules failed to be loaded, any data from these modules (and any other unknown) will "
                "be ignored.");
    }

cleanup:
    free_module_info(server_modules);

    /* set user callback back */
    ly_ctx_set_module_imp_clb(session->ctx, old_clb, old_data);
    ly_ctx_unset_options(session->ctx, LY_CTX_DISABLE_SEARCHDIRS);
    ly_ctx_unset_options(session->ctx, LY_CTX_EXPLICIT_COMPILE);

    return ret;
}

API struct nc_session *
nc_connect_inout(int fdin, int fdout, struct ly_ctx *ctx)
{
    struct nc_session *session;

    if (fdin < 0) {
        ERRARG(NULL, "fdin");
        return NULL;
    } else if (fdout < 0) {
        ERRARG(NULL, "fdout");
        return NULL;
    }

    /* prepare session structure */
    session = nc_new_session(NC_CLIENT, 0);
    NC_CHECK_ERRMEM_RET(!session, NULL);
    session->status = NC_STATUS_STARTING;

    /* transport specific data */
    session->ti_type = NC_TI_FD;
    session->ti.fd.in = fdin;
    session->ti.fd.out = fdout;

    if (nc_client_session_new_ctx(session, ctx) != EXIT_SUCCESS) {
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

    return session;

fail:
    nc_session_free(session, NULL);
    return NULL;
}

API struct nc_session *
nc_connect_unix(const char *address, struct ly_ctx *ctx)
{
    struct nc_session *session = NULL;
    struct sockaddr_un sun;
    struct passwd *pw, pw_buf;
    char *username;
    int sock = -1;
    char *buf = NULL;
    size_t buf_size = 0;

    NC_CHECK_ARG_RET(NULL, address, NULL);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        ERR(NULL, "Failed to create socket (%s).", strerror(errno));
        goto fail;
    }

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", address);

    if (connect(sock, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
        ERR(NULL, "Cannot connect to sock server %s (%s)", address, strerror(errno));
        goto fail;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
        ERR(NULL, "fcntl failed (%s).", strerror(errno));
        goto fail;
    }

    /* prepare session structure */
    session = nc_new_session(NC_CLIENT, 0);
    NC_CHECK_ERRMEM_GOTO(!session, , fail);
    session->status = NC_STATUS_STARTING;

    /* transport specific data */
    session->ti_type = NC_TI_UNIX;
    session->ti.unixsock.sock = sock;
    sock = -1; /* do not close sock in fail label anymore */

    if (nc_client_session_new_ctx(session, ctx) != EXIT_SUCCESS) {
        goto fail;
    }
    ctx = session->ctx;

    session->path = strdup(address);

    pw = nc_getpw(geteuid(), NULL, &pw_buf, &buf, &buf_size);
    if (!pw) {
        ERR(NULL, "Failed to find username for UID %u.", (unsigned int)geteuid());
        goto fail;
    }
    username = strdup(pw->pw_name);
    free(buf);
    NC_CHECK_ERRMEM_GOTO(!username, , fail);
    session->username = username;

    /* NETCONF handshake */
    if (nc_handshake_io(session) != NC_MSG_HELLO) {
        goto fail;
    }
    session->status = NC_STATUS_RUNNING;

    if (nc_ctx_check_and_fill(session) == -1) {
        goto fail;
    }

    return session;

fail:
    nc_session_free(session, NULL);
    if (sock >= 0) {
        close(sock);
    }
    return NULL;
}

/**
 * @brief Convert socket IP address to string.
 *
 * @param[in] saddr Sockaddr to convert.
 * @param[out] str_ip String IP address.
 * @param[out] port Optional port.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
nc_saddr2str(const struct sockaddr *saddr, char **str_ip, uint16_t *port)
{
    void *addr;
    socklen_t str_len;

    assert((saddr->sa_family == AF_INET) || (saddr->sa_family == AF_INET6));

    str_len = (saddr->sa_family == AF_INET) ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    *str_ip = malloc(str_len);
    NC_CHECK_ERRMEM_RET(!(*str_ip), -1);

    if (saddr->sa_family == AF_INET) {
        addr = &((struct sockaddr_in *)saddr)->sin_addr;
        if (port) {
            *port = ntohs(((struct sockaddr_in *)saddr)->sin_port);
        }
    } else {
        addr = &((struct sockaddr_in6 *)saddr)->sin6_addr;
        if (port) {
            *port = ntohs(((struct sockaddr_in6 *)saddr)->sin6_port);
        }
    }
    if (!inet_ntop(saddr->sa_family, addr, *str_ip, str_len)) {
        ERR(NULL, "Converting host to IP address failed (%s).", strerror(errno));
        free(*str_ip);
        return -1;
    }

    return 0;
}

/**
 * @brief Try to connect a socket, optionally a pending one from a previous attempt.
 *
 * @param[in] timeout_ms Timeout in ms to wait for the connection to be fully established, -1 to block.
 * @param[in,out] sock_pending Optional previously created socked that was not fully connected yet. If provided and
 * connected, is set to -1.
 * @param[in] res Addrinfo resource to use when creating a new socket.
 * @param[in] ka Keepalives to set.
 * @return Connected socket or -1 on error.
 */
static int
sock_connect(const char *src_addr, uint16_t src_port, int timeout_ms, int *sock_pending, struct addrinfo *res,
        const struct nc_keepalives *ka)
{
    int flags, ret, error, opt;
    int sock = -1;
    struct pollfd fds = {0};
    socklen_t len = sizeof(int);
    uint16_t port;
    char *str;

    if (sock_pending && (*sock_pending != -1)) {
        VRB(NULL, "Trying to connect the pending socket %d.", *sock_pending);
        sock = *sock_pending;
    } else {
        assert(res);
        if (nc_saddr2str(res->ai_addr, &str, &port)) {
            return -1;
        }
        VRB(NULL, "Trying to connect via %s to %s:%u.", (res->ai_family == AF_INET6) ? "IPv6" : "IPv4", str, port);
        free(str);

        /* connect to a server */
        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock == -1) {
            ERR(NULL, "Socket could not be created (%s).", strerror(errno));
            return -1;
        }
        /* make the socket non-blocking */
        if (((flags = fcntl(sock, F_GETFL)) == -1) || (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)) {
            ERR(NULL, "fcntl() failed (%s).", strerror(errno));
            goto cleanup;
        }

        /* bind the socket to a specific address/port to make the connection from (CH only) */
        if (src_addr || src_port) {
            /* enable address reuse, so that we're able to bind this address again when the CH conn is dropped and retried */
            opt = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) == -1) {
                ERR(NULL, "Could not set SO_REUSEADDR socket option (%s).", strerror(errno));
                goto cleanup;
            }

            if (nc_sock_bind_inet(sock, src_addr, src_port, (res->ai_family == AF_INET) ? 1 : 0)) {
                goto cleanup;
            }
        }

        /* non-blocking connect! */
        if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
            if (errno != EINPROGRESS) {
                /* network connection failed, try another resource */
                ERR(NULL, "connect() failed (%s).", strerror(errno));
                goto cleanup;
            }
        }
    }

    fds.fd = sock;
    fds.events = POLLOUT;

    /* wait until we can write data to the socket */
    ret = poll(&fds, 1, timeout_ms);
    if (ret == -1) {
        /* error */
        ERR(NULL, "poll() failed (%s).", strerror(errno));
        goto cleanup;
    } else if (ret == 0) {
        /* there was a timeout */
        VRB(NULL, "Timed out after %d ms (%s).", timeout_ms, strerror(errno));
        if (sock_pending) {
            /* no sock-close, we'll try it again */
            *sock_pending = sock;
        } else {
            close(sock);
        }
        return -1;
    }

    /* check the usability of the socket */
    error = 0;
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        ERR(NULL, "getsockopt() failed (%s).", strerror(errno));
        goto cleanup;
    }
    if (error) {
        /* network connection failed, try another resource */
        VRB(NULL, "getsockopt() error (%s).", strerror(error));
        errno = error;
        goto cleanup;
    }

    /* configure keepalives */
    if (nc_sock_configure_ka(sock, ka)) {
        goto cleanup;
    }

    /* connected */
    if (sock_pending) {
        *sock_pending = -1;
    }
    return sock;

cleanup:
    if (sock_pending) {
        *sock_pending = -1;
    }
    close(sock);
    return -1;
}

int
nc_sock_connect(const char *src_addr, uint16_t src_port, const char *dst_addr, uint16_t dst_port, int timeout_ms,
        struct nc_keepalives *ka, int *sock_pending, char **ip_host)
{
    int i, opt;
    int sock = sock_pending ? *sock_pending : -1;
    struct addrinfo hints, *res_list = NULL, *res;
    char dst_port_str[6]; /* length of string representation of short int */
    struct sockaddr_storage saddr;
    socklen_t addr_len = sizeof saddr;

    *ip_host = NULL;

    DBG(NULL, "nc_sock_connect(%s, %u, %s, %u, %d, %d)", src_addr, src_port, dst_addr, dst_port, timeout_ms, sock);

    /* no pending socket */
    if (sock == -1) {
        /* connect to a server */
        snprintf(dst_port_str, 6, "%u", dst_port);
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        i = getaddrinfo(dst_addr, dst_port_str, &hints, &res_list);
        if (i != 0) {
            ERR(NULL, "Unable to translate the host address (%s).", gai_strerror(i));
            goto error;
        }

        for (res = res_list; res != NULL; res = res->ai_next) {
            sock = sock_connect(src_addr, src_port, timeout_ms, sock_pending, res, ka);
            if (sock == -1) {
                if (!sock_pending || (*sock_pending == -1)) {
                    /* try the next resource */
                    continue;
                } else {
                    /* timeout, keep pending socket */
                    break;
                }
            }

            if (res->ai_family == AF_INET) {
                VRB(NULL, "Successfully connected to %s:%s over IPv4.", dst_addr, dst_port_str);
            } else {
                VRB(NULL, "Successfully connected to [%s]:%s over IPv6.", dst_addr, dst_port_str);
            }

            opt = 1;
            if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof opt) == -1) {
                ERR(NULL, "Could not set TCP_NODELAY socket option (%s).", strerror(errno));
                goto error;
            }

            if (nc_saddr2str(res->ai_addr, ip_host, NULL)) {
                goto error;
            }
            break;
        }
        freeaddrinfo(res_list);

    } else {
        /* try to get a connection with the pending socket */
        assert(sock_pending);
        sock = sock_connect(src_addr, src_port, timeout_ms, sock_pending, NULL, ka);

        if (sock > 0) {
            if (getpeername(sock, (struct sockaddr *)&saddr, &addr_len)) {
                ERR(NULL, "getpeername failed (%s).", strerror(errno));
                goto error;
            }

            if (nc_saddr2str((struct sockaddr *)&saddr, ip_host, NULL)) {
                goto error;
            }
        }
    }

    return sock;

error:
    if (res_list) {
        freeaddrinfo(res_list);
    }
    if (sock != -1) {
        close(sock);
    }
    if (sock_pending) {
        *sock_pending = -1;
    }
    return -1;
}

#ifdef NC_ENABLED_SSH_TLS

int
nc_client_ch_add_bind_listen(const char *address, uint16_t port, const char *hostname, NC_TRANSPORT_IMPL ti)
{
    int sock;

    NC_CHECK_ARG_RET(NULL, address, port, -1);

    sock = nc_sock_listen_inet(address, port);
    if (sock == -1) {
        return -1;
    }

    ++client_opts.ch_bind_count;
    client_opts.ch_binds = nc_realloc(client_opts.ch_binds, client_opts.ch_bind_count * sizeof *client_opts.ch_binds);
    if (!client_opts.ch_binds) {
        ERRMEM;
        close(sock);
        return -1;
    }

    client_opts.ch_binds_aux = nc_realloc(client_opts.ch_binds_aux, client_opts.ch_bind_count * sizeof *client_opts.ch_binds_aux);
    if (!client_opts.ch_binds_aux) {
        ERRMEM;
        close(sock);
        return -1;
    }
    client_opts.ch_binds_aux[client_opts.ch_bind_count - 1].ti = ti;
    client_opts.ch_binds_aux[client_opts.ch_bind_count - 1].hostname = hostname ? strdup(hostname) : NULL;

    client_opts.ch_binds[client_opts.ch_bind_count - 1].address = strdup(address);
    client_opts.ch_binds[client_opts.ch_bind_count - 1].port = port;
    client_opts.ch_binds[client_opts.ch_bind_count - 1].sock = sock;
    client_opts.ch_binds[client_opts.ch_bind_count - 1].pollin = 0;

    return 0;
}

int
nc_client_ch_del_bind(const char *address, uint16_t port, NC_TRANSPORT_IMPL ti)
{
    uint32_t i;
    int ret = -1;

    if (!address && !port && !ti) {
        for (i = 0; i < client_opts.ch_bind_count; ++i) {
            close(client_opts.ch_binds[i].sock);
            free(client_opts.ch_binds[i].address);

            free(client_opts.ch_binds_aux[i].hostname);

            ret = 0;
        }
        client_opts.ch_bind_count = 0;

        free(client_opts.ch_binds);
        client_opts.ch_binds = NULL;

        free(client_opts.ch_binds_aux);
        client_opts.ch_binds_aux = NULL;
    } else {
        for (i = 0; i < client_opts.ch_bind_count; ++i) {
            if ((!address || !strcmp(client_opts.ch_binds[i].address, address)) &&
                    (!port || (client_opts.ch_binds[i].port == port)) &&
                    (!ti || (client_opts.ch_binds_aux[i].ti == ti))) {
                close(client_opts.ch_binds[i].sock);
                free(client_opts.ch_binds[i].address);

                --client_opts.ch_bind_count;
                if (!client_opts.ch_bind_count) {
                    free(client_opts.ch_binds);
                    client_opts.ch_binds = NULL;

                    free(client_opts.ch_binds_aux);
                    client_opts.ch_binds_aux = NULL;
                } else if (i < client_opts.ch_bind_count) {
                    memcpy(&client_opts.ch_binds[i], &client_opts.ch_binds[client_opts.ch_bind_count],
                            sizeof *client_opts.ch_binds);

                    memcpy(&client_opts.ch_binds_aux[i], &client_opts.ch_binds_aux[client_opts.ch_bind_count],
                            sizeof *client_opts.ch_binds_aux);
                }

                ret = 0;
            }
        }
    }

    return ret;
}

API int
nc_accept_callhome(int timeout, struct ly_ctx *ctx, struct nc_session **session)
{
    int ret, sock;
    char *host = NULL;
    uint16_t port, idx;

    NC_CHECK_ARG_RET(NULL, session, -1);

    if (!client_opts.ch_binds) {
        ERR(NULL, "Call-Home binds not set.");
        return -1;
    }

    ret = nc_sock_accept_binds(client_opts.ch_binds, client_opts.ch_bind_count, &client_opts.ch_bind_lock, timeout,
            &host, &port, &idx, &sock);
    if (ret < 1) {
        free(host);
        return ret;
    }

    /* configure keepalives */
    if (nc_sock_configure_ka(sock, &client_opts.ka)) {
        free(host);
        close(sock);
        return -1;
    }

    if (client_opts.ch_binds_aux[idx].ti == NC_TI_SSH) {
        *session = nc_accept_callhome_ssh_sock(sock, host, port, ctx, NC_TRANSPORT_TIMEOUT);
    } else if (client_opts.ch_binds_aux[idx].ti == NC_TI_TLS) {
        *session = nc_accept_callhome_tls_sock(sock, host, port, ctx, NC_TRANSPORT_TIMEOUT,
                client_opts.ch_binds_aux[idx].hostname);
    } else {
        close(sock);
        *session = NULL;
    }

    free(host);

    if (!(*session)) {
        return -1;
    }

    return 1;
}

#endif /* NC_ENABLED_SSH_TLS */

API const char * const *
nc_session_get_cpblts(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, NULL);

    return (const char * const *)session->opts.client.cpblts;
}

API const char *
nc_session_cpblt(const struct nc_session *session, const char *capab)
{
    int i, len;

    NC_CHECK_ARG_RET(session, session, capab, NULL);

    len = strlen(capab);
    for (i = 0; session->opts.client.cpblts[i]; ++i) {
        if (!strncmp(session->opts.client.cpblts[i], capab, len)) {
            return session->opts.client.cpblts[i];
        }
    }

    return NULL;
}

API int
nc_session_ntf_thread_running(const struct nc_session *session)
{
    NC_CHECK_ARG_RET(session, session, 0);

    if (session->side != NC_CLIENT) {
        ERRARG(NULL, "session");
        return 0;
    }

    return ATOMIC_LOAD_RELAXED(session->opts.client.ntf_thread_running);
}

API int
nc_client_init(void)
{
    int r;

    if ((r = pthread_mutex_init(&client_opts.ch_bind_lock, NULL))) {
        ERR(NULL, "%s: failed to init bind lock(%s).", __func__, strerror(r));
        return -1;
    }

#ifdef NC_ENABLED_SSH_TLS
    if (ssh_init()) {
        ERR(NULL, "%s: failed to init libssh.", __func__);
        return -1;
    }
#endif

    return 0;
}

API void
nc_client_destroy(void)
{
    pthread_mutex_destroy(&client_opts.ch_bind_lock);
    nc_client_set_schema_searchpath(NULL);
#ifdef NC_ENABLED_SSH_TLS
    nc_client_ch_del_bind(NULL, 0, 0);
    nc_client_ssh_destroy_opts();
    nc_client_tls_destroy_opts();
    ssh_finalize();
#endif /* NC_ENABLED_SSH_TLS */
}

static NC_MSG_TYPE
recv_reply_check_msgid(struct nc_session *session, const struct lyd_node *envp, uint64_t msgid)
{
    char *ptr;
    struct lyd_attr *attr;
    uint64_t cur_msgid;

    assert(envp && !envp->schema);

    /* find the message-id attribute */
    LY_LIST_FOR(((struct lyd_node_opaq *)envp)->attr, attr) {
        if (!strcmp(attr->name.name, "message-id")) {
            break;
        }
    }

    if (!attr) {
        ERR(session, "Received a <rpc-reply> without a message-id.");
        return NC_MSG_REPLY_ERR_MSGID;
    }

    cur_msgid = strtoul(attr->value, &ptr, 10);
    if (cur_msgid != msgid) {
        ERR(session, "Received a <rpc-reply> with an unexpected message-id %" PRIu64 " (expected %" PRIu64 ").",
                cur_msgid, msgid);
        return NC_MSG_REPLY_ERR_MSGID;
    }

    return NC_MSG_REPLY;
}

/**
 * @brief Used to roughly estimate the type of the message, does not actually parse or verify it.
 *
 * @param[in] session NETCONF session used to send error messages.
 * @param[in] msg Message to check for type.
 * @return NC_MSG_REPLY If format roughly matches a rpc-reply;
 * @return NC_MSG_NOTIF If format roughly matches a notification;
 * @return NC_MSG_ERROR If format is malformed or unrecognized.
 */
static NC_MSG_TYPE
get_msg_type(struct nc_session *session, struct ly_in *msg)
{
    const char *str, *end;

    str = ly_in_memory(msg, NULL);

    while (*str) {
        /* Skip whitespaces */
        while (isspace(*str)) {
            str++;
        }

        if (*str == '<') {
            str++;
            if (!strncmp(str, "!--", 3)) {
                /* Skip comments */
                end = "-->";
                str = strstr(str, end);
            } else if (!strncmp(str, "?xml", 4)) {
                /* Skip xml declaration */
                end = "?>";
                str = strstr(str, end);
            } else if (!strncmp(str, "rpc-reply", 9)) {
                return NC_MSG_REPLY;
            } else if (!strncmp(str, "notification", 12)) {
                return NC_MSG_NOTIF;
            } else {
                ERR(session, "Unknown xml element '%.10s'.", str);
                return NC_MSG_ERROR;
            }
            if (!str) {
                /* No matching ending tag found */
                ERR(session, "No matching ending tag '%s' found in xml message.", end);
                return NC_MSG_ERROR;
            }
            str += strlen(end);
        } else {
            /* Not a valid xml */
            ERR(session, "Unexpected character '%c' in xml message.", *str);
            return NC_MSG_ERROR;
        }
    }

    /* Unexpected end of message */
    ERR(session, "Unexpected end of xml message.");
    return NC_MSG_ERROR;
}

/**
 * @brief Function to receive either replies or notifications.
 *
 * @param[in] session NETCONF session from which this function receives messages.
 * @param[in] timeout Timeout for reading in milliseconds. Use negative value for infinite.
 * @param[in] expected Type of the message the caller desired.
 * @param[out] message If receiving a message succeeded this is the message, NULL otherwise.
 * @return NC_MSG_REPLY If a rpc-reply was received;
 * @return NC_MSG_NOTIF If a notification was received;
 * @return NC_MSG_ERROR If any error occurred;
 * @return NC_MSG_WOULDBLOCK If the timeout was reached.
 */
static NC_MSG_TYPE
recv_msg(struct nc_session *session, int timeout, NC_MSG_TYPE expected, struct ly_in **message)
{
    struct nc_msg_cont **cont_ptr;
    struct ly_in *msg = NULL;
    struct nc_msg_cont *cont, *prev;
    NC_MSG_TYPE ret = NC_MSG_ERROR;
    int r;

    *message = NULL;

    /* MSGS LOCK */
    r = nc_session_client_msgs_lock(session, &timeout, __func__);
    if (!r) {
        ret = NC_MSG_WOULDBLOCK;
        goto cleanup;
    } else if (r == -1) {
        ret = NC_MSG_ERROR;
        goto cleanup;
    }

    /* Find the expected message in the buffer */
    prev = NULL;
    for (cont = session->opts.client.msgs; cont && (cont->type != expected); cont = cont->next) {
        prev = cont;
    }

    if (cont) {
        /* Remove found message from buffer */
        if (prev) {
            prev->next = cont->next;
        } else {
            session->opts.client.msgs = cont->next;
        }

        /* Use the buffer message */
        ret = cont->type;
        msg = cont->msg;
        free(cont);
        goto cleanup_unlock;
    }

    /* Read a message from the wire */
    r = nc_read_msg_poll_io(session, timeout, &msg);
    if (!r) {
        ret = NC_MSG_WOULDBLOCK;
        goto cleanup_unlock;
    } else if (r == -1) {
        ret = NC_MSG_ERROR;
        goto cleanup_unlock;
    }

    /* Basic check to determine message type */
    ret = get_msg_type(session, msg);
    if (ret == NC_MSG_ERROR) {
        goto cleanup_unlock;
    }

    /* If received a message of different type store it in the buffer */
    if (ret != expected) {
        cont_ptr = &session->opts.client.msgs;
        while (*cont_ptr) {
            cont_ptr = &((*cont_ptr)->next);
        }
        *cont_ptr = malloc(sizeof **cont_ptr);
        NC_CHECK_ERRMEM_GOTO(!*cont_ptr, ret = NC_MSG_ERROR, cleanup_unlock);
        (*cont_ptr)->msg = msg;
        msg = NULL;
        (*cont_ptr)->type = ret;
        (*cont_ptr)->next = NULL;
    }

cleanup_unlock:
    /* MSGS UNLOCK */
    nc_session_client_msgs_unlock(session, __func__);

cleanup:
    if (ret == expected) {
        *message = msg;
    } else {
        ly_in_free(msg, 1);
    }
    return ret;
}

static NC_MSG_TYPE
recv_reply(struct nc_session *session, int timeout, struct lyd_node *op, uint64_t msgid, struct lyd_node **envp)
{
    LY_ERR lyrc;
    struct ly_in *msg = NULL;
    NC_MSG_TYPE ret = NC_MSG_ERROR;
    uint32_t temp_lo = LY_LOSTORE, *prev_lo;

    assert(op && (op->schema->nodetype & (LYS_RPC | LYS_ACTION)));

    *envp = NULL;

    /* Receive messages until a rpc-reply is found or a timeout or error reached */
    ret = recv_msg(session, timeout, NC_MSG_REPLY, &msg);
    if (ret != NC_MSG_REPLY) {
        goto cleanup;
    }

    /* parse */
    prev_lo = ly_temp_log_options(&temp_lo);
    lyrc = lyd_parse_op(NULL, op, msg, LYD_XML, LYD_TYPE_REPLY_NETCONF, envp, NULL);
    ly_temp_log_options(prev_lo);

    if (*envp) {
        /* if the envelopes were parsed, check the message-id, even on error */
        ret = recv_reply_check_msgid(session, *envp, msgid);
        goto cleanup;
    }

    if (lyrc) {
        /* parsing error */
        ERR(session, "Received an invalid message (%s).", ly_err_last(LYD_CTX(op))->msg);
        lyd_free_tree(*envp);
        *envp = NULL;
        ret = NC_MSG_ERROR;
        goto cleanup;
    }

cleanup:
    ly_in_free(msg, 1);
    return ret;
}

static int
recv_reply_dup_rpc(struct nc_session *session, struct nc_rpc *rpc, struct lyd_node **op)
{
    LY_ERR lyrc = LY_SUCCESS;
    struct nc_rpc_act_generic *rpc_gen;
    struct ly_in *in;
    struct lyd_node *tree, *op2;
    const struct lys_module *mod;
    const char *module_name = NULL, *rpc_name = NULL, *module_check = NULL;

    switch (rpc->type) {
    case NC_RPC_ACT_GENERIC:
        rpc_gen = (struct nc_rpc_act_generic *)rpc;
        if (rpc_gen->has_data) {
            tree = rpc_gen->content.data;

            /* find the operation node */
            lyrc = LY_EINVAL;
            LYD_TREE_DFS_BEGIN(tree, op2) {
                if (op2->schema->nodetype & (LYS_RPC | LYS_ACTION)) {
                    lyrc = lyd_dup_single(op2, NULL, 0, op);
                    break;
                }
                LYD_TREE_DFS_END(tree, op2);
            }
        } else {
            ly_in_new_memory(rpc_gen->content.xml_str, &in);
            lyrc = lyd_parse_op(session->ctx, NULL, in, LYD_XML, LYD_TYPE_RPC_YANG, &tree, &op2);
            ly_in_free(in, 0);
            if (lyrc) {
                lyd_free_tree(tree);
                return -1;
            }

            /* we want just the operation node */
            lyrc = lyd_dup_single(op2, NULL, 0, op);

            lyd_free_tree(tree);
        }
        break;
    case NC_RPC_GETCONFIG:
        module_name = "ietf-netconf";
        rpc_name = "get-config";
        break;
    case NC_RPC_EDIT:
        module_name = "ietf-netconf";
        rpc_name = "edit-config";
        break;
    case NC_RPC_COPY:
        module_name = "ietf-netconf";
        rpc_name = "copy-config";
        break;
    case NC_RPC_DELETE:
        module_name = "ietf-netconf";
        rpc_name = "delete-config";
        break;
    case NC_RPC_LOCK:
        module_name = "ietf-netconf";
        rpc_name = "lock";
        break;
    case NC_RPC_UNLOCK:
        module_name = "ietf-netconf";
        rpc_name = "unlock";
        break;
    case NC_RPC_GET:
        module_name = "ietf-netconf";
        rpc_name = "get";
        break;
    case NC_RPC_KILL:
        module_name = "ietf-netconf";
        rpc_name = "kill-session";
        break;
    case NC_RPC_COMMIT:
        module_name = "ietf-netconf";
        rpc_name = "commit";
        break;
    case NC_RPC_DISCARD:
        module_name = "ietf-netconf";
        rpc_name = "discard-changes";
        break;
    case NC_RPC_CANCEL:
        module_name = "ietf-netconf";
        rpc_name = "cancel-commit";
        break;
    case NC_RPC_VALIDATE:
        module_name = "ietf-netconf";
        rpc_name = "validate";
        break;
    case NC_RPC_GETSCHEMA:
        module_name = "ietf-netconf-monitoring";
        rpc_name = "get-schema";
        break;
    case NC_RPC_SUBSCRIBE:
        module_name = "notifications";
        rpc_name = "create-subscription";
        break;
    case NC_RPC_GETDATA:
        module_name = "ietf-netconf-nmda";
        rpc_name = "get-data";
        break;
    case NC_RPC_EDITDATA:
        module_name = "ietf-netconf-nmda";
        rpc_name = "edit-data";
        break;
    case NC_RPC_ESTABLISHSUB:
        module_name = "ietf-subscribed-notifications";
        rpc_name = "establish-subscription";
        break;
    case NC_RPC_MODIFYSUB:
        module_name = "ietf-subscribed-notifications";
        rpc_name = "modify-subscription";
        break;
    case NC_RPC_DELETESUB:
        module_name = "ietf-subscribed-notifications";
        rpc_name = "delete-subscription";
        break;
    case NC_RPC_KILLSUB:
        module_name = "ietf-subscribed-notifications";
        rpc_name = "kill-subscription";
        break;
    case NC_RPC_ESTABLISHPUSH:
        module_name = "ietf-subscribed-notifications";
        rpc_name = "establish-subscription";
        module_check = "ietf-yang-push";
        break;
    case NC_RPC_MODIFYPUSH:
        module_name = "ietf-subscribed-notifications";
        rpc_name = "modify-subscription";
        module_check = "ietf-yang-push";
        break;
    case NC_RPC_RESYNCSUB:
        module_name = "ietf-yang-push";
        rpc_name = "resync-subscription";
        break;
    case NC_RPC_UNKNOWN:
        lyrc = LY_EINT;
        break;
    }

    if (module_name && rpc_name) {
        mod = ly_ctx_get_module_implemented(session->ctx, module_name);
        if (!mod) {
            ERR(session, "Missing \"%s\" module in the context.", module_name);
            return -1;
        }

        /* create the operation node */
        lyrc = lyd_new_inner(NULL, mod, rpc_name, 0, op);
    }
    if (module_check) {
        if (!ly_ctx_get_module_implemented(session->ctx, module_check)) {
            ERR(session, "Missing \"%s\" module in the context.", module_check);
            return -1;
        }
    }

    if (lyrc) {
        return -1;
    }
    return 0;
}

API NC_MSG_TYPE
nc_recv_reply(struct nc_session *session, struct nc_rpc *rpc, uint64_t msgid, int timeout, struct lyd_node **envp,
        struct lyd_node **op)
{
    NC_MSG_TYPE ret;

    NC_CHECK_ARG_RET(session, session, rpc, envp, op, NC_MSG_ERROR);

    if ((session->status != NC_STATUS_RUNNING) || (session->side != NC_CLIENT)) {
        ERR(session, "Invalid session to receive RPC replies.");
        return NC_MSG_ERROR;
    }

    /* get a duplicate of the RPC node to append reply to */
    if (recv_reply_dup_rpc(session, rpc, op)) {
        return NC_MSG_ERROR;
    }

    /* receive a reply */
    ret = recv_reply(session, timeout, *op, msgid, envp);

    /* do not return the RPC copy on error or if the reply includes no data */
    if (((ret != NC_MSG_REPLY) && (ret != NC_MSG_REPLY_ERR_MSGID)) || !lyd_child(*op)) {
        lyd_free_tree(*op);
        *op = NULL;
    }
    return ret;
}

static NC_MSG_TYPE
recv_notif(struct nc_session *session, int timeout, struct lyd_node **envp, struct lyd_node **op)
{
    LY_ERR lyrc;
    struct ly_in *msg = NULL;
    NC_MSG_TYPE ret = NC_MSG_ERROR;

    *op = NULL;
    *envp = NULL;

    /* Receive messages until a notification is found or a timeout or error reached */
    ret = recv_msg(session, timeout, NC_MSG_NOTIF, &msg);
    if (ret != NC_MSG_NOTIF) {
        goto cleanup;
    }

    /* Parse */
    lyrc = lyd_parse_op(session->ctx, NULL, msg, LYD_XML, LYD_TYPE_NOTIF_NETCONF, envp, op);
    if (!lyrc) {
        goto cleanup;
    } else {
        ERR(session, "Received an invalid message (%s).", ly_err_last(session->ctx)->msg);
        lyd_free_tree(*envp);
        *envp = NULL;
        ret = NC_MSG_ERROR;
        goto cleanup;
    }

cleanup:
    ly_in_free(msg, 1);
    return ret;
}

API NC_MSG_TYPE
nc_recv_notif(struct nc_session *session, int timeout, struct lyd_node **envp, struct lyd_node **op)
{
    NC_CHECK_ARG_RET(session, session, envp, op, NC_MSG_ERROR);

    if ((session->status != NC_STATUS_RUNNING) || (session->side != NC_CLIENT)) {
        ERR(session, "Invalid session to receive Notifications.");
        return NC_MSG_ERROR;
    }

    /* receive a notification */
    return recv_notif(session, timeout, envp, op);
}

static void *
nc_recv_notif_thread(void *arg)
{
    struct nc_ntf_thread_arg *ntarg;
    struct nc_session *session;
    nc_notif_dispatch_clb notif_clb;
    void *user_data;

    void (*free_data)(void *);
    struct lyd_node *envp, *op;
    NC_MSG_TYPE msgtype;

    /* detach ourselves */
    pthread_detach(pthread_self());

    ntarg = (struct nc_ntf_thread_arg *)arg;
    session = ntarg->session;
    notif_clb = ntarg->notif_clb;
    user_data = ntarg->user_data;
    free_data = ntarg->free_data;
    free(ntarg);

    while (ATOMIC_LOAD_RELAXED(session->opts.client.ntf_thread_running)) {
        msgtype = nc_recv_notif(session, NC_CLIENT_NOTIF_THREAD_SLEEP / 1000, &envp, &op);
        if (msgtype == NC_MSG_NOTIF) {
            notif_clb(session, envp, op, user_data);
            if (!strcmp(op->schema->name, "notificationComplete") && !strcmp(op->schema->module->name, "nc-notifications")) {
                lyd_free_all(envp);
                lyd_free_all(op);
                break;
            }
            lyd_free_all(envp);
            lyd_free_all(op);
        } else if ((msgtype == NC_MSG_ERROR) && (session->status != NC_STATUS_RUNNING)) {
            /* quit this thread once the session is broken */
            break;
        }

        usleep(NC_CLIENT_NOTIF_THREAD_SLEEP);
    }

    VRB(session, "Notification thread exit.");
    ATOMIC_DEC_RELAXED(session->opts.client.ntf_thread_count);
    if (free_data) {
        free_data(user_data);
    }

    return NULL;
}

API int
nc_recv_notif_dispatch(struct nc_session *session, nc_notif_dispatch_clb notif_clb)
{
    return nc_recv_notif_dispatch_data(session, notif_clb, NULL, NULL);
}

API int
nc_recv_notif_dispatch_data(struct nc_session *session, nc_notif_dispatch_clb notif_clb, void *user_data,
        void (*free_data)(void *))
{
    struct nc_ntf_thread_arg *ntarg;
    pthread_t tid;
    int ret;

    NC_CHECK_ARG_RET(session, session, notif_clb, -1);

    if ((session->status != NC_STATUS_RUNNING) || (session->side != NC_CLIENT)) {
        ERR(session, "Invalid session to receive Notifications.");
        return -1;
    }

    ntarg = malloc(sizeof *ntarg);
    NC_CHECK_ERRMEM_RET(!ntarg, -1);

    ntarg->session = session;
    ntarg->notif_clb = notif_clb;
    ntarg->user_data = user_data;
    ntarg->free_data = free_data;
    ATOMIC_INC_RELAXED(session->opts.client.ntf_thread_count);

    /* just so that nc_recv_notif_thread() does not immediately exit */
    ATOMIC_STORE_RELAXED(session->opts.client.ntf_thread_running, 1);

    ret = pthread_create(&tid, NULL, nc_recv_notif_thread, ntarg);
    if (ret) {
        ERR(session, "Failed to create a new thread (%s).", strerror(errno));
        free(ntarg);
        if (ATOMIC_DEC_RELAXED(session->opts.client.ntf_thread_count) == 1) {
            ATOMIC_STORE_RELAXED(session->opts.client.ntf_thread_running, 0);
        }
        return -1;
    }

    return 0;
}

static const char *
nc_wd2str(NC_WD_MODE wd)
{
    switch (wd) {
    case NC_WD_ALL:
        return "report-all";
    case NC_WD_ALL_TAG:
        return "report-all-tagged";
    case NC_WD_TRIM:
        return "trim";
    case NC_WD_EXPLICIT:
        return "explicit";
    default:
        break;
    }

    return NULL;
}

API NC_MSG_TYPE
nc_send_rpc(struct nc_session *session, struct nc_rpc *rpc, int timeout, uint64_t *msgid)
{
    NC_MSG_TYPE r;
    int dofree = 1;
    struct ly_in *in;
    struct nc_rpc_act_generic *rpc_gen;
    struct nc_rpc_getconfig *rpc_gc;
    struct nc_rpc_edit *rpc_e;
    struct nc_rpc_copy *rpc_cp;
    struct nc_rpc_delete *rpc_del;
    struct nc_rpc_lock *rpc_lock;
    struct nc_rpc_get *rpc_g;
    struct nc_rpc_kill *rpc_k;
    struct nc_rpc_commit *rpc_com;
    struct nc_rpc_cancel *rpc_can;
    struct nc_rpc_validate *rpc_val;
    struct nc_rpc_getschema *rpc_gs;
    struct nc_rpc_subscribe *rpc_sub;
    struct nc_rpc_getdata *rpc_getd;
    struct nc_rpc_editdata *rpc_editd;
    struct nc_rpc_establishsub *rpc_estsub;
    struct nc_rpc_modifysub *rpc_modsub;
    struct nc_rpc_deletesub *rpc_delsub;
    struct nc_rpc_killsub *rpc_killsub;
    struct nc_rpc_establishpush *rpc_estpush;
    struct nc_rpc_modifypush *rpc_modpush;
    struct nc_rpc_resyncsub *rpc_resyncsub;
    struct lyd_node *data = NULL, *node, *cont;
    const struct lys_module *mod = NULL, *mod2 = NULL, *ietfncwd;
    LY_ERR lyrc = 0;
    int i;
    char str[11];
    uint64_t cur_msgid;

    NC_CHECK_ARG_RET(session, session, rpc, msgid, NC_MSG_ERROR);

    if ((session->status != NC_STATUS_RUNNING) || (session->side != NC_CLIENT)) {
        ERR(session, "Invalid session to send RPCs.");
        return NC_MSG_ERROR;
    }

    switch (rpc->type) {
    case NC_RPC_ACT_GENERIC:
        /* checked when parsing */
        break;
    case NC_RPC_GETCONFIG:
    case NC_RPC_EDIT:
    case NC_RPC_COPY:
    case NC_RPC_DELETE:
    case NC_RPC_LOCK:
    case NC_RPC_UNLOCK:
    case NC_RPC_GET:
    case NC_RPC_KILL:
    case NC_RPC_COMMIT:
    case NC_RPC_DISCARD:
    case NC_RPC_CANCEL:
    case NC_RPC_VALIDATE:
        mod = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf");
        if (!mod) {
            ERR(session, "Missing \"ietf-netconf\" module in the context.");
            return NC_MSG_ERROR;
        }
        break;
    case NC_RPC_GETSCHEMA:
        mod = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf-monitoring");
        if (!mod) {
            ERR(session, "Missing \"ietf-netconf-monitoring\" module in the context.");
            return NC_MSG_ERROR;
        }
        break;
    case NC_RPC_SUBSCRIBE:
        mod = ly_ctx_get_module_implemented(session->ctx, "notifications");
        if (!mod) {
            ERR(session, "Missing \"notifications\" module in the context.");
            return NC_MSG_ERROR;
        }
        break;
    case NC_RPC_GETDATA:
    case NC_RPC_EDITDATA:
        mod = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf-nmda");
        if (!mod) {
            ERR(session, "Missing \"ietf-netconf-nmda\" module in the context.");
            return NC_MSG_ERROR;
        }
        break;
    case NC_RPC_ESTABLISHSUB:
    case NC_RPC_MODIFYSUB:
    case NC_RPC_DELETESUB:
    case NC_RPC_KILLSUB:
        mod = ly_ctx_get_module_implemented(session->ctx, "ietf-subscribed-notifications");
        if (!mod) {
            ERR(session, "Missing \"ietf-subscribed-notifications\" module in the context.");
            return NC_MSG_ERROR;
        }
        break;
    case NC_RPC_ESTABLISHPUSH:
    case NC_RPC_MODIFYPUSH:
        mod = ly_ctx_get_module_implemented(session->ctx, "ietf-subscribed-notifications");
        if (!mod) {
            ERR(session, "Missing \"ietf-subscribed-notifications\" module in the context.");
            return NC_MSG_ERROR;
        }
        mod2 = ly_ctx_get_module_implemented(session->ctx, "ietf-yang-push");
        if (!mod2) {
            ERR(session, "Missing \"ietf-yang-push\" module in the context.");
            return NC_MSG_ERROR;
        }
        break;
    case NC_RPC_RESYNCSUB:
        mod = ly_ctx_get_module_implemented(session->ctx, "ietf-yang-push");
        if (!mod) {
            ERR(session, "Missing \"ietf-yang-push\" module in the context.");
            return NC_MSG_ERROR;
        }
        break;
    case NC_RPC_UNKNOWN:
        ERRINT;
        return NC_MSG_ERROR;
    }

#define CHECK_LYRC_BREAK(func_call) if ((lyrc = func_call)) break;

    switch (rpc->type) {
    case NC_RPC_ACT_GENERIC:
        rpc_gen = (struct nc_rpc_act_generic *)rpc;

        if (rpc_gen->has_data) {
            data = rpc_gen->content.data;
            dofree = 0;
        } else {
            ly_in_new_memory(rpc_gen->content.xml_str, &in);
            lyrc = lyd_parse_op(session->ctx, NULL, in, LYD_XML, LYD_TYPE_RPC_YANG, &data, NULL);
            ly_in_free(in, 0);
            if (lyrc) {
                break;
            }
        }
        break;

    case NC_RPC_GETCONFIG:
        rpc_gc = (struct nc_rpc_getconfig *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "get-config", 0, &data));
        CHECK_LYRC_BREAK(lyd_new_inner(data, mod, "source", 0, &cont));
        CHECK_LYRC_BREAK(lyd_new_term(cont, mod, ncds2str[rpc_gc->source], NULL, 0, NULL));
        if (rpc_gc->filter) {
            if (!rpc_gc->filter[0] || (rpc_gc->filter[0] == '<')) {
                CHECK_LYRC_BREAK(lyd_new_any(data, mod, "filter", rpc_gc->filter, LYD_ANYDATA_XML, 0, &node));
                CHECK_LYRC_BREAK(lyd_new_meta(NULL, node, NULL, "ietf-netconf:type", "subtree", 0, NULL));
            } else {
                CHECK_LYRC_BREAK(lyd_new_any(data, mod, "filter", NULL, LYD_ANYDATA_STRING, 0, &node));
                CHECK_LYRC_BREAK(lyd_new_meta(NULL, node, NULL, "ietf-netconf:type", "xpath", 0, NULL));
                CHECK_LYRC_BREAK(lyd_new_meta(NULL, node, NULL, "ietf-netconf:select", rpc_gc->filter, 0, NULL));
            }
        }

        if (rpc_gc->wd_mode) {
            ietfncwd = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf-with-defaults");
            if (!ietfncwd) {
                ERR(session, "Missing \"ietf-netconf-with-defaults\" module in the context.");
                lyrc = LY_ENOTFOUND;
                break;
            }
            CHECK_LYRC_BREAK(lyd_new_term(data, ietfncwd, "with-defaults", nc_wd2str(rpc_gc->wd_mode), 0, NULL));
        }
        break;

    case NC_RPC_EDIT:
        rpc_e = (struct nc_rpc_edit *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "edit-config", 0, &data));
        CHECK_LYRC_BREAK(lyd_new_inner(data, mod, "target", 0, &cont));
        CHECK_LYRC_BREAK(lyd_new_term(cont, mod, ncds2str[rpc_e->target], NULL, 0, NULL));

        if (rpc_e->default_op) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "default-operation", rpcedit_dfltop2str[rpc_e->default_op], 0, NULL));
        }
        if (rpc_e->test_opt) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "test-option", rpcedit_testopt2str[rpc_e->test_opt], 0, NULL));
        }
        if (rpc_e->error_opt) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "error-option", rpcedit_erropt2str[rpc_e->error_opt], 0, NULL));
        }
        if (!rpc_e->edit_cont[0] || (rpc_e->edit_cont[0] == '<')) {
            CHECK_LYRC_BREAK(lyd_new_any(data, mod, "config", rpc_e->edit_cont, LYD_ANYDATA_XML, 0, NULL));
        } else {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "url", rpc_e->edit_cont, 0, NULL));
        }
        break;

    case NC_RPC_COPY:
        rpc_cp = (struct nc_rpc_copy *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "copy-config", 0, &data));
        CHECK_LYRC_BREAK(lyd_new_inner(data, mod, "target", 0, &cont));
        if (rpc_cp->url_trg) {
            CHECK_LYRC_BREAK(lyd_new_term(cont, mod, "url", rpc_cp->url_trg, 0, NULL));
        } else {
            CHECK_LYRC_BREAK(lyd_new_term(cont, mod, ncds2str[rpc_cp->target], NULL, 0, NULL));
        }

        CHECK_LYRC_BREAK(lyd_new_inner(data, mod, "source", 0, &cont));
        if (rpc_cp->url_config_src) {
            if (!rpc_cp->url_config_src[0] || (rpc_cp->url_config_src[0] == '<')) {
                CHECK_LYRC_BREAK(lyd_new_any(cont, mod, "config", rpc_cp->url_config_src, LYD_ANYDATA_XML, 0, NULL));
            } else {
                CHECK_LYRC_BREAK(lyd_new_term(cont, mod, "url", rpc_cp->url_config_src, 0, NULL));
            }
        } else {
            CHECK_LYRC_BREAK(lyd_new_term(cont, mod, ncds2str[rpc_cp->source], NULL, 0, NULL));
        }

        if (rpc_cp->wd_mode) {
            ietfncwd = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf-with-defaults");
            if (!ietfncwd) {
                ERR(session, "Missing \"ietf-netconf-with-defaults\" module in the context.");
                lyrc = LY_ENOTFOUND;
                break;
            }
            CHECK_LYRC_BREAK(lyd_new_term(data, ietfncwd, "with-defaults", nc_wd2str(rpc_cp->wd_mode), 0, NULL));
        }
        break;

    case NC_RPC_DELETE:
        rpc_del = (struct nc_rpc_delete *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "delete-config", 0, &data));
        CHECK_LYRC_BREAK(lyd_new_inner(data, mod, "target", 0, &cont));
        if (rpc_del->url) {
            CHECK_LYRC_BREAK(lyd_new_term(cont, mod, "url", rpc_del->url, 0, NULL));
        } else {
            CHECK_LYRC_BREAK(lyd_new_term(cont, mod, ncds2str[rpc_del->target], NULL, 0, NULL));
        }
        break;

    case NC_RPC_LOCK:
        rpc_lock = (struct nc_rpc_lock *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "lock", 0, &data));
        CHECK_LYRC_BREAK(lyd_new_inner(data, mod, "target", 0, &cont));
        CHECK_LYRC_BREAK(lyd_new_term(cont, mod, ncds2str[rpc_lock->target], NULL, 0, NULL));
        break;

    case NC_RPC_UNLOCK:
        rpc_lock = (struct nc_rpc_lock *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "unlock", 0, &data));
        CHECK_LYRC_BREAK(lyd_new_inner(data, mod, "target", 0, &cont));
        CHECK_LYRC_BREAK(lyd_new_term(cont, mod, ncds2str[rpc_lock->target], NULL, 0, NULL));
        break;

    case NC_RPC_GET:
        rpc_g = (struct nc_rpc_get *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "get", 0, &data));
        if (rpc_g->filter) {
            if (!rpc_g->filter[0] || (rpc_g->filter[0] == '<')) {
                CHECK_LYRC_BREAK(lyd_new_any(data, mod, "filter", rpc_g->filter, LYD_ANYDATA_XML, 0, &node));
                CHECK_LYRC_BREAK(lyd_new_meta(NULL, node, NULL, "ietf-netconf:type", "subtree", 0, NULL));
            } else {
                CHECK_LYRC_BREAK(lyd_new_any(data, mod, "filter", NULL, LYD_ANYDATA_STRING, 0, &node));
                CHECK_LYRC_BREAK(lyd_new_meta(NULL, node, NULL, "ietf-netconf:type", "xpath", 0, NULL));
                CHECK_LYRC_BREAK(lyd_new_meta(NULL, node, NULL, "ietf-netconf:select", rpc_g->filter, 0, NULL));
            }
        }

        if (rpc_g->wd_mode) {
            ietfncwd = ly_ctx_get_module_implemented(session->ctx, "ietf-netconf-with-defaults");
            if (!ietfncwd) {
                ERR(session, "Missing \"ietf-netconf-with-defaults\" module in the context.");
                lyrc = LY_ENOTFOUND;
                break;
            }
            CHECK_LYRC_BREAK(lyd_new_term(data, ietfncwd, "with-defaults", nc_wd2str(rpc_g->wd_mode), 0, NULL));
        }
        break;

    case NC_RPC_KILL:
        rpc_k = (struct nc_rpc_kill *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "kill-session", 0, &data));
        sprintf(str, "%" PRIu32, rpc_k->sid);
        CHECK_LYRC_BREAK(lyd_new_term(data, mod, "session-id", str, 0, NULL));
        break;

    case NC_RPC_COMMIT:
        rpc_com = (struct nc_rpc_commit *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "commit", 0, &data));
        if (rpc_com->confirmed) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "confirmed", NULL, 0, NULL));
        }

        if (rpc_com->confirm_timeout) {
            sprintf(str, "%" PRIu32, rpc_com->confirm_timeout);
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "confirm-timeout", str, 0, NULL));
        }
        if (rpc_com->persist) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "persist", rpc_com->persist, 0, NULL));
        }
        if (rpc_com->persist_id) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "persist-id", rpc_com->persist_id, 0, NULL));
        }
        break;

    case NC_RPC_DISCARD:
        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "discard-changes", 0, &data));
        break;

    case NC_RPC_CANCEL:
        rpc_can = (struct nc_rpc_cancel *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "cancel-commit", 0, &data));
        if (rpc_can->persist_id) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "persist-id", rpc_can->persist_id, 0, NULL));
        }
        break;

    case NC_RPC_VALIDATE:
        rpc_val = (struct nc_rpc_validate *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "validate", 0, &data));
        CHECK_LYRC_BREAK(lyd_new_inner(data, mod, "source", 0, &cont));
        if (rpc_val->url_config_src) {
            if (!rpc_val->url_config_src[0] || (rpc_val->url_config_src[0] == '<')) {
                CHECK_LYRC_BREAK(lyd_new_any(cont, mod, "config", rpc_val->url_config_src, LYD_ANYDATA_XML, 0, NULL));
            } else {
                CHECK_LYRC_BREAK(lyd_new_term(cont, mod, "url", rpc_val->url_config_src, 0, NULL));
            }
        } else {
            CHECK_LYRC_BREAK(lyd_new_term(cont, mod, ncds2str[rpc_val->source], NULL, 0, NULL));
        }
        break;

    case NC_RPC_GETSCHEMA:
        rpc_gs = (struct nc_rpc_getschema *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "get-schema", 0, &data));
        CHECK_LYRC_BREAK(lyd_new_term(data, mod, "identifier", rpc_gs->identifier, 0, NULL));
        if (rpc_gs->version) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "version", rpc_gs->version, 0, NULL));
        }
        if (rpc_gs->format) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "format", rpc_gs->format, 0, NULL));
        }
        break;

    case NC_RPC_SUBSCRIBE:
        rpc_sub = (struct nc_rpc_subscribe *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "create-subscription", 0, &data));
        if (rpc_sub->stream) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "stream", rpc_sub->stream, 0, NULL));
        }

        if (rpc_sub->filter) {
            if (!rpc_sub->filter[0] || (rpc_sub->filter[0] == '<')) {
                CHECK_LYRC_BREAK(lyd_new_any(data, mod, "filter", rpc_sub->filter, LYD_ANYDATA_XML, 0, &node));
                CHECK_LYRC_BREAK(lyd_new_meta(NULL, node, NULL, "ietf-netconf:type", "subtree", 0, NULL));
            } else {
                CHECK_LYRC_BREAK(lyd_new_any(data, mod, "filter", NULL, LYD_ANYDATA_STRING, 0, &node));
                CHECK_LYRC_BREAK(lyd_new_meta(NULL, node, NULL, "ietf-netconf:type", "xpath", 0, NULL));
                CHECK_LYRC_BREAK(lyd_new_meta(NULL, node, NULL, "ietf-netconf:select", rpc_sub->filter, 0, NULL));
            }
        }
        if (rpc_sub->start) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "startTime", rpc_sub->start, 0, NULL));
        }
        if (rpc_sub->stop) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "stopTime", rpc_sub->stop, 0, NULL));
        }
        break;

    case NC_RPC_GETDATA:
        rpc_getd = (struct nc_rpc_getdata *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "get-data", 0, &data));
        CHECK_LYRC_BREAK(lyd_new_term(data, mod, "datastore", rpc_getd->datastore, 0, NULL));

        if (rpc_getd->filter) {
            if (!rpc_getd->filter[0] || (rpc_getd->filter[0] == '<')) {
                CHECK_LYRC_BREAK(lyd_new_any(data, mod, "subtree-filter", rpc_getd->filter, LYD_ANYDATA_XML, 0, NULL));
            } else {
                CHECK_LYRC_BREAK(lyd_new_term(data, mod, "xpath-filter", rpc_getd->filter, 0, NULL));
            }
        }
        if (rpc_getd->config_filter) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "config-filter", rpc_getd->config_filter, 0, NULL));
        }
        for (i = 0; i < rpc_getd->origin_filter_count; ++i) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, rpc_getd->negated_origin_filter ? "negated-origin-filter" :
                    "origin-filter", rpc_getd->origin_filter[i], 0, NULL));
        }
        if (rpc_getd->max_depth) {
            sprintf(str, "%u", rpc_getd->max_depth);
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "max-depth", str, 0, NULL));
        }
        if (rpc_getd->with_origin) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "with-origin", NULL, 0, NULL));
        }

        if (rpc_getd->wd_mode) {
            /* "with-defaults" are used from a grouping so it belongs to the ietf-netconf-nmda module */
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "with-defaults", nc_wd2str(rpc_getd->wd_mode), 0, NULL));
        }
        break;

    case NC_RPC_EDITDATA:
        rpc_editd = (struct nc_rpc_editdata *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "edit-data", 0, &data));
        CHECK_LYRC_BREAK(lyd_new_term(data, mod, "datastore", rpc_editd->datastore, 0, NULL));

        if (rpc_editd->default_op) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "default-operation", rpcedit_dfltop2str[rpc_editd->default_op], 0,
                    NULL));
        }
        if (!rpc_editd->edit_cont[0] || (rpc_editd->edit_cont[0] == '<')) {
            CHECK_LYRC_BREAK(lyd_new_any(data, mod, "config", rpc_editd->edit_cont, LYD_ANYDATA_XML, 0, NULL));
        } else {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "url", rpc_editd->edit_cont, 0, NULL));
        }
        break;

    case NC_RPC_ESTABLISHSUB:
        rpc_estsub = (struct nc_rpc_establishsub *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "establish-subscription", 0, &data));

        if (rpc_estsub->filter) {
            if (!rpc_estsub->filter[0] || (rpc_estsub->filter[0] == '<')) {
                CHECK_LYRC_BREAK(lyd_new_any(data, mod, "stream-subtree-filter", rpc_estsub->filter, LYD_ANYDATA_XML,
                        0, NULL));
            } else if (rpc_estsub->filter[0] == '/') {
                CHECK_LYRC_BREAK(lyd_new_term(data, mod, "stream-xpath-filter", rpc_estsub->filter, 0, NULL));
            } else {
                CHECK_LYRC_BREAK(lyd_new_term(data, mod, "stream-filter-name", rpc_estsub->filter, 0, NULL));
            }
        }
        CHECK_LYRC_BREAK(lyd_new_term(data, mod, "stream", rpc_estsub->stream, 0, NULL));

        if (rpc_estsub->start) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "replay-start-time", rpc_estsub->start, 0, NULL));
        }
        if (rpc_estsub->stop) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "stop-time", rpc_estsub->stop, 0, NULL));
        }
        if (rpc_estsub->encoding) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "encoding", rpc_estsub->encoding, 0, NULL));
        }
        break;

    case NC_RPC_MODIFYSUB:
        rpc_modsub = (struct nc_rpc_modifysub *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "modify-subscription", 0, &data));

        sprintf(str, "%" PRIu32, rpc_modsub->id);
        CHECK_LYRC_BREAK(lyd_new_term(data, mod, "id", str, 0, NULL));

        if (rpc_modsub->filter) {
            if (!rpc_modsub->filter[0] || (rpc_modsub->filter[0] == '<')) {
                CHECK_LYRC_BREAK(lyd_new_any(data, mod, "stream-subtree-filter", rpc_modsub->filter, LYD_ANYDATA_XML,
                        0, NULL));
            } else if (rpc_modsub->filter[0] == '/') {
                CHECK_LYRC_BREAK(lyd_new_term(data, mod, "stream-xpath-filter", rpc_modsub->filter, 0, NULL));
            } else {
                CHECK_LYRC_BREAK(lyd_new_term(data, mod, "stream-filter-name", rpc_modsub->filter, 0, NULL));
            }
        }
        if (rpc_modsub->stop) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "stop-time", rpc_modsub->stop, 0, NULL));
        }
        break;

    case NC_RPC_DELETESUB:
        rpc_delsub = (struct nc_rpc_deletesub *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "delete-subscription", 0, &data));

        sprintf(str, "%" PRIu32, rpc_delsub->id);
        CHECK_LYRC_BREAK(lyd_new_term(data, mod, "id", str, 0, NULL));
        break;

    case NC_RPC_KILLSUB:
        rpc_killsub = (struct nc_rpc_killsub *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "kill-subscription", 0, &data));

        sprintf(str, "%" PRIu32, rpc_killsub->id);
        CHECK_LYRC_BREAK(lyd_new_term(data, mod, "id", str, 0, NULL));
        break;

    case NC_RPC_ESTABLISHPUSH:
        rpc_estpush = (struct nc_rpc_establishpush *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "establish-subscription", 0, &data));
        CHECK_LYRC_BREAK(lyd_new_term(data, mod2, "datastore", rpc_estpush->datastore, 0, NULL));

        if (rpc_estpush->filter) {
            if (!rpc_estpush->filter[0] || (rpc_estpush->filter[0] == '<')) {
                CHECK_LYRC_BREAK(lyd_new_any(data, mod2, "datastore-subtree-filter", rpc_estpush->filter,
                        LYD_ANYDATA_XML, 0, NULL));
            } else if (rpc_estpush->filter[0] == '/') {
                CHECK_LYRC_BREAK(lyd_new_term(data, mod2, "datastore-xpath-filter", rpc_estpush->filter, 0, NULL));
            } else {
                CHECK_LYRC_BREAK(lyd_new_term(data, mod2, "selection-filter-ref", rpc_estpush->filter, 0, NULL));
            }
        }

        if (rpc_estpush->stop) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "stop-time", rpc_estpush->stop, 0, NULL));
        }
        if (rpc_estpush->encoding) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "encoding", rpc_estpush->encoding, 0, NULL));
        }

        if (rpc_estpush->periodic) {
            CHECK_LYRC_BREAK(lyd_new_inner(data, mod2, "periodic", 0, &cont));
            sprintf(str, "%" PRIu32, rpc_estpush->period);
            CHECK_LYRC_BREAK(lyd_new_term(cont, mod2, "period", str, 0, NULL));
            if (rpc_estpush->anchor_time) {
                CHECK_LYRC_BREAK(lyd_new_term(cont, mod2, "anchor-time", rpc_estpush->anchor_time, 0, NULL));
            }
        } else {
            CHECK_LYRC_BREAK(lyd_new_inner(data, mod2, "on-change", 0, &cont));
            if (rpc_estpush->dampening_period) {
                sprintf(str, "%" PRIu32, rpc_estpush->dampening_period);
                CHECK_LYRC_BREAK(lyd_new_term(cont, mod2, "dampening-period", str, 0, NULL));
            }
            CHECK_LYRC_BREAK(lyd_new_term(cont, mod2, "sync-on-start", rpc_estpush->sync_on_start ? "true" : "false", 0,
                    NULL));
            if (rpc_estpush->excluded_change) {
                for (i = 0; rpc_estpush->excluded_change[i]; ++i) {
                    CHECK_LYRC_BREAK(lyd_new_term(cont, mod2, "excluded-change", rpc_estpush->excluded_change[i], 0,
                            NULL));
                }
            }
        }
        break;

    case NC_RPC_MODIFYPUSH:
        rpc_modpush = (struct nc_rpc_modifypush *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "modify-subscription", 0, &data));

        sprintf(str, "%" PRIu32, rpc_modpush->id);
        CHECK_LYRC_BREAK(lyd_new_term(data, mod, "id", str, 0, NULL));
        CHECK_LYRC_BREAK(lyd_new_term(data, mod2, "datastore", rpc_modpush->datastore, 0, NULL));

        if (rpc_modpush->filter) {
            if (!rpc_modpush->filter[0] || (rpc_modpush->filter[0] == '<')) {
                CHECK_LYRC_BREAK(lyd_new_any(data, mod2, "datastore-subtree-filter", rpc_modpush->filter,
                        LYD_ANYDATA_XML, 0, NULL));
            } else if (rpc_modpush->filter[0] == '/') {
                CHECK_LYRC_BREAK(lyd_new_term(data, mod2, "datastore-xpath-filter", rpc_modpush->filter, 0, NULL));
            } else {
                CHECK_LYRC_BREAK(lyd_new_term(data, mod2, "selection-filter-ref", rpc_modpush->filter, 0, NULL));
            }
        }
        if (rpc_modpush->stop) {
            CHECK_LYRC_BREAK(lyd_new_term(data, mod, "stop-time", rpc_modpush->stop, 0, NULL));
        }

        if (rpc_modpush->periodic) {
            CHECK_LYRC_BREAK(lyd_new_inner(data, mod2, "periodic", 0, &cont));
            sprintf(str, "%" PRIu32, rpc_modpush->period);
            CHECK_LYRC_BREAK(lyd_new_term(cont, mod2, "period", str, 0, NULL));
            if (rpc_modpush->anchor_time) {
                CHECK_LYRC_BREAK(lyd_new_term(cont, mod2, "anchor-time", rpc_modpush->anchor_time, 0, NULL));
            }
        } else {
            CHECK_LYRC_BREAK(lyd_new_inner(data, mod2, "on-change", 0, &cont));
            if (rpc_modpush->dampening_period) {
                sprintf(str, "%" PRIu32, rpc_modpush->dampening_period);
                CHECK_LYRC_BREAK(lyd_new_term(cont, mod2, "dampening-period", str, 0, NULL));
            }
        }
        break;

    case NC_RPC_RESYNCSUB:
        rpc_resyncsub = (struct nc_rpc_resyncsub *)rpc;

        CHECK_LYRC_BREAK(lyd_new_inner(NULL, mod, "resync-subscription", 0, &data));
        sprintf(str, "%" PRIu32, rpc_resyncsub->id);
        CHECK_LYRC_BREAK(lyd_new_term(data, mod, "id", str, 0, NULL));
        break;

    case NC_RPC_UNKNOWN:
        ERRINT;
        return NC_MSG_ERROR;
    }

#undef CHECK_LYRC_BREAK

    if (lyrc) {
        ERR(session, "Failed to create RPC, perhaps a required feature is disabled.");
        lyd_free_tree(data);
        return NC_MSG_ERROR;
    }

    /* send RPC, store its message ID */
    r = nc_send_msg_io(session, timeout, data);
    cur_msgid = session->opts.client.msgid;

    if (dofree) {
        lyd_free_tree(data);
    }

    if (r == NC_MSG_RPC) {
        *msgid = cur_msgid;
    }
    return r;
}

API void
nc_client_session_set_not_strict(struct nc_session *session)
{
    if (session->side != NC_CLIENT) {
        ERRARG(NULL, "session");
        return;
    }

    session->flags |= NC_SESSION_CLIENT_NOT_STRICT;
}
