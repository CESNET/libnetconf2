/**
 * \file session_client.c
 * \author Michal Vasko <mvasko@cesnet.cz>
 * \brief libnetconf2 session client functions
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
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <poll.h>

#include <libyang/libyang.h>

#include "libnetconf.h"
#include "session_client.h"
#include "messages_client.h"

static const char *ncds2str[] = {NULL, "config", "url", "running", "startup", "candidate"};

#ifdef NC_ENABLED_SSH
int sshauth_hostkey_check(const char *hostname, ssh_session session, void *priv);
char *sshauth_password(const char *username, const char *hostname, void *priv);
char *sshauth_interactive(const char *auth_name, const char *instruction, const char *prompt, int echo, void *priv);
char *sshauth_privkey_passphrase(const char* privkey_path, void *priv);
#endif /* NC_ENABLED_SSH */

static pthread_once_t nc_client_context_once = PTHREAD_ONCE_INIT;
static pthread_key_t nc_client_context_key;
#ifdef __linux__
static struct nc_client_context context_main = {
    /* .opts zeroed */
#ifdef NC_ENABLED_SSH
    .ssh_opts = {
        .auth_pref = {{NC_SSH_AUTH_INTERACTIVE, 3}, {NC_SSH_AUTH_PASSWORD, 2}, {NC_SSH_AUTH_PUBLICKEY, 1}},
        .auth_hostkey_check = sshauth_hostkey_check,
        .auth_password = sshauth_password,
        .auth_interactive = sshauth_interactive,
        .auth_privkey_passphrase = sshauth_privkey_passphrase
    },
    .ssh_ch_opts = {
        .auth_pref = {{NC_SSH_AUTH_INTERACTIVE, 1}, {NC_SSH_AUTH_PASSWORD, 2}, {NC_SSH_AUTH_PUBLICKEY, 3}},
        .auth_hostkey_check = sshauth_hostkey_check,
        .auth_password = sshauth_password,
        .auth_interactive = sshauth_interactive,
        .auth_privkey_passphrase = sshauth_privkey_passphrase
    },
#endif /* NC_ENABLED_SSH */
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
        nc_client_set_schema_searchpath(NULL);
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
        nc_client_ch_del_bind(NULL, 0, 0);
#endif
#ifdef NC_ENABLED_SSH
        nc_client_ssh_destroy_opts();
#endif
#ifdef NC_ENABLED_TLS
        nc_client_tls_destroy_opts();
#endif
        free(c);
    }
}

static void
nc_client_context_createkey(void)
{
    int r;

    /* initiate */
    while ((r = pthread_key_create(&nc_client_context_key, nc_client_context_free)) == EAGAIN);
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
#ifdef NC_ENABLED_SSH
            e->ssh_opts.auth_pref[0].type = NC_SSH_AUTH_INTERACTIVE;
            e->ssh_opts.auth_pref[0].value = 3;
            e->ssh_opts.auth_pref[1].type = NC_SSH_AUTH_PASSWORD;
            e->ssh_opts.auth_pref[1].value = 2;
            e->ssh_opts.auth_pref[2].type = NC_SSH_AUTH_PUBLICKEY;
            e->ssh_opts.auth_pref[2].value = 1;
            e->ssh_opts.auth_hostkey_check = sshauth_hostkey_check;
            e->ssh_opts.auth_password = sshauth_password;
            e->ssh_opts.auth_interactive = sshauth_interactive;
            e->ssh_opts.auth_privkey_passphrase = sshauth_privkey_passphrase;

            /* callhome settings are the same except the inverted auth methods preferences */
            memcpy(&e->ssh_ch_opts, &e->ssh_opts, sizeof e->ssh_ch_opts);
            e->ssh_ch_opts.auth_pref[0].value = 1;
            e->ssh_ch_opts.auth_pref[1].value = 2;
            e->ssh_ch_opts.auth_pref[2].value = 3;
#endif /* NC_ENABLED_SSH */
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
        ERRARG(context);
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

int
nc_session_new_ctx(struct nc_session *session, struct ly_ctx *ctx)
{
    /* assign context (dicionary needed for handshake) */
    if (!ctx) {
        ctx = ly_ctx_new(NULL, LY_CTX_NOYANGLIBRARY);
        if (!ctx) {
            return EXIT_FAILURE;
        }

        /* user path must be first, the first path is used to store schemas retreived via get-schema */
        if (client_opts.schema_searchpath) {
            ly_ctx_set_searchdir(ctx, client_opts.schema_searchpath);
        }
        ly_ctx_set_searchdir(ctx, NC_SCHEMAS_DIR);

        /* set callback for getting schemas, if provided */
        ly_ctx_set_module_imp_clb(ctx, client_opts.schema_clb, client_opts.schema_clb_data);
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
        if (!client_opts.schema_searchpath) {
            ERRMEM;
            return 1;
        }
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


struct schema_info {
    char *name;
    char *revision;
    struct {
        char *name;
        char *revision;
    } *submodules;
    struct ly_set features;
    int implemented;
};

struct clb_data_s {
    void *user_data;
    ly_module_imp_clb user_clb;
    struct schema_info *schemas;
    struct nc_session *session;
    int has_get_schema;
};

static char *
retrieve_schema_data_localfile(const char *name, const char *rev, struct clb_data_s *clb_data,
                               LYS_INFORMAT *format)
{
    char *localfile = NULL;
    FILE *f;
    long length, l;
    char *model_data = NULL;

    if (lys_search_localfile(ly_ctx_get_searchdirs(clb_data->session->ctx),
                             !(ly_ctx_get_options(clb_data->session->ctx) & LY_CTX_DISABLE_SEARCHDIR_CWD),
                             name, rev, &localfile, format)) {
        return NULL;
    }
    if (localfile) {
        VRB("Session %u: reading schema from localfile \"%s\".", clb_data->session->id, localfile);
        f = fopen(localfile, "r");
        if (!f) {
            ERR("Session %u: unable to open \"%s\" file to get schema (%s).",
                clb_data->session->id, localfile, strerror(errno));
            free(localfile);
            return NULL;
        }

        fseek(f, 0, SEEK_END);
        length = ftell(f);
        if (length < 0) {
            ERR("Session %u: unable to get size of schema file \"%s\".",
                clb_data->session->id, localfile);
            free(localfile);
            fclose(f);
            return NULL;
        }
        fseek(f, 0, SEEK_SET);

        model_data = malloc(length + 1);
        if (!model_data) {
            ERRMEM;
        } else if ((l = fread(model_data, 1, length, f)) != length) {
            ERR("Session %u: reading schema from \"%s\" failed (%d bytes read, but %d expected).",
                clb_data->session->id, localfile, l, length);
            free(model_data);
            model_data = NULL;
        } else {
            /* terminating NULL byte */
            model_data[length] = '\0';
        }
        fclose(f);
        free(localfile);
    }

    return model_data;
}

static char *
retrieve_schema_data_getschema(const char *name, const char *rev, struct clb_data_s *clb_data,
                               LYS_INFORMAT *format)
{
    struct nc_rpc *rpc;
    struct nc_reply *reply;
    struct nc_reply_data *data_rpl;
    struct nc_reply_error *error_rpl;
    struct lyd_node_anydata *get_schema_data;
    NC_MSG_TYPE msg;
    uint64_t msgid;
    char *localfile = NULL;
    FILE *f;
    char *model_data = NULL;

    VRB("Session %u: reading schema from server via get-schema.", clb_data->session->id);
    rpc = nc_rpc_getschema(name, rev, "yang", NC_PARAMTYPE_CONST);

    while ((msg = nc_send_rpc(clb_data->session, rpc, 0, &msgid)) == NC_MSG_WOULDBLOCK) {
        usleep(1000);
    }
    if (msg == NC_MSG_ERROR) {
        ERR("Session %u: failed to send the <get-schema> RPC.", clb_data->session->id);
        nc_rpc_free(rpc);
        return NULL;
    }

    do {
        msg = nc_recv_reply(clb_data->session, rpc, msgid, NC_READ_ACT_TIMEOUT * 1000, 0, &reply);
    } while (msg == NC_MSG_NOTIF);
    nc_rpc_free(rpc);
    if (msg == NC_MSG_WOULDBLOCK) {
        ERR("Session %u: timeout for receiving reply to a <get-schema> expired.", clb_data->session->id);
        return NULL;
    } else if (msg == NC_MSG_ERROR) {
        ERR("Session %u: failed to receive a reply to <get-schema>.", clb_data->session->id);
        return NULL;
    }

    switch (reply->type) {
    case NC_RPL_OK:
        ERR("Session %u: unexpected reply OK to a <get-schema> RPC.", clb_data->session->id);
        nc_reply_free(reply);
        return NULL;
    case NC_RPL_DATA:
        /* fine */
        break;
    case NC_RPL_ERROR:
        error_rpl = (struct nc_reply_error *)reply;
        if (error_rpl->count) {
            ERR("Session %u: error reply to a <get-schema> RPC (tag \"%s\", message \"%s\").",
                clb_data->session->id, error_rpl->err[0].tag, error_rpl->err[0].message);
        } else {
            ERR("Session %u: unexpected reply error to a <get-schema> RPC.", clb_data->session->id);
        }
        nc_reply_free(reply);
        return NULL;
    case NC_RPL_NOTIF:
        ERR("Session %u: unexpected reply notification to a <get-schema> RPC.", clb_data->session->id);
        nc_reply_free(reply);
        return NULL;
    }

    data_rpl = (struct nc_reply_data *)reply;
    if ((data_rpl->data->schema->nodetype != LYS_RPC) || strcmp(data_rpl->data->schema->name, "get-schema")
            || !data_rpl->data->child || (data_rpl->data->child->schema->nodetype != LYS_ANYXML)) {
        ERR("Session %u: unexpected data in reply to a <get-schema> RPC.", clb_data->session->id);
        nc_reply_free(reply);
        return NULL;
    }
    get_schema_data = (struct lyd_node_anydata *)data_rpl->data->child;
    switch (get_schema_data->value_type) {
    case LYD_ANYDATA_CONSTSTRING:
    case LYD_ANYDATA_STRING:
        model_data = strdup(get_schema_data->value.str);
        break;
    case LYD_ANYDATA_DATATREE:
        lyd_print_mem(&model_data, get_schema_data->value.tree, LYD_XML, LYP_WITHSIBLINGS);
        break;
    case LYD_ANYDATA_XML:
        lyxml_print_mem(&model_data, get_schema_data->value.xml, LYXML_PRINT_SIBLINGS);
        break;
    case LYD_ANYDATA_JSON:
    case LYD_ANYDATA_JSOND:
    case LYD_ANYDATA_SXML:
    case LYD_ANYDATA_SXMLD:
    case LYD_ANYDATA_LYB:
    case LYD_ANYDATA_LYBD:
        ERRINT;
        nc_reply_free(reply);
    }
    nc_reply_free(reply);

    if (model_data && !model_data[0]) {
        /* empty data */
        free(model_data);
        model_data = NULL;
    }

    /* try to store the model_data into local schema repository */
    if (model_data) {
        *format = LYS_IN_YANG;
        if (client_opts.schema_searchpath) {
            if (asprintf(&localfile, "%s/%s%s%s.yang", client_opts.schema_searchpath, name,
                         rev ? "@" : "", rev ? rev : "") == -1) {
                ERRMEM;
            } else {
                f = fopen(localfile, "w");
                if (!f) {
                    WRN("Unable to store \"%s\" as a local copy of schema retrieved via <get-schema> (%s).",
                        localfile, strerror(errno));
                } else {
                    fputs(model_data, f);
                    fclose(f);
                }
                free(localfile);
            }
        }
    }

    return model_data;
}

static void free_with_user_data(void *data, void *user_data)
{
    free(data);
    (void)user_data;
}

static const char *
retrieve_schema_data(const char *mod_name, const char *mod_rev, const char *submod_name, const char *sub_rev,
                     void *user_data, LYS_INFORMAT *format, void (**free_module_data)(void *model_data, void *user_data))
{
    struct clb_data_s *clb_data = (struct clb_data_s *)user_data;
    unsigned int u, v, match = 1;
    const char *name = NULL, *rev = NULL;
    char *model_data = NULL;

    /* get and check the final name and revision of the schema to be retrieved */
    if (!mod_rev || !mod_rev[0]) {
        /* newest revision requested - get the newest revision from the list of available modules on server */
        match = 0;
        for (u = 0; clb_data->schemas[u].name; ++u) {
            if (strcmp(mod_name, clb_data->schemas[u].name)) {
                continue;
            }
            if (!match || strcmp(mod_rev, clb_data->schemas[u].revision) > 0) {
                mod_rev = clb_data->schemas[u].revision;
            }
            match = u + 1;
        }
        if (!match) {
            WRN("Session %u: unable to identify revision of the schema \"%s\" from the available server side information.",
                clb_data->session->id, mod_name);
        }
    }
    if (submod_name) {
        name = submod_name;
        if (sub_rev) {
            rev = sub_rev;
        } else if (match) {
            if (!clb_data->schemas[match - 1].submodules) {
                WRN("Session %u: Unable to identify revision of the requested submodule \"%s\", in schema \"%s\", from the available server side information.",
                    clb_data->session->id, submod_name, mod_name);
            } else {
                for (v = 0; clb_data->schemas[match - 1].submodules[v].name; ++v) {
                    if (!strcmp(submod_name, clb_data->schemas[match - 1].submodules[v].name)) {
                        rev = sub_rev = clb_data->schemas[match - 1].submodules[v].revision;
                    }
                }
                if (!rev) {
                    ERR("Session %u: requested submodule \"%s\" is not known for schema \"%s\" on server side.",
                        clb_data->session->id, submod_name, mod_name);
                    return NULL;
                }
            }
        }
    } else {
        name = mod_name;
        rev = mod_rev;
    }

    VRB("Session %u: retreiving data for schema \"%s\", revision \"%s\".", clb_data->session->id, name, rev);

    if (match) {
        /* we have enough information to avoid communication with server and try to get
         * the schema locally */

        /* 1. try to get data locally */
        model_data = retrieve_schema_data_localfile(name, rev, clb_data, format);

        /* 2. try to use <get-schema> */
        if (!model_data && clb_data->has_get_schema) {
            model_data = retrieve_schema_data_getschema(name, rev, clb_data, format);
        }
    } else {
        /* we are unsure which revision of the schema we should load, so first try to get
         * the newest revision from the server via get-schema and only if the server does not
         * implement get-schema, try to load the newest revision locally. This is imperfect
         * solution, but there are situation when a client does not know what revision is
         * actually implemented by the server. */

        /* 1. try to use <get-schema> */
        if (clb_data->has_get_schema) {
            model_data = retrieve_schema_data_getschema(name, rev, clb_data, format);
        }

        /* 2. try to get data locally */
        if (!model_data) {
            model_data = retrieve_schema_data_localfile(name, rev, clb_data, format);
        }
    }

    /* 3. try to use user callback */
    if (!model_data && clb_data->user_clb) {
        VRB("Session %u: reading schema via user callback.", clb_data->session->id);
        return clb_data->user_clb(mod_name, mod_rev, submod_name, sub_rev, clb_data->user_data, format, free_module_data);
    }

    *free_module_data = free_with_user_data;
    return model_data;
}

static int
nc_ctx_load_module(struct nc_session *session, const char *name, const char *revision, struct schema_info *schemas,
                   ly_module_imp_clb user_clb, void *user_data, int has_get_schema, const struct lys_module **mod)
{
    int ret = 0;
    struct ly_err_item *eitem;
    const char *module_data = NULL;
    LYS_INFORMAT format;
    void (*free_module_data)(void*, void*) = NULL;
    struct clb_data_s clb_data;

    *mod = NULL;
    if (revision) {
        *mod = ly_ctx_get_module(session->ctx, name, revision, 0);
    }
    if (*mod) {
        if (!(*mod)->implemented) {
            /* make the present module implemented */
            if (lys_set_implemented(*mod)) {
                ERR("Failed to implement model \"%s\".", (*mod)->name);
                ret = -1;
            }
        }
    } else {
        /* missing implemented module, load it ... */
        clb_data.has_get_schema = has_get_schema;
        clb_data.schemas = schemas;
        clb_data.session = session;
        clb_data.user_clb = user_clb;
        clb_data.user_data = user_data;

        /* clear all the errors and just collect them for now */
        ly_err_clean(session->ctx, NULL);
        ly_log_options(LY_LOSTORE);

        /* get module data */
        module_data = retrieve_schema_data(name, revision, NULL, NULL, &clb_data, &format, &free_module_data);

        if (module_data) {
            /* parse the schema */
            ly_ctx_set_module_imp_clb(session->ctx, retrieve_schema_data, &clb_data);

            *mod = lys_parse_mem(session->ctx, module_data, format);
            if (*free_module_data) {
                (*free_module_data)((char*)module_data, user_data);
            }

            ly_ctx_set_module_imp_clb(session->ctx, NULL, NULL);
        }

        /* restore logging options, then print errors on definite failure */
        ly_log_options(LY_LOLOG | LY_LOSTORE_LAST);
        if (!(*mod)) {
            for (eitem = ly_err_first(session->ctx); eitem && eitem->next; eitem = eitem->next) {
                ly_err_print(eitem);
            }
            ret = -1;
        } else {
            /* print only warnings */
            for (eitem = ly_err_first(session->ctx); eitem && eitem->next; eitem = eitem->next) {
                if (eitem->level == LY_LLWRN) {
                    ly_err_print(eitem);
                }
            }
        }

        /* clean the errors */
        ly_err_clean(session->ctx, NULL);
    }

    return ret;
}

static void
free_schema_info(struct schema_info *list)
{
    unsigned int u, v;

    if (!list) {
        return;
    }

    for (u = 0; list[u].name; ++u) {
        free(list[u].name);
        free(list[u].revision);
        for (v = 0; v < list[u].features.number; ++v) {
            free(list[u].features.set.g[v]);
        }
        free(list[u].features.set.g);
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


static int
build_schema_info_yl(struct nc_session *session, struct schema_info **result)
{
    struct nc_rpc *rpc = NULL;
    struct nc_reply *reply = NULL;
    struct nc_reply_error *error_rpl;
    struct lyd_node *yldata = NULL;
    NC_MSG_TYPE msg;
    uint64_t msgid;
    struct ly_set *modules = NULL;
    unsigned int u, v, submodules_count;
    struct lyd_node *iter, *child;
    struct lys_module *mod;
    int ret = EXIT_SUCCESS;

    /* get yang-library data from the server */
    if (nc_session_cpblt(session, "urn:ietf:params:netconf:capability:xpath:1.0")) {
        rpc = nc_rpc_get("/ietf-yang-library:*", 0, NC_PARAMTYPE_CONST);
    } else {
        rpc = nc_rpc_get("<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\"/>", 0, NC_PARAMTYPE_CONST);
    }
    if (!rpc) {
        goto cleanup;
    }

    while ((msg = nc_send_rpc(session, rpc, 0, &msgid)) == NC_MSG_WOULDBLOCK) {
        usleep(1000);
    }
    if (msg == NC_MSG_ERROR) {
        WRN("Session %u: failed to send request for yang-library data.",
            session->id);
        goto cleanup;
    }

    do {
        msg = nc_recv_reply(session, rpc, msgid, NC_READ_ACT_TIMEOUT * 1000, 0, &reply);
    } while (msg == NC_MSG_NOTIF);
    if (msg == NC_MSG_WOULDBLOCK) {
        WRN("Session %u: timeout for receiving reply to a <get> yang-library data expired.", session->id);
        goto cleanup;
    } else if (msg == NC_MSG_ERROR) {
        WRN("Session %u: failed to receive a reply to <get> of yang-library data.", session->id);
        goto cleanup;
    }

    switch (reply->type) {
    case NC_RPL_OK:
        WRN("Session %u: unexpected reply OK to a yang-library <get> RPC.", session->id);
        goto cleanup;
    case NC_RPL_DATA:
        /* fine */
        break;
    case NC_RPL_ERROR:
        error_rpl = (struct nc_reply_error *)reply;
        if (error_rpl->count) {
            WRN("Session %u: error reply to a yang-library <get> RPC (tag \"%s\", message \"%s\").",
                session->id, error_rpl->err[0].tag, error_rpl->err[0].message);
        } else {
            WRN("Session %u: unexpected reply error to a yang-library <get> RPC.", session->id);
        }
        goto cleanup;
    case NC_RPL_NOTIF:
        WRN("Session %u: unexpected reply notification to a yang-library <get> RPC.", session->id);
        goto cleanup;
    }

    yldata = ((struct nc_reply_data *)reply)->data;
    if (!yldata || strcmp(yldata->schema->module->name, "ietf-yang-library")) {
        WRN("Session %u: unexpected data in reply to a yang-library <get> RPC.", session->id);
        goto cleanup;
    }

    modules = lyd_find_path(yldata, "/ietf-yang-library:modules-state/module");
    if (!modules) {
        WRN("Session %u: no module information in reply to a yang-library <get> RPC.", session->id);
        goto cleanup;
    }

    (*result) = calloc(modules->number + 1, sizeof **result);
    if (!(*result)) {
        ERRMEM;
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    for (u = 0; u < modules->number; ++u) {
        submodules_count = 0;
        mod = ((struct lyd_node *)modules->set.d[u])->schema->module;
        LY_TREE_FOR(modules->set.d[u]->child, iter) {
            if (iter->schema->module != mod) {
                /* ignore node from other schemas (augments) */
                continue;
            }
            if (!((struct lyd_node_leaf_list *)iter)->value_str || !((struct lyd_node_leaf_list *)iter)->value_str[0]) {
                /* ignore empty nodes */
                continue;
            }
            if (!strcmp(iter->schema->name, "name")) {
                (*result)[u].name = strdup(((struct lyd_node_leaf_list *)iter)->value_str);
            } else if (!strcmp(iter->schema->name, "revision")) {
                (*result)[u].revision = strdup(((struct lyd_node_leaf_list *)iter)->value_str);
            } else if (!strcmp(iter->schema->name, "conformance-type")) {
                (*result)[u].implemented = !strcmp(((struct lyd_node_leaf_list *)iter)->value_str, "implement");
            } else if (!strcmp(iter->schema->name, "feature")) {
                ly_set_add(&(*result)[u].features, (void *)strdup(((struct lyd_node_leaf_list *)iter)->value_str), LY_SET_OPT_USEASLIST);
            } else if (!strcmp(iter->schema->name, "submodule")) {
                submodules_count++;
            }
        }

        if (submodules_count) {
            (*result)[u].submodules = calloc(submodules_count + 1, sizeof *(*result)[u].submodules);
            if (!(*result)[u].submodules) {
                ERRMEM;
                free_schema_info(*result);
                *result = NULL;
                ret = EXIT_FAILURE;
                goto cleanup;
            } else {
                v = 0;
                LY_TREE_FOR(modules->set.d[u]->child, iter) {
                    mod = ((struct lyd_node *)modules->set.d[u])->schema->module;
                    if (mod == iter->schema->module && !strcmp(iter->schema->name, "submodule")) {
                        LY_TREE_FOR(iter->child, child) {
                            if (mod != child->schema->module) {
                                continue;
                            } else if (!strcmp(child->schema->name, "name")) {
                                (*result)[u].submodules[v].name = strdup(((struct lyd_node_leaf_list *)child)->value_str);
                            } else if (!strcmp(child->schema->name, "revision")) {
                                (*result)[u].submodules[v].name = strdup(((struct lyd_node_leaf_list *)child)->value_str);
                            }
                        }
                    }
                }
            }
        }
    }

cleanup:
    nc_rpc_free(rpc);
    nc_reply_free(reply);
    ly_set_free(modules);

    if (session->status != NC_STATUS_RUNNING) {
        /* something bad heppened, discard the session */
        ERR("Session %d: invalid session, discarding.", nc_session_get_id(session));
        ret = EXIT_FAILURE;
    }

    return ret;
}

static int
build_schema_info_cpblts(char **cpblts, struct schema_info **result)
{
    unsigned int u, v;
    char *module_cpblt, *ptr, *ptr2;

    for (u = 0; cpblts[u]; ++u);
    (*result) = calloc(u + 1, sizeof **result);
    if (!(*result)) {
        ERRMEM;
        return EXIT_FAILURE;
    }

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
            for (ptr2 = ptr; *ptr && *ptr != '&'; ++ptr) {
                if (*ptr == ',') {
                    ly_set_add(&(*result)[v].features, (void *)strndup(ptr2, ptr - ptr2), LY_SET_OPT_USEASLIST);
                    ptr2 = ptr + 1;
                }
            }
            /* the last one */
            ly_set_add(&(*result)[v].features, (void *)strndup(ptr2, ptr - ptr2), LY_SET_OPT_USEASLIST);
        }
        ++v;
    }

    return EXIT_SUCCESS;
}

static int
nc_ctx_fill(struct nc_session *session, struct schema_info *modules, ly_module_imp_clb user_clb, void *user_data, int has_get_schema)
{
    int ret = EXIT_FAILURE;
    const struct lys_module *mod;
    unsigned int u, v;

    for (u = 0; modules[u].name; ++u) {
        /* skip import-only modules */
        if (!modules[u].implemented) {
            continue;
        }

        /* we can continue even if it fails */
        nc_ctx_load_module(session, modules[u].name, modules[u].revision, modules, user_clb, user_data, has_get_schema, &mod);

        if (!mod) {
            if (session->status != NC_STATUS_RUNNING) {
                /* something bad heppened, discard the session */
                ERR("Session %d: invalid session, discarding.", nc_session_get_id(session));
                goto cleanup;
            }

            /* all loading ways failed, the schema will be ignored in the received data */
            WRN("Failed to load schema \"%s@%s\".", modules[u].name, modules[u].revision ? modules[u].revision : "<latest>");
            session->flags |= NC_SESSION_CLIENT_NOT_STRICT;
        } else {
            /* set features - first disable all to enable specified then */
            lys_features_disable(mod, "*");
            for (v = 0; v < modules[u].features.number; v++) {
                lys_features_enable(mod, (const char*)modules[u].features.set.g[v]);
            }
        }
    }

    /* done */
    ret = EXIT_SUCCESS;

cleanup:

    return ret;
}

static int
nc_ctx_fill_ietf_netconf(struct nc_session *session, struct schema_info *modules, ly_module_imp_clb user_clb, void *user_data, int has_get_schema)
{
    unsigned int u, v;
    const struct lys_module *ietfnc;

    ietfnc = ly_ctx_get_module(session->ctx, "ietf-netconf", NULL, 1);
    if (!ietfnc) {
        nc_ctx_load_module(session, "ietf-netconf", NULL, modules, user_clb, user_data, has_get_schema, &ietfnc);
        if (!ietfnc) {
            WRN("Unable to find correct \"ietf-netconf\" schema, trying to use backup from \"%s\".", NC_SCHEMAS_DIR"/ietf-netconf.yin");
            ietfnc = lys_parse_path(session->ctx, NC_SCHEMAS_DIR"/ietf-netconf.yin", LYS_IN_YIN);
        }
    }
    if (!ietfnc) {
        ERR("Loading base NETCONF schema failed.");
        return 1;
    }

    /* set supported capabilities from ietf-netconf */
    for (u = 0; modules[u].name; ++u) {
        if (strcmp(modules[u].name, "ietf-netconf") || !modules[u].implemented) {
            continue;
        }

        lys_features_disable(ietfnc, "*");
        for (v = 0; v < modules[u].features.number; v++) {
            lys_features_enable(ietfnc, (const char*)modules[u].features.set.g[v]);
        }
    }

    return 0;
}

int
nc_ctx_check_and_fill(struct nc_session *session)
{
    int i, get_schema_support = 0, yanglib_support = 0, ret = -1;
    ly_module_imp_clb old_clb = NULL;
    void *old_data = NULL;
    const struct lys_module *mod = NULL;
    char *revision;
    struct schema_info *server_modules = NULL, *sm = NULL;

    assert(session->opts.client.cpblts && session->ctx);

    /* store the original user's callback, we will be switching between local search, get-schema and user callback */
    old_clb = ly_ctx_get_module_imp_clb(session->ctx, &old_data);

    /* switch off default searchpath to use only our callback integrating modifying searchpath algorithm to limit
     * schemas only to those present on the server side */
    ly_ctx_set_disable_searchdirs(session->ctx);

    /* our callback is set later with appropriate data */
    ly_ctx_set_module_imp_clb(session->ctx, NULL, NULL);

    /* check if get-schema and yang-library is supported */
    for (i = 0; session->opts.client.cpblts[i]; ++i) {
        if (!strncmp(session->opts.client.cpblts[i], "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?", 52)) {
            get_schema_support = 1 + i;
            if (yanglib_support) {
                break;
            }
        } else if (!strncmp(session->opts.client.cpblts[i], "urn:ietf:params:netconf:capability:yang-library:1.0", 51)) {
            yanglib_support = 1 + i;
            if (get_schema_support) {
                break;
            }
        }
    }

    /* get information about server's schemas from capabilities list until we will have yang-library */
    if (build_schema_info_cpblts(session->opts.client.cpblts, &server_modules) || !server_modules) {
        ERR("Session %u: unable to get server's schema information from the <hello>'s capabilities.", session->id);
        goto cleanup;
    }

    /* get-schema is supported, load local ietf-netconf-monitoring so we can create <get-schema> RPCs */
    if (get_schema_support && !ly_ctx_get_module(session->ctx, "ietf-netconf-monitoring", NULL, 1)) {
        if (nc_ctx_load_module(session, "ietf-netconf-monitoring", NULL, server_modules, old_clb, old_data, 0, &mod)) {
            WRN("Session %u: loading NETCONF monitoring schema failed, cannot use <get-schema>.", session->id);
            get_schema_support = 0;
        }
    }

    /* load base model disregarding whether it's in capabilities (but NETCONF capabilities are used to enable features) */
    if (nc_ctx_fill_ietf_netconf(session, server_modules, old_clb, old_data, get_schema_support)) {
        goto cleanup;
    }

    /* get correct version of ietf-yang-library into context */
    if (yanglib_support) {
        /* use get schema to get server's ietf-yang-library */
        revision = strstr(session->opts.client.cpblts[yanglib_support - 1], "revision=");
        if (!revision) {
            WRN("Session %u: loading NETCONF ietf-yang-library schema failed, missing revision in NETCONF <hello> message.", session->id);
            WRN("Session %u: unable to automatically use <get-schema>.", session->id);
            yanglib_support = 0;
        } else {
            revision = strndup(&revision[9], 10);
            if (nc_ctx_load_module(session, "ietf-yang-library", revision, server_modules, old_clb, old_data, get_schema_support, &mod)) {
                WRN("Session %u: loading NETCONF ietf-yang-library schema failed, unable to automatically use <get-schema>.", session->id);
                yanglib_support = 0;
            }
            free(revision);
        }
    }

    /* prepare structured information about server's schemas */
    if (yanglib_support) {
        if (build_schema_info_yl(session, &sm)) {
            goto cleanup;
        } else if (!sm) {
            VRB("Session %u: trying to use capabilities instead of ietf-yang-library data.", session->id);
        } else {
            /* prefer yang-library information, currently we have it from capabilities used for getting correct yang-library schema */
            free_schema_info(server_modules);
            server_modules = sm;
        }
    }

    if (nc_ctx_fill(session, server_modules, old_clb, old_data, get_schema_support)) {
        goto cleanup;
    }

    /* succsess */
    ret = 0;

    if (session->flags & NC_SESSION_CLIENT_NOT_STRICT) {
        WRN("Session %u: some models failed to be loaded, any data from these models (and any other unknown) will be ignored.", session->id);
    }

cleanup:
    free_schema_info(server_modules);

    /* set user callback back */
    ly_ctx_set_module_imp_clb(session->ctx, old_clb, old_data);
    ly_ctx_unset_disable_searchdirs(session->ctx);

    return ret;
}

API struct nc_session *
nc_connect_inout(int fdin, int fdout, struct ly_ctx *ctx)
{
    struct nc_session *session;

    if (fdin < 0) {
        ERRARG("fdin");
        return NULL;
    } else if (fdout < 0) {
        ERRARG("fdout");
        return NULL;
    }

    /* prepare session structure */
    session = nc_new_session(NC_CLIENT, 0);
    if (!session) {
        ERRMEM;
        return NULL;
    }
    session->status = NC_STATUS_STARTING;

    /* transport specific data */
    session->ti_type = NC_TI_FD;
    session->ti.fd.in = fdin;
    session->ti.fd.out = fdout;

    /* assign context (dicionary needed for handshake) */
    if (!ctx) {
        ctx = ly_ctx_new(NC_SCHEMAS_DIR, LY_CTX_NOYANGLIBRARY);
        /* definitely should not happen, but be ready */
        if (!ctx && !(ctx = ly_ctx_new(NULL, 0))) {
            /* that's just it */
            goto fail;
        }
    } else {
        session->flags |= NC_SESSION_SHAREDCTX;
    }
    session->ctx = ctx;

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

/*
   Helper for a non-blocking connect (which is required because of the locking
   concept for e.g. call home settings). For more details see nc_sock_connect().
 */
static int
_non_blocking_connect(int timeout, int* sock_pending, struct addrinfo *res)
{
    int flags, ret=0;
    int sock = -1;
    fd_set  wset;
    struct timeval ts;
    int error = 0;
    socklen_t len = sizeof(int);

    if (sock_pending && *sock_pending != -1) {
        VRB("Trying to connect the pending socket=%d.", *sock_pending );
        sock = *sock_pending;
    } else {
        assert(res);
        VRB("Trying to connect via %s.", (res->ai_family == AF_INET6) ? "IPv6" : "IPv4");
        /* Connect to a server */
        sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock == -1) {
            ERR("socket couldn't be created.", strerror(errno));
            return -1;
        }
        /* make the socket non-blocking */
        if (((flags = fcntl(sock, F_GETFL)) == -1) || (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)) {
            ERR("Fcntl failed (%s).", strerror(errno));
            goto cleanup;
        }
        /* non-blocking connect! */
        if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
            if (errno != EINPROGRESS) {
                /* network connection failed, try another resource */
                ERR("connect failed: (%s).", strerror(errno));
                goto cleanup;
            }
        }
    }
    ts.tv_sec = timeout;
    ts.tv_usec = 0;

    FD_ZERO(&wset);
    FD_SET(sock, &wset);

    if ((ret = select(sock + 1, NULL, &wset, NULL, (timeout != -1) ? &ts : NULL)) < 0) {
        ERR("select failed: (%s).", strerror(errno));
        goto cleanup;
    }

    if (ret == 0) {   //we had a timeout
        VRB("timed out after %ds (%s).", timeout, strerror(errno));
        if (sock_pending) {
            /* no sock-close, we'll try it again */
            *sock_pending = sock;
        } else {
            close(sock);
        }
        return -1;
    }

    /* check the usability of the socket */
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        ERR("getsockopt failed: (%s).", strerror(errno));
        goto cleanup;
    }
    if (error == ECONNREFUSED) {
        /* network connection failed, try another resource */
        VRB("getsockopt error: (%s).", strerror(error));
        errno = error;
        goto cleanup;
    }

    /* enable keep-alive */
    if (nc_sock_enable_keepalive(sock)) {
        goto cleanup;
    }

    return sock;

cleanup:
    if (sock_pending) {
        *sock_pending = -1;
    }
    close(sock);
    return -1;
}

/* A given timeout value limits the time how long the function blocks. If it has to block
   only for some seconds, a socket connection might not yet have been fully established.
   Therefore the active (pending) socket will be stored in *sock_pending, but the return
   value will be -1. In such a case a subsequent invokation is required, by providing the
   stored sock_pending, again.
   In general, if this function returns -1, when a timeout has been given, this function
   has to be invoked, until it returns a valid socket.
 */
int
nc_sock_connect(const char* host, uint16_t port, int timeout, int* sock_pending)
{
    int i;
    int sock = sock_pending?*sock_pending:-1;
    struct addrinfo hints, *res_list, *res;
    char port_s[6]; /* length of string representation of short int */

    VRB("nc_sock_connect(%s, %u, %d, %d)", host, port, timeout, sock);

    /* no pending socket */
    if (sock == -1) {
        /* Connect to a server */
        snprintf(port_s, 6, "%u", port);
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        i = getaddrinfo(host, port_s, &hints, &res_list);
        if (i != 0) {
            ERR("Unable to translate the host address (%s).", gai_strerror(i));
            return -1;
        }

        for (res = res_list; res != NULL; res = res->ai_next) {
            sock = _non_blocking_connect(timeout, sock_pending, res);
            if (sock == -1 && (!sock_pending || *sock_pending == -1)) {
                /* try the next resource */
                continue;
            }
            VRB("Successfully connected to %s:%s over %s.", host, port_s, (res->ai_family == AF_INET6) ? "IPv6" : "IPv4");
            break;
        }
        freeaddrinfo(res_list);

    } else {
        /* try to get a connection with the pending socket */
        assert(sock_pending);
        sock = _non_blocking_connect(timeout, sock_pending, NULL);
    }

    return sock;
}

static NC_MSG_TYPE
get_msg(struct nc_session *session, int timeout, uint64_t msgid, struct lyxml_elem **msg)
{
    char *ptr;
    const char *str_msgid;
    uint64_t cur_msgid;
    struct lyxml_elem *xml;
    struct nc_msg_cont *cont, **cont_ptr;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */

    /* try to get notification from the session's queue */
    if (!msgid && session->opts.client.notifs) {
        cont = session->opts.client.notifs;
        session->opts.client.notifs = cont->next;

        xml = cont->msg;
        free(cont);

        msgtype = NC_MSG_NOTIF;
    }

    /* try to get rpc-reply from the session's queue */
    if (msgid && session->opts.client.replies) {
        cont = session->opts.client.replies;
        session->opts.client.replies = cont->next;

        xml = cont->msg;
        free(cont);

        msgtype = NC_MSG_REPLY;
    }

    if (!msgtype) {
        /* read message from wire */
        msgtype = nc_read_msg_poll_io(session, timeout, &xml);
    }

    /* we read rpc-reply, want a notif */
    if (!msgid && (msgtype == NC_MSG_REPLY)) {
        cont_ptr = &session->opts.client.replies;
        while (*cont_ptr) {
            cont_ptr = &((*cont_ptr)->next);
        }
        *cont_ptr = malloc(sizeof **cont_ptr);
        if (!*cont_ptr) {
            ERRMEM;
            lyxml_free(session->ctx, xml);
            return NC_MSG_ERROR;
        }
        (*cont_ptr)->msg = xml;
        (*cont_ptr)->next = NULL;
    }

    /* we read notif, want a rpc-reply */
    if (msgid && (msgtype == NC_MSG_NOTIF)) {
        if (!session->opts.client.ntf_tid) {
            ERR("Session %u: received a <notification> but session is not subscribed.", session->id);
            lyxml_free(session->ctx, xml);
            return NC_MSG_ERROR;
        }

        cont_ptr = &session->opts.client.notifs;
        while (*cont_ptr) {
            cont_ptr = &((*cont_ptr)->next);
        }
        *cont_ptr = malloc(sizeof **cont_ptr);
        if (!*cont_ptr) {
            ERRMEM;
            lyxml_free(session->ctx, xml);
            return NC_MSG_ERROR;
        }
        (*cont_ptr)->msg = xml;
        (*cont_ptr)->next = NULL;
    }

    switch (msgtype) {
    case NC_MSG_NOTIF:
        if (!msgid) {
            *msg = xml;
        }
        break;

    case NC_MSG_REPLY:
        if (msgid) {
            /* check message-id */
            str_msgid = lyxml_get_attr(xml, "message-id", NULL);
            if (!str_msgid) {
                WRN("Session %u: received a <rpc-reply> without a message-id.", session->id);
            } else {
                cur_msgid = strtoul(str_msgid, &ptr, 10);
                if (cur_msgid != msgid) {
                    ERR("Session %u: received a <rpc-reply> with an unexpected message-id \"%s\".",
                        session->id, str_msgid);
                    msgtype = NC_MSG_REPLY_ERR_MSGID;
                }
            }
            *msg = xml;
        }
        break;

    case NC_MSG_HELLO:
        ERR("Session %u: received another <hello> message.", session->id);
        lyxml_free(session->ctx, xml);
        msgtype = NC_MSG_ERROR;
        break;

    case NC_MSG_RPC:
        ERR("Session %u: received <rpc> from a NETCONF server.", session->id);
        lyxml_free(session->ctx, xml);
        msgtype = NC_MSG_ERROR;
        break;

    default:
        /* NC_MSG_WOULDBLOCK and NC_MSG_ERROR - pass it out;
         * NC_MSG_NONE is not returned by nc_read_msg()
         */
        break;
    }

    return msgtype;
}

/* cannot strictly fail, but does not need to fill any error parameter at all */
static void
parse_rpc_error(struct ly_ctx *ctx, struct lyxml_elem *xml, struct nc_err *err)
{
    struct lyxml_elem *iter, *next, *info;

    LY_TREE_FOR(xml->child, iter) {
        if (!iter->ns) {
            if (iter->content) {
                WRN("<rpc-error> child \"%s\" with value \"%s\" without namespace.", iter->name, iter->content);
            } else {
                WRN("<rpc-error> child \"%s\" without namespace.", iter->name);
            }
            continue;
        } else if (strcmp(iter->ns->value, NC_NS_BASE)) {
            if (iter->content) {
                WRN("<rpc-error> child \"%s\" with value \"%s\" in an unknown namespace \"%s\".",
                    iter->name, iter->content, iter->ns->value);
            } else {
                WRN("<rpc-error> child \"%s\" in an unknown namespace \"%s\".", iter->name, iter->ns->value);
            }
            continue;
        }

        if (!strcmp(iter->name, "error-type")) {
            if (!iter->content || (strcmp(iter->content, "transport") && strcmp(iter->content, "rpc")
                    && strcmp(iter->content, "protocol") && strcmp(iter->content, "application"))) {
                WRN("<rpc-error> <error-type> unknown value \"%s\".", (iter->content ? iter->content : ""));
            } else if (err->type) {
                WRN("<rpc-error> <error-type> duplicated.");
            } else {
                err->type = lydict_insert(ctx, iter->content, 0);
            }
        } else if (!strcmp(iter->name, "error-tag")) {
            if (!iter->content || (strcmp(iter->content, "in-use") && strcmp(iter->content, "invalid-value")
                    && strcmp(iter->content, "too-big") && strcmp(iter->content, "missing-attribute")
                    && strcmp(iter->content, "bad-attribute") && strcmp(iter->content, "unknown-attribute")
                    && strcmp(iter->content, "missing-element") && strcmp(iter->content, "bad-element")
                    && strcmp(iter->content, "unknown-element") && strcmp(iter->content, "unknown-namespace")
                    && strcmp(iter->content, "access-denied") && strcmp(iter->content, "lock-denied")
                    && strcmp(iter->content, "resource-denied") && strcmp(iter->content, "rollback-failed")
                    && strcmp(iter->content, "data-exists") && strcmp(iter->content, "data-missing")
                    && strcmp(iter->content, "operation-not-supported") && strcmp(iter->content, "operation-failed")
                    && strcmp(iter->content, "malformed-message"))) {
                WRN("<rpc-error> <error-tag> unknown value \"%s\".", (iter->content ? iter->content : ""));
            } else if (err->tag) {
                WRN("<rpc-error> <error-tag> duplicated.");
            } else {
                err->tag = lydict_insert(ctx, iter->content, 0);
            }
        } else if (!strcmp(iter->name, "error-severity")) {
            if (!iter->content || (strcmp(iter->content, "error") && strcmp(iter->content, "warning"))) {
                WRN("<rpc-error> <error-severity> unknown value \"%s\".", (iter->content ? iter->content : ""));
            } else if (err->severity) {
                WRN("<rpc-error> <error-severity> duplicated.");
            } else {
                err->severity = lydict_insert(ctx, iter->content, 0);
            }
        } else if (!strcmp(iter->name, "error-app-tag")) {
            if (err->apptag) {
                WRN("<rpc-error> <error-app-tag> duplicated.");
            } else {
                err->apptag = lydict_insert(ctx, (iter->content ? iter->content : ""), 0);
            }
        } else if (!strcmp(iter->name, "error-path")) {
            if (err->path) {
                WRN("<rpc-error> <error-path> duplicated.");
            } else {
                err->path = lydict_insert(ctx, (iter->content ? iter->content : ""), 0);
            }
        } else if (!strcmp(iter->name, "error-message")) {
            if (err->message) {
                WRN("<rpc-error> <error-message> duplicated.");
            } else {
                err->message_lang = lyxml_get_attr(iter, "xml:lang", NULL);
                if (err->message_lang) {
                    err->message_lang = lydict_insert(ctx, err->message_lang, 0);
                } else {
                    VRB("<rpc-error> <error-message> without the recommended \"xml:lang\" attribute.");
                }
                err->message = lydict_insert(ctx, (iter->content ? iter->content : ""), 0);
            }
        } else if (!strcmp(iter->name, "error-info")) {
            LY_TREE_FOR_SAFE(iter->child, next, info) {
                if (info->ns && !strcmp(info->ns->value, NC_NS_BASE)) {
                    if (!strcmp(info->name, "session-id")) {
                        if (err->sid) {
                            WRN("<rpc-error> <error-info> <session-id> duplicated.");
                        } else {
                            err->sid = lydict_insert(ctx, (info->content ? info->content : ""), 0);
                        }
                    } else if (!strcmp(info->name, "bad-attribute")) {
                        ++err->attr_count;
                        err->attr = nc_realloc(err->attr, err->attr_count * sizeof *err->attr);
                        if (!err->attr) {
                            ERRMEM;
                            return;
                        }
                        err->attr[err->attr_count - 1] = lydict_insert(ctx, (info->content ? info->content : ""), 0);
                    } else if (!strcmp(info->name, "bad-element")) {
                        ++err->elem_count;
                        err->elem = nc_realloc(err->elem, err->elem_count * sizeof *err->elem);
                        if (!err->elem) {
                            ERRMEM;
                            return;
                        }
                        err->elem[err->elem_count - 1] = lydict_insert(ctx, (info->content ? info->content : ""), 0);
                    } else if (!strcmp(info->name, "bad-namespace")) {
                        ++err->ns_count;
                        err->ns = nc_realloc(err->ns, err->ns_count * sizeof *err->ns);
                        if (!err->ns) {
                            ERRMEM;
                            return;
                        }
                        err->ns[err->ns_count - 1] = lydict_insert(ctx, (info->content ? info->content : ""), 0);
                    } else {
                        if (info->content) {
                            WRN("<rpc-error> <error-info> unknown child \"%s\" with value \"%s\".",
                                info->name, info->content);
                        } else {
                            WRN("<rpc-error> <error-info> unknown child \"%s\".", info->name);
                        }
                    }
                } else {
                    lyxml_unlink(ctx, info);
                    ++err->other_count;
                    err->other = nc_realloc(err->other, err->other_count * sizeof *err->other);
                    if (!err->other) {
                        ERRMEM;
                        return;
                    }
                    err->other[err->other_count - 1] = info;
                }
            }
        } else {
            if (iter->content) {
                WRN("<rpc-error> unknown child \"%s\" with value \"%s\".", iter->name, iter->content);
            } else {
                WRN("<rpc-error> unknown child \"%s\".", iter->name);
            }
        }
    }
}

static struct nc_reply *
parse_reply(struct ly_ctx *ctx, struct lyxml_elem *xml, struct nc_rpc *rpc, int parseroptions)
{
    struct lyxml_elem *iter;
    struct lyd_node *data = NULL, *rpc_act = NULL;
    struct nc_client_reply_error *error_rpl;
    struct nc_reply_data *data_rpl;
    struct nc_reply *reply = NULL;
    struct nc_rpc_act_generic *rpc_gen;
    int i;

    if (!xml->child) {
        ERR("An empty <rpc-reply>.");
        return NULL;
    }

    /* rpc-error */
    if (!strcmp(xml->child->name, "rpc-error") && xml->child->ns && !strcmp(xml->child->ns->value, NC_NS_BASE)) {
        /* count and check elements */
        i = 0;
        LY_TREE_FOR(xml->child, iter) {
            if (strcmp(iter->name, "rpc-error")) {
                ERR("<rpc-reply> content mismatch (<rpc-error> and <%s>).", iter->name);
                return NULL;
            } else if (!iter->ns) {
                ERR("<rpc-reply> content mismatch (<rpc-error> without namespace).");
                return NULL;
            } else if (strcmp(iter->ns->value, NC_NS_BASE)) {
                ERR("<rpc-reply> content mismatch (<rpc-error> with NS \"%s\").", iter->ns->value);
                return NULL;
            }
            ++i;
        }

        error_rpl = malloc(sizeof *error_rpl);
        if (!error_rpl) {
            ERRMEM;
            return NULL;
        }
        error_rpl->type = NC_RPL_ERROR;
        error_rpl->err = calloc(i, sizeof *error_rpl->err);
        if (!error_rpl->err) {
            ERRMEM;
            free(error_rpl);
            return NULL;
        }
        error_rpl->count = i;
        error_rpl->ctx = ctx;
        reply = (struct nc_reply *)error_rpl;

        i = 0;
        LY_TREE_FOR(xml->child, iter) {
            parse_rpc_error(ctx, iter, error_rpl->err + i);
            ++i;
        }

    /* ok */
    } else if (!strcmp(xml->child->name, "ok") && xml->child->ns && !strcmp(xml->child->ns->value, NC_NS_BASE)) {
        if (xml->child->next) {
            ERR("<rpc-reply> content mismatch (<ok> and <%s>).", xml->child->next->name);
            return NULL;
        }
        reply = malloc(sizeof *reply);
        if (!reply) {
            ERRMEM;
            return NULL;
        }
        reply->type = NC_RPL_OK;

    /* some RPC output */
    } else {
        switch (rpc->type) {
        case NC_RPC_ACT_GENERIC:
            rpc_gen = (struct nc_rpc_act_generic *)rpc;

            if (rpc_gen->has_data) {
                rpc_act = lyd_dup(rpc_gen->content.data, 1);
                if (!rpc_act) {
                    ERR("Failed to duplicate a generic RPC/action.");
                    return NULL;
                }
            } else {
                rpc_act = lyd_parse_mem(ctx, rpc_gen->content.xml_str, LYD_XML, LYD_OPT_RPC | parseroptions, NULL);
                if (!rpc_act) {
                    ERR("Failed to parse a generic RPC/action XML.");
                    return NULL;
                }
            }
            break;

        case NC_RPC_GETCONFIG:
        case NC_RPC_GET:
            if (!xml->child->child) {
                /* we did not receive any data */
                data_rpl = malloc(sizeof *data_rpl);
                if (!data_rpl) {
                    ERRMEM;
                    return NULL;
                }
                data_rpl->type = NC_RPL_DATA;
                data_rpl->data = NULL;
                return (struct nc_reply *)data_rpl;
            }

            /* special treatment */
            data = lyd_parse_xml(ctx, &xml->child->child,
                                 LYD_OPT_DESTRUCT | (rpc->type == NC_RPC_GETCONFIG ? LYD_OPT_GETCONFIG : LYD_OPT_GET)
                                 | parseroptions);
            if (!data) {
                ERR("Failed to parse <%s> reply.", (rpc->type == NC_RPC_GETCONFIG ? "get-config" : "get"));
                return NULL;
            }
            break;

        case NC_RPC_GETSCHEMA:
            rpc_act = lyd_new(NULL, ly_ctx_get_module(ctx, "ietf-netconf-monitoring", NULL, 1), "get-schema");
            if (!rpc_act) {
                ERRINT;
                return NULL;
            }
            break;

        case NC_RPC_EDIT:
        case NC_RPC_COPY:
        case NC_RPC_DELETE:
        case NC_RPC_LOCK:
        case NC_RPC_UNLOCK:
        case NC_RPC_KILL:
        case NC_RPC_COMMIT:
        case NC_RPC_DISCARD:
        case NC_RPC_CANCEL:
        case NC_RPC_VALIDATE:
        case NC_RPC_SUBSCRIBE:
            /* there is no output defined */
            ERR("Unexpected data reply (root elem \"%s\").", xml->child->name);
            return NULL;
        default:
            ERRINT;
            return NULL;
        }

        data_rpl = malloc(sizeof *data_rpl);
        if (!data_rpl) {
            ERRMEM;
            return NULL;
        }
        data_rpl->type = NC_RPL_DATA;
        if (!data) {
            data_rpl->data = lyd_parse_xml(ctx, &xml->child, LYD_OPT_RPCREPLY | LYD_OPT_DESTRUCT | parseroptions,
                                           rpc_act, NULL);
        } else {
            /* <get>, <get-config> */
            data_rpl->data = data;
        }
        lyd_free_withsiblings(rpc_act);
        if (!data_rpl->data) {
            ERR("Failed to parse <rpc-reply>.");
            free(data_rpl);
            return NULL;
        }
        reply = (struct nc_reply *)data_rpl;
    }

    return reply;
}

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)

int
nc_client_ch_add_bind_listen(const char *address, uint16_t port, NC_TRANSPORT_IMPL ti)
{
    int sock;

    if (!address) {
        ERRARG("address");
        return -1;
    } else if (!port) {
        ERRARG("port");
        return -1;
    }

    sock = nc_sock_listen(address, port);
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

    client_opts.ch_bind_ti = nc_realloc(client_opts.ch_bind_ti, client_opts.ch_bind_count * sizeof *client_opts.ch_bind_ti);
    if (!client_opts.ch_bind_ti) {
        ERRMEM;
        close(sock);
        return -1;
    }
    client_opts.ch_bind_ti[client_opts.ch_bind_count - 1] = ti;

    client_opts.ch_binds[client_opts.ch_bind_count - 1].address = strdup(address);
    if (!client_opts.ch_binds[client_opts.ch_bind_count - 1].address) {
        ERRMEM;
        close(sock);
        return -1;
    }
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
            free((char *)client_opts.ch_binds[i].address);

            ret = 0;
        }
        free(client_opts.ch_binds);
        client_opts.ch_binds = NULL;
        client_opts.ch_bind_count = 0;
    } else {
        for (i = 0; i < client_opts.ch_bind_count; ++i) {
            if ((!address || !strcmp(client_opts.ch_binds[i].address, address))
                    && (!port || (client_opts.ch_binds[i].port == port))
                    && (!ti || (client_opts.ch_bind_ti[i] == ti))) {
                close(client_opts.ch_binds[i].sock);
                free((char *)client_opts.ch_binds[i].address);

                --client_opts.ch_bind_count;
                if (!client_opts.ch_bind_count) {
                    free(client_opts.ch_binds);
                    client_opts.ch_binds = NULL;
                } else if (i < client_opts.ch_bind_count) {
                    memcpy(&client_opts.ch_binds[i], &client_opts.ch_binds[client_opts.ch_bind_count], sizeof *client_opts.ch_binds);
                    client_opts.ch_bind_ti[i] = client_opts.ch_bind_ti[client_opts.ch_bind_count];
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
    int sock;
    char *host = NULL;
    uint16_t port, idx;

    if (!client_opts.ch_binds) {
        ERRINIT;
        return -1;
    } else if (!session) {
        ERRARG("session");
        return -1;
    }

    sock = nc_sock_accept_binds(client_opts.ch_binds, client_opts.ch_bind_count, timeout, &host, &port, &idx);

    if (sock < 1) {
        free(host);
        return sock;
    }

#ifdef NC_ENABLED_SSH
    if (client_opts.ch_bind_ti[idx] == NC_TI_LIBSSH) {
        *session = nc_accept_callhome_ssh_sock(sock, host, port, ctx, NC_TRANSPORT_TIMEOUT);
    } else
#endif
#ifdef NC_ENABLED_TLS
    if (client_opts.ch_bind_ti[idx] == NC_TI_OPENSSL) {
        *session = nc_accept_callhome_tls_sock(sock, host, port, ctx, NC_TRANSPORT_TIMEOUT);
    } else
#endif
    {
        close(sock);
        *session = NULL;
    }

    free(host);

    if (!(*session)) {
        return -1;
    }

    return 1;
}

#endif /* NC_ENABLED_SSH || NC_ENABLED_TLS */

API const char * const *
nc_session_get_cpblts(const struct nc_session *session)
{
    if (!session) {
        ERRARG("session");
        return NULL;
    }

    return (const char * const *)session->opts.client.cpblts;
}

API const char *
nc_session_cpblt(const struct nc_session *session, const char *capab)
{
    int i, len;

    if (!session) {
        ERRARG("session");
        return NULL;
    } else if (!capab) {
        ERRARG("capab");
        return NULL;
    }

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
    if (!session || (session->side != NC_CLIENT)) {
        ERRARG("session");
        return 0;
    }

    return session->opts.client.ntf_tid ? 1 : 0;
}

API void
nc_client_init(void)
{
    nc_init();
}

API void
nc_client_destroy(void)
{
    nc_client_set_schema_searchpath(NULL);
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
    nc_client_ch_del_bind(NULL, 0, 0);
#endif
#ifdef NC_ENABLED_SSH
    nc_client_ssh_destroy_opts();
#endif
#ifdef NC_ENABLED_TLS
    nc_client_tls_destroy_opts();
#endif
    nc_destroy();
}

API NC_MSG_TYPE
nc_recv_reply(struct nc_session *session, struct nc_rpc *rpc, uint64_t msgid, int timeout, int parseroptions, struct nc_reply **reply)
{
    struct lyxml_elem *xml;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */

    if (!session) {
        ERRARG("session");
        return NC_MSG_ERROR;
    } else if (!rpc) {
        ERRARG("rpc");
        return NC_MSG_ERROR;
    } else if (!reply) {
        ERRARG("reply");
        return NC_MSG_ERROR;
    } else if (parseroptions & LYD_OPT_TYPEMASK) {
        ERRARG("parseroptions");
        return NC_MSG_ERROR;
    } else if ((session->status != NC_STATUS_RUNNING) || (session->side != NC_CLIENT)) {
        ERR("Session %u: invalid session to receive RPC replies.", session->id);
        return NC_MSG_ERROR;
    }
    parseroptions &= ~(LYD_OPT_DESTRUCT | LYD_OPT_NOSIBLINGS);
    if (!(session->flags & NC_SESSION_CLIENT_NOT_STRICT)) {
        parseroptions &= LYD_OPT_STRICT;
    }
    /* no mechanism to check external dependencies is provided */
    parseroptions|= LYD_OPT_NOEXTDEPS;
    *reply = NULL;

    msgtype = get_msg(session, timeout, msgid, &xml);

    if ((msgtype == NC_MSG_REPLY) || (msgtype == NC_MSG_REPLY_ERR_MSGID)) {
        *reply = parse_reply(session->ctx, xml, rpc, parseroptions);
        lyxml_free(session->ctx, xml);
        if (!(*reply)) {
            return NC_MSG_ERROR;
        }
    }

    return msgtype;
}

API NC_MSG_TYPE
nc_recv_notif(struct nc_session *session, int timeout, struct nc_notif **notif)
{
    struct lyxml_elem *xml, *ev_time;
    NC_MSG_TYPE msgtype = 0; /* NC_MSG_ERROR */

    if (!session) {
        ERRARG("session");
        return NC_MSG_ERROR;
    } else if (!notif) {
        ERRARG("notif");
        return NC_MSG_ERROR;
    } else if (session->status != NC_STATUS_RUNNING || session->side != NC_CLIENT) {
        ERR("Session %u: invalid session to receive Notifications.", session->id);
        return NC_MSG_ERROR;
    }

    msgtype = get_msg(session, timeout, 0, &xml);

    if (msgtype == NC_MSG_NOTIF) {
        *notif = calloc(1, sizeof **notif);
        if (!*notif) {
            ERRMEM;
            lyxml_free(session->ctx, xml);
            return NC_MSG_ERROR;
        }

        /* eventTime */
        LY_TREE_FOR(xml->child, ev_time) {
            if (!strcmp(ev_time->name, "eventTime")) {
                (*notif)->datetime = lydict_insert(session->ctx, ev_time->content, 0);
                /* lyd_parse does not know this element */
                lyxml_free(session->ctx, ev_time);
                break;
            }
        }
        if (!(*notif)->datetime) {
            ERR("Session %u: notification is missing the \"eventTime\" element.", session->id);
            goto fail;
        }

        /* notification body */
        (*notif)->tree = lyd_parse_xml(session->ctx, &xml->child, LYD_OPT_NOTIF | LYD_OPT_DESTRUCT | LYD_OPT_NOEXTDEPS
                                       | (session->flags & NC_SESSION_CLIENT_NOT_STRICT ? 0 : LYD_OPT_STRICT), NULL);
        lyxml_free(session->ctx, xml);
        xml = NULL;
        if (!(*notif)->tree) {
            ERR("Session %u: failed to parse a new notification.", session->id);
            goto fail;
        }
    }

    return msgtype;

fail:
    lydict_remove(session->ctx, (*notif)->datetime);
    lyd_free((*notif)->tree);
    free(*notif);
    *notif = NULL;
    lyxml_free(session->ctx, xml);

    return NC_MSG_ERROR;
}

static void *
nc_recv_notif_thread(void *arg)
{
    struct nc_ntf_thread_arg *ntarg;
    struct nc_session *session;
    void (*notif_clb)(struct nc_session *session, const struct nc_notif *notif);
    struct nc_notif *notif;
    NC_MSG_TYPE msgtype;
    pthread_t *ntf_tid;

    pthread_detach(pthread_self());

    ntarg = (struct nc_ntf_thread_arg *)arg;
    session = ntarg->session;
    notif_clb = ntarg->notif_clb;
    free(ntarg);

    /* remember our allocated tid, we will be freeing it */
    ntf_tid = (pthread_t *)session->opts.client.ntf_tid;

    while (session->opts.client.ntf_tid) {
        msgtype = nc_recv_notif(session, NC_CLIENT_NOTIF_THREAD_SLEEP / 1000, &notif);
        if (msgtype == NC_MSG_NOTIF) {
            notif_clb(session, notif);
            if (!strcmp(notif->tree->schema->name, "notificationComplete")
                    && !strcmp(notif->tree->schema->module->name, "nc-notifications")) {
                nc_notif_free(notif);
                break;
            }
            nc_notif_free(notif);
        } else if ((msgtype == NC_MSG_ERROR) && (session->status != NC_STATUS_RUNNING)) {
            /* quit this thread once the session is broken */
            break;
        }

        usleep(NC_CLIENT_NOTIF_THREAD_SLEEP);
    }

    VRB("Session %u: notification thread exit.", session->id);
    session->opts.client.ntf_tid = NULL;
    free(ntf_tid);
    return NULL;
}

API int
nc_recv_notif_dispatch(struct nc_session *session, void (*notif_clb)(struct nc_session *session, const struct nc_notif *notif))
{
    struct nc_ntf_thread_arg *ntarg;
    int ret;

    if (!session) {
        ERRARG("session");
        return -1;
    } else if (!notif_clb) {
        ERRARG("notif_clb");
        return -1;
    } else if ((session->status != NC_STATUS_RUNNING) || (session->side != NC_CLIENT)) {
        ERR("Session %u: invalid session to receive Notifications.", session->id);
        return -1;
    } else if (session->opts.client.ntf_tid) {
        ERR("Session %u: separate notification thread is already running.", session->id);
        return -1;
    }

    ntarg = malloc(sizeof *ntarg);
    if (!ntarg) {
        ERRMEM;
        return -1;
    }
    ntarg->session = session;
    ntarg->notif_clb = notif_clb;

    /* just so that nc_recv_notif_thread() does not immediately exit, the value does not matter */
    session->opts.client.ntf_tid = malloc(sizeof *session->opts.client.ntf_tid);
    if (!session->opts.client.ntf_tid) {
        ERRMEM;
        free(ntarg);
        return -1;
    }

    ret = pthread_create((pthread_t *)session->opts.client.ntf_tid, NULL, nc_recv_notif_thread, ntarg);
    if (ret) {
        ERR("Session %u: failed to create a new thread (%s).", strerror(errno));
        free(ntarg);
        free((pthread_t *)session->opts.client.ntf_tid);
        session->opts.client.ntf_tid = NULL;
        return -1;
    }

    return 0;
}

API NC_MSG_TYPE
nc_send_rpc(struct nc_session *session, struct nc_rpc *rpc, int timeout, uint64_t *msgid)
{
    NC_MSG_TYPE r;
    int dofree = 1;
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
    struct lyd_node *data, *node;
    const struct lys_module *ietfnc = NULL, *ietfncmon, *notifs, *ietfncwd = NULL;
    char str[11];
    uint64_t cur_msgid;

    if (!session) {
        ERRARG("session");
        return NC_MSG_ERROR;
    } else if (!rpc) {
        ERRARG("rpc");
        return NC_MSG_ERROR;
    } else if (!msgid) {
        ERRARG("msgid");
        return NC_MSG_ERROR;
    } else if (session->status != NC_STATUS_RUNNING || session->side != NC_CLIENT) {
        ERR("Session %u: invalid session to send RPCs.", session->id);
        return NC_MSG_ERROR;
    }

    if ((rpc->type != NC_RPC_GETSCHEMA) && (rpc->type != NC_RPC_ACT_GENERIC) && (rpc->type != NC_RPC_SUBSCRIBE)) {
        ietfnc = ly_ctx_get_module(session->ctx, "ietf-netconf", NULL, 1);
        if (!ietfnc) {
            ERR("Session %u: missing \"ietf-netconf\" schema in the context.", session->id);
            return NC_MSG_ERROR;
        }
    }

    switch (rpc->type) {
    case NC_RPC_ACT_GENERIC:
        rpc_gen = (struct nc_rpc_act_generic *)rpc;

        if (rpc_gen->has_data) {
            data = rpc_gen->content.data;
            dofree = 0;
        } else {
            data = lyd_parse_mem(session->ctx, rpc_gen->content.xml_str, LYD_XML, LYD_OPT_RPC | LYD_OPT_NOEXTDEPS
                                 | (session->flags & NC_SESSION_CLIENT_NOT_STRICT ? 0 : LYD_OPT_STRICT), NULL);
            if (!data) {
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_GETCONFIG:
        rpc_gc = (struct nc_rpc_getconfig *)rpc;

        data = lyd_new(NULL, ietfnc, "get-config");
        node = lyd_new(data, ietfnc, "source");
        node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_gc->source], NULL);
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        if (rpc_gc->filter) {
            if (!rpc_gc->filter[0] || (rpc_gc->filter[0] == '<')) {
                node = lyd_new_anydata(data, ietfnc, "filter", rpc_gc->filter, LYD_ANYDATA_SXML);
                lyd_insert_attr(node, NULL, "type", "subtree");
            } else {
                node = lyd_new_anydata(data, ietfnc, "filter", NULL, LYD_ANYDATA_CONSTSTRING);
                lyd_insert_attr(node, NULL, "type", "xpath");
                lyd_insert_attr(node, NULL, "select", rpc_gc->filter);
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_gc->wd_mode) {
            if (!ietfncwd) {
                ietfncwd = ly_ctx_get_module(session->ctx, "ietf-netconf-with-defaults", NULL, 1);
                if (!ietfncwd) {
                    ERR("Session %u: missing \"ietf-netconf-with-defaults\" schema in the context.", session->id);
                    return NC_MSG_ERROR;
                }
            }
            switch (rpc_gc->wd_mode) {
            case NC_WD_UNKNOWN:
                /* cannot get here */
                break;
            case NC_WD_ALL:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all");
                break;
            case NC_WD_ALL_TAG:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all-tagged");
                break;
            case NC_WD_TRIM:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "trim");
                break;
            case NC_WD_EXPLICIT:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "explicit");
                break;
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_EDIT:
        rpc_e = (struct nc_rpc_edit *)rpc;

        data = lyd_new(NULL, ietfnc, "edit-config");
        node = lyd_new(data, ietfnc, "target");
        node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_e->target], NULL);
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }

        if (rpc_e->default_op) {
            node = lyd_new_leaf(data, ietfnc, "default-operation", rpcedit_dfltop2str[rpc_e->default_op]);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_e->test_opt) {
            node = lyd_new_leaf(data, ietfnc, "test-option", rpcedit_testopt2str[rpc_e->test_opt]);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_e->error_opt) {
            node = lyd_new_leaf(data, ietfnc, "error-option", rpcedit_erropt2str[rpc_e->error_opt]);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (!rpc_e->edit_cont[0] || (rpc_e->edit_cont[0] == '<')) {
            node = lyd_new_anydata(data, ietfnc, "config", rpc_e->edit_cont, LYD_ANYDATA_SXML);
        } else {
            node = lyd_new_leaf(data, ietfnc, "url", rpc_e->edit_cont);
        }
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        break;

    case NC_RPC_COPY:
        rpc_cp = (struct nc_rpc_copy *)rpc;

        data = lyd_new(NULL, ietfnc, "copy-config");
        node = lyd_new(data, ietfnc, "target");
        if (rpc_cp->url_trg) {
            node = lyd_new_leaf(node, ietfnc, "url", rpc_cp->url_trg);
        } else {
            node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_cp->target], NULL);
        }
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }

        node = lyd_new(data, ietfnc, "source");
        if (rpc_cp->url_config_src) {
            if (!rpc_cp->url_config_src[0] || (rpc_cp->url_config_src[0] == '<')) {
                node = lyd_new_anydata(node, ietfnc, "config", rpc_cp->url_config_src, LYD_ANYDATA_SXML);
            } else {
                node = lyd_new_leaf(node, ietfnc, "url", rpc_cp->url_config_src);
            }
        } else {
            node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_cp->source], NULL);
        }
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }

        if (rpc_cp->wd_mode) {
            if (!ietfncwd) {
                ietfncwd = ly_ctx_get_module(session->ctx, "ietf-netconf-with-defaults", NULL, 1);
                if (!ietfncwd) {
                    ERR("Session %u: missing \"ietf-netconf-with-defaults\" schema in the context.", session->id);
                    return NC_MSG_ERROR;
                }
            }
            switch (rpc_cp->wd_mode) {
            case NC_WD_UNKNOWN:
                /* cannot get here */
                break;
            case NC_WD_ALL:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all");
                break;
            case NC_WD_ALL_TAG:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all-tagged");
                break;
            case NC_WD_TRIM:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "trim");
                break;
            case NC_WD_EXPLICIT:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "explicit");
                break;
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_DELETE:
        rpc_del = (struct nc_rpc_delete *)rpc;

        data = lyd_new(NULL, ietfnc, "delete-config");
        node = lyd_new(data, ietfnc, "target");
        if (rpc_del->url) {
            node = lyd_new_leaf(node, ietfnc, "url", rpc_del->url);
        } else {
            node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_del->target], NULL);
        }
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        break;

    case NC_RPC_LOCK:
        rpc_lock = (struct nc_rpc_lock *)rpc;

        data = lyd_new(NULL, ietfnc, "lock");
        node = lyd_new(data, ietfnc, "target");
        node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_lock->target], NULL);
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        break;

    case NC_RPC_UNLOCK:
        rpc_lock = (struct nc_rpc_lock *)rpc;

        data = lyd_new(NULL, ietfnc, "unlock");
        node = lyd_new(data, ietfnc, "target");
        node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_lock->target], NULL);
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        break;

    case NC_RPC_GET:
        rpc_g = (struct nc_rpc_get *)rpc;

        data = lyd_new(NULL, ietfnc, "get");
        if (rpc_g->filter) {
            if (!rpc_g->filter[0] || (rpc_g->filter[0] == '<')) {
                node = lyd_new_anydata(data, ietfnc, "filter", rpc_g->filter, LYD_ANYDATA_SXML);
                lyd_insert_attr(node, NULL, "type", "subtree");
            } else {
                node = lyd_new_anydata(data, ietfnc, "filter", NULL, LYD_ANYDATA_CONSTSTRING);
                lyd_insert_attr(node, NULL, "type", "xpath");
                lyd_insert_attr(node, NULL, "select", rpc_g->filter);
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_g->wd_mode) {
            if (!ietfncwd) {
                ietfncwd = ly_ctx_get_module(session->ctx, "ietf-netconf-with-defaults", NULL, 1);
                if (!ietfncwd) {
                    ERR("Session %u: missing \"ietf-netconf-with-defaults\" schema in the context.", session->id);
                    lyd_free(data);
                    return NC_MSG_ERROR;
                }
            }
            switch (rpc_g->wd_mode) {
            case NC_WD_ALL:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all");
                break;
            case NC_WD_ALL_TAG:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "report-all-tagged");
                break;
            case NC_WD_TRIM:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "trim");
                break;
            case NC_WD_EXPLICIT:
                node = lyd_new_leaf(data, ietfncwd, "with-defaults", "explicit");
                break;
            default:
                /* cannot get here */
                node = NULL;
                break;
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_KILL:
        rpc_k = (struct nc_rpc_kill *)rpc;

        data = lyd_new(NULL, ietfnc, "kill-session");
        sprintf(str, "%u", rpc_k->sid);
        lyd_new_leaf(data, ietfnc, "session-id", str);
        break;

    case NC_RPC_COMMIT:
        rpc_com = (struct nc_rpc_commit *)rpc;

        data = lyd_new(NULL, ietfnc, "commit");
        if (rpc_com->confirmed) {
            lyd_new_leaf(data, ietfnc, "confirmed", NULL);
        }

        if (rpc_com->confirm_timeout) {
            sprintf(str, "%u", rpc_com->confirm_timeout);
            lyd_new_leaf(data, ietfnc, "confirm-timeout", str);
        }

        if (rpc_com->persist) {
            node = lyd_new_leaf(data, ietfnc, "persist", rpc_com->persist);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_com->persist_id) {
            node = lyd_new_leaf(data, ietfnc, "persist-id", rpc_com->persist_id);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_DISCARD:
        data = lyd_new(NULL, ietfnc, "discard-changes");
        break;

    case NC_RPC_CANCEL:
        rpc_can = (struct nc_rpc_cancel *)rpc;

        data = lyd_new(NULL, ietfnc, "cancel-commit");
        if (rpc_can->persist_id) {
            node = lyd_new_leaf(data, ietfnc, "persist-id", rpc_can->persist_id);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_VALIDATE:
        rpc_val = (struct nc_rpc_validate *)rpc;

        data = lyd_new(NULL, ietfnc, "validate");
        node = lyd_new(data, ietfnc, "source");
        if (rpc_val->url_config_src) {
            if (!rpc_val->url_config_src[0] || (rpc_val->url_config_src[0] == '<')) {
                node = lyd_new_anydata(node, ietfnc, "config", rpc_val->url_config_src, LYD_ANYDATA_SXML);
            } else {
                node = lyd_new_leaf(node, ietfnc, "url", rpc_val->url_config_src);
            }
        } else {
            node = lyd_new_leaf(node, ietfnc, ncds2str[rpc_val->source], NULL);
        }
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        break;

    case NC_RPC_GETSCHEMA:
        ietfncmon = ly_ctx_get_module(session->ctx, "ietf-netconf-monitoring", NULL, 1);
        if (!ietfncmon) {
            ERR("Session %u: missing \"ietf-netconf-monitoring\" schema in the context.", session->id);
            return NC_MSG_ERROR;
        }

        rpc_gs = (struct nc_rpc_getschema *)rpc;

        data = lyd_new(NULL, ietfncmon, "get-schema");
        node = lyd_new_leaf(data, ietfncmon, "identifier", rpc_gs->identifier);
        if (!node) {
            lyd_free(data);
            return NC_MSG_ERROR;
        }
        if (rpc_gs->version) {
            node = lyd_new_leaf(data, ietfncmon, "version", rpc_gs->version);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        if (rpc_gs->format) {
            node = lyd_new_leaf(data, ietfncmon, "format", rpc_gs->format);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;

    case NC_RPC_SUBSCRIBE:
        notifs = ly_ctx_get_module(session->ctx, "notifications", NULL, 1);
        if (!notifs) {
            ERR("Session %u: missing \"notifications\" schema in the context.", session->id);
            return NC_MSG_ERROR;
        }

        rpc_sub = (struct nc_rpc_subscribe *)rpc;

        data = lyd_new(NULL, notifs, "create-subscription");
        if (rpc_sub->stream) {
            node = lyd_new_leaf(data, notifs, "stream", rpc_sub->stream);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_sub->filter) {
            if (!rpc_sub->filter[0] || (rpc_sub->filter[0] == '<')) {
                node = lyd_new_anydata(data, notifs, "filter", rpc_sub->filter, LYD_ANYDATA_SXML);
                lyd_insert_attr(node, NULL, "type", "subtree");
            } else {
                node = lyd_new_anydata(data, notifs, "filter", NULL, LYD_ANYDATA_CONSTSTRING);
                lyd_insert_attr(node, NULL, "type", "xpath");
                lyd_insert_attr(node, NULL, "select", rpc_sub->filter);
            }
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_sub->start) {
            node = lyd_new_leaf(data, notifs, "startTime", rpc_sub->start);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }

        if (rpc_sub->stop) {
            node = lyd_new_leaf(data, notifs, "stopTime", rpc_sub->stop);
            if (!node) {
                lyd_free(data);
                return NC_MSG_ERROR;
            }
        }
        break;
    default:
        ERRINT;
        return NC_MSG_ERROR;
    }

    if (!data) {
        /* error was already printed */
        return NC_MSG_ERROR;
    }

    if (lyd_validate(&data, LYD_OPT_RPC | LYD_OPT_NOEXTDEPS
                     | (session->flags & NC_SESSION_CLIENT_NOT_STRICT ? 0 : LYD_OPT_STRICT), NULL)) {
        if (dofree) {
            lyd_free(data);
        }
        return NC_MSG_ERROR;
    }

    /* send RPC, store its message ID */
    r = nc_send_msg_io(session, timeout, data);
    cur_msgid = session->opts.client.msgid;

    if (dofree) {
        lyd_free(data);
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
        ERRARG("session");
        return;
    }

    session->flags |= NC_SESSION_CLIENT_NOT_STRICT;
}
