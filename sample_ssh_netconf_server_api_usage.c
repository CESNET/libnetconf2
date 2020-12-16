#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libyang/libyang.h>
#include<nc_server.h>

#define NETCONF_MODULE_LOCATION "/root/netconf_module_location"
#define NETCONF_ACCEPT_TIMEOUT 3000
#define NETCONF_POLLING_SESSION_TIMEOUT 3000

struct nc_pollsession *netconf_polling_session;   /**< libnetconf2 pollsession structure */

int app_hostkeys_setting_callback(const char *name, void *user_data, char **privkey_path, char **privkey_data,NC_SSH_KEY_TYPE *privkey_type)
{
	if (!strcmp(name, "key_rsa")) {
		*privkey_path = strdup(NETCONF_MODULE_LOCATION"/data/key_rsa");
		return 0;
	} else if (!strcmp(name, "key_dsa")) {
		*privkey_path = strdup(NETCONF_MODULE_LOCATION"/data/key_dsa");
		return 0;
	}

	return 1;
}

struct nc_server_reply * app_get_rpc_callback(struct lyd_node *rpc, struct nc_session *session)
{
	printf("rpc->schema->name is %s\n",rpc->schema->name);

	return nc_server_reply_ok();
}


struct nc_server_reply * app_commit_rpc_callback(struct lyd_node *rpc, struct nc_session *session)
{
	printf("rpc->schema->name is %s\n",rpc->schema->name);
	return nc_server_reply_ok();
}

struct nc_server_reply * app_getconfig_rpc_callback(struct lyd_node *rpc, struct nc_session *session)
{
	struct lyd_node *data;

	printf("rpc->schema->name is %s\n",rpc->schema->name);


	data = lyd_new_path(NULL, nc_session_get_ctx(session), "/ietf-netconf:get-config/data", NULL, LYD_ANYDATA_CONSTSTRING,LYD_PATH_OPT_OUTPUT);

	return nc_server_reply_data(data, NC_WD_EXPLICIT, NC_PARAMTYPE_FREE);
}

app_new_session_request(struct nc_session *new_session)
{
	nc_ps_add_session(netconf_polling_session, new_session);

}
void app_accept_netconf_request()
{
	NC_MSG_TYPE msgtype;
	int rc;
	struct nc_session *netconfSession;

	netconf_polling_session = nc_ps_new();

	while (1) {
		if (nc_server_endpt_count()) {
			msgtype = nc_accept(0, &netconfSession);
			printf("msgtype is %d\n",msgtype);	
			if (msgtype == NC_MSG_HELLO) {
				app_new_session_request(netconfSession);
			}
		}

		rc = nc_ps_poll(netconf_polling_session,NETCONF_POLLING_SESSION_TIMEOUT, &netconfSession);

		if ((rc )) {
			sleep(1);
			continue;
		}
		msgtype = nc_session_accept_ssh_channel(netconfSession, &netconfSession);
		if (msgtype == NC_MSG_HELLO) {
			app_new_session_request(netconfSession);

		}
	}

	nc_thread_destroy();
}
int main(void)
{
	struct ly_ctx *ctx;
	int ret, i, clients = 0;

	const struct lys_module *module;
	const struct lys_node *node;
	ctx = ly_ctx_new(NETCONF_MODULE_LOCATION"/data/modules", 0);
	module = ly_ctx_load_module(ctx, "ietf-netconf", NULL);
	ret = lys_features_enable(module, "candidate");
	ret = lys_features_enable(module, "commit");
	module = ly_ctx_load_module(ctx, "ietf-netconf-monitoring", NULL);

	/* get callback which will get invoke when get request is received*/
	node = ly_ctx_get_node(module->ctx, NULL, "/ietf-netconf:get", 0);
	lys_set_private(node, app_get_rpc_callback);

	/* getconfig callback which will get invoke when getconfig request is received*/
	node = ly_ctx_get_node(module->ctx, NULL, "/ietf-netconf:get-config", 0);
	lys_set_private(node, app_getconfig_rpc_callback);

	/* commit callback which will get invoke when commit request is received*/
	node = ly_ctx_get_node(module->ctx, NULL, "/ietf-netconf:commit", 0);
	lys_set_private(node, app_commit_rpc_callback);

	nc_server_init(ctx);
	nc_server_ssh_set_hostkey_clb(app_hostkeys_setting_callback, NULL, NULL);

	/* SSH parameter setting for listening  netconf ssh server */
	ret = nc_server_add_endpt("main_ssh", NC_TI_LIBSSH);
	ret = nc_server_endpt_set_address("main_ssh", "127.0.0.1");
	ret = nc_server_endpt_set_port("main_ssh", 12324);
	ret = nc_server_ssh_add_authkey_path(NETCONF_MODULE_LOCATION"/data/key_ecdsa.pub", "tester");
	ret = nc_server_ssh_endpt_add_hostkey("main_ssh", "key_rsa", -1);
	app_accept_netconf_request();
	nc_server_destroy();
	ly_ctx_destroy(ctx, NULL);
	return 0;
}

