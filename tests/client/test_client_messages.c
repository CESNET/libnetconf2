#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <session_client.h>
#include <log.h>
#include <config.h>
#include <messages_p.h>
#include "tests/config.h"

static int
setup_f(void **state)
{
    (void)state;

    nc_verbosity(NC_VERB_VERBOSE);

    return 0;
}

static int
teardown_f(void **state)
{
    (void)state;

    return 0;
}

static void
test_nc_rpc_getconfig(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, NULL, NC_WD_ALL, NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_GETCONFIG);

    nc_rpc_free(rpc);

}

static void
test_nc_rpc_edit(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_edit(NC_DATASTORE_RUNNING, NC_RPC_EDIT_DFLTOP_REPLACE , NC_RPC_EDIT_TESTOPT_TESTSET,
                      NC_RPC_EDIT_ERROPT_STOP, "url", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_EDIT);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_copy(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_copy(NC_DATASTORE_RUNNING, "target-url", NC_DATASTORE_RUNNING, "src-url",
                      NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_COPY);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_delete(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_delete(NC_DATASTORE_RUNNING, "target-url", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_DELETE);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_lock(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_LOCK);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_unlock(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_UNLOCK);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_get(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_get(NULL, NC_WD_ALL, NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_GET);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_kill(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_kill(10);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_KILL);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_commit(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_commit(1, 100, "persist", "persist-id", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_COMMIT);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_discard(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_discard();
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_DISCARD);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_cancel(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_cancel("persist-id", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_CANCEL);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_validate(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_validate(NC_DATASTORE_RUNNING, "url", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_VALIDATE);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_getschema(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_getschema("id", "version", "format", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_GETSCHEMA);

    nc_rpc_free(rpc);
}

static void
test_nc_rpc_subscribe(void **state)
{
    (void)state;
    struct nc_rpc *rpc = NULL;

    rpc = nc_rpc_subscribe("stream-name", "filter", "start-time", "stop-time", NC_PARAMTYPE_DUP_AND_FREE);
    assert_non_null(rpc);
    assert_int_equal(rpc->type, NC_RPC_SUBSCRIBE);

    nc_rpc_free(rpc);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nc_rpc_getconfig, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_edit, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_copy, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_delete, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_lock, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_unlock, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_get, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_kill, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_commit, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_discard, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_cancel, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_validate, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_getschema, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_nc_rpc_subscribe, setup_f, teardown_f),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
