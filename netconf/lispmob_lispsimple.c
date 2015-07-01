/*
 * This is automatically generated callbacks file
 * It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
 * Do NOT alter function signatures or any structures unless you know exactly what you are doing.
 */

#include <stdlib.h>
#include <sys/inotify.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include "lispd_api_netconf.h"

/* Structure to store the API connection data */
lmapi_connection_t connection;

/* transAPI version which must be compatible with libnetconf */
int transapi_version = 5;

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
int config_modified = 0;

/*
 * Determines the callbacks order.
 * Set this variable before compilation and DO NOT modify it in runtime.
 * TRANSAPI_CLBCKS_LEAF_TO_ROOT (default)
 * TRANSAPI_CLBCKS_ROOT_TO_LEAF
 */
const TRANSAPI_CLBCKS_ORDER_TYPE callbacks_order = TRANSAPI_CLBCKS_ORDER_DEFAULT;

/* Do not modify or set! This variable is set by libnetconf to announce edit-config's error-option
Feel free to use it to distinguish module behavior for different error-option values.
 * Possible values:
 * NC_EDIT_ERROPT_STOP - Following callback after failure are not executed, all successful callbacks executed till
                         failure point must be applied to the device.
 * NC_EDIT_ERROPT_CONT - Failed callbacks are skipped, but all callbacks needed to apply configuration changes are executed
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks are not executed, but previous successful callbacks are
                         executed again with previous configuration data to roll it back.
 */
NC_EDIT_ERROPT_TYPE erropt = NC_EDIT_ERROPT_NOTSET;

/**
 * @brief Initialize plugin after loaded and before any other functions are called.

 * This function should not apply any configuration data to the controlled device. If no
 * running is returned (it stays *NULL), complete startup configuration is consequently
 * applied via module callbacks. When a running configuration is returned, libnetconf
 * then applies (via module's callbacks) only the startup configuration data that
 * differ from the returned running configuration data.

 * Please note, that copying startup data to the running is performed only after the
 * libnetconf's system-wide close - see nc_close() function documentation for more
 * information.

 * @param[out] running	Current configuration of managed device.

 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int transapi_init(xmlDocPtr *running)
{
    printf("LISP-NC: Starting client-side API... \n");

    if (lmapi_init_client(&connection) != GOOD){
        printf("LISP-NC: Error while starting client-side API \n");
        return EXIT_FAILURE;
    }

    printf("LISP-NC: Started client-side API \n");

    return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void transapi_close(void)
{
    printf("\nUnloading lispmob module...\n");

    lmapi_end(&connection);

    printf("Unload done \n");

    return;
}

/**
 * @brief Retrieve state data from device and return them as XML document
 *
 * @param model	Device data model. libxml2 xmlDocPtr.
 * @param running	Running datastore content. libxml2 xmlDocPtr.
 * @param[out] err  Double pointer to error structure. Fill error when some occurs.
 * @return State data as libxml2 xmlDocPtr or NULL in case of error.
 */
xmlDocPtr get_state_data(xmlDocPtr model, xmlDocPtr running, struct nc_err **err)
{
	return(NULL);
}
/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
struct ns_pair namespace_mapping[] = {{"lispsimple", "urn:ietf:params:xml:ns:yang:lispsimple"}, {NULL, NULL}};

/*
 * CONFIGURATION callbacks
 * Here follows set of callback functions run every time some change in associated part of running datastore occurs.
 * You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
 */

/**
 * @brief This callback will be run when node in path /lispsimple:itr-cfg/lispsimple:map-resolvers changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_lispsimple_itr_cfg_lispsimple_map_resolvers(void **data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err **error)
{
    printf("Node accessed %s\n",node->name);
    return (lmapi_nc_node_accessed(&connection,LMAPI_DEV_XTR,LMAPI_TRGT_MRLIST,op,node,error));
}

/**
 * @brief This callback will be run when node in path /lispsimple:etr-cfg/lispsimple:local-eids changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_lispsimple_etr_cfg_lispsimple_local_eids(void **data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err **error)
{
    printf("Node accessed %s\n",node->name);
    return (lmapi_nc_node_accessed(&connection,LMAPI_DEV_XTR,LMAPI_TRGT_MAPDB,op,node,error));
}

/**
 * @brief This callback will be run when node in path /lispsimple:etr-cfg/lispsimple:map-servers changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] node	Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_lispsimple_etr_cfg_lispsimple_map_servers(void **data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err **error)
{
    printf("Node accessed %s\n",node->name);
    return (lmapi_nc_node_accessed(&connection,LMAPI_DEV_XTR,LMAPI_TRGT_MSLIST,op,node,error));
}

/**
 * @brief This callback will be run when node in path /lispsimple:rtr-cfg/lispsimple:map-resolvers changes
 *
 * @param[in] data      Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op        Observed change in path. XMLDIFF_OP type.
 * @param[in] node      Modified node. if op == XMLDIFF_REM its copy of node removed.
 * @param[out] error    If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_lispsimple_rtr_cfg_lispsimple_map_resolvers(void **data, XMLDIFF_OP op, xmlNodePtr node, struct nc_err **error)
{
    printf("Node accessed %s\n",node->name);
    return (lmapi_nc_node_accessed(&connection,LMAPI_DEV_RTR,LMAPI_TRGT_MRLIST,op,node,error));
}

/*
 * Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
 * It is used by libnetconf library to decide which callbacks will be run.
 * DO NOT alter this structure
 */
struct transapi_data_callbacks clbks =  {
	.callbacks_count = 4,
	.data = NULL,
	.callbacks = {
		{.path = "/lispsimple:itr-cfg/lispsimple:map-resolvers", .func = callback_lispsimple_itr_cfg_lispsimple_map_resolvers},
		{.path = "/lispsimple:etr-cfg/lispsimple:local-eids", .func = callback_lispsimple_etr_cfg_lispsimple_local_eids},
		{.path = "/lispsimple:etr-cfg/lispsimple:map-servers", .func = callback_lispsimple_etr_cfg_lispsimple_map_servers},
		{.path = "/lispsimple:rtr-cfg/lispsimple:map-resolvers", .func = callback_lispsimple_rtr_cfg_lispsimple_map_resolvers}
	}
};

/*
 * RPC callbacks
 * Here follows set of callback functions run every time RPC specific for this device arrives.
 * You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
 * Every function takes array of inputs as an argument. On few first lines they are assigned to named variables. Avoid accessing the array directly.
 * If input was not set in RPC message argument in set to NULL.
 */

/*
 * Structure transapi_rpc_callbacks provides mapping between callbacks and RPC messages.
 * It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
 * DO NOT alter this structure
 */
struct transapi_rpc_callbacks rpc_clbks = {
	.callbacks_count = 0,
	.callbacks = {
	}
};

/*
 * Structure transapi_file_callbacks provides mapping between specific files
 * (e.g. configuration file in /etc/) and the callback function executed when
 * the file is modified.
 * The structure is empty by default. Add items, as in example, as you need.
 *
 * Example:
 * int example_callback(const char *filepath, xmlDocPtr *edit_config, int *exec) {
 *     // do the job with changed file content
 *     // if needed, set edit_config parameter to the edit-config data to be applied
 *     // if needed, set exec to 1 to perform consequent transapi callbacks
 *     return 0;
 * }
 *
 * struct transapi_file_callbacks file_clbks = {
 *     .callbacks_count = 1,
 *     .callbacks = {
 *         {.path = "/etc/my_cfg_file", .func = example_callback}
 *     }
 * }
 */
struct transapi_file_callbacks file_clbks = {
	.callbacks_count = 0,
	.callbacks = {{NULL}}
};

