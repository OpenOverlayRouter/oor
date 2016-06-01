/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdlib.h>
#include <libxml/xmlstring.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <zmq.h>

#include "oor_api_netconf.h"
#include "../oor/lib/util.h"
#include "../oor/lib/oor_log.h"
#include "../oor/liblisp/liblisp.h"



/******** TO REMOVE ********/
/* config paramaters */
char    *config_file                        = NULL;
int      debug_level                        = LDBG_3;
int      default_rloc_afi                   = AF_UNSPEC;
int      daemonize                          = FALSE;

uint32_t iseed                              = 0;  /* initial random number generator */

/* various globals */
pid_t  pid                                  = 0;    /* child pid */
pid_t  sid                                  = 0;

/* sockets (fds)  */
int     ipv4_data_input_fd                  = 0;
int     ipv6_data_input_fd                  = 0;
int     netlink_fd                          = 0;


sockmstr_t *smaster = NULL;
oor_ctrl_dev_t *ctrl_dev;
oor_ctrl_t *lctrl;

xmlNodePtr
get_inner_xmlNodePtr(xmlNodePtr parent, char *name)
{

    xmlNodePtr node = NULL;
    xmlChar * xmlName = xmlCharStrdup(name);

    node = xmlFirstElementChild(parent);

    while (node != NULL){
        if(xmlStrEqual(node->name,xmlName)){
            break;
        }
        node = xmlNextElementSibling(node);
    }

    free(xmlName);
    return node;

}

int
oor_api_nc_xtr_mr_add(oor_api_connection_t *conn, xmlNodePtr mrs_parent, struct nc_err** error)
{
    uint8_t *data = NULL;
    int size = 0;
    char *str_err = NULL;
    int result = 0;
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL;

    printf("OOR_API: Add new Map Resolvers list\n");

    doc = xmlNewDoc((xmlChar *)"1.0");
    root_node = xmlNewNode(NULL, (xmlChar *)"root");
    xmlDocSetRootElement(doc, root_node);
    xmlAddChild(root_node,xmlCopyNode(mrs_parent,1));


    xmlDocDumpMemoryEnc(doc, (xmlChar **)&data, &size,"UTF-8");
    xmlFreeDoc(doc);

    if ((size + sizeof(oor_api_msg_hdr_t)) > MAX_API_PKT_LEN){
        str_err= strdup("Trying to send too many Map Resolvers");
        goto err;
    }
    result = oor_api_apply_config(conn,
            OOR_API_DEV_XTR,
            OOR_API_TRGT_MRLIST,
            OOR_API_OPR_CREATE,
            data,
            size);
    free(data);
    if (result != OOR_API_RES_OK){
        str_err= strdup("Config couldn't be applied (new Map Resolvers list)");
        goto err;
    }
    return EXIT_SUCCESS;
err:
    if (str_err == NULL){
        str_err = strdup("Error while trying to add Map Resolver(s)");
    }
    *error = nc_err_new(NC_ERR_OP_FAILED);
    nc_err_set(*error, NC_ERR_PARAM_MSG,str_err);
    free(str_err);
    return EXIT_FAILURE;
}



int
oor_api_nc_xtr_mr_rem(oor_api_connection_t *conn, xmlNodePtr node, struct nc_err** error)
{

    int result;
    result = oor_api_apply_config(conn,
            OOR_API_DEV_XTR,
            OOR_API_TRGT_MRLIST,
            OOR_API_OPR_DELETE,
            NULL,
            0);
    printf("OOR_API: Remove Map Resolvers list\n");

    if (result != OOR_API_RES_OK){
        *error = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(*error, NC_ERR_PARAM_MSG, "Map Resolvers couldn't be removed.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

}

int
oor_api_nc_xtr_petrs_add(oor_api_connection_t *conn, xmlNodePtr mrs_parent, struct nc_err** error)
{
    uint8_t *data = NULL;
    int size = 0;
    char *str_err = NULL;
    int result = 0;
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL;

    printf("OOR_API: Add new Proxy ETRs list\n");

    doc = xmlNewDoc((xmlChar *)"1.0");
    root_node = xmlNewNode(NULL, (xmlChar *)"root");
    xmlDocSetRootElement(doc, root_node);
    xmlAddChild(root_node,xmlCopyNode(mrs_parent,1));


    xmlDocDumpMemoryEnc(doc, (xmlChar **)&data, &size,"UTF-8");
    xmlFreeDoc(doc);

    if ((size + sizeof(oor_api_msg_hdr_t)) > MAX_API_PKT_LEN){
        str_err= strdup("Trying to send too many Proxy ETRs");
        goto err;
    }
    result = oor_api_apply_config(conn,
            OOR_API_DEV_XTR,
            OOR_API_TRGT_PETRLIST,
            OOR_API_OPR_CREATE,
            data,
            size);
    free(data);
    if (result != OOR_API_RES_OK){
        str_err= strdup("Config couldn't be applied (new Map Resolvers list)");
        goto err;
    }
    return EXIT_SUCCESS;
err:
    if (str_err == NULL){
        str_err = strdup("Error while trying to add Proxy ETR(s)");
    }
    *error = nc_err_new(NC_ERR_OP_FAILED);
    nc_err_set(*error, NC_ERR_PARAM_MSG,str_err);
    free(str_err);
    return EXIT_FAILURE;
}



int
oor_api_nc_xtr_petrs_rem(oor_api_connection_t *conn, xmlNodePtr node, struct nc_err** error)
{

    int result;
    result = oor_api_apply_config(conn,
            OOR_API_DEV_XTR,
            OOR_API_TRGT_PETRLIST,
            OOR_API_OPR_DELETE,
            NULL,
            0);
    printf("OOR_API: Remove Map Resolvers list\n");

    if (result != OOR_API_RES_OK){
        *error = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(*error, NC_ERR_PARAM_MSG, "Proxy ETRs couldn't be removed.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

}

int
oor_api_nc_xtr_ms_add(oor_api_connection_t *conn, xmlNodePtr map_servers_parent,
        struct nc_err** error)
{
    uint8_t *data = NULL;
    int size = 0;
    char *str_err = NULL;
    int result = 0;
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL;

    printf("OOR_API: Add new Map Servers list\n");

    doc = xmlNewDoc((xmlChar *)"1.0");
    root_node = xmlNewNode(NULL, (xmlChar *)"root");
    xmlDocSetRootElement(doc, root_node);
    xmlAddChild(root_node,xmlCopyNode(map_servers_parent,1));


    xmlDocDumpMemoryEnc(doc, (xmlChar **)&data, &size,"UTF-8");
    xmlFreeDoc(doc);

    if ((size + sizeof(oor_api_msg_hdr_t)) > MAX_API_PKT_LEN){
        str_err= strdup("Trying to send too many Map Resolvers");
        goto err;
    }
    result = oor_api_apply_config(conn,
            OOR_API_DEV_XTR,
            OOR_API_TRGT_MSLIST,
            OOR_API_OPR_CREATE,
            data,
            size);
    free(data);
    if (result != OOR_API_RES_OK){
        str_err= strdup("Config couldn't be applied (new Map Servers list)");
        goto err;
    }
    return EXIT_SUCCESS;
err:
    if (str_err == NULL){
        str_err = strdup("Error while trying to add Map Server(s)");
    }
    *error = nc_err_new(NC_ERR_OP_FAILED);
    nc_err_set(*error, NC_ERR_PARAM_MSG,str_err);
    free(str_err);
    return EXIT_FAILURE;
}



int
oor_api_nc_xtr_ms_rem(oor_api_connection_t *conn, xmlNodePtr node, struct nc_err** error)
{
    int result;

    printf("OOR_API: Remove Map Servers list\n");

    result = oor_api_apply_config(conn,
            OOR_API_DEV_XTR,
            OOR_API_TRGT_MSLIST,
            OOR_API_OPR_DELETE,
            NULL,
            0);

    if (result != OOR_API_RES_OK){
        *error = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(*error, NC_ERR_PARAM_MSG, "Map Servers couldn't be removed.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int
oor_api_nc_xtr_mapdb_rem(oor_api_connection_t *conn, xmlNodePtr node, struct nc_err** error)
{

    int result;

    printf("OOR_API: Remove local map database\n");

    result = oor_api_apply_config(conn,
            OOR_API_DEV_XTR,
            OOR_API_TRGT_MAPDB,
            OOR_API_OPR_DELETE,
            NULL,
            0);


    if (result != OOR_API_RES_OK){
        *error = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(*error, NC_ERR_PARAM_MSG, "Local Map database couldn't be removed.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int
oor_api_nc_xtr_mapdb_add(oor_api_connection_t *conn, xmlNodePtr xml_local_eid_database,
        struct nc_err** error)
{
    int result;
    char *str_err = NULL;
    uint8_t *data = NULL;
    int size = 0;
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL;

    printf("OOR_API: Add new local map database\n");
    doc = xmlNewDoc((xmlChar *)"1.0");
    root_node = xmlNewNode(NULL, (xmlChar *)"root");
    xmlDocSetRootElement(doc, root_node);
    xmlAddChild(root_node,xmlCopyNode(xml_local_eid_database,1));


    xmlDocDumpMemoryEnc(doc, (xmlChar **)&data, &size,"UTF-8");
    xmlFreeDoc(doc);

    if ((size + sizeof(oor_api_msg_hdr_t)) > MAX_API_PKT_LEN){
        str_err= strdup("oor_api_nc_xtr_mapdb_add: Trying to send too many local EIDs");
        goto err;
    }

    result = oor_api_apply_config(conn,
            OOR_API_DEV_XTR,
            OOR_API_TRGT_MAPDB,
            OOR_API_OPR_CREATE,
            data,
            size);
    free(data);

    printf("config applied\n");

    if (result != OOR_API_RES_OK){
        str_err= strdup("Config couldn't be applied (new local EIDs list)");
        goto err;
    }

    return EXIT_SUCCESS;

err:
    OOR_LOG(LDBG_1,"OOR_API: Error adding local data base mapping");

    *error = nc_err_new(NC_ERR_OP_FAILED);
    nc_err_set(*error, NC_ERR_PARAM_MSG, "Error while processing config modification request.");

    return EXIT_FAILURE;

}

int
oor_api_nc_rtr_mr_add(oor_api_connection_t *conn, xmlNodePtr mrs_parent,
        struct nc_err** error)
{
    uint8_t *data = NULL;
    int size = 0;
    char *str_err = NULL;
    int result = 0;
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL;

    printf("OOR_API: Add new Map Resolvers list to RTR\n");

    doc = xmlNewDoc((xmlChar *)"1.0");
    root_node = xmlNewNode(NULL, (xmlChar *)"root");
    xmlDocSetRootElement(doc, root_node);
    xmlAddChild(root_node,xmlCopyNode(mrs_parent,1));


    xmlDocDumpMemoryEnc(doc, (xmlChar **)&data, &size,"UTF-8");
    xmlFreeDoc(doc);

    if ((size + sizeof(oor_api_msg_hdr_t)) > MAX_API_PKT_LEN){
        str_err= strdup("Trying to send too many Map Resolvers");
        goto err;
    }
    result = oor_api_apply_config(conn,
            OOR_API_DEV_RTR,
            OOR_API_TRGT_MRLIST,
            OOR_API_OPR_CREATE,
            data,
            size);
    free(data);
    if (result != OOR_API_RES_OK){
        str_err= strdup("Config couldn't be applied (new Map Resolvers list)");
        goto err;
    }
    return EXIT_SUCCESS;
err:
    if (str_err == NULL){
        str_err = strdup("Error while trying to add Map Resolver(s) to RTR");
    }
    *error = nc_err_new(NC_ERR_OP_FAILED);
    nc_err_set(*error, NC_ERR_PARAM_MSG,str_err);
    free(str_err);
    return EXIT_FAILURE;
}



int
oor_api_nc_rtr_mr_rem(oor_api_connection_t *conn, xmlNodePtr node, struct nc_err** error)
{

    int result;
    result = oor_api_apply_config(conn,
            OOR_API_DEV_RTR,
            OOR_API_TRGT_MRLIST,
            OOR_API_OPR_DELETE,
            NULL,
            0);
    printf("OOR_API: Remove Map Resolvers list\n");

    if (result != OOR_API_RES_OK){
        *error = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(*error, NC_ERR_PARAM_MSG, "Map Resolvers couldn't be removed from RTR.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

}


int
oor_api_nc_node_accessed(oor_api_connection_t *conn, int dev, int trgt, XMLDIFF_OP op,
        xmlNodePtr node, struct nc_err** error)
{

    if (op <= 0 || op > (XMLDIFF_MOD | XMLDIFF_CHAIN | XMLDIFF_ADD | XMLDIFF_REM) || ((op & XMLDIFF_ADD) && (op & XMLDIFF_REM))) {
        goto err;
    }

    switch (dev){
    case OOR_API_DEV_XTR:
        switch (trgt){
        case OOR_API_TRGT_MRLIST:
            if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD) || (op & XMLDIFF_CHAIN)){
                return (oor_api_nc_xtr_mr_add(conn, node, error));
            }else if (op & XMLDIFF_REM){
                return (oor_api_nc_xtr_mr_rem(conn, node, error));
            }
            goto err;
        case OOR_API_TRGT_MSLIST:
            if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD) || (op & XMLDIFF_CHAIN)){
                return (oor_api_nc_xtr_ms_add(conn, node, error));
            }else if (op & XMLDIFF_REM){
                return (oor_api_nc_xtr_ms_rem(conn, node, error));
            }
            goto err;
        case OOR_API_TRGT_MAPDB:
            if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD) || (op & XMLDIFF_CHAIN)){
                return (oor_api_nc_xtr_mapdb_add(conn, node, error));
            }else if (op & XMLDIFF_REM){
                return (oor_api_nc_xtr_mapdb_rem(conn, node, error));
            }
            goto err;
        case OOR_API_TRGT_PETRLIST:
            if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD) || (op & XMLDIFF_CHAIN)){
                return (oor_api_nc_xtr_petrs_add(conn, node, error));
            }else if (op & XMLDIFF_REM){
                return (oor_api_nc_xtr_petrs_rem(conn, node, error));
            }
            goto err;
        default:
            goto err;
        }
        break;
    case OOR_API_DEV_RTR:
        switch (trgt){
        case OOR_API_TRGT_MRLIST:
            if ((op & XMLDIFF_ADD) || (op & XMLDIFF_MOD) || (op & XMLDIFF_CHAIN)){
                return (oor_api_nc_rtr_mr_add(conn, node, error));
            }else if (op & XMLDIFF_REM){
                return (oor_api_nc_rtr_mr_rem(conn, node, error));
            }
            goto err;
        default:
            goto err;
        }
        break;
    default:
        goto err;
    }

    /* We should not reach here */
err:
    *error = nc_err_new(NC_ERR_OP_FAILED);
    nc_err_set(*error, NC_ERR_PARAM_MSG, "oor module: operation not supported");
    return (EXIT_FAILURE);

}
