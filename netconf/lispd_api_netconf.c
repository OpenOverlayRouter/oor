/*
 * lispd_api_netconf.c
 *
 * This file is part of the LISPmob implementation.
 * It connects the LISPmob API to NETCONF
 *
 * Copyright (C) The LISPmob project, 2014. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 */

#include <stdlib.h>
#include <libxml/xmlstring.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <zmq.h>

#include "lispd_api_netconf.h"
#include "../lispd/lib/util.h"
#include "../lispd/lib/lmlog.h"
#include "../lispd/liblisp/liblisp.h"



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

/* NAT */
int nat_aware = FALSE;
int nat_status = UNKNOWN;
nonces_list_t *nat_ir_nonce = NULL;

sockmstr_t *smaster = NULL;
lisp_ctrl_dev_t *ctrl_dev;
lisp_ctrl_t *lctrl;

void
exit_cleanup(void) {
    LMLOG(LDBG_2,"Exit Cleanup");

    //TODO delete connection on error
    //lmapi_end(&lmapi_connection);

    LMLOG(LINF,"Exiting ...");
    exit(EXIT_SUCCESS);
}

xmlNodePtr get_inner_xmlNodePtr(xmlNodePtr parent, char *name){

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

int lmapi_nc_xtr_mr_add(lmapi_connection_t *conn, xmlNodePtr mrs_parent, struct nc_err** error){
    uint8_t *data = NULL;
    int size = 0;
    char *str_err = NULL;
    int result = 0;
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL;

    printf("LMAPI: Add new Map Resolvers list\n");

    doc = xmlNewDoc((xmlChar *)"1.0");
    root_node = xmlNewNode(NULL, (xmlChar *)"root");
    xmlDocSetRootElement(doc, root_node);
    xmlAddChild(root_node,xmlCopyNode(mrs_parent,1));


    xmlDocDumpMemoryEnc(doc, (xmlChar **)&data, &size,"UTF-8");
    xmlFreeDoc(doc);

    if ((size + sizeof(lmapi_msg_hdr_t)) > MAX_API_PKT_LEN){
        str_err= strdup("Trying to send too many Map Resolvers");
        goto err;
    }
    result = lmapi_apply_config(conn,
            LMAPI_DEV_XTR,
            LMAPI_TRGT_MRLIST,
            LMAPI_OPR_CREATE,
            data,
            size);
    free(data);
    if (result != LMAPI_RES_OK){
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



int lmapi_nc_xtr_mr_rem(lmapi_connection_t *conn, xmlNodePtr node, struct nc_err** error){

    int result;
    result = lmapi_apply_config(conn,
            LMAPI_DEV_XTR,
            LMAPI_TRGT_MRLIST,
            LMAPI_OPR_DELETE,
            NULL,
            0);
    printf("LMAPI: Remove Map Resolvers list\n");

    if (result != LMAPI_RES_OK){
        *error = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(*error, NC_ERR_PARAM_MSG, "Map Resolvers couldn't be removed.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

}

int lmapi_nc_xtr_ms_add(lmapi_connection_t *conn, xmlNodePtr map_servers_parent, struct nc_err** error){
    uint8_t *data = NULL;
    int size = 0;
    char *str_err = NULL;
    int result = 0;
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL;

    printf("LMAPI: Add new Map Servers list\n");

    doc = xmlNewDoc((xmlChar *)"1.0");
    root_node = xmlNewNode(NULL, (xmlChar *)"root");
    xmlDocSetRootElement(doc, root_node);
    xmlAddChild(root_node,xmlCopyNode(map_servers_parent,1));


    xmlDocDumpMemoryEnc(doc, (xmlChar **)&data, &size,"UTF-8");
    xmlFreeDoc(doc);

    if ((size + sizeof(lmapi_msg_hdr_t)) > MAX_API_PKT_LEN){
        str_err= strdup("Trying to send too many Map Resolvers");
        goto err;
    }
    result = lmapi_apply_config(conn,
            LMAPI_DEV_XTR,
            LMAPI_TRGT_MSLIST,
            LMAPI_OPR_CREATE,
            data,
            size);
    free(data);
    if (result != LMAPI_RES_OK){
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



int lmapi_nc_xtr_ms_rem(lmapi_connection_t *conn, xmlNodePtr node, struct nc_err** error){

    int result;

    printf("LMAPI: Remove Map Servers list\n");

    result = lmapi_apply_config(conn,
            LMAPI_DEV_XTR,
            LMAPI_TRGT_MSLIST,
            LMAPI_OPR_DELETE,
            NULL,
            0);


    if (result != LMAPI_RES_OK){
        *error = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(*error, NC_ERR_PARAM_MSG, "Map Servers couldn't be removed.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

}

int lmapi_nc_xtr_mapdb_rem(lmapi_connection_t *conn, xmlNodePtr node, struct nc_err** error){

    int result;

    printf("LMAPI: Remove local map database\n");

    result = lmapi_apply_config(conn,
            LMAPI_DEV_XTR,
            LMAPI_TRGT_MAPDB,
            LMAPI_OPR_DELETE,
            NULL,
            0);


    if (result != LMAPI_RES_OK){
        *error = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(*error, NC_ERR_PARAM_MSG, "Local Map database couldn't be removed.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int lmapi_nc_xtr_mapdb_add(lmapi_connection_t *conn, xmlNodePtr xml_local_eid_database, struct nc_err** error){

    int result;
    char *str_err = NULL;

    uint8_t *data = NULL;
    int size = 0;

    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL;

    printf("LMAPI: Add new local map database\n");
    doc = xmlNewDoc((xmlChar *)"1.0");
    root_node = xmlNewNode(NULL, (xmlChar *)"root");
    xmlDocSetRootElement(doc, root_node);
    xmlAddChild(root_node,xmlCopyNode(xml_local_eid_database,1));


    xmlDocDumpMemoryEnc(doc, (xmlChar **)&data, &size,"UTF-8");
    xmlFreeDoc(doc);

    if ((size + sizeof(lmapi_msg_hdr_t)) > MAX_API_PKT_LEN){
        str_err= strdup("lmapi_nc_xtr_mapdb_add: Trying to send too many local EIDs");
        goto err;
    }

    result = lmapi_apply_config(conn,
            LMAPI_DEV_XTR,
            LMAPI_TRGT_MAPDB,
            LMAPI_OPR_CREATE,
            data,
            size);
    free(data);

    printf("config applied\n");

    if (result != LMAPI_RES_OK){
        str_err= strdup("Config couldn't be applied (new local EIDs list)");
        goto err;
    }

    return EXIT_SUCCESS;

err:
    LMLOG(LDBG_1,"LMAPI: Error adding local data base mapping");

    *error = nc_err_new(NC_ERR_OP_FAILED);
    nc_err_set(*error, NC_ERR_PARAM_MSG, "Error while processing config modification request.");

    return EXIT_FAILURE;

}

int lmapi_nc_rtr_mr_add(lmapi_connection_t *conn, xmlNodePtr mrs_parent, struct nc_err** error){
    uint8_t *data = NULL;
    int size = 0;
    char *str_err = NULL;
    int result = 0;
    xmlDocPtr doc = NULL;
    xmlNodePtr root_node = NULL;

    printf("LMAPI: Add new Map Resolvers list to RTR\n");

    doc = xmlNewDoc((xmlChar *)"1.0");
    root_node = xmlNewNode(NULL, (xmlChar *)"root");
    xmlDocSetRootElement(doc, root_node);
    xmlAddChild(root_node,xmlCopyNode(mrs_parent,1));


    xmlDocDumpMemoryEnc(doc, (xmlChar **)&data, &size,"UTF-8");
    xmlFreeDoc(doc);

    if ((size + sizeof(lmapi_msg_hdr_t)) > MAX_API_PKT_LEN){
        str_err= strdup("Trying to send too many Map Resolvers");
        goto err;
    }
    result = lmapi_apply_config(conn,
            LMAPI_DEV_RTR,
            LMAPI_TRGT_MRLIST,
            LMAPI_OPR_CREATE,
            data,
            size);
    free(data);
    if (result != LMAPI_RES_OK){
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



int lmapi_nc_rtr_mr_rem(lmapi_connection_t *conn, xmlNodePtr node, struct nc_err** error){

    int result;
    result = lmapi_apply_config(conn,
            LMAPI_DEV_RTR,
            LMAPI_TRGT_MRLIST,
            LMAPI_OPR_DELETE,
            NULL,
            0);
    printf("LMAPI: Remove Map Resolvers list\n");

    if (result != LMAPI_RES_OK){
        *error = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(*error, NC_ERR_PARAM_MSG, "Map Resolvers couldn't be removed from RTR.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

}


int lmapi_nc_node_accessed(lmapi_connection_t *conn, int dev, int trgt, XMLDIFF_OP op, xmlNodePtr node, struct nc_err** error){

    if (op <= 0 || op > (XMLDIFF_MOD | XMLDIFF_CHAIN | XMLDIFF_ADD | XMLDIFF_REM) || ((op & XMLDIFF_ADD) && (op & XMLDIFF_REM))) {
        goto err;
    }

    if ((dev == LMAPI_DEV_XTR) && (trgt == LMAPI_TRGT_MRLIST) &&
            ( (op & XMLDIFF_ADD) || (op & XMLDIFF_MOD) || (op & XMLDIFF_CHAIN) )) {
        return (lmapi_nc_xtr_mr_add(conn, node, error));
    }

    if ((dev == LMAPI_DEV_XTR) && (trgt == LMAPI_TRGT_MRLIST) &&
            ( (op & XMLDIFF_REM) )) {
        return (lmapi_nc_xtr_mr_rem(conn, node, error));
    }

    if ((dev == LMAPI_DEV_XTR) && (trgt == LMAPI_TRGT_MSLIST) &&
            ( (op & XMLDIFF_ADD) || (op & XMLDIFF_MOD) || (op & XMLDIFF_CHAIN) )) {
        return (lmapi_nc_xtr_ms_add(conn, node, error));
    }

    if ((dev == LMAPI_DEV_XTR) && (trgt == LMAPI_TRGT_MSLIST) &&
            ( (op & XMLDIFF_REM) )) {
        return (lmapi_nc_xtr_ms_rem(conn, node, error));
    }

    if ((dev == LMAPI_DEV_XTR) && (trgt == LMAPI_TRGT_MAPDB) &&
            ( (op & XMLDIFF_ADD) || (op & XMLDIFF_MOD) || (op & XMLDIFF_CHAIN) )) {
        return (lmapi_nc_xtr_mapdb_add(conn, node, error));
    }

    if ((dev == LMAPI_DEV_XTR) && (trgt == LMAPI_TRGT_MAPDB) &&
            ( (op & XMLDIFF_REM) )) {
        return (lmapi_nc_xtr_mapdb_rem(conn, node, error));
    }

    if ((dev == LMAPI_DEV_RTR) && (trgt == LMAPI_TRGT_MRLIST) &&
            ( (op & XMLDIFF_ADD) || (op & XMLDIFF_MOD) || (op & XMLDIFF_CHAIN) )) {
        return (lmapi_nc_rtr_mr_add(conn, node, error));
    }

    if ((dev == LMAPI_DEV_RTR) && (trgt == LMAPI_TRGT_MRLIST) &&
            ( (op & XMLDIFF_REM) )) {
        return (lmapi_nc_rtr_mr_rem(conn, node, error));
    }

    /* We should not reach here */
err:
    *error = nc_err_new(NC_ERR_OP_FAILED);
    nc_err_set(*error, NC_ERR_PARAM_MSG, "lispmob module: operation not supported");
    return (EXIT_FAILURE);

}
