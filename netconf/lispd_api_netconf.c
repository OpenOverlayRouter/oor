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
int      debug_level                        = DBG_3;
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
    LMLOG(DBG_2,"Exit Cleanup");

    //TODO delete connection on error
    //lmapi_end(&lmapi_connection);

    LMLOG(LINF,"Exiting ...");
    exit(EXIT_SUCCESS);
}
/******** TO REMOVE ********/



int lmapi_nc_xtr_mr_add(lmapi_connection_t *conn, xmlNodePtr mrs_parent, struct nc_err** error){

    lisp_addr_t *mr_addr;

    uint8_t *data = NULL;
    int nbytes = 0;
    int result = 0;
    int maxData = 0;
    int lenData = 0;
    xmlNodePtr mr_child = NULL;
    char *str_err = NULL;

    //Max size of an IP address (IPv6) + AFI header
    int max_ip_len = sizeof(uint16_t)+sizeof(struct in6_addr);

    //Allocate enough data and keep track of it
    maxData = MAX_API_PKT_LEN - sizeof(lmapi_msg_hdr_t);
    data = xzalloc(maxData);

    //Parse mr addresses
    mr_child = xmlFirstElementChild(mrs_parent);
    mr_addr = lisp_addr_new();

    while (mr_child != NULL){
        //Sub-optimal way of checking if we are running out of packet space
        if (max_ip_len > maxData - lenData){
            str_err= strdup("Trying to send too many Map Resolvers");
            goto err;
        }
        if (lisp_addr_ip_from_char((char*)xmlNodeGetContent(mr_child),mr_addr) != GOOD){
            goto err;
        }
        nbytes = lisp_addr_write(data,mr_addr);
        if (nbytes <= 0){
            goto err;
        }
        lenData += nbytes;
        mr_child = xmlNextElementSibling(mr_child);
    }

    lisp_addr_del(mr_addr);

    result = lmapi_apply_config(conn,
            LMAPI_DEV_XTR,
            LMAPI_TRGT_MRLIST,
            LMAPI_OPR_CREATE,
            data,
            lenData);
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


    if (result != LMAPI_RES_OK){
        *error = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(*error, NC_ERR_PARAM_MSG, "Config couldn't be applied.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

}

int lmapi_nc_xtr_mapdb_rem(lmapi_connection_t *conn, xmlNodePtr node, struct nc_err** error){

    mapping_t *mapping;
    locator_t *locator;
    lbuf_t *lbuf;
    lisp_addr_t *eid;
    lisp_addr_t *rloc;

    int result;


    printf("called lmapi_nc_xtr_mapdb_del\n");

    return EXIT_SUCCESS;
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

int lmapi_nc_xtr_mapdb_add(lmapi_connection_t *conn, xmlNodePtr xml_local_eid_database, struct nc_err** error){

    mapping_t *mapping;
    locator_t *locator;
    lbuf_t *lbuf;
    lisp_addr_t *eid;
    lisp_addr_t *rloc;
    char *str_eid = NULL;
    char *str_rloc = NULL;
    int prty = 2;
    int wght = 22;
    int result;

    //Dependent on YANG model
    xmlNodePtr xml_local_eid = NULL;
    xmlNodePtr xml_eid_prefix = NULL;
    xmlNodePtr xml_local_rlocs = NULL;
    xmlNodePtr xml_rloc = NULL;


    printf("called lmapi_nc_xtr_mapdb_add\n");

    xml_local_eid = xmlFirstElementChild(xml_local_eid_database);

    //Parse EID prefix
    //TODO iterate over more prefixes
    xml_eid_prefix = get_inner_xmlNodePtr(xml_local_eid,"eid-prefix");
    str_eid = (char*)xmlNodeGetContent(xml_eid_prefix);
    eid = lisp_addr_new();
    lisp_addr_ippref_from_char(str_eid,eid);

    printf("new eid created\n");

    mapping = mapping_init_local(eid);

    if (mapping == NULL){
        //TODO handle error
        goto err;
    }

    printf("mapping created\n");

    printf("Printing mapping: \n %s\n",mapping_to_char(mapping));


    xml_local_rlocs = get_inner_xmlNodePtr(xml_local_eid,"local-rlocs");
    //TODO iterate over locators
    xml_rloc = get_inner_xmlNodePtr(xml_local_rlocs,"rloc");
    str_rloc = (char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_rloc,"address"));
    if (get_inner_xmlNodePtr(xml_rloc,"priority") != NULL){
        prty = atoi((char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_rloc,"priority")));
    }
    if (get_inner_xmlNodePtr(xml_rloc,"weight") != NULL){
        wght = atoi((char*)xmlNodeGetContent(get_inner_xmlNodePtr(xml_rloc,"weight")));
    }

    rloc = lisp_addr_new();
    lisp_addr_ip_from_char(str_rloc,rloc);
    //XXX init_local_full to avoid segfaults caused by absence of extended info
    locator = locator_init_local_full(rloc,UP,prty,wght,255,0,NULL);

    printf("AFI %d\n",lisp_addr_get_iana_afi(locator->addr));

    if (locator == NULL){
        //TODO handle error
        goto err;
    }

    printf("locator created\n");

    //XXX YANG should include status for locators?
    //XXX YANG should account for no duplicate locators?

    printf("Printing mapping: \n %s\n",mapping_to_char(mapping));
    printf("Printing locator: \n %s\n",locator_to_char(locator));

    if (mapping_add_locator(mapping, locator) != GOOD){
        //TODO handle error
        goto err;
    }

    printf("added locator\n");

    lbuf = lbuf_new(MAX_API_PKT_LEN - sizeof(lmapi_msg_hdr_t));

    lisp_msg_put_mapping(lbuf,mapping,NULL);

    printf("mapping in buffer\n");





    result = lmapi_apply_config(conn,
            LMAPI_DEV_XTR,
            LMAPI_TRGT_MAPDB,
            LMAPI_OPR_CREATE,
            lbuf->data,
            lbuf->size);

    printf("config applied\n");

    lbuf_del(lbuf);
    printf("buf del \n");

    //XXX Check problem with locator free (double free of extended info) (locator former address still in locator lists)
    //locator_del(locator);
    printf("loc del\n");
    mapping_del(mapping);
    printf("map del\n");


    if (result != LMAPI_RES_OK){
        *error = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(*error, NC_ERR_PARAM_MSG, "Config couldn't be applied.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

err:
    LMLOG(DBG_3,"Error");

    *error = nc_err_new(NC_ERR_OP_FAILED);
    nc_err_set(*error, NC_ERR_PARAM_MSG, "Error while processing config modification request.");

    lbuf_del(lbuf);
    locator_del(locator);
    mapping_del(mapping);

    return EXIT_FAILURE;

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

    if ((dev == LMAPI_DEV_XTR) && (trgt == LMAPI_TRGT_MAPDB) &&
            ( (op & XMLDIFF_ADD) || (op & XMLDIFF_MOD) || (op & XMLDIFF_CHAIN) )) {
        return (lmapi_nc_xtr_mapdb_add(conn, node, error));
    }

    if ((dev == LMAPI_DEV_XTR) && (trgt == LMAPI_TRGT_MAPDB) &&
            ( (op & XMLDIFF_REM) )) {
        return (lmapi_nc_xtr_mapdb_rem(conn, node, error));
    }

    /* We should not reach here */
err:
    *error = nc_err_new(NC_ERR_OP_FAILED);
    nc_err_set(*error, NC_ERR_PARAM_MSG, "lispmob module: operation not supported");
    return (EXIT_FAILURE);

}
