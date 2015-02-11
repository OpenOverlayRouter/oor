/*
 * lispd_api_internals.c
 *
 * This file is part of LISPmob implementation. It implements
 * the API to interact with LISPmob internals.
 *
 * Copyright (C) The LISPmob project, 2015. All rights reserved.
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
 *    LISPmob developers <devel@lispmob.org>
 *
 */

#include "lispd_api_internals.h"

#include "lispd_config_functions.h"
#include "lib/lmlog.h"
#include "liblisp/liblisp.h"
#include "lib/util.h"
#include "data-tun/lispd_tun.h"

#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>



int lmapi_init_server(lmapi_connection_t *conn) {

	int error = 0;

    conn->context = zmq_ctx_new();
    LMLOG(DBG_3,"LMAPI: zmq_ctx_new errno: %s\n",zmq_strerror (errno));

    //Request-Reply communication pattern (Server side)
    conn->socket = zmq_socket(conn->context, ZMQ_REP);
    LMLOG(DBG_3,"LMAPI: zmq_socket: %s\n",zmq_strerror (errno));

    //Attachment point for other processes
    error = zmq_bind(conn->socket, IPC_FILE);

    if (error != 0){
    	LMLOG(DBG_2,"LMAPI: Error while ZMQ binding on server: %s\n",zmq_strerror (error));
    	goto err;
    }

    LMLOG(DBG_2,"LMAPI: API server initiated using ZMQ\n");

    return (GOOD);

err:
    LMLOG(LERR,"LMAPI: The API server couldn't be initialized.\n");
    return (BAD);

}

int lmapi_xtr_mr_create(lmapi_connection_t *conn, lmapi_msg_hdr_t *hdr, uint8_t *data){

    lisp_addr_t *   mr_itr          = NULL;
    uint8_t *       pos_itr         = NULL;
    int             mr_len          = 0;
    int             total_len       = 0;
    lisp_xtr_t *    xtr             = NULL;
    uint8_t *       result_msg      = NULL;
    int             result_msg_len  = 0;
    glist_t *       list            = NULL;


    LMLOG(DBG_1, "LMAPI: Creating new list of Map Resolvers");

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);


    list = glist_new_managed((glist_del_fct)lisp_addr_del);
    pos_itr = data;

    while (total_len < hdr->datalen){
        mr_itr = lisp_addr_new();
        mr_len = lisp_addr_parse(pos_itr,mr_itr);

        if (!mr_len){
        	LMLOG(LWRN, "lmapi_xtr_mr_create: Couldn't parse address");
        	goto err;
        }

        if (default_rloc_afi != AF_UNSPEC && default_rloc_afi != lisp_addr_ip_afi(mr_itr)){
        	LMLOG(LWRN, "lmapi_xtr_mr_create: The Map Resolver %s will not be added due to the selected "
        			"default rloc afi (-a option)", lisp_addr_to_char(mr_itr));
        	goto err;
        }

        glist_add_tail(lisp_addr_clone(mr_itr), list);

        pos_itr = CO(pos_itr,mr_len);
        total_len += mr_len;
        lisp_addr_del(mr_itr);
    }

    if (total_len != hdr->datalen){
    	LMLOG(LWRN, "lmapi_xtr_mr_create: Expected data length was %d, "
    			"however received data length is %d", lisp_addr_to_char(mr_itr));
    	goto err;

    }

    //Everything fine. We replace the old list with the new one
    glist_destroy(xtr->map_resolvers);
    xtr->map_resolvers = list;

    LMLOG(DBG_1, "LMAPI: List of Map Resolvers successfully created");
    LMLOG(DBG_2, "************* %13s ***************", "Map Resolvers");
            glist_dump(xtr->map_resolvers, (glist_to_char_fct)lisp_addr_to_char, DBG_1);

	result_msg_len = lmapi_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,LMAPI_RES_OK);
    lmapi_send(conn,result_msg,result_msg_len,LMAPI_NOFLAGS);

    return GOOD;

err:
	LMLOG(LERR, "LMAPI: Error while creating Map Resolver list");

	glist_destroy(list);

	result_msg_len = lmapi_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,LMAPI_RES_ERR);
    lmapi_send(conn,result_msg,result_msg_len,LMAPI_NOFLAGS);

    return BAD;

}

int lmapi_xtr_mr_delete(lmapi_connection_t *conn, lmapi_msg_hdr_t *hdr, uint8_t *data){

	lisp_xtr_t *xtr = NULL;
	uint8_t *result_msg;
	int result_msg_len;

	LMLOG(DBG_2, "LMAPI: Deleting Map Resolver list");


	xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

	if (xtr->map_resolvers == NULL){
		//ERROR: Already NULL
		result_msg_len = lmapi_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,LMAPI_RES_ERR);
		lmapi_send(conn,result_msg,result_msg_len,LMAPI_NOFLAGS);
		LMLOG(LWRN, "LMAPI: Trying to remove Map Resolver list, but list was already empty");
		return BAD;
	}

	glist_destroy(xtr->map_resolvers);
	xtr->map_resolvers = NULL;

	result_msg_len = lmapi_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,LMAPI_RES_OK);
	lmapi_send(conn,result_msg,result_msg_len,LMAPI_NOFLAGS);

	LMLOG(DBG_1, "LMAPI: Map Resolver list deleted");

	return GOOD;

}


static void add_locator_list_to_config_mapping(conf_mapping_t *cfg_map, locator_list_t *loc_lst_pos){

    conf_loc_t*   cfg_loc;

    while (loc_lst_pos != NULL){
        cfg_loc = conf_loc_new();

        cfg_loc->address = strdup(lisp_addr_to_char(loc_lst_pos->locator->addr));
        cfg_loc->priority = loc_lst_pos->locator->priority;
        cfg_loc->weight =loc_lst_pos->locator->weight;

        LMLOG(DBG_3, "LMAPI: Converted new config_locator: %s, %d/%d",
                cfg_loc->address,cfg_loc->priority,cfg_loc->weight);

        glist_add(cfg_loc,cfg_map->conf_loc_list);

        loc_lst_pos = loc_lst_pos->next;
    }

}

int lmapi_xtr_mapdb_create(lmapi_connection_t *conn, lmapi_msg_hdr_t *hdr, uint8_t *data){

    lisp_xtr_t *        xtr                 = NULL;
    mapping_t *         parsed_mapping      = NULL;
    mapping_t *         processed_mapping   = NULL;

    lbuf_t              b;

    glist_t *           map_list            = NULL;
    glist_t *           conf_map_list       = NULL;
    glist_entry_t *     map_entry           = NULL;

    locator_list_t *    loc_it              = NULL;
    conf_mapping_t *    conf_mapping        = NULL;

    int                 result_msg_len      = 0;
    uint8_t *           result_msg          = NULL;


    LMLOG(DBG_2, "LMAPI: Creating Mapping Database");

    xtr = CONTAINER_OF(ctrl_dev, lisp_xtr_t, super);

    lbuf_set_data(&b,data);
    lbuf_set_size(&b,hdr->datalen);

    map_list = glist_new_managed((glist_del_fct)mapping_del);
    conf_map_list = glist_new_managed((glist_del_fct)conf_mapping_destroy);

    /* We get the mappings from the raw message */

    while (lbuf_size(&b) > 0){

        parsed_mapping = mapping_new();
        if (lisp_msg_parse_mapping_record(&b,parsed_mapping,NULL) != GOOD){
            LMLOG(LERR, "LMAPI: Couldn't parse parsed_mapping");
            goto err;
        }

        glist_add(parsed_mapping,map_list);
    }

    LMLOG(DBG_3, "LMAPI: %d mapping(s) parsed from API message",glist_size(map_list));

    /* We convert the extracted mappings to configuration mappings */

    glist_for_each_entry(map_entry, map_list){
        parsed_mapping = (mapping_t *) glist_entry_data(map_entry);

        conf_mapping = conf_mapping_new();
        conf_mapping->eid_prefix = strdup(lisp_addr_to_char(&(parsed_mapping->eid_prefix)));

        loc_it = parsed_mapping->head_v4_locators_list;
        add_locator_list_to_config_mapping(conf_mapping,loc_it);
        loc_it = parsed_mapping->head_v6_locators_list;
        add_locator_list_to_config_mapping(conf_mapping,loc_it);

        glist_add(conf_mapping,conf_map_list);

    }

    LMLOG(DBG_3, "LMAPI: %d mapping(s) converted into config_mappings",glist_size(conf_map_list));

    /* We leverage on the LISPmob configuration subsystem to introduce
     * and process the configuration mappings into the system */

    glist_for_each_entry(map_entry, conf_map_list){

        conf_mapping = (conf_mapping_t *) glist_entry_data(map_entry);

        //XXX Beware the NULL in lcaf_ht. No LCAF support yet
        processed_mapping = process_mapping_config(&(xtr->super),NULL,LOCAL_LOCATOR,conf_mapping);

        if (processed_mapping == NULL){
            LMLOG(DBG_3, "LMAPI: Couldn't process mapping %s",conf_mapping->eid_prefix);
            goto err;
        }

        if (add_local_db_mapping(processed_mapping,xtr) != GOOD){
            LMLOG(DBG_3, "LMAPI: Couldn't add mapping %s to local database",
                    lisp_addr_to_char(&(processed_mapping->eid_prefix)));
            goto err;
        }

        LMLOG(DBG_1, "LMAPI: Updating data-plane for EID prefix %s",
                lisp_addr_to_char(&(processed_mapping->eid_prefix)));

        if (ctrl_register_eid_prefix(ctrl_dev,mapping_eid(processed_mapping))!=GOOD){
           LMLOG(LERR, "LMAPI: Unable to update data-plane for mapping %s",
                   lisp_addr_to_char(&(processed_mapping->eid_prefix)));
           goto err;
       }


    }

    result_msg_len = lmapi_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,LMAPI_RES_OK);
    lmapi_send(conn,result_msg,result_msg_len,LMAPI_NOFLAGS);


    glist_destroy(map_list);
    glist_destroy(conf_map_list);

    return GOOD;

err:
    //XXX if error, destroy mappings added to local mapdb? deattach locators from ifaces?

    result_msg_len = lmapi_result_msg_new(&result_msg,hdr->device,hdr->target,hdr->operation,LMAPI_RES_ERR);
    lmapi_send(conn,result_msg,result_msg_len,LMAPI_NOFLAGS);
    LMLOG(LWRN, "LMAPI: Error while setting new Mapping Database content");

    //XXX beware double free

    glist_destroy(map_list);
    glist_destroy(conf_map_list);

    return BAD;
}


int (*lmapi_get_proc_func(lmapi_msg_hdr_t* hdr))(lmapi_connection_t *,lmapi_msg_hdr_t *, uint8_t *){

    int (*process_func)(lmapi_connection_t *, lmapi_msg_hdr_t *, uint8_t *) = NULL;

    lisp_dev_type_e device = hdr->device;
    lmapi_msg_target_e target = hdr->target;
    lmapi_msg_opr_e operation = hdr->operation;


    switch (device){
    case LMAPI_DEV_XTR:
        switch (target){
        case LMAPI_TRGT_MRLIST:
            switch (operation){
                case LMAPI_OPR_CREATE:
                	LMLOG(DBG_2, "LMAPI call = (Device: xTR | Target: MR list | Operation: Create)");
                    process_func = lmapi_xtr_mr_create;
                    break;
                case LMAPI_OPR_DELETE:
                	LMLOG(DBG_2, "LMAPI call = (Device: xTR | Target: MR list | Operation: Delete)");
                	process_func = lmapi_xtr_mr_delete;
                	break;
                default:
                	LMLOG(LWRN, "LMAPI call = (Device: xTR | Target: MR list | Operation: Unsupported)");
                    break;
                }
            break;
        case LMAPI_TRGT_MAPDB:
            switch (operation){
                case LMAPI_OPR_CREATE:
                    LMLOG(DBG_2, "LMAPI call = (Device: xTR | Target: Mapping DB | Operation: Create)");
                    process_func = lmapi_xtr_mapdb_create;
                    break;
                default:
                    LMLOG(LWRN, "LMAPI call = (Device: xTR | Target: Mapping DB | Operation: Unsupported)");
                    break;
            }
            break;
        default:
        	LMLOG(LWRN, "LMAPI call = (Device: xTR | Target: Unsupported)");
            break;
        }
        break;
    default:
    	LMLOG(LWRN, "LMAPI call = (Device: Unsupported)");
        break;
    }

    return process_func;
}

void lmapi_loop(lmapi_connection_t *conn) {

    uint8_t *buffer;
    uint8_t *data;
    int nbytes;
    int datalen;
    lmapi_msg_hdr_t *header;
    int (*process_func)(lmapi_connection_t *, lmapi_msg_hdr_t *, uint8_t *) = NULL;

    buffer = xzalloc(MAX_API_PKT_LEN);

    nbytes = lmapi_recv(conn,buffer,LMAPI_DONTWAIT);

    if (nbytes == LMAPI_NOTHINGTOREAD){
    	goto end;
    }

    if (nbytes == LMAPI_ERROR){
    	LMLOG(LERR, "lmapi_loop: Error while trying to retrieve API packet\n");
    	goto end;
    }

    header = (lmapi_msg_hdr_t *)buffer;

    data = CO(buffer,sizeof(lmapi_msg_hdr_t));
    datalen = nbytes - sizeof(lmapi_msg_hdr_t);

    if (header->datalen < datalen){
        LMLOG(LWRN, "lmapi_loop: API packet longer than expected\n");
    }
    else if (header->datalen > datalen){
        LMLOG(LERR, "lmapi_loop: API packet shorter than expected\n");
        goto end;
    }

    process_func = lmapi_get_proc_func(header);

    if (process_func != NULL){
    	(*process_func)(conn,header,data);
    }

end:
    free(buffer);

    return;
}


