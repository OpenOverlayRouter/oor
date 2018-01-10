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


#ifndef LISP_XTR_H_
#define LISP_XTR_H_

#include "lisp_tr.h"
#include "oor_ctrl_device.h"

//#include "../defs.h"
//#include "../fwd_policies/fwd_policy.h"
//#include "../lib/shash.h"

typedef struct lisp_xtr {
    oor_ctrl_dev_t super; /* base "class",  Don't change order */
    lisp_tr_t tr; /* Don't change order */

    glist_t *pitrs; // <lisp_addr_t *>

    /* DATABASES */
    local_map_db_t *local_mdb;

    /* MAP SERVERs */
    glist_t *map_servers; // <map_server_elt *>

    /* NAT */
    int nat_aware;
    int nat_status;
    lisp_site_id site_id;
    lisp_xtr_id xtr_id;

    /* TIMERS */
    oor_timer_t *smr_timer;
} lisp_xtr_t;

typedef struct map_server_elt_t {
    lisp_addr_t *   address;
    uint8_t         key_type;
    char *          key;
    uint8_t         proxy_reply;
} map_server_elt;



/**************************** LOGICAL PROCESSES ******************************/
lisp_xtr_t * lisp_xtr_cast(oor_ctrl_dev_t *dev);
/****************************** Map Register *********************************/
int xtr_program_map_register(lisp_xtr_t *xtr);
/*********************************** SMR *************************************/
void xtr_smr_start_for_locl_mapping(lisp_xtr_t *xtr, map_local_entry_t *map_loc_e);

/**************************** Map Server struct ******************************/

map_server_elt * map_server_elt_new_init(lisp_addr_t *address,uint8_t key_type, char *key,
        uint8_t proxy_reply);
void map_server_elt_del (map_server_elt *map_server);

/**********************************  Dump ************************************/
void proxy_etrs_dump(lisp_xtr_t *xtr, int log_level);
void map_servers_dump(lisp_xtr_t *xtr, int log_level);

#endif /* LISP_XTR_H_ */
