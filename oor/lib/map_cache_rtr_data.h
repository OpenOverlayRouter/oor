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

#ifndef OOR_LIB_MAP_CACHE_RTR_DATA_H_
#define OOR_LIB_MAP_CACHE_RTR_DATA_H_

#include "htable_ptrs.h"
#include "map_cache_entry.h"
#include "shash.h"
#include "../liblisp/lisp_address.h"
#include "../liblisp/lisp_message_fields.h"

/*
 * Structure used to store the NAT information learned during the process
 * of the Encapsulated Map Registers
 */
typedef struct rloc_nat_data_t_{
    lisp_addr_t *pub_addr;
    uint16_t pub_port;
    lisp_addr_t *priv_addr;
    lisp_addr_t *rtr_rloc;
    lisp_xtr_id xtr_id;
    uint8_t priority;
    uint8_t weight;
}rloc_nat_data_t;

typedef struct mc_rtr_nat_data_t_{
    /* Group rloc_nat_data using the xTR_ID. Used in process of EMReg and to build the
     * mapping*/
    shash_t *xtrid_to_nat; // <xTR_id str , glist <rloc_nat_data_t>>
    /* Hash table to locate the nat information associated to a locator. Usied during
     * build of forwarding  structure*/
    htable_ptrs_t *loc_to_nat_data; //<locator ptr,rloc_nat_data_t>
}mc_rtr_nat_data_t;

typedef struct mc_rtr_data_t_{
    mc_rtr_nat_data_t *nat_data;
}mc_rtr_data_t;

inline mc_rtr_data_t * mc_rtr_data_new();
mc_rtr_data_t * mc_rtr_data_nat_new();
void mc_rtr_data_destroy(mc_rtr_data_t *mc);
char *rloc_nat_data_to_char(rloc_nat_data_t *rloc_nat_data);
int mc_rtr_data_mapping_update(mcache_entry_t *mc, mapping_t *rcv_map, lisp_addr_t *rtr_addr,
        lisp_addr_t *xTR_pub_addr, uint16_t xTR_port, lisp_addr_t *xTR_prv_addr, lisp_xtr_id *xtr_id);
int mc_rm_rtr_rloc_nat_data(mcache_entry_t *mce, rloc_nat_data_t *rloc_nat_data);
rloc_nat_data_t * mc_rtr_data_get_rloc_nat_data(mcache_entry_t *mc, lisp_xtr_id *xtr_id,
        lisp_addr_t *xTR_prv_addr);




#endif /* OOR_LIB_MAP_CACHE_RTR_DATA_H_ */
