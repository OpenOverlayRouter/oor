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

#ifndef OOR_CONTROL_LISP_RTR_H_
#define OOR_CONTROL_LISP_RTR_H_

#include "lisp_tr.h"
#include "oor_ctrl_device.h"




typedef struct lisp_rtr {
    oor_ctrl_dev_t super; /* base "class" ,  Don't change order*/

    lisp_tr_t tr; /* Don't change order */

    /* LOCAL IFACE MAPPING */
    /* in case of RTR can be used for outgoing load balancing */
    map_local_entry_t *all_locs_map;
    shash_t *rtr_ms_table; //< IP char * , rtr_ms_node_t *>
} lisp_rtr_t;

typedef struct rtr_ms_node {
    lisp_addr_t * addr;
    char * key;
    nat_version nat_version;
}rtr_ms_node_t;

inline lisp_rtr_t * lisp_rtr_cast(oor_ctrl_dev_t *dev);

/************************** rtr_ms_node_t functions **************************/

rtr_ms_node_t * rtr_ms_node_new_init(lisp_addr_t *addr, char *key, nat_version version);
void rtr_ms_node_destroy(rtr_ms_node_t *ms_node);
char *rtr_ms_node_to_char(rtr_ms_node_t *ms_node);

#endif /* OOR_CONTROL_LISP_RTR_H_ */
