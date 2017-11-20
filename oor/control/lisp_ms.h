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

#ifndef LISP_MS_H_
#define LISP_MS_H_

#include "oor_ctrl_device.h"
#include "../lib/lisp_site.h"

typedef struct _rtr_set {
    char *id;
    int ttl;
    glist_t *rtr_list; //<rtr_node_t *>
}ms_rtr_set_t;

typedef struct _rtr_node_t {
    char *id;
    lisp_addr_t *addr;
    lisp_key_type_e key_type;
    char *passwd;
}ms_rtr_node_t;

typedef struct _lisp_ms {
    oor_ctrl_dev_t super;    /* base "class" */

    /* ms members */
    mdb_t *lisp_sites_db;
    mdb_t *reg_sites_db;

    /* List of lists of RTRs used for NAT Traversal */
    shash_t *rtrs_set_table; // <key= id , value= rtr_set_t *>
    /* Two hashes two search same object using different fields */
    shash_t *rtrs_table_by_name; // <key= id , value= rtr_node_t *>
    shash_t *rtrs_table_by_ip; // <key= ip_str , value= rtr_node_t *>
    ms_rtr_set_t *def_rtr_set;
} lisp_ms_t;


/* ms interface */
int ms_add_lisp_site_prefix(lisp_ms_t *ms, lisp_site_prefix_t *site);
int ms_add_registered_site_prefix(lisp_ms_t *dev, mapping_t *sp);
void ms_dump_configured_sites(lisp_ms_t *dev, int log_level);
void ms_dump_registered_sites(lisp_ms_t *dev, int log_level);

inline lisp_ms_t *lisp_ms_cast(oor_ctrl_dev_t *dev);
/*****  Basic rtr_node_t and rtr_set_t functions *****/
ms_rtr_node_t *ms_rtr_node_new_init(char *id, lisp_addr_t *addr, char *passwd);
void ms_rtr_node_del(ms_rtr_node_t * rtr);
ms_rtr_set_t *ms_rtr_set_new_init(char *id, int ttl);
void ms_rtr_set_del(ms_rtr_set_t *rtr_set);
void ms_rtr_set_dump(ms_rtr_set_t *rtr_set, int log_level);

#endif /* LISP_MS_H_ */
