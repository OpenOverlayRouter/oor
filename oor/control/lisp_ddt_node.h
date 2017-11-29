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

#ifndef LISP_DDT_NODE_H_
#define LISP_DDT_NODE_H_

#include "oor_ctrl_device.h"
#include "../lib/lisp_site.h"
#include "../liblisp/lisp_mref_mapping.h"


typedef struct _lisp_ddt_node {
    oor_ctrl_dev_t super;    /* base "class" */

    /* ddt-node members */
    mdb_t *auth_sites_db; /* auth_sites_db is filled with ddt_authoritative_site_t */
    mdb_t *deleg_sites_db; /* deleg_sites_db is filled with ddt_delegation_site_t */
} lisp_ddt_node_t;

typedef struct _ddt_authoritative_site{
	lisp_addr_t *xeid;
} ddt_authoritative_site_t;

typedef enum ddt_deleg_type {
    CHILD_DDT_NODE,
    MAP_SERVER_DDT_NODE
} ddt_deleg_type_e;

typedef struct _ddt_delegation_site{
    mref_mapping_t *mapping;
} ddt_delegation_site_t;

/* DDT-Node interface */

void ddt_node_dump_authoritative_sites(lisp_ddt_node_t *dev, int log_level);
void ddt_node_dump_delegation_sites(lisp_ddt_node_t *dev, int log_level);

int ddt_node_add_authoritative_site(lisp_ddt_node_t *ddt_node, ddt_authoritative_site_t *site);
int ddt_node_add_delegation_site(lisp_ddt_node_t *ddt_node, ddt_delegation_site_t *site);

ddt_authoritative_site_t *ddt_authoritative_site_init(lisp_addr_t *eid_prefix, uint32_t iid);
ddt_delegation_site_t *ddt_delegation_site_init(lisp_addr_t *eid_prefix, uint32_t iid, int type, glist_t *child_nodes);
void ddt_authoritative_site_del(ddt_authoritative_site_t *as);
static inline lisp_addr_t *
asite_xeid(ddt_authoritative_site_t *as) {
    return(as->xeid);
}
void ddt_delegation_site_del(ddt_delegation_site_t *ds);
static inline lisp_addr_t *
dsite_xeid(ddt_delegation_site_t *ds) {
    return(mref_mapping_eid(ds->mapping));
}

#endif /* LISP_DDT_NODE_H_ */
