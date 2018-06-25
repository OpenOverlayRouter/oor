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

#ifndef NET_MGR_H_
#define NET_MGR_H_

#include "../lib/generic_list.h"
#include "../lib/shash.h"
#include "../liblisp/lisp_address.h"


typedef struct net_mgr_class {
    int (*netm_init)();
    void (*netm_uninit)();
    glist_t *(*netm_get_ifaces_names)();
    glist_t *(*netm_get_iface_addr_list)(char *, int);
    /*netm_get_src_addr_to only works for the gw*/
    lisp_addr_t *(*netm_get_src_addr_to)(lisp_addr_t *);
    lisp_addr_t *(*netm_get_iface_gw)(char *,int);
    lisp_addr_t *(*netm_get_first_ipv6_addr_from_iface_with_scope)(char *, ipv6_scope_e);
    uint8_t (*netm_get_iface_status)(char *);
    int (*netm_get_iface_index)(char *);
    void (*netm_get_iface_mac_addr)(char *, uint8_t *);
    int (*netm_reload_routes)(uint32_t table, int afi);
    shash_t *(*netm_build_addr_to_if_name_hasht)();
    char *(*netm_get_iface_associated_with_pref)(lisp_addr_t *addr);
    void * data;
} net_mgr_class_t;

void net_mgr_select();

extern net_mgr_class_t netm_kernel;
extern net_mgr_class_t netm_vpp;
extern net_mgr_class_t netm_apple;

#endif /* NET_MGR_H_ */
