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

#ifndef IFACE_LOCATORS_H_
#define IFACE_LOCATORS_H_

#include "map_local_entry.h"
#include "shash.h"
#include "../liblisp/liblisp.h"


typedef struct iface_locators_{
    char        *iface_name;
    glist_t     *map_loc_entries;   /*Mappings associated to this iface <map_local_entry_t>*/
    glist_t     *ipv4_locators;     /*IPv4 locators associated with this iface <lisp_addr_t>*/
    glist_t     *ipv6_locators;     /*IPv6 locators associated with this iface <lisp_addr_t>*/
    uint8_t     status_changed;     /*Iface change status --> Used to avioid transitions*/
    lisp_addr_t *ipv4_prev_addr;    /*Previous IPv4 address of the iface --> Used to avoid transitions A->B->A*/
    lisp_addr_t *ipv6_prev_addr;    /*Previous IPv6 address of the iface --> Used to avoid transitions A->B->A*/
}iface_locators;

iface_locators *iface_locators_new(char *iface_name);
void iface_locators_del(iface_locators *if_loct);

void
iface_locators_attach_map_local_entry(
        shash_t *   iface_locators_table,
        map_local_entry_t * map_loc_e);

void iface_locators_unattach_mapping_and_loct(shash_t *iface_locators_table,
        map_local_entry_t * map_loc_e);

void iface_locators_unattach_locator(shash_t *iface_locators_table,
        locator_t *locator);

#endif /* IFACE_LOCATORS_H_ */
