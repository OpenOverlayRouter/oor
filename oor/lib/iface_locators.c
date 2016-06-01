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

#include "../defs.h"
#include "../iface_list.h"
#include "iface_locators.h"
#include "oor_log.h"
#include "sockets.h"

iface_locators *iface_locators_get_element_with_loct(shash_t *iface_locators_table,
        locator_t *locator);

/*
 * Creates and initialize a new iface_locator
 * @param iface_name Name of the interface
 * @return iface_locators element
 */
iface_locators *
iface_locators_new(char *iface_name)
{
    iface_locators *if_loct;

    if_loct = xzalloc(sizeof(iface_locators));
    if_loct->iface_name = xstrdup(iface_name);
    if_loct->map_loc_entries = glist_new();
    if_loct->ipv4_locators = glist_new();
    if_loct->ipv6_locators = glist_new();
    if_loct->status_changed = TRUE;

    return(if_loct);
}

/*
 * Release memory of an iface_locators structure
 * @param if_loct Element to be released
 */
void
iface_locators_del(iface_locators *if_loct)
{
    free(if_loct->iface_name);
    glist_destroy(if_loct->map_loc_entries);
    glist_destroy(if_loct->ipv4_locators);
    glist_destroy(if_loct->ipv6_locators);
    if (if_loct->ipv4_prev_addr != NULL){
        lisp_addr_del(if_loct->ipv4_prev_addr);
    }
    if (if_loct->ipv6_prev_addr != NULL){
        lisp_addr_del(if_loct->ipv6_prev_addr);
    }
    free(if_loct);
}



void
iface_locators_attach_map_local_entry(shash_t *iface_locators_table,
        map_local_entry_t * map_loc_e)
{
    mapping_t * mapping;
    locator_t * locator;
    iface_locators * iface_loct;

    mapping = map_local_entry_mapping(map_loc_e);

    mapping_foreach_locator(mapping,locator){
    		iface_loct = iface_locators_get_element_with_loct(
    				iface_locators_table, locator);
    		if (iface_loct != NULL &&
    				glist_contain(map_loc_e, iface_loct->map_loc_entries) == FALSE){
    			glist_add(map_loc_e, iface_loct->map_loc_entries);
    		}
    }mapping_foreach_locator_end;
}

void
iface_locators_unattach_mapping_and_loct(shash_t *iface_locators_table,
        map_local_entry_t * map_loc_e)
{
    glist_t *iface_loct_list;
    glist_entry_t *it_if_loct;
    iface_locators *iface_loct;
    mapping_t *mapping;
    locator_t *locator;

    mapping = map_local_entry_mapping(map_loc_e);
    mapping_foreach_locator(mapping,locator){
        iface_locators_unattach_locator(iface_locators_table, locator);
    }mapping_foreach_locator_end;

    iface_loct_list = shash_values(iface_locators_table);
    glist_for_each_entry(it_if_loct,iface_loct_list){
        iface_loct = (iface_locators *)glist_entry_data(it_if_loct);
        glist_remove_obj(map_loc_e,iface_loct->map_loc_entries);
    }
}

/*
 * Remove a locator from the structure iface_locators associated to it.
 */
void
iface_locators_unattach_locator(shash_t *iface_locators_table, locator_t *locator)
{
    lisp_addr_t * ip_addr;
    lisp_addr_t * addr = locator_addr(locator);
    iface_locators * iface_loct;
    glist_t * loct_lists[2];
    glist_entry_t * it_loct;
    locator_t * loct;
    int ctr;
    uint16_t afi = AF_UNSPEC;


    /* Get structure from where the locator is removed */
    iface_loct = iface_locators_get_element_with_loct(iface_locators_table,locator);
    if (iface_loct == NULL){
        return;
    }

    if (lisp_addr_is_no_addr(addr) == FALSE){
    	ip_addr = lisp_addr_get_ip_addr(addr);
    	if (ip_addr == NULL) {
    		OOR_LOG(LERR, "unattach_locator_from_iface: Can't determine RLOC's IP "
    				"address %s", lisp_addr_to_char(addr));
    		return;
    	}
        afi = lisp_addr_ip_afi(ip_addr);
    }else{
        loct_lists[0] = iface_loct->ipv4_locators;
        loct_lists[1] = iface_loct->ipv6_locators;
        for (ctr=0;ctr<2;ctr++){
            glist_for_each_entry(it_loct,loct_lists[ctr]){
                loct = (locator_t *)glist_entry_data(it_loct);
                if (loct == locator){
                    if (ctr == 0){
                        afi = AF_INET;
                    }else{
                        afi = AF_INET6;
                    }
                    break;
                }
            }
            if (afi != AF_UNSPEC){
                break;
            }
        }
    }

    switch (afi){
    case AF_INET:
        glist_remove_obj(locator,iface_loct->ipv4_locators);
        break;
    case AF_INET6:
        glist_remove_obj(locator,iface_loct->ipv6_locators);
        break;
    }

    return;
}

iface_locators *
iface_locators_get_element_with_loct(shash_t *iface_locators_table,
        locator_t *locator)
{
    glist_t * iface_loct_list;
    glist_entry_t * it;
    glist_entry_t * it_loct;
    iface_locators * iface_loct;
    glist_t * loct_lists[2];
    locator_t * loct;
    lisp_addr_t * addr = locator_addr(locator);
    lisp_addr_t * ip_addr;
    char * iface_name;
    int ctr;

    if (lisp_addr_is_no_addr(addr) == FALSE)
    {
    	ip_addr = lisp_addr_get_ip_addr(addr);
    	if (ip_addr == NULL) {
    		OOR_LOG(LERR, "iface_locators_get_element_with_loct: Can't determine RLOC's IP "
                    "address %s", lisp_addr_to_char(addr));
    		return (NULL);
    	}

        /* Find the interface name associated to the RLOC */
        iface_name = get_interface_name_from_address(ip_addr);
        if (iface_name == NULL){
            OOR_LOG(LERR, "iface_locators_get_element_with_loct: Can't find iface associated to "
                                "address %s", lisp_addr_to_char(addr));
            return (NULL);
        }

        /* Get iface-locators structure and add the mapping */
        iface_loct = shash_lookup(iface_locators_table, iface_name);

        return (iface_loct);
    }else{
        iface_loct_list = shash_values(iface_locators_table);
        glist_for_each_entry(it,iface_loct_list){
            iface_loct = (iface_locators *)glist_entry_data(it);
            loct_lists[0] = iface_loct->ipv4_locators;
            loct_lists[1] = iface_loct->ipv6_locators;
            for (ctr=0;ctr<2;ctr++){
                glist_for_each_entry(it_loct,loct_lists[ctr]){
                    loct = (locator_t *)glist_entry_data(it_loct);
                    if (loct == locator){
                        glist_destroy(iface_loct_list);
                        return (iface_loct);
                    }
                }
            }
        }
    }
    glist_destroy(iface_loct_list);
    return (NULL);
}

