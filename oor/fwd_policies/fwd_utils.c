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


#include "fwd_utils.h"
#include "../lib/oor_log.h"


void
locators_classify_in_4_6(mapping_t *mapping, glist_t *loc_loct_addr,
        glist_t *ipv4_loct_list, glist_t *ipv6_loct_list, get_fwd_ip_addr fwd_if)
{
    locator_t *locator;
    lisp_addr_t *addr;
    lisp_addr_t *ip_addr;

    if (glist_size(mapping->locators_lists) == 0){
        OOR_LOG(LDBG_3,"locators_classify_in_4_6: No locators to classify for mapping with eid %s",
                lisp_addr_to_char(mapping_eid(mapping)));
        return;
    }
    mapping_foreach_active_locator(mapping,locator){
        addr = locator_addr(locator);
        ip_addr = fwd_if(addr,loc_loct_addr);
        if (ip_addr == NULL){
            OOR_LOG(LDBG_2,"locators_classify_in_4_6: No IP address for %s", lisp_addr_to_char(addr));
            continue;
        }

        if (lisp_addr_ip_afi(ip_addr) == AF_INET){
            glist_add(locator,ipv4_loct_list);
        }else{
            glist_add(locator,ipv6_loct_list);
        }
    }mapping_foreach_active_locator_end;
}
