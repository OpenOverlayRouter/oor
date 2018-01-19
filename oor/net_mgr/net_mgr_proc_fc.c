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

#include "net_mgr.h"
#include "net_mgr_proc_fc.h"
#include "../control/oor_control.h"
#include "../data-plane/data-plane.h"
#include "../lib/oor_log.h"

/* Change the address of the interface. If the address belongs to a not
 * initialized locator, activate it. Program SMR */
void
nm_process_address_change(uint8_t act, uint32_t iface_index, lisp_addr_t *new_addr)
{
    iface_t *iface;
    lisp_addr_t *iface_addr;
    lisp_addr_t *new_addr_cpy;
    lisp_addr_t *old_addr_cpy;
    int new_addr_ip_afi;
    glist_t *iface_addr_list = NULL;
    uint8_t free_addr = FALSE;

    iface = get_interface_from_index(iface_index);

    if (iface == NULL) {
        OOR_LOG(LDBG_2, "nm_process_address_change: the notification message is not "
                "for any interface associated with RLOCs (%d)", iface_index);
        return;
    }

    new_addr_ip_afi = lisp_addr_ip_afi(new_addr);
    iface_addr = iface_address(iface,new_addr_ip_afi);

    if (iface_addr == NULL){
        OOR_LOG(LDBG_2,"nm_process_address_change: OOR not configured to use %s address for the interface %s",
                (new_addr_ip_afi == AF_INET ? "IPv4" : "IPv6"),iface->iface_name);
        return;
    }

    if (act == RM){
        OOR_LOG(LDBG_2,"nm_process_address_change: Address %s removed from interface %s",
                lisp_addr_to_char(new_addr),iface->iface_name);
        /* If we removed the active IPv6 address, try to get a new one */
        if (new_addr_ip_afi == AF_INET6){
            if (lisp_addr_cmp(iface_addr, new_addr) == 0){
                new_addr = net_mgr->netm_get_first_ipv6_addr_from_iface_with_scope(iface->iface_name,ipv6_scope);
                if (new_addr){
                    OOR_LOG(LDBG_2,"nm_process_address_change: Using next available address %s",
                            lisp_addr_to_char(new_addr));
                    free_addr = TRUE;
                    goto change;
                }
            }else{
                OOR_LOG(LDBG_2,"nm_process_address_change: The removed address %s is not being used by OOR",
                        lisp_addr_to_char(new_addr));
                return;
            }
        }
        new_addr = lisp_addr_new_lafi(LM_AFI_NO_ADDR);
        free_addr = TRUE;
        goto change;
    }

    /* Check if the addres is a global address*/
    if (ip_addr_is_link_local(lisp_addr_ip(new_addr)) == TRUE) {
        OOR_LOG(LDBG_2,"nm_process_address_change: the address is a local link "
                "address: %s discarded",lisp_addr_to_char(new_addr));
        return;
    }
    /* If default RLOC afi defined (-a 4 or 6), only accept addresses of the
     * specified afi */
    if (default_rloc_afi != AF_UNSPEC
        && default_rloc_afi != new_addr_ip_afi) {
        OOR_LOG(LDBG_2,"nm_process_address_change: Default RLOC afi defined (-a #): "
                "Skipped %s address in iface %s",
                (new_addr_ip_afi == AF_INET) ? "IPv4" : "IPv6",
                iface->iface_name);
        return;
    }
    /* If IPv6, check if the current address is still configured */
    if (new_addr_ip_afi == AF_INET6){
        /* If IPv6, check if the current address is still configured */
        iface_addr_list = net_mgr->netm_get_iface_addr_list(iface->iface_name,AF_INET6);
        if (glist_contain_using_cmp_fct(iface->ipv6_address,iface_addr_list, (glist_cmp_fct)lisp_addr_cmp)){
            OOR_LOG(LDBG_2,"nm_process_address_change: Current IPv6 address (%s) associated with interface %s is "
                    "still active. Ignoring change",lisp_addr_to_char(iface->ipv6_address), iface->iface_name);
            glist_destroy(iface_addr_list);
            return;
        }
        glist_destroy(iface_addr_list);
        /* Check the scope of the received address match with the selected one */
        if (ipv6_scope == SCOPE_GLOBAL){
            if (!IN6_IS_ADDR_GLOBAL(ip_addr_get_v6(lisp_addr_ip(new_addr)))){
                OOR_LOG(LDBG_2, "nm_process_address_change file: New IPv6 address %s doesn't match the IPv6 selected scope. Ignoring it...",
                        lisp_addr_to_char(new_addr));
                return;
            }
        }else { //SCOPE_SITE_LOCAL
            if (!IN6_IS_ADDR_SITE_LOCAL(ip_addr_get_v6(lisp_addr_ip(new_addr)))){
                OOR_LOG(LDBG_2, "nm_process_address_change file: New IPv6 address %s doesn't match the IPv6 selected scope. Ignoring it...",
                        lisp_addr_to_char(new_addr));
                return;
            }
        }
    }

change:
    /* Detected a valid change of address  */
    OOR_LOG(LDBG_2,"nm_process_address_change: New address detected for interface "
            "%s. Address changed from %s to %s", iface->iface_name,
            lisp_addr_to_char(iface_addr), lisp_addr_to_char(new_addr));

    old_addr_cpy = lisp_addr_clone(iface_addr);
    new_addr_cpy = lisp_addr_clone(new_addr);

    /* Update interface */
    lisp_addr_copy(iface_addr, new_addr);
    /* raise event to data plane */
    OOR_LOG(LDBG_3,"nm_process_address_change: Updating data plane");
    data_plane->datap_updated_addr(iface,old_addr_cpy,new_addr_cpy);
    /* raise event in ctrl */
    OOR_LOG(LDBG_3,"nm_process_address_change: Updating control data plane");
    ctrl_if_addr_update(lctrl, iface, old_addr_cpy, new_addr_cpy);
    lisp_addr_del(old_addr_cpy);
    lisp_addr_del(new_addr_cpy);
    if (free_addr){
        lisp_addr_del(new_addr);
    }
}


void
nm_process_link_change(uint32_t old_iface_index, uint32_t new_iface_index, uint8_t new_status)
{
    iface_t *iface;

    iface = get_interface_from_index(old_iface_index);
    if (!iface) {
        OOR_LOG(LDBG_2, "nm_process_link_change: the link change notification is not for "
                "any interface associated with RLOCs ");
        return;
    }

    /* Check if status has changed */
    if (iface->status == new_status){
        OOR_LOG(LDBG_2,"nm_process_link_change: The detected change of status"
                " doesn't affect");
        return;
    }
    OOR_LOG(LDBG_2, "nm_process_link_change: The interface %s has changed its status to %s",
            iface->iface_name, new_status == UP ? "UP" : "DOWN");

    /* Update iface */
    iface->status = new_status;
    iface->iface_index = new_iface_index;
    /* raise event to data plane */
    OOR_LOG(LDBG_3,"nm_process_link_change: Updating data plane");
    data_plane->datap_update_link(iface, old_iface_index, new_iface_index, new_status);
    /* raise event in ctrl */
    OOR_LOG(LDBG_3,"nm_process_link_change: Updating control data plane");
    ctrl_if_link_update(lctrl, iface, old_iface_index, new_iface_index, new_status);
}

void
nm_process_route_change(uint8_t act, uint32_t iface_index, lisp_addr_t *src,
        lisp_addr_t *dst, lisp_addr_t *gateway)
{
    iface_t *iface;

    iface = get_interface_from_index(iface_index);
    if (iface == NULL){
        OOR_LOG(LDBG_2, "nm_process_route_change: the route message is not for any "
                "interface associated with RLOCs (%d)", iface_index);
        return;
    }

    /* Check default afi*/

    if (lisp_addr_ip_afi(src) != LM_AFI_NO_ADDR &&
            default_rloc_afi != AF_UNSPEC &&
            default_rloc_afi != lisp_addr_ip_afi(src)) {
        OOR_LOG(LDBG_1, "nm_process_route_change: Default RLOC afi "
                "defined (-a #): Skipped route with source address %s in iface %s",
                (lisp_addr_ip_afi(src)== AF_INET) ? "IPv4" : "IPv6",
                        iface->iface_name);
        return;
    }

    if (lisp_addr_ip_afi(dst) != LM_AFI_NO_ADDR &&
            default_rloc_afi != AF_UNSPEC &&
            default_rloc_afi != lisp_addr_ip_afi(dst)) {
        OOR_LOG(LDBG_1, "nm_process_route_change: Default RLOC afi "
                "defined (-a #): Skipped route with destination address %s in iface %s",
                (lisp_addr_ip_afi(dst)== AF_INET) ? "IPv4" : "IPv6",
                        iface->iface_name);
        return;
    }

    if (lisp_addr_ip_afi(gateway) != LM_AFI_NO_ADDR &&
            default_rloc_afi != AF_UNSPEC &&
            default_rloc_afi != lisp_addr_ip_afi(gateway)) {
        OOR_LOG(LDBG_1, "nm_process_route_change gateway %s  in iface %s",
                (lisp_addr_ip_afi(gateway)== AF_INET) ? "IPv4" : "IPv6",
                        iface->iface_name);
        return;
    }

    OOR_LOG(LDBG_2, "nm_process_route_change: %s route: src: %s, dst: %s , gw: %s",
            act == ADD ? "Added" : "Removed", lisp_addr_to_char(src),
                    lisp_addr_to_char(dst), lisp_addr_to_char(gateway));

    /* raise event to data plane */
    OOR_LOG(LDBG_3,"nm_process_route_change: Updating data plane");
    data_plane->datap_updated_route(act, iface, src, dst, gateway);
    /* raise event to control plane */
    OOR_LOG(LDBG_3,"nm_process_route_change: Updating control data plane");
    ctrl_route_update(lctrl, act, iface, src, dst, gateway);
}


