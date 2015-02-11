/*
 * iface_locators.c
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2014 Universitat Politècnica de Catalunya.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Albert López <alopez@ac.upc.edu>
 */

#include "../defs.h"
#include "../iface_list.h"
#include "iface_locators.h"
#include "lmlog.h"
#include "sockets.h"

iface_locators *
iface_locators_get_element_with_loct(
        shash_t *       iface_locators_table,
        locator_t *     locator);

/*
 * Creates and initialize a new iface_locator
 * @param iface_name Name of the interface
 * @return iface_locators element
 */
iface_locators *iface_locators_new(char *iface_name)
{
    iface_locators *if_loct = NULL;
    if_loct = xzalloc(sizeof(iface_locators));
    if_loct->iface_name = xstrdup(iface_name);
    if_loct->mappings = glist_new();
    if_loct->ipv4_locators = glist_new();
    if_loct->ipv6_locators = glist_new();
    if_loct->status_changed = TRUE;
    return(if_loct);
}

/*
 * Release memory of an iface_locators structure
 * @param if_loct Element to be released
 */
void iface_locators_del(iface_locators *if_loct)
{
    free(if_loct->iface_name);
    glist_destroy(if_loct->mappings);
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
iface_locators_attach_mapping(
        shash_t *   iface_locators_table,
        mapping_t * mapping)
{
    locator_list_t *    locators_lists[3]   = {NULL,NULL,NULL};
    locator_t *         locator             = NULL;
    iface_locators *    iface_loct          = NULL;
    int                 ctr                 = 0;

    locators_lists[0] = mapping_get_locators_with_afi(mapping,LM_AFI_NO_ADDR,0);
    locators_lists[1] = mapping_get_locators_with_afi(mapping,LM_AFI_IP,AF_INET);
    locators_lists[2] = mapping_get_locators_with_afi(mapping,LM_AFI_IP,AF_INET6);

    for (ctr = 0 ; ctr < 3 ; ctr++){
        while (locators_lists[ctr] != NULL){
            locator = locators_lists[ctr]->locator;
            iface_loct = iface_locators_get_element_with_loct(
                                   iface_locators_table, locator);
            if (iface_loct != NULL &&
                    glist_contain(mapping, iface_loct->mappings) == FALSE){
                glist_add(mapping, iface_loct->mappings);
            }

            locators_lists[ctr] = locators_lists[ctr]->next;
        }
    }
}

void
iface_locators_unattach_mapping_and_loct(
        shash_t *   iface_locators_table,
        mapping_t * mapping)
{
    locator_list_t *    locators_lists[3]   = {NULL,NULL,NULL};
    glist_t *           iface_loct_list     = NULL;
    glist_entry_t *     it_if_loct          = NULL;
    iface_locators *    iface_loct          = NULL;
    int                 ctr                 = 0;

    locators_lists[0] = mapping_get_locators_with_afi(mapping,LM_AFI_NO_ADDR,0);
    locators_lists[1] = mapping_get_locators_with_afi(mapping,LM_AFI_IP,AF_INET);
    locators_lists[2] = mapping_get_locators_with_afi(mapping,LM_AFI_IP,AF_INET6);

    for (ctr=0;ctr<3;ctr++){
        while(locators_lists[ctr] != NULL){
            iface_locators_unattach_locator(
                    iface_locators_table,
                    locators_lists[ctr]->locator);
            locators_lists[ctr] = locators_lists[ctr]->next;
        }
    }

    iface_loct_list = shash_values(iface_locators_table);
    glist_for_each_entry(it_if_loct,iface_loct_list){
        iface_loct = (iface_locators *)glist_entry_data(it_if_loct);
        glist_remove_obj(mapping,iface_loct->mappings);
    }
}

/*
 * Remove a locator from the structure iface_locators associated to it.
 */
void
iface_locators_unattach_locator(
        shash_t *       iface_locators_table,
        locator_t *     locator)
{
    lisp_addr_t *       ip_addr         = NULL;
    lisp_addr_t *       addr            = locator_addr(locator);
    iface_locators *    iface_loct      = NULL;
    glist_t *           loct_lists[2]   = {NULL,NULL};
    glist_entry_t *     it_loct         = NULL;
    locator_t *         loct            = NULL;
    int                 ctr             = 0;
    uint16_t            afi             = AF_UNSPEC;


    /* Get structure from where the locator is removed */
    iface_loct = iface_locators_get_element_with_loct(iface_locators_table,locator);
    if (iface_loct == NULL){
        return;
    }

    if (lisp_addr_is_no_addr(addr) == FALSE){
        if (lisp_addr_is_lcaf(addr) == TRUE) {
            ip_addr = lcaf_rloc_get_ip_addr(addr);
            if (ip_addr == NULL) {
                LMLOG(LERR, "unattach_locator_from_iface: Can't determine RLOC's IP "
                        "address %s", lisp_addr_to_char(addr));
                return;
            }
        } else {
            ip_addr = addr;
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
iface_locators_get_element_with_loct(
        shash_t *       iface_locators_table,
        locator_t *     locator)
{
    glist_t *           iface_loct_list = NULL;
    glist_entry_t *     it              = NULL;
    glist_entry_t *     it_loct         = NULL;
    iface_locators *    iface_loct      = NULL;
    glist_t *           loct_lists[2]   = {NULL,NULL};
    locator_t *         loct            = NULL;
    lisp_addr_t *       addr            = locator_addr(locator);
    lisp_addr_t *       ip_addr         = NULL;
    char *              iface_name      = NULL;
    int                 ctr             = 0;

    if (lisp_addr_is_no_addr(addr) == FALSE)
    {
        if (lisp_addr_is_lcaf(addr) == TRUE) {
            ip_addr = lcaf_rloc_get_ip_addr(addr);
            if (ip_addr == NULL) {
                LMLOG(LERR, "iface_locators_get_element_with_loct: Can't determine RLOC's IP "
                        "address %s", lisp_addr_to_char(addr));
                return (NULL);
            }
        } else {
            ip_addr = addr;
        }
        /* Find the interface name associated to the RLOC */
        iface_name = get_interface_name_from_address(ip_addr);

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
                        return (iface_loct);
                    }
                }
            }
        }
    }

    return (NULL);
}

