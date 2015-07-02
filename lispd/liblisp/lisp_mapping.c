/*
 * lispd_mapping.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send registration messages for each database mapping to
 * configured map-servers.
 *
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
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
 *    Albert Lopez      <alopez@ac.upc.edu>
 */

#include "../lib/lmlog.h"
#include "lisp_mapping.h"

inline mapping_t *
mapping_new()
{
    mapping_t *mapping;
    mapping = xzalloc(sizeof(mapping_t));
    if (mapping == NULL){

        return (NULL);
    }
    mapping->locators_lists = glist_new_complete(
            (glist_cmp_fct) locator_list_cmp_afi,
            (glist_del_fct) glist_destroy);
    if (mapping->locators_lists == NULL){
        free(mapping);
        return (NULL);
    }
    return(mapping);
}

inline mapping_t *
mapping_new_init(lisp_addr_t *eid)
{
    mapping_t *mapping;
    mapping = mapping_new();
    if (!mapping){
        LMLOG(LWRN, "mapping_new_init: Couldn't allocate mapping_t structure");
        return (NULL);
    }

    lisp_addr_copy(&(mapping->eid_prefix), eid);
    if (lisp_addr_lafi(&mapping->eid_prefix) == LM_AFI_IP){
        lisp_addr_ip_to_ippref(&mapping->eid_prefix);
    }

    return (mapping);
}

void mapping_del(mapping_t *m)
{
    if (!m) {
        return;
    }

    /* Free the locators list*/
    glist_destroy(m->locators_lists);

    /*  MUST free lcaf addr */
    lisp_addr_dealloc(mapping_eid(m));
    free(m);
}


/* compare two mappings
 * returns 0 if they are the same and 1 otherwise */
int
mapping_cmp(mapping_t *m1, mapping_t *m2)
{
    glist_t *loct_list1 = NULL;
    glist_t *loct_list2 = NULL;
    locator_t *loct1 = NULL;
    locator_t *loct2 = NULL;
    glist_entry_t *it_list1 = NULL;
    glist_entry_t *it_list2 = NULL;
    glist_entry_t *it_loct1 = NULL;
    glist_entry_t *it_loct2 = NULL;

    if (lisp_addr_cmp(mapping_eid(m1), mapping_eid(m2)) != 0) {
        return (1);
    }
    if (m1->locator_count != m2->locator_count) {
        return (1);
    }
    if (glist_size(m1->locators_lists) != glist_size(m2->locators_lists)){
        return (1);
    }

    it_list2 = glist_first(m2->locators_lists);
    glist_for_each_entry(it_list1,m1->locators_lists){
        loct_list1 = (glist_t *)glist_entry_data(it_list1);
        loct_list2 = (glist_t *)glist_entry_data(it_list2);
        if (glist_size(loct_list1) != glist_size(loct_list2)){
            return (1);
        }
        it_loct2 = glist_first(loct_list2);
        glist_for_each_entry(it_loct1,loct_list1){
            loct1 = (locator_t *)glist_entry_data(it_loct1);
            loct2 = (locator_t *)glist_entry_data(it_loct2);
            if (locator_cmp(loct1, loct2) != 0) {
                return (1);
            }
             it_loct2 = glist_next(it_loct2);
        }
        it_list2 = glist_next(it_list2);

    }

    return (0);
}

/* Clones a mapping_t data structure
 * NOTE: it does not clone the 'extended_info'! This should be done by the
 * caller and in the future it shouldn't be done at all. 'extended_info'
 * should be moved out */
//XXX IT IS NOT CLONING LOCATORS
mapping_t *
mapping_clone(mapping_t *m) {
    mapping_t *cm = mapping_new();
    mapping_set_eid(cm, mapping_eid(m));
    cm->action = m->action;
    cm->authoritative = m->authoritative;
    cm->locator_count = m->locator_count;
    cm->ttl = m->ttl;

    return(cm);
}

char *
mapping_to_char(mapping_t *m)
{
    glist_t *loct_list = NULL;
    locator_t *locator = NULL;
    glist_entry_t * it_list = NULL;
    glist_entry_t * it_loct = NULL;

    static char buf[100];

    sprintf(buf, "EID: %s, ttl: %d, loc-count: %d, action: %s, "
            "auth: %d", lisp_addr_to_char(mapping_eid(m)), mapping_ttl(m),
            mapping_locator_count(m),
            mapping_action_to_char(mapping_action(m)), mapping_auth(m));


    if (m->locator_count > 0) {
        glist_for_each_entry(it_list,m->locators_lists){
            loct_list = (glist_t *)glist_entry_data(it_list);
            if (glist_size(loct_list) == 0){
                continue;
            }
            locator = (locator_t *)glist_first_data(loct_list);
            if (lisp_addr_is_no_addr(locator_addr(locator)) == TRUE){
                continue;
            }
            glist_for_each_entry(it_loct,loct_list){
                locator = (locator_t *)glist_entry_data(it_loct);
                sprintf(buf+strlen(buf), "\n  RLOC: %s", locator_to_char(locator));
            }
        }
    }
    return(buf);
}

int
mapping_add_locator(
		mapping_t *mapping,
		locator_t *loct)
{
	lisp_addr_t *addr = NULL;
	glist_t *loct_list = NULL;


	int result = GOOD;

	addr = locator_addr(loct);

	loct_list = mapping_get_loct_lst_with_addr_type(mapping,addr);
	if (loct_list == NULL){
		loct_list = glist_new_complete(
				(glist_cmp_fct)locator_cmp_addr,
				(glist_del_fct)locator_del);
		// The locator is added firstly in order the list has an associated afi
		if ((result = glist_add(loct,loct_list)) == GOOD){
			result = glist_add(loct_list,mapping->locators_lists);
		}

	}else {
		if (glist_contain(loct, loct_list) == TRUE){
			LMLOG(LDBG_2, "mapping_add_locator: The locator %s already exists "
					"for the EID %s.", lisp_addr_to_char(locator_addr(loct)),
					lisp_addr_to_char(mapping_eid(mapping)));
			return (ERR_EXIST);
		}
		result = glist_add(loct,loct_list);
	}
	if (result == GOOD) {
		LMLOG(LDBG_2, "mapping_add_locator: Added locator %s to the mapping with"
				" EID %s.", lisp_addr_to_char(locator_addr(loct)),
				lisp_addr_to_char(mapping_eid(mapping)));
		if (lisp_addr_is_no_addr(addr) == FALSE){
		    mapping->locator_count++;
		}

		result = GOOD;
	} else {
		if (glist_size(loct_list) == 0){
			glist_remove_obj_with_ptr(loct_list,mapping->locators_lists);
		}
		result = BAD;
	}
	return (result);
}

void
mapping_update_locators(mapping_t *mapping, glist_t *locts_lists)
{
    glist_t *loct_list = NULL;
    glist_t *new_loct_list = NULL;
    glist_entry_t *it_list = NULL;
    locator_t *locator = NULL;

    int loct_ctr = 0;

    if (!mapping || !locts_lists) {
        return;
    }

    /* TODO: do a comparison first */
    glist_remove_all(mapping->locators_lists);

    glist_for_each_entry(it_list,locts_lists){
        loct_list = (glist_t *)glist_entry_data(it_list);
        new_loct_list = locator_list_clone(loct_list);
        glist_add(new_loct_list,mapping->locators_lists);
        locator = (locator_t*)glist_first_data(new_loct_list);
        if (lisp_addr_is_no_addr(locator_addr(locator)) == FALSE){
            loct_ctr = loct_ctr + glist_size(new_loct_list);
        }
    }
    mapping->locator_count = loct_ctr;
}

/*
 * Returns the locators with the address passed as a parameter
 */

locator_t *
mapping_get_loct_with_addr(mapping_t *mapping, lisp_addr_t *address)
{
    locator_t *locator = NULL;
    glist_t *locator_list = NULL;

    locator_list = mapping_get_loct_lst_with_addr_type(mapping,address);

    locator = locator_list_get_locator_with_addr(locator_list, address);

    return (locator);
}

glist_t *
mapping_get_loct_lst_with_afi(
        mapping_t * mapping,
        lm_afi_t    lafi,
        int         afi)
{
    glist_entry_t *it = NULL;
    glist_t *loct_list = NULL;
    locator_t *loct = NULL;
    lisp_addr_t *addr = NULL;

    glist_for_each_entry(it, mapping->locators_lists){
        loct_list = (glist_t *)glist_entry_data(it);
        loct = (locator_t *)glist_first_data(loct_list);
        addr = locator_addr(loct);
        if ( lisp_addr_lafi(addr) == lafi){
            switch (lafi){
            case LM_AFI_NO_ADDR:
                return (loct_list);
            case LM_AFI_IP:
                if (lisp_addr_ip_afi(addr) == afi){
                    return (loct_list);
                }
                break;
            case LM_AFI_IPPREF:
                LMLOG(LDBG_1,"mapping_get_locators_with_afi: No locators of type prefix");
                return (NULL);
            case LM_AFI_LCAF:
                if (lisp_addr_lcaf_type(addr) == afi){
                    return (loct_list);
                }
                break;
            }
        }
    }

    LMLOG(LDBG_1,"mapping_get_locators_with_afi: List for Lisp Mob AFI %d and afi %d not yet created",lafi,afi);
    return (NULL);
}

glist_t *
mapping_get_loct_lst_with_addr_type(
        mapping_t * mapping,
        lisp_addr_t *addr)
{
    lm_afi_t    lafi;
    int         afi;

    lafi = lisp_addr_lafi(addr);
    afi = lisp_addr_ip_afi_lcaf_type(addr);

    return (mapping_get_loct_lst_with_afi(mapping,lafi,afi));
}

/*
 * Check if the locator is part of the mapping
 */
uint8_t
mapping_has_locator(
        mapping_t *mapping,
        locator_t *loct)
{
    glist_t         *loct_list              = NULL;
    glist_entry_t   *it                     = NULL;
    lisp_addr_t     *addr                   = locator_addr(loct);

    loct_list = mapping_get_loct_lst_with_addr_type(mapping,addr);


    if (loct_list == NULL || glist_size(loct_list) == 0 || addr == NULL){
        return (FALSE);
    }

    glist_for_each_entry(it,loct_list){
        if (loct == (locator_t *)glist_entry_data(it)){
            return (TRUE);
        }
    }

    return (FALSE);
}

/* This function sorts the locator list with IP = changed_loc_addr */
int
mapping_sort_locators(mapping_t *mapping, lisp_addr_t *changed_loc_addr)
{
    glist_t        *loct_list = NULL;
    locator_t      *locator = NULL;
    int            res = 0;

    loct_list = mapping_get_loct_lst_with_addr_type(mapping,changed_loc_addr);

    locator = locator_list_extract_locator_with_addr(loct_list, changed_loc_addr);
    if (locator != NULL){
        res = glist_add(locator,loct_list);
    }else{
        res = BAD;
    }
    return (res);
}

/*
 * Remove the locator from the non active locators list and reinsert in the correct list
 * The address of the locator should be modified before calling this function
 * This function is only used when an interface is down during the initial configuration
 * process and then is activated
 */

int
mapping_activate_locator(
        mapping_t *mapping,
        locator_t *loct)
{
    int res = GOOD;

    glist_t *loct_list = NULL;

    loct_list = mapping_get_loct_lst_with_afi(mapping,LM_AFI_NO_ADDR,0);
    if (loct_list == NULL){
        return (BAD);
    }

    if (locator_list_extract_locator_with_ptr(loct_list,loct) != GOOD){
        LMLOG(LDBG_1,"mapping_activate_locator: The locator %s has not been found",
                        lisp_addr_to_char(locator_addr(loct)));
        return (BAD);
    }

    res = mapping_add_locator(mapping,loct);

    if (res == GOOD){
        LMLOG(LDBG_1,"mapping_activate_locator: The locator %s of the mapping %s has been activated",
                lisp_addr_to_char(locator_addr(loct)),
                lisp_addr_to_char(&(mapping->eid_prefix)));
    }else{
        locator_del(loct);
        LMLOG(LDBG_1,"mapping_activate_locator: Error activating the locator %s of the mapping %s. Locator couldn't be reinserted",
                        lisp_addr_to_char(locator_addr(loct)),
                        lisp_addr_to_char(&(mapping->eid_prefix)));
    }
    return (res);
}
