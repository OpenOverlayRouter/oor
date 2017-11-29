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

#include "../lib/oor_log.h"
#include "lisp_mref_mapping.h"

inline mref_mapping_t *
mref_mapping_new()
{
    mref_mapping_t *mref_mapping;
    mref_mapping = xzalloc(sizeof(mref_mapping_t));
    if (mref_mapping == NULL){

        return (NULL);
    }
    mref_mapping->referral_lists = glist_new_complete(
            (glist_cmp_fct) locator_list_cmp_afi,
            (glist_del_fct) glist_destroy);
    if (mref_mapping->referral_lists == NULL){
        free(mref_mapping);
        return (NULL);
    }
    return(mref_mapping);
}

inline mref_mapping_t *
mref_mapping_new_init(lisp_addr_t *eid)
{
    mref_mapping_t *mref_mapping;
    lisp_addr_t *ip_pref;

    /* If eid is an IP address, convert it to IP prefix */
    if (lisp_addr_get_ip_pref_addr(eid) == NULL){
        ip_pref = lisp_addr_get_ip_addr(eid);
        if (!ip_pref){
            OOR_LOG(LWRN, "mref_mapping_new_init: Couldn't get eid prefix from %s", lisp_addr_to_char(eid));
            return (NULL);
        }
        lisp_addr_ip_to_ippref(ip_pref);
    }

    mref_mapping = mref_mapping_new();
    if (!mref_mapping){
        OOR_LOG(LWRN, "mref_mapping_new_init: Couldn't allocate mref_mapping_t structure");
        return (NULL);
    }

    lisp_addr_copy(&(mref_mapping->eid_prefix), eid);

    return (mref_mapping);
}

inline mref_mapping_t *
mref_mapping_new_init_full(lisp_addr_t *eid, int ttl, lisp_ref_action_e act, lisp_authoritative_e a,
        int i, glist_t *ref_list, glist_t *sig_list, lisp_addr_t *ms_loc){

    mref_mapping_t *mref_mapping;
    lisp_addr_t *ip_pref;
    locator_t *loct;
    glist_entry_t *itr;
    lisp_addr_t *addr;

    /* If eid is an IP address, convert it to IP prefix */
    if (lisp_addr_get_ip_pref_addr(eid) == NULL){
        ip_pref = lisp_addr_get_ip_addr(eid);
        if (!ip_pref){
            OOR_LOG(LWRN, "mref_mapping_new_init_full: Couldn't get eid prefix from %s", lisp_addr_to_char(eid));
            return (NULL);
        }
        lisp_addr_ip_to_ippref(ip_pref);
    }

    mref_mapping = mref_mapping_new();
    if (!mref_mapping){
        OOR_LOG(LWRN, "mref_mapping_new_init_full: Couldn't allocate mref_mapping_t structure");
        return (NULL);
    }

    lisp_addr_copy(&(mref_mapping->eid_prefix), eid);

    mref_mapping_set_ttl(mref_mapping, ttl);
    mref_mapping_set_action(mref_mapping, act);
    mref_mapping_set_auth(mref_mapping, a);
    mref_mapping_set_incomplete(mref_mapping, i);

    if(act == LISP_ACTION_MS_ACK || act == LISP_ACTION_NOT_REGISTERED){
        if(i==0){

            loct = locator_new_init(ms_loc,UP,1,1,0,0,0,0);
            mref_mapping_add_referral(mref_mapping, loct);
        }
    }

    glist_for_each_entry(itr,ref_list){
        addr = (lisp_addr_t *)glist_entry_data(itr);

        loct = locator_new_init(addr,UP,0,1,0,0,0,0);
        mref_mapping_add_referral(mref_mapping, loct);
    }

    /* add the signatures to the Map Referral based on sig_list here */

    return mref_mapping;

}

void mref_mapping_del(mref_mapping_t *m)
{
    if (!m) {
        return;
    }

    /* Free the referral list*/
    glist_destroy(m->referral_lists);

    /*  MUST free lcaf addr */
    lisp_addr_dealloc(mref_mapping_eid(m));
    free(m);
}


/* compare two mappings
 * returns 0 if they are the same and 1 otherwise */
int
mref_mapping_cmp(mref_mapping_t *m1, mref_mapping_t *m2)
{
    glist_t *loct_list1 = NULL;
    glist_t *loct_list2 = NULL;
    locator_t *loct1 = NULL;
    locator_t *loct2 = NULL;
    glist_entry_t *it_list1 = NULL;
    glist_entry_t *it_list2 = NULL;
    glist_entry_t *it_loct1 = NULL;
    glist_entry_t *it_loct2 = NULL;

    if (lisp_addr_cmp(mref_mapping_eid(m1), mref_mapping_eid(m2)) != 0) {
        return (1);
    }
    if (m1->referral_count != m2->referral_count) {
        return (1);
    }
    if (glist_size(m1->referral_lists) != glist_size(m2->referral_lists)){
        return (1);
    }

    it_list2 = glist_first(m2->referral_lists);
    glist_for_each_entry(it_list1,m1->referral_lists){
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

/* Clones a mref_mapping_t data structure
 * NOTE: it does not clone the 'extended_info'! This should be done by the
 * caller and in the future it shouldn't be done at all. 'extended_info'
 * should be moved out */
//XXX IT IS NOT CLONING LOCATORS
mref_mapping_t *
mref_mapping_clone(mref_mapping_t *m) {
    mref_mapping_t *cm = mref_mapping_new();
    mref_mapping_set_eid(cm, mref_mapping_eid(m));
    cm->action = m->action;
    cm->authoritative = m->authoritative;
    cm->incomplete = m->incomplete;
    cm->referral_count = m->referral_count;
    cm->ttl = m->ttl;

    return(cm);
}

char *
mref_mapping_to_char(mref_mapping_t *m)
{
    locator_t *locator = NULL;
    static char buf[500];
    size_t buf_size = sizeof(buf);


    *buf = '\0';
    snprintf(buf,buf_size, "EID: %s, ttl: %d, ref-count: %d, action: %s, "
            "auth: %d, incomplete: %d\n", lisp_addr_to_char(mref_mapping_eid(m)), mref_mapping_ttl(m),
            mref_mapping_referral_count(m),
            mref_mapping_action_to_char(mref_mapping_action(m)), mref_mapping_auth(m), mref_mapping_incomplete(m));

    if (m->referral_count > 0) {
        mref_mapping_foreach_active_referral(m,locator){
            snprintf(buf+strlen(buf), buf_size - strlen(buf),"  RLOC: %s\n", locator_to_char(locator));
        }mref_mapping_foreach_active_referral_end;
    }
    return(buf);
}

int
mref_mapping_add_referral(
		mref_mapping_t *mref_mapping,
		locator_t *loct)
{
	lisp_addr_t *addr = NULL;
	glist_t *loct_list = NULL;
	locator_t *aux_loct = NULL;


	int result = GOOD;

	addr = locator_addr(loct);

	loct_list = mref_mapping_get_ref_lst_with_addr_type(mref_mapping,addr);
	if (loct_list == NULL){
		loct_list = glist_new_complete(
				(glist_cmp_fct)locator_cmp_addr,
				(glist_del_fct)locator_del);
		// The Referral is added firstly in order the list has an associated afi
		if ((result = glist_add(loct,loct_list)) == GOOD){
			result = glist_add(loct_list,mref_mapping->referral_lists);
		}

	}else {
		if (glist_contain(loct, loct_list) == TRUE){
			OOR_LOG(LDBG_2, "mref_mapping_add_referral: The referral %s already exists "
					"for the EID %s. Discarding the one with less priority", lisp_addr_to_char(locator_addr(loct)),
					lisp_addr_to_char(mref_mapping_eid(mref_mapping)));
			aux_loct = mref_mapping_get_ref_with_addr(mref_mapping, locator_addr(loct));
			if (locator_priority(aux_loct) > locator_priority(loct)){
			    /* Returns good in order the caller of this functione doesn't free the memory of the locator */
			    glist_remove_obj_with_ptr(aux_loct,loct_list);
			    return (glist_add(loct,loct_list));
			}else{
			    /* Return error in order the caller of this functione frees the memory of the locator */
			    return (ERR_EXIST);
			}
		}else {
		    result = glist_add(loct,loct_list);
		}
	}
	if (result == GOOD) {
		OOR_LOG(LDBG_2, "mref_mapping_add_referral: Added referral %s to the mref_mapping with"
				" EID %s.", lisp_addr_to_char(locator_addr(loct)),
				lisp_addr_to_char(mref_mapping_eid(mref_mapping)));
		if (lisp_addr_is_no_addr(addr) == FALSE){
		    mref_mapping->referral_count++;
		}

		result = GOOD;
	} else {
		if (glist_size(loct_list) == 0){
			glist_remove_obj_with_ptr(loct_list,mref_mapping->referral_lists);
		}
		result = BAD;
	}
	return (result);
}

/* This function extract the locator from the list of locators of the mapping */
int
mref_mapping_remove_referral(
        mref_mapping_t *mref_mapping,
        locator_t *loct)
{
    lisp_addr_t *addr = NULL;
    glist_t *loct_list = NULL;

    addr = locator_addr(loct);

    loct_list = mref_mapping_get_ref_lst_with_addr_type(mref_mapping,addr);
    if (loct_list == NULL){
        OOR_LOG(LDBG_2,"mref_mapping_remove_referral: The referral %s has not been found in the mref_mapping",
                lisp_addr_to_char(locator_addr(loct)));
        return (GOOD);
    }

    if (locator_list_extract_locator_with_ptr(loct_list,loct) != GOOD){
        OOR_LOG(LDBG_2,"mref_mapping_remove_referral: The referral %s has not been found in the mref_mapping",
                lisp_addr_to_char(locator_addr(loct)));
        return (GOOD);
    }

    if (glist_size(loct_list) == 0){
        glist_remove_obj_with_ptr(loct_list, mref_mapping->referral_lists);
    }

    if (!lisp_addr_is_no_addr(addr)){
        mref_mapping->referral_count = mref_mapping->referral_count - 1;
    }

    if (lisp_addr_is_no_addr(addr) == FALSE){
        mref_mapping->referral_count++;
    }

    OOR_LOG(LDBG_2, "mref_mapping_remove_referral: Removed referral %s from the mref_mapping with"
                    " EID %s.", lisp_addr_to_char(locator_addr(loct)),
                    lisp_addr_to_char(mref_mapping_eid(mref_mapping)));

    return (GOOD);
}

void
mref_mapping_remove_referrals(mref_mapping_t *mref_mapping)
{
    glist_remove_all(mref_mapping->referral_lists);
    mref_mapping->referral_count = 0;
}


void
mref_mapping_update_referrals(mref_mapping_t *mref_mapping, glist_t *locts_lists)
{
    glist_t *loct_list = NULL;
    glist_t *new_loct_list = NULL;
    glist_entry_t *it_list = NULL;
    locator_t *locator = NULL;

    int loct_ctr = 0;

    if (!mref_mapping || !locts_lists) {
        return;
    }

    /* TODO: do a comparison first */
    glist_remove_all(mref_mapping->referral_lists);

    glist_for_each_entry(it_list,locts_lists){
        loct_list = (glist_t *)glist_entry_data(it_list);
        new_loct_list = locator_list_clone(loct_list);
        glist_add(new_loct_list,mref_mapping->referral_lists);
        locator = (locator_t*)glist_first_data(new_loct_list);
        if (lisp_addr_is_no_addr(locator_addr(locator)) == FALSE){
            loct_ctr = loct_ctr + glist_size(new_loct_list);
        }
    }
    mref_mapping->referral_count = loct_ctr;
}

/*
 * Returns the locators with the address passed as a parameter
 */

locator_t *
mref_mapping_get_ref_with_addr(mref_mapping_t *mref_mapping, lisp_addr_t *address)
{
    locator_t *locator = NULL;
    glist_t *locator_list = NULL;

    locator_list = mref_mapping_get_ref_lst_with_addr_type(mref_mapping,address);

    locator = locator_list_get_locator_with_addr(locator_list, address);

    return (locator);
}

glist_t *
mref_mapping_get_ref_lst_with_afi(
        mref_mapping_t * mref_mapping,
        lm_afi_t    lafi,
        int         afi)
{
    glist_entry_t *it = NULL;
    glist_t *loct_list = NULL;
    locator_t *loct = NULL;
    lisp_addr_t *addr = NULL;

    glist_for_each_entry(it, mref_mapping->referral_lists){
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
                OOR_LOG(LDBG_1,"mref_mapping_get_ref_with_afi: No referrals of type prefix");
                return (NULL);
            case LM_AFI_LCAF:
                if (lisp_addr_lcaf_type(addr) == afi){
                    return (loct_list);
                }
                break;
            }
        }
    }

    OOR_LOG(LDBG_2,"mapping_get_locators_with_afi: List for OOR AFI %d and afi %d not yet created",lafi,afi);
    return (NULL);
}

glist_t *
mref_mapping_get_ref_lst_with_addr_type(
        mref_mapping_t * mref_mapping,
        lisp_addr_t *addr)
{
    lm_afi_t    lafi;
    int         afi;

    lafi = lisp_addr_lafi(addr);
    afi = lisp_addr_ip_afi_lcaf_type(addr);

    return (mref_mapping_get_ref_lst_with_afi(mref_mapping,lafi,afi));
}

/*
 * Check if the locator is part of the mapping
 */
uint8_t
mref_mapping_has_referral(
        mref_mapping_t *mref_mapping,
        locator_t *loct)
{
    glist_t         *loct_list              = NULL;
    glist_entry_t   *it                     = NULL;
    lisp_addr_t     *addr                   = locator_addr(loct);

    loct_list = mref_mapping_get_ref_lst_with_addr_type(mref_mapping,addr);


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
mref_mapping_sort_referrals(mref_mapping_t *mref_mapping, lisp_addr_t *changed_loc_addr)
{
    glist_t        *loct_list = NULL;
    locator_t      *locator = NULL;
    int            res = 0;

    loct_list = mref_mapping_get_ref_lst_with_addr_type(mref_mapping,changed_loc_addr);

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
mref_mapping_activate_referral(
        mref_mapping_t *mref_mapping,
        locator_t *loct,
        lisp_addr_t *new_addr)
{
    int res = GOOD;

    glist_t *loct_list = NULL;
    loct_list = mref_mapping_get_ref_lst_with_afi(mref_mapping,LM_AFI_NO_ADDR,0);
    if (loct_list == NULL){
        return (BAD);
    }

    mref_mapping_remove_referral(mref_mapping, loct);

    locator_clone_addr(loct,new_addr);
    res = mref_mapping_add_referral(mref_mapping,loct);

    if (res == GOOD){
        OOR_LOG(LDBG_1,"mref_mapping_activate_referral: The referral %s of the mref_mapping %s has been activated",
                lisp_addr_to_char(locator_addr(loct)),
                lisp_addr_to_char(&(mref_mapping->eid_prefix)));
        OOR_LOG(LDBG_2,"mref_mapping_activate_referral: Updated mapping -> %s",mref_mapping_to_char(mref_mapping));
    }else{
        locator_del(loct);
        OOR_LOG(LDBG_1,"mref_mapping_activate_locator: Error activating the referral %s of the mref_mapping %s. Referral couldn't be reinserted",
                        lisp_addr_to_char(locator_addr(loct)),
                        lisp_addr_to_char(&(mref_mapping->eid_prefix)));
    }
    return (res);
}
