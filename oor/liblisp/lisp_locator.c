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

#include <errno.h>

#include "lisp_locator.h"
#include "../lib/oor_log.h"


locator_t *
locator_new()
{
    return (xzalloc(sizeof(locator_t)));
}

locator_t *
locator_new_init(lisp_addr_t* addr,uint8_t state,uint8_t L_bit,uint8_t R_bit,
        uint8_t priority, uint8_t weight,uint8_t mpriority, uint8_t mweight)
{
    locator_t*  locator;

    locator = locator_new();
    if (locator == NULL){
        return (NULL);
    }
    locator->addr = lisp_addr_clone(addr);
    locator->state = state;
    locator->L_bit = L_bit;
    locator->R_bit = R_bit;
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;

    return (locator);
}

char *
locator_to_char(locator_t *l)
{
    static char buf[5][500];
    static int i=0;
    if (l == NULL){
        sprintf(buf[i], "_NULL_");
        return (buf[i]);
    }
    /* hack to allow more than one locator per line */
    i++; i = i % 5;
    *buf[i] = '\0';
    sprintf(buf[i] + strlen(buf[i]), "%s, ", lisp_addr_to_char(locator_addr(l)));
    sprintf(buf[i] + strlen(buf[i]), "%s, ", l->state ? "Up" : "Down");
    sprintf(buf[i] + strlen(buf[i]), "%d/%-d, %d/%d", l->priority, l->weight,
            l->mpriority, l->mweight);
    return (buf[i]);
}

int locator_parse(void *ptr, locator_t *loc)
{
    locator_hdr_t *hdr;
    uint8_t status = UP;
    int len;

    hdr = ptr;
    if (!LOC_REACHABLE(hdr) && LOC_LOCAL(hdr)) {
        status = DOWN;
    }
    if (!loc->addr) {
        loc->addr = lisp_addr_new();
    }

    len = lisp_addr_parse(LOC_ADDR(hdr), loc->addr);
    if (len <= 0) {
        return (BAD);
    }

    loc->state = status;
    loc->L_bit = LOC_LOCAL(hdr);
    loc->R_bit = LOC_REACHABLE(hdr);
    loc->priority = LOC_PRIORITY(hdr);
    loc->weight = LOC_WEIGHT(hdr);
    loc->mpriority = LOC_MPRIORITY(hdr);
    loc->mweight = LOC_MWEIGHT(hdr);

    return (sizeof(locator_hdr_t) + len);
}

int locator_cmp(locator_t *l1, locator_t *l2)
{
    int ret = 0;
    if ((ret = lisp_addr_cmp(locator_addr(l1), locator_addr(l2))) != 0) {
        return (1);
    }

    if (l1->priority != l2->priority)
        return (1);
    if (l1->weight != l2->weight)
        return (1);
    if (l1->mpriority != l2->mpriority)
        return (1);
    if (l1->mweight != l2->mweight)
        return (1);
    return (0);
}

void
locator_del(locator_t *locator)
{
    if (!locator) {
        return;
    }

    lisp_addr_del(locator->addr);
    free(locator);
    locator = NULL;
}


locator_t *
locator_clone(locator_t *loc)
{
    locator_t *locator = locator_new_init(loc->addr, loc->state,loc->L_bit, loc->R_bit,
            loc->priority, loc->weight, loc->mpriority, loc->mweight);

    return (locator);
}

/*
 * Compare lisp_addr_t of two locators.
 * Returns:
 *          -1: If they are from different afi
 *           0: Both address are the same
 *           1: Addr1 is bigger than addr2
 *           2: Addr2 is bigger than addr1
 */
inline int
locator_cmp_addr (locator_t *loct1, locator_t *loct2)
{
    return (lisp_addr_cmp(locator_addr(loct1),locator_addr(loct2)));
}

/*
 * Get lafi and type of a list
 */
void locator_list_lafi_type (glist_t *loct_list,int	*lafi,int *type)
{
	locator_t *loct = NULL;
	lisp_addr_t *addr = NULL;

	*lafi = 0;
	*type = 0;
	if (loct_list == NULL || glist_size(loct_list) == 0){
		return;
	}

    loct = (locator_t *)glist_first_data(loct_list);
    addr = locator_addr(loct);
    *lafi = lisp_addr_lafi(addr);
    switch(*lafi){
    case LM_AFI_NO_ADDR:
    	*type = 0;
    	return;
    case LM_AFI_IP:
    	*type = lisp_addr_ip_afi(addr);
    	return;
    case LM_AFI_IPPREF:
    	OOR_LOG(LDBG_2, "locator_list_lafi_type: locator list should not contain prefixes");
    	return;
    case LM_AFI_LCAF:
    	*type = lisp_addr_lcaf_type(addr);
    	return;
    }


}


/* Return the locator from the list that contains the address passed as a
 * parameter */
locator_t *
locator_list_get_locator_with_addr(glist_t *loct_list,lisp_addr_t *addr)
{
    locator_t       *locator                = NULL;
    glist_entry_t   *it                     = NULL;

    if (!loct_list || glist_size(loct_list) == 0 || addr == NULL){
        return (NULL);
    }

    glist_for_each_entry(it,loct_list){
        locator = (locator_t *)glist_entry_data(it);
        if (lisp_addr_cmp(locator_addr(locator), addr) == 0) {
            return (locator);
        }
    }

    return (NULL);
}



/* Extract the locator of locators list that match with the address.
 * The locator is removed from the list */
locator_t *
locator_list_extract_locator_with_addr(glist_t *loct_list,lisp_addr_t *addr)
{
    locator_t       *locator                = NULL;
    glist_entry_t   *it                     = NULL;

    if (!loct_list || glist_size(loct_list) == 0 || addr == NULL){
        return (NULL);
    }

    glist_for_each_entry(it,loct_list){
        locator = (locator_t *)glist_entry_data(it);
        if (lisp_addr_cmp(locator_addr(locator), addr) == 0) {
            glist_extract(it,loct_list);
            return (locator);
        }
    }

    return (NULL);
}


/* Extract the locator of locators list comparing the pointer to the structure.
 * The locator is removed from the list */
int
locator_list_extract_locator_with_ptr(glist_t *loct_list,locator_t *locator)
{
    glist_entry_t   *it                     = NULL;
    locator_t       *loct                   = NULL;

    if (!loct_list || glist_size(loct_list) == 0 || locator == NULL){
        return (BAD);
    }

    glist_for_each_entry(it,loct_list){
        loct = (locator_t *)glist_entry_data(it);
        if (loct == locator){
            glist_extract(it,loct_list);
            return(GOOD);
        }
    }

    return(ERR_NO_EXIST);
}


/* Clones locators list BUT it DISCARDS probing nonces and timers! */
glist_t *
locator_list_clone(glist_t *loct_list)
{
    glist_t *new_loct_list = NULL;
    glist_entry_t *it_loct = NULL;
    locator_t *loct1 = NULL;
    locator_t *loct2 = NULL;

    if (loct_list == NULL || glist_size(loct_list) == 0){
        return (NULL);
    }

    new_loct_list = glist_new_complete(
            (glist_cmp_fct)locator_cmp_addr,
            (glist_del_fct)locator_del);

    glist_for_each_entry(it_loct, loct_list){
        loct1 = (locator_t *)glist_entry_data(it_loct);
        loct2 = locator_clone(loct1);
        glist_add(loct2,new_loct_list);
    }

    return (new_loct_list);
}

int
locator_list_cmp_afi(glist_t *loct_list_a,glist_t *loct_list_b)
{
	locator_t *		loct_a = NULL;
	locator_t *		loct_b = NULL;
    lisp_addr_t *   addr_a = NULL;
    lisp_addr_t *   addr_b = NULL;

    if (loct_list_a == NULL || loct_list_b == NULL){
        return (-2);
    }

    if(glist_size(loct_list_a) == 0 || glist_size(loct_list_b) == 0){
    	OOR_LOG(LDBG_2, "locator_list_cmp_afi: One of the compared list is empty");
    	return (-2);
    }
    loct_a = (locator_t *)glist_first_data(loct_list_a);
    loct_b = (locator_t *)glist_first_data(loct_list_b);
    addr_a = locator_addr(loct_a);
    addr_b = locator_addr(loct_b);

    return (lisp_addr_cmp_afi(addr_a,addr_b));
}
