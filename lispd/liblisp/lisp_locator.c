/*
 * lispd_locator.c
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

#include <errno.h>

#include "lisp_locator.h"
#include "lispd_lib.h"
#include "lmlog.h"


static lcl_locator_extended_info_t *new_lcl_locator_extended_info(int *);
static rmt_locator_extended_info_t *new_rmt_locator_extended_info();
static void free_lcl_locator_extended_info(lcl_locator_extended_info_t *);
static void free_rmt_locator_extended_info(rmt_locator_extended_info_t *);

static lcl_locator_extended_info_t *
new_lcl_locator_extended_info(int *out_socket)
{
    lcl_locator_extended_info_t *lcl_loc_ext_inf;
    lcl_loc_ext_inf = xmalloc(sizeof(lcl_locator_extended_info_t));

    lcl_loc_ext_inf->out_socket = out_socket;
    lcl_loc_ext_inf->rtr_locators_list = NULL;

    return lcl_loc_ext_inf;
}

static rmt_locator_extended_info_t *
new_rmt_locator_extended_info()
{
    rmt_locator_extended_info_t *rmt_loc_ext_inf;
    rmt_loc_ext_inf = xmalloc(sizeof(rmt_locator_extended_info_t));
    rmt_loc_ext_inf->rloc_probing_nonces = NULL;
    rmt_loc_ext_inf->probe_timer = NULL;

    return rmt_loc_ext_inf;
}

static void
free_lcl_locator_extended_info(lcl_locator_extended_info_t *extended_info)
{
    if (!extended_info) {
        return;
    }

    rtr_list_del(extended_info->rtr_locators_list);
    free(extended_info);
}

static void
free_rmt_locator_extended_info(rmt_locator_extended_info_t *extended_info)
{
    if (!extended_info) {
        return;
    }

    if (extended_info->probe_timer != NULL) {
        /* This is needed because in case of RLOC probing we allocate
         * a struct pointing to the mapping and the locator */
        free(extended_info->probe_timer->cb_argument);
        lmtimer_stop(extended_info->probe_timer);
        extended_info->probe_timer = NULL;
    }
    if (extended_info->rloc_probing_nonces != NULL) {
        free(extended_info->rloc_probing_nonces);
    }
    free(extended_info);
}

/* Clones of local locator extended info */
static lcl_locator_extended_info_t *
lcl_locator_extended_info_clone(lcl_locator_extended_info_t *einf)
{
    lcl_locator_extended_info_t *ei = NULL;

    ei = new_lcl_locator_extended_info(einf->out_socket);

    if (einf->rtr_locators_list != NULL) {
        ei->rtr_locators_list = rtr_locator_list_clone(einf->rtr_locators_list);
    }

    return (ei);
}

/* Clone remote locator extended info. Actually it just allocates memory for a
 * extended info and does't clone anything, THAT IS, probing nonces ARE NOT
 * copied */
static rmt_locator_extended_info_t *
rmt_locator_extended_info_clone(rmt_locator_extended_info_t *einf)
{
    rmt_locator_extended_info_t *ei = NULL;

    ei = new_rmt_locator_extended_info();

    return (ei);
}

locator_t *
locator_new()
{
    return (xzalloc(sizeof(locator_t)));
}

locator_t *
locator_init(
        lisp_addr_t*    addr,
        uint8_t         state,
        uint8_t         priority,
        uint8_t         weight,
        uint8_t         mpriority,
        uint8_t         mweight,
        uint8_t         type
        )
{
    locator_t*  locator = NULL;

    locator = locator_new();
    if (locator == NULL){
        return (NULL);
    }
    locator->addr = lisp_addr_clone(addr);
    locator->state = state;
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;
    locator->type = type;

    return (locator);
}

char *
locator_to_char(locator_t *l)
{
    static char buf[5][500];
    static int i=0;
    /* hack to allow more than one locator per line */
    i++; i = i % 5;
    *buf[i] = '\0';
    if (l == NULL){
        sprintf(buf[i], "_NULL_");
        return (buf[i]);
    }
    sprintf(buf[i], "%s, ", lisp_addr_to_char(locator_addr(l)));
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
    loc->type = DYNAMIC_LOCATOR;
    loc->priority = LOC_PRIORITY(hdr);
    loc->weight = LOC_WEIGHT(hdr);
    loc->mpriority = LOC_MPRIORITY(hdr);
    loc->mweight = LOC_MWEIGHT(hdr);
    loc->extended_info = new_rmt_locator_extended_info();

    /* TODO: should we remove these? */
    loc->data_packets_in = 0;
    loc->data_packets_out = 0;

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

locator_t *
locator_init_remote(lisp_addr_t *addr)
{
    if (!addr) {
        return (NULL);
    }

    locator_t *locator = locator_new();
    locator->addr = lisp_addr_clone(addr);
    locator->extended_info = new_rmt_locator_extended_info();
    locator->type = DYNAMIC_LOCATOR;

    return (locator);
}

/* Initializes a remote locator. 'addr' is cloned so it can be freed by the
 * caller*/
locator_t *
locator_init_remote_full(lisp_addr_t *addr, uint8_t state, uint8_t priority,
        uint8_t weight, uint8_t mpriority, uint8_t mweight)
{
    locator_t *locator = locator_init_remote(addr);
    if (!locator) {
        return (NULL);
    }

    locator->state = state;
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;
    return (locator);
}

/* For local locators address is NOT CLONED, since it is
 * linked to that of the associated interface */
locator_t *
locator_init_local(lisp_addr_t *addr)
{
    if (!addr) {
        return (NULL);
    }

    locator_t *locator = locator_new();
    /* Initialize locator */
    locator->addr = lisp_addr_clone(addr);
    locator->type = LOCAL_LOCATOR;

    return (locator);
}

/* Initializes a local locator.*/
locator_t *
locator_init_local_full(lisp_addr_t *addr, uint8_t state, uint8_t priority,
        uint8_t weight, uint8_t mpriority, uint8_t mweight, int *out_socket)
{
    locator_t *locator = locator_init_local(addr);
    if (!locator) {
        return (NULL);
    }
    /* Initialize locator */
    locator->priority = priority;
    locator->weight = weight;
    locator->mpriority = mpriority;
    locator->mweight = mweight;
    locator->data_packets_in = 0;
    locator->data_packets_out = 0;
    locator->state = state;
    locator->extended_info = (void *) new_lcl_locator_extended_info(out_socket);

    return (locator);
}

void
locator_del(locator_t *locator)
{
    if (!locator) {
        return;
    }

    if (locator->type != LOCAL_LOCATOR) {
        free_rmt_locator_extended_info(locator->extended_info);
    } else {
        free_lcl_locator_extended_info(locator->extended_info);
    }
    lisp_addr_del(locator->addr);
    free(locator);
    locator = NULL;
}


locator_t *
locator_clone(locator_t *loc)
{
    locator_t *locator = NULL;

    if (loc->type != LOCAL_LOCATOR) {
        locator = locator_init_remote_full(loc->addr, loc->state,
                loc->priority, loc->weight, loc->mpriority, loc->mweight);
    } else {
        /* For local locators, address and state are LINKED to the associated
         * interface. Socket is cloned with the extended info */
        locator = locator_init_local_full(loc->addr, loc->state, loc->priority,
                loc->weight, loc->mpriority, loc->mweight, NULL);
    }

    locator->type = loc->type;
    if (loc->extended_info != NULL){
        if (locator->type == LOCAL_LOCATOR){
            free_lcl_locator_extended_info((lcl_locator_extended_info_t *)locator->extended_info);
            locator->extended_info =
                    lcl_locator_extended_info_clone(loc->extended_info);
        }else{
            free_rmt_locator_extended_info((rmt_locator_extended_info_t *)locator->extended_info);
            locator->extended_info =
                    rmt_locator_extended_info_clone(loc->extended_info);
        }
    }

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
locator_cmp_addr (
        locator_t *loct1,
        locator_t *loct2)
{
    return (lisp_addr_cmp(locator_addr(loct1),locator_addr(loct2)));
}

/*
 * Get lafi and type of a list
 */
void locator_list_lafi_type (
		glist_t         *loct_list,
		int				*lafi,
		int				*type)
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
    	LMLOG(DBG_2, "locator_list_lafi_type: locator list should not contain prefixes");
    	return;
    case LM_AFI_LCAF:
    	*type = lisp_addr_lcaf_type(addr);
    	return;
    }


}


/* Return the locator from the list that contains the address passed as a
 * parameter */
locator_t *
locator_list_get_locator_with_addr(
        glist_t         *loct_list,
        lisp_addr_t     *addr)
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
locator_list_extract_locator_with_addr(
        glist_t         *loct_list,
        lisp_addr_t     *addr)
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
locator_list_extract_locator_with_ptr(
        glist_t         *loct_list,
        locator_t       *locator)
{
    glist_entry_t   *it                     = NULL;
    locator_t       *loct                   = NULL;

    if (!loct_list || glist_size(loct_list) == 0 || locator == NULL){
        return (BAD);
    }

    glist_for_each_entry(it,loct_list){
        locator = (locator_t *)glist_entry_data(it);
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
locator_list_cmp_afi(
        glist_t *loct_list_a,
        glist_t *loct_list_b)
{
	locator_t *		loct_a = NULL;
	locator_t *		loct_b = NULL;
    lisp_addr_t *   addr_a = NULL;
    lisp_addr_t *   addr_b = NULL;
    int             lafi_a;
    int             lafi_b;
    int             afi_a;
    int             afi_b;

    if (loct_list_a == NULL || loct_list_b == NULL){
        return (-2);
    }

    if(glist_size(loct_list_a) == 0 || glist_size(loct_list_b) == 0){
    	LMLOG(DBG_2, "locator_list_cmp_afi: One of the compared list is empty");
    	return (-2);
    }
    loct_a = (locator_t *)glist_first_data(loct_list_a);
    loct_b = (locator_t *)glist_first_data(loct_list_b);
    addr_a = locator_addr(loct_a);
    addr_b = locator_addr(loct_b);
    lafi_a = lisp_addr_lafi(addr_a);
    lafi_b = lisp_addr_lafi(addr_a);

    if (lafi_a > lafi_b){
        return (1);
    }
    if (lafi_a < lafi_b){
        return (2);
    }

    switch(lafi_a){
    case LM_AFI_NO_ADDR:
        return (0);
    case LM_AFI_IP:
        afi_a = lisp_addr_ip_afi(addr_a);
        afi_b = lisp_addr_ip_afi(addr_b);
        break;
    case LM_AFI_IPPREF:
        LMLOG(DBG_1,"locator_list_cmp_afi: No locators of type prefix");
        return (-2);
    case LM_AFI_LCAF:
        afi_a = lisp_addr_lcaf_type(addr_a);
        afi_b = lisp_addr_lcaf_type(addr_b);
    }

    if (afi_a > afi_b){
        return (1);
    }
    if (afi_a < afi_b){
        return (2);
    }

    return (0);
}

rtr_locator_t *
rtr_locator_new(lisp_addr_t address)
{
    rtr_locator_t *rtr_locator = NULL;

    rtr_locator = xmalloc(sizeof(rtr_locator));
    if (rtr_locator == NULL) {
        LMLOG(LWRN, "new_rtr_locator: Unable to allocate memory for "
                "lispd_rtr_locator: %s", strerror(errno));
        return (NULL);
    }
    rtr_locator->address = address;
    rtr_locator->latency = 0;
    rtr_locator->state = UP;

    return (rtr_locator);
}

rtr_locators_list_t*
rtr_locator_list_new()
{
    rtr_locators_list_t *rtr_list;
    rtr_list = xmalloc(sizeof(rtr_locators_list_t));
    return (rtr_list);
}

int rtr_list_add(rtr_locators_list_t **list, rtr_locator_t *locator)
{
    rtr_locators_list_t *loc_list_elt = NULL;
    rtr_locators_list_t *loc_list = *list;

    loc_list = rtr_locator_list_new();
    loc_list_elt->locator = locator;
    loc_list_elt->next = NULL;
    if (loc_list != NULL) {
        while (loc_list->next != NULL) {
            loc_list = loc_list->next;
        }
        loc_list->next = loc_list_elt;
    } else {
        *list = loc_list_elt;
    }

    return (GOOD);
}

void rtr_list_del(rtr_locators_list_t *rtr_list_elt)
{
    rtr_locators_list_t *aux_rtr_list_elt = NULL;

    while (rtr_list_elt != NULL) {
        aux_rtr_list_elt = rtr_list_elt->next;
        free(rtr_list_elt->locator);
        free(rtr_list_elt);
        rtr_list_elt = aux_rtr_list_elt;
    }
}

/* Leave in the list, rtr with afi equal to the afi passed as a parameter */
void
rtr_list_remove_locs_with_afi_different_to(rtr_locators_list_t **rtr_list,
        int afi)
{
    rtr_locators_list_t *rtr_list_elt = *rtr_list;
    rtr_locators_list_t *prev_rtr_list_elt = NULL;
    rtr_locators_list_t *aux_rtr_list_elt = NULL;

    while (rtr_list_elt != NULL) {
        if (rtr_list_elt->locator->address.afi == afi) {
            if (prev_rtr_list_elt == NULL) {
                prev_rtr_list_elt = rtr_list_elt;
                if (rtr_list_elt != *rtr_list) {
                    *rtr_list = rtr_list_elt;
                }
            } else {
                prev_rtr_list_elt->next = rtr_list_elt;
                prev_rtr_list_elt = prev_rtr_list_elt->next;
            }
            rtr_list_elt = rtr_list_elt->next;
        } else {
            aux_rtr_list_elt = rtr_list_elt;
            rtr_list_elt = rtr_list_elt->next;
            free(aux_rtr_list_elt->locator);
            free(aux_rtr_list_elt);
        }
    }
    /* Put the next element of the last rtr_locators_list found with afi X
     * to NULL*/
    if (prev_rtr_list_elt != NULL) {
        prev_rtr_list_elt->next = NULL;
    } else {
        *rtr_list = NULL;
    }
}

/* Clone RTR locator list */
rtr_locators_list_t *
rtr_locator_list_clone(rtr_locators_list_t *rtr_list)
{
    rtr_locators_list_t *rtr_locator_list = NULL;
    rtr_locator_t *rtr_locator = NULL;

    while (rtr_list != NULL){
        rtr_locator = rtr_locator_new(rtr_list->locator->address);
        rtr_list_add(&rtr_locator_list,rtr_locator);
        rtr_list = rtr_list->next;
    }
    return (rtr_locator_list);
}

