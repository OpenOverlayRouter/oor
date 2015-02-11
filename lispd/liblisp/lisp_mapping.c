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

#include "lmlog.h"
#include "lisp_mapping.h"


/* Free the dinamic arrays that contains the balancing_locators_vecs structure; */

static locator_t **set_balancing_vector(locator_t **, int, int, int *);
static int select_best_priority_locators(glist_t *, locator_t **);
static inline void get_hcf_locators_weight(locator_t **, int *, int *);
static int highest_common_factor(int a, int b);

/* Initialize to 0 balancing_locators_vecs */
static void reset_balancing_locators_vecs (balancing_locators_vecs *blv);
static void free_balancing_locators_vecs(balancing_locators_vecs);
static void balancing_locators_vec_to_char(balancing_locators_vecs,
        mapping_t *, int);
static int balancing_vectors_calculate(mapping_t *, balancing_locators_vecs *);

int
mapping_add_locator(
        mapping_t *m,
        locator_t *loc)
{
    lisp_addr_t *addr = NULL;
    glist_t *loct_list = NULL;
    lm_afi_t lafi;
    int afi = 0;


    int result = GOOD;

    addr = locator_addr(loc);
    lafi = lisp_addr_lafi(addr);
    afi = lisp_addr_ip_afi_lcaf_type(addr);

    loct_list = mapping_get_loct_lst_with_afi(m,lafi,afi);
    if (loct_list == NULL){
        loct_list = glist_new_complete(
                (glist_cmp_fct)locator_cmp_addr,
                (glist_del_fct)locator_del);
        // The locator is added firstly in order the list has an associated afi
        if ((result = glist_add(loc,loct_list)) == GOOD){
        	glist_add(loct_list,m->locators_lists);
        }
    }else {
    	if (glist_contain(loc, loct_list) == TRUE){
    		LMLOG(DBG_2, "mapping_add_locator: The locator %s already exists "
    				"for the EID %s.", lisp_addr_to_char(locator_addr(loc)),
    				lisp_addr_to_char(mapping_eid(m)));
    		locator_del(loc);
    		return (GOOD);
    	}
    	result = glist_add(loc,loct_list);
    }
    if (result == GOOD) {
        LMLOG(DBG_2, "mapping_add_locator: Added locator %s to the mapping with"
                " EID %s.", lisp_addr_to_char(locator_addr(loc)),
                lisp_addr_to_char(mapping_eid(m)));
        if (lisp_addr_is_no_addr(addr) == FALSE){
            m->locator_count++;
        }
        result = GOOD;
    } else {
        locator_del(loc);
        if (glist_size(loct_list) == 0){
            glist_remove_obj_with_ptr(loct_list,m->locators_lists);
        }
        result = BAD;
    }
    return (result);
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


inline glist_t *mapping_locators(mapping_t *map){
	return (map->locators_lists);
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
                LMLOG(DBG_1,"mapping_get_locators_with_afi: No locators of type prefix");
                return (NULL);
            case LM_AFI_LCAF:
                if (lisp_addr_lcaf_type(addr) == afi){
                    return (loct_list);
                }
                break;
            }
        }
    }

    LMLOG(DBG_1,"mapping_get_locators_with_afi: List for Lisp Mob AFI %d and afi %d not yet created",lafi,afi);
    return (NULL);
}

inline glist_t *
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


    if (!loct_list || glist_size(loct_list) == 0 || addr == NULL){
        return (FALSE);
    }

    glist_for_each_entry(it,loct_list){
        if (loct == (locator_t *)glist_entry_data(it)){
            return (TRUE);
        }
    }

    return (FALSE);
}


/* Free the dinamic arrays that contains the balancing_locators_vecs
 * structure */
static void
free_balancing_locators_vecs(balancing_locators_vecs locs_vec)
{
    /* IPv4 locators more priority -> IPv4_IPv6 vector = IPv4 locator vector
     * IPv6 locators more priority -> IPv4_IPv6 vector = IPv4 locator vector */
    if (locs_vec.balancing_locators_vec != NULL
            && locs_vec.balancing_locators_vec
                    != locs_vec.v4_balancing_locators_vec
            && locs_vec.balancing_locators_vec
                    != locs_vec.v6_balancing_locators_vec) {
        free(locs_vec.balancing_locators_vec);
    }
    if (locs_vec.v4_balancing_locators_vec != NULL) {
        free(locs_vec.v4_balancing_locators_vec);
    }
    if (locs_vec.v6_balancing_locators_vec != NULL) {
        free(locs_vec.v6_balancing_locators_vec);
    }
}

/* Initialize to 0 balancing_locators_vecs */
static void
reset_balancing_locators_vecs(balancing_locators_vecs *blv)
{
    free_balancing_locators_vecs(*blv);
    blv->v4_balancing_locators_vec = NULL;
    blv->v4_locators_vec_length = 0;
    blv->v6_balancing_locators_vec = NULL;
    blv->v6_locators_vec_length = 0;
    blv->balancing_locators_vec = NULL;
    blv->locators_vec_length = 0;
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

/**************************************** TRAFFIC BALANCING FUNCTIONS ************************/

static int
select_best_priority_locators(
        glist_t         *loct_list,
        locator_t       **selected_locators)
{
    glist_entry_t       *it_loct    = NULL;
    locator_t           *locator    = NULL;
    int                 min_priority = UNUSED_RLOC_PRIORITY;
    int                 pos = 0;

    if (glist_size(loct_list) == 0){
        return (BAD);
    }

    glist_for_each_entry(it_loct,loct_list){
        locator = (locator_t *)glist_entry_data(it_loct);
        /* Only use locators with status UP  */
        if (locator_state(locator) == DOWN
                || locator_priority(locator) == UNUSED_RLOC_PRIORITY) {
            continue;
        }
        /* If priority of the locator equal to min_priority, then add the
         * locator to the list */
        if (locator_priority(locator) == min_priority) {
            selected_locators[pos] = locator;
            pos++;
            selected_locators[pos] = NULL;
        }
        /* If priority of the locator is minor than the min_priority, then
         * min_priority and list of rlocs is updated */
        if (locator_priority(locator) < min_priority) {
            pos = 0;
            min_priority = locator_priority(locator);
            selected_locators[pos] = locator;
            pos++;
            selected_locators[pos] = NULL;
        }
    }

    return (min_priority);
}

static locator_t **
set_balancing_vector(locator_t **locators, int total_weight, int hcf,
        int *locators_vec_length)
{
    locator_t **balancing_locators_vec = NULL;
    int vector_length = 0;
    int used_pos = 0;
    int ctr = 0;
    int ctr1 = 0;
    int pos = 0;

    if (total_weight != 0) {
        /* Length of the dynamic vector */
        vector_length = total_weight / hcf;
    } else {
        /* If all locators have weight equal to 0, we assign one position for
         * each locator */
        while (locators[ctr] != NULL) {
            ctr++;
        }
        vector_length = ctr;
        ctr = 0;
    }

    /* Reserve memory for the dynamic vector */
    balancing_locators_vec = xmalloc(vector_length * sizeof(locator_t *));
    *locators_vec_length = vector_length;

    while (locators[ctr] != NULL) {
        if (total_weight != 0) {
            used_pos = locator_weight(locators[ctr]) / hcf;
        } else {
            /* If all locators has weight equal to 0, we assign one position
             * for each locator. Simetric balancing */
            used_pos = 1;
        }
        ctr1 = 0;
        for (ctr1 = 0; ctr1 < used_pos; ctr1++) {
            balancing_locators_vec[pos] = locators[ctr];
            pos++;
        }
        ctr++;
    }

    return (balancing_locators_vec);
}


/*
 * Calculate the vectors used to distribute the load from the priority and weight of the locators of the mapping
 */
static int
balancing_vectors_calculate(mapping_t *m, balancing_locators_vecs *blv)
{
    // Store locators with same priority. Maximum 32 locators (33 to no get out of array)
    locator_t *locators[3][33];
    // Aux list to classify all locators between IP4 and IPv6
    glist_t *ipv4_loct_list = glist_new();
    glist_t *ipv6_loct_list = glist_new();


    int min_priority[2] = { 255, 255 };
    int total_weight[3] = { 0, 0, 0 };
    int hcf[3] = { 0, 0, 0 };
    int ctr = 0;
    int ctr1 = 0;
    int pos = 0;

    locators[0][0] = NULL;
    locators[1][0] = NULL;

    reset_balancing_locators_vecs(blv);

    locators_classify_in_4_6(m,&ipv4_loct_list,&ipv6_loct_list);


    /* Fill the locator balancing vec using only IPv4 locators and according
     * to their priority and weight */
    if (glist_size(ipv4_loct_list) != 0)
    {
        min_priority[0] = select_best_priority_locators(
                ipv4_loct_list, locators[0]);
        if (min_priority[0] != UNUSED_RLOC_PRIORITY) {
            get_hcf_locators_weight(locators[0], &total_weight[0], &hcf[0]);
            blv->v4_balancing_locators_vec = set_balancing_vector(
                    locators[0], total_weight[0], hcf[0],
                    &(blv->v4_locators_vec_length));
        }
    }

    /* Fill the locator balancing vec using only IPv6 locators and according
     * to their priority and weight*/
    if (glist_size(ipv6_loct_list) != 0)
    {
        min_priority[1] = select_best_priority_locators(
                ipv6_loct_list, locators[1]);
        if (min_priority[1] != UNUSED_RLOC_PRIORITY) {
            get_hcf_locators_weight(locators[1], &total_weight[1], &hcf[1]);
            blv->v6_balancing_locators_vec = set_balancing_vector(
                    locators[1], total_weight[1], hcf[1],
                    &(blv->v6_locators_vec_length));
        }
    }
    /* Fill the locator balancing vec using IPv4 and IPv6 locators and according
     * to their priority and weight*/
    if (blv->v4_balancing_locators_vec != NULL
            && blv->v6_balancing_locators_vec != NULL) {
        //Only IPv4 locators are involved (due to priority reasons)
        if (min_priority[0] < min_priority[1]) {
            blv->balancing_locators_vec =
                    blv->v4_balancing_locators_vec;
            blv->locators_vec_length =
                    blv->v4_locators_vec_length;
        } //Only IPv6 locators are involved (due to priority reasons)
        else if (min_priority[0] > min_priority[1]) {
            blv->balancing_locators_vec =
                    blv->v6_balancing_locators_vec;
            blv->locators_vec_length =
                    blv->v6_locators_vec_length;
        } //IPv4 and IPv6 locators are involved
        else {
            hcf[2] = highest_common_factor(hcf[0], hcf[1]);
            total_weight[2] = total_weight[0] + total_weight[1];
            for (ctr = 0; ctr < 2; ctr++) {
                ctr1 = 0;
                while (locators[ctr][ctr1] != NULL) {
                    locators[2][pos] = locators[ctr][ctr1];
                    ctr1++;
                    pos++;
                }
            }
            locators[2][pos] = NULL;
            blv->balancing_locators_vec = set_balancing_vector(
                    locators[2], total_weight[2], hcf[2],
                    &(blv->locators_vec_length));
        }
    }

    balancing_locators_vec_to_char(*blv, m, DBG_1);

    return (GOOD);
}

static inline void
get_hcf_locators_weight(locator_t **locators, int *total_weight,
        int *hcf)
{
    int ctr = 0;
    int weight = 0;
    int tmp_hcf = 0;

    if (locators[0] != NULL) {
        tmp_hcf = locator_weight(locators[0]);
        while (locators[ctr] != NULL) {
            weight = weight + locator_weight(locators[ctr]);
            tmp_hcf = highest_common_factor(tmp_hcf, locator_weight(locators[ctr]));
            ctr++;
        }
    }
    *total_weight = weight;
    *hcf = tmp_hcf;
}

static int
highest_common_factor(int a, int b)
{
    int c;
    if (b == 0) {
        return a;
    }
    if (a == 0) {
        return b;
    }

    if (a < b) {
        c = a;
        a = b;
        a = c;
    }
    c = 1;
    while (b != 0) {
        c = a % b;
        a = b;
        b = c;
    }

    return (a);
}


/* Print balancing locators vector information */
static void
balancing_locators_vec_to_char(balancing_locators_vecs b_locators_vecs,
        mapping_t *mapping, int log_level)
{
    int ctr = 0;
    char str[3000];

    if (is_loggable(log_level)) {
        LMLOG(log_level, "Balancing locator vector for %s: ",
                lisp_addr_to_char(mapping_eid(mapping)));

        sprintf(str, "  IPv4 locators vector (%d locators):  ",
                b_locators_vecs.v4_locators_vec_length);
        for (ctr = 0; ctr < b_locators_vecs.v4_locators_vec_length; ctr++) {
            if (strlen(str) > 2850) {
                sprintf(str + strlen(str), " ...");
                break;
            }
            sprintf(str + strlen(str), " %s  ",
                    lisp_addr_to_char(
                            b_locators_vecs.v4_balancing_locators_vec[ctr]->addr));
        }
        LMLOG(log_level, "%s", str);
        sprintf(str, "  IPv6 locators vector (%d locators):  ",
                b_locators_vecs.v6_locators_vec_length);
        for (ctr = 0; ctr < b_locators_vecs.v6_locators_vec_length; ctr++) {
            if (strlen(str) > 2900) {
                sprintf(str + strlen(str), " ...");
                break;
            }
            sprintf(str + strlen(str), " %s  ",
                    lisp_addr_to_char(
                            b_locators_vecs.v6_balancing_locators_vec[ctr]->addr));
        }
        LMLOG(log_level, "%s", str);
        sprintf(str, "  IPv4 & IPv6 locators vector (%d locators):  ",
                b_locators_vecs.locators_vec_length);
        for (ctr = 0; ctr < b_locators_vecs.locators_vec_length; ctr++) {
            if (strlen(str) > 2950) {
                sprintf(str + strlen(str), " ...");
                break;
            }
            sprintf(str + strlen(str), " %s  ",
                    lisp_addr_to_char(
                            b_locators_vecs.balancing_locators_vec[ctr]->addr));
        }
        LMLOG(log_level, "%s", str);
    }
}

void
locators_classify_in_4_6(
        mapping_t *     mapping,
        glist_t **      ipv4_loct_list,
        glist_t **      ipv6_loct_list)
{
    glist_t *               loct_list   = NULL;
    glist_entry_t *         it_list     = NULL;
    glist_entry_t *         it_loct     = NULL;
    locator_t *             locator     = NULL;
    lisp_addr_t *           addr        = NULL;
    lisp_addr_t *           ip_addr     = NULL;

    if (glist_size(mapping->locators_lists) == 0){
        LMLOG(DBG_3,"locators_classify_in_4_6: No locators to classify for mapping with eid %s",
                lisp_addr_to_char(mapping_eid(mapping)));
        return;
    }
    glist_for_each_entry(it_list,mapping->locators_lists){
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
            addr = locator_addr(locator);
            // XXX alopez: to check if used for fwd
            ip_addr = lisp_addr_get_ip_addr(addr);
            if (ip_addr == NULL){
            	LMLOG(DBG_2,"locators_classify_in_4_6: No IP address for %s", lisp_addr_to_char(addr));
            	continue;
            }

            if (lisp_addr_ip_afi(ip_addr) == AF_INET){
                glist_add(locator,*ipv4_loct_list);
            }else{
                glist_add(locator,*ipv6_loct_list);
            }
        }
    }
}

/* [re]Calculate balancing locator vectors  if it is not a negative map reply*/
int
mapping_compute_balancing_vectors(mapping_t *m)
{
    rmt_mapping_extended_info *reinf;
    lcl_mapping_extended_info *leinf;

    switch (m->type) {
    case MAPPING_REMOTE:
        if (!m->extended_info) {
            m->extended_info = xzalloc(sizeof(rmt_mapping_extended_info));
        }
        if (m->locator_count > 0) {
            reinf = m->extended_info;
            return(balancing_vectors_calculate(m,
                    &reinf->rmt_balancing_locators_vecs));
        }
        break;
    case MAPPING_LOCAL:
        if (!m->extended_info) {
            m->extended_info = xzalloc(sizeof(lcl_mapping_extended_info));
        }
        if (m->locator_count > 0) {
            leinf = m->extended_info;
            return(balancing_vectors_calculate(m,
                    &leinf->outgoing_balancing_locators_vecs));
        }
        break;
    case MAPPING_RE:
        return(GOOD);
    default:
        LMLOG(DBG_1, "mapping_compute_balancing_vectors: Mapping type %d "
                "unknown. Aborting!",  m->type);
        return(BAD);
    }
    return(GOOD);
}

/********************************************************************************************/



inline mapping_t *
mapping_new()
{
	mapping_t *mapping;
	mapping = xzalloc(sizeof(mapping_t));
	mapping->locators_lists = glist_new_complete(
			(glist_cmp_fct) locator_list_cmp_afi,
			(glist_del_fct) glist_destroy);
	if (mapping->locators_lists == NULL){
		free(mapping);
		return (NULL);
	}
	return(mapping);
}

static inline mapping_t *
mapping_init(lisp_addr_t *eid)
{
    mapping_t *mapping;
    mapping = mapping_new();
    if (!mapping)
        return (NULL);

    lisp_addr_copy(&(mapping->eid_prefix), eid);
    if (lisp_addr_lafi(&mapping->eid_prefix) == LM_AFI_IP){
        lisp_addr_ip_to_ippref(&mapping->eid_prefix);
    }

    return (mapping);
}


static void *
extended_info_init_local()
{
    lcl_mapping_extended_info *ei = NULL;

    ei = xmalloc(sizeof(lcl_mapping_extended_info));

    ei->outgoing_balancing_locators_vecs.v4_balancing_locators_vec = NULL;
    ei->outgoing_balancing_locators_vecs.v6_balancing_locators_vec = NULL;
    ei->outgoing_balancing_locators_vecs.balancing_locators_vec = NULL;
    ei->outgoing_balancing_locators_vecs.v4_locators_vec_length = 0;
    ei->outgoing_balancing_locators_vecs.v6_locators_vec_length = 0;
    ei->outgoing_balancing_locators_vecs.locators_vec_length = 0;
    return (ei);
}

/* Initializes a local mapping with 'eid' and no locators. 'eid' is
 * copied so, if needed, it should be freed outside  */
mapping_t *mapping_init_local(lisp_addr_t *eid)
{
    mapping_t *mapping = mapping_init(eid);

    if (!mapping) {
        LMLOG(LWRN, "mapping_init_local: Can't allocate mapping!");
        return (NULL);
    }

    mapping->type = MAPPING_LOCAL;
    mapping->extended_info = extended_info_init_local();
    mapping->authoritative = 1;

    return (mapping);
}

static void *
extended_info_init_remote()
{
    rmt_mapping_extended_info *ei = NULL;

    ei = xmalloc(sizeof(rmt_mapping_extended_info));

    ei->rmt_balancing_locators_vecs.v4_balancing_locators_vec = NULL;
    ei->rmt_balancing_locators_vecs.v6_balancing_locators_vec = NULL;
    ei->rmt_balancing_locators_vecs.balancing_locators_vec = NULL;
    ei->rmt_balancing_locators_vecs.v4_locators_vec_length = 0;
    ei->rmt_balancing_locators_vecs.v6_locators_vec_length = 0;
    ei->rmt_balancing_locators_vecs.locators_vec_length = 0;
    return (ei);
}

mapping_t *
mapping_init_static(lisp_addr_t *eid)
{
    mapping_t *mapping = mapping_init(eid);

    if (!mapping) {
        LMLOG(LWRN, "mapping_init_static: Can't allocate mapping!");
        return (NULL);
    }

    /* although static, it contains remote data */
    mapping->type = MAPPING_REMOTE;
    mapping->extended_info = extended_info_init_remote();

    return (mapping);
}

mapping_t *
mapping_init_remote(lisp_addr_t *eid)
{
    mapping_t *mapping = mapping_init(eid);

    if (!mapping) {
        LMLOG(LWRN, "mapping_init_learned: Can't allocate mapping!");
        return (NULL);
    }

    mapping->type = MAPPING_REMOTE;
    mapping->extended_info = extended_info_init_remote();
    return (mapping);
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
    cm->type = m->type;

    return(cm);
}


void mapping_del(mapping_t *m)
{
    if (!m) {
        return;
    }

    /* Free the locators list*/
    glist_destroy(m->locators_lists);

    mapping_extended_info_del(m);

    /*  MUST free lcaf addr */
    lisp_addr_dealloc(mapping_eid(m));
    free(m);

}

void
mapping_extended_info_del(mapping_t *mapping)
{
    lcl_mapping_extended_info *leinf;
    rmt_mapping_extended_info *reinf;

    if (mapping->extended_info) {
        switch (mapping->type) {
        case MAPPING_LOCAL:
            leinf = mapping->extended_info;
            free_balancing_locators_vecs(leinf->outgoing_balancing_locators_vecs);
            free (leinf);
            break;
        case MAPPING_REMOTE:
            reinf = mapping->extended_info;
            free_balancing_locators_vecs(reinf->rmt_balancing_locators_vecs);
            free (reinf);
            break;
        case MAPPING_RE:
            /* RE is not a type, it sets its own destruct function for the
             * extended info */
            if (mapping->extended_info)
                mapping->extended_info_del(mapping->extended_info);
            break;
        default:
            LMLOG(DBG_1, "mapping_del: unknown mapping type %d. Can't free "
                    "extended info!", mapping->type);
            break;
        }
    }
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
    glist_destroy(mapping->locators_lists);
    mapping->locators_lists = glist_new_complete(
            (glist_cmp_fct) locator_list_cmp_afi,
            (glist_del_fct) glist_destroy);

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
        LMLOG(DBG_1,"mapping_activate_locator: The locator %s has not been found",
                        lisp_addr_to_char(locator_addr(loct)));
        return (BAD);
    }

    res = mapping_add_locator(mapping,loct);

    if (res == GOOD){
        LMLOG(DBG_1,"mapping_activate_locator: The locator %s of the mapping %s has been activated",
                lisp_addr_to_char(locator_addr(loct)),
                lisp_addr_to_char(&(mapping->eid_prefix)));
    }
    return (res);
}
