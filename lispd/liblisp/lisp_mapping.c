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

//#include "lispd_lib.h"
//#include "lispd_local_db.h"
#include "lmlog.h"
#include "lisp_mapping.h"


/* Free the dinamic arrays that contains the balancing_locators_vecs structure; */

locator_t **set_balancing_vector(locator_t **, int, int, int *);
int select_best_priority_locators(locators_list_t *, locator_t **);
static inline void get_hcf_locators_weight(locator_t **, int *, int *);
static int highest_common_factor(int a, int b);

/* Initialize to 0 balancing_locators_vecs */
void reset_balancing_locators_vecs (balancing_locators_vecs *blv);
static void free_balancing_locators_vecs(balancing_locators_vecs);
static void balancing_locators_vec_to_char(balancing_locators_vecs,
        mapping_t *, int);



/* Add a locator into the locators list of the mapping. */
int
mapping_add_locators(mapping_t *mapping, locators_list_t *locators)
{
    locators_list_t *it;

    it = locators;
    while (it) {
        mapping_add_locator(mapping, it->locator);
        it = it->next;
    }

    return(GOOD);
}


int
mapping_add_locator(mapping_t *m, locator_t *loc)
{
    lisp_addr_t *addr = NULL;
    lisp_addr_t *auxaddr = NULL;
    lcl_mapping_extended_info *leinf;

    int result = GOOD;

    addr = locator_addr(loc);
    switch (lisp_addr_afi(addr)) {
    case LM_AFI_IP:
    case LM_AFI_NO_ADDR:
        auxaddr = addr;
        break;
    case LM_AFI_LCAF:
        auxaddr = lcaf_rloc_get_ip_addr(addr);
        break;
    default:
        lmlog(DBG_1, "mapping_add_locator: AFI %d not supported",
                lisp_addr_afi(addr));
    }

    switch (lisp_addr_ip_afi(auxaddr)) {
    case AF_INET:
        err = locator_list_add(&m->head_v4_locators_list, loc);
        break;
    case AF_INET6:
        err = locator_list_add(&m->head_v6_locators_list, loc);
        break;
    case AF_UNSPEC:
        leinf = m->extended_info;
        err = locator_list_add(&leinf->head_not_init_locators_list, loc);
        if (err == GOOD) {
            return (GOOD);
        } else {
            locator_del(loc);
            return (BAD);
        }
    default:
        lmlog(DBG_1, "Unknown locator afi %d", lisp_addr_ip_afi(auxaddr));
        err = BAD;
    }

    if (err == GOOD) {
        m->locator_count++;
        result = GOOD;
    } else if (err == ERR_EXIST) {
        lmlog(DBG_3, "mapping_add_locator: The locator %s already exists "
                "for the EID %s.", lisp_addr_to_char(locator_addr(loc)),
                lisp_addr_to_char(mapping_eid(m)));
        locator_del(loc);
        result = GOOD;
    } else {
        locator_del(loc);
        result = BAD;
    }

    return (result);
}


/* This function sorts the locator list with IP = changed_loc_addr */
void
sort_locators_list_elt(mapping_t *mapping, lisp_addr_t *changed_loc_addr)
{
    locators_list_t *current_locators_list_elt = NULL;
    locators_list_t *prev_locators_list_elt = NULL;
    locators_list_t *changed_locator = NULL;
    locators_list_t *prev_changed_locator = NULL;
    locators_list_t *new_prev_changed_locator = NULL;
    int changed_locator_updated = FALSE;
    int new_prev_changed_lct_updated = FALSE;
    int afi_length = 0;
    int cmp = 0;

    switch (lisp_addr_ip_afi(changed_loc_addr)) {
    case AF_INET:
        current_locators_list_elt = mapping->head_v4_locators_list;
        afi_length = sizeof(struct in_addr);
        break;
    case AF_INET6:
        current_locators_list_elt = mapping->head_v6_locators_list;
        afi_length = sizeof(struct in6_addr);
        break;
    }

    if (current_locators_list_elt == NULL) {
        lmlog(DBG_1, "sort_locators_list_elt: It should never reach "
                "this point");
        return;
    }

    while (current_locators_list_elt != NULL) {
        cmp = memcmp(&(current_locators_list_elt->locator->addr->address),
                &(changed_loc_addr->address), afi_length);
        if (cmp == 0) {
            changed_locator = current_locators_list_elt;
            prev_changed_locator = prev_locators_list_elt;
            changed_locator_updated = TRUE;
            if (new_prev_changed_lct_updated == TRUE) {
                break;
            }

        } else if (cmp > 0 && new_prev_changed_lct_updated == FALSE) {
            new_prev_changed_locator = prev_locators_list_elt;
            new_prev_changed_lct_updated = TRUE;
            if (changed_locator_updated == TRUE) {
                break;
            }
        }
        prev_locators_list_elt = current_locators_list_elt;
        current_locators_list_elt = current_locators_list_elt->next;
    }

    /* The new locator goes to the last position */
    if (new_prev_changed_locator == NULL
            && new_prev_changed_lct_updated == FALSE) {
        new_prev_changed_locator = prev_locators_list_elt;
    }

    if (new_prev_changed_locator == changed_locator) {
        new_prev_changed_locator = prev_changed_locator;
    }

    if (prev_changed_locator != NULL) {
        prev_changed_locator->next = changed_locator->next;
    } else {
        switch (changed_loc_addr->afi) {
        case AF_INET:
            mapping->head_v4_locators_list = changed_locator->next;
            break;
        case AF_INET6:
            mapping->head_v6_locators_list = changed_locator->next;
            break;
        }
    }
    if (new_prev_changed_locator != NULL) {
        changed_locator->next = new_prev_changed_locator->next;
        new_prev_changed_locator->next = changed_locator;
    } else {
        switch (changed_loc_addr->afi) {
        case AF_INET:
            changed_locator->next = mapping->head_v4_locators_list;
            mapping->head_v4_locators_list = changed_locator;
            break;
        case AF_INET6:
            changed_locator->next = mapping->head_v6_locators_list;
            mapping->head_v6_locators_list = changed_locator;
            break;
        }
    }
}


/*
 * Returns the locators with the address passed as a parameter
 */

locator_t *
mapping_get_locator(mapping_t *mapping, lisp_addr_t *address)
{
    locator_t *locator = NULL;
    locators_list_t *locator_list = NULL;

    switch (lisp_addr_ip_afi(address)) {
    case AF_INET:
        locator_list = mapping->head_v4_locators_list;
        break;
    case AF_INET6:
        locator_list = mapping->head_v6_locators_list;
        break;
    }

    locator = locator_list_get_locator(locator_list, address);

    return (locator);
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
void
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
    locators_list_t *locator_iterator_array[2] = { NULL, NULL };
    locators_list_t *locator_iterator = NULL;
    locator_t *locator = NULL;
    int ctr = 0;
    static char buf[100];

    sprintf(buf, "EID: %s, ttl: %d, loc-count: %d, action: %s, "
            "auth: %d", lisp_addr_to_char(mapping_eid(m)), mapping_ttl(m),
            mapping_locator_count(m),
            mapping_action_to_char(mapping_action(m)), mapping_auth(m));

    if (m->locator_count > 0) {
        locator_iterator_array[0] = m->head_v4_locators_list;
        locator_iterator_array[1] = m->head_v6_locators_list;
        /* Loop through the locators and print each */

        for (ctr = 0; ctr < 2; ctr++) {
            locator_iterator = locator_iterator_array[ctr];
            while (locator_iterator != NULL) {
                locator = locator_iterator->locator;
                sprintf(buf+strlen(buf), "\n  RLOC: %s", locator_to_char(locator));
                locator_iterator = locator_iterator->next;
            }
        }
    }
    return(buf);
}

/**************************************** TRAFFIC BALANCING FUNCTIONS ************************/

/*
 * Calculate the vectors used to distribute the load from the priority and weight of the locators of the mapping
 */
int
balancing_vectors_calculate(mapping_t *mapping,
        balancing_locators_vecs *b_locators_vecs)
{
    // Store locators with same priority. Maximum 32 locators (33 to no get out of array)
    locator_t *locators[3][33];

    int min_priority[2] = { 255, 255 };
    int total_weight[3] = { 0, 0, 0 };
    int hcf[3] = { 0, 0, 0 };
    int ctr = 0;
    int ctr1 = 0;
    int pos = 0;

    locators[0][0] = NULL;
    locators[1][0] = NULL;

    reset_balancing_locators_vecs(b_locators_vecs);

    /* Fill the locator balancing vec using only IPv4 locators and according
     * to their priority and weight */
    if (mapping->head_v4_locators_list != NULL) {
        min_priority[0] = select_best_priority_locators(
                mapping->head_v4_locators_list, locators[0]);
        if (min_priority[0] != UNUSED_RLOC_PRIORITY) {
            get_hcf_locators_weight(locators[0], &total_weight[0], &hcf[0]);
            b_locators_vecs->v4_balancing_locators_vec = set_balancing_vector(
                    locators[0], total_weight[0], hcf[0],
                    &(b_locators_vecs->v4_locators_vec_length));
        }
    }
    /* Fill the locator balancing vec using only IPv6 locators and according
     * to their priority and weight*/
    if (mapping->head_v6_locators_list != NULL) {
        min_priority[1] = select_best_priority_locators(
                mapping->head_v6_locators_list, locators[1]);
        if (min_priority[1] != UNUSED_RLOC_PRIORITY) {
            get_hcf_locators_weight(locators[1], &total_weight[1], &hcf[1]);
            b_locators_vecs->v6_balancing_locators_vec = set_balancing_vector(
                    locators[1], total_weight[1], hcf[1],
                    &(b_locators_vecs->v6_locators_vec_length));
        }
    }
    /* Fill the locator balancing vec using IPv4 and IPv6 locators and according
     * to their priority and weight*/
    if (b_locators_vecs->v4_balancing_locators_vec != NULL
            && b_locators_vecs->v6_balancing_locators_vec != NULL) {
        //Only IPv4 locators are involved (due to priority reasons)
        if (min_priority[0] < min_priority[1]) {
            b_locators_vecs->balancing_locators_vec =
                    b_locators_vecs->v4_balancing_locators_vec;
            b_locators_vecs->locators_vec_length =
                    b_locators_vecs->v4_locators_vec_length;
        } //Only IPv6 locators are involved (due to priority reasons)
        else if (min_priority[0] > min_priority[1]) {
            b_locators_vecs->balancing_locators_vec =
                    b_locators_vecs->v6_balancing_locators_vec;
            b_locators_vecs->locators_vec_length =
                    b_locators_vecs->v6_locators_vec_length;
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
            b_locators_vecs->balancing_locators_vec = set_balancing_vector(
                    locators[2], total_weight[2], hcf[2],
                    &(b_locators_vecs->locators_vec_length));
        }
    }

    balancing_locators_vec_to_char(*b_locators_vecs, mapping, DBG_1);

    return (GOOD);
}

locator_t **
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
            used_pos = locators[ctr]->weight / hcf;
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

int
select_best_priority_locators(locators_list_t *locators_list_elt,
        locator_t **selected_locators)
{
    locators_list_t *list_elt = locators_list_elt;
    int min_priority = UNUSED_RLOC_PRIORITY;
    int pos = 0;

    while (list_elt != NULL) {
        /* Only use locators with status UP */
        if (*(list_elt->locator->state) == DOWN
                || list_elt->locator->priority == UNUSED_RLOC_PRIORITY) {
            list_elt = list_elt->next;
            continue;
        }
        /* If priority of the locator equal to min_priority, then add the
         * locator to the list */
        if (list_elt->locator->priority == min_priority) {
            selected_locators[pos] = list_elt->locator;
            pos++;
            selected_locators[pos] = NULL;
        }
        /* If priority of the locator is minor than the min_priority, then
         * min_priority and list of rlocs is updated */
        if (list_elt->locator->priority < min_priority) {
            pos = 0;
            min_priority = list_elt->locator->priority;
            selected_locators[pos] = list_elt->locator;
            pos++;
            selected_locators[pos] = NULL;
        }
        list_elt = list_elt->next;
    }

    return (min_priority);
}

static inline void
get_hcf_locators_weight(locator_t **locators, int *total_weight,
        int *hcf)
{
    int ctr = 0;
    int weight = 0;
    int tmp_hcf = 0;

    if (locators[0] != NULL) {
        tmp_hcf = locators[0]->weight;
        while (locators[ctr] != NULL) {
            weight = weight + locators[ctr]->weight;
            tmp_hcf = highest_common_factor(tmp_hcf, locators[ctr]->weight);
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
        lmlog(log_level, "Balancing locator vector for %s: ",
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
        lmlog(log_level, "%s", str);
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
        lmlog(log_level, "%s", str);
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
        lmlog(log_level, "%s", str);
    }
}

/********************************************************************************************/


/*
 * lispd_mapping_elt set/get functions
 */

inline mapping_t *
mapping_new()
{
    mapping_t *mapping;
    mapping = xzalloc(sizeof(mapping_t));
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
    if (lisp_addr_afi(&mapping->eid_prefix) == LM_AFI_IP)
        lisp_addr_ip_to_ippref(&mapping->eid_prefix);
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
    ei->head_not_init_locators_list = NULL;
    return (ei);
}

mapping_t *mapping_init_local(lisp_addr_t *eid)
{
    mapping_t *mapping = mapping_init(eid);

    if (!mapping) {
        lmlog(LWRN, "mapping_init_local: Can't allocate mapping!");
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
        lmlog(LWRN, "mapping_init_static: Can't allocate mapping!");
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
        lmlog(LWRN, "mapping_init_learned: Can't allocate mapping!");
        return (NULL);
    }

    mapping->type = MAPPING_REMOTE;
    mapping->extended_info = extended_info_init_remote();
    return (mapping);
}

/* Clones a mapping_t data structure
 * NOTE: it does not clone the 'extended_info'! This should be done by the
 * caller and in the future it shouldn't be done at all. 'extended_info'
 * should be moved into map_cache_entry */
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
    /* Free the locators list*/
    locator_list_del(m->head_v4_locators_list);
    locator_list_del(m->head_v6_locators_list);

    mapping_extended_info_del(m);

    /*  need hack to free lcaf addr */
    if (lisp_addr_afi(mapping_eid(m)) == LM_AFI_LCAF)
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
            locator_list_del(leinf->head_not_init_locators_list);
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
            lmlog(DBG_1, "mapping_del: unknown mapping type %d. Can't free "
                    "extended info!", mapping->type);
            break;
        }
    }
}


void
mapping_update_locators(mapping_t *mapping, locators_list_t *locv4,
        locators_list_t *locv6, int nb_locators)
{
    if (!mapping)
        return;

    /* TODO: do a comparison first */
    if (mapping->head_v4_locators_list)
        locator_list_del(mapping->head_v4_locators_list);
    if (mapping->head_v6_locators_list)
        locator_list_del(mapping->head_v6_locators_list);
    mapping->head_v4_locators_list = locv4;
    mapping->head_v6_locators_list = locv6;
    mapping->locator_count = nb_locators;
}

/* [re]Calculate balancing locator vectors  if it is not a negative map reply*/
int
mapping_compute_balancing_vectors(mapping_t *mapping)
{
    rmt_mapping_extended_info *reinf;
    lcl_mapping_extended_info *leinf;

    switch (mapping->type) {
    case MAPPING_REMOTE:
        if (!mapping->extended_info) {
            mapping->extended_info = xzalloc(sizeof(rmt_mapping_extended_info));
        }
        if (mapping->locator_count != 0) {
            reinf = mapping->extended_info;
            return(balancing_vectors_calculate(mapping,
                    &reinf->rmt_balancing_locators_vecs));
        }
        break;
    case MAPPING_LOCAL:
        if (!mapping->extended_info) {
            mapping->extended_info = xzalloc(sizeof(lcl_mapping_extended_info));
        }
        if (mapping->locator_count > 0) {
            leinf = mapping->extended_info;
            return(balancing_vectors_calculate(mapping,
                    &leinf->outgoing_balancing_locators_vecs));
        }
        break;
    case MAPPING_RE:
        return(GOOD);
    default:
        lmlog(DBG_1, "mapping_compute_balancing_vectors: Mapping type %d "
                "unknown. Aborting!",  mapping->type);
        return(BAD);
    }
    return(GOOD);
}

/* compare two mappings
 * returns 0 if they are the same and 1 otherwise */
int
mapping_cmp(mapping_t *m1, mapping_t *m2)
{
    int ret = 0, ctr = 0;
    locators_list_t *ll1[2] = { NULL, NULL }, *ll2[2] = { NULL, NULL };
    locator_t *l1 = NULL, *l2 = NULL;

    if ((ret = lisp_addr_cmp(mapping_eid(m1), mapping_eid(m2))) != 0)
        return (1);
    if (m1->locator_count != m2->locator_count)
        return (1);

    ll1[0] = m1->head_v4_locators_list;
    ll1[1] = m1->head_v6_locators_list;

    ll2[0] = m2->head_v4_locators_list;
    ll2[1] = m2->head_v6_locators_list;

    for (ctr = 0; ctr < 2; ctr++) {
        while (ll1[ctr] && ll2[ctr]) {
            l1 = ll1[ctr]->locator;
            l2 = ll2[ctr]->locator;
            if ((ret = locator_cmp(l1, l2)) != 0)
                return (ret);
            ll1[ctr] = ll1[ctr]->next;
            ll2[ctr] = ll2[ctr]->next;
        }

        if ((ll1[ctr] && !ll2[ctr]) || (!ll1[ctr] && ll2[ctr]))
            return (1);
    }
    return (0);

}

void
mapping_del_locators(mapping_t *m)
{
    locator_list_del(m->head_v4_locators_list);
    locator_list_del(m->head_v6_locators_list);
    m->head_v4_locators_list = NULL;
    m->head_v6_locators_list = NULL;
}



