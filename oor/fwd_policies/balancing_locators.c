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

#include "balancing_locators.h"
#include "fwd_addr_func.h"
#include "../lib/oor_log.h"
#include "../lib/util.h"


static void balancing_locators_vecs_reset(balancing_locators_vecs *blv);
static int select_best_priority_locators(glist_t *loct_list, locator_t **selected_locators,
        uint8_t is_mce);
static locator_t **set_balancing_vector(locator_t **locators, int total_weight, int hcf,
        int *locators_vec_length);
static inline void get_hcf_locators_weight(locator_t **locators, int *total_weight,int *hcf);
static int highest_common_factor(int a, int b);

static inline balancing_locators_vecs *
balancing_locators_vecs_new()
{
    balancing_locators_vecs * bal_loct_vec;

    bal_loct_vec = (balancing_locators_vecs *)xzalloc(sizeof(balancing_locators_vecs));
    if (bal_loct_vec == NULL){
        OOR_LOG(LWRN, "balancing_locators_vecs_new: Couldn't allocate memory for balancing_locators_vecs");
    }

    return (bal_loct_vec);
}

void *
balancing_locators_vecs_new_init(mapping_t *map, glist_t *loc_loct, uint8_t is_mce)
{
    balancing_locators_vecs *bal_vec;

    bal_vec = balancing_locators_vecs_new();
    if (!bal_vec){
        return (NULL);
    }

    if (balancing_vectors_calculate(bal_vec, map, loc_loct, is_mce) != GOOD){
        balancing_locators_vecs_del(bal_vec);
        OOR_LOG(LDBG_2,"balancing_locators_vecs_new_init: Error calculating balancing vectors");
        return (NULL);
    }

    return((void *)bal_vec);
}

void
balancing_locators_vecs_del(void * bal_vec)
{
    balancing_locators_vecs_reset((balancing_locators_vecs *)bal_vec);
    free((balancing_locators_vecs *)bal_vec);
}

/* Print balancing locators vector information */
void
balancing_locators_vec_dump(balancing_locators_vecs b_locators_vecs,
        mapping_t *mapping, int log_level)
{
    int ctr;
    char str[3000];

    if (is_loggable(log_level)) {
        OOR_LOG(log_level, "Balancing locator vector for %s: ",
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
        OOR_LOG(log_level, "%s", str);
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
        OOR_LOG(log_level, "%s", str);
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
        OOR_LOG(log_level, "%s", str);
    }
}

/*
 * Calculate the vectors used to distribute the load from the priority and weight of the locators of the mapping
 */
int
balancing_vectors_calculate(balancing_locators_vecs *blv, mapping_t * map, glist_t *loc_loct, uint8_t is_mce)
{
    // Store locators with same priority. Maximum 32 locators (33 to no get out of array)
    locator_t *locators[3][33];
    // Aux list to classify all locators between IP4 and IPv6
    glist_t *ipv4_loct_list  = glist_new();
    glist_t *ipv6_loct_list  = glist_new();

    int min_priority[2] = { 255, 255 };
    int total_weight[3] = { 0, 0, 0 };
    int hcf[3]          = { 0, 0, 0 };
    int ctr             = 0;
    int ctr1            = 0;
    int pos             = 0;

    locators[0][0]      = NULL;
    locators[1][0]      = NULL;

    balancing_locators_vecs_reset(blv);

    locators_classify_in_4_6(map,loc_loct,ipv4_loct_list,ipv6_loct_list, laddr_get_fwd_ip_addr);


    /* Fill the locator balancing vec using only IPv4 locators and according
     * to their priority and weight */
    if (glist_size(ipv4_loct_list) != 0)
    {
        min_priority[0] = select_best_priority_locators(
                ipv4_loct_list, locators[0], is_mce);
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
                ipv6_loct_list, locators[1], is_mce);
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

    balancing_locators_vec_dump(*blv, map, LDBG_1);

    glist_destroy(ipv4_loct_list);
    glist_destroy(ipv6_loct_list);

    return (GOOD);
}

/* Initialize to 0 balancing_locators_vecs */
static void
balancing_locators_vecs_reset(balancing_locators_vecs *blv)
{
    /* IPv4 locators more priority -> IPv4_IPv6 vector = IPv4 locator vector
     * IPv6 locators more priority -> IPv4_IPv6 vector = IPv4 locator vector */
    if (blv->balancing_locators_vec != NULL
            && blv->balancing_locators_vec
                    != blv->v4_balancing_locators_vec
            && blv->balancing_locators_vec
                    != blv->v6_balancing_locators_vec) {
        free(blv->balancing_locators_vec);
    }
    if (blv->v4_balancing_locators_vec != NULL) {
        free(blv->v4_balancing_locators_vec);
    }
    if (blv->v6_balancing_locators_vec != NULL) {
        free(blv->v6_balancing_locators_vec);
    }

    blv->v4_balancing_locators_vec = NULL;
    blv->v4_locators_vec_length = 0;
    blv->v6_balancing_locators_vec = NULL;
    blv->v6_locators_vec_length = 0;
    blv->balancing_locators_vec = NULL;
    blv->locators_vec_length = 0;
}


static int
select_best_priority_locators(glist_t *loct_list, locator_t **selected_locators, uint8_t is_mce)
{
    glist_entry_t *it_loct;
    locator_t *locator;
    int min_priority = UNUSED_RLOC_PRIORITY;
    int pos = 0;

    if (glist_size(loct_list) == 0){
        return (BAD);
    }

    glist_for_each_entry(it_loct,loct_list){
        locator = (locator_t *)glist_entry_data(it_loct);
        /* Only use locators with status UP  */
        if (locator_state(locator) == DOWN
                || locator_priority(locator) == UNUSED_RLOC_PRIORITY ) {
            continue;
        }
        /* For local mappings, the locator should be local */
        if (!is_mce && locator_L_bit(locator) == 0){
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
    locator_t **balancing_locators_vec;
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



