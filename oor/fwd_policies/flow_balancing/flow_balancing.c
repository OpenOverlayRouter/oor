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

#include "flow_balancing.h"
#include "fb_addr_func.h"
#include "../../lib/oor_log.h"
#include "../../liblisp/liblisp.h"

inline fb_dev_parm *fb_dev_parm_new();
void *fb_dev_parm_new_init(oor_ctrl_dev_t *ctrl_dev,
        fwd_policy_dev_parm *dev_parm_inf);
inline void fb_dev_parm_del(void *dev_parm);
inline balancing_locators_vecs *balancing_locators_vecs_new();
int mle_balancing_locators_vecs_new_init(void *dev_parm, map_local_entry_t *mle,
        fwd_policy_map_parm *map_parm,fwd_info_del_fct fwd_del_fct);
int mce_balancing_locators_vecs_new_init(void *dev_parm, mcache_entry_t *mce,
        routing_info_del_fct del_fct);
static void *balancing_locators_vecs_new_init(void *dev_parm, mapping_t *map, uint8_t is_mce);
void balancing_locators_vecs_del(void * bal_vec);
void fb_get_fw_entry(void *fwd_dev_parm, void *src_map_parm,
        void *dst_map_parm, packet_tuple_t *tuple, fwd_info_t *fwd_info);
static locator_t **set_balancing_vector(locator_t **, int, int, int *);
static int select_best_priority_locators(glist_t *, locator_t **, uint8_t);
static inline void get_hcf_locators_weight(locator_t **, int *, int *);
static int highest_common_factor(int a, int b);
/* Initialize to 0 balancing_locators_vecs */
static void balancing_locators_vecs_reset (balancing_locators_vecs *blv);
static void balancing_locators_vec_dump(balancing_locators_vecs,
        mapping_t *, int);

int mle_balancing_vectors_calculate(void *dev_parm, map_local_entry_t *mle);
int mce_balancing_vectors_calculate(void *dev_parm, mcache_entry_t *mce);
static int balancing_vectors_calculate(void *dev_parm, balancing_locators_vecs *blv,
        mapping_t *map, uint8_t is_mce);
void fb_locators_classify_in_4_6(mapping_t *mapping,glist_t *loc_loct_addr,
        glist_t *ipv4_loct_list,glist_t *ipv6_loct_list);

fwd_policy_class  fwd_policy_flow_balancing = {
        .new_dev_policy_inf = fb_dev_parm_new_init,
        .del_dev_policy_inf = fb_dev_parm_del,
        .init_map_loc_policy_inf = mle_balancing_locators_vecs_new_init,
        .del_map_loc_policy_inf = balancing_locators_vecs_del,
        .init_map_cache_policy_inf = mce_balancing_locators_vecs_new_init,
        .del_map_cache_policy_inf = balancing_locators_vecs_del,
        .updated_map_loc_inf = mle_balancing_vectors_calculate,
        .updated_map_cache_inf = mce_balancing_vectors_calculate,
        .policy_get_fwd_info = fb_get_fw_entry,
        .get_fwd_ip_addr = fb_addr_get_fwd_ip_addr
};


inline fb_dev_parm *
fb_dev_parm_new()
{
    fb_dev_parm *dev_parm;
    dev_parm = (fb_dev_parm *)xzalloc(sizeof(fb_dev_parm));
    if(dev_parm == NULL){
        OOR_LOG(LWRN, "fb_dev_parm_new: Couldn't allocate memory for fb_dev_parm");
    }

    return(dev_parm);
}

void *
fb_dev_parm_new_init(oor_ctrl_dev_t *ctrl_dev,
        fwd_policy_dev_parm *dev_parm_inf)
{
    fb_dev_parm *   dev_parm;

    dev_parm = fb_dev_parm_new();
    if(dev_parm == NULL){
        return (NULL);
    }
    dev_parm->dev_type = ctrl_dev_mode(ctrl_dev);
    dev_parm->loc_loct = ctrl_rlocs(ctrl_dev_ctrl(ctrl_dev));

    return(dev_parm);
}

inline void
fb_dev_parm_del(void *dev_parm)
{
    free((fb_dev_parm *)dev_parm);
}

inline balancing_locators_vecs *
balancing_locators_vecs_new()
{
    balancing_locators_vecs * bal_loct_vec;

    bal_loct_vec = (balancing_locators_vecs *)xzalloc(sizeof(balancing_locators_vecs));
    if (bal_loct_vec == NULL){
        OOR_LOG(LWRN, "balancing_locators_vecs_new: Couldn't allocate memory for balancing_locators_vecs");
    }

    return (bal_loct_vec);
}

int
mle_balancing_locators_vecs_new_init(void *dev_parm, map_local_entry_t *mle, fwd_policy_map_parm *map_parm,
        fwd_info_del_fct fwd_del_fct)
{
    void * fwd_inf = balancing_locators_vecs_new_init(dev_parm, map_local_entry_mapping(mle), FALSE);
    if (!fwd_inf){
        return (BAD);
    }
    map_local_entry_set_fwd_info(mle, fwd_inf, fwd_del_fct);
    return (GOOD);
}

int
mce_balancing_locators_vecs_new_init(void *dev_parm, mcache_entry_t *mce, routing_info_del_fct del_fct)
{
    void * routing_inf =  balancing_locators_vecs_new_init(dev_parm, mcache_entry_mapping(mce), TRUE);
    if (!routing_inf){
        return (BAD);
    }
    mcache_entry_set_routing_info(mce, routing_inf, del_fct);
    return (GOOD);
}

static void *
balancing_locators_vecs_new_init(void *dev_parm, mapping_t *map, uint8_t is_mce)
{
    balancing_locators_vecs *bal_vec;

    bal_vec = balancing_locators_vecs_new();
    if (!bal_vec){
        return (NULL);
    }

    if (balancing_vectors_calculate(dev_parm, bal_vec, map, is_mce) != GOOD){
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

/**************************************** TRAFFIC BALANCING FUNCTIONS ************************/

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

int
mle_balancing_vectors_calculate(void *dev_parm,map_local_entry_t *mle){
    return (balancing_vectors_calculate(dev_parm, map_local_entry_fwd_info(mle),
            map_local_entry_mapping(mle),FALSE));
}

int
mce_balancing_vectors_calculate(void *dev_parm,mcache_entry_t *mce){
    return (balancing_vectors_calculate(dev_parm, mcache_entry_routing_info(mce),
            mcache_entry_mapping(mce),TRUE));
}


/*
 * Calculate the vectors used to distribute the load from the priority and weight of the locators of the mapping
 */
static int
balancing_vectors_calculate(void *dev_parm, balancing_locators_vecs *blv, mapping_t * map, uint8_t is_mce)
{
    // Store locators with same priority. Maximum 32 locators (33 to no get out of array)
    locator_t *locators[3][33];
    // Aux list to classify all locators between IP4 and IPv6
    glist_t *ipv4_loct_list  = glist_new();
    glist_t *ipv6_loct_list  = glist_new();
    fb_dev_parm *fw_dev_parm = (fb_dev_parm *)dev_parm;

    int min_priority[2] = { 255, 255 };
    int total_weight[3] = { 0, 0, 0 };
    int hcf[3]          = { 0, 0, 0 };
    int ctr             = 0;
    int ctr1            = 0;
    int pos             = 0;

    locators[0][0]      = NULL;
    locators[1][0]      = NULL;

    balancing_locators_vecs_reset(blv);

    fb_locators_classify_in_4_6(map,fw_dev_parm->loc_loct,ipv4_loct_list,ipv6_loct_list);


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

void
fb_locators_classify_in_4_6(mapping_t *mapping, glist_t *loc_loct_addr,
        glist_t *ipv4_loct_list, glist_t *ipv6_loct_list)
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
        ip_addr = fb_addr_get_fwd_ip_addr(addr,loc_loct_addr);
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

/*************************** Forward Select Function *************************/

/* Select the source and destination RLOC according to the priority and weight.
 * The destination RLOC is selected according to the AFI of the selected source
 * RLOC */


void
fb_get_fw_entry(void *fwd_dev_parm, void *src_map_parm, void *dst_map_parm,
        packet_tuple_t *tuple, fwd_info_t *fwd_info)
{
    fwd_entry_t *fwd_entry;
    fb_dev_parm * dev_parm = (fb_dev_parm *)fwd_dev_parm;
    balancing_locators_vecs * src_blv = (balancing_locators_vecs *)src_map_parm;
    balancing_locators_vecs * dst_blv = (balancing_locators_vecs *)dst_map_parm;
    int src_vec_len, dst_vec_len;
    uint32_t pos, hash;
    locator_t ** src_loc_vec;
    locator_t ** dst_loc_vec;
    locator_t * src_loct;
    locator_t * dst_loct;

    lisp_addr_t * src_addr;
    lisp_addr_t * dst_addr;
    lisp_addr_t * src_ip_addr;
    lisp_addr_t * dst_ip_addr;
    int afi;

    if (src_blv->balancing_locators_vec != NULL
            && dst_blv->balancing_locators_vec != NULL) {
        src_loc_vec = src_blv->balancing_locators_vec;
        src_vec_len = src_blv->locators_vec_length;
    } else if (src_blv->v6_balancing_locators_vec != NULL
            && dst_blv->v6_balancing_locators_vec != NULL) {
        src_loc_vec = src_blv->v6_balancing_locators_vec;
        src_vec_len = src_blv->v6_locators_vec_length;
    } else if (src_blv->v4_balancing_locators_vec != NULL
            && dst_blv->v4_balancing_locators_vec != NULL) {
        src_loc_vec = src_blv->v4_balancing_locators_vec;
        src_vec_len = src_blv->v4_locators_vec_length;
    } else {
        if (src_blv->v4_balancing_locators_vec == NULL
                && src_blv->v6_balancing_locators_vec == NULL) {
            OOR_LOG(LDBG_3, "fb_get_fw_entry: No SRC locators "
                    "available");
        }else if (dst_blv->v4_balancing_locators_vec == NULL
                && dst_blv->v6_balancing_locators_vec == NULL) {
            OOR_LOG(LDBG_3, "fb_get_fw_entry: No DST locators "
                    "available");
        } else {
            OOR_LOG(LDBG_3, "fb_get_fw_entry: Source and "
                    "destination RLOCs are not compatible");
        }
        return;
    }

    hash = pkt_tuple_hash(tuple);
    if (hash == 0) {
        OOR_LOG(LDBG_1, "fb_get_fw_entry: Couldn't get the hash of the tuple "
                "to select the rloc. Using the default rloc");
        //pos = hash%x_vec_len -> 0%x_vec_len = 0;
    }

    pos = hash % src_vec_len;
    src_loct = src_loc_vec[pos];
    src_addr = locator_addr(src_loct);

    /* decide dst afi based on src afi*/


    src_ip_addr = fb_addr_get_fwd_ip_addr(src_addr,dev_parm->loc_loct);
    afi = lisp_addr_ip_afi(src_ip_addr);

    switch (afi) {
    case (AF_INET):
        dst_loc_vec = dst_blv->v4_balancing_locators_vec;
        dst_vec_len = dst_blv->v4_locators_vec_length;
        break;
    case (AF_INET6):
        dst_loc_vec = dst_blv->v6_balancing_locators_vec;
        dst_vec_len = dst_blv->v6_locators_vec_length;
        break;
    default:
        OOR_LOG(LDBG_2, "select_locs_from_maps: Unknown IP AFI %d",
                lisp_addr_ip_afi(src_addr));
        return;
    }

    pos = hash % dst_vec_len;
    dst_loct = dst_loc_vec[pos];
    dst_addr = locator_addr(dst_loct);
    dst_ip_addr = fb_addr_get_fwd_ip_addr(dst_addr,dev_parm->loc_loct);


    fwd_entry = fwd_entry_new_init(src_ip_addr, dst_ip_addr, tuple->iid, NULL);
    fwd_info->fwd_info = fwd_entry;

    OOR_LOG(LDBG_3, "select_locs_from_maps: EID: %s -> %s, protocol: %d, "
            "port: %d -> %d\n  --> RLOC: %s -> %s",
            lisp_addr_to_char(&(tuple->src_addr)),
            lisp_addr_to_char(&(tuple->dst_addr)), tuple->protocol,
            tuple->src_port, tuple->dst_port,
            lisp_addr_to_char(src_ip_addr),
            lisp_addr_to_char(dst_ip_addr));

    return;
}
