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

#ifndef ROUTING_POLICY_H_
#define ROUTING_POLICY_H_

#include "../lib/map_cache_entry.h"
#include "../lib/map_local_entry.h"

typedef struct packet_tuple packet_tuple_t;

typedef lisp_addr_t *(*get_fwd_ip_addr_fct)(void *, glist_t *);
typedef void (*fwd_info_data_del)(void *);


/*
 * Structure used to pass routing configuration parameters releated
 * to the device into the fwd module
 */
typedef struct fwd_policy_dev_parm_t{
	shash_t *paramiters;
} fwd_policy_dev_parm;

/*
 * Structure used to pass routing configuration parameters releated
 * to a mapping into the fwd module
 */
typedef struct fwd_policy_map_parm_t{
	lisp_addr_t     *eid_prefix;
	shash_t 		*paramiters;
	glist_t			*locators;
} fwd_policy_map_parm;

/*
 * Structure used to pass routing configuration parameters releated
 * to a locator into the fwd module
 */
typedef struct fwd_policy_loct_parm_t{
	lisp_addr_t     *rloc_addr;
	shash_t 		*paramiters;
} fwd_policy_loct_parm;

typedef struct fwd_info_{
    void *fwd_info;
    uint8_t temporal;
    lisp_action_e neg_map_reply_act;
    oor_encap_t encap;
}fwd_info_t;


/* functions to manipulate routing */
typedef struct fwd_policy_class {
    void *(*new_dev_policy_inf)(oor_ctrl_dev_t *ctrl_dev, fwd_policy_dev_parm *dev_parm);
    void (*del_dev_policy_inf)(void *);
    int (*init_map_loc_policy_inf)(void *dev_parm, map_local_entry_t *mle, fwd_policy_map_parm *map_parm,
            fwd_info_del_fct fwd_del_fct);
    void (*del_map_loc_policy_inf)(void *);
    int (*init_map_cache_policy_inf)(void *dev_parm, mcache_entry_t *mce, routing_info_del_fct rt_del_fct);
    void (*del_map_cache_policy_inf)(void *);
    int (*updated_map_loc_inf)(void *dev_parm, map_local_entry_t *mle);
    int (*updated_map_cache_inf)(void *dev_parm, mcache_entry_t *mce);
    void (*policy_get_fwd_info)(void *dev_parm, void *src_map_parm, void *dst_map_parm,
            packet_tuple_t *tuple, fwd_info_t *fdw_info);
    lisp_addr_t *(*get_fwd_ip_addr)(lisp_addr_t *addr, glist_t *locl_rlocs_addr);
} fwd_policy_class;


extern fwd_policy_class fwd_policy_flow_balancing;

fwd_policy_dev_parm *fwd_policy_dev_parm_new();
void fwd_policy_dev_parm_del(fwd_policy_dev_parm *pol_dev);
fwd_policy_map_parm *fwd_policy_map_parm_new(lisp_addr_t *eid_prefix);
void fwd_policy_map_parm_del (fwd_policy_map_parm *pol_map);
fwd_policy_loct_parm *fwd_policy_loct_parm_new(lisp_addr_t *rloc_addr);
void fwd_policy_loct_parm_del(fwd_policy_loct_parm *pol_loct);

fwd_policy_class *fwd_policy_class_find(char *lib);
fwd_info_t *fwd_info_new();
void fwd_info_del(fwd_info_t * fwd_info,fwd_info_data_del del_fn);

#endif /* ROUTING_POLICY_H_ */
