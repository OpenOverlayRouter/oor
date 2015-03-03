/*
 * routing_policy.h
 *
 *  Created on: 27/01/2015
 *      Author: albert
 */

#ifndef ROUTING_POLICY_H_
#define ROUTING_POLICY_H_

#include "../lib/generic_list.h"
#include "../lib/shash.h"
#include "../liblisp/liblisp.h"

typedef lisp_addr_t *(*get_fwd_ip_addr_fct)(void *, glist_t *);

typedef struct fwd_policy_dev_parm_t{
	shash_t 		*paramiters;
} fwd_policy_dev_parm;

typedef struct fwd_policy_map_parm_t{
	lisp_addr_t     *eid_prefix;
	shash_t 		*paramiters;
	glist_t			*locators;
} fwd_policy_map_parm;

typedef struct fwd_policy_loct_parm_t{
	lisp_addr_t     *rloc_addr;
	shash_t 		*paramiters;
} fwd_policy_loct_parm;


/* functions to manipulate routing */
typedef struct fwd_policy_class {
    void *(*new_dev_policy_inf)(lisp_ctrl_dev_t *ctrl_dev, fwd_policy_dev_parm *dev_parm);
    void (*del_dev_policy_inf)(void *);
    void *(*new_map_loc_policy_inf)(void *dev_parm, mapping_t *map, fwd_policy_map_parm *map_parm);
    void (*del_map_loc_policy_inf)(void *);
    void *(*new_map_cache_policy_inf)(void *dev_parm, mapping_t *map);
    void (*del_map_cache_policy_inf)(void *);
    int (*updated_map_loc_inf)(void *dev_parm, void *map_parm, mapping_t *map);
    int (*updated_map_cache_inf)(void *dev_parm, void *map_parm, mapping_t *map);
    fwd_entry_t *(*policy_get_fwd_entry)(void *dev_parm, void *src_map_parm, void *dst_map_parm, packet_tuple_t *tuple);
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

#endif /* ROUTING_POLICY_H_ */
