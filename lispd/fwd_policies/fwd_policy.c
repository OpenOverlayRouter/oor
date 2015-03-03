/*
 * routing_policy.c
 *
 *  Created on: 27/01/2015
 *      Author: albert
 */

#include "fwd_policy.h"
#include "../lib/lmlog.h"

static fwd_policy_class *fwd_policy_libs[1] = {
        &fwd_policy_flow_balancing,
};

fwd_policy_class *fwd_policy_class_find(char *lib)
{
	if (strcmp(lib,"flow_balancing") == 0){
		return(fwd_policy_libs[0]);
	}
	LMLOG(LERR, "The forward policy library \"%s\" has not been found",lib);
	return (NULL);
}


fwd_policy_dev_parm *fwd_policy_dev_parm_new()
{
	fwd_policy_dev_parm *pol_dev = xzalloc(sizeof(fwd_policy_dev_parm));
	pol_dev->paramiters = shash_new();
	return (pol_dev);
}

void fwd_policy_dev_parm_del(fwd_policy_dev_parm *pol_dev)
{

}

fwd_policy_map_parm *policy_map_parm_new(lisp_addr_t *eid_prefix)
{
    fwd_policy_map_parm *pol_map = xzalloc(sizeof(fwd_policy_map_parm));
	pol_map->eid_prefix = eid_prefix;
	pol_map->paramiters = shash_new();
	return (pol_map);
}

void policy_map_parm_del (fwd_policy_map_parm *pol_map)
{

}

fwd_policy_loct_parm *policy_loct_parm_new(lisp_addr_t *rloc_addr)
{
    fwd_policy_loct_parm *pol_loct = xzalloc(sizeof(fwd_policy_loct_parm));
	pol_loct->rloc_addr = rloc_addr;
	pol_loct->paramiters = shash_new();
	return (pol_loct);
}

void policy_loct_parm_del(fwd_policy_loct_parm *pol_loct)
{

}
