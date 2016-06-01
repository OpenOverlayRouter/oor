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

#include "fwd_policy.h"
#include "../lib/oor_log.h"

static fwd_policy_class *fwd_policy_libs[1] = {
        &fwd_policy_flow_balancing,
};

void policy_loct_parm_del(fwd_policy_loct_parm *pol_loct);

fwd_policy_class *
fwd_policy_class_find(char *lib)
{
	if (strcmp(lib,"flow_balancing") == 0){
		return(fwd_policy_libs[0]);
	}
	OOR_LOG(LERR, "The forward policy library \"%s\" has not been found",lib);
	return (NULL);
}


fwd_policy_dev_parm *
fwd_policy_dev_parm_new()
{
	fwd_policy_dev_parm *pol_dev = xzalloc(sizeof(fwd_policy_dev_parm));
	pol_dev->paramiters = shash_new_managed((free_value_fn_t)free);
	return (pol_dev);
}

void
fwd_policy_dev_parm_del(fwd_policy_dev_parm *pol_dev)
{
    shash_destroy(pol_dev->paramiters);
    free (pol_dev);
}

fwd_policy_map_parm *
policy_map_parm_new(lisp_addr_t *eid_prefix)
{
    fwd_policy_map_parm *pol_map = xzalloc(sizeof(fwd_policy_map_parm));
	pol_map->eid_prefix = lisp_addr_clone(eid_prefix);
	pol_map->paramiters = shash_new();
	pol_map->locators = glist_new_managed((glist_del_fct)policy_loct_parm_del);

	return (pol_map);
}

void
policy_map_parm_del (fwd_policy_map_parm *pol_map)
{
    lisp_addr_del(pol_map->eid_prefix);
    shash_destroy(pol_map->paramiters);
    glist_destroy(pol_map->locators);
    free(pol_map);
}

fwd_policy_loct_parm *
policy_loct_parm_new(lisp_addr_t *rloc_addr)
{
    fwd_policy_loct_parm *pol_loct = xzalloc(sizeof(fwd_policy_loct_parm));
	pol_loct->rloc_addr = lisp_addr_clone(rloc_addr);
	pol_loct->paramiters = shash_new();
	return (pol_loct);
}

void
policy_loct_parm_del(fwd_policy_loct_parm *pol_loct)
{
    lisp_addr_del(pol_loct->rloc_addr);
    shash_destroy(pol_loct->paramiters);
    free(pol_loct);
}


fwd_info_t *
fwd_info_new()
{
    return (xzalloc(sizeof(fwd_info_t)));
}

void
fwd_info_del(fwd_info_t * fwd_info,fwd_info_data_del del_fn)
{
    del_fn(fwd_info->fwd_info);
    free(fwd_info);
}
