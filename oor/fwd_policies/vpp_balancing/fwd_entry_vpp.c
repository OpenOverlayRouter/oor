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

#include "fwd_entry_vpp.h"
#include "../../lib/oor_log.h"
#include "../../liblisp/lisp_address.h"

fwd_entry_vpp_t *
fwd_entry_vpp_new_init(lisp_addr_t *seid,lisp_addr_t *deid,int iid)
{
    fwd_entry_vpp_t * fwd_entry;

    fwd_entry = xzalloc(sizeof(fwd_entry_vpp_t));
    if (!fwd_entry){
        return (NULL);
    }
    fwd_entry->seid = lisp_addr_clone(seid);
    fwd_entry->deid = lisp_addr_clone(deid);
    fwd_entry->iid = iid;
    fwd_entry->loc_pair_lst = glist_new_managed((glist_del_fct)vpp_loct_pair_del);

    return (fwd_entry);
}

void
fwd_entry_vpp_del(fwd_entry_vpp_t *fwd_entry)
{
    if (!fwd_entry){
        return;
    }
    lisp_addr_del(fwd_entry->seid);
    lisp_addr_del(fwd_entry->deid);
    glist_destroy(fwd_entry->loc_pair_lst);
    free(fwd_entry);
    fwd_entry = NULL;
}

vpp_loct_pair *
vpp_loct_pair_new_init(lisp_addr_t *srloc,lisp_addr_t *drloc,int weight)
{
    vpp_loct_pair * loc_pair;
    loc_pair = xzalloc(sizeof(vpp_loct_pair));
    loc_pair->srloc = lisp_addr_clone(srloc);
    loc_pair->drloc = lisp_addr_clone(drloc);
    loc_pair->weight = weight;
    return (loc_pair);
}

void
vpp_loct_pair_del(vpp_loct_pair *loc_pair)
{
    lisp_addr_del(loc_pair->srloc);
    lisp_addr_del(loc_pair->drloc);
    free(loc_pair);
    loc_pair = NULL;
}

void
fwd_entry_vpp_dump(fwd_entry_vpp_t *fwd_entry, int log_level){
    vpp_loct_pair * loc_pair;
    glist_entry_t *it_pair;

    OOR_LOG(log_level, "VPP forward information for: %s -> %s (VNI: %d)",
            lisp_addr_to_char(fwd_entry->seid),lisp_addr_to_char(fwd_entry->deid),
            fwd_entry->iid);
    glist_for_each_entry(it_pair,fwd_entry->loc_pair_lst){
        loc_pair = (vpp_loct_pair *)glist_entry_data(it_pair);
        OOR_LOG(log_level, "\t\t%s -> %s  w:%d",lisp_addr_to_char(loc_pair->srloc),
                lisp_addr_to_char(loc_pair->drloc),loc_pair->weight);
    }
}

