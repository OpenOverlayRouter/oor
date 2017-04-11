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


#ifndef OOR_FWD_POLICIES_VPP_BALANCING_FWD_ENTRY_VPP_H_
#define OOR_FWD_POLICIES_VPP_BALANCING_FWD_ENTRY_VPP_H_

#include "../../liblisp/lisp_address.h"


typedef struct fwd_entry_vpp_ {
    lisp_addr_t *seid;
    lisp_addr_t *deid;
    glist_t *loc_pair_lst; //<vpp_loc_pair>
    uint32_t iid;
} fwd_entry_vpp_t;

typedef struct vpp_loc_pair_ {
    lisp_addr_t *srloc;
    lisp_addr_t *drloc;
    int weight;
} vpp_loct_pair;

fwd_entry_vpp_t *fwd_entry_vpp_new_init(lisp_addr_t *seid,lisp_addr_t *deid,int iid);
void fwd_entry_vpp_del(fwd_entry_vpp_t *fwd_entry);
vpp_loct_pair *vpp_loct_pair_new_init(lisp_addr_t *srloc,lisp_addr_t *drloc,int weight);
void vpp_loct_pair_del(vpp_loct_pair *loc_pair);
void fwd_entry_vpp_dump(fwd_entry_vpp_t *fwd_entry, int log_level);

#endif /* OOR_FWD_POLICIES_VPP_BALANCING_FWD_ENTRY_VPP_H_ */
