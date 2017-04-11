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
#ifndef VPP_H_
#define VPP_H_

#include "../../lib/shash.h"

#define TAP_VPP_MISS_IFACE_NAME      "oorDtap0"
#define TAP_MTU_VPP             1440
#define TAP_VPP_BUFFER_SIZE     2048


typedef struct vpp_dplane_data_{
    /* < char *eid -> glist_t <fwd_info_t *>> Used to find the fwd entries to be removed
     * of the data plane when there is a change with the mapping of the eid */
    shash_t *eid_to_dp_entries; //< char *eid -> glist_t <fwd_info_t *>>
    shash_t *iid_lst; //< char *iid , glist of eids>
}vpp_dplane_data_t;

#endif /* VPP_H_ */
