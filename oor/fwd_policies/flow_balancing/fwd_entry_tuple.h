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

#ifndef OOR_FWD_POLICIES_FLOW_BALANCING_FWD_ENTRY_TUPLE_H_
#define OOR_FWD_POLICIES_FLOW_BALANCING_FWD_ENTRY_TUPLE_H_

#include "../../lib/packets.h"
#include "../../liblisp/lisp_address.h"


typedef struct fwd_entry_tuple_ {
    packet_tuple_t *tuple; // Must be the first element
    lisp_addr_t *srloc;
    lisp_addr_t *drloc;
    int *out_sock;
    uint32_t iid;
} fwd_entry_tuple_t;

fwd_entry_tuple_t *fwd_entry_tuple_new_init(packet_tuple_t *tuple, lisp_addr_t *srloc,
        lisp_addr_t *drloc, uint32_t iid, int *out_socket);
void fwd_entry_tuple_del(fwd_entry_tuple_t *fwd_entry);

#endif /* OOR_FWD_POLICIES_FLOW_BALANCING_FWD_ENTRY_TUPLE_H_ */
