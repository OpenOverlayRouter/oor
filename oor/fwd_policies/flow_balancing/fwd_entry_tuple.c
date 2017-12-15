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

#include "fwd_entry_tuple.h"

inline fwd_entry_tuple_t *
fwd_entry_tuple_new_init(packet_tuple_t *tuple, lisp_addr_t *srloc,
        lisp_addr_t *drloc, uint16_t src_port, uint16_t dst_port,  uint32_t iid, int *out_socket)
{
    fwd_entry_tuple_t *fw_entry = xzalloc(sizeof(fwd_entry_tuple_t));
    if (!fw_entry){
        return (NULL);
    }
    fw_entry->tuple = pkt_tuple_clone(tuple);
    fw_entry->srloc = lisp_addr_clone(srloc);
    fw_entry->drloc = lisp_addr_clone(drloc);
    fw_entry->src_port = src_port;
    fw_entry->dst_port = dst_port;
    fw_entry->iid = iid;
    fw_entry->out_sock = out_socket;
    return (fw_entry);
}

inline void
fwd_entry_tuple_del(fwd_entry_tuple_t *fwd_entry)
{
    if (fwd_entry == NULL){
        return;
    }
    pkt_tuple_del(fwd_entry->tuple);
    lisp_addr_del(fwd_entry->srloc);
    lisp_addr_del(fwd_entry->drloc);
    free(fwd_entry);
    fwd_entry = NULL;
}
