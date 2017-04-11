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

#ifndef OOR_NET_MGR_NET_MGR_PROC_FC_H_
#define OOR_NET_MGR_NET_MGR_PROC_FC_H_

#include "../iface_list.h"


/* Change the address of the interface. If the address belongs to a not
 * initialized locator, activate it. Program SMR */
void nm_process_address_change(uint8_t act, uint32_t iface_index, lisp_addr_t *new_addr);
void nm_process_link_change(uint32_t old_iface_index, uint32_t new_iface_index,
        uint8_t new_status);
void nm_process_route_change(uint8_t act, uint32_t iface_index, lisp_addr_t *src,
        lisp_addr_t *dst, lisp_addr_t *gateway);
#endif /* OOR_NET_MGR_NET_MGR_PROC_FC_H_ */
