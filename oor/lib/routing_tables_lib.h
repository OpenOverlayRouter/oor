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

#ifndef ROUTING_TABLES_LIB_H_
#define ROUTING_TABLES_LIB_H_

#include "../defs.h"
#include "../liblisp/lisp_address.h"

#define RULE_IFACE_BASE_TABLE_PRIORITY 10
#define RULE_AVOID_LISP_TABLE_PRIORITY 99
#define RULE_TO_LISP_TABLE_PRIORITY 100

/*
 * This function adds a specific ip rule to
 * kernel's rule list
 */
int add_rule(int afi, int if_index, uint8_t table, uint32_t priority, uint8_t type,
        lisp_addr_t *src_pref, lisp_addr_t *dst_pref, int flags);

/*
 * This function deletes a specific ip rule to
 * kernel's rule list
 */
int del_rule(int afi, int if_index, uint8_t table, uint32_t priority, uint8_t type,
        lisp_addr_t *src_pref, lisp_addr_t *dst_pref, int flags);

/*
 * Creates a routing entry in the specified table
 * ifindex:     Output interface
 * dest:        Destination address
 * gw:          Gateway
 * prefix_len:  Destination address mask (/n)
 * metric:      Route metric
 * table:       Routing table. 0 = main table
 */

int add_route(int afi, uint32_t ifindex, lisp_addr_t *dest_pref, lisp_addr_t *src,
        lisp_addr_t *gw, uint32_t metric, uint32_t table);

/*
 * Deletes a routing entry in the specified table
 * ifindex:     Output interface
 * dest:        Destination address
 * gw:          Gateway
 * prefix_len:  Destination address mask (/n)
 * metric:      Route metric
 * table:       Routing table. 0 = main table
 */

int del_route(int  afi, uint32_t ifindex, lisp_addr_t *dest_pref, lisp_addr_t *src,
        lisp_addr_t *gw, uint32_t metric, uint32_t table);

#endif /* ROUTING_TABLES_LIB_H_ */
