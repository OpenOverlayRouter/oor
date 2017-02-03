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

#ifndef PREFIXES_H_
#define PREFIXES_H_

#include "../liblisp/lisp_address.h"

int pref_is_addr_part_of_prefix(lisp_addr_t *addr, lisp_addr_t *pref);

/*
 * If prefix b is contained in prefix a, then return TRUE. Otherwise return FALSE.
 * If both prefixs are the same it also returns TRUE
 */
int pref_is_prefix_b_part_of_a (lisp_addr_t *a_prefix,lisp_addr_t *b_prefix);

lisp_addr_t *pref_get_network_address(lisp_addr_t *address);

/*
 * pref_get_network_prefix returns a prefix address from an IP prefix.
 * For instance:  10.0.1.1/8 -> 10.0.0.0/8
 */
lisp_addr_t * pref_get_network_prefix(lisp_addr_t *address);

int pref_conv_to_netw_pref(lisp_addr_t *addr);



#endif /* PREFIXES_H_ */
