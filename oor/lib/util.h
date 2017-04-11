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

#ifndef UTIL_H_
#define UTIL_H_

#include "../liblisp/liblisp.h"

typedef lisp_addr_t *  (*get_fwd_ip_addr)(lisp_addr_t *, glist_t *);

int convert_hex_string_to_bytes(char *hex, uint8_t *bytes, int bytes_len);

char *get_char_from_xTR_ID (lisp_xtr_id *xtrid);

/* Remove the address from the list not compatible with the local RLOCs */
void addr_list_rm_not_compatible_addr(glist_t *addr_lst, int compatible_addr_flags);
uint8_t is_compatible_addr(lisp_addr_t *addr, int compatible_addr_flags);
void str_rm_spaces(char *src, char *dst);
void str_rm_double_spaces(char *src, char *dst);
void locators_classify_in_4_6(mapping_t *mapping, glist_t *loc_loct_addr,
        glist_t *ipv4_loct_list, glist_t *ipv6_loct_list, get_fwd_ip_addr fn);


#endif /* UTIL_H_ */


