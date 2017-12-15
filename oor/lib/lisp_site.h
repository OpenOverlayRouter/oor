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

#ifndef LISP_SITE_H_
#define LISP_SITE_H_

#include "../liblisp/liblisp.h"
#include "timers.h"

typedef struct lisp_site_prefix {
    lisp_addr_t *eid_prefix;
    uint8_t proxy_reply;
    uint8_t accept_more_specifics;
    lisp_key_type_e key_type;
    char *key;
    uint8_t merge;
} lisp_site_prefix_t;

typedef struct lisp_reg_site {
    mapping_t *site_map;
    uint8_t proxy_reply;
} lisp_reg_site_t;

lisp_site_prefix_t *lisp_site_prefix_init(lisp_addr_t *eid_prefix, uint32_t iid,
        int key_type, char *key, uint8_t more_specifics, uint8_t proxy_reply,
        uint8_t merge);
void lisp_site_prefix_del(lisp_site_prefix_t *sp);
void lisp_reg_site_del(lisp_reg_site_t *rs);

static inline lisp_addr_t *
lsite_prefix(lisp_site_prefix_t *ls) {
    return(ls->eid_prefix);
}

#endif /* LISP_SITE_H_ */
