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

#ifndef TTABLE_H_
#define TTABLE_H_

#include <time.h>
#include "../elibs/khash/khash.h"
#include "../elibs/ovs/list.h"
#include "../lib/packets.h"

typedef struct fwd_info_ fwd_info_t;


KHASH_INIT(ttable, packet_tuple_t *, fwd_info_t *, 1, pkt_tuple_hash, pkt_tuple_cmp)

typedef struct ttable {
    khash_t(ttable) *htable; //<packet_tuple_t *, fwd_info_t *>
    struct ovs_list head_list; /* To order flows */
} ttable_t;

void ttable_init(ttable_t *tt);
void ttable_uninit(ttable_t *tt);
ttable_t *ttable_create();
void ttable_destroy(ttable_t *tt);
int ttable_insert(ttable_t *, packet_tuple_t *tpl, fwd_info_t *fe);
void ttable_remove(ttable_t *tt, packet_tuple_t *tpl);
fwd_info_t *ttable_lookup(ttable_t *tt, packet_tuple_t *tpl);


#endif /* TTABLE_H_ */
