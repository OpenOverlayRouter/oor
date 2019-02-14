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

#include "ttable.h"
#include "../lib/mem_util.h"
#include "../lib/packets.h"
#include "../lib/oor_log.h"
#include "../lib/sockets.h"
#include "../fwd_policies/fwd_policy.h"
#include "../liblisp/liblisp.h"


/* Maximum size of the tuple table */
#define MAX_SIZE 10000

void ttable_remove_with_khiter(ttable_t *tt, khiter_t k);


void
ttable_init(ttable_t *tt)
{
    tt->htable =  kh_init(ttable);
    list_init(&tt->head_list);
}

void
ttable_uninit(ttable_t *tt)
{
    khiter_t k;
    fwd_info_t *fi;

    for (k = kh_begin(tt->htable); k != kh_end(tt->htable); ++k){
        if (kh_exist(tt->htable, k)){
            // The key is remove when removing value
            fi = kh_value(tt->htable,k);
            fwd_info_del(fi);
        }
    }
    kh_destroy(ttable, tt->htable);
}

ttable_t *
ttable_create()
{
   ttable_t *tt = xzalloc(sizeof(ttable_t));
   ttable_init(tt);
   return(tt);
}

void
ttable_destroy(ttable_t *tt)
{
    ttable_uninit(tt);
    free(tt);
}


int
ttable_insert(ttable_t *tt, packet_tuple_t *tpl, fwd_info_t *fi)
{
    khiter_t k;
    int ret;

    /* If table is full remove old entries */
    if (kh_size(tt->htable) >= MAX_SIZE) {
        OOR_LOG(LDBG_1,"ttable_insert: Max size of forwarding table reached.");
        return (BAD);
    }

    k = kh_put(ttable,tt->htable,tpl,&ret);
    kh_value(tt->htable, k) = fi;
    OOR_LOG(LDBG_3,"ttable_insert: Inserted tupla: %s ", pkt_tuple_to_char(tpl));
    return (GOOD);
}

void
ttable_remove(ttable_t *tt, packet_tuple_t *tpl)
{
    khiter_t k;
    fwd_info_t *fi;

    k = kh_get(ttable,tt->htable, tpl);
    if (k == kh_end(tt->htable)){
        return;
    }

    fi = kh_value(tt->htable,k);
    OOR_LOG(LDBG_3,"ttable_remove: Remove tupla: %s ", pkt_tuple_to_char(tpl));
    // We don't remove the key (tuple). It is part of the fwd_info_t;
    /* Free value */
    fwd_info_del(fi);
    /* Remove entry from hash table */
    kh_del(ttable,tt->htable,k);
}

void
ttable_remove_with_khiter(ttable_t *tt, khiter_t k)
{
    fwd_info_t *fi;

    fi = kh_value(tt->htable,k);
    OOR_LOG(LDBG_3,"ttable_remove_with_khiter: Remove tupla: %s ", pkt_tuple_to_char((packet_tuple_t *)fi->dp_conf_inf));
    fwd_info_del(fi);
    kh_del(ttable,tt->htable,k);
}

fwd_info_t *
ttable_lookup(ttable_t *tt, packet_tuple_t *tpl)
{
    fwd_info_t *fi;
    khiter_t k;

    k = kh_get(ttable,tt->htable, tpl);
    if (k == kh_end(tt->htable)){
        return (NULL);
    }
    fi = kh_value(tt->htable,k);

    return (fi);
}
