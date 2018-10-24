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

#include "lisp_site.h"
#include "timers_utils.h"
#include "../defs.h"
#include "../oor_external.h"

lisp_site_prefix_t *
lisp_site_prefix_init(lisp_addr_t *eid, uint32_t iid, int key_type, char *key,
        uint8_t more_specifics, uint8_t proxy_reply, uint8_t merge)
{
    lisp_site_prefix_t *sp = NULL;
    int iidmlen;

    sp = xzalloc(sizeof(lisp_site_prefix_t));
    if (iid > 0){
        iidmlen = 32;
        sp->eid_prefix = lisp_addr_new_init_iid(iid, eid, iidmlen);
    }else{
        sp->eid_prefix = lisp_addr_clone(eid);
    }
    sp->key_type = key_type;
    sp->key = strdup(key);
    sp->accept_more_specifics = more_specifics;
    sp->proxy_reply = proxy_reply;
    sp->merge = merge;
    sp->ddt_ms_peers_complete = TRUE;
    sp->ddt_ms_peers = glist_new_managed((glist_del_fct)lisp_addr_del);

    return(sp);
}

void
lisp_site_prefix_add_ms_peer (lisp_site_prefix_t * sp, lisp_addr_t *peer_addr)
{
	glist_add(lisp_addr_clone(peer_addr),sp->ddt_ms_peers);
}

void
lisp_site_prefix_del(lisp_site_prefix_t *sp)
{
    if (!sp)
        return;
    lisp_addr_del(sp->eid_prefix);
    if (sp->key)
        free(sp->key);
    glist_destroy(sp->ddt_ms_peers);
    free(sp);
}

void
lisp_reg_site_del(lisp_reg_site_t *rs)
{
    stop_timers_from_obj(rs,ptrs_to_timers_ht,nonces_ht);
    mapping_del(rs->site_map);
    free(rs);
}
