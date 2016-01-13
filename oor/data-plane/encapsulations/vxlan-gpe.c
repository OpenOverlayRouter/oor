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

#include "vxlan-gpe.h"
#include "../../lib/oor_log.h"
#include "../../lib/packets.h"

void
vxlan_gpe_data_hdr_init(vxlan_gpe_hdr_t *vhdr, uint32_t vni, vxlan_gpe_nprot_t np)
{
    memset (vhdr,0,sizeof(vxlan_gpe_hdr_t));
    vhdr->vni_flag = 1;
    pkt_add_uint32_in_3bytes (vhdr->vni, vni);
    vhdr->next_prot_flag = 1;
    vhdr->next_proto = np;
}

void *
vxlan_gpe_data_push_hdr(lbuf_t *b, uint32_t vni, vxlan_gpe_nprot_t next_prot)
{
    vxlan_gpe_hdr_t *vhdr;
    vhdr = lbuf_push_uninit(b, sizeof(vxlan_gpe_hdr_t));
    vxlan_gpe_data_hdr_init(vhdr, vni, next_prot);
    return(vhdr);
}

void *
vxlan_gpe_data_encap(lbuf_t *b, int lp, int rp, lisp_addr_t *la, lisp_addr_t *ra,
        uint32_t vni)
{
    int ttl = 0, tos = 0;
    vxlan_gpe_nprot_t next_prot;

    /* read ttl and tos */
    ip_hdr_ttl_and_tos(lbuf_data(b), &ttl, &tos);

    switch (lisp_addr_ip_afi(la)){
    case AF_INET:
        next_prot = NP_IPv4;
        break;
    case AF_INET6:
        next_prot = NP_IPv6;
        break;
    default:
        OOR_LOG(LDBG_1, "vxlan_gpe_data_encap: Next protocol not supported");
        return (NULL);
    }

    /* push vxlan-gpe data hdr */
    vxlan_gpe_data_push_hdr(b, vni, next_prot);

    /* push outer UDP and IP */
    pkt_push_udp_and_ip(b, lp, rp, lisp_addr_ip(la), lisp_addr_ip(ra));

    ip_hdr_set_ttl_and_tos(lbuf_data(b), ttl, tos);

    return(lbuf_data(b));
}

void *
vxlan_gpe_data_pull_hdr(lbuf_t *b)
{
    void *dt = lbuf_pull(b, sizeof(vxlan_gpe_hdr_t));

    return(dt);
}

uint32_t
vxlan_gpe_hdr_get_vni(vxlan_gpe_hdr_t *hdr)
{
    return (pkt_get_uint32_from_3bytes(hdr->vni));
}



