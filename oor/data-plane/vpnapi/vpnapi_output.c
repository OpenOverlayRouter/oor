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
#include <errno.h>

#include "vpnapi_output.h"
#include "vpnapi.h"
#include "../data-plane.h"
#include "../ttable.h"
#include "../encapsulations/vxlan-gpe.h"
#include "../../fwd_policies/fwd_policy.h"
#include "../../fwd_policies/flow_balancing/fwd_entry_tuple.h"
#include "../../liblisp/liblisp.h"
#include "../../lib/packets.h"
#include "../../lib/sockets.h"
#include "../../control/oor_control.h"
#include "../../lib/oor_log.h"
#include "../../lib/sockets-util.h"


/* static buffer to receive packets */
static uint8_t pkt_recv_buf[VPNAPI_RECEIVE_SIZE];
static lbuf_t pkt_buf;

static int vpnapi_output_unicast(lbuf_t *b, packet_tuple_t *tuple);
static int vpnapi_forward_native(lbuf_t *b, lisp_addr_t *dst);
void vpnapi_rm_dp_entry(packet_tuple_t *tuple);


static int
vpnapi_forward_native(lbuf_t *b, lisp_addr_t *dst)
{
    /* XXX Forward native not supported in VPNAPI */
    return (BAD);
}

static int
vpnapi_output_unicast(lbuf_t *b, packet_tuple_t *tuple)
{
    fwd_info_t *fi;
    fwd_entry_tuple_t *fe;
    glist_t *fwd_tuple_lst, *pxtr_fwd_tuple_list;
    vpnapi_data_t *dp_data;
    int dst_port;
    /* For xTR tuple->iid is 0 when received while for RTRs tuple->iid is the correct value */
    uint32_t iid = tuple->iid;

    dp_data =  vpnapi_get_datap_data();
    fi = ttable_lookup(&(dp_data->ttable), tuple);
    if (!fi) {
        fi = ctrl_get_forwarding_info(tuple);
        if (!fi){
            return (BAD);
        }
        fe = (fwd_entry_tuple_t *)fi->dp_conf_inf;
        if (!fe){
            return (BAD);
        }
        if (fe->srloc && fe->drloc)  {
            switch (lisp_addr_ip_afi(fe->srloc)){
            case AF_INET:
                fe->out_sock = &(dp_data->ipv4_data_socket);
                break;
            case AF_INET6:
                fe->out_sock = &(dp_data->ipv6_data_socket);
                break;
            default:
                OOR_LOG(LDBG_3,"OUTPUT: No output socket for afi %d", lisp_addr_ip_afi(fe->srloc));
                return(BAD);
            }
        }
        // While we can not get iid from interface (xTR), we insert the tupla with iid = 0.
        // For RTRs iid is initialized with the right value
        //   We only support a same EID prefix per xTR
        fe->tuple->iid = iid;
        // fe->tuple is cloned from tuple
        if (ttable_insert(&(dp_data->ttable), fe->tuple, fi) != GOOD){
            /* If table is full, reset the data plane */
            vpnapi_reset_all_fwd();
            ttable_insert(&(dp_data->ttable), fe->tuple, fi);
        }

        /* Associate eid with fwd_info.*/
        fwd_tuple_lst = (glist_t *)shash_lookup(dp_data->eid_to_dp_entries,lisp_addr_to_char(fi->associated_entry));
        if (!fwd_tuple_lst){
            fwd_tuple_lst = glist_new_managed((glist_del_fct)vpnapi_rm_dp_entry);
            shash_insert(dp_data->eid_to_dp_entries, strdup(lisp_addr_to_char(fi->associated_entry)), fwd_tuple_lst);
        }
        glist_add(fe->tuple,fwd_tuple_lst);
        OOR_LOG(LDBG_3, "vpnapi_output_unicast: The tupla [%s] has been associated with the EID %s",
                pkt_tuple_to_char(tuple),lisp_addr_to_char(fi->associated_entry));

        if(fi->neg_map_reply_act == ACT_NATIVE_FWD){ // Forwarding entry should be also associated with PeTRs list
            switch (lisp_addr_ip_afi(fi->associated_entry)){
            case AF_INET:
                pxtr_fwd_tuple_list = (glist_t *)shash_lookup(dp_data->eid_to_dp_entries,FULL_IPv4_ADDRESS_SPACE);
                if (unlikely(!pxtr_fwd_tuple_list)){
                    // The entries that are in the pxtr list has also an specific entry. For this reason the list is not managed
                    pxtr_fwd_tuple_list = glist_new();
                    shash_insert(dp_data->eid_to_dp_entries, strdup(FULL_IPv4_ADDRESS_SPACE), pxtr_fwd_tuple_list);
                }
                break;
            case AF_INET6:
                pxtr_fwd_tuple_list = (glist_t *)shash_lookup(dp_data->eid_to_dp_entries,FULL_IPv6_ADDRESS_SPACE);
                if (unlikely(!pxtr_fwd_tuple_list)){
                    // The entries that are in the pxtr list has also an specific entry. For this reason the list is not managed
                    pxtr_fwd_tuple_list = glist_new();
                    shash_insert(dp_data->eid_to_dp_entries, strdup(FULL_IPv6_ADDRESS_SPACE), pxtr_fwd_tuple_list);
                }
                break;
            default:
                OOR_LOG(LDBG_3, "vpnapi_output_unicast: Forwarding to PeTR is only for IP EIDs. It should never reach here");
                return (BAD);
            }
            glist_add(fe->tuple,pxtr_fwd_tuple_list);
            OOR_LOG(LDBG_3, "  and with PeTRs");
        }
    }else{
        fe = fi->dp_conf_inf;
    }

    /* Packets with no/negative map cache entry AND no PETR
     * OR packets with missing src or dst RLOCs*/
    if (!fe || !fe->srloc || !fe->drloc) {
        switch (fi->neg_map_reply_act){
        case ACT_NO_ACTION:
        case ACT_SEND_MREQ:
        case ACT_NATIVE_FWD:
        case ACT_DROP:
            OOR_LOG(LDBG_3,"OUTPUT: Packet with non lisp destination. No PeTRs compatibles to be used. Discarding packet");
            return (GOOD);
        }
    }

    OOR_LOG(LDBG_3,"OUTPUT: Sending encapsulated packet: RLOC %s -> %s\n",
            lisp_addr_to_char(fe->srloc),
            lisp_addr_to_char(fe->drloc));

    switch (fi->encap){
    case ENCP_LISP:
        lisp_data_push_hdr(b, fe->iid);
        dst_port = LISP_DATA_PORT;
        break;
    case ENCP_VXLAN_GPE:
        vxlan_gpe_data_push_hdr(b, fe->iid, vxlan_gpe_get_next_prot(&tuple->dst_addr));
        dst_port = VXLAN_GPE_DATA_PORT;
        break;
    }

    return(send_datagram_packet (*(fe->out_sock), lbuf_data(b), lbuf_size(b),
            fe->drloc, dst_port));
}

int
vpnapi_output(lbuf_t *b, packet_tuple_t *tpl)
{
    OOR_LOG(LDBG_3,"OUTPUT: Received EID %s -> %s, Proto: %d, Port: %d -> %d ",
            lisp_addr_to_char(&tpl->src_addr), lisp_addr_to_char(&tpl->dst_addr),
            tpl->protocol, tpl->src_port, tpl->dst_port);

    /* If already LISP packet, do not encapsulate again */
    if (pkt_tuple_is_lisp(tpl)) {
        OOR_LOG(LDBG_3,"OUTPUT: Is a lisp packet, do not encapsulate again");
        return (vpnapi_forward_native(b, &tpl->dst_addr));
    }

    vpnapi_output_unicast(b, tpl);

    return(GOOD);
}

int
vpnapi_output_recv(struct sock *sl)
{
    packet_tuple_t tpl;
    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, VPNAPI_RECEIVE_SIZE);
    lbuf_reserve(&pkt_buf, LBUF_STACK_OFFSET);

    if (sock_recv(sl->fd, &pkt_buf) != GOOD) {
        OOR_LOG(LWRN, "OUTPUT: Error while reading from tun!");
        return (BAD);
    }
    lbuf_reset_ip(&pkt_buf);

    if (pkt_parse_5_tuple(&pkt_buf, &tpl) != GOOD) {
        return (BAD);
    }
    /* XXX Since OOR doesn't support same local prefixes with different IIDs when
     * operating as a XTR or MN, we use IID = 0 to calculate the hash of the ttable.
     * The actual IID to be used on the encapsulation processed is already stored
     * in the forwarding entry, which is obtained on a ttable miss.*/
    tpl.iid = 0;
    vpnapi_output(&pkt_buf, &tpl);
    return (GOOD);
}

int
vpnapi_send_ctrl_msg(lbuf_t *buf, uconn_t *udp_conn)
{
    /* With VPNAI packets are send using his own interface */
    return (BAD);
}

void
vpnapi_rm_dp_entry(packet_tuple_t *tuple)
{
    vpnapi_data_t *data = vpnapi_get_datap_data();
    ttable_remove(&(data->ttable), tuple);
}
