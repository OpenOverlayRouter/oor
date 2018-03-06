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

#include "tun.h"
#include "tun_output.h"
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
static uint8_t pkt_recv_buf[TUN_RECEIVE_SIZE];
static lbuf_t pkt_buf;


static int tun_output_multicast(lbuf_t *b, packet_tuple_t *tuple);
static int tun_output_unicast(lbuf_t *b, packet_tuple_t *tuple);
static int tun_forward_native(lbuf_t *b, lisp_addr_t *dst);

static int
tun_forward_native(lbuf_t *b, lisp_addr_t *dst)
{
    int ret, sock, afi;

    OOR_LOG(LDBG_3, "Forwarding native to destination %s",
            lisp_addr_to_char(dst));

    afi = lisp_addr_ip_afi(dst);
    sock = tun_get_default_output_socket(afi);

    if (sock == ERR_SOCKET) {
        OOR_LOG(LDBG_2, "tun_forward_native: No output interface for afi %d", afi);
        return (BAD);
    }

    ret = send_raw_packet(sock, lbuf_data(b), lbuf_size(b), lisp_addr_ip(dst));
    return (ret);
}

static int
make_mcast_addr(packet_tuple_t *tuple, lisp_addr_t *addr){

    /* TODO this really needs optimization */

    uint16_t    plen;
    lcaf_addr_t *lcaf;

    if (ip_addr_is_multicast(lisp_addr_ip(&tuple->dst_addr))) {
        if (lisp_addr_lafi(&tuple->src_addr) != LM_AFI_IP
            || lisp_addr_lafi(&tuple->src_addr) != LM_AFI_IP) {
           OOR_LOG(LDBG_1, "tuple_get_dst_lisp_addr: (S,G) (%s, %s)pair is not "
                   "of IP syntax!", lisp_addr_to_char(&tuple->src_addr),
                   lisp_addr_to_char(&tuple->dst_addr));
           return(BAD);
        }

        lisp_addr_set_lafi(addr, LM_AFI_LCAF);
        plen = ip_afi_to_default_mask(lisp_addr_ip_afi(&tuple->dst_addr));
        lcaf = lisp_addr_get_lcaf(addr);
        lcaf_addr_set_mc(lcaf, &tuple->src_addr, &tuple->dst_addr, plen, plen,
                0);

    } else {
        lisp_addr_set_lafi(addr, LM_AFI_NO_ADDR);
    }

    return(GOOD);
}


void
tun_rm_dp_entry(packet_tuple_t *tuple)
{
    tun_dplane_data_t *data = tun_get_datap_data();
    ttable_remove(&(data->ttable), tuple);
}

static int
tun_output_multicast(lbuf_t *b, packet_tuple_t *tuple)
{
    glist_t *or_list = NULL;
    lisp_addr_t *src_rloc = NULL, *daddr = NULL, *dst_rloc = NULL;
    locator_t *locator = NULL;
    glist_entry_t *it = NULL;
    int *out_sock = NULL;

    OOR_LOG(LDBG_1, "Multicast packets not supported for now!");
    return(GOOD);

    /* convert tuple to lisp_addr_t, to be used for map-cache lookup
     * TODO: should be a tad more efficient  */
    daddr = lisp_addr_new();
    if (make_mcast_addr(tuple, daddr) != GOOD) {
        OOR_LOG(LWRN, "tun_output_multicast: Unable to determine "
                "destination address from tuple: src %s dst %s",
                lisp_addr_to_char(&tuple->src_addr),
                lisp_addr_to_char(&tuple->dst_addr));
        return(BAD);
    }

    /* get the output RLOC list */
    /* or_list = re_get_orlist(dst_eid); */
    if (!or_list) {
        return(BAD);
    }

    glist_for_each_entry(it, or_list)
    {
        /* TODO: take locator out, just send mcaddr and out socket */
        locator = (locator_t *) glist_entry_data(it);
        src_rloc = lcaf_mc_get_src(lisp_addr_get_lcaf(locator_addr(locator)));
        dst_rloc = lcaf_mc_get_grp(lisp_addr_get_lcaf(locator_addr(locator)));
        out_sock = get_out_socket_ptr_from_address(src_rloc);
        if (out_sock == NULL){
            return (BAD);
        }
        lisp_data_encap(b, LISP_DATA_PORT, LISP_DATA_PORT, src_rloc, dst_rloc, 0);

        send_raw_packet(*out_sock, lbuf_data(b), lbuf_size(b),lisp_addr_ip(dst_rloc));
    }

    glist_destroy(or_list);

    return (GOOD);
}

static int
tun_output_unicast(lbuf_t *b, packet_tuple_t *tuple)
{
    fwd_info_t *fi;
    fwd_entry_tuple_t *fe;
    glist_t *fwd_tuple_lst, *pxtr_fwd_tuple_list;
    tun_dplane_data_t *dp_data;
    /* For xTR tuple->iid is 0 when received while for RTRs tuple->iid is the correct value */
    uint32_t iid = tuple->iid;

    dp_data = tun_get_datap_data();

    fi = ttable_lookup(&(dp_data->ttable), tuple);
    if (!fi) {
        fi = (fwd_info_t *)ctrl_get_forwarding_info(tuple);
        if (!fi){
            return (BAD);
        }
        fe = (fwd_entry_tuple_t *)fi->dp_conf_inf;
        if (!fe){
            return (BAD);
        }
        if (fe->srloc && fe->drloc)  {
            fe->out_sock = get_out_socket_ptr_from_address(fe->srloc);
        }
        // While we can not get iid from interface (xTR), we insert the tupla with iid = 0.
        // For RTRs iid is initialized with the right value. Used to search in the table
        // We only support a same EID prefix per xTR
        fe->tuple->iid = iid;
        // fe->tuple is cloned from tuple
        if (ttable_insert(&(dp_data->ttable), fe->tuple, fi) != GOOD){
            /* If table is full, reset the data plane */
            tun_reset_all_fwd();
            ttable_insert(&(dp_data->ttable), fe->tuple, fi);
        }


        /* Associate eid with fwd_info */
        fwd_tuple_lst = (glist_t *)shash_lookup(dp_data->eid_to_dp_entries,lisp_addr_to_char(fi->associated_entry));
        if (!fwd_tuple_lst){
            fwd_tuple_lst = glist_new_managed((glist_del_fct)tun_rm_dp_entry);
            shash_insert(dp_data->eid_to_dp_entries, strdup(lisp_addr_to_char(fi->associated_entry)), fwd_tuple_lst);
        }
        glist_add(fe->tuple,fwd_tuple_lst);
        OOR_LOG(LDBG_3, "tun_output_unicast: The tupla [%s] has been associated with the EID %s",
                pkt_tuple_to_char(tuple),lisp_addr_to_char(fi->associated_entry));

        if(fi->neg_map_reply_act == ACT_NATIVE_FWD){ // Forwarding entry should be also associated with PeTRs list
            switch (lisp_addr_ip_afi(fi->associated_entry)){
            case AF_INET:
                pxtr_fwd_tuple_list = (glist_t *)shash_lookup(dp_data->eid_to_dp_entries,FULL_IPv4_ADDRESS_SPACE);
                break;
            case AF_INET6:
                pxtr_fwd_tuple_list = (glist_t *)shash_lookup(dp_data->eid_to_dp_entries,FULL_IPv6_ADDRESS_SPACE);
                break;
            default:
                OOR_LOG(LDBG_3, "tun_output_unicast: Forwarding to PeTR is only for IP EIDs. It should never reach here");
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
    if (!fe->srloc || !fe->drloc) {
        switch (fi->neg_map_reply_act){
        case ACT_NO_ACTION:
        case ACT_SEND_MREQ:
        case ACT_DROP:
            OOR_LOG(LDBG_3, "tun_output_unicast: Packet dropped");
            return (GOOD);
        case ACT_NATIVE_FWD:
            return(tun_forward_native(b, &tuple->dst_addr));
        }
    }

    OOR_LOG(LDBG_3,"OUTPUT: Sending encapsulated packet: RLOC %s -> %s\n",
            lisp_addr_to_char(fe->srloc),
            lisp_addr_to_char(fe->drloc));

    switch (fi->encap){
    case ENCP_LISP:
        lisp_data_encap(b, fe->src_port, fe->dst_port, fe->srloc, fe->drloc, fe->iid);
        break;
    case ENCP_VXLAN_GPE:
        vxlan_gpe_data_encap(b, VXLAN_GPE_DATA_PORT, VXLAN_GPE_DATA_PORT, fe->srloc, fe->drloc, fe->iid,
                             &tuple->dst_addr);
        break;
    }

    return(send_raw_packet(*(fe->out_sock), lbuf_data(b), lbuf_size(b),
               lisp_addr_ip(fe->drloc)));
}

int
tun_output(lbuf_t *b, packet_tuple_t *tpl)
{
    OOR_LOG(LDBG_3,"OUTPUT: Received EID %s -> %s, Proto: %d, Port: %d -> %d ",
            lisp_addr_to_char(&tpl->src_addr), lisp_addr_to_char(&tpl->dst_addr),
            tpl->protocol, tpl->src_port, tpl->dst_port);

    /* If already LISP packet, do not encapsulate again */
    if (pkt_tuple_is_lisp(tpl)) {
        OOR_LOG(LDBG_3,"OUTPUT: Is a lisp packet, do not encapsulate again");
        return (tun_forward_native(b, &tpl->dst_addr));
    }
    if (ip_addr_is_multicast(lisp_addr_ip(&tpl->dst_addr))) {
        tun_output_multicast(b, tpl);
    } else {
        tun_output_unicast(b, tpl);
    }
    return(GOOD);
}

int
tun_output_recv(sock_t *sl)
{
    packet_tuple_t tpl;

    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, TUN_RECEIVE_SIZE);
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
    tun_output(&pkt_buf, &tpl);
    return (GOOD);
}
