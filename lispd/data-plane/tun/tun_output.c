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

#include "tun_output.h"
#include "tun.h"
#include "../../fwd_policies/fwd_policy.h"
#include "../../liblisp/liblisp.h"
#include "../../lib/packets.h"
#include "../../lib/sockets.h"
#include "../../control/lisp_control.h"
#include "../../lib/ttable.h"
#include "../../lib/lmlog.h"
#include "../../lib/sockets-util.h"


/* static buffer to receive packets */
static uint8_t pkt_recv_buf[TUN_RECEIVE_SIZE];
static lbuf_t pkt_buf;
ttable_t ttable;


static int tun_output_multicast(lbuf_t *b, packet_tuple_t *tuple);
static int tun_output_unicast(lbuf_t *b, packet_tuple_t *tuple);
static int tun_forward_native(lbuf_t *b, lisp_addr_t *dst);
static inline int is_lisp_packet(packet_tuple_t *tpl);

void
tun_output_init()
{
    ttable_init(&ttable);
}

void
tun_output_uninit()
{
    ttable_uninit(&ttable);
}

static int
tun_forward_native(lbuf_t *b, lisp_addr_t *dst)
{
    int ret, sock, afi;

    LMLOG(LDBG_3, "Forwarding native to destination %s",
            lisp_addr_to_char(dst));

    afi = lisp_addr_ip_afi(dst);
    sock = tun_get_default_output_socket(afi);

    if (sock == ERR_SOCKET) {
        LMLOG(LDBG_2, "tun_forward_native: No output interface for afi %d", afi);
        return (BAD);
    }

    ret = send_raw_packet(sock, lbuf_data(b), lbuf_size(b), lisp_addr_ip(dst));
    return (ret);
}


static inline int
is_lisp_packet(packet_tuple_t *tpl)
{
    /* Don't encapsulate LISP messages  */
    if (tpl->protocol != IPPROTO_UDP) {
        return (FALSE);
    }

    /* If either of the udp ports are the control port or data, allow
     * to go out natively. This is a quick way around the
     * route filter which rewrites the EID as the source address. */
    if (tpl->dst_port != LISP_CONTROL_PORT
        && tpl->src_port != LISP_CONTROL_PORT
        && tpl->src_port != LISP_DATA_PORT
        && tpl->dst_port != LISP_DATA_PORT) {
        return (FALSE);
    }

    return (TRUE);
}

static int
make_mcast_addr(packet_tuple_t *tuple, lisp_addr_t *addr){

    /* TODO this really needs optimization */

    uint16_t    plen;
    lcaf_addr_t *lcaf;

    if (ip_addr_is_multicast(lisp_addr_ip(&tuple->dst_addr))) {
        if (lisp_addr_lafi(&tuple->src_addr) != LM_AFI_IP
            || lisp_addr_lafi(&tuple->src_addr) != LM_AFI_IP) {
           LMLOG(LDBG_1, "tuple_get_dst_lisp_addr: (S,G) (%s, %s)pair is not "
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

static int
tun_output_multicast(lbuf_t *b, packet_tuple_t *tuple)
{
    glist_t *or_list = NULL;
    lisp_addr_t *src_rloc = NULL, *daddr = NULL, *dst_rloc = NULL;
    locator_t *locator = NULL;
    glist_entry_t *it = NULL;
    int *out_sock = NULL;

    LMLOG(LDBG_1, "Multicast packets not supported for now!");
    return(GOOD);

    /* convert tuple to lisp_addr_t, to be used for map-cache lookup
     * TODO: should be a tad more efficient  */
    daddr = lisp_addr_new();
    if (make_mcast_addr(tuple, daddr) != GOOD) {
        LMLOG(LWRN, "tun_output_multicast: Unable to determine "
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
        lisp_data_encap(b, LISP_DATA_PORT, LISP_DATA_PORT, src_rloc, dst_rloc);

        send_raw_packet(*out_sock, lbuf_data(b), lbuf_size(b),lisp_addr_ip(dst_rloc));
    }

    glist_destroy(or_list);

    return (GOOD);
}

static int
tun_output_unicast(lbuf_t *b, packet_tuple_t *tuple)
{
    fwd_info_t *fi;
    fwd_entry_t *fe;

    fi = ttable_lookup(&ttable, tuple);
    if (!fi) {
        fi = (fwd_info_t *)ctrl_get_forwarding_info(tuple);
        if (fi == NULL){
            return (BAD);
        }
        fe = fi->fwd_info;
        if (fe && fe->srloc && fe->drloc)  {
            fe->out_sock = get_out_socket_ptr_from_address(fe->srloc);
        }
        // XXX Should packets to be send natively be added to the table?
        ttable_insert(&ttable, pkt_tuple_clone(tuple), fi);
    }else{
        fe = fi->fwd_info;
    }

    /* Packets with no/negative map cache entry AND no PETR
     * OR packets with missing src or dst RLOCs
     * forward them natively */
    if (!fe || !fe->srloc || !fe->drloc) {
        return(tun_forward_native(b, &tuple->dst_addr));
    }

    LMLOG(LDBG_3,"OUTPUT: Sending encapsulated packet: RLOC %s -> %s\n",
            lisp_addr_to_char(fe->srloc),
            lisp_addr_to_char(fe->drloc));

    lisp_data_encap(b, LISP_DATA_PORT, LISP_DATA_PORT, fe->srloc, fe->drloc);

    return(send_raw_packet(*(fe->out_sock), lbuf_data(b), lbuf_size(b),
               lisp_addr_ip(fe->drloc)));

}

int
tun_output(lbuf_t *b)
{
    packet_tuple_t tpl;

    if (pkt_parse_5_tuple(b, &tpl) != GOOD) {
        return (BAD);
    }


    LMLOG(LDBG_3,"OUTPUT: Received EID %s -> %s, Proto: %d, Port: %d -> %d ",
            lisp_addr_to_char(&tpl.src_addr), lisp_addr_to_char(&tpl.dst_addr),
            tpl.protocol, tpl.src_port, tpl.dst_port);

    /* If already LISP packet, do not encapsulate again */
    if (is_lisp_packet(&tpl)) {
        LMLOG(LDBG_3,"OUTPUT: Is a lisp packet, do not encapsulate again");
        return (tun_forward_native(b, &tpl.dst_addr));
    }
    if (ip_addr_is_multicast(lisp_addr_ip(&tpl.dst_addr))) {
        tun_output_multicast(b, &tpl);
    } else {
        tun_output_unicast(b, &tpl);
    }

    return(GOOD);
}

int
tun_output_recv(sock_t *sl)
{
    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, TUN_RECEIVE_SIZE);
    lbuf_reserve(&pkt_buf, LBUF_STACK_OFFSET);

    if (sock_recv(sl->fd, &pkt_buf) != GOOD) {
        LMLOG(LWRN, "OUTPUT: Error while reading from tun!");
        return (BAD);
    }
    lbuf_reset_ip(&pkt_buf);
    tun_output(&pkt_buf);
    return (GOOD);
}
