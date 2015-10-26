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
#include "../../liblisp/liblisp.h"
#include "../../lib/packets.h"
#include "../../lib/sockets.h"
#include "../../control/lisp_control.h"
#include "../../lib/ttable.h"
#include "../../lib/lmlog.h"
#include "../../lib/sockets-util.h"


/* static buffer to receive packets */
static uint8_t pkt_recv_buf[VPNAPI_RECEIVE_SIZE];
static lbuf_t pkt_buf;
ttable_t ttable;

static int vpnapi_output_unicast(lbuf_t *b, packet_tuple_t *tuple);
static int vpnapi_forward_native(lbuf_t *b, lisp_addr_t *dst);

void
vpnapi_output_init()
{
    ttable_init(&ttable);
}

void
vpnapi_output_uninit()
{
    ttable_uninit(&ttable);
}

static int
vpnapi_forward_native(lbuf_t *b, lisp_addr_t *dst)
{
    /* XXX Forward native not supported in VPNAPI */
    return (BAD);
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
vpnapi_output_unicast(lbuf_t *b, packet_tuple_t *tuple)
{
    fwd_entry_t *fe;

    fe = ttable_lookup(&ttable, tuple);
    if (!fe) {
        fe = ctrl_get_forwarding_entry(tuple);
        if (fe && (fe->srloc && fe->drloc))  {
            switch (lisp_addr_ip_afi(fe->srloc)){
            case AF_INET:
                fe->out_sock = &(((vpnapi_data_t *)dplane_vpnapi.datap_data)->ipv4_data_socket);
                break;
            case AF_INET6:
                fe->out_sock = &(((vpnapi_data_t *)dplane_vpnapi.datap_data)->ipv6_data_socket);
                break;
            default:
                LMLOG(LDBG_3,"OUTPUT: No output socket for afi %d", lisp_addr_ip_afi(fe->srloc));
                return(BAD);
            }
        }

        ttable_insert(&ttable, pkt_tuple_clone(tuple), fe);
    }

    /* Packets with no/negative map cache entry AND no PETR
     * OR packets with missing src or dst RLOCs
     * forward them natively */
    if (!fe || (!fe->srloc || !fe->drloc)) {
        LMLOG(LDBG_3,"OUTPUT: Packet with non lisp destination. No PeTRs compatibles to be used. Discarding packet");
        return(BAD);
    }

    LMLOG(LDBG_3,"OUTPUT: Sending encapsulated packet: RLOC %s -> %s\n",
            lisp_addr_to_char(fe->srloc),
            lisp_addr_to_char(fe->drloc));

    /* push lisp data hdr */
    lisp_data_push_hdr(b);

    return(send_datagram_packet (*(fe->out_sock), lbuf_data(b), lbuf_size(b),
            fe->drloc, LISP_DATA_PORT));
}

int
vpnapi_output(lbuf_t *b)
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
        return (vpnapi_forward_native(b, &tpl.dst_addr));
    }

    vpnapi_output_unicast(b, &tpl);

    return(GOOD);
}

int
vpnapi_output_recv(struct sock *sl)
{
    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, VPNAPI_RECEIVE_SIZE);
    lbuf_reserve(&pkt_buf, LBUF_STACK_OFFSET);

    if (sock_recv(sl->fd, &pkt_buf) != GOOD) {
        LMLOG(LWRN, "OUTPUT: Error while reading from tun!");
        return (BAD);
    }
    lbuf_reset_ip(&pkt_buf);
    vpnapi_output(&pkt_buf);
    return (GOOD);
}

int
vpnapi_send_ctrl_msg(lbuf_t *buf, uconn_t *udp_conn)
{
    /* With VPNAI packets are send using his own interface */
    return (BAD);
}
