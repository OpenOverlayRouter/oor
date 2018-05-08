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

#include <string.h>
#include <errno.h>

#include "tun.h"
#include "tun_input.h"
#include "tun_output.h"
#include "../../lib/packets.h"
#include "../../lib/mem_util.h"
#include "../../liblisp/liblisp.h"
#include "../../lib/oor_log.h"

/* static buffer to receive packets */
static uint8_t pkt_recv_buf[MAX_IP_PKT_LEN+1];
static lbuf_t pkt_buf;

int
tun_read_and_decap_pkt(int sock, lbuf_t *b, uint32_t *iid)
{
    uint8_t ttl = 0, tos = 0;
    int afi;
    struct udphdr *udph;
    lisp_data_hdr_t *lisph;
    vxlan_gpe_hdr_t *vxlanh;
    int port;

    if (sock_data_recv(sock, b, &afi, &ttl, &tos) != GOOD) {
        return(BAD);
    }

    if (afi == AF_INET){
        /* With input RAW UDP sockets in IPv4, we get the whole external
         * IPv4 packet */
        lbuf_reset_ip(b);
        pkt_pull_ip(b);
        lbuf_reset_udp(b);
    }else{
        /* With input RAW UDP sockets in IPv6, we get the whole external
         * UDP packet */
        lbuf_reset_udp(b);
    }

    udph = pkt_pull_udp(b);
    if (ntohs(udplen(udph)) < 16){//8 udp header + 8 lisp header
        return (ERR_NOT_ENCAP);
    }

    /* FILTER UDP: with input RAW UDP sockets, we receive all UDP packets,
     * we only want LISP data ones */
    switch (ntohs(udpdport(udph))){
    case LISP_DATA_PORT:
        lisph = lisp_data_pull_hdr(b);
        if (LDHDR_LSB_BIT(lisph)){
            *iid = lisp_data_hdr_get_iid(lisph);
        }else{
            *iid = 0;
        }

        port = LISP_DATA_PORT;
        break;
    case VXLAN_GPE_DATA_PORT:

        vxlanh = vxlan_gpe_data_pull_hdr(b);
        if (VXLAN_HDR_VNI_BIT(vxlanh)){
            *iid = vxlan_gpe_hdr_get_vni(vxlanh);
        }
        port = VXLAN_GPE_DATA_PORT;
        break;
    default:
        return (ERR_NOT_ENCAP);
    }

    /* RESET L3: prepare for output */
    lbuf_reset_l3(b);

    /* UPDATE IP TOS and TTL. Checksum is also updated for IPv4
     * NOTE: we always assume an IP payload*/
    ip_hdr_set_ttl_and_tos(lbuf_data(b), ttl, tos);

    OOR_LOG(LDBG_3, "INPUT (%d): %s",port, ip_src_and_dst_to_char(lbuf_l3(b),
            "Inner IP: %s -> %s"));

    return(GOOD);
}

int
tun_process_input_packet(sock_t *sl)
{
    uint32_t iid;
    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, MAX_IP_PKT_LEN);

    if (tun_read_and_decap_pkt(sl->fd, &pkt_buf, &iid) != GOOD) {
        return (BAD);
    }

    /* XXX Destination packet should be checked it belongs to this xTR */
    if ((write(tun_receive_fd, lbuf_l3(&pkt_buf), lbuf_size(&pkt_buf))) < 0) {
        OOR_LOG(LDBG_2, "lisp_input: write error: %s\n ", strerror(errno));
    }

    return (GOOD);
}

int
tun_rtr_process_input_packet(struct sock *sl)
{
    packet_tuple_t tpl;
    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, MAX_IP_PKT_LEN);
    /* Reserve space in case the received packet was IPv6. In this case the IPv6 header is
     * not provided */
    lbuf_reserve(&pkt_buf,LBUF_STACK_OFFSET);

    if (tun_read_and_decap_pkt(sl->fd, &pkt_buf, &(tpl.iid)) != GOOD) {
        return (BAD);
    }

    OOR_LOG(LDBG_3, "Forwarding packet to OUPUT for re-encapsulation");

    lbuf_point_to_l3(&pkt_buf);
    lbuf_reset_ip(&pkt_buf);

    if (pkt_parse_5_tuple(&pkt_buf, &tpl) != GOOD) {
        return (BAD);
    }
    tun_output(&pkt_buf, &tpl);

    return(GOOD);
}

