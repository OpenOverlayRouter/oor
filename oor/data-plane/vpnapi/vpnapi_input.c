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


#include "vpnapi.h"
#include "vpnapi_input.h"
#include "vpnapi_output.h"
#include "../data-plane.h"
#include "../encapsulations/vxlan-gpe.h"
#include "../../lib/packets.h"
#include "../../lib/mem_util.h"
#include "../../liblisp/liblisp.h"
#include "../../lib/oor_log.h"

/* static buffer to receive packets */
static uint8_t pkt_recv_buf[MAX_IP_PKT_LEN+1];
static lbuf_t pkt_buf;


int
vpnapi_read_and_decap_pkt(int sock, lbuf_t *b, uint32_t *iid)
{
    uint8_t ttl = 0, tos = 0;
    int afi, port;
    lisp_data_hdr_t *lisp_hdr;
    vxlan_gpe_hdr_t *vxlan_hdr;
    vpnapi_data_t *data;

    data = (vpnapi_data_t *)dplane_vpnapi.datap_data;

    if (sock_data_recv(sock, b, &afi, &ttl, &tos) != GOOD) {
        return(BAD);
    }
    if (lbuf_size(b) < 8){ // 8-> At least LISP header size
        return (ERR_NOT_ENCAP);
    }

    switch (data->encap_type){
    case ENCP_LISP:
        lisp_hdr = lisp_data_pull_hdr(b);
        if (LDHDR_LSB_BIT(lisp_hdr)){
            *iid = lisp_data_hdr_get_iid(lisp_hdr);
        }else{
            *iid = 0;
        }

        port = LISP_DATA_PORT;
        break;
    case ENCP_VXLAN_GPE:

        vxlan_hdr = vxlan_gpe_data_pull_hdr(b);
        if (VXLAN_HDR_VNI_BIT(vxlan_hdr)){
            *iid = vxlan_gpe_hdr_get_vni(vxlan_hdr);
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
vpnapi_process_input_packet(sock_t *sl)
{
    uint32_t iid;
    vpnapi_data_t *data;

    data = (vpnapi_data_t *)dplane_vpnapi.datap_data;
    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, MAX_IP_PKT_LEN);

    if (vpnapi_read_and_decap_pkt(sl->fd, &pkt_buf, &iid) != GOOD) {
        return (BAD);
    }
    /* XXX Destination packet should be checked it belongs to this xTR */
    if ((write(data->tun_socket, lbuf_l3(&pkt_buf), lbuf_size(&pkt_buf))) < 0) {
        OOR_LOG(LDBG_2, "lisp_input: write error: %s\n ", strerror(errno));
    }

    return (GOOD);
}

int
vpnapi_rtr_process_input_packet(sock_t *sl)
{
    packet_tuple_t tpl;

    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, MAX_IP_PKT_LEN);
    /* Reserve space in case the received packet was IPv6. In this case the IPv6 header is
     * not provided */
    lbuf_reserve(&pkt_buf,LBUF_STACK_OFFSET);

    if (vpnapi_read_and_decap_pkt(sl->fd, &pkt_buf, &(tpl.iid)) != GOOD) {
        return (BAD);
    }

    OOR_LOG(LDBG_3, "Forwarding packet to OUPUT for re-encapsulation");

    lbuf_point_to_l3(&pkt_buf);
    lbuf_reset_ip(&pkt_buf);

    if (pkt_parse_5_tuple(&pkt_buf, &tpl) != GOOD) {
        return (BAD);
    }

    vpnapi_output(&pkt_buf, &tpl);

    return(GOOD);
}
