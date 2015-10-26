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
#include "../../lib/packets.h"
#include "../../lib/util.h"
#include "../../liblisp/liblisp.h"
#include "../../lib/lmlog.h"

/* static buffer to receive packets */
static uint8_t pkt_recv_buf[MAX_IP_PKT_LEN+1];
static lbuf_t pkt_buf;


int
vpnapi_read_and_decap_pkt(int sock, lbuf_t *b)
{
    uint8_t ttl = 0, tos = 0;
    int afi;
    lisphdr_t *lisp_hdr;

    if (sock_data_recv(sock, b, &afi, &ttl, &tos) != GOOD) {
        return(BAD);
    }

    lisp_hdr = lisp_data_pull_hdr(b);

    /* RESET L3: prepare for output */
    lbuf_reset_l3(b);

    /* UPDATE IP TOS and TTL. Checksum is also updated for IPv4
     * NOTE: we always assume an IP payload*/
    ip_hdr_set_ttl_and_tos(lbuf_data(b), ttl, tos);

    LMLOG(LDBG_3, "%s", ip_src_and_dst_to_char(lbuf_l3(b),
            "INPUT (4341): Inner IP: %s -> %s"));

    /* Poor discriminator for data map notify... */
    if (lisp_hdr->instance_id == 1){
        LMLOG(LDBG_2,"Data-Map-Notify received\n ");
        /* XXX Is there something to do here? */
    }

    return(GOOD);
}

int
vpnapi_process_input_packet(sock_t *sl)
{
    vpnapi_data_t *data;

    data = (vpnapi_data_t *)dplane_vpnapi.datap_data;
    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, MAX_IP_PKT_LEN);

    if (vpnapi_read_and_decap_pkt(sl->fd, &pkt_buf) != GOOD) {
        return (BAD);
    }

    if ((write(data->tun_socket, lbuf_l3(&pkt_buf), lbuf_size(&pkt_buf))) < 0) {
        LMLOG(LDBG_2, "lisp_input: write error: %s\n ", strerror(errno));
    }

    return (GOOD);
}

int
vpnapi_rtr_process_input_packet(sock_t *sl)
{
    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, MAX_IP_PKT_LEN);
    /* Reserve space in case the received packet was IPv6. In this case the IPv6 header is
     * not provided */
    lbuf_reserve(&pkt_buf,LBUF_STACK_OFFSET);

    if (vpnapi_read_and_decap_pkt(sl->fd, &pkt_buf) != GOOD) {
        return (BAD);
    }

    LMLOG(LDBG_3, "INPUT (4341): Forwarding to OUPUT for re-encapsulation");

    lbuf_point_to_l3(&pkt_buf);
    lbuf_reset_ip(&pkt_buf);
    vpnapi_output(&pkt_buf);

    return(GOOD);
}

