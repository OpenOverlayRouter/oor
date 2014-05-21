/*
 * lispd_input.c
 *
 * This file is part of LISP Mobile Node Implementation.
 *
 * Copyright (C) 2012 Cisco Systems, Inc, 2012. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Alberto Rodriguez Natal <arnatal@ac.upc.edu>
 */

#include <string.h>
#include <errno.h>

#include "lispd_input.h"
#include "lispd_tun.h"
#include "lispd_output.h"
#include "packets.h"
#include "util.h"
#include "liblisp.h"
#include "lmlog.h"

/* static buffer to receive packets */
static uint8_t pkt_recv_buf[MAX_IP_PKT_LEN+1];
static lbuf_t pkt_buf;

static char *
ip_src_and_dst_to_char(struct iphdr *iph, char *fmt)
{
    static char buf[150];
    struct ip6_hdr *ip6h;

    switch (iph->version) {
    case 4:
        sprintf(buf, fmt, ip_to_char(&iph->saddr, AF_INET),
                ip_to_char(&iph->daddr, AF_INET));
        break;
    case 6:
        ip6h = (struct ip6_hdr *)iph;
        sprintf(buf, fmt, ip_to_char(&ip6h->ip6_src, AF_INET6),
                ip_to_char(&ip6h->ip6_dst, AF_INET6));
        break;
    default:
        sprintf(buf, fmt, "NOT IP", "NOT IP");
    }

    return(buf);
}

int
read_and_decap_pkt(int sock, lbuf_t *b)
{
    uint8_t ttl = 0, tos = 0;
    lisphdr_t *lisp_hdr;
    struct udphdr *udph;

    if (sock_data_recv(sock, b, &ttl, &tos) != GOOD) {
        return(BAD);
    }

    /* DECAP UDP: IP header for IPv4 is pulled in sock_recv_data*/
    udph = pkt_pull_udp(b);

    /* FILTER UDP: with input RAW UDP sockets, we receive all UDP packets,
     * we only want LISP data ones */
    if (ntohs(udph->dest) != LISP_DATA_PORT) {
        return (ERR_NOT_LISP);
    }

    lisp_hdr = lisp_data_pull_hdr(b);

    /* RESET L3: prepare for output */
    lbuf_reset_l3(b);

    /* UPDATE IP TOS and TTL. Checksum is also updated for IPv4
     * NOTE: we always assume an IP payload*/
    ip_hdr_set_ttl_and_tos(lbuf_data(b), ttl, tos);

    LMLOG(DBG_3, "%s", ip_src_and_dst_to_char(lbuf_l3(b),
            "INPUT (4341): Inner IP: %s -> %s"));

    /* Poor discriminator for data map notify... */
    if (lisp_hdr->instance_id == 1){
        LMLOG(DBG_2,"Data-Map-Notify received\n ");
        /* XXX Is there something to do here? */
    }

    return(GOOD);
}

int
process_input_packet(sock_t *sl)
{
    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, MAX_IP_PKT_LEN);

    if (read_and_decap_pkt(sl->fd, &pkt_buf) != GOOD) {
        return (BAD);
    }

    if ((write(tun_receive_fd, lbuf_l3(&pkt_buf), lbuf_size(&pkt_buf))) < 0) {
        LMLOG(DBG_2, "lisp_input: write error: %s\n ", strerror(errno));
    }

    return (GOOD);
}

int rtr_process_input_packet(struct sock *sl)
{
    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, MAX_IP_PKT_LEN);

    if (read_and_decap_pkt(sl->fd, &pkt_buf) != GOOD) {
        return (BAD);
    }

    LMLOG(DBG_3, "INPUT (4341): Forwarding to OUPUT for re-encapsulation");
    lisp_output(&pkt_buf);

    return(GOOD);
}

