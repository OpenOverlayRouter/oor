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
#include "lmlog.h"

/* static buffer to receive packets */
static uint8_t pkt_recv_buf[MAX_IP_PKT_LEN+1];
static lbuf_t pkt_buf;

int
read_and_decap_pkt(int sock, lbuf_t *b)
{
    uint8_t ttl = 0, tos = 0;
    lisphdr_t *lisp_hdr;
    struct udphdr *udph;

    if (sock_recv_data_packet(sock, b, &ttl, &tos) != GOOD) {
        return(BAD);
    }

    udph = pkt_pull_udp(b);

    /* With input RAW UDP sockets, we receive all UDP packets,
     * we only want lisp data ones */
    if (ntohs(udph->dest) != LISP_DATA_PORT) {
        return (ERR_NOT_LISP);
    }

    /* DECAP packet and reset IP*/
    lisp_hdr = lbuf_pull(b, sizeof(lisphdr_t));
    lbuf_reset_ip(b);

    /* UPDATE IP TOS and checksum */
    pkt_update_ttl_and_tos(b, ttl, tos);

    /* Poor discriminator for data map notify... */
    if (lisp_hdr->instance_id == 1){
        lmlog(DBG_2,"Data-Map-Notify received\n ");
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

    if ((write(tun_receive_fd, lbuf_ip(&pkt_buf), lbuf_size(&pkt_buf))) < 0) {
        lmlog(DBG_2, "lisp_input: write error: %s\n ", strerror(errno));
    }

    return (GOOD);
}

int rtr_process_input_packet(struct sock *sl)
{
    lbuf_use_stack(&pkt_buf, &pkt_recv_buf, MAX_IP_PKT_LEN);

    if (read_and_decap_pkt(sl->fd, &pkt_buf) != GOOD) {
        return (BAD);
    }

    lmlog(DBG_3, "INPUT (4341): Forwarding to OUPUT for re-encapsulation");
    lisp_output(lbuf_ip(&pkt_buf), lbuf_size(&pkt_buf));

    return(GOOD);
}

