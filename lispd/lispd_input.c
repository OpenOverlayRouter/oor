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


#include "lispd_input.h"


 void lisp_input(char *packet_buf, int length, void *source, int tun_receive_fd)
 {
     int ret;
     struct lisphdr *lisp_hdr;
     struct iphdr *iph;
     //struct sockaddr_in *source_sock;
     
     //source_sock    = (struct sockaddr_in *)source;
     
     
     //iph = (struct iphdr *)((char *)packet_buf + sizeof(struct iphdr));


     lisp_hdr = (struct lisphdr *)packet_buf;

     iph = (struct iphdr *)((char *)lisp_hdr + sizeof(struct lisphdr));
     
     if (iph->version == 4) {
     
         ret = write(tun_receive_fd, iph, length - sizeof(struct lisphdr));
     
     }
     
     if (ret==-1){
        lispd_log_msg(LOG_DEBUG,"write: %s\n ", strerror(errno));
         
     }
     
 }
 
 void process_input_packet(int fd, int tun_receive_fd)
 {
     uint8_t                 packet[4096];
     int                     recv_len;
     socklen_t               fromlen4 = sizeof(struct sockaddr_in);
     struct sockaddr_in      s4;
     
    lispd_log_msg(LOG_DEBUG,"tuntap_process_input_packet\n");
     
     memset(&s4, 0, sizeof(struct sockaddr_in));
     
     if ((recv_len = recvfrom(fd, packet, 4096, 0,(struct sockaddr *) &s4, &fromlen4)) < 0)
        lispd_log_msg(LOG_DEBUG,"recvfrom (v4): %s", strerror(errno));
     else
         lisp_input((char *)packet, recv_len, &s4, tun_receive_fd);
     
 }
 
