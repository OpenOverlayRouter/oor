/*
 * lispd_sockets.h
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
 *    Albert López <alopez@ac.upc.edu>
 */

#ifndef LISPD_SOCKETS_H_
#define LISPD_SOCKETS_H_

/* Define _GNU_SOURCE in order to use in6_pktinfo (get destinatio address of received ctrl packets*/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "defs.h"
#include <lisp_address.h>
#include <lmbuf.h>

//#include "lispd_output.h"

typedef enum {
    SOCK_READ, SOCK_WRITE,
} sock_type;

/*
 * inspired by quagga thread.c
 * It might be a little bit of an overkill for now
 * but it could prove useful in the future
 */
struct sock;

struct sock_list {
    struct sock *head;
    struct sock *tail;
    int count;
    int maxfd;
};

struct sock {
    sock_type type;
    int (*func)(struct sock *);
    void *arg;
    int fd;
    struct sock *next;
    struct sock *prev;
};

typedef struct _udpsock_t {
    lisp_addr_t src;
    lisp_addr_t dst;
    uint16_t src_port;
    uint16_t dst_port;
} udpsock_t;

struct sock_master {
    struct sock_list read;
//    struct sock_list *write;
//    struct sock_list *netlink;
    fd_set readfds;
//    fd_set *writefds;
//    fd_set *netlinkfds;
};

union sockunion {
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
};

extern struct sock_master *sock_master_new();
extern struct sock *sock_register_read_listener(struct sock_master *m,
        int (*)(struct sock *), void *arg, int fd);
extern void sock_process_all(struct sock_master *m);
extern void sock_fdset_all_read(struct sock_master *m);

int open_device_binded_raw_socket(char *device, int afi);

int open_data_input_socket(int afi);

int open_control_input_socket(int afi);

int open_udp_socket(int afi);

int bind_socket_src_address(int sock, lisp_addr_t *addr);

/*
 * Sends a raw packet through the specified socket
 */

int send_packet(int sock, uint8_t *packet, int packet_length);

/*
 * Get a packet from the socket. It also returns the destination addres and source port of the packet.
 * Used for control packets
 */

int get_packet_and_socket_inf(int, struct lbuf *, udpsock_t *);

int get_data_packet(int sock, int *afi, uint8_t *packet, int *length,
        uint8_t *ttl, uint8_t *tos);

#endif /*LISPD_SOCKETS_H_*/
