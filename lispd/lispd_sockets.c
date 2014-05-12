/*
 * lispd_sockets.c
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
 *    Florin Coras <fcoras@ac.upc.edu>
 */

#include "lispd_sockets.h"
#include "lispd_iface_list.h"
#include "lispd_lib.h"
#include "sockets-util.h"
#include "liblisp.h"

struct sock_master *
sock_master_new() {
    struct sock_master *sm;
    sm = xzalloc(sizeof(struct sock_master));
    return (sm);
}

static void
sock_list_add(struct sock_list *lst, struct sock *sock) {
    sock->next = NULL;
    sock->prev = lst->tail;
    if (lst->tail) {
        lst->tail->next = sock;
    } else {
        lst->head = sock;
    }

    lst->tail = sock;
    lst->count++;
    if (sock->fd > lst->maxfd) {
        lst->maxfd = sock->fd;
    }

}

struct sock *
sock_register_read_listener(struct sock_master *m,
        int (*func)(struct sock *), void *arg, int fd) {
    struct sock *sock;
    sock = xzalloc(sizeof(struct sock));
    sock->recv_cb = func;
    sock->type = SOCK_READ;
    sock->arg = arg;
    sock->fd = fd;
    sock_list_add(&m->read, sock);
//    FD_SET(fd, &m->readfds);
    return (sock);
}

static void
sock_process_fd(struct sock_list *lst, fd_set *fdset) {
    struct sock *sit;

    for (sit = lst->head; sit; sit = sit->next) {
        if (FD_ISSET(sit->fd, fdset))
            (*sit->recv_cb)(sit);
    }
}

void
sock_process_all(struct sock_master *m) {
//    fd_set          readfds;
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = DEFAULT_SELECT_TIMEOUT;

//    readfds = m->readfds;

    while (1) {
        if (select(m->read.maxfd + 1, &m->readfds, NULL, NULL, &tv) == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                lmlog(DBG_2, "sock_process_all: select error: %s",
                        strerror(errno));
                return;
            }
        } else {
            break;
        }
    }

    sock_process_fd(&m->read, &m->readfds);
}

void
sock_fdset_all_read(struct sock_master *m)
{
    struct sock *sit;
    for (sit = m->read.head; sit; sit = sit->next) {
        FD_SET(sit->fd, &m->readfds);
    }
}

int
open_control_input_socket(int afi)
{

    const int on = 1;
    int sock = 0;

    sock = open_udp_socket(afi);
    sock = bind_socket(sock, afi, LISP_CONTROL_PORT);

    if (sock == BAD) {
        return (BAD);
    }

    switch (afi) {
    case AF_INET:
        /* IP_PKTINFO is requiered to get later the IPv4 destination address
         * of incoming control packets */
        if (setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
            lmlog(LWRN, "setsockopt IP_PKTINFO: %s", strerror(errno));
        }
        break;
    case AF_INET6:
        /* IPV6_RECVPKTINFO is requiered to get later the IPv6 destination
         * address of incoming control packets */
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on))
                < 0) {
            lmlog(LWRN, "setsockopt IPV6_RECVPKTINFO: %s", strerror(errno));
        }
        break;
    default:
        return (BAD);
    }
    return (sock);
}

int
open_data_input_socket(int afi)
{

    int sock = 0;
    int dummy_sock = 0; /* To avoid ICMP port unreacheable packets */
    const int on = 1;

    sock = open_raw_socket(afi);

    dummy_sock = open_udp_socket(afi);
    dummy_sock = bind_socket(dummy_sock, afi, LISP_DATA_PORT);

    if (sock == BAD) {
        return (BAD);
    }

    switch (afi) {
    case AF_INET:

        /* IP_RECVTOS is requiered to get later the IPv4 original TOS */
        if (setsockopt(sock, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on)) < 0) {
            lmlog(LWRN, "setsockopt IP_RECVTOS: %s", strerror(errno));
        }

        /* IP_RECVTTL is requiered to get later the IPv4 original TTL */
        if (setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on)) < 0) {
            lmlog(LWRN, "setsockopt IP_RECVTTL: %s", strerror(errno));
        }

        break;

    case AF_INET6:

        /* IPV6_RECVTCLASS is requiered to get later the IPv6 original TOS */
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on))
                < 0) {
            lmlog(LWRN, "setsockopt IPV6_RECVTCLASS: %s", strerror(errno));
        }

        /* IPV6_RECVHOPLIMIT is requiered to get later the IPv6 original TTL */
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on))
                < 0) {
            lmlog(LWRN, "setsockopt IPV6_RECVHOPLIMIT: %s", strerror(errno));
        }

        break;

    default:
        close(sock);
        return (BAD);
    }

    return (sock);
}

/* Get a packet from the socket. It also returns the destination addres and
 * source port of the packet */
int
sock_recv(int sock, struct lbuf *buf, uconn_t *uc)
{

    union control_data {
        struct cmsghdr cmsg;
        u_char data4[CMSG_SPACE(sizeof(struct in_pktinfo))];
        u_char data6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    };

    union sockunion su;
    struct msghdr msg;
    struct iovec iov[1];
    union control_data cmsg;
    struct cmsghdr *cmsgptr = NULL;
    int nbytes = 0;

    iov[0].iov_base = lbuf_data(buf);
    iov[0].iov_len = buf->size;

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg;
    msg.msg_controllen = sizeof cmsg;
    msg.msg_name = &su;
    msg.msg_namelen = sizeof(union sockunion);

    nbytes = recvmsg(sock, &msg, 0);
    if (nbytes == -1) {
        lmlog(LWRN, "read_packet: recvmsg error: %s", strerror(errno));
        return (BAD);
    }

    buf->size += nbytes;

    if (su.s4.sin_family == AF_INET) {
        for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr;
                cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
            if (cmsgptr->cmsg_level == IPPROTO_IP
                    && cmsgptr->cmsg_type == IP_PKTINFO) {
                lisp_addr_ip_init(&uc->ra,
                        &(((struct in_pktinfo *) (CMSG_DATA(cmsgptr)))->ipi_addr),
                        AF_INET);
                break;
            }
        }

        lisp_addr_ip_init(&uc->la, &su.s4.sin_addr, AF_INET);
        uc->lp = ntohs(su.s4.sin_port);
    } else {
        for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr;
                cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
            if (cmsgptr->cmsg_level == IPPROTO_IPV6
                    && cmsgptr->cmsg_type == IPV6_PKTINFO) {
                lisp_addr_ip_init(&uc->ra,
                        &(((struct in6_pktinfo *) (CMSG_DATA(cmsgptr)))->ipi6_addr.s6_addr),
                        AF_INET6);
                break;
            }
        }
        lisp_addr_ip_init(&uc->la, &su.s6.sin6_addr, AF_INET6);
        uc->lp = ntohs(su.s6.sin6_port);
    }

    return (GOOD);
}

int
sock_send(int sock, struct lbuf *b, uconn_t *uc)
{
    ip_addr_t *src, *dst;

    if (lisp_addr_afi(&uc->la) != LM_AFI_IP
        || lisp_addr_afi(&uc->ra) != LM_AFI_IP) {
        lmlog(DBG_2, "sock_send: src %s and dst % of UDP are not IP. "
                "Discarding!", lisp_addr_to_char(&uc->la),
                lisp_addr_to_char(&uc->ra));
        return(BAD);
    }
    src = lisp_addr_ip(&uc->la);
    dst = lisp_addr_ip(&uc->ra);

    if (ip_addr_afi(src) != ip_addr_afi(dst)) {
        lmglog(DBG_2, "sock_send: src %s and dst %s of UDP connection have"
                "different IP AFI. Discarding!", ip_addr_to_char(src),
                ip_addr_to_char(dst));
        return(BAD);
    }

    /* TODO, XXX: this assumes RAW sockets. Change for android!*/
    pkt_push_udp_and_ip(b, uc->lp, uc->rp, src, dst);
    send_raw(sock, lbuf_data(b), lbuf_size(b), dst);
    return(GOOD);
}

int
get_data_packet(int sock, int *afi, uint8_t *packet, int *length,
        uint8_t *ttl, uint8_t *tos)
{

    /* Space for TTL and TOS data */
    union control_data {
        struct cmsghdr cmsg;
        u_char data[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(int))];
    };

    union sockunion su;
    struct msghdr msg;
    struct iovec iov[1];
    union control_data cmsg;
    struct cmsghdr *cmsgptr = NULL;
    int nbytes = 0;

    iov[0].iov_base = packet;
    iov[0].iov_len = MAX_IP_PKT_LEN;

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg;
    msg.msg_controllen = sizeof cmsg;
    msg.msg_name = &su;
    msg.msg_namelen = sizeof(union sockunion);

    nbytes = recvmsg(sock, &msg, 0);
    if (nbytes == -1) {
        lmlog(LWRN, "read_packet: recvmsg error: %s", strerror(errno));
        return (BAD);
    }

    *length = nbytes;
    *afi = su.s4.sin_family;
    if (*afi == AF_INET) {
        for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr =
                CMSG_NXTHDR(&msg, cmsgptr)) {

            if (cmsgptr->cmsg_level == IPPROTO_IP
                    && cmsgptr->cmsg_type == IP_TTL) {
                *ttl = *((uint8_t *) CMSG_DATA(cmsgptr));
            }

            if (cmsgptr->cmsg_level == IPPROTO_IP
                    && cmsgptr->cmsg_type == IP_TOS) {
                *tos = *((uint8_t *) CMSG_DATA(cmsgptr));
            }
        }

    } else {
        for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr =
                CMSG_NXTHDR(&msg, cmsgptr)) {

            if (cmsgptr->cmsg_level == IPPROTO_IPV6
                    && cmsgptr->cmsg_type == IPV6_HOPLIMIT) {
                *ttl = *((uint8_t *) CMSG_DATA(cmsgptr));
            }

            if (cmsgptr->cmsg_level == IPPROTO_IPV6
                    && cmsgptr->cmsg_type == IPV6_TCLASS) {
                *tos = *((uint8_t *) CMSG_DATA(cmsgptr));
            }
        }
    }

    return (GOOD);
}

