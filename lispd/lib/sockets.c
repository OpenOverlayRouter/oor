/*
 * sockets.c
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

/* Define _GNU_SOURCE in order to use in6_pktinfo (get destination address of
 * received ctrl packets) */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#include <netinet/in.h>
#endif

#include <errno.h>

#include "sockets.h"
#include "sockets-util.h"
#include "../liblisp/liblisp.h"
#include "../iface_list.h"
#include "lmlog.h"


inline void fwd_entry_del(fwd_entry_t *fwd_entry)
{
    if (fwd_entry == NULL){
        return;
    }
    lisp_addr_del(fwd_entry->srloc);
    lisp_addr_del(fwd_entry->drloc);
    free(fwd_entry);
}


sockmstr_t *
sockmstr_create()
{
    sockmstr_t *sm;
    sm = xzalloc(sizeof(sockmstr_t));
    return (sm);
}



static void
sock_list_remove_all(sock_list_t *lst)
{
    sock_t *sk, *next;

    sk = lst->head;
    while(sk) {
        next = sk->next;
        close(sk->fd);
        free(sk);
        sk = next;
    }
}

static void
sock_list_add(sock_list_t *lst, sock_t *sock)
{
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

void
sockmstr_destroy(sockmstr_t *sm)
{
    if (sm == NULL){
        return;
    }
    sock_list_remove_all(&sm->read);
    free(sm);
    LMLOG(LDBG_1,"Sockets closed");
}

struct sock *
sockmstr_register_read_listener(sockmstr_t *m,
        int (*func)(struct sock *), void *arg, int fd)
{
    struct sock *sock;
    sock = xzalloc(sizeof(struct sock));
    sock->recv_cb = func;
    sock->type = SOCK_READ;
    sock->arg = arg;
    sock->fd = fd;
    sock_list_add(&m->read, sock);
    return (sock);
}

static void
sock_process_fd(struct sock_list *lst, fd_set *fdset)
{
    struct sock *sit;

    for (sit = lst->head; sit; sit = sit->next) {
        if (FD_ISSET(sit->fd, fdset))
            (*sit->recv_cb)(sit);
    }
}

void
sockmstr_process_all(sockmstr_t *m)
{
    struct timeval tv;

    tv.tv_sec = 0;
    tv.tv_usec = DEFAULT_SELECT_TIMEOUT;

    while (1) {
        if (select(m->read.maxfd + 1, &m->readfds, NULL, NULL, &tv) == -1) {
            if (errno == EINTR) {
                continue;
            } else {
                LMLOG(LDBG_2, "sock_process_all: select error: %s",
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
sockmstr_wait_on_all_read(sockmstr_t *m)
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
            LMLOG(LWRN, "setsockopt IP_PKTINFO: %s", strerror(errno));
        }
        break;
    case AF_INET6:
        /* IPV6_RECVPKTINFO is requiered to get later the IPv6 destination
         * address of incoming control packets */
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on))
                < 0) {
            LMLOG(LWRN, "setsockopt IPV6_RECVPKTINFO: %s", strerror(errno));
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
            LMLOG(LWRN, "setsockopt IP_RECVTOS: %s", strerror(errno));
        }

        /* IP_RECVTTL is requiered to get later the IPv4 original TTL */
        if (setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on)) < 0) {
            LMLOG(LWRN, "setsockopt IP_RECVTTL: %s", strerror(errno));
        }

        break;

    case AF_INET6:

        /* IPV6_RECVTCLASS is requiered to get later the IPv6 original TOS */
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on))
                < 0) {
            LMLOG(LWRN, "setsockopt IPV6_RECVTCLASS: %s", strerror(errno));
        }

        /* IPV6_RECVHOPLIMIT is requiered to get later the IPv6 original TTL */
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on))
                < 0) {
            LMLOG(LWRN, "setsockopt IPV6_RECVHOPLIMIT: %s", strerror(errno));
        }

        break;

    default:
        close(sock);
        return (BAD);
    }

    return (sock);
}

int
sock_recv(int sfd, lbuf_t *b)
{
    int nread;
    nread = read(sfd, lbuf_data(b), lbuf_tailroom(b));
    if (nread == 0) {
        LMLOG(LWRN, "sock_recv: recvmsg error: %s", strerror(errno));
        return (BAD);
    }

    lbuf_set_size(b, lbuf_size(b) + nread);
    return(GOOD);
}

/* Get a packet from the socket. It also returns the destination addres and
 * source port of the packet */
int
sock_ctrl_recv(int sock, struct lbuf *buf, uconn_t *uc)
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
    iov[0].iov_len = lbuf_tailroom(buf);

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg;
    msg.msg_controllen = sizeof cmsg;
    msg.msg_name = &su;
    msg.msg_namelen = sizeof(union sockunion);

    nbytes = recvmsg(sock, &msg, 0);
    if (nbytes == -1) {
        LMLOG(LWRN, "sock_recv_ctrl: recvmsg error: %s", strerror(errno));
        return (BAD);
    }

    lbuf_set_size(buf, lbuf_size(buf) + nbytes);

    /* read local address, remote port and remote address */
    if (su.s4.sin_family == AF_INET) {
        for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr;
                cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
            if (cmsgptr->cmsg_level == IPPROTO_IP
                    && cmsgptr->cmsg_type == IP_PKTINFO) {
                lisp_addr_ip_init(&uc->la,
                        &(((struct in_pktinfo *) (CMSG_DATA(cmsgptr)))->ipi_addr),
                        AF_INET);
                break;
            }
        }

        lisp_addr_ip_init(&uc->ra, &su.s4.sin_addr, AF_INET);
        uc->rp = ntohs(su.s4.sin_port);
    } else {
        for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr;
                cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
            if (cmsgptr->cmsg_level == IPPROTO_IPV6
                    && cmsgptr->cmsg_type == IPV6_PKTINFO) {
                lisp_addr_ip_init(&uc->la,
                        &(((struct in6_pktinfo *) (CMSG_DATA(cmsgptr)))->ipi6_addr),
                        AF_INET6);
                break;
            }
        }
        lisp_addr_ip_init(&uc->ra, &su.s6.sin6_addr, AF_INET6);
        uc->rp = ntohs(su.s6.sin6_port);
    }

    return (GOOD);
}

int
sock_data_recv(int sock, lbuf_t *b, uint8_t *ttl, uint8_t *tos)
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

    iov[0].iov_base = lbuf_data(b);
    iov[0].iov_len = lbuf_tailroom(b);

    memset(&msg, 0, sizeof msg);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg;
    msg.msg_controllen = sizeof cmsg;
    msg.msg_name = &su;
    msg.msg_namelen = sizeof(union sockunion);

    nbytes = recvmsg(sock, &msg, 0);
    if (nbytes == -1) {
        LMLOG(LWRN, "read_packet: recvmsg error: %s", strerror(errno));
        return (BAD);
    }

    lbuf_set_size(b, lbuf_size(b) + nbytes);

    if (su.s4.sin_family == AF_INET) {
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

        /* With input RAW UDP sockets in IPv4, we get the whole external
         * IPv4 packet */
        lbuf_reset_ip(b);
        pkt_pull_ip(b);
        lbuf_reset_udp(b);
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
        /* With input RAW UDP sockets in IPv6, we get the whole external
         * UDP packet */
        lbuf_reset_udp(b);
    }

    return (GOOD);
}

int
sock_ctrl_send(uconn_t *uc, struct lbuf *b)
{
    ip_addr_t *src, *dst;
    int sock, dst_afi;
    iface_t *iface;
    lisp_addr_t *ctrl_addr;

    /* FIND the socket where to output the packet */
    dst_afi = lisp_addr_ip_afi(&uc->ra);
    if (lisp_addr_is_no_addr(&uc->la)) {
        ctrl_addr = get_default_ctrl_address(dst_afi);
        if (!ctrl_addr) {
            LMLOG(LERR, "No control address found, send aborted!");
            return(BAD);
        }
        lisp_addr_copy(&uc->la, ctrl_addr);
        sock = get_default_ctrl_socket(dst_afi);
    } else {
        iface = get_interface_with_address(&uc->la);
        if (iface) {
            sock = iface_socket(iface, dst_afi);
        } else {
            sock = get_default_ctrl_socket(dst_afi);
        }
        if (sock < 0) {
            LMLOG(LERR, "No output socket found, send aborted!");
            return(BAD);
        }
    }

    src = lisp_addr_ip(&uc->la);
    dst = lisp_addr_ip(&uc->ra);

    if (ip_addr_afi(src) != ip_addr_afi(dst)) {
        LMLOG(LDBG_2, "sock_ctrl_send: src %s and dst %s of UDP connection have"
                "different IP AFI. Discarding!", ip_addr_to_char(src),
                ip_addr_to_char(dst));
        return(BAD);
    }

    /* TODO, XXX: this assumes RAW sockets. Change for android!*/
    pkt_push_udp_and_ip(b, uc->lp, uc->rp, src, dst);
    send_raw(sock, lbuf_data(b), lbuf_size(b), dst);

    return(GOOD);
}

/* lisp encapsulates and forwards a packet */
int
sock_lisp_data_send(lbuf_t *b, lisp_addr_t *src, lisp_addr_t *dst, int out_sock)
{
    int ret;

    /* FIXME: this works only with RAW sockets */
    lisp_data_encap(b, LISP_DATA_PORT, LISP_DATA_PORT, src,
            dst);

    ret = send_raw(out_sock, lbuf_data(b), lbuf_size(b),
            lisp_addr_ip(dst));

    if (ret) {
        return(GOOD);
    } else {
        return(BAD);
    }
}

/* forwards natively a packet */
int
sock_data_send(lbuf_t *b, lisp_addr_t *dst)
{
    int ret = 0, ofd = 0, afi = 0;

    afi = lisp_addr_ip_afi(dst);
    ofd = get_default_output_socket(afi);

    if (ofd == -1) {
        LMLOG(LDBG_2, "sock_data_send: No output interface for afi %d", afi);
        return (BAD);
    }

    ret = send_raw(ofd, lbuf_data(b), lbuf_size(b), lisp_addr_ip(dst));
    return (ret);
}



