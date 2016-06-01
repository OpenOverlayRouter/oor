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

/* Define _GNU_SOURCE in order to use in6_pktinfo (get destination address of
 * received ctrl packets) */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#include <netinet/in.h>
#endif

#include <errno.h>
#include <sys/socket.h>

#include "oor_log.h"
#include "sockets.h"
#include "sockets-util.h"
#include "../iface_list.h"
#include "../liblisp/liblisp.h"

inline fwd_entry_t *
fwd_entry_new_init(lisp_addr_t *srloc, lisp_addr_t *drloc, uint32_t iid, int *out_socket)
{
    fwd_entry_t *fw_entry = xzalloc(sizeof(fwd_entry_t));
    if (!fw_entry){
        return (NULL);
    }
    fw_entry->srloc = lisp_addr_clone(srloc);
    fw_entry->drloc = lisp_addr_clone(drloc);
    fw_entry->iid = iid;
    fw_entry->out_sock = out_socket;
    return (fw_entry);
}

inline void
fwd_entry_del(fwd_entry_t *fwd_entry)
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



static inline void
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

static inline void
sock_list_remove(sock_list_t *lst, struct sock *sock)
{
    int fd;
    if (sock->prev == NULL){
        lst->head = sock->next;
        if (sock->next != NULL){
            sock->next->prev = NULL;
        }
    }else{
        sock->prev->next = sock->next;
        if (sock->next != NULL){
            sock->next->prev = sock->prev;
        }
    }
    fd = sock->fd;
    close(sock->fd);
    free(sock);

    lst->count--;

    if (fd == lst->maxfd){
        sock= lst->head;
        if (sock == NULL){
            lst->maxfd = 0;
        }
        while (sock != NULL){
            if (sock->fd > lst->maxfd) {
                lst->maxfd = sock->fd;
            }
            sock = sock->next;
        }
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
    OOR_LOG(LDBG_1,"Sockets closed");
}

sock_t *
sockmstr_register_get_by_fd(sockmstr_t *m, int fd){
    sock_list_t *lst;
    sock_t * sock = NULL;

    lst = &m->read;
    sock = lst->head;
    if (sock == NULL){
        return (NULL);
    }

    while (sock != NULL){
        if (sock->fd == fd){
            return (sock);
        }
        sock = sock->next;
    }

    return (sock);
}

sock_t *
sockmstr_register_get_by_bind_port (sockmstr_t *m, int afi, uint16_t port)
{
    sock_list_t *lst;
    sock_t * sock = NULL;
    struct sockaddr sa;
    socklen_t sa_len = sizeof(sa);

    lst = &m->read;
    sock = lst->head;
    if (sock == NULL){
        return (NULL);
    }

    while (sock != NULL){
        if (getsockname(sock->fd, (struct sockaddr *)&sa, &sa_len) == -1){
            sock = sock->next;
            continue;
        }
        if (sa_len == sizeof(struct sockaddr_in)){
            if (afi == AF_INET && port == ntohs(((struct sockaddr_in *)&sa)->sin_port)){
                return (sock);
            }
        }else{
            if (afi == AF_INET6 && port == ntohs(((struct sockaddr_in6 *)&sa)->sin6_port)){
                return (sock);
            }
        }
        sock = sock->next;
    }

    return (sock);
}

sock_t *
sockmstr_register_read_listener(sockmstr_t *m,int (*func)(struct sock *),
        void *arg, int fd)
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

inline int
sock_fd(struct sock * sock)
{
    return (sock->fd);
}


int
sockmstr_unregister_read_listenedr(sockmstr_t *m, struct sock *sock)
{
   sock_list_remove(&m->read, sock);
   return (GOOD);
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
                OOR_LOG(LDBG_2, "sock_process_all: select error: %s",
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
    int sock = ERR_SOCKET;

    sock = open_udp_datagram_socket(afi);
    if (sock == ERR_SOCKET) {
        return (ERR_SOCKET);
    }
    bind_socket(sock, afi, NULL, LISP_CONTROL_PORT);



    switch (afi) {
    case AF_INET:
        /* IP_PKTINFO is requiered to get later the IPv4 destination address
         * of incoming control packets */
        if (setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
            OOR_LOG(LWRN, "setsockopt IP_PKTINFO: %s", strerror(errno));
        }
        break;
    case AF_INET6:
        /* IPV6_RECVPKTINFO is requiered to get later the IPv6 destination
         * address of incoming control packets */
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on))
                < 0) {
            OOR_LOG(LWRN, "setsockopt IPV6_RECVPKTINFO: %s", strerror(errno));
        }
        break;
    default:
        return (ERR_SOCKET);
    }
    return (sock);
}

int
open_data_raw_input_socket(int afi, uint16_t port)
{

    int sock = ERR_SOCKET;
    int dummy_sock = ERR_SOCKET; /* To avoid ICMP port unreacheable packets */

    sock = open_udp_raw_socket(afi);
    if (sock == ERR_SOCKET){
        return (ERR_SOCKET);
    }

    dummy_sock = open_udp_datagram_socket(afi);
    dummy_sock = bind_socket(dummy_sock, afi, NULL, port);

    if (socket_conf_req_ttl_tos(sock,afi)!= GOOD){
        close(sock);
        close(dummy_sock);
        return (ERR_SOCKET);
    }

    return (sock);
}

int
open_data_datagram_input_socket(int afi, int port)
{

    int sock = ERR_SOCKET;

    if ((sock = open_udp_datagram_socket(afi)) < 0){
        return(ERR_SOCKET);
    }
    if(bind_socket(sock,afi,NULL,port) != GOOD){
        close(sock);
        return(ERR_SOCKET);
    }

    if (socket_conf_req_ttl_tos(sock,afi)!= GOOD){
        close(sock);
        return (ERR_SOCKET);
    }

    return (sock);
}


int
sock_recv(int sfd, lbuf_t *b)
{
    int nread;
    nread = read(sfd, lbuf_data(b), lbuf_tailroom(b));
    if (nread == 0) {
        OOR_LOG(LWRN, "sock_recv: recvmsg error: %s", strerror(errno));
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
        OOR_LOG(LWRN, "sock_recv_ctrl: recvmsg error: %s", strerror(errno));
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
sock_data_recv(int sock, lbuf_t *b, int *afi, uint8_t *ttl, uint8_t *tos)
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
        OOR_LOG(LWRN, "read_packet: recvmsg error: %s", strerror(errno));
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
        *afi = AF_INET;
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
        *afi = AF_INET6;
    }

    return (GOOD);
}

inline int
uconn_init(uconn_t *uc, int lp, int rp, lisp_addr_t *la,lisp_addr_t *ra)
{
    uc->lp = lp;
    uc->rp = rp;
    la ? lisp_addr_copy(&uc->la, la) :
            lisp_addr_set_lafi(&uc->la, LM_AFI_NO_ADDR);
    ra ? lisp_addr_copy(&uc->ra, ra) :
            lisp_addr_set_lafi(&uc->ra, LM_AFI_NO_ADDR);
    return(GOOD);
}
