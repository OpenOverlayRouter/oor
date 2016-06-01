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

#ifndef SOCKETS_H_
#define SOCKETS_H_

#include "../defs.h"
#include "sockets-util.h"
#include "packets.h"
#include "../liblisp/lisp_address.h"
#include "lbuf.h"


typedef enum {
    SOCK_READ,
    SOCK_WRITE,
} sock_type_e;

/*
 * inspired by quagga thread.c
 * It might be a little bit of an overkill for now
 * but it could prove useful in the future
 */


typedef struct sock_list {
    struct sock *head;
    struct sock *tail;
    int count;
    int maxfd;
}sock_list_t;

typedef struct sock {
    sock_type_e type;
    int (*recv_cb)(struct sock *);
    void *arg;
    int fd;
    struct sock *next;
    struct sock *prev;
}sock_t;

typedef struct uconn {
    /* TODO: decide if la, ra should be IP */
    lisp_addr_t la;     /* local address */
    lisp_addr_t ra;     /* remote address */
    uint16_t lp;        /* local port */
    uint16_t rp;        /* remote port */
} uconn_t;

typedef struct sockmstr {
    sock_list_t read;
//    struct sock_list *write;
//    struct sock_list *netlink;
    fd_set readfds;
//    fd_set *writefds;
//    fd_set *netlinkfds;
} sockmstr_t;

union sockunion {
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
};


typedef struct fwd_entry {
    lisp_addr_t *srloc;
    lisp_addr_t *drloc;
    int *out_sock;
    uint32_t iid;
} fwd_entry_t;

inline fwd_entry_t *fwd_entry_new_init(lisp_addr_t *srloc, lisp_addr_t *drloc,
        uint32_t iid, int *out_socket);
inline void fwd_entry_del(fwd_entry_t *fwd_entry);
static inline void fwd_entry_set_srloc(fwd_entry_t *fwd_ent, lisp_addr_t * srloc);
static inline void fwd_entry_set_drloc(fwd_entry_t *fwd_ent, lisp_addr_t * drloc);
typedef struct iface iface_t;

sockmstr_t *sockmstr_create();
void sockmstr_destroy(sockmstr_t *sm);
sock_t *sockmstr_register_get_by_fd(sockmstr_t *m, int fd);
sock_t *sockmstr_register_get_by_bind_port (sockmstr_t *m, int afi, uint16_t port);
sock_t *sockmstr_register_read_listener(sockmstr_t *m,
        int (*)(struct sock *), void *arg, int fd);
inline int sock_fd(struct sock * sock);
int sockmstr_unregister_read_listenedr(sockmstr_t *m, struct sock *sock);
void sockmstr_process_all(sockmstr_t *m);
void sockmstr_wait_on_all_read(sockmstr_t *m);

int open_data_raw_input_socket(int afi, uint16_t port);
int open_data_datagram_input_socket(int afi, int port);
int open_control_input_socket(int afi);

int sock_recv(int, lbuf_t *);
int sock_ctrl_recv(int, lbuf_t *, uconn_t *);
int sock_data_recv(int sock, lbuf_t *b, int *afi, uint8_t *ttl, uint8_t *tos);
inline int uconn_init(uconn_t *uc, int lp, int rp, lisp_addr_t *la,
        lisp_addr_t *ra);

static inline void
fwd_entry_set_srloc(fwd_entry_t *fwd_ent, lisp_addr_t * srloc)
{
    fwd_ent->srloc = srloc;
}

static inline void
fwd_entry_set_drloc(fwd_entry_t *fwd_ent, lisp_addr_t * drloc)
{
    fwd_ent->drloc = drloc;
}

#endif /*SOCKETS_H_*/
