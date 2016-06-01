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


#ifndef SOCKETS_UTIL_H_
#define SOCKETS_UTIL_H_

#include "../liblisp/lisp_address.h"

int open_ip_raw_socket(int afi);
int open_udp_raw_socket(int afi);
int opent_netlink_socket();

int open_udp_datagram_socket(int afi);
inline int socket_bindtodevice(int sock, char *device);
inline int socket_conf_req_ttl_tos(int sock, int afi);

int bind_socket(int sock,int afi, lisp_addr_t *src_addr, int src_port);
int send_raw_packet(int, const void *, int, ip_addr_t *);
int send_datagram_packet (int sock, const void *packet, int packet_length,
        lisp_addr_t *addr_dest, int port_dest);

#endif /* SOCKETS_UTIL_H_ */
