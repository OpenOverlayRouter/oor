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

#ifndef IFACE_LIST_H_
#define IFACE_LIST_H_

#include "liblisp/lisp_mapping.h"
#include "defs.h"
#include "lib/timers.h"
#ifdef ANDROID
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

/* Interface structure
 * ===================
 * Locator address (rloc) is linked to the interface address. If the address
 * of the interface changes, the locator address changes automatically */
typedef struct iface {
    char *iface_name;
    uint32_t iface_index;
    uint8_t status;
    lisp_addr_t *ipv4_address;
    lisp_addr_t *ipv6_address;
    lisp_addr_t *ipv4_gateway;
    lisp_addr_t *ipv6_gateway;

    int out_socket_v4;
    int out_socket_v6;
} iface_t;


#ifdef ANDROID

/*
 * Different from oor_if_t to maintain
 * linux system call compatibility.
 */
typedef struct ifaddrs {
    struct ifaddrs      *ifa_next;
    char                *ifa_name;
    unsigned int         ifa_flags;
    struct sockaddr      *ifa_addr;
    int                  ifa_index;
} ifaddrs;


typedef struct {
    struct nlmsghdr nlh;
    struct rtgenmsg  rtmsg;
} request_struct;

#endif

extern glist_t *interface_list;  //<iface_t *>

extern shash_t *iface_addr_ht;


int ifaces_init();
inline void ifaces_destroy();


void iface_destroy(iface_t *iface);
char *iface_to_char(iface_t *iface);

lisp_addr_t *get_iface_address(char *ifacename, int afi);
iface_t *add_interface(char *iface_name);
int iface_setup_addr(iface_t *iface, int afi);
iface_t *get_interface(char *iface_name);
iface_t *get_interface_from_index(int iface_index);
iface_t *get_interface_with_address(lisp_addr_t *address);
int *get_out_socket_ptr_from_address(lisp_addr_t *address);

/* Print the interfaces and locators of the lisp node */
void iface_list_to_char(int log_level);

iface_t *get_any_output_iface(int);

lisp_addr_t *iface_address(iface_t *iface, int afi);
int iface_socket(iface_t *iface, int afi);
int *iface_socket_pointer(iface_t *iface, int afi);
static uint8_t iface_status(iface_t *iface);
char *get_interface_name_from_address(lisp_addr_t *addr);

static inline uint8_t iface_status(iface_t *iface)
{
    return (iface->status);
}



#endif /*IFACE_LIST_H_*/
