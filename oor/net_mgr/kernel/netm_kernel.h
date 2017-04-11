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

#ifndef NETM_KERNEL_H_
#define NETM_KERNEL_H_

#ifdef ANDROID
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

typedef struct netm_data_type_ {
    int netlink_fd;
}netm_data_type;


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


#endif /* NETM_KERNEL_H_ */
