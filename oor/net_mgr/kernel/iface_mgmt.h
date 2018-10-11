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

#ifndef IFACE_MGMT_H_
#define IFACE_MGMT_H_

#include "iface_list.h"
#include "../../lib/sockets.h"


int process_netlink_msg(sock_t *sl);
int get_all_ifaces_name_list(char ***ifaces,int *count);
lisp_addr_t * get_network_pref_of_host(lisp_addr_t *address);
lisp_addr_t * iface_get_getway(int iface_index, int afi);

#endif /* IFACE_MGMT_H_ */
