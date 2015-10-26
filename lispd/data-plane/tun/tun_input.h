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

#ifndef TUN_INPUT_H_
#define TUN_INPUT_H_

#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include "tun_output.h"
#include "../../defs.h"
#include "../../lib/sockets.h"
#include "../../lib/cksum.h"

int tun_process_input_packet(struct sock *sl);
int tun_rtr_process_input_packet(struct sock *sl);

#endif /*TUN_IFACE_LIST_H_*/
