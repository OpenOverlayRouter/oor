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

#ifndef IOS_OUTPUT_H_
#define IOS_OUTPUT_H_

#include "../../../lib/sockets.h"

#define IOS_RECEIVE_SIZE        2048 // Should probably tune to match largest MTU

int ios_output(lbuf_t *b, packet_tuple_t *tpl);
int ios_output_recv(struct sock *sl);
int ios_send_ctrl_msg(lbuf_t *buf, uconn_t *udp_conn);


#endif /* ios_OUTPUT_H_ */
