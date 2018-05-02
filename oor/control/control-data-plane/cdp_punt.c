/*
 *
 * Copyright (C) 2018 Cisco Systems, Inc.
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

#include "cdp_punt.h"
#include "../../control/oor_ctrl_device.h"

int
control_dp_punt(lbuf_t *b, oor_ctrl_dev_t *ctrl_dev)
{
    packet_tuple_t tpl;
    uconn_t uc;

    if (lisp_msg_parse_int_ip_udp(b) != GOOD) {
        return (BAD);
    }

    pkt_parse_inner_5_tuple(b, &tpl);
    uconn_from_5_tuple(&tpl, &uc, 1);
    ctrl_dev_recv(ctrl_dev, b, &uc);

    return (GOOD);
}
