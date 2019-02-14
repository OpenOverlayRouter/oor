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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>

#include "ios_packetTunnelProvider_api.h"
#include "ios_packetTunnelProvider_api_l.h"
#include "lbuf.h"
#include "packets.h"
#include "oor_log.h"
#include "../liblisp/liblisp.h"
#include "../data-plane/apple/ios/ios_output.h"

static iOS_CLibCallbacks ios_Callbacks;
static glist_t *lbuf_list = NULL;
static sem_t *semaphore;

extern void iOS_init_out_packet_buffer()
{
    lbuf_list = glist_new_managed((glist_del_fct)lbuf_del);
}

extern void iOS_init_semaphore()
{
    if ((semaphore = sem_open("/semaphore", O_CREAT, 0644, 1)) == SEM_FAILED ) {
        OOR_LOG(LERR,"Error creating semaphore: %s",strerror(errno));
        exit(EXIT_FAILURE);
    }
}

extern void iOS_end_semaphore()
{
    if (sem_close(semaphore) == -1) {
        OOR_LOG(LERR,"Error closeing semaphore: %s",strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (sem_unlink("/semaphore") == -1) {
        OOR_LOG(LERR,"Error removing semaphore: %s",strerror(errno));
    }
}

extern void iOS_CLibCallbacks_setup(const iOS_CLibCallbacks * callbacks) {
    ios_Callbacks = *callbacks;
}

void
oor_ptp_write_to_tun (const char *buffer, int length, int afi)
{
    ios_Callbacks.ptp_write_to_tun((char *)buffer, length, afi, (void *)ios_Callbacks.packetTunnelProviderPtr);
}

extern void
oor_ptp_read_from_tun (const void *buffer, int length)
{
    lbuf_t *b;

    b = lbuf_new_with_headroom(MAX_IP_PKT_LEN, MAX_LISP_MSG_ENCAP_LEN);
    lbuf_put(b,(void *)buffer,length);
    sem_wait(semaphore);
    glist_add(b,lbuf_list);
    sem_post(semaphore);
}

glist_t *
oor_ptp_get_packets_to_process()
{
    glist_t *pkt_lst = NULL;
    sem_wait(semaphore);
    if (glist_size(lbuf_list) > 0){
        pkt_lst = lbuf_list;
        lbuf_list = glist_new_managed((glist_del_fct)lbuf_del);
    }
    sem_post(semaphore);
    return (pkt_lst);
}
