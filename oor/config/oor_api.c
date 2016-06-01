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

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zmq.h>

#include "oor_api.h"
#include "../lib/oor_log.h"
#include "../lib/mem_util.h"
#include "../liblisp/liblisp.h"


int
oor_api_init_client(oor_api_connection_t *conn)
{
    int error;

    conn->context = zmq_ctx_new();

    //Request-Reply communication pattern (Client side)
    conn->socket = zmq_socket(conn->context, ZMQ_REQ);

    //Attachment point for other processes
    error = zmq_connect(conn->socket, IPC_FILE);

    if (error != 0){
        OOR_LOG(LDBG_2,"LMAPI: Error while ZMQ binding on client: %s\n",zmq_strerror (error));
        goto err;
    }

    OOR_LOG(LDBG_2,"LMAPI: API client initiated using ZMQ\n");

    return (GOOD);

err:
    OOR_LOG(LERR,"LMAPI: The API client couldn't be initialized.\n");
    return (BAD);
}


void
oor_api_end(oor_api_connection_t *conn)
{
    OOR_LOG(LDBG_2,"LMAPI: Closing ZMQ-based API\n");

    zmq_close (conn->socket);
    zmq_ctx_destroy (conn->context);

    OOR_LOG(LDBG_2,"LMAPI: Closed ZMQ-based API\n");
}

uint8_t *
oor_api_hdr_push(uint8_t *buf, oor_api_msg_hdr_t * hdr)
{
    uint8_t *ptr;

    memcpy(buf,hdr,sizeof(oor_api_msg_hdr_t));

    ptr = CO(buf,sizeof(oor_api_msg_hdr_t));

    return (ptr);
}

void oor_api_fill_hdr(oor_api_msg_hdr_t *hdr, oor_api_msg_device_e dev,
        oor_api_msg_target_e trgt, oor_api_msg_opr_e opr,
        oor_api_msg_type_e type, int dlen)
{
    hdr->device = (uint8_t) dev;
    hdr->target = (uint8_t) trgt;
    hdr->operation = (uint8_t) opr;
    hdr->type = (uint8_t) type;
    hdr->datalen = (uint32_t) dlen;
}

int
oor_api_result_msg_new(uint8_t **buf,oor_api_msg_device_e  dev,
        oor_api_msg_target_e trgt, oor_api_msg_opr_e opr,
        oor_api_msg_result_e res)
{
    oor_api_msg_hdr_t hdr;
    uint8_t *ptr;

    oor_api_fill_hdr(&hdr,dev,trgt,opr,OOR_API_TYPE_RESULT,sizeof(oor_api_msg_result_e));
    *buf = xzalloc(sizeof(oor_api_msg_hdr_t)+sizeof(oor_api_msg_result_e));
    ptr = oor_api_hdr_push(*buf,&hdr);
    memcpy(ptr, &res,sizeof(oor_api_msg_result_e));

    return (sizeof(oor_api_msg_hdr_t)+sizeof(oor_api_msg_result_e));
}


int
oor_api_recv(oor_api_connection_t *conn, void *buffer, int flags)
{
    int nbytes;
    int zmq_flags = 0;
    zmq_pollitem_t items [1];
    int poll_timeout;
    int poll_rc;

    if (flags == OOR_API_DONTWAIT){
        zmq_flags = ZMQ_DONTWAIT;
        poll_timeout = 0; //Return immediately
    }else{
    	poll_timeout = -1; //Wait indefinitely
    }

    items[0].socket = conn->socket;
    items[0].events = ZMQ_POLLIN; //Check for incoming packets on socket

    // Poll for packets on socket for poll_timeout time
    poll_rc = zmq_poll (items, 1, poll_timeout);

    if (poll_rc == 0) { //There is nothing to read on the socket
    	return (OOR_API_NOTHINGTOREAD);
    }

    OOR_LOG(LDBG_3,"LMAPI: Data available in API socket\n");

    nbytes = zmq_recv(conn->socket, buffer, MAX_API_PKT_LEN, zmq_flags);
    OOR_LOG(LDBG_3,"LMAPI: Bytes read from API socket: %d. ",nbytes);

    if (nbytes == -1){
    	OOR_LOG(LERR,"LMAPI: Error while ZMQ receiving: %s\n",zmq_strerror (errno));
    	return (OOR_API_ERROR);
    }

    return (nbytes);
}



int
oor_api_send(oor_api_connection_t *conn, void *msg, int len, int flags)
{
    int nbytes;

    OOR_LOG(LDBG_3,"LMAPI: Ready to send %d bytes through API socket\n",len);

    nbytes = zmq_send(conn->socket,msg,len,0);

    OOR_LOG(LDBG_3,"LMAPI: Bytes transmitted over API socket: %d. ",nbytes);

    if (nbytes == -1){
        	OOR_LOG(LERR,"LMAPI: Error while ZMQ sending: %s\n",zmq_strerror (errno));
    }

    return (GOOD);
}

int
oor_api_apply_config(oor_api_connection_t *conn, int dev, int trgt, int opr,
        uint8_t *data, int dlen)
{
	oor_api_msg_hdr_t *hdr;
	uint8_t *buffer;
	uint8_t *dta_ptr;
	uint8_t *res_ptr;
	int len;

	buffer = xzalloc(MAX_API_PKT_LEN);
	hdr = (oor_api_msg_hdr_t *) buffer;
	dta_ptr = CO(buffer,sizeof(oor_api_msg_hdr_t));

	oor_api_fill_hdr(hdr,dev,trgt,opr,OOR_API_TYPE_REQUEST,dlen);
	memcpy(dta_ptr,data,dlen);

	len = dlen + sizeof(oor_api_msg_hdr_t);
	oor_api_send(conn,buffer,len,OOR_API_NOFLAGS);
	free(buffer);

	buffer = xzalloc(MAX_API_PKT_LEN);

	//Blocks until reply
	len = oor_api_recv(conn,buffer,OOR_API_NOFLAGS);

	hdr = (oor_api_msg_hdr_t *) buffer;

	//We expect an OK/ERR result
	if ((hdr->type != OOR_API_TYPE_RESULT) || (hdr->datalen != sizeof(oor_api_msg_result_e))){
	    goto err;
	}

	res_ptr = CO(buffer,sizeof(oor_api_msg_hdr_t));
	if (*res_ptr != OOR_API_RES_OK){
	    //TODO support fine-grain errors
	    goto err;
	}

	// All good
	free (buffer);
	return (OOR_API_RES_OK);

err:

    free (buffer);
    return (OOR_API_RES_ERR);

}
