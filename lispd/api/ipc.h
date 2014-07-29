/*
 * ipc.h
 *
 *  Created on: Feb 11, 2014
 *      Author: alopez
 */

#ifndef IPC_H_
#define IPC_H_

#include "../lispd.h"

#define IPC_ENCAP               0
#define IPC_DECAP               1
#define IPC_DATA_IN             2
#define IPC_DATA_OUT            3
#define IPC_CTRL_IN             4
#define IPC_CTRL_OUT            5
#define IPC_LOG_MSG              6
#define IPC_PROTECT_SOCK        7

#define NO_ERR                  0
#define NO_CONF_FILE            1
#define WRONG_CONF              2
#define NO_NETWORK              3
#define MAP_REG_ERR             4
#define INF_REQ_ERR             5

#define CONTROL_PKT             0
#define DATA_PKT                1

int process_ipc_packet(int socket);

int ipc_send_out_packet(
        uint8_t         *packet,
        int             packet_length,
        lisp_addr_t     *dest_addr,
        uint16_t        src_port,
        uint16_t        dest_port,
        uint8_t         flag);


int ipc_send_decap_packet(
        uint8_t         *packet,
        int             packet_length);

int ipc_send_log_msg (int error_code);

int ipc_protect_socket(int socket);


#endif /* IPC_H_ */
