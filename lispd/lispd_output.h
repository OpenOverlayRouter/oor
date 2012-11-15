#pragma once

#include <stdio.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "lispd.h"
#include "lispd_iface_list.h"
#include "lispd_lib.h"
#include "cksum.h"
#include "lispd_map_cache_db.h"
#include "lispd_external.h"


void process_output_packet(int fd, char *tun_receive_buf, unsigned int tun_receive_size);

lisp_addr_t extract_dst_addr_from_packet ( char *packet );

int handle_map_cache_miss(lisp_addr_t *eid);

lisp_addr_t *get_proxy_etr(int afi);