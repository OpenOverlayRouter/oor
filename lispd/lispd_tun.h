#pragma once

#include <stdio.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include "lispd.h"

#define CLONEDEV "/dev/net/tun"

int create_tun(char *tun_dev_name,
               unsigned int tun_receive_size,
               int tun_mtu,
               int *tun_receive_fd,
               int *tun_ifindex,
               char **tun_receive_buf);

int tun_set_v4_eid(lisp_addr_t eid_address_v4,
                   char *tun_dev_name);

int tun_set_v6_eid(lisp_addr_t eid_address_v6,
                   char *tun_dev_name,
                   int tun_ifindex);