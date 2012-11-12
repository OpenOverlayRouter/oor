#pragma once

#include <stdio.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include "lispd.h"
#include "lispd_iface_list.h"
#include "lispd_lib.h"
#include "cksum.h"


void process_output_packet(int fd, char *tun_receive_buf, unsigned int tun_receive_size);
