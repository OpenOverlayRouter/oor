#pragma once

#include <stdio.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include "lispd.h" 


void process_input_packet(int fd, int tun_receive_fd);