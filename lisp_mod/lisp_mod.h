/*
 * lisp_mod.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Declarations and constants for the LISP kernel module.
 * 
 * Copyright (C) 2011 Cisco Systems, Inc, 2011. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Please send any bug reports or fixes you make to the email address(es):
 *    LISP-MN developers <devel@lispmob.org>
 *
 * Written or modified by:
 *    Chris White       <chris@logicalelegance.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *
 */

#pragma once

#include "linux/module.h"	
#include "linux/kernel.h"
#include "linux/netfilter.h"
#include "linux/netfilter_ipv4.h"
#include "linux/netlink.h"
#include "net/net_namespace.h"
#include "net/ipv6.h"
#include "tables.h"
#include "lisp_ipc.h"
#include "lisp_ipc_kernel.h"
#include "lisp_input.h"
#include "lisp_output.h"
#include "lisp_slab.h"
#include "lib/patricia/patricia.h"

#define NETLINK_LISP 20  /* XXX Temporary, needs to be in /usr/include/linux/netlink.h */
#define MAXLOCALEID 10 /*Max number of local EIDs that lispmob handles*/
#define IFINDEX_HASH_BITS 4

typedef struct {
  struct sock *nl_socket;       /* Netlink socket */
  struct nf_hook_ops netfilter_ops_in;  /* Netfilter hook definition, input */
  struct nf_hook_ops netfilter_ops_out; /* Netfilter hook definition, output */
  struct nf_hook_ops netfilter_ops_out6; /* "" For ipv6 */
  int    always_encap;         /* Always LISP encapsulate? */
  int    multiple_rlocs;       /* Use multiple RLOCs */
  ushort my_rloc_af;
  ushort udp_encap_port;
  ushort udp_control_port;
  int   daemonPID; /* Process ID for lispd */
  int num_local_eid;
  lisp_addr_t local_eid_list[MAXLOCALEID];
  // RLOC to if_index table, used by lisp connection manager
  rloc_map_entry_t *if_to_rloc_hash_table[1 << IFINDEX_HASH_BITS];
} lisp_globals;

