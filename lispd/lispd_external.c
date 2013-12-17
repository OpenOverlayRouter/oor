/*
 * lispd_external.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * External definitions for lispd
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
 *    Albert Lopez      <alopez@ac.upc.edu>
 *
 */

#include "lispd_external.h"

void init_globales()
{
    router_mode                         = FALSE;
	map_resolvers						= NULL;
	ddt_client                          = FALSE;
	proxy_itrs							= NULL;
	proxy_etrs							= NULL;
	map_servers							= NULL;
	config_file							= NULL;
	map_request_retries 				= DEFAULT_MAP_REQUEST_RETRIES;
	control_port            			= LISP_CONTROL_PORT;
	debug_level             			= 0;
	daemonize               			= FALSE;
	ctrl_supported_afi                  = -1;
	default_rloc_afi        			= AF_UNSPEC;
	/* RLOC probing parameters */
	rloc_probe_interval                	= RLOC_PROBING_INTERVAL;
	rloc_probe_retries                 	= DEFAULT_RLOC_PROBING_RETRIES;
	rloc_probe_retries_interval       	= DEFAULT_RLOC_PROBING_RETRIES_INTERVAL;
	total_mappings                      = 0;
	netlink_fd                          = 0;
	ipv4_data_input_fd                  = 0;
	ipv6_data_input_fd                  = 0;
	ipv4_control_input_fd               = 0;
	ipv6_control_input_fd               = 0;
	timers_fd                       	= 0;

	/* NAT */

	nat_aware   					    = FALSE;
	nat_status  						= UNKNOWN;
    lispd_site_ID   site_ID             = {.byte = {0}};
    lispd_xTR_ID    xTR_ID              = {.byte = {0}};
	memset (&site_ID,0,sizeof(lispd_site_ID));
	memset (&xTR_ID,0,sizeof(lispd_xTR_ID));
	// Global variables used to store nonces of encapsulated map register and info request.
	// To be removed when NAT with multihoming supported.
	nat_emr_nonce  					= NULL;
	nat_ir_nonce   					= NULL;



	head_interface_list					= NULL;
	default_ctrl_iface_v4 				= NULL;
	default_ctrl_iface_v6				= NULL;
	default_out_iface_v4				= NULL;
	default_out_iface_v6				= NULL;
	smr_timer							= NULL;
	info_reply_ttl_timer                = NULL;


	memset (msg,0,sizeof(char)*128);
	memset (&dst_addr,0,sizeof(struct sockaddr_nl));
	memset (&src_addr,0,sizeof(struct sockaddr_nl));
	memset (&nlh,0,sizeof(nlsock_handle));
}
