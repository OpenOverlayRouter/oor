/*
 * lisp_ipc.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Defines the message structure for lisp ipc messages.
 * These messages can be used to communicate between
 * lisp user-level processes and the kernel, for example.
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
 *    David Meyer		<dmm@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *
 */

#pragma once

#ifdef KERNEL
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/in6.h>
#endif /* KERNEL */

/*
 * Constants
 */
#define MAX_MSG_LENGTH 1024  /* Max total message size. */

/*
 * XXX Temporary, needs to be in 
 * /usr/include/linux/netlink.h
 * formally.
 */
#define NETLINK_LISP 20 

/*
 * Lisp message types
 */
typedef enum {
  LispOk = 0,
  LispFailed = 1,
  LispMapCacheLookup = 2,
  LispMapCacheEIDList = 3,  // For ???
  LispMapCacheRLOCList = 4, // For SMR's
  LispDatabaseLookup = 5,
  LispCacheSample = 6,      /* Kernel to process-level */
  LispSetRLOC = 7,
  LispMapCacheAdd = 8,
  LispMapCacheDelete = 9,
  LispMapCacheClear = 10,
  LispDatabaseAdd = 11,
  LispDatabaseDelete = 12,
  LispDaemonRegister = 13,
  LispTrafficMonStart = 14,
  LispSetUDPPorts = 15,
  LispAddLocalEID = 16,
  LispMaxType = LispAddLocalEID
} lisp_msgtype_e;

/* 
 * Lisp address structure
 */
typedef struct {
  union {
    struct in_addr ip;
    struct in6_addr ipv6;
  } address;
  int afi;
} lisp_addr_t;

/*
 * Top level LISP message type, 
 * all other messages are placed inside.
 */
typedef struct _lisp_cmd {
  uint16_t type;
  uint16_t length; // No message can exceed MAX_MSG_LENGTH - nlmsghdr length
  char val[0];
} lisp_cmd_t;

/*
 * Convey the UDP ports to use for encapsulation
 * and controlto the kernel module. Sent by lispd.
 */
typedef struct {
    uint16_t data_port;
    uint16_t control_port;
} lisp_set_ports_msg_t;

typedef struct _lisp_lookup_msg {
  lisp_addr_t prefix;
  uint32_t    prefix_length;
  int         exact_match;
  int         all_entries;
} lisp_lookup_msg_t;

/*#ifndef LISPMOBMH
typedef struct _lisp_set_rloc_msg {
  lisp_addr_t addr;
} lisp_set_rloc_msg_t;

#else*/
/*
 * RLOC/ifindex mapping. if_index
 * of zero indicates default/single RLOC
 */
typedef struct {
    lisp_addr_t addr;
    int if_index;
} rloc_t;

typedef struct _lisp_set_rloc_msg {
    int count;
    rloc_t rlocs[0];
} lisp_set_rloc_msg_t;
//#endif

typedef struct _lisp_add_local_eid_msg {
  lisp_addr_t addr;
} lisp_add_local_eid_msg_t;


#define ACTION_DROP         0
#define ACTION_FORWARD      1
#define ACTION_SEND_MAP_REQ 2

/*
 * Locator portion of eid map msg
 */
typedef struct {
  lisp_addr_t locator;
  uint8_t priority;
  uint8_t weight;
  uint8_t mpriority;
  uint8_t mweight;
} lisp_eid_map_msg_loc_t;

/*
 * Message structure for adding a cache entry,
 * sent from user-space processes to the kernel.
 */
typedef struct {
  lisp_addr_t   eid_prefix;
  uint16_t      eid_prefix_length;
  uint8_t       count;
  uint8_t       actions; /* Defined above */
  uint16_t      how_learned; /* 0: static or 1: map-reply */
  uint32_t      ttl;
  uint32_t      sampling_interval; /* In seconds, 0 never sample */
  lisp_eid_map_msg_loc_t locators[0];
} lisp_eid_map_msg_t;

/*
 * Compact response types for parties only
 * interested in a list of RLOC's or EID's
 * currently in use (for SMR, rloc probe purposes).
 */
typedef struct {
    int cookie;               // opaque value passed back to lispd
    int count;
    lisp_addr_t addr_list[0];
} lisp_cache_address_list_t;

/*
 * Response type for a cache entry lookup,
 * sent from the kernel to user-space.
 */
typedef struct {
  lisp_addr_t   locator;
  uint8_t       priority;
  uint8_t       weight;
  uint8_t       mpriority;
  uint8_t       mweight;
  uint8_t       reachability_alg:2; /* rloc_prob | echo_none */
  uint8_t       state:1;
  uint8_t       reserved:5;
  uint32_t      data_packets_in;
  uint32_t      data_packets_out;
} lisp_cache_response_loc_t;

typedef struct {
  lisp_addr_t eid_prefix;
  uint8_t     eid_prefix_length;
  uint8_t     how_learned:1;
  uint8_t     complete:1;
  uint8_t     actions:2;
  uint8_t     locators_present:1;
  uint8_t     reserved:3;
  uint32_t    nonce0;
  uint32_t    nonce1;
  uint16_t    lsb;
  uint16_t    ttl;
  uint32_t    timestamp;
  uint32_t    control_packets_in;
  uint32_t    control_packets_out;
  uint8_t     num_locators;
  lisp_cache_response_loc_t locators[0];
} lisp_cache_response_msg_t;

/*
 * Message structure for adding a database entry,
 * sent from user-space to the kernel.
 */
typedef struct {
    lisp_addr_t locator;
    uint8_t     priority;
    uint8_t     weight;
    uint8_t     mpriority;
    uint8_t     mweight;
} lisp_db_add_msg_loc_t;

typedef struct {
  lisp_addr_t           eid_prefix;
  uint16_t              eid_prefix_length;
  uint16_t              count;
  lisp_db_add_msg_loc_t locators[0];
} lisp_db_add_msg_t;

/* 
 * Response type for a database entry lookup,
 * sent from the kernel to user-space.
 */
typedef struct {
  lisp_addr_t    locator;
  uint8_t        priority;
  uint8_t	 weight;
  uint8_t        mpriority;
  uint8_t	 mweight;
  uint8_t	 reserved:4;		
} lisp_db_response_loc_t;

typedef struct {
  lisp_addr_t    eid_prefix;
  uint8_t        eid_prefix_length;
  uint8_t        num_locators;
  uint16_t         lsb;
  lisp_db_response_loc_t locators[0];
} lisp_db_response_msg_t;

/* 
 * Database deletion message type. Sent
 * from user-space to the kernel.
 */
typedef struct {
  lisp_addr_t eid_prefix;
  uint8_t     eid_prefix_length;
  lisp_addr_t     locator;
} lisp_db_delete_msg_t;
  
/*
 * Cache miss or sampling notification, sent from kernel
 * to lispd. When sent with no locators, indicates cache
 * miss. Also sent *back* from lispd to the kernel
 * when an RLOC probe sequence is completed for an EID.
 * In this case, the status bits indicate the reachability
 * of the locators in the list.
 */
typedef enum {
    ProbeSample,
    SMRSample,
    CacheMiss
} sample_reason_e;

typedef struct {
  int         reason;
  lisp_addr_t eid;
  int         eid_prefix_length; /* Unused when cache miss */
  int         num_locators;      /* zero when cache miss */
  int         status_bits;       /* Bitfield filled by lispd when sending back to kernel */
  lisp_addr_t locators[0];
} lisp_cache_sample_msg_t;
