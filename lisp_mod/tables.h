/*
 * tables.h
 *
 * This file is part of LISP Mobile Node Implementation.
 * Support and storage declarations for LISP EID maps and other
 * tables.
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

#include "linux/timer.h"
#include "lib/patricia/patricia.h"
#include "lisp_ipc.h"

#define TRAFFIC_MON_PERIOD (15)

/*
 * Table externs
 */
extern patricia_tree_t *AF4_eid_cache;
extern patricia_tree_t *AF6_eid_cache;

extern patricia_tree_t *AF4_eid_db;
extern patricia_tree_t *AF6_eid_db;


/******************************************
 * Map Cache Definitions
 ******************************************/

/*
 * Locator structure definition
 */
typedef struct _lisp_map_cache_loctype {
  lisp_addr_t   locator;
  uint8_t       priority;
  uint8_t       weight;
  uint8_t       mpriority;
  uint8_t       mweight;
  uint8_t       reachability_alg:2; /* rloc_prob | echo_none */
  uint8_t       state:1;            /* 1: up, 0: down */
  uint8_t       reserved:5; 
  uint32_t      data_packets_in;
  uint32_t      data_packets_out;
} lisp_map_cache_loc_t;

/*
 * EID Map cache entry
 */
#define MAX_LOCATORS 8
#define LOC_HASH_SIZE 25

typedef struct _lisp_map_cache_t {
  lisp_addr_t             eid_prefix;         /* EID Prefix */
  uint8_t                 eid_prefix_length;  /* length */
  uint8_t                 how_learned:1;      /* 0: static or 1: map-reply */
  uint8_t                 actions:2;           /* Defined in lisp_ipc.h */
  uint8_t                 locators_present:1; /* No locators: negative cache entry */
  uint8_t                 active_within_period:1; /* Traffic was tx/rx during monitor period */
  uint8_t                 reserved:3;         /* */
  uint32_t                nonce0;             /* 64 bit nonce */
  uint32_t                nonce1;             /*  "" */
  ushort                  ttl;                /* ttl for the whole mapping */
  uint32_t                sampling_interval;    /* how often to send a copy to lispd */
  uint32_t                timestamp;          /* entry creation time */
  struct timer_list       expiry_timer;       /* Expiration kernel timer */
  struct timer_list       smr_timer;       /* Sample to user space timer for SMR */
  struct timer_list       probe_timer;     /* Sample to user space timer for RLOC Probe */
  uint32_t                control_packets_in; 
  uint32_t                control_packets_out;
  uint32_t                lsb;                /* Locator status bits */
  uint32_t                count;
  lisp_map_cache_loc_t   *locator_list[MAX_LOCATORS];
  char                    locator_hash_table[25];
} lisp_map_cache_t;


/******************************************
 * Map Database Definitions
 ******************************************/

typedef struct _lisp_database_loc_t {
   lisp_addr_t    	locator;
   uint8_t		priority;
   uint8_t		weight;
   uint8_t		mpriority;
   uint8_t		mweight;
   uint8_t		state:4;		/* e.g., up, local */
   uint8_t		reserved:4;
} lisp_database_loc_t;

typedef struct _lisp_database_entry_t {
  lisp_addr_t    	  eid_prefix;		/* eid prefix */
   uint32_t	          eid_prefix_length;	/* length */
   ushort		  lsb;			/* local locator status bits */
   uint32_t		  timestamp;		/* when entry was created */
   int                    count;
   lisp_database_loc_t *locator_list[MAX_LOCATORS];		/* locators */
} lisp_database_entry_t;

/*
 * Function declarations
 */
void create_tables(void);
void add_eid_cache_entry(lisp_eid_map_msg_t *entry);
void update_locator_hash_table(lisp_map_cache_t *entry);
void del_eid_cache_entry(lisp_addr_t prefix, int prefixlen);
void add_eid_db_entry(lisp_db_add_msg_t *entry);
int lookup_eid_cache_v4(int, lisp_map_cache_t **);
int lookup_eid_cache_v4_exact(int eid, int prefixlen, lisp_map_cache_t **entry);
int lookup_eid_cache_v6_exact(lisp_addr_t eid_prefix, int prefixlen, lisp_map_cache_t **entry);
int lookup_eid_cache_v6(lisp_addr_t, lisp_map_cache_t **);
int lookup_eid_db_v4(int, lisp_database_entry_t **);
lisp_map_cache_loc_t *get_locator_for_eid(lisp_addr_t *, ushort *,
					  lisp_map_cache_t *);
void start_traffic_monitor(void);
void finish_traffic_monitor(unsigned long);
void update_locator_set_by_msg(lisp_cache_sample_msg_t *);
void clear_map_cache(lisp_cmd_t *cmd, int pid);
void teardown_trees(void);
