/*
 * lisp_ipc.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Implements message handling functions for communication
 * between the kerenl and user-level processes.
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

#include "lisp_mod.h"
#include "tables.h"

/*
 * Import symbols
 */
extern lisp_globals globals;
extern spinlock_t table_lock;

/*
 * Command types
 */
typedef void(*ipc_handler)(lisp_cmd_t *cmd, int pid);

struct ipc_handler_struct {
    const char    *description;
    ipc_handler    handler;
};

/*
 * Command table for IPC messages. This must
 * match the contents and order of the lisp_msgtype_e
 * enum defined in the header.
 */
const struct ipc_handler_struct ipc_table[] = {
    { "Ok", handle_no_action },
    { "Failed", handle_no_action },
    { "Map Cache Lookup", handle_map_cache_lookup },
    { "Map Cache EID List", handle_map_cache_list_request },
    { "Map Cache RLOC List", handle_map_cache_list_request },
    { "Database Lookup", handle_map_db_lookup },
    { "Cache Sample", handle_cache_sample },
    { "Set RLOC", handle_set_rloc },
    { "Add Map Cache Entry", handle_map_cache_add },
    { "Delete Map Cache", handle_no_action },
    { "Map Cache Clear", clear_map_cache },
    { "Add Database Entry", handle_map_db_add },
    { "Delete Database Entry", handle_map_db_delete },
    { "Register Daemon", handle_daemon_register },
    { "Start Traffic Monitor", handle_traffic_mon_start },
    { "Set UDP Ports", handle_set_udp_ports },
    { "Add Local EID", handle_add_eid }
};

/*
 * dump_message()
 * 
 * Debug facility to print the contents of a message as
 * as series of hexadecimal 32-bit words.
 * 
 * Length is in bytes.
 */
void dump_message(char *msg, int length)
{
  int words = length / sizeof(uint32_t);
  int i;

  printk(KERN_INFO "Lisp message dump:\n");
  for (i = 0; i < words; i++) { 
      printk(KERN_INFO "%08x: %02x %02x %02x %02x\n", i,  *msg,*(msg + 1), *(msg + 2), *(msg + 3));
      msg = msg + 4;
  }
}

int send_message(lisp_cmd_t *cmd, int length)
{
    return 0;
}

/*
 * send_command_complete_msg()
 *
 * Send a message to user-level client that the previous
 * command is complete.
 */
int send_command_complete_msg(int dstpid)
{
  struct nlmsghdr *nlh;
  lisp_cmd_t *cmd;
  /* PN
   * GFP_ATOMIC vs. GFP_KERNEL
   */
  //struct sk_buff *skb = alloc_skb(NLMSG_SPACE(MAX_MSG_LENGTH), GFP_KERNEL);
  struct sk_buff *skb = alloc_skb(NLMSG_SPACE(MAX_MSG_LENGTH), GFP_ATOMIC);
 
  if (!skb) {
    printk(KERN_INFO "Unable to allocate skb for response.\n");
    return -1;
  }
  nlh = (struct nlmsghdr *) skb_put(skb, NLMSG_SPACE(MAX_MSG_LENGTH));
  nlh->nlmsg_len            = NLMSG_SPACE(MAX_MSG_LENGTH);
  NETLINK_CB(skb).pid       = 0;    /* from kernel */
  NETLINK_CB(skb).dst_group = 0;    /* unicast */
  cmd                       = NLMSG_DATA(nlh);
  cmd->type                 = LispOk;
  cmd->length               = 0;

  netlink_unicast(globals.nl_socket, skb, dstpid, MSG_DONTWAIT);
  return 0;
}

/*
 * send_cache_miss_notification()
 *
 * Send a message to the registered lispd (if any)
 * that an EID lookup has failed in the forwarding
 * path.
 */
void send_cache_miss_notification(lisp_addr_t addr, short af)
{
  struct nlmsghdr *nlh;
  lisp_cmd_t *cmd;
  struct sk_buff *skb;
  lisp_cache_sample_msg_t *msg;
  int err;

  if (!globals.daemonPID) {
    printk(KERN_INFO "  No lispd process has registered, notification aborted.\n");
    return;
  } else {
    if (af == AF_INET) {
      printk(KERN_INFO "  Sending notification to %d for EID %pI4\n", globals.daemonPID, &addr.address.ip.s_addr);
    } else if (af == AF_INET6) {
      printk(KERN_INFO "  Sending notification to %d for EID %pI6\n", globals.daemonPID, addr.address.ipv6.s6_addr);
    }
  }

  /*
   * This operation CAN fail (because GFP_ATOMIC tries to allocate
   * memory quickly without much thought). If it does, we'll try again
   * on the next packet.
   */
  skb = alloc_skb(NLMSG_SPACE(MAX_MSG_LENGTH), GFP_ATOMIC);
  
  if (!skb) {
    printk(KERN_INFO "Unable to allocate skb for notification.\n");
    return;
  }
  nlh = (struct nlmsghdr *) skb_put(skb, NLMSG_SPACE(MAX_MSG_LENGTH));
  nlh->nlmsg_len            = NLMSG_SPACE(MAX_MSG_LENGTH);
  NETLINK_CB(skb).pid       = 0;    /* from kernel */
  NETLINK_CB(skb).dst_group = 0;    /* unicast */
  cmd                       = NLMSG_DATA(nlh);
  cmd->type                 = LispCacheSample;
  cmd->length               = sizeof(lisp_cache_sample_msg_t);

  msg = (lisp_cache_sample_msg_t *)cmd->val;
  msg->reason = CacheMiss;
  if (af == AF_INET) {
    msg->eid.address.ip.s_addr = addr.address.ip.s_addr;
    msg->eid.afi = af;
  } else if (af == AF_INET6) {
    memcpy(msg->eid.address.ipv6.s6_addr, addr.address.ipv6.s6_addr,
	   sizeof(lisp_addr_t));
    msg->eid.afi = af;
  }
  msg->num_locators = 0; // Cache miss message, EID only
  err = netlink_unicast(globals.nl_socket, skb, globals.daemonPID, 
			MSG_DONTWAIT);
  if (err < 0) {
    printk(KERN_INFO "Error sending to lispd. Clearing PID.\n");
    globals.daemonPID = 0;
  }
  return;
}

/*
 * send_cache_sample_notification()
 *
 * Send a message to the registered lispd with details
 * of the given eid cache entry. Primarily intended
 * for RLOC-probing. TBD: Check if all locators should be included
 * for SMR'ing.
 */
void send_cache_sample_notification(lisp_map_cache_t *entry, sample_reason_e reason)
{
  struct nlmsghdr *nlh;
  lisp_cmd_t *cmd;
  struct sk_buff *skb;
  lisp_cache_sample_msg_t *msg;
  lisp_map_cache_loc_t *loc;
  int i;
  int err;

  if (!globals.daemonPID) {
    printk(KERN_INFO "  No lispd process has registered, sample notification aborted.\n");
    return;
  } else {
    if (entry->eid_prefix.afi == AF_INET) {
      printk(KERN_INFO "  Sending sample to %d for EID %pI4\n", globals.daemonPID, &entry->eid_prefix.address.ip.s_addr);
    } else if (entry->eid_prefix.afi == AF_INET6) {
      printk(KERN_INFO "  Sending sample to %d for EID %pI6\n", globals.daemonPID, &entry->eid_prefix.address.ipv6.s6_addr);
    }
  }

  /*
   * This operation CAN fail (because GFP_ATOMIC tries to allocate
   * memory quickly without much thought). If it does, we'll try again
   * on the next packet.
   */
  skb = alloc_skb(NLMSG_SPACE(MAX_MSG_LENGTH), GFP_ATOMIC);

  if (!skb) {
    printk(KERN_INFO "Unable to allocate skb for notification.\n");
    return;
  }
  nlh = (struct nlmsghdr *) skb_put(skb, NLMSG_SPACE(MAX_MSG_LENGTH));
  nlh->nlmsg_len            = NLMSG_SPACE(MAX_MSG_LENGTH);
  NETLINK_CB(skb).pid       = 0;    /* from kernel */
  NETLINK_CB(skb).dst_group = 0;    /* unicast */
  cmd                       = NLMSG_DATA(nlh);
  cmd->type                 = LispCacheSample;
  cmd->length               = sizeof(lisp_cache_sample_msg_t) + sizeof(lisp_addr_t) * entry->count;

  msg = (lisp_cache_sample_msg_t *)cmd->val;
  msg->reason = reason;
  msg->eid_prefix_length = entry->eid_prefix_length;

  msg->eid.afi = entry->eid_prefix.afi;
  memcpy(&msg->eid.address, &entry->eid_prefix.address, sizeof(lisp_addr_t));

  msg->num_locators = entry->count;

  /*
   * Populate the locators
   */
  for (i = 0; i < entry->count; i++) {
    loc = entry->locator_list[i];

    memcpy(&msg->locators[i].address,
           &loc->locator.address,
           sizeof(lisp_addr_t));

    msg->locators[i].afi = loc->locator.afi;
  }

  err = netlink_unicast(globals.nl_socket, skb, globals.daemonPID,
                        MSG_DONTWAIT);
  if (err < 0) {
    printk(KERN_INFO "Error sending to lispd. Clearing PID.\n");
    globals.daemonPID = 0;
  }
  return;
}

/*
 * send_cache_lookup_response_msg()
 *
 * Send a response message to user-level clients for
 * a cache lookup.
 */
int send_cache_lookup_response_msg(lisp_map_cache_t *entry, int dstpid)
{
  struct nlmsghdr       *nlh;
  lisp_cmd_t            *cmd;
  /* PN
   * GFP_ATOMIC vs. GFP_KERNEL
   */
  //struct sk_buff        *skb = alloc_skb(NLMSG_SPACE(MAX_MSG_LENGTH), GFP_KERNEL);
  struct sk_buff        *skb = alloc_skb(NLMSG_SPACE(MAX_MSG_LENGTH), GFP_ATOMIC);
  int                        max_locators;
  lisp_cache_response_loc_t *tmp_loc;
  lisp_map_cache_loc_t      *locator;
  int                        loc_count = 0, err = 0;
  lisp_cache_response_msg_t *map_msg;

  if (!skb) {
    printk(KERN_INFO "Unable to allocate skb for response.\n");
    return -1;
  }

  max_locators = (MAX_MSG_LENGTH - sizeof(lisp_cache_response_msg_t)) /
    sizeof(lisp_cache_response_loc_t);

  // Instead of just pointing to skb data, must do a put()
  nlh = (struct nlmsghdr *) skb_put(skb, NLMSG_SPACE(MAX_MSG_LENGTH));
  NETLINK_CB(skb).pid       = 0;      /* from kernel */
  NETLINK_CB(skb).dst_group = 0;  /* unicast */
  
  nlh->nlmsg_len            = NLMSG_SPACE(MAX_MSG_LENGTH);
  cmd                       = NLMSG_DATA(nlh);
  cmd->type                 = LispMapCacheLookup;
  cmd->length               = sizeof(lisp_eid_map_msg_t); // XXX reflect locators
  map_msg  = (lisp_cache_response_msg_t *)cmd->val;
  
  memcpy(&map_msg->eid_prefix, &entry->eid_prefix,
     sizeof(lisp_addr_t));
  map_msg->eid_prefix_length = entry->eid_prefix_length;
  map_msg->ttl         = entry->ttl;
  map_msg->how_learned = entry->how_learned;
  map_msg->nonce0      = entry->nonce0;
  map_msg->nonce1      = entry->nonce1;
  map_msg->lsb         = entry->lsb;
  map_msg->timestamp   = entry->timestamp;
  map_msg->control_packets_in  = entry->control_packets_in;
  map_msg->control_packets_out = entry->control_packets_out;

  /*
   * Walk the locator list and fill in the locator entries.
   */
  for (loc_count = 0; loc_count < entry->count; loc_count++) {
      tmp_loc = map_msg->locators + loc_count;
      locator = entry->locator_list[loc_count];
      if (locator) {
          memcpy(&tmp_loc->locator, &locator->locator, sizeof(lisp_addr_t));
          tmp_loc->priority = locator->priority;
          tmp_loc->weight = locator->weight;
          tmp_loc->mpriority = locator->mpriority;
          tmp_loc->mweight = locator->mweight;
          tmp_loc->reachability_alg = locator->reachability_alg;
          tmp_loc->state = locator->state;
          tmp_loc->data_packets_in = locator->data_packets_in;
          tmp_loc->data_packets_out = locator->data_packets_out;
      }
  }
  map_msg->num_locators = entry->count;
  printk(KERN_INFO " Added %d locators\n", entry->count);
  printk(KERN_INFO " Sending response to %d\n", dstpid);

  err =  netlink_unicast(globals.nl_socket, skb, dstpid, MSG_DONTWAIT);
  printk(KERN_INFO " netlink_unicast() returned %d\n", err);
  return 0;
}

/*
 * send_db_lookup_response_msg()
 *
 * Send a response message to user-level clients for
 * a cache lookup.
 */
int send_db_lookup_response_msg(lisp_database_entry_t *entry, int dstpid)
{
  struct nlmsghdr       *nlh;
  lisp_cmd_t                *cmd;
  /* PN
   * GFP_ATOMIC vs. GFP_KERNEL
   */
  //struct sk_buff        *skb = alloc_skb(NLMSG_SPACE(MAX_MSG_LENGTH), GFP_KERNEL);
  struct sk_buff        *skb = alloc_skb(NLMSG_SPACE(MAX_MSG_LENGTH), GFP_ATOMIC);
  int                    err;
  int                        max_locators;
  lisp_database_loc_t       *locator;
  lisp_db_response_loc_t    *tmp_loc;
  int                        loc_count = 0;
  lisp_db_response_msg_t    *map_msg;

  if (!skb) {
    printk(KERN_INFO "Unable to allocate skb for response.\n");
    return -1;
  }

  max_locators = (MAX_MSG_LENGTH - sizeof(lisp_db_response_msg_t)) /
    sizeof(lisp_db_response_loc_t);

  // Instead of just pointing to skb data, must do a put()
  nlh = (struct nlmsghdr *) skb_put(skb, NLMSG_SPACE(MAX_MSG_LENGTH));
  NETLINK_CB(skb).pid       = 0;      /* from kernel */
  NETLINK_CB(skb).dst_group = 0;  /* unicast */
  
  nlh->nlmsg_len            = NLMSG_SPACE(MAX_MSG_LENGTH);
  cmd                       = NLMSG_DATA(nlh);
  cmd->type                 = LispDatabaseLookup;
  cmd->length               = sizeof(lisp_eid_map_msg_t);
  map_msg  = (lisp_db_response_msg_t *)cmd->val;
  
  memcpy(&map_msg->eid_prefix, &entry->eid_prefix,
     sizeof(lisp_addr_t));
  map_msg->eid_prefix_length = entry->eid_prefix_length;
  map_msg->lsb = entry->lsb;

  /*
   * Walk the locator list and fill in the locator entries.
   */
  for (loc_count = 0; loc_count < entry->count; loc_count++) {
      tmp_loc = map_msg->locators + loc_count;
      locator = entry->locator_list[loc_count];
      if (locator) {
          memcpy(&tmp_loc->locator, &locator->locator, sizeof(lisp_addr_t));
          tmp_loc->priority = locator->priority;
          tmp_loc->weight = locator->weight;
          tmp_loc->mpriority = locator->mpriority;
          tmp_loc->mweight = locator->mweight;
      }
  }
  map_msg->num_locators = entry->count;

  printk(KERN_INFO " Added %d locators\n", loc_count);
  printk(KERN_INFO " Sending response to %d\n", dstpid);

  err =  netlink_unicast(globals.nl_socket, skb, dstpid, MSG_DONTWAIT);
  printk(KERN_INFO " netlink_unicast() returned %d\n", err);
  return 0;
}

/*
 * handle_map_cache_lookup()
 *
 * Process a cache lookup request message from user-level
 */
void handle_map_cache_lookup(lisp_cmd_t *cmd, int pid)
{
  patricia_node_t *node;
  lisp_map_cache_t *map_entry = NULL;
  lisp_lookup_msg_t *lu_msg = (lisp_lookup_msg_t *)cmd->val;

  spin_lock_bh(&table_lock);

  /*
   * Exact match request? Do the lookup and send a single
   * response
   */
  if (!lu_msg->all_entries) {
      switch (lu_msg->prefix.afi) {
            case AF_INET:
                 if (lu_msg->exact_match) {
                     lookup_eid_cache_v4_exact(lu_msg->prefix.address.ip.s_addr,
                                               lu_msg->prefix_length,
                                               &map_entry);
                 } else {
                     lookup_eid_cache_v4(lu_msg->prefix.address.ip.s_addr, &map_entry);
                 }
                 break;
           case AF_INET6:
                if (lu_msg->exact_match) {
                    lookup_eid_cache_v6_exact(lu_msg->prefix,
                                              lu_msg->prefix_length,
                                              &map_entry);
                } else {
                    lookup_eid_cache_v6(lu_msg->prefix, &map_entry);
                }
                break;
      }
      if (map_entry != NULL) {
          send_cache_lookup_response_msg(map_entry, pid);
      }
  } else {

      /*
       * Walk the cache patricia trie and send a message back
       * for each entry.
       */
      PATRICIA_WALK(AF4_eid_cache->head, node) {
          map_entry = node->data;
          printk(KERN_INFO "at node %pi4/%d @0x%x\n",
                 &(node->prefix->add.sin.s_addr),
                 node->prefix->bitlen,
                 (unsigned) map_entry);
          if (map_entry)
              send_cache_lookup_response_msg(map_entry, pid);
      } PATRICIA_WALK_END;

      PATRICIA_WALK(AF6_eid_cache->head, node) {
          map_entry = node->data;
          printk(KERN_INFO "at node %pi6/%d @0x%x\n",
                 node->prefix->add.sin6.s6_addr,
                 node->prefix->bitlen,
                 (unsigned) map_entry);
          if (map_entry)
              send_cache_lookup_response_msg(map_entry, pid);
      } PATRICIA_WALK_END;
  }
  spin_unlock_bh(&table_lock);

  /*
   * Notify the client that the walk is complete
   */
  send_command_complete_msg(pid);
}

/*
 * allocate_nl_buffer()
 *
 * Allocate a new skb and form a netlink hdr around it.
 * Return a pointer to the skb and modify the passed in
 * pointer to refer to the user data area.
 */
 struct sk_buff *allocate_nl_buffer(lisp_cmd_t **cmd, lisp_msgtype_e type, int len)
 {
     struct sk_buff *skb = alloc_skb(NLMSG_SPACE(MAX_MSG_LENGTH), GFP_ATOMIC);
     struct nlmsghdr *nlh;

     if (!skb) {
        printk(KERN_INFO "Failed to allocate skb for %s message", ipc_table[type].description);
        return NULL;
     }
     nlh = (struct nlmsghdr *) skb_put(skb, NLMSG_SPACE(MAX_MSG_LENGTH));
     nlh->nlmsg_len            = NLMSG_SPACE(MAX_MSG_LENGTH);
     NETLINK_CB(skb).pid       = 0;    /* from kernel */
     NETLINK_CB(skb).dst_group = 0;    /* unicast */
     *cmd                       = NLMSG_DATA(nlh);
     (*cmd)->type                 = type;
     (*cmd)->length               = len;

     return (skb);
 }

 /*
  * build_eid_list_entry()
  *
  * Place a single eid address in the eid list for a message
  */
 bool build_eid_list_entry(int *count, struct sk_buff **skb, int dstpid, lisp_cmd_t **cmd,
                           lisp_addr_t *addr)
 {
     int err;
     int max_entries = (MAX_MSG_LENGTH - (sizeof(lisp_cmd_t) + sizeof(lisp_cache_address_list_t))) /
                                                 sizeof(lisp_addr_t);
     lisp_cache_address_list_t *eidlist = (lisp_cache_address_list_t *)(*cmd)->val;

     if (*count == max_entries) {
         printk("Entries exceeds single message size, sending current and building new");
         (*cmd)->length = sizeof(lisp_cache_address_list_t) + sizeof(lisp_addr_t) * (*count);
         eidlist->count = *count;
         err = netlink_unicast(globals.nl_socket, *skb, dstpid, MSG_DONTWAIT);
         if (err < 0) {
             printk(KERN_INFO "Error sending to lispd. Clearing PID.\n");
             globals.daemonPID = 0;
             return false;
         }

         /* Grab a new buffer */
         *count = 0;
         *skb = allocate_nl_buffer(cmd, LispMapCacheEIDList, 0); // Set length later
         if (!*skb) {
             return false; // Client can retry on schedule.
         }
         eidlist = (lisp_cache_address_list_t *)(*cmd)->val;
     }
     (*count)++;
     memcpy(&eidlist->addr_list[*count - 1], addr,
            sizeof(lisp_addr_t));
     return true;
 }

 /*
  * build_rloc_list_entry()
  *
  * Place a single rloc address in the list for a message
  */
 bool build_rloc_list_entry(int *count, struct sk_buff **skb, int dstpid, lisp_cmd_t **cmd,
                            lisp_map_cache_t *entry)
 {
     int err;
     int i;
     int max_entries = (MAX_MSG_LENGTH - (sizeof(lisp_cmd_t) + sizeof(lisp_cache_address_list_t))) /
                                                 sizeof(lisp_addr_t);
     lisp_cache_address_list_t *rloclist = (lisp_cache_address_list_t *)(*cmd)->val;

     for (i = 0; i < entry->count; i++) {
         if (*count == max_entries) {
             printk("Entries exceeds single message size, sending current and building new");
             (*cmd)->length = sizeof(lisp_cache_address_list_t) + sizeof(lisp_addr_t) * (*count);
             rloclist->count = *count;
             err = netlink_unicast(globals.nl_socket, *skb, dstpid, MSG_DONTWAIT);
             if (err < 0) {
                 printk(KERN_INFO "Error sending to lispd. Clearing PID.\n");
                 globals.daemonPID = 0;
                 return false;
             }

             /* Grab a new buffer */
             *count = 0;
             *skb = allocate_nl_buffer(cmd, LispMapCacheRLOCList, 0); // Set length later
             if (!*skb) {
                 return false; // Client can retry on schedule.
             }
             rloclist = (lisp_cache_address_list_t *)(*cmd)->val;
         }
         (*count)++;
         memcpy(&rloclist->addr_list[*count - 1], &entry->locator_list[i]->locator,
                sizeof(lisp_addr_t));
     }
     return true;
 }

/*
 * send_map_cache_list()
 *
 * Provide a list of all EIDs or RLOCs in all address families
 * currently in the map cache, addresses and AFIs only.
 */
void send_map_cache_list(int dstpid, uint16_t request_type,
                                   char with_traffic_only)
{
    patricia_node_t *node;
    lisp_map_cache_t *map_entry = NULL;
    lisp_cmd_t *cmd;
    int addr_count = 0;
    struct sk_buff *skb;
    int    err;

    skb = allocate_nl_buffer(&cmd, request_type, 0); // Set length later
    if (!skb) {
        return; // Client can retry on schedule.
    }
    spin_lock_bh(&table_lock);

    /*
     * Walk the cache patricia trie and build a
     * message containing the list of addresses
     * of each EID entry.
     */
    PATRICIA_WALK(AF4_eid_cache->head, node) {
        map_entry = node->data;
        printk(KERN_INFO "at node %pi4/%d @0x%x\n",
               &(node->prefix->add.sin.s_addr),
               node->prefix->bitlen,
               (unsigned) map_entry);

        if (request_type == LispMapCacheEIDList) {
            if (!build_eid_list_entry(&addr_count, &skb, dstpid, &cmd,
                                      &map_entry->eid_prefix)) {
                return;
            }
        } else if (request_type == LispMapCacheRLOCList) {

            /*
             * If for traffic monitoring function, only add those
             * entries that had traffic.
             */
            if (!(with_traffic_only && !map_entry->active_within_period)) {
                if (!build_rloc_list_entry(&addr_count, &skb, dstpid, &cmd,
                                           map_entry)) {
                    return;
                }
            }
        } else {
            printk(KERN_INFO "Unknown map cache request type %d\n", request_type);
            return;
        }
    } PATRICIA_WALK_END;

    PATRICIA_WALK(AF6_eid_cache->head, node) {
        map_entry = node->data;
        printk(KERN_INFO "at node %pi6/%d @0x%x\n",
               node->prefix->add.sin6.s6_addr,
               node->prefix->bitlen,
               (unsigned) map_entry);

        if (request_type == LispMapCacheEIDList) {
            if (!build_eid_list_entry(&addr_count, &skb, dstpid, &cmd,
                                      &map_entry->eid_prefix)) {
                return;
            }
        } else if (request_type == LispMapCacheRLOCList) {

            /*
             * If for traffic monitoring function, only add those
             * entries that had traffic.
             */
            if (!(with_traffic_only && !map_entry->active_within_period)) {
                if (!build_rloc_list_entry(&addr_count, &skb, dstpid, &cmd,
                                           map_entry)) {
                    return;
                }
            }
        } else {
            printk(KERN_INFO "Unknown map cache request type %d\n", request_type);
            return;
        }
    } PATRICIA_WALK_END;

    /*
     * If any are left after the above run, send them out
     */
    if (addr_count) {
        printk("Sending map-cache list to lispd with %d entries.", addr_count);
        ((lisp_cache_address_list_t *)(cmd->val))->count = addr_count;
        cmd->length = sizeof(lisp_cache_address_list_t) + sizeof(lisp_addr_t) * (addr_count);
        err = netlink_unicast(globals.nl_socket, skb, dstpid, MSG_DONTWAIT);
        if (err < 0) {
            printk(KERN_INFO "Error sending to lispd. Clearing PID.\n");
            globals.daemonPID = 0;
            return;
        }
    }

    spin_unlock_bh(&table_lock);

    /*
     * Notify the client that the list is complete
     */
    send_command_complete_msg(dstpid);
}

/*
 * handle_map_cache_list_request()
 *
 * Respond to a cache list request from a process-level client
 */
void handle_map_cache_list_request(lisp_cmd_t *cmd, int srcpid)
{
    send_map_cache_list(srcpid, cmd->type, 0);
}

/*
 * handle_map_db_delete()
 *
 * Delete a mapping entry, locator or set of locators
 * from the database.
 */
void handle_map_db_delete(lisp_cmd_t *cmd, int length)
{
  return;
}


/*
 * handle_map_db_lookup()
 *
 * Process a databse lookup request message from user-level
 */
void handle_map_db_lookup(lisp_cmd_t *cmd, int pid)
{
  patricia_node_t *node;
  lisp_database_entry_t *db_entry;

  /*
   * Walk the cache patricia trie and send a message back
   * for each entry.
   */
  spin_lock_bh(&table_lock);
  PATRICIA_WALK(AF4_eid_db->head, node) {
    db_entry = node->data;
    printk(KERN_INFO "at node %pi4/%d @0x%x\n",
       &(node->prefix->add.sin.s_addr),
       node->prefix->bitlen,
       (unsigned) db_entry);
    if (db_entry)
      send_db_lookup_response_msg(db_entry, pid);
    } PATRICIA_WALK_END;
  
  PATRICIA_WALK(AF6_eid_db->head, node) {
    db_entry = node->data;
    printk(KERN_INFO "at node %pi6/%d @0x%x\n",
	   node->prefix->add.sin6.s6_addr,
	   node->prefix->bitlen,
	   (unsigned) db_entry);
    if (db_entry)
      send_db_lookup_response_msg(db_entry, pid);
  } PATRICIA_WALK_END;
  spin_unlock_bh(&table_lock);

  /*
   * Notify the client that the walk is complete
   */
  send_command_complete_msg(pid);
}

/*
 * handle_map_cache_add()
 *
 * Process an eid mapping message from user-level
 */
void handle_map_cache_add(lisp_cmd_t *cmd, int pid)
{
    int entries;
    lisp_eid_map_msg_t     *current_entry;
    lisp_eid_map_msg_loc_t *current_loc;
    char eid_str[128];
    char loc_str[128];
    int i;
  
    printk(KERN_INFO "   Contains %d mapping(s)", entries);
  
    /*
     * Dump the info for each entry to the kernel log
     */
    current_entry = (lisp_eid_map_msg_t *)cmd->val;
    if (current_entry->eid_prefix.afi == AF_INET) {
        snprintf(eid_str, 128, "  %pi4/%d -> ",
                 &(current_entry->eid_prefix.address.ip.s_addr),
                 current_entry->eid_prefix_length);
    } else if (current_entry->eid_prefix.afi == AF_INET6) {
        snprintf(eid_str, 128, " %pi6/%d ->",
                 current_entry->eid_prefix.address.ipv6.s6_addr,
                 current_entry->eid_prefix_length);
    } else {
        printk(KERN_INFO "     Unknown address family %d, skipping\n",
               current_entry->eid_prefix.afi);
        return;
    }

    entries = current_entry->count;

    printk(KERN_INFO "   Contains %d locators(s)\n", entries);

    for (i = 0; i < entries; i++) {
        current_loc = (lisp_eid_map_msg_loc_t *)(current_entry->locators + i * sizeof(lisp_eid_map_msg_loc_t));
        if (current_loc->locator.afi == AF_INET) {
            snprintf(loc_str, 128, " to %pi4",
                     &current_loc->locator.address.ip.s_addr);
        } else if (current_loc->locator.afi == AF_INET6) {
            snprintf(loc_str, 128, " to %pi6",
                     current_loc->locator.address.ipv6.s6_addr);
        } else {
            printk(KERN_INFO " Unknown locator address family %d, skipping\n",
                   current_loc->locator.afi);
            continue;
        }
        printk(KERN_INFO "%s%s, (%d, %d)\n",
               eid_str, loc_str,
               current_loc->priority,
               current_loc->weight);
    }
    if (!i) {
        printk(KERN_INFO "Negative cache entry\n");
    }
    add_eid_cache_entry(current_entry);
    return;
}

/*
 * handle_map_db_add()
 *
 * Process an eid database mapping message from user-level
 */
void handle_map_db_add(lisp_cmd_t *cmd, int length)
{
    lisp_db_add_msg_t *current_entry;
    lisp_db_add_msg_loc_t *loc;
    char eid_str[128];
    char loc_str[128];
    int i;
  
    /*
     * Dump the info for each entry to the kernel log
     */
    current_entry = (lisp_db_add_msg_t *)cmd->val;
    if (current_entry->eid_prefix.afi == AF_INET) {
      snprintf(eid_str, 128, "  %pi4/%d -> ", 
           &(current_entry->eid_prefix.address.ip.s_addr),
           current_entry->eid_prefix_length);
    } else if (current_entry->eid_prefix.afi == AF_INET6) {
      snprintf(eid_str, 128, " %pi6/%d ->",
           current_entry->eid_prefix.address.ipv6.s6_addr,
           current_entry->eid_prefix_length);
    } else {
      printk(KERN_INFO " Unknown address family %d, skipping", 
         current_entry->eid_prefix.afi);
      return;
    }

    for (i = 0; i < current_entry->count; i++) {
        loc = (lisp_db_add_msg_loc_t *)(current_entry->locators + i * sizeof(lisp_db_add_msg_loc_t));
        if (loc->locator.afi == AF_INET) {
            snprintf(loc_str, 128, " to %pi4",
                     &loc->locator.address.ip.s_addr);
        } else if (loc->locator.afi == AF_INET6) {
            snprintf(loc_str, 128, " to %pi6",
                     loc->locator.address.ipv6.s6_addr);
        } else {
            printk(KERN_INFO " Unknown locator address family %d!",
                   loc->locator.afi);
            sprintf(loc_str, "N/A");
        }
        printk(KERN_INFO "%s%s, (%d, %d)",
               eid_str, loc_str,
               loc->priority,
               loc->weight);
    }
    add_eid_db_entry(current_entry);
}

/*
 * handle_set_rloc()
 *
 * Set our local rloc to the address provided in the message.
 * This is used as the source address of all encapsulated packets.
 */
void handle_set_rloc(lisp_cmd_t *cmd, int pid)
{
  lisp_set_rloc_msg_t *msg = (lisp_set_rloc_msg_t *)cmd->val;

  if (msg->addr.afi == AF_INET) {
    globals.my_rloc.address.ip.s_addr = msg->addr.address.ip.s_addr;
    globals.my_rloc_af = msg->addr.afi;
    printk(KERN_INFO "  Set to %pI4\n", &globals.my_rloc.address.ip.s_addr);
  } else {
    if (msg->addr.afi == AF_INET6) {
      memcpy(globals.my_rloc.address.ipv6.s6_addr, 
	     msg->addr.address.ipv6.s6_addr,
	     sizeof(lisp_addr_t));
      globals.my_rloc_af = msg->addr.afi;
      printk(KERN_INFO "  Set to %pI6\n", globals.my_rloc.address.ipv6.s6_addr);
    } else {
      printk(KERN_INFO "Unknown AF %d in set rloc message\n", msg->addr.afi);
    }
  }
}

/*
 * handle_cache_sample()
 *
 * Process a reponse to our cache sample message, containing
 * marked status for locators.
 */
void handle_cache_sample(lisp_cmd_t *cmd, int srcpid)
{
    lisp_cache_sample_msg_t *msg;

    msg = (lisp_cache_sample_msg_t *)cmd->val;

    if (msg->eid.afi == AF_INET) {
        printk(KERN_INFO "Received returned cache sample message for EID %pI4/%d\n",
               &msg->eid.address, msg->eid_prefix_length);
    } else if (msg->eid.afi == AF_INET6) {
        printk(KERN_INFO "Received returned cache sample message for EID %pI6/%d\n",
               msg->eid.address.ipv6.s6_addr, msg->eid_prefix_length);
    } else {
        printk(KERN_INFO "Received returned cache sample message for EID with unknown AFI");
        return;
    }

    update_locator_set_by_msg(msg);
}

/*
 * handle_traffic_mon_start
 *
 * Start the traffic monitoring timer, and mark the current
 * cache entries with their traffic stats so we can compare
 * later.
 */
void handle_traffic_mon_start(lisp_cmd_t *cmd, int pid) {
    start_traffic_monitor();
}

/*
 * handle_set_udp_ports
 *
 * lispd is informing us that the udp ports have changed, update
 * our values.
 */
void handle_set_udp_ports(lisp_cmd_t *cmd, int pid) {
    lisp_set_ports_msg_t *msg = (lisp_set_ports_msg_t *)cmd->val;

    globals.udp_encap_port = msg->data_port;
    globals.udp_control_port = msg->control_port;
    printk(KERN_INFO "Set UDP ports to %d (control), %d (encap)",
           globals.udp_control_port, globals.udp_encap_port);
}


/*
 * handle_daemon_register()
 *
 * Accept a new lispd registration and cache
 * it's pid for later communication.
 */
void handle_daemon_register(lisp_cmd_t *cmd, int pid)
{
    if (globals.daemonPID != 0) {
        printk(KERN_INFO "   Warning, a lisp daemon was already registered, replacing PID\n");
    }
    globals.daemonPID = pid;
}

/*
 * handle_no_action()
 *
 * Generic handler for messages we either don't take action on or don't
 * support.
 */
void handle_no_action(lisp_cmd_t *cmd, int pid)
{
    printk(KERN_INFO "  No action taken for this message type.");
}


/*
 * handle_add_local_eid()
 *
 * Adds EID to the list of source eids to verify before encapsulating.
 */
void handle_add_eid(lisp_cmd_t *cmd, int pid)
{
	lisp_add_local_eid_msg_t *msg = (lisp_add_local_eid_msg_t *)cmd->val;
	int index=0;
	printk(KERN_INFO "Trying to add EID for data plane verification\n");
	for(index=0;index<globals.num_local_eid;index++){
		//compare address types
		if (msg->addr.afi == globals.local_eid_list[index].afi) {
			//compare addresses
			if (msg->addr.afi == AF_INET) {
				if(globals.local_eid_list[index].address.ip.s_addr==msg->addr.address.ip.s_addr){
					//is in list at position index
					break;
				}
			}
			if (msg->addr.afi == AF_INET6) {
				if(!ipv6_addr_equal(&(globals.local_eid_list[index].address.ipv6),&(msg->addr.address.ipv6))){
					//is in list at position index
					break;
				}
			}
		}
	}
	if(index==globals.num_local_eid && index<MAXLOCALEID){
		globals.local_eid_list[index]=msg->addr;
		globals.num_local_eid++;
		if (msg->addr.afi == AF_INET) {
			printk(KERN_INFO "The EID is new: %pI4. Added to position %d\n", &(globals.local_eid_list[index].address.ip.s_addr),index);
		}
	}
}

/*
 * lisp_netlink_input()
 *
 * Message entry point for LISP user-space to kernel module
 * control processing. 
*/
void lisp_netlink_input(struct sk_buff *skb)
{ 

  struct nlmsghdr *nlh = NULL;
  int lispmsglen       = 0;
  int pid;
  lisp_cmd_t *cmd;
    
  nlh        = (struct nlmsghdr *)(skb->data);
  cmd        = (lisp_cmd_t *)NLMSG_DATA(nlh);
  pid        = NETLINK_CB(skb).pid;
  lispmsglen = nlh->nlmsg_len - NLMSG_HDRLEN;

  printk(KERN_INFO "  Received netlink input, PID %d, len %d.\n",
     pid, lispmsglen);

#ifdef DEBUG
  dump_message((char *)cmd, lispmsglen);
#endif

  if (cmd->type <= LispMaxType) {
      printk(KERN_INFO "  Got %s message.\n", ipc_table[cmd->type].description);
  } else {
      printk(KERN_INFO "  Message type out of range: %d\n", cmd->type);
  }

  /*
   * Call the handler from the table
   */
  (*(ipc_table[cmd->type].handler))(cmd, pid);
  return;
}

/* 
 * setup_netlink_socket
 *
 * Create the netlink socket through which user-level process
 * can communicate with the module. Configuration and status
 * messages traverse this channel.
 */
int setup_netlink_socket(void)
{ 

  // Set up the socket in the init network namespace
  globals.nl_socket = netlink_kernel_create(&init_net, NETLINK_LISP, 0,
                        lisp_netlink_input, NULL, THIS_MODULE);

  if (globals.nl_socket != NULL) {
    printk(KERN_INFO "  Netlink socket created.\n");
    return 0;
  } else {
    printk(KERN_INFO "  Failed to create Netlink socket.\n");
    return -1;
  }
}

/*
 * teardown_netlink_socket
 *
 * Disconnect the netlink socket
 */
void teardown_netlink_socket(void) {
  netlink_kernel_release(globals.nl_socket);
  return;
}

