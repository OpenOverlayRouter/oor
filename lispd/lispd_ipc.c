/*
 *      lispd_ipc.c 
 *
 * This file is part of LISP Mobile Node Implementation.
 * Kernel IPC suport for the lispd
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
 *    David Meyer       <dmm@cisco.com>
 *    Vina Ermagan      <vermagan@cisco.com>
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

#include "lispd_external.h"

/*
 *  install_database_mapping --
 *
 *  Install a single database mapping entry in the kernel
 *
 */

/* TODO (LJ): lispd_db_entry_t should be updated to support multiple locators */
int install_database_mapping(db_entry)
    lispd_db_entry_t   *db_entry;
{

    size_t                  cmd_length = 0;
    int                     retval = 0;
    lisp_cmd_t              *cmd;
    lisp_db_add_msg_t       *map_msg;
    lisp_db_add_msg_loc_t   *map_msg_loc;
    uint16_t                loc_count  = 1; /* TODO: support for multiple locators */
    int i;

    cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_db_add_msg_t) +
                 sizeof(lisp_db_add_msg_loc_t) * loc_count;

    if ((cmd = malloc(cmd_length)) < 0) {
        syslog (LOG_DAEMON, "install_database_mapping(): memory allocation error");
        return(0);
    }

    memset((char *) cmd, 0, cmd_length);

    map_msg     = (lisp_db_add_msg_t *) CO(cmd, sizeof(lisp_cmd_t));
    map_msg_loc = (lisp_db_add_msg_loc_t *) CO(map_msg, sizeof(lisp_db_add_msg_t));

    cmd->type   = LispDatabaseAdd;
    cmd->length = cmd_length - sizeof(lisp_cmd_t);

    memcpy(&(map_msg->eid_prefix), &(db_entry->eid_prefix), sizeof(lisp_addr_t));
    map_msg->eid_prefix.afi    = db_entry->eid_prefix.afi;
    map_msg->eid_prefix_length = db_entry->eid_prefix_length;
    map_msg->count             = loc_count;

    /* XXX: code needs to be updated when lispd_db_entry_t supports more locators */
    for (i = 0; i < loc_count; i++) {
        memcpy(map_msg_loc + i * sizeof(lisp_db_add_msg_loc_t),
                &(db_entry->locator), sizeof(lisp_addr_t));

        map_msg->locators[i].locator.afi = db_entry->locator.afi;
        map_msg->locators[i].priority    = db_entry->priority;
        map_msg->locators[i].weight      = db_entry->weight;
        map_msg->locators[i].mpriority   = db_entry->mpriority;
        map_msg->locators[i].mweight     = db_entry->mweight;
    }

    retval = send_command(cmd, cmd_length + sizeof(lisp_cmd_t));
    free(cmd);
    return(retval);
}

/*
 *  install_database_mappings_afi --
 *
 *  Install per_afi database mappings into the kernel
 *
 */

int install_database_mappings_afi(tree)
    patricia_tree_t *tree;
{
    patricia_node_t     *node;
    lispd_locator_chain_t   *locator_chain      = NULL;
    lispd_locator_chain_elt_t   *locator_chain_elt  = NULL;
    lispd_db_entry_t        *db_entry           = NULL;
    int                 retval = 1;
   
    if (!tree)
    return(0);

    PATRICIA_WALK(tree->head, node) {
        locator_chain     = ((lispd_locator_chain_t *)(node->data));
        if (locator_chain)
            locator_chain_elt = locator_chain->head;
    while (locator_chain_elt) {
        db_entry = locator_chain_elt->db_entry;
        if (install_database_mapping(db_entry) < 0) {
        syslog(LOG_DAEMON,
               "  Could not install database mapping %s/%d->%s",
               locator_chain->eid_name,
               locator_chain->eid_prefix_length,
               locator_chain_elt->locator_name);
        retval = 0;         /* something wrong */
        } 
#ifdef  DEBUG
            else {
                debug_installed_database_entry(db_entry, locator_chain);
        }
#endif
        locator_chain_elt = locator_chain_elt->next;
    }
    } PATRICIA_WALK_END;
    return(retval);
}

/*
 *  install_database_mappings --
 *
 *  Install database mappings into the kernel
 *
 */


int install_database_mappings(void)
{

    syslog(LOG_DAEMON, "Installing database-mappings:");
    if (!install_database_mappings_afi(AF4_database))
    return(0);
    if (!install_database_mappings_afi(AF6_database))
    return(0);
    return(1);
}


/*
 *  install_map-cache_entries
 *
 *  Install static map-cache entries into the kernel
 *
 */

int install_map_cache_entries(void)
{
    lispd_map_cache_t       *map_cache_entry;
    lispd_map_cache_entry_t *mc_entry;
    int             afi; 
    int             retval;
    char            eid[128];
    char            rloc[128];
    char            buf[128];

    if (!lispd_map_cache)
    return(0);

    syslog(LOG_DAEMON, "installing static map-cache entries:");

    map_cache_entry = lispd_map_cache;
    while (map_cache_entry) {
    mc_entry = &(map_cache_entry->map_cache_entry);
    afi      = mc_entry->eid_prefix.afi;
    inet_ntop(afi,
          &(mc_entry->eid_prefix.address),
          eid,
          128);
    if (install_map_cache_entry(mc_entry) < 0) {
        syslog(LOG_DAEMON, " Could not install map-cache entry %s/%d->%s",
            eid,
            mc_entry->eid_prefix_length,
            mc_entry->locator_name);
        retval = 0;
    } else {
        inet_ntop(mc_entry->locator.afi,
              &(mc_entry->locator.address),
              rloc, 128);
#ifdef DEBUG
        if (mc_entry->locator_type == STATIC_LOCATOR)
        sprintf(buf, "%s", rloc);
        else
        sprintf(buf, "%s (%s)", mc_entry->locator_name, rloc);
        syslog(LOG_DAEMON, " installed %s lisp %s/%d %s p %d w %d",
            (afi == AF_INET) ? "ip":"ipv6",
            eid,
            mc_entry->eid_prefix_length, 
            buf,
            mc_entry->priority,
            mc_entry->weight);
#endif
        retval = 1;
    }
    map_cache_entry = map_cache_entry->next;
    }
    return(retval);
}

/*
 *  install_map_cache_entry --
 *
 *  Install a single map_cache entry in the kernel
 *
 */
 
/* TODO (LJ): lispd_map_cache_entry_t should be updated to support multiple locators */
int install_map_cache_entry(map_cache_entry)
    lispd_map_cache_entry_t   *map_cache_entry;
{

    size_t                  cmd_length = 0;
    int                     retval     = 0;
    lisp_cmd_t              *cmd;
    lisp_eid_map_msg_t      *map_msg;
    lisp_eid_map_msg_loc_t  *map_msg_loc;
    uint16_t                loc_count  = 1; /* TODO: support for multiple locators */
    int i;
 
    /*
     *  Handle Negative Map_Reply
     */
    /* XXX (LJ): locator_afi 0 is not the way to properly check for Neg. MRep */
    if(map_cache_entry->locator.afi == 0)
        loc_count = 0;
    else
        loc_count = 1;

    cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_eid_map_msg_t) +
                 sizeof(lisp_eid_map_msg_loc_t) * loc_count;

    if ((cmd = malloc(cmd_length)) < 0){
        syslog (LOG_DAEMON, "install_map_cache_entry(): memory allocation error");
        return(0);
    }

    memset((char *) cmd, 0, cmd_length);

    map_msg     = (lisp_eid_map_msg_t *) CO(cmd, sizeof(lisp_cmd_t));
    map_msg_loc = (lisp_eid_map_msg_loc_t *) CO(map_msg, sizeof(lisp_eid_map_msg_t));

    cmd->type   = LispMapCacheAdd;
    cmd->length = cmd_length - sizeof(lisp_cmd_t);

    memcpy(&(map_msg->eid_prefix), &(map_cache_entry->eid_prefix), sizeof(lisp_addr_t));
    map_msg->eid_prefix.afi    = map_cache_entry->eid_prefix.afi;
    map_msg->eid_prefix_length = map_cache_entry->eid_prefix_length;
    map_msg->count             = loc_count;
    map_msg->actions           = map_cache_entry->actions;
    map_msg->how_learned       = map_cache_entry->how_learned;
    map_msg->ttl               = map_cache_entry->ttl;
    map_msg->sampling_interval = RLOC_PROBING_INTERVAL;
    /* Don't RLOC probe PETRs */
    if (map_cache_entry->locator_type == PETR_LOCATOR)
        map_msg->sampling_interval = 0;

    /* XXX: code needs to be updated when lispd_map_cache_entry_t supports more locators */
    for (i = 0; i < loc_count; i++) {
        memcpy(map_msg_loc + i * sizeof(lisp_eid_map_msg_loc_t),
                &(map_cache_entry->locator), sizeof(lisp_addr_t));

        map_msg->locators[i].locator.afi = map_cache_entry->locator.afi;
        map_msg->locators[i].priority    = map_cache_entry->priority;
        map_msg->locators[i].weight      = map_cache_entry->weight;
        map_msg->locators[i].mpriority   = map_cache_entry->mpriority;
        map_msg->locators[i].mweight     = map_cache_entry->mweight;
    }

    retval = send_command(cmd, cmd_length + sizeof(lisp_cmd_t));
    free(cmd);
    return(retval);
}

int send_eid_map_msg(lisp_eid_map_msg_t *map_msg, int map_msg_len)
{
    size_t                  cmd_length = 0;
    int                     retval     = 0;
    lisp_cmd_t              *cmd;

    cmd_length = sizeof(lisp_cmd_t) + map_msg_len;

    if ((cmd = malloc(cmd_length)) < 0){
        syslog (LOG_DAEMON, "send_eid_map_msg(): memory allocation error");
        return(0);
    }

    memset((char *) cmd, 0, cmd_length);

    cmd->type   = LispMapCacheAdd;
    cmd->length = map_msg_len;
    memcpy((void *)(cmd->val), map_msg, map_msg_len);

    retval = send_command(cmd, cmd_length);
    free(cmd);
    return(retval);
}

int update_map_cache_entry_rloc_status(lisp_addr_t *eid_prefix,
        uint8_t eid_prefix_length, lisp_addr_t *locator, int status_bits)
{
    size_t                  cmd_length  = 0;
    int                     retval      = 0;
    lisp_cmd_t              *cmd;
    lisp_cache_sample_msg_t *cache_sample_msg;
    uint16_t                loc_count   = 1;
    int i;

    cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_cache_sample_msg_t) +
                 sizeof(lisp_addr_t) * loc_count;

    if ((cmd = malloc(cmd_length)) < 0){
        syslog (LOG_DAEMON, "update_map_cache_entry_rloc_status(): memory allocation error");
        return(0);
    }

    memset((char *) cmd, 0, cmd_length);

    cache_sample_msg     = (lisp_cache_sample_msg_t *) CO(cmd, sizeof(lisp_cmd_t));

    cmd->type   = LispCacheSample;
    cmd->length = cmd_length - sizeof(lisp_cmd_t);

    memcpy(&(cache_sample_msg->eid), eid_prefix, sizeof(lisp_addr_t));
    cache_sample_msg->reason            = ProbeSample;
    cache_sample_msg->eid.afi           = eid_prefix->afi;
    cache_sample_msg->eid_prefix_length = eid_prefix_length;
    cache_sample_msg->num_locators      = loc_count;
    cache_sample_msg->status_bits       = status_bits;

    for (i = 0; i < loc_count; i++) {
        memcpy(&(cache_sample_msg->locators[i]),
                locator, sizeof(lisp_addr_t));
    }

    retval = send_command(cmd, cmd_length + sizeof(lisp_cmd_t));
    free(cmd);
    return(retval);
}

/*
 *  set up the NETLINK socket and bind to it.
 */

int setup_netlink(void)
{
    if ((netlink_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_LISP)) <  0) 
    return(0);

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid    = getpid();       /* self pid */
    src_addr.nl_groups = 0;              /* not in mcast groups */

    if (bind(netlink_fd,
         (struct sockaddr *) &src_addr, sizeof(src_addr)) == -1) 
    return(0);

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid    = 0;              /* For Linux Kernel */
    dst_addr.nl_groups = 0;              /* unicast */
    return(1);
}

int send_command(lisp_cmd_t *cmd, size_t length)
{
 
    struct nlmsghdr *nlh;
    struct iovec    iov;
    struct msghdr   kmsg;
    int             retval = 0;

    if ((nlh = malloc(NLMSG_SPACE(MAX_MSG_LENGTH))) == 0)
    return (0);

    /*
     *  make sure these are clean
     */

    memset(&src_addr, 0, sizeof(src_addr));
    memset(&iov,      0, sizeof(struct iovec));
    memset(&kmsg,     0, sizeof(struct msghdr));
    memset(nlh,       0, sizeof(struct nlmsghdr));
    
    /* Fill the NETLINK message header */

    nlh->nlmsg_len   = length + sizeof(struct nlmsghdr);
    nlh->nlmsg_pid   = 0;  /* To kernel */
    nlh->nlmsg_flags = 0;

    /* Fill in the NETLINK message payload */

    memcpy(NLMSG_DATA(nlh), cmd, length);
  
    iov.iov_base     = (void *)nlh;
    iov.iov_len      = nlh->nlmsg_len;
    kmsg.msg_name    = (void *)&dst_addr;
    kmsg.msg_namelen = sizeof(dst_addr);
    kmsg.msg_iov     = &iov;
    kmsg.msg_iovlen  = 1;

    retval = sendmsg(netlink_fd, &kmsg, 0);
    free(nlh);
    return(retval);
}

/*
 *  Receive NETLINK message from kernel module.
 */


int process_netlink_msg(void) {

    struct nlmsghdr *nlh;
    struct iovec    iov;
    struct msghdr   kmsg;
    int         len = 0;
    lisp_cmd_t      *cmd;

    if ((nlh = malloc(NLMSG_SPACE(MAX_MSG_LENGTH))) == 0)
    return (0);

    /*
     *  make sure these are clean
     */

    memset(&iov,      0, sizeof(struct iovec));
    memset(&kmsg,     0, sizeof(struct msghdr));
    memset(nlh,       0, NLMSG_SPACE(MAX_MSG_LENGTH));
    memset(&dst_addr, 0, sizeof(dst_addr));


    /* Fill the NETLINK message header */

    iov.iov_base     = (void *)nlh;
    iov.iov_len      = MAX_MSG_LENGTH;
    kmsg.msg_name    = (void *)&dst_addr;
    kmsg.msg_namelen = sizeof(dst_addr);
    kmsg.msg_iov     = &iov;
    kmsg.msg_iovlen  = 1;

    /*
     * Receive the message
     */

    if ( (len = recvmsg(netlink_fd, &kmsg, 0)) <=0 ){
        syslog(LOG_DAEMON, " Could not receive NETLINK message , len is %d, NLMSG_OK is %d, flags = %d",len,NLMSG_OK(nlh,len),kmsg.msg_flags);
        fflush(stderr);
        return (0);
    }

    /*
     * Point to command inside the NETLINK message
     */

    cmd = (lisp_cmd_t *)NLMSG_DATA(nlh);

    switch (cmd->type) {
        case LispOk:
            syslog(LOG_DAEMON, "Received LispOk NETLINK message");
            break;
        case LispMapCacheLookup:
            syslog(LOG_DAEMON, "Received LispMapCacheLookup NETLINK message");
            if(!handle_LispMapCacheLookup(cmd))
                return(0);
            break;
        case LispMapCacheRLOCList:
            syslog(LOG_DAEMON, "Received LispMapCacheRLOCList NETLINK message");
            if(!handle_LispMapCacheRLOCList(cmd))
                return(0);
            break;
        case LispDatabaseLookup:
            syslog(LOG_DAEMON, "Received LispDatabaseLookup NETLINK message");
            break;
        case LispCacheSample:
            if(!handle_LispCacheSample(cmd))
                return(0);
            break;
        default:
#ifdef DEBUG
            syslog(LOG_DAEMON,"Received NETLINK message type %d", cmd->type);
#endif
            break;
    }

    free(nlh);

    return(1);
}

/*
 * Process LispCacheSample command from the Lisp module
 */

int handle_LispCacheSample(lisp_cmd_t* cmd) {
    lisp_cache_sample_msg_t *msg;
    msg = (lisp_cache_sample_msg_t *) cmd->val;

    switch (msg->reason) {
        case ProbeSample:
            syslog(LOG_DAEMON, "Received LispCacheSample (ProbeSample) NETLINK message");
            if(!handle_LispProbeSample(msg))
                return(0);
            break;
        case SMRSample:
            syslog(LOG_DAEMON, "Received LispCacheSample (SMRSample) NETLINK message");
            break;
        case CacheMiss:
            syslog(LOG_DAEMON, "Received LispCacheSample (CacheMiss) NETLINK message");
            if(!handle_LispCacheMiss(msg))
                return(0);
            break;
    }
    return(1);
}

/*
 * Process LispCacheSample/ProbeSample command from the Lisp module
 */

int handle_LispProbeSample(lisp_cache_sample_msg_t *msg) {
    lisp_addr_t locator;
    char eid_name[128];
    char rloc_name[128];
    int i;

    inet_ntop(msg->eid.afi, &((msg->eid).address), eid_name, 128);
#ifdef DEBUG
    syslog(LOG_DAEMON,"  EID: %s/%d", eid_name, msg->eid_prefix_length);
#endif

    if (msg->num_locators == 0)
        return (0);

    for (i = 0; i < msg->num_locators; i++) {
        /* XXX (LJ): Need checks for locator count/msg length */
        memcpy(&locator, &msg->locators[i], sizeof(lisp_addr_t));
        /* Don't RLOC probe our own locator (TODO need IPv6 support) */
        if (locator.afi == AF_INET &&
                locator.address.ip.s_addr == source_rloc.address.ip.s_addr)
            continue;
        inet_ntop(locator.afi, &(locator.address), rloc_name, 128);
        if (build_and_send_map_request_msg(&locator,
                &(msg->eid),
                msg->eid_prefix_length,
                rloc_name,
                0, 1, 0, 0, 0, 0, LISPD_INITIAL_PROBE_TIMEOUT, 0))
            syslog(LOG_DAEMON, "  RLOC probing locator %s", rloc_name);
    }
    return(1);
}

/*
 * Process LispCacheSample/CacheMiss command from the Lisp module
 */

int handle_LispCacheMiss(lisp_cache_sample_msg_t *msg) {
    char eid_name [128];

    inet_ntop(msg->eid.afi, &((msg->eid).address), eid_name, 128);
#ifdef DEBUG
    syslog(LOG_DAEMON,"  EID: %s", eid_name);
#endif

/*
 * VE, DM:
 * Note: we can check datacache if we have an outstanding Map_Request for this EID
 */

    if( !build_and_send_map_request_msg(map_resolvers->address,
                                &(msg->eid),
                                (get_addr_len(msg->eid.afi) * 8),
                                eid_name,
                                1,
                                0,
                                0,
                                0,
                                0,
                                0,
                                LISPD_INITIAL_MRQ_TIMEOUT,
                                1) ){
        syslog(LOG_DAEMON,"LispCacheMiss : couldn't build/send map_request");
        return (0);

    }
#ifdef DEBUG
        syslog(LOG_DAEMON, "Sent Map-Request for %s", eid_name);
#endif
    return (1);

}


int handle_LispMapCacheRLOCList(lisp_cmd_t *cmd) {
    patricia_node_t *node;
    lispd_locator_chain_t *locator_chain = NULL;
    lisp_cache_address_list_t *addr_list;
    lisp_addr_t *rloc;
    char rloc_name[128];
    int i;

    addr_list = (lisp_cache_address_list_t *) cmd->val;

    PATRICIA_WALK(AF4_database->head, node) {
        locator_chain = ((lispd_locator_chain_t *)(node->data));
        if (locator_chain) {
            for (i = 0; i < addr_list->count; i++) {
                /* XXX LJ:
                 * We send an SMR to each RLOC in the received list for our own
                 * EID, since the below function fills the Source-EID field the
                 * same as destination (the function should be extended).
                 */
                rloc = &(addr_list->addr_list[i]);
                /* Don't SMR PETRs (TODO need IPv6 support) */
                if (addr_list->addr_list[i].afi == AF_INET &&
                        addr_list->addr_list[i].address.ip.s_addr ==
                        proxy_etrs->address->address.ip.s_addr)
                    continue;
                inet_ntop(rloc->afi, &(rloc->address), rloc_name, 128);
                if (build_and_send_map_request_msg(rloc,
                        &(locator_chain->eid_prefix),
                        (get_addr_len(locator_chain->eid_prefix.afi) * 8),
                        locator_chain->eid_name,
                        0, 0, 1, 0, 0, 0, LISPD_INITIAL_MRQ_TIMEOUT, 0))
                    syslog(LOG_DAEMON, "SMR'ing %s", rloc_name);
            }
        }
    } PATRICIA_WALK_END;

    PATRICIA_WALK(AF6_database->head, node) {
        locator_chain = ((lispd_locator_chain_t *)(node->data));
        if (locator_chain) {
            for (i = 0; i < addr_list->count; i++) {
                /* XXX LJ:
                 * We send an SMR to each RLOC in the received list for our own
                 * EID, since the below function fills the Source-EID field the
                 * same as destination (the function should be extended).
                 */
                rloc = &(addr_list->addr_list[i]);
                /* Don't SMR PETRs (TODO need IPv6 support) */
                if (addr_list->addr_list[i].afi == AF_INET &&
                        addr_list->addr_list[i].address.ip.s_addr ==
                        proxy_etrs->address->address.ip.s_addr)
                    continue;
                inet_ntop(rloc->afi, &(rloc->address), rloc_name, 128);
                if (build_and_send_map_request_msg(&rloc,
                        &(locator_chain->eid_prefix),
                        (get_addr_len(locator_chain->eid_prefix.afi) * 8),
                        locator_chain->eid_name,
                        0, 0, 1, 0, 0, 0, LISPD_INITIAL_MRQ_TIMEOUT, 0))
                    syslog(LOG_DAEMON, "SMR'ing %s", rloc_name);
            }
        }
    } PATRICIA_WALK_END;
    return(1);
}


int handle_LispMapCacheLookup(lisp_cmd_t *cmd) {
    lisp_cache_response_msg_t *cache_entry;
    lisp_cache_response_loc_t *locators = NULL;
    char rloc_name[128];
    int i;

    cache_entry = (lisp_cache_response_msg_t *) cmd->val;
    locators    = cache_entry->locators;

    /* XXX: LJ:
     * Need support in build_and_send_map_request_msg() to explicitly select
     * Source-EID, if we want to support several EIDs on the host. Also, need
     * a mechanisms when performing SMR to specify for which EIDs
     */
    if (cache_entry->num_locators) {
        for (i = 0; i < cache_entry->num_locators; i++) {
            /* Don't SMR PETRs (TODO need IPv6 support) */
            if (locators->locator.afi == AF_INET &&
                    locators->locator.address.ip.s_addr ==
                    proxy_etrs->address->address.ip.s_addr) {
                locators++;
                continue;
            }
            inet_ntop(locators->locator.afi, &(locators->locator.address), rloc_name, 128);
            if (build_and_send_map_request_msg(&(locators->locator),
                    &(cache_entry->eid_prefix),
                    (get_addr_len(cache_entry->eid_prefix.afi) * 8),
                    NULL,
                    0, 0, 1, 0, 0, 0, LISPD_INITIAL_MRQ_TIMEOUT, 0))
                syslog(LOG_DAEMON, "SMR'ing %s", rloc_name);
            locators++;
        }
        return(1);
    }
    return(0);
}

/*
 *  register the lispd process with the kernel
 */

int register_lispd_process(void) {
    int retval = 0;
    lisp_cmd_t *cmd;

    if ((cmd = malloc(sizeof(lisp_cmd_t))) == 0) {
        syslog(LOG_DAEMON, "register_lispd_process: malloc failed");
        return(0);
    }

    memset(cmd, 0, sizeof(lisp_cmd_t));

    cmd->type   = LispDaemonRegister;
    cmd->length = 0;

    retval = send_command(cmd, sizeof(lisp_cmd_t));
    free(cmd);
    return(retval);
} 


/*
 *  ask for the full map cache (for SMR)
 */

int get_map_cache_list() {
    int retval = 0;
    lisp_cmd_t *cmd;
    lisp_lookup_msg_t lookup_msg;

    if ((cmd = malloc(sizeof(lisp_cmd_t) + sizeof(lisp_lookup_msg_t))) == 0) {
        syslog(LOG_DAEMON, "get_map_cache_list: malloc failed");
        return(0);
    }

    memset(cmd, 0, sizeof(lisp_cmd_t));

    cmd->type   = LispMapCacheLookup;
    cmd->length = sizeof(lisp_lookup_msg_t);

    memset((char *)&lookup_msg, 0, sizeof(lisp_lookup_msg_t));
    lookup_msg.all_entries = 1;
    lookup_msg.exact_match = 0;
    memcpy(cmd->val, (char *)&lookup_msg, sizeof(lisp_lookup_msg_t));

    retval = send_command(cmd, sizeof(lisp_cmd_t) + sizeof(lisp_lookup_msg_t));
    syslog(LOG_DAEMON, "Asking for map cache to do SMR");
    free(cmd);
    return(retval);
}


/*
 *  ask for the list of RLOCs in map cache (for SMR)
 */

int get_map_cache_rloc_list() {
    int retval = 0;
    lisp_cmd_t *cmd;

    if ((cmd = malloc(sizeof(lisp_cmd_t))) == 0) {
        syslog(LOG_DAEMON, "get_map_cache_rloc_list: malloc failed");
        return(0);
    }

    memset(cmd, 0, sizeof(lisp_cmd_t));

    cmd->type   = LispMapCacheRLOCList;
    cmd->length = 0;

    retval = send_command(cmd, sizeof(lisp_cmd_t));
    syslog(LOG_DAEMON, "Asking for RLOC list to do SMR");
    free(cmd);
    return(retval);
}


/*
 *  update source RLOC in kernel module
 */
//#ifdef LISPMOBMH
int set_rloc(lisp_addr_t *my_addr, int if_index) {
//#else
//int set_rloc(lisp_addr_t *my_addr) {
//#endif
    int                 retval = 0;
    size_t              cmd_length = 0;
    lisp_cmd_t          *cmd;
    lisp_set_rloc_msg_t *set_rloc_msg;
//#ifdef LISPMOBMH
	//rloc_t rloc2set;
	cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_set_rloc_msg_t) + sizeof(rloc_t);
//#else
  //  cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_set_rloc_msg_t);
//#endif
    if ((cmd = malloc(cmd_length)) == 0) {
        syslog(LOG_DAEMON, "set_rloc: malloc failed");
        return(0);
    }

    memset(cmd, 0, cmd_length);

    set_rloc_msg = (lisp_set_rloc_msg_t *) CO(cmd, sizeof(lisp_cmd_t));

    cmd->type   = LispSetRLOC;
//#ifdef LISPMOBMH
    cmd->length = sizeof(lisp_set_rloc_msg_t) + sizeof(rloc_t);

	set_rloc_msg->count=1;
    memcpy(&(set_rloc_msg->rlocs->addr), my_addr, sizeof(lisp_addr_t));
    //set_rloc_msg->rlocs->addr.afi = my_addr->afi;
    set_rloc_msg->rlocs->if_index=if_index;	
//#else
  //  cmd->length = sizeof(lisp_set_rloc_msg_t);

   // memcpy(&(set_rloc_msg->addr), my_addr, sizeof(lisp_addr_t));
//#endif
    retval = send_command(cmd, cmd_length);
    syslog(LOG_DAEMON, "Updating RLOC in data plane");
    free(cmd);
    return(retval);
} 

/*
 *  add local EID to kernel module list
 */

int add_local_eid(lisp_addr_t *my_addr) {
    int                 retval = 0;
    size_t              cmd_length = 0;
    lisp_cmd_t          *cmd;
    lisp_add_local_eid_msg_t *add_eid_msg;

    cmd_length = sizeof(lisp_cmd_t) + sizeof(lisp_add_local_eid_msg_t);

    if ((cmd = malloc(cmd_length)) == 0) {
        syslog(LOG_DAEMON, "add_local_eid: malloc failed");
        return(0);
    }

    memset(cmd, 0, cmd_length);

    add_eid_msg = (lisp_add_local_eid_msg_t *) CO(cmd, sizeof(lisp_cmd_t));

    cmd->type   = LispAddLocalEID;
    cmd->length = sizeof(lisp_add_local_eid_msg_t);

    memcpy(&(add_eid_msg->addr), my_addr, sizeof(lisp_addr_t));

    retval = send_command(cmd, cmd_length);
    syslog(LOG_DAEMON, "Adding local EID to data plane list");
    free(cmd);
    return(retval);
}



/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
