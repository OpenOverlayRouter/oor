/* 
 * lispd_map_register.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Send registration messages for each database mapping to
 * configured map-servers.
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
 *    Preethi Natarajan <prenatar@cisco.com>
 *    Lorand Jakab      <ljakab@ac.upc.edu>
 *
 */

#include <sys/timerfd.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "lispd_external.h"

/*
 *  map_server_register (tree)
 *
 */

int map_register(tree)
    patricia_tree_t *tree;
{

    lispd_map_server_list_t   *ms;
    lispd_pkt_map_register_t  *map_register_pkt; 
    patricia_node_t           *node;
    lispd_locator_chain_t     *locator_chain;

    if (!map_servers) {
    syslog(LOG_DAEMON, "No Map Servers conifgured!");
    return(0);
    }

    if (!tree)
    return(0);

    PATRICIA_WALK(tree->head, node) {
    locator_chain = ((lispd_locator_chain_t *)(node->data));
        if (locator_chain) {
        if ((map_register_pkt =
         build_map_register_pkt(locator_chain)) == NULL) {
        syslog(LOG_DAEMON, "Couldn't build map register packet");
        return(0);
        }

        /*
         *  for each map server, send a register, and if verify
         *  send a map-request for our eid prefix
         */

        ms = map_servers;

        while (ms) {
        if (!send_map_register(ms,
                       map_register_pkt,
                       locator_chain->mrp_len)) {
            syslog(LOG_DAEMON,
               "Couldn't send map-register for %s",
               locator_chain->eid_name);
        } else if (ms->verify) {
            if (!build_and_send_map_request_msg(ms->address,
                            &(locator_chain->eid_prefix),
                            locator_chain->eid_prefix_length,
                            1,1,0,0,0,0,0,LISPD_INITIAL_MRQ_TIMEOUT,1))


            syslog(LOG_DAEMON,"map_register:couldn't build/send map_request");
        }
        ms = ms->next;
        }
        free(map_register_pkt);
    }
    } PATRICIA_WALK_END;
    return(1);
}


/*
 *  build_map_register_pkt
 *
 *  Build the map-register
 *
 */
    
lispd_pkt_map_register_t *build_map_register_pkt(locator_chain)
    lispd_locator_chain_t           *locator_chain;
{
    lispd_pkt_map_register_t        *mrp;
    lispd_pkt_mapping_record_t      *mr;
    int                             mrp_len = 0;

    mrp_len = sizeof(lispd_pkt_map_register_t) +
              get_record_length(locator_chain);

    if ((mrp = malloc(mrp_len)) == NULL) {
        syslog(LOG_DAEMON, "build_map_register_pkt: malloc: %s", strerror(errno));
        return(NULL);
    }
    memset(mrp, 0, mrp_len);
    locator_chain->mrp_len = mrp_len;

    /*
     *  build the packet
     *
     *  Fill in mrp->proxy_reply and compute the HMAC in 
     *  send_map_register()
     *
     */

    mrp->lisp_type        = LISP_MAP_REGISTER;
    mrp->map_notify       = 1;              /* TODO conf item */
    mrp->nonce            = 0;
    mrp->record_count     = 1;              /* XXX  > 1 ? */
    mrp->key_id           = 0;              /* XXX not sure */
    mrp->auth_data_len    = htons(LISP_SHA1_AUTH_DATA_LEN);

    /* skip over the fixed part,  assume one record (mr) */

    mr = (lispd_pkt_mapping_record_t *) CO(mrp, sizeof(lispd_pkt_map_register_t));

    if (build_mapping_record(mr, locator_chain, NULL))
        return(mrp);
    else
        return(NULL);
}


/*
 *  send_map_register
 *
 *  Assumes IPv4 transport for map-registers
 *
 */

int send_map_register(ms, mrp, mrp_len)
    lispd_map_server_list_t  *ms;
    lispd_pkt_map_register_t *mrp;
    int                      mrp_len;
{

    lisp_addr_t         *addr;
    struct sockaddr_in  map_server;
    int                 s;      /*socket */
    int                 nbytes;
    unsigned int        md_len;
    struct sockaddr_in  ctrl_saddr;

    /*
     * Fill in proxy_reply and compute the HMAC with SHA-1. Have to 
     * do this here since we need to know which map-server (since it 
     * has the proxy_reply bit)
     *
     */

    mrp->proxy_reply = ms->proxy_reply;
    memset(mrp->auth_data,0,LISP_SHA1_AUTH_DATA_LEN);   /* make sure */

    if (!HMAC((const EVP_MD *) EVP_sha1(), 
          (const void *) ms->key,
          strlen(ms->key),
          (uchar *) mrp,
          mrp_len,
          (uchar *) mrp->auth_data,
          &md_len)) {
    syslog(LOG_DAEMON, "HMAC failed for map-register");
        free(mrp);
    return(0);
    }    

    /* 
     * ok, now go send it...
     */

    if ((s = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) < 0) {
    syslog(LOG_DAEMON, "socket (send_map_register): %s", strerror(errno));
    return(0);
    }

    /*
     * PN: Bind the UDP socket to a valid rloc on the ctrl_iface
     * (assume v4 transport)
     */
    if (!(ctrl_iface) || !(ctrl_iface->AF4_locators->head)) {

        /* 
         * No physical interface available for control messages
         */

        syslog(LOG_DAEMON, "(send_map_register): Unable to find valid physical interface\n");
        return (0);
    }
    memset((char *) &ctrl_saddr, 0, sizeof(struct sockaddr_in));
    ctrl_saddr.sin_family       = AF_INET;
    ctrl_saddr.sin_port         = htons(INADDR_ANY);
    ctrl_saddr.sin_addr.s_addr  = (ctrl_iface->AF4_locators->head->db_entry->locator).address.ip.s_addr;

    if (bind(s, (struct sockaddr *)&ctrl_saddr, sizeof(struct sockaddr_in)) < 0) {
        syslog(LOG_DAEMON, "bind (send_map_register): %s", strerror(errno));
        close(s);
        return(0);
    }

    memset((char *) &map_server, 0, sizeof(map_server));

    addr                       = ms->address;
    map_server.sin_family      = AF_INET;
    map_server.sin_addr.s_addr = addr->address.ip.s_addr;
    map_server.sin_port        = htons(LISP_CONTROL_PORT);

    if ((nbytes = sendto(s,
             (const void *) mrp,
             mrp_len,
             0,
             (struct sockaddr *)&map_server,
             sizeof(struct sockaddr))) < 0) {
    syslog(LOG_DAEMON,"sendto (send_map_register): %s", strerror(errno));
    close(s);
    return(0);
    }

    if (nbytes != mrp_len) {
    syslog(LOG_DAEMON,
        "send_map_register: nbytes (%d) != mrp_len (%d)\n",
        nbytes, mrp_len);
    close(s);
    return(0);
    }

    close(s);
    return(1);
}


/*
 *  get_locator_chain_length
 *
 *  Compute the sum of the lengths of the locators 
 *  in the chain so we can allocate a chunk of memory for 
 *  the packet....
 */

int get_locator_length(locator_chain_elt)
    lispd_locator_chain_elt_t   *locator_chain_elt;
{
    int sum = 0;
    while (locator_chain_elt) {
        switch (locator_chain_elt->db_entry->locator.afi) {
        case AF_INET:
            sum += sizeof(struct in_addr);
            break;
        case AF_INET6:
            sum += sizeof(struct in6_addr);
            break;
        default:
            syslog(LOG_DAEMON, "Uknown AFI (%d) for %s",
               locator_chain_elt->db_entry->locator.afi,
               locator_chain_elt->db_entry->locator_name);
            break;
        }
        locator_chain_elt = locator_chain_elt->next;
    }
    return(sum);
}


void start_periodic_map_register(void)
{
    struct itimerspec interval;

    interval.it_interval.tv_sec  = MAP_REGISTER_INTERVAL;
    interval.it_interval.tv_nsec = 0;
    interval.it_value.tv_sec     = 1;
    interval.it_value.tv_nsec    = 0;

    if (!map_register(AF6_database))
        syslog(LOG_INFO, "Could not map register AF_INET6 with Map Servers");

    if (!map_register(AF4_database))
        syslog(LOG_INFO, "Could not map register AF_INET with Map Servers");

    syslog(LOG_INFO, "Starting timer to send map register every %d seconds",
            MAP_REGISTER_INTERVAL);

    if (timerfd_settime(map_register_timer_fd, 0, &interval, NULL) == -1)
        syslog(LOG_INFO, "timerfd_settime: %s", strerror(errno));
}


void stop_periodic_map_register(void)
{
    struct itimerspec interval;

    interval.it_interval.tv_sec  = 0;
    interval.it_interval.tv_nsec = 0;
    interval.it_value.tv_sec     = 0;
    interval.it_value.tv_nsec    = 0;

    syslog(LOG_INFO, "Stopping timer to send map register every %d seconds",
            MAP_REGISTER_INTERVAL);

    if (timerfd_settime(map_register_timer_fd, 0, &interval, NULL) == -1)
        syslog(LOG_INFO, "timerfd_settime: %s", strerror(errno));
}


inline void periodic_map_register(void)
{
    ssize_t s;
    uint64_t num_exp;

    if((s = read(map_register_timer_fd, &num_exp, sizeof(num_exp))) != sizeof(num_exp))
        syslog(LOG_INFO, "read (periodic_map_register): %s", strerror(errno));

    if (!map_register(AF6_database))
        syslog(LOG_INFO, "Periodic AF_INET6 map register failed");

    if (!map_register(AF4_database))
        syslog(LOG_INFO, "Periodic AF_INET map register failed");
}


#ifdef LISPMOBMH
/* Machinery to handle rate limited smrs when interfaces go up and down
 * in dynamic multihomed scenarios.
 */

void start_smr_timeout(void)
{
    struct itimerspec interval;

    if (timerfd_gettime(smr_timer_fd, &interval) == -1)
            syslog(LOG_INFO, "timerfd_gettime: %s", strerror(errno));

    if (interval.it_value.tv_sec == 0){
    	/*Timer is disarmed. Start it*/

    	interval.it_interval.tv_sec  = 0;
    	interval.it_interval.tv_nsec = 0;
    	interval.it_value.tv_sec     = DEFAULT_SMR_TIMEOUT;
    	interval.it_value.tv_nsec    = 0;

    	syslog(LOG_INFO, "Start timer to send an smr in %d seconds",
    			DEFAULT_SMR_TIMEOUT);

    	if (timerfd_settime(smr_timer_fd, 0, &interval, NULL) == -1)
    		syslog(LOG_INFO, "timerfd_settime: %s", strerror(errno));
    }
}


void stop_smr_timeout(void)
{
    struct itimerspec interval;

    interval.it_interval.tv_sec  = 0;
    interval.it_interval.tv_nsec = 0;
    interval.it_value.tv_sec     = 0;
    interval.it_value.tv_nsec    = 0;

    syslog(LOG_INFO, "Clear timer to send smrs");

    if (timerfd_settime(smr_timer_fd, 0, &interval, NULL) == -1)
        syslog(LOG_INFO, "timerfd_settime: %s", strerror(errno));
}


inline void smr_on_timeout(void)
{
    ssize_t s;
    uint64_t num_exp;

    if((s = read(smr_timer_fd, &num_exp, sizeof(num_exp))) != sizeof(num_exp))
        syslog(LOG_INFO, "read error (smr_on_timeout): %s", strerror(errno));
    /*
     * Trigger SMR to PITRs and the MN's peers
     */
    smr_pitrs();
    get_map_cache_list();
}
#endif





/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
