/*
 * lispd_config.c
 *
 * This file is part of LISP Mobile Node Implementation.
 * Handle lispd command line and config file
 * Parse command line args using gengetopt.
 * Handle config file with libconfuse.
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

#include "cmdline.h"
#include "confuse.h"
#include "lispd_external.h"
#include "lispd_iface_list.h"
#include "lispd_iface_mgmt.h"
#include "lispd_ipc.h"
#include "lispd_lib.h"
#include "lispd_local_db.h"
#include "lispd_map_cache_db.h"



int add_database_mapping(cfg_t *dm);
int add_map_server(
     char       *map_server,
     int        key_type,
     char       *key,
     uint8_t    proxy_reply,
     uint8_t    verify);
int add_proxy_etr_entry(cfg_t *petr, lispd_weighted_addr_list_t **petr_list);
int add_server(char *server, lispd_addr_list_t  **list);
int add_static_map_cache_entry(cfg_t  *smc);




/*
 *  handle_lispd_command_line --
 *
 *  Get command line args and set up whatever is needed
 *
 *  David Meyer
 *  dmm@1-4-5.net
 *  Wed Apr 21 13:31:00 2010
 *
 *  $Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */

void handle_lispd_command_line(int argc, char **argv)
{
    struct gengetopt_args_info args_info;

    if (cmdline_parser(argc, argv, &args_info) != 0) 
        exit(EXIT_FAILURE);

    if (args_info.nodaemonize_given) {
        daemonize = 0;
    }
    if (args_info.config_file_given) {
        config_file = strdup(args_info.config_file_arg);
    }
    if (args_info.map_request_retries_given) {
        map_request_retries = args_info.map_request_retries_arg;
    }
}

/*
 *  handle_lispd_config_file --
 *
 *  Parse config file and set up whatever is needed
 *
 *  David Meyer
 *  dmm@1-4-5.net
 *  Wed Apr 21 13:31:00 2010
 *
 *  $Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */

int handle_lispd_config_file()
{
    cfg_t           *cfg   = 0;
    unsigned int    i      = 0;
    unsigned        n      = 0;
    int             ret    = 0;

    static cfg_opt_t map_server_opts[] = {
    CFG_STR("address",      0, CFGF_NONE),
    CFG_INT("key-type",     0, CFGF_NONE),
    CFG_STR("key",          0, CFGF_NONE),
    CFG_BOOL("proxy-reply", cfg_false, CFGF_NONE),
    CFG_BOOL("verify",      cfg_false, CFGF_NONE),
    CFG_END()
    };

    static cfg_opt_t db_mapping_opts[] = {
        CFG_STR("eid-prefix",           0, CFGF_NONE),
        CFG_INT("iid",                  -1, CFGF_NONE),
        CFG_STR("interface",            0, CFGF_NONE),
        CFG_INT("priority_v4",          0, CFGF_NONE),
        CFG_INT("weight_v4",            0, CFGF_NONE),
        CFG_INT("priority_v6",          0, CFGF_NONE),
        CFG_INT("weight_v6",            0, CFGF_NONE),
        CFG_END()
    };

    static cfg_opt_t mc_mapping_opts[] = {
        CFG_STR("eid-prefix",           0, CFGF_NONE),
        CFG_INT("iid",                  0, CFGF_NONE),
        CFG_STR("rloc",                 0, CFGF_NONE),
        CFG_INT("priority",             0, CFGF_NONE),
        CFG_INT("weight",               0, CFGF_NONE),
        CFG_END()
    };

    static cfg_opt_t petr_mapping_opts[] = {
            CFG_STR("address",              0, CFGF_NONE),
            CFG_INT("priority",           255, CFGF_NONE),
            CFG_INT("weight",               0, CFGF_NONE),
            CFG_END()
    };

    cfg_opt_t opts[] = {
        CFG_SEC("database-mapping",     db_mapping_opts, CFGF_MULTI),
        CFG_SEC("static-map-cache",     mc_mapping_opts, CFGF_MULTI),
        CFG_SEC("map-server",           map_server_opts, CFGF_MULTI),
        CFG_SEC("proxy-etr",            petr_mapping_opts, CFGF_MULTI),
        CFG_INT("map-request-retries",  0, CFGF_NONE),
        CFG_INT("control-port",         0, CFGF_NONE),
        CFG_BOOL("debug",               cfg_false, CFGF_NONE),
        CFG_STR("map-resolver",         0, CFGF_NONE),
        CFG_STR_LIST("proxy-itrs",      0, CFGF_NONE),
        CFG_END()
    };

    /*
     *  parse config_file
     */

    cfg = cfg_init(opts, CFGF_NOCASE);
    ret = cfg_parse(cfg, config_file);

    if (ret == CFG_FILE_ERROR) {
        syslog(LOG_DAEMON, "Couldn't find config file %s, exiting...", config_file);
        exit(EXIT_FAILURE);
    } else if(ret == CFG_PARSE_ERROR) {
        syslog(LOG_DAEMON, "NOTE: Version 0.2.4 changed the format of the 'proxy-etr' element.");
        syslog(LOG_DAEMON, "      Check the 'lispd.conf.example' file for an example entry in");
        syslog(LOG_DAEMON, "      the new format.");
        syslog(LOG_DAEMON, "Parse error in file %s, exiting...", config_file);
        exit(EXIT_FAILURE);
    }

    
    /*
     *  lispd config options
     */

    ret = cfg_getint(cfg, "map-request-retries");
    if (ret != 0)
        map_request_retries = ret;

    cfg_getbool(cfg, "debug") ? (debug = 1) : (debug = 0); 

    /*
     *  LISP config options
     */

    /*
     *  handle map-resolver config
     */

    map_resolver = cfg_getstr(cfg, "map-resolver");
    if (!add_server(map_resolver, &map_resolvers))
        return(0); 
#ifdef DEBUG
    syslog(LOG_DAEMON, "Added %s to map-resolver list", map_resolver);
#endif

    /*
     *  handle proxy-etr config
     */


    n = cfg_size(cfg, "proxy-etr");
    for(i = 0; i < n; i++) {
        cfg_t *petr = cfg_getnsec(cfg, "proxy-etr", i);
        if (!add_proxy_etr_entry(petr, &proxy_etrs)) {
            syslog(LOG_DAEMON, "Can't add proxy-etr %d (%s)", i, cfg_getstr(petr, "address"));
        }
    }

    if (!proxy_etrs){
        syslog(LOG_DAEMON, "WARNING: No Proxy-ETR defined. Packets to non-LISP destinations will be forwarded natively (no LISP encapsulation). This may prevent mobility in some scenarios.");
        sleep(3);
    }

    /*
     *  handle proxy-itr config
     */

    n = cfg_size(cfg, "proxy-itrs");
    for(i = 0; i < n; i++) {
        if ((proxy_itr = cfg_getnstr(cfg, "proxy-itrs", i)) != NULL) {
            if (!add_server(proxy_itr, &proxy_itrs))
                continue;
#ifdef DEBUG
            syslog(LOG_DAEMON, "Added %s to proxy-itr list", proxy_itr);
#endif
        }
    }

    /*
     *  handle database-mapping config
     */

    n = cfg_size(cfg, "database-mapping");
    for(i = 0; i < n; i++) {
        cfg_t *dm = cfg_getnsec(cfg, "database-mapping", i);
        if (!add_database_mapping(dm)) {
            syslog(LOG_DAEMON, "Can't add database-mapping %d (%s->%s)",
               i,
               cfg_getstr(dm, "eid-prefix"),
               cfg_getstr(dm, "interface"));
        }
    }

    /*
     *  handle map-server config
     */

    n = cfg_size(cfg, "map-server");
    for(i = 0; i < n; i++) {
        cfg_t *ms = cfg_getnsec(cfg, "map-server", i);
        if (!add_map_server(cfg_getstr(ms, "address"),
                                cfg_getint(ms, "key-type"),
                cfg_getstr(ms, "key"),
                (cfg_getbool(ms, "proxy-reply") ? 1:0),
                (cfg_getbool(ms, "verify")      ? 1:0)))

            return(0);
#ifdef DEBUG
        syslog(LOG_DAEMON, "Added %s to map-server list",
            cfg_getstr(ms, "address"));
#endif
    }

    /*
     *  handle static-map-cache config
     */

    n = cfg_size(cfg, "static-map-cache");
    for(i = 0; i < n; i++) {
        cfg_t *smc = cfg_getnsec(cfg, "static-map-cache", i);
            if (!add_static_map_cache_entry(smc)) {
        syslog(LOG_DAEMON,"Can't add static-map-cache %d (EID:%s -> RLOC:%s)",
               i,
               cfg_getstr(smc, "eid-prefix"),
               cfg_getstr(smc, "rloc"));
        }
    }


#if (DEBUG > 3)
    dump_tree(AF_INET,AF4_database);
    dump_tree(AF_INET6,AF6_database);
    dump_database();
    dump_map_servers();
    dump_servers(map_resolvers, "map-resolvers");
    dump_servers(proxy_etrs, "proxy-etrs");
    dump_servers(proxy_itrs, "proxy-itrs");
    dump_map_cache();
#endif

    cfg_free(cfg);
    return(0);
}

/*
 *  add_database_mapping
 *
 *  Get a single database mapping 
 *
 *  David Meyer <dmm@1-4-5.net>
 *  Preethi Natarajan <prenatar@cisco.com>
 *
 */

int add_database_mapping(dm)
     cfg_t      *dm;
{
    lispd_identifier_elt        *identifier;
    lispd_iface_elt             *interface;
    lispd_locator_elt			*locator_v4;
    lispd_locator_elt			*locator_v6;
    lisp_addr_t                 eid_prefix;           /* save the eid_prefix here */
    int                         eid_prefix_length;
    uint8_t						is_new_identifier;

    char   *eid               = cfg_getstr(dm, "eid-prefix");
    int    iid                = cfg_getint(dm, "iid");
    char   *iface_name        = cfg_getstr(dm, "interface");
    int    priority_v4        = cfg_getint(dm, "priority_v4");
    int    weight_v4          = cfg_getint(dm, "weight_v4");
    int    priority_v6        = cfg_getint(dm, "priority_v6");
    int    weight_v6          = cfg_getint(dm, "weight_v6");

    if (iid > MAX_IID || iid < 0) {
        syslog (LOG_ERR, "Configuration file: Instance ID %d out of range [0..%d], disabling...", iid, MAX_IID);
        iid = -1;
    }

    if (priority_v4 < MAX_PRIORITY || priority_v4 > UNUSED_RLOC_PRIORITY) {
        syslog (LOG_ERR, "Configuration file: Priority %d out of range [%d..%d], set minimum priority...",
                priority_v4, MAX_PRIORITY, UNUSED_RLOC_PRIORITY);
        priority_v4 = MIN_PRIORITY;
    }

    if (priority_v6 < MAX_PRIORITY || priority_v6 > UNUSED_RLOC_PRIORITY) {
        syslog (LOG_ERR, "Configuration file: Priority %d out of range [%d..%d], set minimum priority...",
                priority_v6, MAX_PRIORITY, UNUSED_RLOC_PRIORITY);
        priority_v6 = MIN_PRIORITY;
    }

    if (get_lisp_addr_and_mask_from_char(eid,&eid_prefix,&eid_prefix_length)!=GOOD){
        syslog (LOG_ERR, "Configuration file: Error parsing EID address ... Ignoring identifier");
        return BAD;
    }


    if (if_nametoindex(iface_name) == 0) {
        syslog(LOG_ERR, "Configuration file: Invalid interface: %s ... Ignoring identifier", iface_name);
        return (ERR_CTR_IFACE);
    }

    /*
     * Lookup if the identifier exists. If not, a new identifier is created.
     */
    if (lookup_eid_exact_in_db(eid_prefix,eid_prefix_length,&identifier)==BAD)
    {
        identifier = new_identifier(eid_prefix,eid_prefix_length,iid);
        if (identifier == NULL){
            syslog (LOG_ERR,"Configuration file: Identifier %s could not be added",eid);
            return BAD;
        }
        is_new_identifier = TRUE;
    }else{
        if (identifier->iid != iid){
            syslog (LOG_ERR,"Same identifier with different iid. This configuration is not supported..."
                    "Ignoring identifier.");
            return BAD;
        }
        is_new_identifier = FALSE;
    }
    /*
     * Add the new interface.
     */
    /* Check if the interface already exists. If not, add it*/
    if ((interface=get_interface(iface_name))==NULL)
    	interface = add_interface (iface_name);


    /* If we couldn't add the interface and the identifier is new, we remove it. */
    if (interface == NULL){
        if (is_new_identifier){
            del_identifier_entry (identifier->eid_prefix, identifier->eid_prefix_length);
        }
    }

    /* XXX Process when the new locator could not be allocated */
    if (priority_v4 > 0){
    	if (!interface->ipv4_address){
    		syslog(LOG_ERR,"ERROR: IPv4 locator can not be added to the EID %s/%d. Interface %s doesn't have IPv4 address",
    				get_char_from_lisp_addr_t(identifier->eid_prefix),identifier->eid_prefix_length,
    				interface->iface_name);
    		return (BAD);
    	}
        if ((err = add_identifier_to_interface (interface, identifier,AF_INET)) == GOOD){
            locator_v4 = new_locator (identifier,interface->ipv4_address,&(interface->status),LOCAL_LOCATOR,priority_v4,weight_v4,255,0);
        }
    }
    if (priority_v6 > 0){
    	if (!interface->ipv6_address){
    		syslog(LOG_ERR,"ERROR: IPv6 locator can not be added to the EID %s/%d. Interface %s doesn't have IPv6 address",
    				get_char_from_lisp_addr_t(identifier->eid_prefix),identifier->eid_prefix_length,
    				interface->iface_name);
    		return (BAD);
    	}
    	if ((err = add_identifier_to_interface (interface, identifier,AF_INET6)) == GOOD)
            locator_v6 = new_locator (identifier,interface->ipv6_address,&(interface->status),LOCAL_LOCATOR,priority_v6,weight_v6,255,0);
    }

    /* 
     * PN: Setup the LISP-MN interface (ex: lisp_tun0) for this EID.
     * Assume single EID/LISP-MN interface per MN for now.
     * Multiple EIDs per MN is a possibility in the future; then
     * each EID requires its own LISP-MN interface and 
     * one of the interfaces will be the default one.
     */
/*    if (!setup_lisp_eid_iface(LISP_MN_EID_IFACE_NAME,
                &(identifier->eid_prefix),
                identifier->eid_prefix_length)) {
        syslog(LOG_ERR, "setup_lisp_eid_iface (%s) failed\b", iface_name);
        return (BAD);
    } 
*/

    /* 
     * PN: Find an active interface for lispd control messages
     */
    if (ctrl_iface == NULL)
        ctrl_iface = find_active_ctrl_iface();
#ifdef LISPMOBMH
    /* We need a default rloc (iface) to use. As of now 
     * we will use the same as the ctrl_iface */
    if(ctrl_iface != NULL){
       if (ctrl_iface->AF4_locators->head){
		  if (ctrl_iface->AF4_locators->head->db_entry) {
				set_rloc(&(ctrl_iface->AF4_locators->head->db_entry->locator),0);
				syslog(LOG_INFO,"Mapping RLOC %pI4 to iface %d\n",
		             &(ctrl_iface->AF4_locators->head->db_entry->locator.address.ip),0);
			}
		}
		else{
			if (ctrl_iface->AF6_locators->head){
			  if (ctrl_iface->AF6_locators->head->db_entry) {
					set_rloc(&(ctrl_iface->AF6_locators->head->db_entry->locator),0);
				}
			}
		}
    }

#endif
    return(GOOD);
}

/*
 *  add_static_map_cache_entry --
 *
 *  Get a single static mapping
 *
 *  David Meyer
 *  dmm@1-4-5.net
 *  Wed Apr 21 13:31:00 2010
 *
 *  $Header: /usr/local/src/lispd/RCS/lispd_config.c,v 1.16 2010/04/21 23:32:08 root Exp $
 *
 */

int add_static_map_cache_entry(smc)
     cfg_t  *smc;
{
    lispd_map_cache_entry    *map_cache_entry;
    lispd_locator_elt        *locator;
    lisp_addr_t              eid_prefix;
    lisp_addr_t              *rloc_addr;
    int                      eid_prefix_length;
    uint8_t                  *state = 0;

    char   *eid         = cfg_getstr(smc, "eid-prefix");
    char   *rloc        = cfg_getstr(smc, "rloc");
    int    priority     = cfg_getint(smc, "priority");
    int    weight       = cfg_getint(smc, "weight");
    int    iid          = cfg_getint(smc, "iid");


    if (iid > MAX_IID) {
        syslog (LOG_ERR, "Configuration file: Instance ID %d out of range [0..%d], disabling...", iid, MAX_IID);
        iid = 0;
    }

    if (iid < 0)
    	iid = 0;

    if (priority < MAX_PRIORITY || priority > UNUSED_RLOC_PRIORITY) {
        syslog (LOG_ERR, "Configuration file: Priority %d out of range [%d..%d], set minimum priority...",
                priority, MAX_PRIORITY, UNUSED_RLOC_PRIORITY);
        priority = MIN_PRIORITY;
    }

    if (get_lisp_addr_and_mask_from_char(eid,&eid_prefix,&eid_prefix_length)!=GOOD){
        syslog (LOG_ERR, "Configuration file: Error parsing RLOC address ...Ignoring static map cache entry");
        return BAD;
    }

    map_cache_entry = new_map_cache_entry(eid_prefix, eid_prefix_length, STATIC_MAP_CACHE_ENTRY,255);
    if (map_cache_entry == NULL)
        return (BAD);

    if((rloc_addr = malloc(sizeof(lisp_addr_t))) == NULL){
        syslog(LOG_ERR,"add_static_map_cache_entry: Couldn't allocate lisp_addr_t for rloc address");
        return (ERR_MALLOC);
    }
    if((state = malloc(sizeof(uint8_t))) == NULL){
        syslog(LOG_ERR,"add_static_map_cache_entry: Couldn't allocate uint8_t for status");
        return (ERR_MALLOC);
    }

    if (get_lisp_addr_from_char(rloc,rloc_addr) == BAD){
        syslog (LOG_ERR, "Configuration file: Error parsing RLOC address ... Ignoring static map cache entry");
        return BAD;
    }

    *state = UP;

    map_cache_entry->identifier->iid = iid;

    locator = new_locator(map_cache_entry->identifier,
    		rloc_addr,
    		state,
    		STATIC_LOCATOR,
    		priority,
    		weight,
    		255,
    		0);
    if (locator)
        return(GOOD);
    else
        return (BAD);
}

/*
 *  add a map-resolver to the list
 */

int add_server(server, list)
     char       *server;
     lispd_addr_list_t  **list;
{

    uint                afi;
    lisp_addr_t         *addr;
    lispd_addr_list_t   *list_elt;
 
    if ((addr = malloc(sizeof(lisp_addr_t))) == NULL) {
        syslog(LOG_DAEMON, "malloc(sizeof(lisp_addr_t)): %s", strerror(errno));
        return(0);
    }
    memset(addr,0,sizeof(lisp_addr_t));

    afi = get_afi(server);
    addr->afi = afi;

    if (inet_pton(afi, server, &(addr->address)) != 1) {
        syslog(LOG_DAEMON, "inet_pton: %s", strerror(errno));
        free(addr);
        return(0);
    }

    if ((list_elt = malloc(sizeof(lispd_addr_list_t))) == NULL) {
        syslog(LOG_DAEMON, "malloc(sizeof(lispd_addr_list_t)): %s", strerror(errno));
        free(addr);
        return(0);
    }
    memset(list_elt,0,sizeof(lispd_addr_list_t));

    list_elt->address = addr;

    /*
     * hook this one to the front of the list
     */

    if (*list) {
        list_elt->next = *list;
        *list = list_elt;
    } else {
        *list = list_elt;
    }

    return(1);
}

/*
 *  add_map_server to map_servers
 */

int add_map_server(map_server, key_type, key, proxy_reply,verify)
     char       *map_server;
     int        key_type;
     char       *key;
     uint8_t    proxy_reply;
     uint8_t    verify;
{
    lisp_addr_t             *addr;
    lispd_map_server_list_t *list_elt;
    struct hostent          *hptr;

    if ((addr = malloc(sizeof(lisp_addr_t))) == NULL) {
        syslog(LOG_DAEMON, "malloc(sizeof(lisp_addr_t)): %s", strerror(errno));
        return(0);
    }

    /*
     *  make sure this is clean
     */

    memset(addr,0,sizeof(lisp_addr_t));

    if (((hptr = gethostbyname2(map_server,AF_INET))  == NULL) &&
    ((hptr = gethostbyname2(map_server,AF_INET6)) == NULL)) {
        syslog(LOG_DAEMON, "can gethostbyname2 for map_server (%s)", map_server);
        free(addr);
        return(0);
    }

    memcpy((void *) &(addr->address),
       (void *) *(hptr->h_addr_list), sizeof(lisp_addr_t));
    addr->afi = hptr->h_addrtype;

    if ((list_elt = malloc(sizeof(lispd_map_server_list_t))) == NULL) {
        sprintf(msg,"malloc(sizeof(lispd_map_server_list_t)) failed");
        syslog(LOG_DAEMON, "%s", msg);
        free(addr);
        return(0);
    }

    memset(list_elt,0,sizeof(lispd_map_server_list_t));

    list_elt->address     = addr;
    list_elt->key_type    = key_type;
    list_elt->key         = strdup(key);
    list_elt->verify      = verify;
    list_elt->proxy_reply = proxy_reply;

    /*
     * hook this one to the front of the list
     */

    if (map_servers) {
        list_elt->next = map_servers;
        map_servers = list_elt;
    } else {
        map_servers = list_elt;
    }

    return(1);
}

/*
 *  add_proxy_etr_entry --
 *
 *  Add a proxy-etr entry
 *
 */

int add_proxy_etr_entry(petr, petr_list)
    cfg_t  *petr;
    lispd_weighted_addr_list_t      **petr_list;
{

    lisp_addr_t                     *address;
    lispd_weighted_addr_list_t      *petr_unit;

    uint32_t                flags = 0;

    char   *addr        = cfg_getstr(petr, "address");
    int    priority     = cfg_getint(petr, "priority");
    int    weight       = cfg_getint(petr, "weight");

    if (priority > 255 || priority < 0) {
        syslog (LOG_DAEMON, "WARNING: Priority %d out of range [0..255]", priority);
        return (0);
    }

    if (weight > 100 || weight < 0) {
        syslog (LOG_DAEMON, "WARNING: Weight %d out of range [0..100]", priority);
        return (0);
    }

    if ((address = malloc(sizeof(lisp_addr_t))) == NULL) {
        syslog(LOG_DAEMON, "malloc(sizeof(lisp_addr_t)): %s", strerror(errno));
        return(0);
    }
    if ((petr_unit = malloc(sizeof(lispd_weighted_addr_list_t))) == NULL) {
        syslog(LOG_DAEMON, "malloc(sizeof(lispd_weighted_addr_list_t)): %s", strerror(errno));
        free(address);
        return(0);
    }
    memset(address, 0,sizeof(lisp_addr_t));
    memset(petr_unit,0,sizeof(lispd_weighted_addr_list_t));

    if (lispd_get_address(addr,address,&flags)==BAD) {
        free(address);
        free(petr_unit);
    return(0);
    }
    petr_unit->address      = address;
    petr_unit->priority     = priority;
    petr_unit->weight       = weight;

    /*
     * hook this one to the front of the list
     */

    if (*petr_list) {
        petr_unit->next = *petr_list;
        *petr_list = petr_unit;
    } else {
        *petr_list = petr_unit;
    }

#ifdef DEBUG
        syslog(LOG_DAEMON, "Added %s to proxy-etr list", addr);
#endif

    return(1);
}


/*
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
