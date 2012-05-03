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
        exit(0);

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
        CFG_STR("interface",            0, CFGF_NONE),
        CFG_INT("priority",             0, CFGF_NONE),
        CFG_INT("weight",               0, CFGF_NONE),
        CFG_END()
    };

    static cfg_opt_t mc_mapping_opts[] = {
        CFG_STR("eid-prefix",           0, CFGF_NONE),
        CFG_STR("rloc",                 0, CFGF_NONE),
        CFG_INT("priority",             0, CFGF_NONE),
        CFG_INT("weight",               0, CFGF_NONE),
        CFG_END()
    };

    cfg_opt_t opts[] = {
        CFG_SEC("database-mapping",     db_mapping_opts, CFGF_MULTI),
        CFG_SEC("static-map-cache",     mc_mapping_opts, CFGF_MULTI),
        CFG_SEC("map-server",           map_server_opts, CFGF_MULTI),
        CFG_INT("map-request-retries",  0, CFGF_NONE),
        CFG_INT("control-port",         0, CFGF_NONE),
        CFG_BOOL("debug",               cfg_false, CFGF_NONE),
        CFG_STR("map-resolver",         0, CFGF_NONE),
        CFG_STR("proxy-etr",            0, CFGF_NONE),
        CFG_STR_LIST("proxy-itrs",      0, CFGF_NONE),
        CFG_END()
    };

    /*
     *  parse config_file
     */

    cfg = cfg_init(opts, CFGF_NOCASE);
    ret = cfg_parse(cfg, config_file);

    if (ret == CFG_FILE_ERROR) {
        syslog(LOG_DAEMON, "Couldn't find config file (%s)", config_file);
        return 1;
    } else if(ret == CFG_PARSE_ERROR) {
        syslog(LOG_DAEMON, "Parse error (%s)", config_file);
        return 2;
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

    if ((proxy_etr = cfg_getstr(cfg, "proxy-etr")) != NULL) {
        if (!add_server(proxy_etr, &proxy_etrs))
            return(0); 
#ifdef DEBUG
        syslog(LOG_DAEMON, "Added %s to proxy-etr list", proxy_etr);
#endif
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
        syslog(LOG_DAEMON,"Can't add static-map-cache %d (%s->%s)",
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

    lisp_addr_t                 *rloc_ptr;
    char                        *token;
    char                        *eid;           /* save the eid_prefix here */
    int                         afi;
    patricia_node_t             *node;
    lispd_db_entry_t            *db_entry;
    lispd_locator_chain_t       *locator_chain;
    lispd_locator_chain_elt_t   *locator_chain_elt;

    char   *eid_prefix        = cfg_getstr(dm, "eid-prefix");
    char   *iface_name        = cfg_getstr(dm, "interface");
    int    priority           = cfg_getint(dm, "priority");
    int    weight             = cfg_getint(dm, "weight");
    eid = eid_prefix;           /* save this for later */

    char *eid_pref_for_add_iface = strdup (eid_prefix);
    lisp_addr_t eid_addr;

    memset(&eid_addr, 0, sizeof(lisp_addr_t));
    afi = get_afi(eid_prefix);  
    eid_addr.afi = afi;

    /*
     *  find or make the node correspoding to the eid_prefix/length 
     */

    switch (afi) {
    case AF_INET:
        node = make_and_lookup(AF4_database, AF_INET, eid);
        break;
    case AF_INET6:
        node = make_and_lookup(AF6_database, AF_INET6, eid);
        break;
    default:
        syslog(LOG_DAEMON, "Unknown AFI (%d) for %s", afi, eid);
        break;
    }

    if (node == NULL) {
        syslog(LOG_DAEMON, "Couldn't allocate patricia node");
        return(0);
    }

    if (if_nametoindex(iface_name) == 0) {
        syslog(LOG_DAEMON, "Invalid interface: %s\n", iface_name);
        return (0);
    }

    /* 
     * PN: Add this physical interface to the list of tracked
     * interfaces (for iface management purposes).
     * In case of multiple physical interfaces per EID,
     * each physical interface must be added via update_iface_list()
     */
    if (!update_iface_list (iface_name, eid, NULL, 
                1, priority, weight)) {
        syslog(LOG_DAEMON, "add_iface (%s) failed\b", iface_name);
        return(0);
    } 

    if ((token = strtok(eid_prefix, "/")) == NULL) {
        syslog(LOG_DAEMON,"eid prefix not of the form prefix/length");
        return(0);
    }

    /* 
     *  get the EID prefix into the right place/format
     */

    if (inet_pton(afi, token, &eid_addr.address) != 1) {
        syslog(LOG_DAEMON, "inet_pton: %s", strerror(errno));
        return(0);
    }

    /*
     *  get the prefix length into token
     */

    if ((token = strtok(NULL,"/")) == NULL) {
        syslog(LOG_DAEMON, "strtok: %s", strerror(errno));
        return(0);
    }

    /* 
     * PN: Setup the LISP-MN interface (ex: lmn0) for this EID.
     * Assume single EID/LISP-MN interface per MN for now.
     * Multiple EIDs per MN is a possibility in the future; then
     * each EID requires its own LISP-MN interface and 
     * one of the interfaces will be the default one.
     */
    if (!setup_lisp_eid_iface(LISP_MN_EID_IFACE_NAME, 
                &eid_addr,
                atoi (token))) {
        syslog(LOG_DAEMON, "setup_lisp_eid_iface (%s) failed\b", iface_name);
    } 

    if ((rloc_ptr = malloc(sizeof(lisp_addr_t))) == NULL) {
        syslog(LOG_DAEMON,"malloc(sizeof(lisp_addr_t)): %s", strerror(errno));
        return(0);
    }
    memset(rloc_ptr,0,sizeof(lisp_addr_t));

    if (!lispd_get_iface_address(iface_name,rloc_ptr)) {
        syslog(LOG_DAEMON, "Can't get address for %s", iface_name);
        free(rloc_ptr);
        return(0);
    }

    if ((db_entry = malloc(sizeof(lispd_db_entry_t))) == NULL) {
        syslog(LOG_DAEMON,"malloc(sizeof(lispd_database_t)): %s", strerror(errno));
        return(0);
    }

    memset(db_entry,0,sizeof(lispd_db_entry_t));

    db_entry->locator_name = strdup(iface_name);        /* save the name */

    /*
     *  store the locator address and afi
     */

    memcpy((void *) &(db_entry->locator.address),
           (void *) &(rloc_ptr->address),
           sizeof(lisp_addr_t));
    db_entry->locator.afi = rloc_ptr->afi;

    memcpy((void *) &(db_entry->eid_prefix.address),
           (void *) &(eid_addr.address),
           sizeof(lisp_addr_t));
    db_entry->eid_prefix_length = atoi(token);
    db_entry->eid_prefix.afi    = afi;

    db_entry->priority          = priority;
    db_entry->weight            = weight;
    db_entry->mpriority         = 255;
    db_entry->mweight           = 0;

    if (node->data == NULL) {           /* its a new node */
        if ((locator_chain = malloc(sizeof(lispd_locator_chain_t))) == NULL) {
            syslog(LOG_DAEMON, "Can't malloc(sizeof(lispd_locator_chain_t))");
            free(rloc_ptr);
            free(db_entry);
            free(eid);
            return(0);
        }
        memset(locator_chain,0,sizeof(lispd_locator_chain_t));

        node->data = (lispd_locator_chain_t *) locator_chain;   /* set up chain */

        /*
         *      put the eid_prefix information into the locator_chain
         */

        copy_lisp_addr_t(&(locator_chain->eid_prefix),
                         &(db_entry->eid_prefix),
                         0);            
        locator_chain->eid_prefix_length    = db_entry->eid_prefix_length;
        locator_chain->eid_prefix.afi       = db_entry->eid_prefix.afi;
        locator_chain->eid_name             = strdup(eid);
        locator_chain->has_dynamic_locators = DYNAMIC_LOCATOR;
        locator_chain->timer                = DEFAULT_MAP_REGISTER_TIMEOUT;
    } else {                            /* there's an existing locator_chain */
        locator_chain = (lispd_locator_chain_t *) node->data;   /* have one */
    }

    if ((locator_chain_elt = malloc(sizeof(lispd_locator_chain_elt_t))) == NULL) {
        syslog(LOG_DAEMON, "Can't malloc(sizeof(lispd_locator_chain_elt_t))");
        free(rloc_ptr);
        free(db_entry);
        free(eid);
        return(0);
    }

#if (DEBUG > 3)
    char x[128];
    memset(x,0,128);
    inet_ntop(locator_chain->eid_prefix.afi,
              &(locator_chain->eid_prefix),
              x, 128);
    printf("add_database_mapping: locator_chain->eid_prefix = %s (0x%x)\n" ,x, locator_chain);
#endif

    memset(locator_chain_elt, 0, sizeof(lispd_locator_chain_elt_t));

    /*
     *  link up db_entry
     */

    locator_chain_elt->db_entry      = db_entry;  
    locator_chain_elt->locator_name  = db_entry->locator_name;

    /*
     *  connect up the locator_chain and locator_chain_elt
     */
    if (locator_chain->head == NULL) {
        locator_chain->head = locator_chain_elt;
        locator_chain->tail = locator_chain_elt;
    } else {
        locator_chain->tail->next = locator_chain_elt;
        locator_chain->tail       = locator_chain_elt;
    }

    locator_chain->locator_count ++;
       
    /* 
     * PN: Update interface information with the new rloc 
     * information
     */
    if (!update_iface_list (iface_name, eid_pref_for_add_iface, 
                db_entry, 1, priority, weight)) {
        syslog(LOG_DAEMON, "update_iface_list: (%s) failed\b", iface_name);
    }

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

    free(eid_pref_for_add_iface);
    free(rloc_ptr);
    return(1);
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

    lisp_addr_t             *rloc_ptr;
    lispd_map_cache_t       *map_cache;
    lispd_map_cache_entry_t *map_cache_entry;
    
    char                    *token;
    int                     afi;
    uint32_t                flags = 0;

    char   *eid_prefix  = cfg_getstr(smc, "eid-prefix");
    char   *rloc        = cfg_getstr(smc, "rloc");
    int    priority     = cfg_getint(smc, "priority");
    int    weight       = cfg_getint(smc, "weight");

    if ((rloc_ptr = malloc(sizeof(lisp_addr_t))) == NULL) {
        syslog(LOG_DAEMON, "malloc(sizeof(lisp_addr_t)): %s", strerror(errno));
        return(0);
    }
    if ((map_cache = malloc(sizeof(lispd_map_cache_t))) == NULL) {
        syslog(LOG_DAEMON, "malloc(sizeof(lispd_map_cache_t)): %s", strerror(errno));
        return(0);
    }
    memset(rloc_ptr, 0,sizeof(lisp_addr_t));
    memset(map_cache,0,sizeof(lispd_map_cache_t));

    map_cache_entry = &(map_cache->map_cache_entry);

    if (!lispd_get_address(rloc,rloc_ptr,&flags)) {
        free(rloc_ptr);
        free(map_cache);
    return(0);
    }

    /*
     *  store the locator address and afi
     */

    memcpy(&(map_cache_entry->locator), rloc_ptr, sizeof(lisp_addr_t));
    map_cache_entry->ttl          = 255;    /*shouldn't matter */
    map_cache_entry->locator_name = strdup(rloc);
    map_cache_entry->locator_type = flags;

    map_cache_entry->how_learned  = STATIC_MAP_CACHE_ENTRY;

    afi = get_afi(eid_prefix);

    if ((token = strtok(eid_prefix, "/")) == NULL) {
        sprintf(msg,"eid prefix not of the form prefix/length ");
        syslog(LOG_DAEMON, "%s", msg);
        free(rloc_ptr);
        free(map_cache);
        return(0);
    }

    /* 
     *  get the EID prefix into the right place/format
     */

    if (inet_pton(afi, token, &(map_cache_entry->eid_prefix.address)) != 1) {
        syslog(LOG_DAEMON, "inet_pton: %s (%s)", strerror(errno), token);
        free(rloc_ptr);
        free(map_cache);
        return(0);
    }

    /*
     *  get the prefix length into token
     */

    if ((token = strtok(NULL,"/")) == NULL) {
        syslog(LOG_DAEMON,"strtok: %s", strerror(errno));
        free(rloc_ptr);
        free(map_cache);
        return(0);
    }

    map_cache_entry->eid_prefix_length = atoi(token);
    map_cache_entry->eid_prefix.afi    = afi;
    map_cache_entry->priority          = priority;
    map_cache_entry->weight            = weight;

    if (lispd_database) 
    map_cache->next = lispd_map_cache;
    else
    map_cache->next = NULL;
    lispd_map_cache = map_cache;

    free(rloc_ptr);
    return(1);
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
 * Editor modelines
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
