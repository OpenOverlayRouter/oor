/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef OOR_CONFIG_FUNCTIONS_H_
#define OOR_CONFIG_FUNCTIONS_H_

#include "../control/lisp_ms.h"
#include "../control/lisp_xtr.h"
#include "../lib/iface_locators.h"
#include "../lib/lisp_site.h"
#include "../lib/map_local_entry.h"
#include "../lib/shash.h"


#define MAX_CFG_STRING 100

typedef struct no_addr_loct_ {
    locator_t *     locator;
    char *          iface_name;
    int             afi;
}no_addr_loct;

typedef struct conf_loc_ {
    char * address;
    int priority;
    int weight;
    int mpriority;
    int mweight;
}conf_loc_t;

typedef struct conf_loc_iface_ {
    char * interface;
    int afi;
    int priority;
    int weight;
    int mpriority;
    int mweight;
}conf_loc_iface_t;

typedef struct conf_mapping_ {
    char    *eid_prefix;
    int     ttl;
    int     iid;
    glist_t *conf_loc_list;
    glist_t *conf_loc_iface_list;
}conf_mapping_t;

static inline conf_loc_t * conf_loc_new(){
    return ((conf_loc_t *)xzalloc(sizeof(conf_loc_t)));
}

inline conf_loc_t * conf_loc_new_init(char *addr, uint8_t priority,
        uint8_t weight, uint8_t mpriority, uint8_t mweight);

static inline void conf_loc_destroy(conf_loc_t *conf_loc){
    if (conf_loc == NULL) return;
    free(conf_loc->address);
    free(conf_loc);
}

char *conf_loc_to_char(conf_loc_t * loc);

static inline conf_loc_iface_t * conf_loc_iface_new(){
    return ((conf_loc_iface_t *)xzalloc(sizeof(conf_loc_iface_t)));
}

inline conf_loc_iface_t * conf_loc_iface_new_init(char *iface_name, int afi, uint8_t priority,
        uint8_t weight, uint8_t mpriority, uint8_t mweight);

static inline void conf_loc_iface_destroy(conf_loc_iface_t *conf_loc_iface){
    if (conf_loc_iface == NULL) return;
    free(conf_loc_iface->interface);
    free(conf_loc_iface);
}

char *conf_loc_iface_to_char(conf_loc_iface_t * loc_iface);


inline conf_mapping_t *conf_mapping_new();

inline void conf_mapping_destroy(conf_mapping_t * conf_map);

inline void conf_mapping_dump(conf_mapping_t * conf_map, int log_level);

no_addr_loct *
no_addr_loct_new_init(locator_t * loct, char *iface, int afi);

void
no_addr_loct_del(no_addr_loct * nloct);

no_addr_loct *
get_no_addr_loct_from_list(glist_t *list, locator_t *locator);

void
validate_rloc_probing_parameters(int *interval,int *retries,int *retries_int);

int
validate_priority_weight(int p, int w);

int
add_server(char *str_addr, glist_t *list);

int
add_map_server(glist_t *ms_list, char *str_addr, int key_type, char *key,
        uint8_t proxy_reply);

int
add_proxy_etr_entry(mcache_entry_t *petrs, char *str_addr, int priority,
        int weight);


/*
 * Create the locators associated with the address of the iface and assign them
 * to the mapping_t and the iface_locators
 * @param iface Interface containing the rlocs associated to the mapping
 * @param if_loct Structure that associate iface with locators
 * @param mapping Mapping where to add the new locators
 * @param priority4 priority of the IPv4 RLOC. 1..255 -1 the IPv4 address is not used
 * @param weight4 weight of the IPv4 RLOC
 * @param priority6 priority of the IPv6 RLOC. 1..255 -1 the IPv6 address is not used
 * @param weight6 weight of the IPv6 RLOC
 * @return GOOD if finish correctly or an error code otherwise
 */

int
link_iface_and_mapping(iface_t *iface, iface_locators *if_loct,
        map_local_entry_t *map_loc_e, int afi, int priority, int weight);

int
add_rtr_iface(lisp_xtr_t *xtr, char *iface_name,int afi, int priority,
        int weight);

lisp_site_prefix_t *
build_lisp_site_prefix(lisp_ms_t *ms, char *eidstr, uint32_t iid, int key_type,
        char *key, uint8_t more_specifics, uint8_t proxy_reply, uint8_t merge,
        shash_t *lcaf_ht);

char *
get_interface_name_from_address(lisp_addr_t *addr);


/* Parses an EID/RLOC (IP or LCAF) and returns a list of 'lisp_addr_t'.
 * Caller must free the returned value */
glist_t *
parse_lisp_addr(char *address, shash_t *lcaf_ht);

/* Parses a char (IP or FQDN) into a list of 'lisp_addr_t'.
 * Caller must free the returned value */
glist_t *
parse_ip_addr(char *addr_str);

locator_t*
clone_customize_locator(oor_ctrl_dev_t *dev, locator_t * locator,
        glist_t * no_addr_loct_l, uint8_t is_local);

mapping_t *
process_mapping_config(oor_ctrl_dev_t * dev, shash_t * lcaf_ht,
        conf_mapping_t * conf_mapping, uint8_t is_local);

int
add_local_db_map_local_entry(map_local_entry_t *map_loca_entry, lisp_xtr_t *xtr);

void nat_set_site_ID(lisp_xtr_t *xtr, uint64_t site_id);
void nat_set_xTR_ID(lisp_xtr_t *xtr);




#endif /* OOR_CONFIG_FUNCTIONS_H_ */
