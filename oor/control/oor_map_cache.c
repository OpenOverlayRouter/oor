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

#include "oor_map_cache.h"
#include "../lib/oor_log.h"
#include <math.h>


map_cache_db_t*
mcache_new()
{
    map_cache_db_t *mcdb = xzalloc(sizeof(map_cache_db_t));
    if (!mcdb) {
        OOR_LOG(LCRIT, "Could allocate map cache db ");
        return(NULL);
    }

    mcdb->db = mdb_new();
    if (!mcdb->db) {
        OOR_LOG(LCRIT, "Could create map cache db ");
        return(NULL);
    }

    return(mcdb);
}

void
mcache_del(map_cache_db_t *mcdb)
{
    mdb_del(mcdb->db, (mdb_del_fct)mcache_entry_del);
    free(mcdb);
}


int
mcache_add_entry(map_cache_db_t *mcdb, lisp_addr_t *key, mcache_entry_t *mce)
{
    return(mdb_add_entry(mcdb->db, key, mce));
}

void *
mcache_remove_entry(map_cache_db_t *mcdb, lisp_addr_t *key)
{
    return(mdb_remove_entry(mcdb->db, key));
}


/*
 * Look up a given lisp_addr_t in the database, returning the
 * oor_map_cache_entry of this lisp_addr_t if it exists or NULL
 * if the returned entry is the all space entry.
 */
mcache_entry_t *
mcache_lookup(map_cache_db_t *mcdb, lisp_addr_t *laddr)
{
    mcache_entry_t * mce = mdb_lookup_entry(mcdb->db, laddr);
    lisp_addr_t *eid;
    if (!mce){
        return (NULL);
    }
    eid =  mcache_entry_eid(mce);
    // If the entry is the all space entry return NULL
    if (lisp_addr_is_ip_pref(eid) && lisp_addr_get_plen(eid) == 0){
        return (NULL);
    }
    return(mce);
}

/*
 * Find an exact match for a prefix/prefixlen if possible
 */
mcache_entry_t *
mcache_lookup_exact(map_cache_db_t *mcdb, lisp_addr_t *laddr)
{
    return(mdb_lookup_entry_exact(mcdb->db, laddr));
}

/*
 * Return the full space entry 0.0.0.0/0 or ::/0 according to afi
 */
mcache_entry_t *
mcache_get_all_space_entry(map_cache_db_t *mcdb, int afi)
{
    mcache_entry_t *mce;
    lisp_addr_t addr;

    switch (afi){
    case AF_INET:
        lisp_addr_ippref_from_char(FULL_IPv4_ADDRESS_SPACE, &addr);
        mce = mcache_lookup_exact(mcdb, &addr);
        return (mce);
    case AF_INET6:
        lisp_addr_ippref_from_char(FULL_IPv6_ADDRESS_SPACE, &addr);
        mce = mcache_lookup_exact(mcdb, &addr);
        return (mce);
    default:
        return (NULL);
    }
}


void mcache_dump_db(map_cache_db_t *mcdb, int log_level)
{
    if (is_loggable(log_level) == FALSE) {
        return;
    }

    mcache_entry_t *mce;
    void *it;

    OOR_LOG(log_level,"**************** LISP Mapping Cache ******************\n");
    mdb_foreach_entry(mcdb->db, it) {
        mce = (mcache_entry_t *)it;
        map_cache_entry_dump(mce, log_level);
    } mdb_foreach_entry_end;
    OOR_LOG(log_level,"*******************************************************\n");

}
