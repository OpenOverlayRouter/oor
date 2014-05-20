/*
 * lisp_map_cache_db.c
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
 *    Albert Lopez      <alopez@ac.upc.edu>
 *    Florin Coras      <fcoras@ac.upc.edu>
 */

#include "lisp_map_cache.h"
#include "lmlog.h"
#include <math.h>


map_cache_db_t*
mcache_new()
{
    map_cache_db_t *mcdb = xzalloc(sizeof(map_cache_db_t));
    if (!mcdb) {
        lmlog(LCRIT, "Could allocate map cache db ");
        return(NULL);
    }

    mcdb->db = mdb_new();
    if (!mcdb->db) {
        lmlog(LCRIT, "Could create map cache db ");
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
 * lispd_map_cache_entry of this lisp_addr_t if it exists or NULL.
 */
mcache_entry_t *
mcache_lookup(map_cache_db_t *mcdb, lisp_addr_t *laddr)
{
    return(mdb_lookup_entry(mcdb->db, laddr));
}

/*
 * Find an exact match for a prefix/prefixlen if possible
 */
mcache_entry_t *
mcache_lookup_exact(map_cache_db_t *mcdb, lisp_addr_t *laddr)
{
    return(mdb_lookup_entry_exact(mcdb->db, laddr));
}



/* Looks up @nonce among the not active cache entries having afi @afi. Return
 * the entry if any is found */
mcache_entry_t *
lookup_nonce_in_no_active_map_caches(map_cache_db_t *mcdb, lisp_addr_t *eid,
        uint64_t nonce) {
    void *it;
    mcache_entry_t *mce;

    mdb_foreach_entry(mcdb->db, it){
        mce = it;
        if (mce->active == FALSE) {
            if (nonce_check(mce->nonces,nonce) == GOOD) {
                free(mce->nonces);
                mce->nonces = NULL;
                return(mce);
            }
        }
    } mdb_foreach_entry_end;

    return (NULL);
}


void mcache_dump_db(map_cache_db_t *mcdb, int log_level)
{
    mcache_entry_t *mce;
    void *it;

    lmlog(log_level,"**************** LISP Mapping Cache ******************\n");
    mdb_foreach_entry(mcdb->db, it) {
        mce = (mcache_entry_t *)it;
        map_cache_entry_to_char(mce, log_level);
    } mdb_foreach_entry_end;
    lmlog(log_level,"*******************************************************\n");

}





