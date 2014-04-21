/*
 * lispd_map_cache_db.c
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
 */

#include "lispd_map_cache_db.h"
#include "lispd_lib.h"
#include "lispd_rloc_probing.h"
#include <math.h>

mdb_t *mdb = NULL;


/*
 * create_tables
 */
void map_cache_init()
{
    mdb = mdb_new();
    if (!mdb) {
        lmlog(LCRIT, "Could not initialize the mappings cache! Exiting .. ");
        exit(1);
    }
}

int
mcache_add_mapping(mapping_t *m)
{
    mcache_entry_t *mce;
    lisp_addr_t *addr;

    /* TODO: will change when nonces are handled outside of the map-cache */
    addr = mapping_eid(m);
    mce = mcache_new();
    mcache_entry_init(mce, m);

    /* prepare mapping for installment */
    mapping_compute_balancing_vectors(m);

    /* Reprogramming timers */
    map_cache_entry_start_expiration_timer(mce);

    /* RLOC probing timer */
    mapping_program_rloc_probing(m);

    return(mdb_add_entry(mdb, addr, mce));
}

int
mcache_add_static_mapping(mapping_t *mapping)
{
    mcache_entry_t *mce;
    lisp_addr_t *addr;

    addr = mapping_eid(mapping);
    mce = mcache_entry_new();
    mcache_entry_init_static(mce, mapping);
    mapping_program_rloc_probing(mapping);

    return (mdb_add_entry(mdb, addr, mce));
}

int
mcache_del_mapping(lisp_addr_t *laddr)
{
    void *data;
    data = mdb_remove_entry(mdb, laddr);
    map_cache_entry_del(data);
    return (GOOD);
}

mapping_t *mcache_lookup_mapping(lisp_addr_t *laddr)
{

    mcache_entry_t *mce;
    mce = mdb_lookup_entry(mdb, laddr);

    if ((mce == NULL) || (mce->active == NOT_ACTIVE))
        return (NULL);
    else
        return (mcache_entry_mapping(mce));
}

mapping_t *mcache_lookup_mapping_exact(lisp_addr_t *laddr)
{
    mcache_entry_t *mce;

    mce = mdb_lookup_entry_exact(mdb, laddr);

    if (!mce || (mce->active == NOT_ACTIVE))
        return (NULL);
    else
        return (mcache_entry_mapping(mce));
}





int
map_cache_add_entry(mcache_entry_t *mce)
{
    return(mdb_add_entry(mdb, mapping_eid(mcache_entry_mapping(mce)), mce));
}


/*
 * Look up a given lisp_addr_t in the database, returning the
 * lispd_map_cache_entry of this lisp_addr_t if it exists or NULL.
 */
mcache_entry_t *
map_cache_lookup(lisp_addr_t *laddr)
{
    return(mdb_lookup_entry(mdb, laddr));
}

/*
 * Find an exact match for a prefix/prefixlen if possible
 */
mcache_entry_t *
map_cache_lookup_exact(lisp_addr_t *laddr)
{
    return(mdb_lookup_entry_exact(mdb, laddr));
}



/* Looks up @nonce among the not active cache entries having afi @afi. Return
 * the entry if any is found */
mcache_entry_t *
lookup_nonce_in_no_active_map_caches(lisp_addr_t *eid, uint64_t nonce) {
    void *it;
    mcache_entry_t *mce;

    mdb_foreach_entry(mdb, it){
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


void map_cache_dump_db(int log_level)
{
    mcache_entry_t *mce;
    void *it;

    lmlog(log_level,"**************** LISP Mapping Cache ******************\n");
    mdb_foreach_entry(mdb, it) {
        mce = (mcache_entry_t *)it;
        map_cache_entry_dump(mce, log_level);
    } mdb_foreach_entry_end;
    lmlog(log_level,"*******************************************************\n");

}






