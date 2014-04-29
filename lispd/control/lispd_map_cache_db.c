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


map_cache_db_t*
mcache_new() {
    map_cache_db_t *mcdb = calloc(1, sizeof(map_cache_db_t));
    if (!mcdb) {
        lmlog(LCRIT, "Could allocate map cache db ");
        exit_cleanup();
    }

    mcdb->db = mdb_new();
    if (!mcdb->db) {
        lmlog(LCRIT, "Could create map cache db ");
        exit_cleanup();
    }

    return(mcdb);
}

int
mcache_add_mapping(lisp_ctrl_dev_t *dev, mapping_t *m)
{
    map_cache_db_t *mcdb;
    mcache_entry_t *mce;
    lisp_addr_t *addr;

    mcdb = ctrl_dev_get_map_cache(dev); dev->tr_class->get_map_cache(dev);

    /* TODO: will change when nonces are handled outside of the map-cache */
    addr = mapping_eid(m);
    mce = mcache_entry_new();
    mcache_entry_init(mce, m);

    /* prepare mapping for installment */
    mapping_compute_balancing_vectors(m);

    /* Reprogramming timers */
    macache_start_expiration_timer_entry(dev, mce);

    /* RLOC probing timer */
    program_mapping_rloc_probing(dev, m);

    return(mdb_add_entry(mcdb->db, addr, mce));
}

int
mcache_add_static_mapping(map_cache_db_t *mcdb, mapping_t *mapping)
{
    mcache_entry_t *mce;
    lisp_addr_t *addr;

    addr = mapping_eid(mapping);
    mce = mcache_entry_new();
    mcache_entry_init_static(mce, mapping);
    program_mapping_rloc_probing(mapping);

    return (mdb_add_entry(mcdb->db, addr, mce));
}

int
mcache_remove_mapping(map_cache_db_t *mcdb, lisp_addr_t *laddr)
{
    void *data;
    data = mdb_remove_entry(mcdb->db, laddr);
    map_cache_entry_del(data);
    return (GOOD);
}

mapping_t *
mcache_lookup_mapping(map_cache_db_t *mcdb, lisp_addr_t *laddr)
{

    mcache_entry_t *mce;
    mce = mdb_lookup_entry(mcdb->db, laddr);

    if ((mce == NULL) || (mce->active == NOT_ACTIVE))
        return (NULL);
    else
        return (mcache_entry_mapping(mce));
}

mapping_t *
mcache_lookup_mapping_exact(map_cache_db_t *mcdb, lisp_addr_t *laddr)
{
    mcache_entry_t *mce;

    mce = mdb_lookup_entry_exact(mcdb->db, laddr);

    if (!mce || (mce->active == NOT_ACTIVE))
        return (NULL);
    else
        return (mcache_entry_mapping(mce));
}





int
map_cache_add_entry(map_cache_db_t *mcdb, mcache_entry_t *mce)
{
    return(mdb_add_entry(mcdb->db, mapping_eid(mcache_entry_mapping(mce)), mce));
}


/*
 * Look up a given lisp_addr_t in the database, returning the
 * lispd_map_cache_entry of this lisp_addr_t if it exists or NULL.
 */
mcache_entry_t *
map_cache_lookup(map_cache_db_t *mcdb, lisp_addr_t *laddr)
{
    return(mdb_lookup_entry(mcdb->db, laddr));
}

/*
 * Find an exact match for a prefix/prefixlen if possible
 */
mcache_entry_t *
map_cache_lookup_exact(map_cache_db_t *mcdb, lisp_addr_t *laddr)
{
    return(mdb_lookup_entry_exact(mcdb->db, laddr));
}

/* Called when the timer associated with an EID entry expires. */
static int
mcache_start_expiration_entry_cb(timer *t, void *arg)
{
    mcache_entry_t *entry = NULL;
    mapping_t *mapping = NULL;
    lisp_addr_t *addr = NULL;

    entry = (mcache_entry_t *)arg;
    mapping = mcache_entry_mapping(entry);
    addr = mapping_eid(mapping);
    lmlog(DBG_1,"Got expiration for EID %s", lisp_addr_to_char(addr));

    mcache_remove_mapping(addr);
    return(GOOD);
}

void
macache_start_expiration_timer_entry(lisp_ctrl_dev_t *dev, mcache_entry_t *mce)
{
    /* Expiration cache timer */
    if (!mce->expiry_cache_timer) {
        mce->expiry_cache_timer = create_timer(EXPIRE_MAP_CACHE_TIMER);
    }

    start_timer(mce->expiry_cache_timer, mce->ttl*60,
            mcache_start_expiration_entry_cb,(void *)mce);

    lmlog(DBG_1,"The map cache entry of EID %s will expire in %ld minutes.",
            lisp_addr_to_char(mapping_eid(mcache_entry_mapping(mce))),
            mce->ttl);
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


void map_cache_dump_db(map_cache_db_t *mcdb, int log_level)
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






