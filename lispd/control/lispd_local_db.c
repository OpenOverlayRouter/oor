/*
 * lispd_local_db.h
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
 *    Albert Lopez              <alopez@ac.upc.edu>
 *    Alberto Rodriguez Natal   <arnatal@ac.upc.edu>
 */


#include "lispd_local_db.h"
#include <netinet/in.h>
#include "lispd_external.h"
#include "lispd_lib.h"
//#include "lispd_map_cache_db.h"


mdb_t *local_mdb = NULL;

/*
 * Initialize databases
 */


void local_map_db_init(void)
{
    local_mdb = mdb_new();
    if (!local_mdb) {
        lispd_log_msg(LISP_LOG_CRIT, "Could not initialize the local mappings db! Exiting .. ");
        exit_cleanup();
    }

}

/*
 *  Add a mapping entry to the database.
 */
int local_map_db_add_mapping(mapping_t *mapping)
{
    if (mdb_add_entry(local_mdb, mapping_eid(mapping), mapping) != GOOD) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "Couldn't add mapping for EID %s to local mappings db",
                lisp_addr_to_char(mapping_eid(mapping)));
        return(BAD);
    }

    total_mappings ++;
    return(GOOD);
}

/*
 * lookup_eid_in_db
 *
 * Look up a given eid in the database, returning the
 * lispd_mapping_elt of this EID if it exists or NULL.
 */
mapping_t *local_map_db_lookup_eid(lisp_addr_t *eid)
{

    mapping_t       *mapping = NULL;

    mapping = mdb_lookup_entry(local_mdb, eid);
    if (!mapping) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "Couldn't find mapping for EID %s in local mappings db",
                        lisp_addr_to_char(eid));
        return(NULL);
    }
    return(mapping);
}

/*
 * lookup_eid_in_db
 *
 *  Look up a given eid in the database, returning the
 * lispd_mapping_elt containing the exact EID if it exists or NULL.
 */
mapping_t *local_map_db_lookup_eid_exact(lisp_addr_t *eid)
{
    mapping_t       *mapping = NULL;

    if (lisp_addr_get_afi(eid) == LM_AFI_IP) {
        lispd_log_msg(LISP_LOG_WARNING, "Called with IP EID %s, probably it should've been an IPPREF",
                lisp_addr_to_char(eid));
    }

    mapping = mdb_lookup_entry_exact(local_mdb, eid);
    if (!mapping) {
        lispd_log_msg(LISP_LOG_DEBUG_3, "Couldn't find mapping for EID %s in local mappings db",
                        lisp_addr_to_char(eid));
        return(NULL);
    }
    return(mapping);
}

/*
 * del_mapping_entry_from_db()
 *
 * Delete an EID mapping from the data base
 */
void local_map_db_del_mapping(lisp_addr_t *eid)
{
    mapping_t    *mapping   = NULL;
    mapping = mdb_remove_entry(local_mdb, eid);
    if (mapping) {
        mapping_del(mapping);
        total_mappings--;
    }
}

lisp_addr_t *local_map_db_get_main_eid(int afi) {

    void                *it         = NULL;
    lisp_addr_t         *eid        = NULL;

    mdb_foreach_entry(local_mdb, it) {
        eid = mapping_eid((mapping_t *)it);

        if (eid && lisp_addr_ip_get_afi(eid) == afi)
            return(eid);

    } mdb_foreach_entry_end;
    return(NULL);
}

/*
 * Return the number of IP entries of requested afi in the database
 */
int local_map_db_num_ip_eids(int afi){
    void                *it         = NULL;
    lisp_addr_t         *eid        = NULL;
    int                 ctr         = 0;

    /* search could be better implemented but local db is small
     * so this should do for now
     */
    mdb_foreach_entry(local_mdb, it) {
        eid = mapping_eid((mapping_t *)it);
        if (eid && lisp_addr_get_afi(eid) == LM_AFI_IP && lisp_addr_ip_get_afi(eid) == afi)
            ctr ++;
    }mdb_foreach_entry_end;

    return (ctr);
}

/*
 * dump the mapping list of the database
 */
void local_map_db_dump(int log_level)
{
    mapping_t   *mapping    = NULL;
    void                *it         = NULL;

    lispd_log_msg(log_level,"****************** LISP Local Mappings ****************\n");

    mdb_foreach_entry(local_mdb, it) {
        mapping = (mapping_t *)it;
        dump_mapping_entry(mapping, log_level);
    } mdb_foreach_entry_end;
    lispd_log_msg(log_level,"*******************************************************\n");
}

