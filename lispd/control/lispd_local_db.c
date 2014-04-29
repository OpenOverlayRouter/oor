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


local_map_db_t *
local_map_db_new() {
    local_map_db_t *db;
    db = calloc(1, sizeof(local_map_db_t));
    if (!db) {
        lmlog(LCRIT, "Could allocate map cache db ");
        exit_cleanup();
    }

    db->db = mdb_new();
    if (!db->db) {
        lmlog(LCRIT, "Could allocate map cache db ");
        exit_cleanup();
    }

    return(db);
}


int
local_map_db_add_mapping(local_map_db_t *lmdb, mapping_t *mapping)
{
    if (mdb_add_entry(lmdb->db, mapping_eid(mapping), mapping) != GOOD) {
        lmlog(DBG_3, "Couldn't add mapping for EID %s to local mappings db",
                lisp_addr_to_char(mapping_eid(mapping)));
        return(BAD);
    }

    total_mappings ++;
    return(GOOD);
}

mapping_t *
local_map_db_lookup_eid(local_map_db_t *lmdb, lisp_addr_t *eid)
{
    mapping_t *mapping = NULL;

    mapping = mdb_lookup_entry(lmdb->db, eid);
    if (!mapping) {
        lmlog(DBG_3, "Couldn't find mapping for EID %s in local mappings db",
                lisp_addr_to_char(eid));
        return (NULL);
    }
    return (mapping);
}

mapping_t *
local_map_db_lookup_eid_exact(local_map_db_t *lmdb, lisp_addr_t *eid)
{
    mapping_t *mapping = NULL;

    if (lisp_addr_afi(eid) == LM_AFI_IP) {
        lmlog(LWRN, "Called with IP EID %s, probably it should've been an "
                "IPPREF", lisp_addr_to_char(eid));
    }

    mapping = mdb_lookup_entry_exact(lmdb->db, eid);
    if (!mapping) {
        lmlog(DBG_3, "Couldn't find mapping for EID %s in local mappings db",
                lisp_addr_to_char(eid));
        return (NULL);
    }
    return (mapping);
}

void
local_map_db_del_mapping(local_map_db_t *lmdb, lisp_addr_t *eid)
{
    mapping_t *mapping = NULL;
    mapping = mdb_remove_entry(lmdb->db, eid);
    if (mapping) {
        mapping_del(mapping);
        total_mappings--;
    }
}

lisp_addr_t *
local_map_db_get_main_eid(local_map_db_t *lmdb, int afi)
{
    void                *it         = NULL;
    lisp_addr_t         *eid        = NULL;

    mdb_foreach_ip_entry(lmdb->db, it) {
        eid = mapping_eid((mapping_t *)it);
        if (eid && lisp_addr_ip_afi(eid) == afi) {
            return(eid);
        }
    } mdb_foreach_ip_entry_end;
    return(NULL);
}

int
local_map_db_num_ip_eids(local_map_db_t *lmdb, int afi)
{
    void *it = NULL;
    lisp_addr_t *eid = NULL;
    int ctr = 0;

    /* search could be better implemented but local db is small
     * so this should do for now  */
    mdb_foreach_ip_entry(lmdb->db, it) {
        eid = mapping_eid((mapping_t *)it);
        if (eid && lisp_addr_afi(eid) == LM_AFI_IP
            && lisp_addr_ip_afi(eid) == afi) {
            ctr ++;
        }
    } mdb_foreach_ip_entry_end;

    return (ctr);
}

void
local_map_db_dump(local_map_db_t *lmdb, int log_level)
{
    mapping_t *mapping = NULL;
    void *it = NULL;

    lmlog(log_level,"****************** LISP Local Mappings ****************\n");

    mdb_foreach_entry(lmdb->db, it) {
        mapping = it;
        mapping_to_char(mapping, log_level);
    } mdb_foreach_entry_end;
    lmlog(log_level,"*******************************************************\n");
}
