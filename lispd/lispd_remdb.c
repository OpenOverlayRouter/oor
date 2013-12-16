/*
 * lispd_re_jib.c
 *
 *  Created on: Oct 27, 2013
 *      Author: florin
 */

#include "defs_re.h"

void free_remdb_member(void *member) {
    /*
     * TODO: free a member
     */
}

lispd_remdb_t *remdb_new() {
    lispd_remdb_t     *db    = NULL;
    db =  glist_new(NULL, free_remdb_member);
    return(db);
}

glist_t *remdb_get_orlist(lispd_remdb_t *jib) {
    glist_t        *orlist     = NULL;
    lispd_remdb_member_t           *jibentry   = NULL;
    glist_entry_t  *it         = NULL;

    orlist = glist_new(NULL, free_remdb_member);

    glist_for_each_entry(it,jib){
        /* Ugly but should do for now. Just take the first locator */
        jibentry = (lispd_remdb_member_t *)glist_entry_get_data(it);
        glist_add(jibentry->locators->locator, orlist);
    }

    return(orlist);
}

void remdb_add_member(lisp_addr_t *peer, lisp_addr_t *rloc_pair, lispd_remdb_t *jib) {

    lispd_remdb_member_t *member;

    assert(jib);
    assert(rloc_pair);

    member = remdb_member_init(peer, rloc_pair);
    glist_add(member, jib);
}

lispd_remdb_member_t *remdb_find_member(lisp_addr_t *peer, lispd_remdb_t *jib) {
    glist_entry_t           *it         = NULL;
    lispd_remdb_member_t    *member     = NULL;

    assert(peer);
    assert(jib);

    glist_for_each_entry(it,jib) {
        member = (lispd_remdb_member_t *)glist_entry_get_data(it);
        if (lisp_addr_cmp(member->addr, peer))
            return(member);
    }

    return(NULL);


}

void remdb_del_member(lisp_addr_t *addr, lispd_remdb_t *jib) {
    glist_entry_t           *it         = NULL;
    lispd_remdb_member_t    *member     = NULL;

    glist_for_each_entry(it,jib) {
        member = (lispd_remdb_member_t *)glist_entry_get_data(it);
        if (lisp_addr_cmp(member->addr, addr))
            glist_del(it, jib);
    }
}

inline uint32_t remdb_size(lispd_remdb_t *jib) {
    return(glist_size(jib));
}

lispd_remdb_member_t *remdb_member_init(lisp_addr_t *src, lisp_addr_t *rloc_pair) {
    lispd_remdb_member_t    *member             = NULL;
    lispd_locators_list     *locator_list       = NULL;

    member = calloc(1, sizeof(lispd_remdb_member_t));
    locator_list  = calloc(1, sizeof(lispd_locators_list));
    locator_list->locator = calloc(1, sizeof(lispd_locator_elt));
    locator_list->next = NULL;
    /* the pair is of the type (S-RLOC, D-RLOC)
     * If the join will carry in the future more D-RLOCs for TE
     * add them one by one to the locator list
     */
    locator_list->locator->locator_addr = lisp_addr_clone(rloc_pair);

    member->addr = lisp_addr_clone(src);
    member->locators = locator_list;

    return(member);
}
