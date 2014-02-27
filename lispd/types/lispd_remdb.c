

#include "lispd_remdb.h"
//#include "defs_re.h"

remdb_t *remdb_new() {
    remdb_t     *db    = NULL;
    db =  glist_new(NO_CMP, NO_DEL);
    return(db);
}

void remdb_del(remdb_t *db) {
    glist_destroy(db);
}

glist_t *remdb_get_orlist(remdb_t *jib) {
    glist_t                 *orlist     = NULL;
    remdb_member_t          *jibentry   = NULL;
    glist_entry_t           *it         = NULL;

    orlist = glist_new(NO_CMP, NO_DEL);

    glist_for_each_entry(it,jib){
        /* Ugly but should do for now. Just take the first locator */
        jibentry = glist_entry_data(it);

        if (jibentry->locators->locator)
            glist_add(jibentry->locators->locator, orlist);
    }

    return(orlist);
}

void remdb_add_member(lisp_addr_t *peer, lisp_addr_t *rloc_pair, remdb_t *jib) {

    remdb_member_t *member;

    assert(jib);
    assert(rloc_pair);

    member = remdb_member_init(peer, rloc_pair);
    glist_add(member, jib);
}

remdb_member_t *remdb_find_member(lisp_addr_t *peer, remdb_t *jib) {
    glist_entry_t     *it         = NULL;
    remdb_member_t    *member     = NULL;

    assert(peer);
    assert(jib);

    glist_for_each_entry(it,jib) {
        member = glist_entry_data(it);
        if (lisp_addr_cmp(member->addr, peer))
            return(member);
    }

    return(NULL);
}

void remdb_del_member(lisp_addr_t *addr, remdb_t *jib) {
    glist_entry_t           *it         = NULL;
    remdb_member_t    *member     = NULL;

    glist_for_each_entry(it,jib) {
        member = (remdb_member_t *)glist_entry_data(it);
        if (lisp_addr_cmp(member->addr, addr))
            glist_del(it, jib);
    }
}

inline uint32_t remdb_size(remdb_t *jib) {
    return(glist_size(jib));
}

remdb_member_t *remdb_member_init(lisp_addr_t *src, lisp_addr_t *rloc_pair) {
    remdb_member_t    *member             = NULL;
    lispd_locators_list     *locator_list       = NULL;

    member = calloc(1, sizeof(remdb_member_t));
    locator_list  = calloc(1, sizeof(lispd_locators_list));
    locator_list->locator = calloc(1, sizeof(locator_t));
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
