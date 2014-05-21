

#include "lispd_remdb.h"
//#include "defs_re.h"

remdb_t *remdb_new() {
    remdb_t     *db    = NULL;
    db =  glist_new();
    return(db);
}

void remdb_del(remdb_t *db) {
    glist_destroy(db);
}

glist_t *remdb_get_orlist(remdb_t *jib) {
    glist_t                 *orlist     = NULL;
    remdb_member_t          *jibentry   = NULL;
    glist_entry_t           *it         = NULL;

    orlist = glist_new();

    glist_for_each_entry(it, jib){

        /* Ugly but should do for now. Just take the first locator */
        jibentry = glist_entry_data(it);

        if (jibentry->locators && jibentry->locators->locator)
            glist_add(jibentry->locators->locator, orlist);
    }

    return(orlist);
}

void remdb_add_member(lisp_addr_t *peer, lisp_addr_t *rloc_pair, remdb_t *jib) {

    remdb_member_t *member;

    LMLOG(LISP_LOG_DEBUG_2, "Adding peer %s requesting replication to %s to the re joining information base",
            lisp_addr_to_char(peer), lisp_addr_to_char(rloc_pair));

    assert(jib);
    assert(rloc_pair);

    member = remdb_member_init(peer, rloc_pair);
    glist_add_tail(member, jib);
}

remdb_member_t *remdb_find_member(lisp_addr_t *peer, remdb_t *jib) {
    glist_entry_t     *it         = NULL;
    remdb_member_t    *member     = NULL;

    assert(peer);
    assert(jib);

    glist_for_each_entry(it,jib) {
        member = glist_entry_data(it);
        if (lisp_addr_cmp(member->addr, peer) == 0)
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
            glist_remove(it, jib);
    }
}

inline uint32_t remdb_size(remdb_t *jib) {
    return(glist_size(jib));
}

remdb_member_t *remdb_member_init(lisp_addr_t *src, lisp_addr_t *rloc_pair) {
    remdb_member_t          *member             = NULL;
    locators_list_t     *locator_list       = NULL;

    member = calloc(1, sizeof(remdb_member_t));
    locator_list  = calloc(1, sizeof(locators_list_t));
    locator_list->locator = calloc(1, sizeof(locator_t));
    locator_list->next = NULL;
    /* the pair is of the type (S-RLOC, D-RLOC)
     * If the join will carry in the future more D-RLOCs for TE
     * add them one by one to the locator list
     */
    locator_list->locator->addr = lisp_addr_clone(rloc_pair);

    member->addr = lisp_addr_clone(src);
    member->locators = locator_list;

    return(member);
}

void remdb_dump(remdb_t *remdb, int log_level) {
    glist_entry_t *it;
    remdb_member_t *rmem;

    LMLOG(log_level, "************************************* REMDB ****************************");
    glist_for_each_entry(it, remdb) {
        rmem = glist_entry_data(it);
        LMLOG(log_level, "downstream: %s locator: %s", lisp_addr_to_char(rmem->addr),
                lisp_addr_to_char(locator_addr(rmem->locators->locator)));
    }
    LMLOG(log_level, "************************************************************************");

}
