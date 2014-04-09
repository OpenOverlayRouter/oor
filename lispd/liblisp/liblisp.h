
#ifndef LIBLISP_H_
#define LIBLISP_H_

#include "lisp_address.h"
#include "lispd_locator.h"
#include "lispd_mapping.h"
#include "lisp_messages.h"
#include "generic_list.h"
#include "lbuf.h"

int lisp_msg_parse_addr(struct lbuf *, lisp_addr_t *);
int lisp_msg_parse_eid_rec(struct lbuf *msg, lisp_addr_t *, void *eid_ptr);


int lisp_msg_put_addr(struct lbuf *msg, lisp_addr_t *addr);
void *lisp_msg_put_locator(struct lbuf *msg, locator_t *locator);
void *lisp_msg_put_mapping_hdr(struct lbuf *b, int plen) ;
void *lisp_msg_put_mapping(struct lbuf *msg, mapping_t *mapping,
        locator_t *probed_rloc);

struct lbuf* lisp_msg_create();
inline lisp_msg_destroy(struct lbuf *);
static inline lisp_msg_hdr(struct lbuf *b);

char *lisp_msg_hdr_to_char(struct lbuf *b);


inline void lisp_msg_destroy(struct lbuf *b) {
    if (!b) {
        return;
    }

    lbuf_del(b);
}

static inline lisp_msg_hdr(struct lbuf *b) {
    return(lbuf_lisp(b));
}

static glist_t *lisp_addr_list_new() {
    return(glist_new_managed((glist_del_fct)lisp_addr_del));
}

static glist_t *list_addr_sorted_list_new() {
    return(glist_new_full((glist_cmp_fct)lisp_addr_cmp, (glist_del_fct)lisp_addr_del));
}


#endif /* LIBLISP_H_ */
