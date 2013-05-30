

#pragma once


#include "lispd.h"


#define NAT_REPLY                        1
#define NAT_NO_REPLY                     0 

#define FIELD_AFI_LEN                    2
#define FIELD_PORT_LEN                   2 



/* NAT traversal Info-Request message
 * auth_data may be variable length in the future
 */

typedef struct lispd_pkt_info_nat_t_ {
#ifdef LITTLE_ENDIANS
    uint8_t reserved1:3;
    uint8_t rbit:1;
    uint8_t lisp_type:4;
#else
    uint8_t lisp_type:4;
    uint8_t rbit:1;
    uint8_t reserved1:3;
#endif
    uint8_t reserved2;
    uint16_t reserved3;

    uint64_t nonce;
    uint16_t key_id;
    uint16_t auth_data_len;
    uint8_t auth_data[LISP_SHA1_AUTH_DATA_LEN];
} PACKED lispd_pkt_info_nat_t;

/* EID fixed part of an Info-Request message
 * variable length EID address follows
 */

typedef struct lispd_pkt_info_nat_eid_t_ {
    uint32_t ttl;
    uint8_t reserved;
    uint8_t eid_mask_length;
    uint16_t eid_prefix_afi;
} PACKED lispd_pkt_info_nat_eid_t;


/* Global NAT variables*/ //XXX should be there?

extern int nat_aware;
extern int behind_nat;
extern lisp_addr_t natt_rtr; 



int extract_info_nat_header(lispd_pkt_info_nat_t *hdr,
                            uint8_t *type,
                            uint8_t *reply,
                            uint64_t *nonce,
                            uint16_t *key_id,
                            uint16_t *auth_data_len,
                            uint8_t **auth_data,
                            uint32_t *ttl,
                            uint8_t *eid_mask_len,
                            lisp_addr_t *eid_prefix);

lispd_pkt_info_nat_t *create_and_fill_info_nat_header(int lisp_type,
                                                      int reply,
                                                      unsigned long nonce,
                                                      uint16_t auth_data_len,
                                                      uint32_t ttl,
                                                      uint8_t eid_mask_length,
                                                      lisp_addr_t *eid_prefix,
                                                      unsigned int *header_len);

int process_info_nat_msg(uint8_t *packet);