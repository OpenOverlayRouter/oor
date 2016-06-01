/*
 *
 * Copyright (C) 2011, 2015 Cisco Systems, Inc.
 * Copyright (C) 2015 CBA research group, Technical University of Catalonia.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <time.h>

#include "nonces_table.h"
#include "oor_log.h"
#include "mem_util.h"


int nonce_list_cmp_nonce(void *nonce1, void *nonce2);
void nonce_list_free_nonce(void *nonce);


htable_nonces_t *
htable_nonces_new()
{
    htable_nonces_t * nonces_lst;
    nonces_lst = (htable_nonces_t *)malloc(sizeof(htable_nonces_t));
    nonces_lst->ht = kh_init(nonces);
    return(nonces_lst);
}

void
htable_nonces_insert(htable_nonces_t *nonces_ht, uint64_t nonce,
        nonces_list_t *nonces_lst)
{
    khiter_t k;
    int ret;
    uint64_t *nonce_val;
    nonce_val = xmalloc(sizeof(uint64_t));
    *nonce_val = nonce;
    glist_add(nonce_val,nonces_lst->nonces_list);
    k = kh_put(nonces,nonces_ht->ht,nonce,&ret);
    kh_value(nonces_ht->ht, k) = nonces_lst;
}

nonces_list_t *
htable_nonces_remove(htable_nonces_t *nonces_ht, uint64_t nonce)
{
    khiter_t k;
    nonces_list_t *nonces_lst;

    k = kh_get(nonces,nonces_ht->ht, nonce);
    if (k == kh_end(nonces_ht->ht)){
        return (NULL);
    }
    nonces_lst = kh_value(nonces_ht->ht, k);
    glist_remove_obj(&nonce,nonces_lst->nonces_list);
    /* We don't remove the value as it can be pointed by several nonces*/
    kh_del(nonces,nonces_ht->ht,k);
    return (nonces_lst);
}

void htable_nonces_destroy(htable_nonces_t *nonces_ht)
{
    khiter_t k;
    nonces_list_t *nonces_lst;

    if (!nonces_ht) {
        return;
    }

    for (k = kh_begin(nonces_ht->ht); k != kh_end(nonces_ht->ht); ++k){
        if (kh_exist(nonces_ht->ht, k)){
            nonces_lst = kh_value(nonces_ht->ht, k);
            nonces_list_free(nonces_lst);
        }
    }
    kh_destroy(nonces,nonces_ht->ht);
    free (nonces_ht);
}


nonces_list_t *
htable_nonces_lookup(htable_nonces_t *nonces_ht, uint64_t nonce)
{
    khiter_t k;

    k = kh_get(nonces,nonces_ht->ht, nonce);
    if (k == kh_end(nonces_ht->ht)){
        return (NULL);
    }
    return (kh_value(nonces_ht->ht,k));
}

void
htable_nonces_reset_nonces_lst(htable_nonces_t *nonces_ht,nonces_list_t *nonces_lst)
{
    glist_t *nonces = nonces_lst->nonces_list;
    glist_entry_t *nonce_it, *aux_nonce_it;
    uint64_t *nonce;
    khiter_t k;

    glist_for_each_entry_safe(nonce_it,aux_nonce_it,nonces){
        nonce = (uint64_t *)glist_entry_data(nonce_it);
        k = kh_get(nonces,nonces_ht->ht, *nonce);
        if (k == kh_end(nonces_ht->ht)){
            continue;
        }
        glist_remove(nonce_it,nonces);
        kh_del(nonces,nonces_ht->ht,k);
    }
}

/*  Generates a nonce random number. Requires librt */
uint64_t
nonce_build(int seed)
{

    uint64_t nonce;
    uint32_t nonce_lower;
    uint32_t nonce_upper;
    struct timespec ts;

    /*
     * Put nanosecond clock in lower 32-bits and put an XOR of the nanosecond
     * clock with the seond clock in the upper 32-bits.
     */

    clock_gettime(CLOCK_MONOTONIC, &ts);
    nonce_lower = ts.tv_nsec;
    nonce_upper = ts.tv_sec ^ htonl(nonce_lower);

    /*
     * OR in a caller provided seed to the low-order 32-bits.
     */
    nonce_lower |= seed;

    /*
     * Return 64-bit nonce.
     */
    nonce = nonce_upper;
    nonce = (nonce << 32) | nonce_lower;
    return (nonce);
}

uint64_t
nonce_new()
{
    return(nonce_build((unsigned int) time(NULL)));
}

inline glist_t *
nonces_list_list(nonces_list_t * nonces_lst)
{
    return (nonces_lst->nonces_list);
}

inline oor_timer_t *
nonces_list_timer(nonces_list_t * nonces_lst)
{
    return (nonces_lst->timer);
}

inline nonces_list_t *
nonces_list_new_init(oor_timer_t *timer)
{
    nonces_list_t *nonces_lst;

    nonces_lst = xzalloc(sizeof(nonces_list_t));
    if (!nonces_lst){
        return (NULL);
    }
    nonces_lst->timer = timer;
    nonces_lst->nonces_list = glist_new_complete(
            (glist_cmp_fct)nonce_list_cmp_nonce,
            (glist_del_fct)nonce_list_free_nonce);
    return (nonces_lst);
}


void
nonces_list_free(nonces_list_t *nonces_lst)
{
    glist_destroy(nonces_lst->nonces_list);
    free(nonces_lst);
}

inline int
nonces_list_size(nonces_list_t *nonces_lst)
{
    return (glist_size(nonces_lst->nonces_list));
}

int
nonce_list_cmp_nonce(void *nonce1, void *nonce2)
{
    uint64_t nonce_a = *((uint64_t *)nonce1);
    uint64_t nonce_b = *((uint64_t *)nonce2);
    return (nonce_a == nonce_b);
}
void
nonce_list_free_nonce(void *nonce)
{
    free((uint64_t *)nonce);
}


