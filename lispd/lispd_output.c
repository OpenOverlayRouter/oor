#include "lispd_output.h"



void process_output_packet(int fd, char *tun_receive_buf, unsigned int tun_receive_size)
{
    int nread;

    nread = read(fd, tun_receive_buf, tun_receive_size);

    printf("In tuntap_process_output_packet\n");

    lisp_output4(tun_receive_buf, nread);
}


int lisp_output4(char *packet_buf, int pckt_length)
{
    lispd_iface_elt *iface;

    char *encap_packet;
    int  encap_packet_size;
    lisp_addr_t aux_addr;
    lisp_addr_t aux2_addr;
    lisp_addr_t *dst_addr;
    lisp_addr_t *src_addr;

    //Temporal while developing
    iface = get_output_iface(); //TODO: check if up
    src_addr = iface->ipv4_address;
    
    //Temporal, just for testing
    get_lisp_addr_from_char("192.168.1.10",&aux_addr);
    dst_addr = &aux_addr;
    
    
    create_encap_packet_v4(packet_buf,
                           pckt_length,
                           src_addr,
                           dst_addr,
                           &encap_packet,
                           &encap_packet_size);
    
    send_by_raw_socket(iface,encap_packet,encap_packet_size);

    free(encap_packet);
    
    return GOOD;
}

/* Creates (malloc) new packet with encapsulation. Should be freed afterwards.*/

int create_encap_packet_v4(char *packet_buf,
                           int pckt_length,
                           lisp_addr_t *src_addr,
                           lisp_addr_t *dst_addr,
                           char **encap_packet,
                           int  *encap_packet_size){
    
    int extra_headers_size;
    char *new_packet;
    
    struct udphdr *udh;
    struct iphdr *iph;
    struct iphdr *inner_iph;
    
    
    
    
    extra_headers_size = sizeof(struct iphdr) + sizeof(struct udphdr);
    new_packet = (char *)malloc(pckt_length + extra_headers_size);
    
    memcpy(new_packet + extra_headers_size, packet_buf, pckt_length);
    
    /*
     * Construct and add the udp header
     */
    udh = (struct udphdr *)(new_packet + sizeof(struct iphdr));
    
    /*
     * Hash of inner header source/dest addr. This needs thought.
     */
    udh->source = htons(LISP_DATA_PORT);
    udh->dest =  htons(LISP_DATA_PORT);
    udh->len = htons(sizeof(struct udphdr) + pckt_length);
    //udh->len = htons(sizeof(struct udphdr)); /* Wireshark detects this as error*/
    udh->check = 0; // SHOULD be 0 as in LISP ID
    
    /*
     * Construct and add the outer ip header
     */

    //check if inner packet is IPv4, if so, copy tos and ttl
    
    iph = (struct iphdr *)new_packet;
    inner_iph = (struct iphdr *)packet_buf;

    
    iph->version  = 4;
    iph->ihl      = sizeof(struct iphdr)>>2;
    iph->frag_off = 0;   // XXX recompute above, use method in 5.4.1 of draft
    iph->protocol = IPPROTO_UDP;
    
    iph->tos      = inner_iph->tos; 
    
    iph->daddr    = dst_addr->address.ip.s_addr;
    iph->saddr    = src_addr->address.ip.s_addr;
    
    iph->ttl      = inner_iph->ttl;
    
    
    //iph->check = ip_checksum((uint16_t*) iph, sizeof(struct iphdr));

    //if ((udpsum = udp_checksum(udh, pckt_length - iph_len, packet_buf, AF_INET)) == -1) {
        //    return (0);
    //}
    //udh->check = udpsum;

    *encap_packet = new_packet;
    *encap_packet_size = pckt_length + extra_headers_size;

    return (GOOD);

    
}

int send_by_raw_socket(lispd_iface_elt *iface, char *packet_buf, int pckt_length){

    int socket;

    struct sockaddr *dst_addr;
    int dst_addr_len;
    struct sockaddr_in dst_addr4;
    struct sockaddr_in6 dst_addr6;
    struct iphdr *iph;
    int nbytes;

    
    iph = (struct iphdr *) packet_buf;

    memset((char *) &dst_addr, 0, sizeof(dst_addr));

    if(iph->version == 4){
        memset((char *) &dst_addr4, 0, sizeof(dst_addr4));
        dst_addr4.sin_family = AF_INET;
        dst_addr4.sin_port = htons(LISP_DATA_PORT);
        dst_addr4.sin_addr.s_addr = iph->daddr;

        dst_addr = (struct sockaddr *) &dst_addr4;
        dst_addr_len = sizeof(struct sockaddr_in);
        socket = iface->out_socket_v4;
    }else{
        //TODO: write IPv6 support
    }

    printf("Trying to send in Socket %d\n",iface->out_socket_v4);

    
    nbytes = sendto(iface->out_socket_v4,
                    (const void *) packet_buf,
                    pckt_length,
                    0,
                    dst_addr,
                    dst_addr_len);

    if (nbytes != pckt_length) {
        syslog(LOG_DAEMON, "send_by_raw_socket: send failed %s", strerror(errno));
        return (BAD);
    }

    printf("packet sent\n");

    return GOOD;

}
