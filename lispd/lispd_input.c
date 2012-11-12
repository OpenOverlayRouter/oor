#include "lispd_input.h"


 void lisp_input(char *packet_buf, int length, void *source, int tun_receive_fd)
 {
     int ret;
     //struct sockaddr_in *source_sock;
     
     //source_sock    = (struct sockaddr_in *)source;
     
     printf("lisp_input\n");
     
     //iph = (struct iphdr *)((char *)packet_buf + sizeof(struct iphdr));
     
     ret = write(tun_receive_fd, (void *)packet_buf, length);
     
     if (ret==-1){
         printf ("write: %s\n ", strerror(errno));
         
     }
     
     return;
 }
 
 void process_input_packet(int fd, int tun_receive_fd)
 {
     uint8_t                 packet[4096];
     int                     recv_len;
     int                     fromlen4 = sizeof(struct sockaddr_in);
     struct sockaddr_in      s4;
     
     printf("tuntap_process_input_packet\n");
     
     memset(&s4, 0, sizeof(struct sockaddr_in));
     
     if ((recv_len = recvfrom(fd, packet, 4096, 0,(struct sockaddr *) &s4, &fromlen4)) < 0)
         printf ("recvfrom (v4): %s", strerror(errno));
     else
         lisp_input((char *)packet, recv_len, &s4, tun_receive_fd);
     
 }
 