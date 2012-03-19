#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "clientserver.h"

void error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}


int main(int argc, char **argv)
{
    struct sockaddr_in si_server;
    int port, s, i, slen = sizeof(si_server);
    char buf[BUFLEN];
    char *srv_addr;
    fd_set readfds;
    struct timeval tv;
    int ret;

    if (argc < 3) {
        printf("Usage: %s ip_add port\n", argv[0]);
        exit(1);
    }

    port = atoi(argv[2]);
    srv_addr = argv[1];


    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        error("socket");
    }

    memset((char *) &si_server, 0, sizeof(si_server));
    si_server.sin_family = AF_INET;
    si_server.sin_port = htons(port);
    if (inet_aton(srv_addr, &si_server.sin_addr) == 0) {
        fprintf(stderr, "inet_aton() failed\n");
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < NPACK; i++) {
        sprintf(buf, "DATA PACKET # %d", i);
        printf("Sending -- %s -- to %s:%d\n", buf,
               inet_ntoa(si_server.sin_addr), ntohs(si_server.sin_port));
        slen = sizeof(si_server);
        if (sendto(s, buf, BUFLEN, 0, (struct sockaddr *) &si_server, slen)
            == -1) {
            error("sendto()");
        }

        FD_ZERO(&readfds);
        FD_SET(s, &readfds);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if (select(s + 1, &readfds, NULL, NULL, &tv) == -1) {
            error("select()");
        }
        if (FD_ISSET(s, &readfds)) {
            ret =
                recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_server,
                         &slen);
            if (ret > 0) {
                printf("Received -- %s -- from %s:%d\n", buf,
                       inet_ntoa(si_server.sin_addr),
                       ntohs(si_server.sin_port));
            }
        }
        sleep(2);
    }
    close(s);
    return 0;
}
