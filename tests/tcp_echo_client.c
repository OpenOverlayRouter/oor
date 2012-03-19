#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "tcp_echo.h"

int main(int argc, char **argv)
{
    struct sockaddr_in si_server;
    int port, s, i, slen = sizeof(si_server);
    char buf[BUFLEN];
    char srv_addr[16];
    fd_set readfds;
    struct timeval tv;
    int ret;

    /* TCP socket creation */
    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /* Server sockaddr structure  */
    memset((char *) &si_server, 0, sizeof(si_server));
    si_server.sin_family = AF_INET;
    si_server.sin_port = htons(SPORT);
    if (inet_aton(SADDR, &si_server.sin_addr) == 0) {
        fprintf(stderr, "inet_aton() failed\n");
        exit(EXIT_FAILURE);
    }

    /* Establish connection */
    if (connect(s, (struct sockaddr *) &si_server, sizeof(si_server)) ==
        -1) {
        fprintf(stderr, "connect() failed\n");
        exit(EXIT_FAILURE);
    }

    /* Send-Recv loop */
    for (i = 0; i < NPACK; i++) {
        sprintf(buf, "DATA PACKET # %d", i);
        printf("Sending -- %s -- to %s:%d\n", buf,
               inet_ntoa(si_server.sin_addr), ntohs(si_server.sin_port));

        if (send(s, buf, BUFLEN, 0) == -1) {
            perror("send()");
            exit(EXIT_FAILURE);
        }

        ret = recv(s, buf, BUFLEN, 0);
        if (ret > 0) {
            printf("Received -- %s -- from %s:%d\n", buf,
                   inet_ntoa(si_server.sin_addr),
                   ntohs(si_server.sin_port));
        } else {
            perror("recv()");
            exit(EXIT_FAILURE);
        }

        sleep(2);
    }


    close(s);
    return 0;
}
