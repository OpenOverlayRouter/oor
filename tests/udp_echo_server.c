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
    struct sockaddr_in si_local, si_remote;
    int s;
    int port;
    int slen;
    char buf[BUFLEN];


    if (argc < 2) {
        printf("Usage: %s port\n", argv[0]);
        exit(1);
    }

    port = atoi(argv[1]);

    slen = sizeof(si_remote);
    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        error("socket");
    }

    memset((char *) &si_local, 0, sizeof(si_local));
    si_local.sin_family = AF_INET;
    si_local.sin_port = htons(port);
    si_local.sin_addr.s_addr = INADDR_ANY;


    if (bind(s, (const struct sockaddr *) &si_local, sizeof(si_local)) ==
        -1) {
        error("bind");
    }

    while (1) {
        slen = sizeof(si_remote);
        memset(buf, 0, sizeof(char) * BUFLEN);
        memset(&si_remote, 0, sizeof(si_remote));

        if (recvfrom
            (s, buf, BUFLEN, 0, (struct sockaddr *) &si_remote,
             &slen) == -1) {
            error("recvfrom()");
        } else {
            printf("Received -- %s -- from %s:%d\n", buf,
                   inet_ntoa(si_remote.sin_addr),
                   ntohs(si_remote.sin_port));
            printf("Sending -- %s -- to %s:%d\n", buf,
                   inet_ntoa(si_remote.sin_addr),
                   ntohs(si_remote.sin_port));
            slen = sizeof(si_remote);

            if (sendto
                (s, buf, BUFLEN, 0, (struct sockaddr *) &si_remote,
                 slen) == -1) {
                error("recvfrom()");
            }
        }
    }

    close(s);
    exit(EXIT_SUCCESS);
}
