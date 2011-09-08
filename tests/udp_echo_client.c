#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "clientserver.h"

int main(int argc, char **argv)
{
	struct sockaddr_in  si_server;
	int                 port, s, i, slen=sizeof(si_server);
	char                buf[BUFLEN];
	char                srv_addr[16];
        fd_set readfds;
        struct timeval tv;
        int ret;

	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset((char *) &si_server, 0, sizeof(si_server));
	si_server.sin_family   =  AF_INET;
	si_server.sin_port     =  htons(SPORT);
	if (inet_aton(SADDR, &si_server.sin_addr)==0)
	{
		fprintf(stderr, "inet_aton() failed\n");
		exit(EXIT_FAILURE);
	}
	for (i=0; i<NPACK; i++)
	{
            sprintf(buf, "DATA PACKET # %d", i);
            printf("Sending -- %s -- to %s:%d\n", buf, inet_ntoa(si_server.sin_addr), ntohs(si_server.sin_port));
            slen = sizeof(si_server);
    	    if (sendto(s, buf, BUFLEN, 0, (struct sockaddr *)&si_server, slen)==-1)
	    {
			perror("sendto()");
			exit(EXIT_FAILURE);
	    }


        FD_ZERO(&readfds);
        FD_SET(s,&readfds);

    tv.tv_sec  = 1;
    tv.tv_usec = 0;

    if (select(s+1,&readfds,NULL,NULL,&tv) == -1) {
        perror("select()");
        exit (EXIT_FAILURE);
    } 
        if (FD_ISSET(s,&readfds)) {
  	    ret = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *)&si_server, &slen);
            if (ret > 0)
                printf("Received -- %s -- from %s:%d\n", buf, inet_ntoa(si_server.sin_addr), ntohs(si_server.sin_port));
        }
        sleep(2);
        }
	close(s);
	return 0;
}
