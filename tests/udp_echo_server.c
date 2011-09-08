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
	struct sockaddr_in   si_local, si_remote;
	int                  s;
	int                  port;
	int                  slen;
	char                 buf[BUFLEN];

	slen     =   sizeof(si_remote);
	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	memset((char *) &si_local, 0, sizeof(si_local));
	si_local.sin_family       =  AF_INET;
	si_local.sin_port         =  htons(SPORT);
        if (inet_aton(SADDR, &si_local.sin_addr)==0) 
        {
            perror("inet_aton()");
            exit (EXIT_FAILURE);

        }
	if (bind(s, (const struct sockaddr *)&si_local, sizeof(si_local))==-1)
	{
		perror("bind");
		exit(EXIT_FAILURE);
	}

	while(1)
	{
	        slen     =   sizeof(si_remote);
		memset(buf, 0, sizeof(char)*BUFLEN);
		memset(&si_remote, 0, sizeof(si_remote));
		if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *)&si_remote, &slen)==-1)
		{
			perror("recvfrom()");
			exit(EXIT_FAILURE);
		}
		{
			printf("Received -- %s -- from %s:%d\n", buf, inet_ntoa(si_remote.sin_addr), ntohs(si_remote.sin_port));
			printf("Sending -- %s -- to %s:%d\n", buf, inet_ntoa(si_remote.sin_addr), ntohs(si_remote.sin_port));
                        slen = sizeof(si_remote);
		        if (sendto(s, buf, BUFLEN, 0, (struct sockaddr *)&si_remote, slen)==-1)
		        {
			    perror("recvfrom()");
			    exit(EXIT_FAILURE);
		        }
		}
	}

	close(s);
	exit(EXIT_SUCCESS);
}
