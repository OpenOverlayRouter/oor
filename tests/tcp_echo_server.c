#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "clientserver.h"


 void handle_client(int sock, struct sockaddr_in si_remote) {
	 char buf[BUFLEN];
	 int rec = -1;

	 /* Message received */
	 if ((rec = recv(sock, buf, BUFLEN, 0)) == -1) 
	 {
		 perror("recv");
		 exit(EXIT_FAILURE);
	 }  
	 printf("Received -- %s -- from %s:%d\n", buf, inet_ntoa(si_remote.sin_addr), ntohs(si_remote.sin_port));

	 /* While the client is sending data */
	 while (rec > 0) 
	 {      

		 /* Send back data */          
		 printf("Sending -- %s -- to %s:%d\n", buf, inet_ntoa(si_remote.sin_addr), ntohs(si_remote.sin_port));

		 if (send(sock, buf, rec, 0) == -1) 
		 {
			 perror("send");
			 exit(EXIT_FAILURE);
		 }

		 /* More data? */
		 if ((rec = recv(sock, buf, BUFLEN, 0)) == -1) 
		 {
			 perror("send");
			 exit(EXIT_FAILURE);
		 }
		 else
		 {
			 printf("Received -- %s -- from %s:%d\n", buf, inet_ntoa(si_remote.sin_addr), ntohs(si_remote.sin_port));
		 }

	 }
	 close(sock);
 }


 int main(int argc, char **argv)
 {
	 struct sockaddr_in   si_local, si_remote;
	 int                  s_loc,s_rem;
	 int                  port;
	 int                  slen;
	 char                 buf[BUFLEN];

	 slen     =   sizeof(si_remote);

	 /* Socket creation */
	 if ((s_loc=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))==-1)
	 {
		 perror("socket");
		 exit(EXIT_FAILURE);
	 }

	 /* Server sockaddr structure  */
	 memset((char *) &si_local, 0, sizeof(si_local));
	 si_local.sin_family       =  AF_INET;
	 si_local.sin_port         =  htons(SPORT);
	 si_local.sin_addr.s_addr  =  INADDR_ANY; /* Any interface */

	 if (bind(s_loc, (const struct sockaddr *)&si_local, sizeof(si_local))==-1)
	 {
		 perror("bind");
		 exit(EXIT_FAILURE);
	 }

	 if (listen(s_loc, QUEUELENGTH) == -1) 
	 {
		 perror("listen");
		 exit(EXIT_FAILURE);
	 }


	 while(1)
	 {

		 slen     =   sizeof(si_remote);

		 /* Accept connection */
		 if ((s_rem = accept(s_loc, (struct sockaddr *)&si_remote, &slen)) == -1)
		 {
			 perror("accept");
			 exit(EXIT_FAILURE);
		 }

		 printf("Connection from %s:%d\n", inet_ntoa(si_remote.sin_addr), ntohs(si_remote.sin_port));

		 /* Per client management */
		 handle_client(s_rem, si_remote);

	 }

	 close(s_loc);
	 exit(EXIT_SUCCESS);
 }
 
