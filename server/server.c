/* server.c -- Implements server side of the ROHC IP-IP tunnel

Description :

The server will listen on a TCP socket for incoming client. A client
will send command in netstrings
Protocol version


Client commands :
 * 6:connect, : Connection asked, a raw socket is created with the incoming
                client IP as destination. An IP address is picked for this client.
                The server then answer :
    - If ok : 1x:xxxxx,y:yyyyy with x the IP address and y a token generated 
    IP address of the endpoint, 
    - Else  : 0z:zzzzz, with z a human readable error message
 * 9:disconnect,x:xxxxxx : Disconnection asked, raw socket is destroyed.
                           The socket is retrieved by the token (xxxxx) 
                           Then server then answer
    - If ok : 1
    - Else  : 0

Client are described by a structure containing its raw socket and its VPN address

*/


#include <sys/socket.h> 
#include <sys/types.h> 
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>


#define MAX_CLIENTS 50

/* Stucture defining a client */
struct client {
    struct in_addr local_address;
    struct in_addr dest_address ;
    int      raw_socket   ;   
    pthread_t thread      ;
} ;

/* Create TCP socket for communication with clients */
int create_tcp_socket(uint32_t address, uint16_t port) {

    int sock = socket(AF_INET, SOCK_STREAM, 0) ;

    struct    sockaddr_in servaddr ;
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = htonl(address);
    servaddr.sin_port        = htons(port);

    if (bind(sock,  (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
        perror("Bind failed") ;
    
    if (listen(sock, 10) < 0)
        perror("Listen failed") ;

    return sock ;
}

/* Called in a thread on a new client */
void* new_client(void* arg) {

    struct client* client = (struct client*) arg ;
    int i;
    char message[255] ;
    char s_local[16] ;
    char s_dest[16] ;

    strcpy(s_local, inet_ntoa(client->local_address)) ;
    strcpy(s_dest, inet_ntoa(client->dest_address)) ;
    sprintf(message, "Hello client %s (%d) from IP %s (%d)\n", s_local, client->local_address.s_addr, 
                                                               s_dest, client->dest_address.s_addr) ;   

    if (send(client->raw_socket, message, strlen(message), 0) < 0) {
        perror("send") ;
    }

    for (i=20; i > 0; i--) {
        sprintf(message, "%d...\n", i) ;
        send(client->raw_socket, message, strlen(message), 0) ;
        sleep(1) ;
    }

    close(client->raw_socket) ;
    return NULL ;
}

int main(int argc, char *argv[]) {

    struct client clients[MAX_CLIENTS] ;
    int ret ;
    int i = 0 ;
    struct    sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);


    int socket = create_tcp_socket(INADDR_ANY, 1989) ;

    char buffer[255] ;
    while (1) {
        int conn = accept(socket, (struct sockaddr*)&src_addr, &src_addr_len) ;
        if (conn < 0) {
            perror("Fail accept\n") ;
        }
        printf("Connection from %s (%d)\n", inet_ntoa(src_addr.sin_addr), src_addr.sin_addr.s_addr) ;

        /* client parameters */

        /* dest_addr */
        clients[i].dest_address  = src_addr.sin_addr ;
        
        /* local_addr */
        struct in_addr local;
        local.s_addr = htonl(inet_network("192.168.1.23")) ;
        clients[i].local_address = local ;
        
        /* socket -- TO BE REMOVED */
        clients[i].raw_socket = conn ;

        /* Go thread, go ! */
        pthread_create(&(clients[i].thread), NULL, new_client, (void*)&clients[i]) ;

        i++ ;
    }
}


