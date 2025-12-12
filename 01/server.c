#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 12345
#define BUF_SIZE 1024

int main() {
    int sockfd;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) { perror("socket"); exit(1); }


    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY; // all the addr of this machine
    servaddr.sin_port = htons(PORT);
    if(bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) { perror("bind"); exit(1); }
                                                                    // bind: system call, bind the socket to
                                                                    // a local port for receiving data. If not
                                                                    // bound yet, you cannot call `accept` to
                                                                    // establish a connection


    if(listen(sockfd, 5) < 0) { perror("listen"); exit(1); }        // listen: system call, change the normal 
                                                                    // socket into listening socket, for receiving
                                                                    // message from client
    printf("TCP server listening on port %d\n", PORT);


    struct sockaddr_in cliaddr;
    socklen_t len = sizeof(cliaddr);
    int connfd = accept(sockfd, (struct sockaddr*)&cliaddr, &len);  // accept: system call, block this thread, 
    if(connfd < 0) { perror("accept"); exit(1); }                   // until a connection request from client.
                                                                    // kernel do handshake, and this thread 
                                                                    // continue to run
                                                                    //
                                                                    // This code doesn't use client address, and
                                                                    // it is not necessary to pass the sockaddress
                                                                    // struct in, when we don't care the address
                                                                    // of client, just pass NULL into the func.
    

    char buffer[BUF_SIZE];
    while(1) {
        ssize_t n = recv(connfd, buffer, BUF_SIZE, 0);              // recv: system call, receive a stream from
                                                                    // a connfd to buffer
        if(n <= 0) break;
        write(STDOUT_FILENO, buffer, n);
    }

    close(connfd);
    close(sockfd);
    return 0;
}
