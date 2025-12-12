#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>

#define PORT 12345

int main() {
    
    int sockfd;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);   // system call, create a kernel socket object, with TCP class
                                                // AF_INET: Address Family: Internet，represents IPv4
                                                // SOCK_STREAM: Use TCP(byte stream)
    if(sockfd < 0) { perror("socket"); exit(1); }

    
    struct sockaddr_in servaddr;                // a struct type that represents IPv4 address and port
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);            // htons: host-to-network short(16 bit)
                                                // change port number from host endian(little endian) to net endian(big endian)
    const char* ip = getenv("SERVER_IP");
    assert(ip && "SERVER_IP environment variable not set");
    inet_pton(AF_INET, ip, &servaddr.sin_addr); // change string IP address to binary format(32bit int)


    if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) { perror("connect"); exit(1); }
                                                // struct sockaddr is uniform addr type, and sockaddr_in is for IPv4
                                                // connect is a system call，make a TCP socket from CLOSED to ESTABLISHED
                                                // through SYN, SYN+ACK, ACK 3 times handshake, from local random high 
                                                // port to specific server address and port.
                                                // 
                                                // you can also specify a local port to establish the connect, just call
                                                // bind(a system call) before connect.


    const char* buffer = "Hello from client\n";
    send(sockfd, buffer, strlen(buffer), 0);    // system call: send
    
    while(1){
        char s[1024];
        if(!fgets(s, sizeof(s), stdin)) break;
        write(sockfd, s, strlen(s));
    }
    close(sockfd);
    return 0;
}
