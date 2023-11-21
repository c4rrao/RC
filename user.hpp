#ifndef USER_HPP
#define USER_HPP

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <string>
#include <sstream>
#include <iostream>

using namespace std;

#define DEBUG 1

#define PUBLIC_PORT "58011"
#define PORT "58036"
#define PUBLIC_IP "tejo.tecnico.ulisboa.pt"

#define NO_USER ""
#define NO_PASS ""

#define ERR(...)                                                        \
    {                                                                   \
        if (DEBUG)                                                      \
            printf("[ERROR]: %s | Line %d\n", __VA_ARGS__, __LINE__);   \
        exit(1);                                                        \
    }

#define STATUS(...)                                                 \
    {printf("[STATUS]: %s | Line %d\n", __VA_ARGS__, __LINE__);}

#define MSG(...)                    \
    {printf("%s\n", __VA_ARGS__);}   \


typedef struct protocol {
    int fd,errcode;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in addr;
    char buffer[128];
} protocol;

#endif 