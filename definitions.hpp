#ifndef __DEFINITIONS_HPP__
#define __DEFINITIONS_HPP__

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
#include <fstream>
#include <regex>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <time.h>
#include <sys/file.h>
#include <csignal>
#include <sys/wait.h>

using namespace std;

#define STATUS_ON (1)

#define PORT ("58036")

#define BUFFER_SIZE (6010)
#define FILE_NAME_MAX_SIZE (24)
#define FILE_MAX_SIZE (10000000)
#define AID_SIZE (3)
#define NAME_MAX_LEN (10)
#define MAX_START_VALUE (999999)
#define MAX_BID_VALUE (999999)
#define MAX_TIME_ACTIVE (99999)
#define UID_LEN (6)
#define PASSWORD_LEN (8)
#define MAX_BIDS_SHOWN (50)
#define DATE_TIME_LEN (19)
#define END_TIME_LEN (5)
#define MAX_AUCTIONS (1000)

#define TIMEOUT_SECONDS (15)

typedef struct bid {
    string UID, date_time;
    int value, time;
} bid;

typedef struct protocol {
    int fd,errcode;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in addr;
    char buffer[BUFFER_SIZE+1];
    bool active = false;
} protocol;

#define ERR(...)                                                        \
    {                                                                   \
        printf("[ERROR]: %s | Line %d\n", __VA_ARGS__, __LINE__);   \
        exit(1);                                                        \
    }

#define LOG(active, msg)                                                     \
    {if (active) {printf("[LOG]: %s\n", msg);}}

#define LOG_WA(active, format, ...)                                          \
    {if (active) {printf("[LOG]: " format "\n", __VA_ARGS__);}}

#define STATUS(msg)                                                     \
    {if (STATUS_ON) {printf("[STATUS]: %s  [Line %d] [File %s]\n", msg, __LINE__, __FILE__);}}

#define STATUS_WA(format, ...)                                          \
    {if (STATUS_ON) {printf("[STATUS]: " format "  [Line %d] [File %s]\n", __VA_ARGS__, __LINE__, __FILE__);}}


#endif 