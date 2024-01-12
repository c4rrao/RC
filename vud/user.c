#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <fcntl.h>

#define MAX_ANAME 20
#define MAX_FNAME 30
#define MAX_VALUE 6
#define MAX_TIME 5

long getFileSize(FILE *file) {
    long size;
    
    // Save the current position
    long currentPosition = ftell(file);

    // Move to the end of the file
    fseek(file, 0, SEEK_END);

    // Get the current position, which is now the size of the file
    size = ftell(file);

    // Restore the original position
    fseek(file, currentPosition, SEEK_SET);

    return size;
}

typedef struct user{
    char pass[8], uid[6];
}user;

user* login(char *buffer, struct addrinfo *res){

    socklen_t addrlen;
    struct sockaddr_in addr;
    int fd, errcode;
    char uid[6]="123123", pass[8]="12312312", message[20];
    size_t n;

    user *new; 

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;


    memcpy(message,"LIN ", 4);
    memcpy(message+4, uid, 6);
    memcpy(message+10, " ", 1);
    memcpy(message+11, pass, 8);

    message[19] = '\n';


    fd=socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(fd==-1){
        fprintf(stderr, "Error creating socket\n");
        return NULL;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    n=sendto(fd,message,sizeof(message),0,res->ai_addr,res->ai_addrlen);

    if(n==-1){
        close(fd);
        fprintf(stderr, "Error creating a socket\n");
        return NULL;
    }
    n=recvfrom(fd,message,20,0, (struct sockaddr*)&addr,&addrlen);
    if(n==-1){
        close(fd);
        fprintf(stderr, "Error communicating with server1\n");
        return NULL;
    }
    
    close(fd);
    if((!memcmp("RLI OK\n",message, 7) && n == 7) || (!memcmp("RLI REG\n",message, 8) && n == 8)){
        new = malloc(sizeof(user));
        memcpy(new->pass,pass,8);
        memcpy(new->uid, uid, 6);
        if(!memcmp("RLI REG\n",message, 8) && n == 8){
            fprintf(stdout, "User succesfully registered\n");
        }
        else{
            fprintf(stdout, "User successfully logged in\n");
        }
        return new;
    }
    else if(!memcmp("RLI NOK\n",message, 8) && n == 8){
        fprintf(stdout, "Wrong password\n");
    }
    else{
        fprintf(stderr, "Error parsing servers response\n");
    }
    return NULL;
}

void unreg(user* current, struct addrinfo *res){
    char message[20];
    int fd, n;
    socklen_t addrlen;
    struct sockaddr_in addr;

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if(!current){
        fprintf(stderr, "USER NOT LOGGED IN\n");
        return;
    }

    memcpy(message, "UNR ", 4);
    memcpy(message+4, current->uid,6);
    memcpy(message+10, " ", 1);
    memcpy(message+11, current->pass, 8);
    message[19] = '\n';

    fd=socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(fd==-1){
        fprintf(stderr, "Error creating socket\n");
        return;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    n=sendto(fd,message,sizeof(message),0,res->ai_addr,res->ai_addrlen);

    if(n==-1){
        close(fd);
        fprintf(stderr, "Error sending request to server\n");
        return;
    }
    n=recvfrom(fd,message,20,0,
    (struct sockaddr*)&addr,&addrlen);
    if(n==-1){
        close(fd);
        fprintf(stderr, "Error parsing server´s response\n");
        return;
    }
    if(n == 7){
        if(!memcmp(message, "RUR OK\n", 7)){
            fprintf(stdout, "Unregistered successfully\n");
        }
        else{
            fprintf(stderr, "Error parsing server´s response\n");
        }
    }
    else if(n == 8){
        if(!memcmp(message, "RUR NOK\n", 8)){
            fprintf(stdout, "User was not logged in\n");
        }
        else if(!memcmp(message, "RUR UNR\n", 8)){
            fprintf(stdout, "User was not registered\n");
        }
        else{
            fprintf(stderr, "Error parsing server´s response\n");
        }
    }
    else{
        fprintf(stderr, "Error communicating with server\n");
    }
    close(fd);
}

void logout(user* current, struct addrinfo *res){
    char message[20];
    int fd, n;
    socklen_t addrlen;
    struct sockaddr_in addr;

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if(!current){
        fprintf(stderr, "USER NOT LOGGED IN\n");
        return;
    }

    memcpy(message, "LOU ", 4);
    memcpy(message+4, current->uid,6);
    memcpy(message+10, " ", 1);
    memcpy(message+11, current->pass, 8);
    message[19] = '\n';

    fd=socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(fd==-1){
        fprintf(stderr, "Error creating socket\n");
        return;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    n=sendto(fd,message,sizeof(message),0,res->ai_addr,res->ai_addrlen);

    if(n==-1){
        close(fd);
        fprintf(stderr, "Error sending request to server\n");
        return;
    }
    n=recvfrom(fd,message,20,0,
    (struct sockaddr*)&addr,&addrlen);
    if(n==-1){
        fprintf(stderr, "Error parsing servers response\n");
        close(fd);
        return;
    }
    if(n == 7){
        if(!memcmp(message, "RLO OK\n", 7)){
            fprintf(stdout, "Logged out successfully\n");
        }
        else{
            fprintf(stderr, "Error parsing servers response\n");
        }
    }
    else if(n == 8){
        if(!memcmp(message, "RLO NOK\n", 8)){
            fprintf(stdout, "User was not logged in\n");
        }
        else{
            fprintf(stderr, "Error parsing servers response\n");
        }
    }
    close(fd);
}

int display_auctions(char *buffer, char* display_message, int n){
    int count = 0, num_a, aid, x;
    char aid_str[4], act_c, a_info[50];
    if(n%6 != 0){
        return -1;
    }
    num_a = n/6;
    for(int i = 0; i<num_a;i++){
        memset(aid_str,0,sizeof(aid_str));
        memcpy(aid_str,buffer+i*6,3);
        for(int j = 0; j<3; j++){
            if(aid_str[j] < '0' || aid_str[j] > '9' ){
                return -1;
            }
        }
        sscanf(aid_str, "%d", &aid);
        if(buffer[i*6+3]!=' '){
            return -1;
        }
        if(buffer[i*6+4] == '0'){
            sprintf(a_info, "Auction number %03d [STATUS : NOT ACTIVE]\n",aid);
            x = strlen(a_info);
            memcpy(display_message+count, a_info, x);
            count += x;
        }
        else if(buffer[i*6+4] == '1'){
            sprintf(a_info, "Auction number %03d [STATUS : ACTIVE]\n",aid);
            x =  strlen(a_info);
            memcpy(display_message+count, a_info, x);
            count += x;
        }
        else{
            return -1;
        }
        if(i == num_a-1){
            if(buffer[i*6+5] != '\n'){
                return -1;
            }
        }
        else{
            if(buffer[i*6+5] != ' '){
                return -1;
            }
        }
    }
    display_message[count] = '\0';
    return 0;
}

void ma(struct addrinfo *res, user* usr){
    char message[11], buffer[6500], status[4], display_message[15000];
    int fd, n;
    socklen_t addrlen;
    struct sockaddr_in addr;

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if(!usr){
        fprintf(stderr, "USER NOT LOGGED IN\n");
        return;
    }

    memcpy(message, "LMA ", 4);
    memcpy(message+4, usr->uid,6);
    memcpy(message+10, "\n", 1);

    fd=socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(fd==-1){
        fprintf(stderr, "Error creating socket\n");
        return;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    n=sendto(fd,message,sizeof(message),0,res->ai_addr,res->ai_addrlen);

    if(n==-1){
        close(fd);
        fprintf(stderr, "Error sending request to server\n");
        return;
    }
    n=recvfrom(fd,buffer,sizeof(buffer),0,
    (struct sockaddr*)&addr,&addrlen);
    if(n==-1){
        close(fd);
        fprintf(stderr, "Error parsing servers response\n");
        return;
    }
    if(n == 8){
        if(!memcmp(buffer,"RMA NLG\n",8)){
            fprintf(stdout, "You must be logged in to perform this action\n");
        }
        if(!memcmp(buffer,"RMA NOK\n",8)){
            fprintf(stdout, "You havent started any auctions\n");
        }
        else{
            fprintf(stderr, "Error parsing servers response\n");
        }
    }
    if(n>7){
        if(!memcmp(buffer, "RMA OK ",7)){
            if(display_auctions(buffer+7, display_message, n-7) == -1){
                fprintf(stderr, "Error parsing servers response\n");
            }
            else{
                fprintf(stdout, "Auctions you started:\n");
                fprintf(stdout, "%s" ,display_message);
            }
        }
    }
    close(fd);
}

void mb(struct addrinfo *res, user* usr){
    char message[11], buffer[6500], status[4], display_message[15000];
    int fd, n;
    socklen_t addrlen;
    struct sockaddr_in addr;

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if(!usr){
        fprintf(stderr, "USER NOT LOGGED IN\n");
        return;
    }

    memcpy(message, "LMB ", 4);
    memcpy(message+4, usr->uid,6);
    memcpy(message+10, "\n", 1);

    fd=socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(fd==-1){
        fprintf(stderr, "Error creating socket\n");
        return;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    n=sendto(fd,message,sizeof(message),0,res->ai_addr,res->ai_addrlen);

    if(n==-1){
        close(fd);
        fprintf(stderr, "Error sending request to server\n");
        return;
    }
    n=recvfrom(fd,buffer,sizeof(buffer),0,
    (struct sockaddr*)&addr,&addrlen);
    if(n==-1){
        close(fd);
        fprintf(stderr, "Error parsing servers response\n");
        return;
    }
    if(n == 8){
        if(!memcmp(buffer,"RMB NLG\n",8)){
            fprintf(stdout, "You must be logged in to perform this action\n");
        }
        if(!memcmp(buffer,"RMB NOK\n",8)){
            fprintf(stdout, "You didnt place any bids\n");
        }
        else{
            fprintf(stderr, "Error parsing servers response\n");
        }
    }
    if(n>7){
        if(!memcmp(buffer, "RMB OK ",7)){
            if(display_auctions(buffer+7, display_message, n-7) == -1){
                fprintf(stderr, "Error parsing servers response\n");
            }
            else{
                fprintf(stdout, "Auctions where you placed bids:\n");
                fprintf(stdout, "%s" ,display_message);
            }
        }
    }
    close(fd);
}

int isValidDateFormat(const char *input) {
    int year, month, day, hour, minute, second;

    // Attempt to parse the input string
    if (sscanf(input, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second) == 6) {
        // Check if the parsed values are within valid ranges
        if (year >= 0 && month >= 1 && month <= 12 && day >= 1 && day <= 31 &&
            hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59 && second >= 0 && second <= 59) {
            return 1; // Valid format and values
        }
    }

    return 0; // Invalid format or values
}

void sr(char *buffer, struct addrinfo *res){
    char host_uid[7], message[8], buffer_sock[8000], status[4], buf_ad[256], fname[MAX_FNAME+1], aname[MAX_ANAME+1], value_str[MAX_VALUE+1], timeactive_str[MAX_TIME+1], timestamp[20], display_message[15000], info[200], bidder_uid[7];
    int fd, n, aid, c, disp_c, no_biders = 1;
    socklen_t addrlen;
    struct sockaddr_in addr;

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    sscanf(buffer, "%s", buf_ad);

    if(strlen(buf_ad)>3){
        fprintf(stderr, "INVALID AID\n");
        return;
    }

    for(int i = 0; i < strlen(buf_ad); i++){
        if(buf_ad[i]<'0' || buf_ad[i] > '9'){
            fprintf(stderr, "INVALID AID\n");
            return;
        }
    }

    sscanf(buffer, "%d", &aid);

    sprintf(message,"SRC %03d",aid);

    message[7] = '\n';

    fd=socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(fd==-1){
        fprintf(stderr, "Error creating socket\n");
        return;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    n=sendto(fd,message,sizeof(message),0,res->ai_addr,res->ai_addrlen);

    if(n==-1){
        fprintf(stderr, "Error communicating with server\n");
        close(fd);
        return;
    }
    memset(buffer_sock,0,sizeof(buffer_sock));
    n=recvfrom(fd,buffer_sock,sizeof(buffer_sock),0,
    (struct sockaddr*)&addr,&addrlen);
    if(n < 8 || n == sizeof(buffer_sock)){
        fprintf(stderr, "Error communicating with server\n");
        close(fd);
        return;
    }
    if(!memcmp("RRC NOK\n",buffer_sock,8)){
        fprintf(stderr, "Auction does not exist\n");
        close(fd);
        return;
    }
    if(memcmp("RRC OK ", buffer_sock, 7)){
        fprintf(stderr, "Error communicating with server\n");
        close(fd);
        return;
    }
    c = 0;

    memset(host_uid,0,sizeof(host_uid));
    for(int i = 7; i<n; i++){
        host_uid[c] = buffer_sock[i];
        if(host_uid[c] == ' '){
            if(!c){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
            else{
                host_uid[c] = '\0';
                c = i+1;
                break;
            }
        }
        else{
            if(host_uid[c]<'0' || host_uid[c] > '9'){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
        }
        c++;
        if(c == 6){
            if(buffer_sock[i+1] != ' '){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
            c = i+2;
            break;
        }
        if(i == n-1){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
    }
    
    memset(aname,0,sizeof(aname));
    for(int i = c; i<n; i++){
        if(i == c) c = 0;
        aname[c] = buffer_sock[i];
        if(aname[c] == ' '){
            if(!c){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
            else{
                aname[c] = '\0';
                c = i+1;
                break;
            }
        }
        c++;
        if(c == MAX_ANAME){
            if(buffer_sock[i+1] != ' '){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
            c = i+2;
            break;
        }
        if(i == n-1){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
    }
    memset(fname,0,sizeof(fname));
    for(int i = c; i<n; i++){
        if(i == c) c = 0;
        fname[c] = buffer_sock[i];
        if(fname[c] == ' '){
            if(!c){
                fprintf(stderr, "-\n-");
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
            else{
                fname[c] = '\0';
                c = i+1;
                break;
            }
        }
        c++;
        if(c == MAX_FNAME){
            if(buffer_sock[i+1] != ' '){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
            c = i+2;
            break;
        }
        if(i == n-1){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
    }
    memset(value_str,0,sizeof(value_str));
    for(int i = c; i<n; i++){
        if(i == c) c = 0;
        value_str[c] = buffer_sock[i];
        if(value_str[c] == ' '){
            if(!c){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
            else{
                value_str[c] = '\0';
                c = i+1;
                break;
            }
        }
        else{
            if(value_str[c]<'0' || value_str[c] >'9'){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
        }
        c++;
        if(c == MAX_VALUE){
            if(buffer_sock[i+1] != ' '){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
            c = i+2;
            break;
        }
        if(i == n-1){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
    }

    if(n-c < 20){
        fprintf(stderr, "Error communicating with server\n");
        close(fd);
        return;
    }

    if(!isValidDateFormat(buffer_sock+c)){
        fprintf(stderr, "Error communicating with server\n");
        close(fd);
        return;
    }
    memset(timestamp,0,sizeof(timestamp));
    memcpy(timestamp,buffer_sock+c,19);

    c += 19;
    if(buffer_sock[c] != ' '){
        fprintf(stderr, "Error communicating with server\n");
        close(fd);
        return;
    }
    c++;

    memset(timeactive_str,0,sizeof(timeactive_str));
    for(int i = c; i<n; i++){
        if(i == c) c = 0;
        timeactive_str[c] = buffer_sock[i];
        if(timeactive_str[c] == ' ' || timeactive_str[c] == '\n'){
            if(!c){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
            else{
                timeactive_str[c] = '\0';
                c = i+1;
                break;
            }
        }
        else{
                if(timeactive_str[c]<'0' || timeactive_str[c]>'9'){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
            }
        c++;
        if(c == MAX_TIME){
            if(i == n-1 || (buffer_sock[i+1] != ' ' && buffer_sock[i+1] != '\n')){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
            c = i+2;
            break;
        }
        if(i == n-1){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
    }
    memset(display_message,0,sizeof(display_message));
    sprintf(display_message, "Auction %03d [NAME: %s, ASSET FILE NAME: %s]\nHOSTED BY USER WITH UID %s\nSTARTED AT %s\nACTIVE FOR %s\nSTART VALUE: %s\n",aid,aname,fname,host_uid,timestamp,timeactive_str,value_str);
    while(buffer_sock[c] == 'B'){
        c++;
        if(buffer_sock[c] != ' '){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
        c++;
        memset(bidder_uid,0,sizeof(bidder_uid));
        for(int i = c; i<n; i++){
            if(i == c) c = 0;
            bidder_uid[c] = buffer_sock[i];
            if(bidder_uid[c] == ' '){
                if(!c){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
                else{
                    bidder_uid[c] = ' ';
                    c = i+1;
                    break;
                }
            }
            else{
                if(bidder_uid[c]<'0' || bidder_uid[c] >'9'){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
            }
            c++;
            if(c == 6){
                if(i == n-1 || buffer_sock[i+1] != ' '){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
                c = i+2;
                break;
            }
            if(i == n-1){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
        }
        memset(value_str,0,sizeof(value_str));
        for(int i = c; i<n; i++){
            if(i == c) c = 0;
            value_str[c] = buffer_sock[i];
            if(value_str[c] == ' '){
                if(!c){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
                else{
                    value_str[c] = '\0';
                    c = i+1;
                    break;
                }
            }
            else{
                if(value_str[c]<'0' || value_str[c] >'9'){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
            }
            c++;
            if(c == MAX_VALUE){
                if(buffer_sock[i+1] != ' '){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
                c = i+2;
                break;
            }
            if(i == n-1){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
        }
        if(!isValidDateFormat(buffer_sock+c)){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
        memset(timestamp, 0, sizeof(timestamp));
        memcpy(timestamp,buffer_sock+c, 19);
        c+= 19;
        if(buffer_sock[c] != ' '){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
        c++;
        for(int i = c; i<n; i++){
            if(i == c) c = 0;
            timeactive_str[c] = buffer_sock[i];
            if(timeactive_str[c] == ' ' || timeactive_str[c] == '\n'){
                if(!c){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
                else{
                    timeactive_str[c] = '\0';
                    c = i+1;
                    break;
                }
            }
            else{
                if(timeactive_str[c]<'0' || timeactive_str[c]>'9'){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
            }
            c++;
            if(c == MAX_TIME){
                if(i == n-1 || (buffer_sock[i+1] != ' ' && buffer_sock[i+1] != '\n')){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
                c = i+2;
                break;
            }
            if(i == n-1){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
        }
        if(no_biders){
            no_biders = 0;
            sprintf(info, "\n---RECENT BIDS---\nBID BY USER WITH UID %s\nVALUE OF BID: %s\nTIMESTAMP OF BID: %s\nBID WAS MADE %s seconds after the auction started\n", bidder_uid, value_str, timestamp, timeactive_str);
        }
        else{
            sprintf(info, "\nBID BY USER WITH UID %s\nVALUE OF BID: %s\nTIMESTAMP OF BID: %s\nBID WAS MADE %s seconds after the auction started\n", bidder_uid, value_str, timestamp, timeactive_str);
        }
        disp_c = strlen(display_message);
        memcpy(display_message+disp_c, info, strlen(info));
    }

    if(buffer_sock[c] == 'E'){
        c++;
        if(buffer_sock[c]!=' '){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
        c++;
        if(!isValidDateFormat(buffer_sock+c)){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
        memset(timestamp, 0, sizeof(timestamp));
        memcpy(timestamp,buffer_sock+c, 19);
        c+= 19;
        if(buffer_sock[c] != ' '){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
        c++;
        memset(timeactive_str,0,sizeof(timeactive_str));
        for(int i = c; i<n; i++){
            if(i == c) c = 0;
            timeactive_str[c] = buffer_sock[i];
            if(timeactive_str[c] == '\n'){
                if(!c){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
                else{
                    timeactive_str[c] = '\0';
                    c = i+1;
                    break;
                }
            }
            else{
                if(timeactive_str[c]<'0' || timeactive_str[c]>'9'){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
            }
            c++;
            if(c == MAX_TIME){
                if(i == n-1 || buffer_sock[i+1] != '\n'){
                    fprintf(stderr, "Error communicating with server\n");
                    close(fd);
                    return;
                }
                c = i+2;
                break;
            }
            if(i == n-1){
                fprintf(stderr, "Error communicating with server\n");
                close(fd);
                return;
            }
        }
        sprintf(info,"\nAUCTION ENDED AT %s\nAUCTION WAS ACTIVE FOR %s seconds\n", timestamp, timeactive_str);
        disp_c = strlen(display_message);
        memcpy(display_message+disp_c,info,strlen(info));
    }
    else{
        sprintf(info,"\n--AUCTION STILL ONGOING--\n");
        disp_c = strlen(display_message);
        memcpy(display_message+disp_c, info, strlen(info));
    }
    fprintf(stdout,"%s",display_message);
    close(fd);
}

void list(struct addrinfo *res){
    char message[4], buffer[6500], status[4], display_message[50000];
    int fd, n;
    socklen_t addrlen;
    struct sockaddr_in addr;

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;


    memcpy(message, "LST\n", 4);
    fd=socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(fd==-1){
        fprintf(stderr,"Error creating socket\n");
        return;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    n=sendto(fd,message,sizeof(message),0,res->ai_addr,res->ai_addrlen);

    if(n==-1){
        fprintf(stderr,"Error communicating with server\n");
        close(fd);
        return;
    }
    n=recvfrom(fd,buffer,sizeof(buffer),0,
    (struct sockaddr*)&addr,&addrlen);
    if(n == 8){
        if(!memcmp(buffer, "RLS NOK\n",8)){
            fprintf(stdout, "There is no auctions yet\n");
        }
    }
    else if(n>7){
        if(!memcmp(buffer, "RLS OK ",7)){
            if(display_auctions(buffer+7, display_message, n-7) == -1){
                fprintf(stderr, "Error communicating with server\n");
            }
            else{
                fprintf(stdout, "Auctions:\n");
                fprintf(stdout, "%s" ,display_message);
            }
        }
    }
    else{
        fprintf(stderr, "Error communicating with server\n");
    }
    close(fd);
    
}

void bid(char *buffer, struct addrinfo *res, user *usr){
    int fd, aid, n, val;
    char message[50], buf_ad[256], uid_str[7], pass_str[9];

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if(!usr){
        fprintf(stderr, "You must be logged in\n");
        return;
    }
    memset(uid_str,0,sizeof(uid_str));
    memset(pass_str,0,sizeof(pass_str));
    memcpy(uid_str,usr->uid,6);
    memcpy(pass_str, usr->pass,8);

    sscanf(buffer,"%s",buf_ad);

    if(strlen(buf_ad)>3){
        fprintf(stderr, "INVALID AID\n");
        return;
    }

    for(int i = 0; i < strlen(buf_ad); i++){
        if(buf_ad[i]<'0' || buf_ad[i] > '9'){
            fprintf(stderr, "INVALID AID\n");
            return;
        }
    }

    if(buffer[strlen(buf_ad)]!=' '){
        fprintf(stderr, "No value provided\n");
        return;
    }

    

    sscanf(buffer,"%*s %s", buf_ad);

    if(strlen(buf_ad)>6){
        fprintf(stderr, "INVALID VALUE\n");
        return;
    }

    for(int i = 0; i < strlen(buf_ad); i++){
        if(buf_ad[i]<'0' || buf_ad[i] > '9'){
            fprintf(stderr, "INVALID VALUE\n");
            return;
        }
    }


    sscanf(buffer, "%d %d", &aid, &val);

    memset(message, 0, sizeof(message));
    sprintf(message, "BID %s %s %03d %d", uid_str, pass_str, aid, val);

    message[strlen(message)] = '\n';

    fd=socket(AF_INET,SOCK_STREAM,0); //TCP socket
    if (fd==-1) {
        fprintf(stderr, "Error creating socket\n");
        return;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    n=connect(fd,res->ai_addr,res->ai_addrlen);
    if(n==-1){
        fprintf(stderr, "Error communicating with server\n");
        close(fd);
        return;
    }
    
    n = write(fd, message, strlen(message));
    if(n == -1){
        fprintf(stderr, "Error communicating with server\n");
        close(fd);
        return;
    }
    n = read(fd, message, sizeof(message));
    if(n == -1){
        fprintf(stderr, "Error communicating with server\n");
        close(fd);
        return;
    }
    if(n != 8){
        fprintf(stderr, "Error communicating with server\n");
        close(fd);
        return;
    }
    if(!memcmp(message, "RBD ACC\n",8)){
        fprintf(stderr,"Your bid was accepted\n");
    }
    else if(!memcmp(message, "RBD NOK\n",8)){
        fprintf(stderr,"This auction is no longer active\n");
    }
    else if(!memcmp(message, "RBD REF\n",8)){
        fprintf(stderr,"There is already a higher bid placed on this auction\n");
    }
    else if(!memcmp(message, "RBD ILG\n",8)){
        fprintf(stderr,"You cannot place bids on auction that you have started\n");
    }
    else{
        fprintf(stderr, "Error communicating with server\n");
    }
    close(fd);
}

void close_a(char *buffer, struct addrinfo *res, user *usr){
    int fd, aid, n;
    char message[24], buf_ad[256], uid_str[7], pass_str[9];

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if(!usr){
        fprintf(stderr, "You must be logged in\n");
        return;
    }
    memset(uid_str,0,sizeof(uid_str));
    memset(pass_str,0,sizeof(pass_str));
    memcpy(uid_str,usr->uid,6);
    memcpy(pass_str, usr->pass,8);

    sscanf(buffer,"%s",buf_ad);

    if(strlen(buf_ad)>3){
        fprintf(stderr, "INVALID AID\n");
        return;
    }

    for(int i = 0; i < strlen(buf_ad); i++){
        if(buf_ad[i]<'0' || buf_ad[i] > '9'){
            fprintf(stderr, "INVALID AID\n");
            return;
        }
    }

    sscanf(buffer,"%d",&aid);

    sprintf(message,"CLS %s %s %03d", uid_str, pass_str, aid);
    message[23] = '\n';
    fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd==-1){
        fprintf(stderr, "Error creating socket\n");
        return;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    n=connect(fd,res->ai_addr,res->ai_addrlen);
    if(n==-1){
        fprintf(stderr,"Error communicating with server\n");
        close(fd);
        return;
    }
    
    write(fd, message, sizeof(message));
    n = read(fd, message, sizeof(message));
    if(n==-1){
        fprintf(stderr,"Error communicating with server\n");
        close(fd);
        return;
    }
    else if(n == 7){
        if(!memcmp(message, "RCL OK\n",7)){
            fprintf(stdout, "Auction closed successfully\n");
        }
        else{
            fprintf(stderr,"Error communicating with server\n");
            close(fd);
            return;
        }
    }
    else if(n==8){
        if(!memcmp(message, "RCL NOK\n",8)){
            fprintf(stdout, "User uid does not exist or password is incorrect\n");
        }
        else if(!memcmp(message, "RCL NLG\n",8)){
            fprintf(stdout, "You are not logged in\n");
        }
        else if(!memcmp(message, "RCL EAU\n",8)){
            fprintf(stdout, "Auction does not exist\n");
        }
        else if(!memcmp(message, "RCL EOW\n",8)){
            fprintf(stdout, "You can only close auctions you have hosted\n");
        }
        else if(!memcmp(message, "RCL END\n",8)){
            fprintf(stdout, "Auction has already ended\n");
        }
        else{
            fprintf(stderr,"Error communicating with server\n");
            close(fd);
            return;
        }
    }
    close(fd);
}

void open_a(char *buffer, struct addrinfo *res, user *usr){
    int fd,errcode, fd_f, f_asset, left, y;
    ssize_t n;

    char name[21], fname[31], buffer1[256], buffer_sock[2048], uid_str[7], pass_str[9], x[256], aid_str[4];
    int timeactive, start_value, aid;
    long f_size;
    FILE *file;

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;


    if(!usr){
        fprintf(stderr, "You must be logged in to open an asset\n");
        return;
    }

    if(sscanf(buffer, "%s", buffer1) == -1){
        fprintf(stderr, "ERROR parsing name\n");
        return;
    }

    if(strlen(buffer1)>20){
        fprintf(stderr, "MAX NAME LEN = 20\n");
        return;
    }
    
    y = strlen(buffer1);

    if(buffer[y] != ' '){
        fprintf(stderr, "WRONG INPUT, PROVIDE ALL THE ARGUMENTS AND SEPARATE THEM WITH SPACES\n");
        return;
    }

    strcpy(name,buffer1);
    memset(buffer1, 0, sizeof(buffer1));

    if(sscanf(buffer, "%*s %s", buffer1)==-1){
        fprintf(stderr, "ERROR parsing file name\n");
        return;
    }

    y += 1 + strlen(buffer1);

    if(buffer[y] != ' '){
        fprintf(stderr, "WRONG INPUT, PROVIDE ALL THE ARGUMENTS AND SEPARATE THEM WITH SPACES\n");
        return;
    }

    if(strlen(buffer1)>30){
        fprintf(stderr, "MAX FILE NAME LEN = 20\n");
        return;
    }
    strcpy(fname,buffer1);

    if (sscanf(buffer, "%*s %*s %s", x) == -1){
        fprintf(stderr, "Error parsing start value\n");
        return;
    }
    if(strlen(x) > 6){
        fprintf(stderr, "MAX START VALUE - 999999\n");
        return;
    }
    for(int i; i<strlen(x); i++){
        if(x[i]<'0' || x[i]>'9'){
        fprintf(stderr, "Start value must be an integer\n");
        return;
        }
    }

    y += 1 + strlen(x);

    if(buffer[y] != ' '){
        fprintf(stderr, "WRONG INPUT, PROVIDE ALL THE ARGUMENTS AND SEPARATE THEM WITH SPACES\n");
        return;
    }

    if (sscanf(buffer, "%*s %*s %*s %s", x) == -1){
        fprintf(stderr, "Error parsing time active\n");
        return;
    }
    if(strlen(x)>5){
        fprintf(stderr, "MAX TIME ACTIVE - 99999\n");
        return;
    }
    for(int i; i<strlen(x); i++){
        if(x[i]<'0' || x[i]>'9'){
        fprintf(stderr, "Time active must be an integer\n");
        return;
        }
    }

    if(sscanf(buffer, "%*s %*s %d %d", &start_value, &timeactive) == -1){
        fprintf(stderr, "ERROR parsing start value and timeactive\n");
        return;
    }

    if(!(file = fopen(fname, "r"))){
        fprintf(stderr, "COULDNT FIND A FILE WITH PROVIDED NAME\n");
        return;
    }

    f_size = getFileSize(file);

    fclose(file);

    if(f_size > 99999999){
        fprintf(stderr, "Too big file to send\n");
        return;
    }

    f_asset = open(fname, O_RDONLY);
    memset(uid_str,0,sizeof(uid_str));
    memcpy(uid_str,usr->uid,sizeof(usr->uid));


    memset(pass_str,0,sizeof(pass_str));
    memcpy(pass_str,usr->pass,sizeof(usr->pass));

    fd=socket(AF_INET,SOCK_STREAM,0); //TCP socket
    if (fd==-1){
        fprintf(stderr,"Error creating socket\n");
        return;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    n=connect(fd,res->ai_addr,res->ai_addrlen);
    if(n==-1){
        fprintf(stderr, "COULDNT ESTABILISH CONNECTION\n");
        close(fd);
        close(f_asset);
        return;
    }

    memset(buffer_sock, 0, sizeof(buffer_sock));
    sprintf(buffer_sock,"OPA %s %s %s %d %d %s %ld ", uid_str, pass_str, name, start_value, timeactive, fname, f_size);
    left = sizeof(buffer_sock)-strlen(buffer_sock);

    int counter=0;

    n = read(f_asset,buffer_sock+strlen(buffer_sock),left);
    if(n==-1){
        close(f_asset);
        close(fd);
        fprintf(stderr, "ERRO\n");
        return;
    }
    if(n == left){
        y = write(fd,buffer_sock,sizeof(buffer_sock));
        if(y == -1){
            close(f_asset);
            close(fd);
            fprintf(stderr, "ERRO\n");
            return;
        }
        n = read(f_asset,buffer_sock,sizeof(buffer_sock));
        while(n==sizeof(buffer_sock)){
            y = write(fd,buffer_sock,sizeof(buffer_sock));
            counter +=y;
            if(y == -1){
                fprintf(stderr, "ERRO\n");
                close(f_asset);
                close(fd);
                return;
            }
            n = read(f_asset,buffer_sock,sizeof(buffer_sock));

        }
        buffer_sock[n] = '\n';
        y = write(fd,buffer_sock,n+1);
        if(y == -1){
            fprintf(stderr, "ERRO\n");
            close(f_asset);
            close(fd);
            return;
        }
        printf("NUMERO DE BYUTES ESCRITOS = %ld\n", counter+n);
    }
    else{
        buffer_sock[sizeof(buffer_sock)-left+n] = '\n';
        y = write(fd,buffer_sock,sizeof(buffer_sock)-left+n+1);
        if(y == -1){
            fprintf(stderr, "ERRO\n");
            close(fd);
            return;
        }
    }
    
    close(f_asset);
    n=read(fd,buffer1,256);
    if(n==-1){
        close(fd);
        fprintf(stderr,"Error communicating with server\n");
        return;
    }
    if(n == 11){
        if(!memcmp(buffer1, "ROA OK ",7)){
            for(int i = 7; i<7+3; i++){
                if(buffer1[i] < '0' || buffer1[i] >'9'){
                    close(fd);
                    fprintf(stderr,"Error communicating with server\n");
                    return;
                }
            }
            if(buffer1[10] != '\n'){
                close(fd);
                fprintf(stderr,"Error communicating with server\n");
                return;
            }
            memset(aid_str,0,sizeof(aid_str));
            memcpy(aid_str,buffer1+7,3);
            sscanf(aid_str,"%d",&aid);
            fprintf(stdout,"Successfully created auction with AID - %03d\n",aid);
        }
    }
    else if(n==8){
        if(!memcmp(buffer1,"ROA NOK\n",8)){
            fprintf(stdout,"Server couldnt open asset\n");
        }
        else{
            close(fd);
            fprintf(stderr,"Error communicating with server\n");
            return;
        }
    }
    else{
        close(fd);
        fprintf(stderr,"Error communicating with server\n");
        return;
    }
    close(fd);
    return;

}

void sa(char *buffer, struct addrinfo *res){
    int fd,errcode, fd_f, f_asset, left, aid, r;
    ssize_t n;

    char name[21], fname[31], buffer1[256], buffer_sock[2048], status[4];
    int timeactive, start_value, first = 1;
    long f_size;

    FILE *file;

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    if(sscanf(buffer, "%s", buffer1) == -1){
        fprintf(stderr, "ERROR parsing AID\n");
        return;
    }
    for(int i; i<strlen(buffer1); i++){
        if(buffer1[i]<'0' || buffer1[i]>'9'){
        fprintf(stderr, "AID must be an integer\n");
        return;
        }
    }

    sscanf(buffer, "%d", &aid);
    


    fd=socket(AF_INET,SOCK_STREAM,0); //TCP socket
    if (fd==-1){
        fprintf(stderr,"Error creating socket\n");
        return;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    n=connect(fd,res->ai_addr,res->ai_addrlen);
    if(n==-1){
        fprintf(stderr,"Error communicating with server\n");
        close(fd);
        return;
    }
    memset(buffer_sock, 0, sizeof(buffer_sock));
    sprintf(buffer_sock,"SAS %03d\n", aid);

    n=write(fd,buffer_sock,strlen(buffer_sock));
    if(n!=8){
        fprintf(stderr,"Error communicating with server\n");
        close(fd);
        return;
    }


    memset(buffer_sock, 0, sizeof(buffer_sock));
    n = read(fd,buffer_sock,7);
    if(n != 7){
        fprintf(stderr,"Error communicating with server\n");
        close(fd);
        return;
    }
    if(memcmp(buffer_sock+4,"OK",2)){
        fprintf(stderr, "Unable to show asset\n");
        close(fd);
        return;
    }
    memset(buffer_sock, 0, sizeof(buffer_sock));
    while(1){
        n = read(fd,buffer_sock,sizeof(buffer_sock));
        if(n == -1){
            fprintf(stderr, "Error communicating with server\n");
            close(fd);
            return;
        }
        if(first){
            sscanf(buffer_sock, "%s %ld", fname, &f_size); // strlen(fname) + 1 + stlen(f_size) + 1
            sscanf(buffer_sock, "%*s %s", buffer1);
            f_asset = open(fname, O_WRONLY | O_TRUNC | O_CREAT);
            r = n-2-strlen(buffer1)-strlen(fname);
            if(r == f_size+1){
                write(f_asset,buffer_sock+n-r,r-1);
                break;
            }
            write(f_asset,buffer_sock+n-r,r);
        }
        else{
            r += n;
            if(r == f_size+1)
                write(f_asset,buffer_sock,n-1);
            write(f_asset,buffer_sock,n);
        }
        first = 0;
        if(r == f_size+1){
            break;
        }
    }
    close(f_asset);
    close(fd);
    fprintf(stdout, "Successfully received auction file [FILE NAME : %s]\n", fname);
}


int main(int argc, char **argv){

    int fd,errcode;
    ssize_t n;
    
    struct addrinfo hints,*res;

    user *registered = NULL;
    
    char buffer[256], command[20];
    char *PORT = NULL, *name = NULL, c;

    for(size_t i = 1; i < argc; i ++){
        if(!strcmp(argv[i], "-n")){
            i++;
            name = malloc(strlen(argv[i])+1);
            strcpy(name, argv[i]);
        }
        if(!strcmp(argv[i], "-p")){
            i++;
            PORT = malloc(strlen(argv[i])+1);
            strcpy(PORT, argv[i]);
        }
    }
    if(!PORT){
        PORT = malloc(strlen("58036")+1);
        strcpy(PORT, "58036");
    }

    if(!name){
        name = malloc(strlen("localhost")+1);
        strcpy(name,"localhost");
    }
    
    //getting addr

    memset(&hints,0,sizeof hints);
    hints.ai_family=AF_INET; //IPv4
    hints.ai_socktype=SOCK_DGRAM; //UDP socket
    errcode=getaddrinfo(name,PORT,&hints,&res);
    if(errcode!=0) /*error*/ exit(1);

    while(1){
        memset(buffer,0,sizeof(buffer));
        if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Remove the newline character from the end of the input
            if(buffer[sizeof(buffer)-1] != '\0'){
                fprintf(stderr, "INVALID COMMAND, MAX LENGTH = 255\n");
                continue;
            }
            sscanf(buffer,"%s",command);
            if(!strcmp(command,"login")){
                if(!registered){
                    if(buffer[5] == ' ')
                        registered = login(buffer+6, res);
                    else
                        fprintf(stderr, "INVALID COMMAND\n");
                }
                else{
                    fprintf(stdout,"Logout first to login as a different user\n");
                }
            }
            else if (!strcmp(command,"logout")){
                if(buffer[6] == '\n'){
                    logout(registered, res);
                    if(registered)
                        free(registered);
                    registered = NULL;
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");
            }
            else if(!strcmp(command,"unregister")){
                if(buffer[10] == '\n'){
                    unreg(registered, res);
                    if(registered)
                        free(registered);
                    registered = NULL;
                }
            }
            else if(!strcmp(command,"exit")){
                if(registered){

                    while (1) {
                        printf("Are you sure you want to exit ? (You are still logged in)\nInput y to exit or n to continue using the program\n");
                        c = getchar();

                        // Clear input buffer
                        while ((getchar()) != '\n');

                        if (c == 'y' || c == 'n') break;
                        if (c == EOF) {
                            // Handle end-of-file or error condition
                            break;
                        }
                    }
                    if(c == 'y'){
                        logout(registered, res);
                        break;
                    }
                    
                }
                else
                    break;
            }
            else if(!strcmp(command,"open")){
                if(buffer[4] == ' '){
                    open_a(buffer+5, res, registered);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");
            }
            else if(!strcmp(command,"show_asset")){
                if(buffer[10] == ' '){
                    sa(buffer+11, res);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");
            }
            else if(!strcmp(command,"sa")){
                if(buffer[2] == ' '){
                    sa(buffer+3, res);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else if(!strcmp(command,"ma")){
                if(buffer[2] == '\n'){
                    ma(res, registered);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else if(!strcmp(command,"myauctions")){
                if(buffer[10] == '\n'){
                    ma(res, registered);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else if(!strcmp(command,"close")){
                if(buffer[5] == ' '){
                    close_a(buffer+6, res, registered);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else if(!strcmp(command,"mybids")){
                if(buffer[6] == '\n'){
                    mb(res, registered);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else if(!strcmp(command,"mb")){
                if(buffer[2] == '\n'){
                    mb(res, registered);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else if(!strcmp(command,"l")){
                if(buffer[1] == '\n'){
                    list(res);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else if(!strcmp(command,"list")){
                if(buffer[4] == '\n'){
                    list(res);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else if(!strcmp(command,"bid")){
                if(buffer[3] == ' '){
                    bid(buffer+4, res, registered);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else if(!strcmp(command,"b")){
                if(buffer[1] == ' '){
                    bid(buffer+2, res, registered);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else if(!strcmp(command,"show_record")){
                if(buffer[11] == ' '){
                    sr(buffer+12, res);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else if(!strcmp(command,"sr")){
                if(buffer[2] == ' '){
                    sr(buffer+3, res);
                }
                else
                    fprintf(stderr, "INVALID COMMAND\n");;
            }
            else
                fprintf(stderr,"UNVALID COMMAND\n");
        }
    }
    
    freeaddrinfo(res);
    if(registered)
        free(registered);
    free(PORT);
    free(name);
}
