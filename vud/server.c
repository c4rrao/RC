#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#define MAX_ANAME 20
#define MAX_FNAME 30
#define MAX_VALUE 6
#define MAX_TIME 5
#define MAX_F_S 8

int a_count;

int v = 0;

void signal_handler(int signum) {
    // Do nothing in the signal handler
}

void set_a_count(){
    char dirname[30];
    int n_entries, first = 1;
    struct dirent **filelist;
    sprintf(dirname ,"AUCTIONS/");
    n_entries = scandir(dirname, &filelist , 0, alphasort);
    while(n_entries--){
        if(strlen(filelist[n_entries]->d_name) == 3 && first){
            sscanf(filelist[n_entries]->d_name, "%d", &a_count);
            first = 0;
        }
        free(filelist[n_entries]);
    }
    free(filelist);
    if(first)
        a_count = 0;
}

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

int user_logged_in(char *uid){
    char uid_dir_e[20], uid_str[7], uid_log[30];
    int f;
    memset(uid_str,0,sizeof(uid_str));
    memcpy(uid_str, uid, 6);
    sprintf(uid_log, "USERS/%s/%s_login.txt",uid_str, uid_str);
    f = open(uid_log, O_RDONLY);
    if(f == -1){
        return 0;
    }
    close(f);
    return 1;
}

int correct_password(char *uid, char *password){
    int f;
    char uid_str[7], uid_pass_f[30], correct_pass[8];
    memset(uid_str,0,sizeof(uid_str));
    memcpy(uid_str, uid, 6);
    sprintf(uid_pass_f, "USERS/%s/%s_pass.txt",uid_str, uid_str);
    f = open(uid_pass_f, O_RDONLY);
    if(f == -1){
        return 0;
    }
    read(f,correct_pass,sizeof(correct_pass));
    close(f);
    if(!memcmp(password,correct_pass, sizeof(correct_pass)))
        return 1;
    return 0;
}

void logout(char *buffer, int fd, socklen_t addrlen, struct sockaddr_in addr){
    int n, logged_in = 0, registered = 0, f, f_log;
    char uid[6], pass[8], message[20], uid_entry_log[30], pass_entry_name[29], uid_str[7], uid_entry_dir[13], pass_real[8], hosted_str[20], bidded_str[20];
    DIR *dir;

    if(v) fprintf(stderr, "Received a request to logout ...\n");


    if(buffer[6] != ' '){
        if(v) fprintf(stderr, "Something went wrong\n");
        memcpy(message,"RLO ERR\n",8);
            n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
        return;
    }

    if(buffer[15]!= '\n'){
        if(v) fprintf(stderr, "Something went wrong\n");
        memcpy(message,"RLO ERR\n",8);
            n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
        return;
    }

    for(size_t i = 0; i < 6; i++){
        if(buffer[i] < '0' || buffer[i] > '9'){
            if(v) fprintf(stderr, "Something went wrong\n");
            memcpy(message,"RLO ERR\n",8);
            n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
            return;
        }
        uid[i] = buffer[i];
    }


    for(size_t i = 7; i < 7+8; i++){
        if((buffer[i] < '0' || buffer[i] > '9') && (buffer[i] < 'a' || buffer[i] > 'z') && (buffer[i] < 'A' || buffer[i] > 'Z')){
            if(v) fprintf(stderr, "Something went wrong\n");
            memcpy(message,"RLO ERR\n",8);
            n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
            return;
        }
        pass[i-7] = buffer[i];
    }

    memset(uid_str,0,sizeof(uid_str));
    memcpy(uid_str, uid, sizeof(uid));

    sprintf(uid_entry_log, "USERS/%s/%s_login.txt", uid_str, uid_str);
    sprintf(uid_entry_dir, "USERS/%s", uid_str);
    sprintf(pass_entry_name, "USERS/%s/%s_pass.txt", uid_str, uid_str);
    sprintf(hosted_str,"USERS/%s/HOSTED", uid_str);
    sprintf(bidded_str,"USERS/%s/BIDDED", uid_str);

    dir = opendir(uid_entry_dir);
    if(!dir){
        if(v) fprintf(stderr, "User was not registered\n");
        memcpy(message,"RLO UNR\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    closedir(dir);

    f = open(pass_entry_name, O_RDONLY);
    if(f==-1){
        if(v) fprintf(stderr, "User was not registered\n");
        memcpy(message,"RLO UNR\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }

    read(f,pass_real,sizeof(pass_real));

    if(memcmp(pass,pass_real, sizeof(pass))){
        if(v) fprintf(stderr, "Wrong password provided\n");
        memcpy(message,"RLO NOK\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }

    close(f);

    f = open(uid_entry_log,O_RDONLY);

    if(f == -1){
        if(v) fprintf(stderr, "User was not logged in\n");
        memcpy(message,"RLO NOK\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }

    close(f);

    remove(uid_entry_log);
    if(v) fprintf(stderr, "User with uid - %s logged out successfully\n", uid_str);
    memcpy(message,"RLO OK\n",7);
    n=sendto(fd,message,7,0,
    (struct sockaddr*)&addr,addrlen);
    return;
    
}

void unreg(char *buffer, int fd, socklen_t addrlen, struct sockaddr_in addr){
    int n, logged_in = 0, registered = 0, f, f_log;
    char uid[6], pass[8], message[20], uid_entry_log[30], pass_entry_name[29], uid_str[7], uid_entry_dir[13], pass_real[8], hosted_str[20], bidded_str[20];
    DIR *dir;

    if(v) fprintf(stderr, "Received a request to unregister ...\n");

    if(buffer[6] != ' '){
        if(v) fprintf(stderr, "Something went wrong\n");
        memcpy(message,"RUR ERR\n",8);
            n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
        return;
    }

    if(buffer[15]!= '\n'){
        if(v) fprintf(stderr, "Something went wrong\n");
        memcpy(message,"RUR ERR\n",8);
            n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
        return;
    }

    for(size_t i = 0; i < 6; i++){
        if(buffer[i] < '0' || buffer[i] > '9'){
            if(v) fprintf(stderr, "Something went wrong\n");
            memcpy(message,"RUR ERR\n",8);
            n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
            return;
        }
        uid[i] = buffer[i];
    }


    for(size_t i = 7; i < 7+8; i++){
        if((buffer[i] < '0' || buffer[i] > '9') && (buffer[i] < 'a' || buffer[i] > 'z') && (buffer[i] < 'A' || buffer[i] > 'Z')){
            if(v) fprintf(stderr, "Something went wrong\n");
            memcpy(message,"RUR ERR\n",8);
            n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
            return;
        }
        pass[i-7] = buffer[i];
    }

    memset(uid_str,0,sizeof(uid_str));
    memcpy(uid_str, uid, sizeof(uid));

    sprintf(uid_entry_log, "USERS/%s/%s_login.txt", uid_str, uid_str);
    sprintf(uid_entry_dir, "USERS/%s", uid_str);
    sprintf(pass_entry_name, "USERS/%s/%s_pass.txt", uid_str, uid_str);
    sprintf(hosted_str,"USERS/%s/HOSTED", uid_str);
    sprintf(bidded_str,"USERS/%s/BIDDED", uid_str);

    dir = opendir(uid_entry_dir);
    if(!dir){
        if(v) fprintf(stderr, "User was not registered\n");
        memcpy(message,"RUR UNR\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    closedir(dir);

    f = open(pass_entry_name, O_RDONLY);
    if(f==-1){
        if(v) fprintf(stderr, "User was not registered\n");
        memcpy(message,"RUR UNR\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }

    read(f,pass_real,sizeof(pass_real));

    if(memcmp(pass,pass_real, sizeof(pass))){
        if(v) fprintf(stderr, "Wrong password\n");
        memcpy(message,"RUR ERR\n",8);
            n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
        return;
    }

    close(f);

    f = open(uid_entry_log,O_RDONLY);

    if(f == -1){
        if(v) fprintf(stderr, "User was not logged in\n");
        memcpy(message,"RUR NOK\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }

    close(f);

    remove(uid_entry_log);
    remove(pass_entry_name);

    if(v) fprintf(stderr, "User with uid %s was successfully unregistered\n", uid_str);

    memcpy(message,"RUR OK\n",7);
    n=sendto(fd,message,7,0,
    (struct sockaddr*)&addr,addrlen);
    return;
    
}

void login(char *buffer, int fd, socklen_t addrlen, struct sockaddr_in addr){
    int n, logged_in = 0, registered = 0, f, f_log;
    char uid[6], pass[8], message[20], uid_entry_log[30], pass_entry_name[29], uid_str[7], uid_entry_dir[13], pass_real[8], hosted_str[20], bidded_str[20];
    
    struct dirent *entry;
    DIR *dir;

    if(v) fprintf(stderr, "Received a login request ...\n");

    if(buffer[6] != ' '){
        if(v) fprintf(stderr, "Something went wrong\n");
        memcpy(message,"RLI ERR\n",8);
        n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
        return;
    }

    if(buffer[15]!= '\n'){
        if(v) fprintf(stderr, "Something went wrong\n");
        memcpy(message,"RLI ERR\n",8);
        n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
        return;
    }

    for(size_t i = 0; i < 6; i++){
        if(buffer[i] < '0' || buffer[i] > '9'){
            if(v) fprintf(stderr, "Something went wrong\n");
            memcpy(message,"RLI ERR\n",8);
            n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
            return;
        }
        uid[i] = buffer[i];
    }


    for(size_t i = 7; i < 7+8; i++){
        if((buffer[i] < '0' || buffer[i] > '9') && (buffer[i] < 'a' || buffer[i] > 'z') && (buffer[i] < 'A' || buffer[i] > 'Z')){
            if(v) fprintf(stderr, "Something went wrong\n");
            memcpy(message,"RLI ERR\n",8);
            n=sendto(fd,message,8,0,(struct sockaddr*)&addr,addrlen);
            return;
        }
        pass[i-7] = buffer[i];
    }

    memset(uid_str,0,sizeof(uid_str));
    memcpy(uid_str, uid, sizeof(uid));

    sprintf(uid_entry_log, "USERS/%s/%s_login.txt", uid_str, uid_str);
    sprintf(uid_entry_dir, "USERS/%s", uid_str);
    sprintf(pass_entry_name, "USERS/%s/%s_pass.txt", uid_str, uid_str);
    sprintf(hosted_str,"USERS/%s/HOSTED", uid_str);
    sprintf(bidded_str,"USERS/%s/BIDDED", uid_str);
    
    dir = opendir(uid_entry_dir);
    if(dir){
        registered = 1;
        closedir(dir);
    }

    if(!registered){
        mkdir(uid_entry_dir,0777);
        mkdir(hosted_str,0777);
        mkdir(bidded_str,0777);

        f = open(pass_entry_name, O_WRONLY | O_TRUNC | O_CREAT, 0666);

        write(f, pass, sizeof(pass));

        close(f);

        f = open(uid_entry_log, O_WRONLY | O_TRUNC | O_CREAT, 0666);
        close(f);
        if(v) fprintf(stderr, "Successfully registered new user with uid - %s\n", uid_str);
        memcpy(message,"RLI REG\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    else{
        f = open(pass_entry_name, O_RDONLY);

        if(f == -1){
            f_log = open(pass_entry_name, O_WRONLY | O_TRUNC | O_CREAT, 0666);
            write(f_log,pass,sizeof(pass));
            close(f_log);
            f_log = open(uid_entry_log, O_WRONLY | O_TRUNC | O_CREAT, 0666);
            close(f_log);
            if(v) fprintf(stderr, "Successfully registered new user with uid - %s\n", uid_str);
            memcpy(message,"RLI REG\n",8);
            n=sendto(fd,message,8,0,
            (struct sockaddr*)&addr,addrlen);
            return;
        }
        

        read(f, pass_real, sizeof(pass_real));

        if(!memcmp(pass, pass_real, sizeof(pass))){
            // correct password

            f_log = open(uid_entry_log, O_WRONLY | O_TRUNC | O_CREAT, 0666);
            close(f_log);
            if(v) fprintf(stderr, "Successfully logged in user with uid - %s\n", uid_str);
            memcpy(message,"RLI OK\n",7);
            n=sendto(fd,message,7,0,
            (struct sockaddr*)&addr,addrlen);
            return;
        }
        else{
            if(v) fprintf(stderr, "Wrong password\n");
            memcpy(message,"RLI NOK\n",8);
            n=sendto(fd,message,8,0,
            (struct sockaddr*)&addr,addrlen);
            return;
        }
        close(f);
    }
}

int verify_pass(char *pass){
    for(int i = 0; i < 8; i++){
        if((pass[i]<'0' || pass[i] > '9') && (pass[i] < 'a' || pass[i] > 'z') && (pass[i] < 'A' || pass[i] > 'Z')){
            return 0;
        }
    }
    return 1;
}

int verify_uid(char *uid){
    for(int i = 0; i < 6; i++){
        if(uid[i]<'0' || uid[i] > '9'){
            return 0;
        }
    }
    return 1;
}

int next_not_space(int fd){
    int n;
    char c[3];
    n = read(fd, c, 1);
    if(n != 1 || c[0] != ' '){
        return 1;
    }
    return 0;
}

void open_a(int fd){
    int n, f_asset, f, time_act, val;
    char buffer[2048], uid[7], pass[9], fname[MAX_FNAME+1], aname[MAX_ANAME+1], value_str[MAX_VALUE+1], f_size_str[MAX_F_S+1], timeactive_str[MAX_TIME+1],
    f_asset_str[MAX_FNAME+15], dir_a_str[20], f_start_a[35], bids_dir[25], response[20], start_content[256];
    long f_size, bytes_read = 0;

    fd_set read_fds;
    struct timeval timeout;

    // Set the timeout to 5 seconds
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    // Initialize the file descriptor set
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    int ready = select(fd + 1, &read_fds, NULL, NULL, &timeout);


    if(v) fprintf(stderr, "Received a request to open an asset ...\n");

    memset(uid,0,sizeof(uid));
    n = read(fd,uid,6);
    if(n != 6){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "ROA ERR\n", 8);
        return;
    }
    if(!verify_uid(uid)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "ROA ERR\n", 8);
        return;
    }

    if(next_not_space(fd)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "ROA ERR\n", 8);
        return;
    }
    memset(pass, 0, sizeof(pass));
    n = read(fd,pass,8);
    if(n != 8){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "ROA ERR\n", 8);
        return;
    }
    if(!verify_pass(pass)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "ROA ERR\n", 8);
        return;
    }
    if(next_not_space(fd)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "ROA ERR\n", 8);
        return;
    }
    if(!correct_password(uid,pass)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "ROA ERR\n", 8);
        return;
    }
    if(!user_logged_in(uid)){
        if(v) fprintf(stderr, "User was not logged in\n");
        write(fd, "ROA NLG\n", 8);
        return;
    }
    memset(aname,0,sizeof(aname));
    for(int i = 0; i < MAX_ANAME; i++){
        n = read(fd, aname+i, 1);
        if(n!=1){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
        if(aname[i] == ' '){
            if(!i){
                if(v) fprintf(stderr, "Something went wrong\n");
                write(fd, "ROA ERR\n", 8);
                return;
            }
            aname[i] = '\0';
            break;
        }
    }

    if(aname[MAX_ANAME-1] != '\0'){
        if(next_not_space(fd)){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
    }
    memset(value_str,0,sizeof(value_str));
    for(int i = 0; i < MAX_VALUE; i++){
        n = read(fd, value_str+i, 1);
        if(n!=1){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
        if(value_str[i] == ' ' ){
            if(!i){
                if(v) fprintf(stderr, "Something went wrong\n");
                write(fd, "ROA ERR\n", 8);
                return;
            }
            value_str[i] = '\0';
            break;
        }
        if(value_str[i]<'0' || value_str[i] > '9'){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
    }
    if(value_str[MAX_VALUE-1] != '\0'){
        if(next_not_space(fd)){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
    }
    memset(timeactive_str,0,sizeof(timeactive_str));
    for(int i = 0; i < MAX_TIME; i++){
        n = read(fd, timeactive_str+i, 1);
        if(n!=1){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
        if(timeactive_str[i] == ' '){
            if(!i){
                if(v) fprintf(stderr, "Something went wrong\n");
                write(fd, "ROA ERR\n", 8);
                return;
            }
            timeactive_str[i] = '\0';
            break;
        }
        if(timeactive_str[i]<'0' || timeactive_str[i] > '9'){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
    }
    if(timeactive_str[MAX_TIME-1] != '\0'){
        if(next_not_space(fd)){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
    }

    memset(fname,0,sizeof(fname));
    for(int i = 0; i < MAX_FNAME; i++){
        n = read(fd, fname+i, 1);
        if(n!=1){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
        if(fname[i] == ' '){
            if(!i){
                if(v) fprintf(stderr, "Something went wrong\n");
                write(fd, "ROA ERR\n", 8);
                return;
            }
            fname[i] = '\0';
            break;
        }
    }
    if(fname[MAX_FNAME-1] != '\0'){
        if(next_not_space(fd)){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
    }

    memset(f_size_str,0,sizeof(f_size_str));
    for(int i = 0; i < MAX_F_S; i++){
        n = read(fd, f_size_str+i, 1);
        if(n!=1){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
        if(f_size_str[i] == ' '){
            if(!i){
                if(v) fprintf(stderr, "Something went wrong\n");
                write(fd, "ROA ERR\n", 8);
                return;
            }
            f_size_str[i] = '\0';
            break;
        }
        if(f_size_str[i]<'0' || f_size_str[i] > '9'){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
    }
    if(f_size_str[MAX_F_S-1] != '\0'){
        if(next_not_space(fd)){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "ROA ERR\n", 8);
            return;
        }
    }

    sscanf(timeactive_str, "%d", &time_act);
    sscanf(value_str, "%d", &val);
    sscanf(f_size_str, "%ld", &f_size);
    set_a_count();
    a_count++;
    sprintf(dir_a_str,"AUCTIONS/%03d",a_count);
    sprintf(f_start_a,"AUCTIONS/%03d/START_%03d.txt", a_count, a_count);
    sprintf(f_asset_str, "AUCTIONS/%03d/%s", a_count, fname);
    sprintf(bids_dir, "AUCTIONS/%03d/BIDS",a_count);

    mkdir(dir_a_str,0777);
    mkdir(bids_dir, 0777);
    f_asset = open(f_asset_str, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if(f_asset == -1){
        if(v) fprintf(stderr, "Something went wrong\n");
        remove(f_asset_str);
        rmdir(bids_dir);
        rmdir(dir_a_str);
        write(fd, "ROA ERR\n", 8);
        return;
    }

    while(bytes_read < f_size){
        n = read(fd, buffer, sizeof(buffer));
        if(n<=0){
            if(v) fprintf(stderr, "Something went wrong\n");
            close(f_asset);
            remove(f_asset_str);
            rmdir(bids_dir);
            rmdir(dir_a_str);
            write(fd, "ROA ERR\n", 8);
            return;
        }
        bytes_read += n;
        if(bytes_read<f_size){
            write(f_asset,buffer, n);
        }
        else{
            if(bytes_read > f_size){
                if(buffer[n-(bytes_read-f_size)] == '\n'){
                   write(f_asset,buffer, n-(bytes_read-f_size)); 
                }
                else {
                    if(v) fprintf(stderr, "Something went wrong\n");
                    close(f_asset);
                    remove(f_asset_str);
                    rmdir(bids_dir);
                    rmdir(dir_a_str);
                    write(fd, "ROA ERR\n", 8);
                    return;
                }
            }
            else if(bytes_read == f_size){
                write(f_asset,buffer, n);
                n = read(fd, buffer, sizeof(buffer));
                if(n != 1 || buffer[0] != '\n'){
                    if(v) fprintf(stderr, "Something went wrong\n");
                    close(f_asset);
                    remove(f_asset_str);
                    rmdir(bids_dir);
                    rmdir(dir_a_str);
                    write(fd, "ROA ERR\n", 8);
                    return;
                }
            }
            else{
                if(v) fprintf(stderr, "Something went wrong\n");
                close(f_asset);
                remove(f_asset_str);
                rmdir(bids_dir);
                rmdir(dir_a_str);
                write(fd, "ROA ERR\n", 8);
                return;
            }
        }
    }
    close(f_asset);
    f = open(f_start_a, O_WRONLY | O_TRUNC | O_CREAT, 0666);
    sprintf(start_content, "%s %s %s %s %s %ld ", uid, aname, fname, value_str, timeactive_str, (long)difftime(time(NULL),0));
    write(f, start_content, strlen(start_content));
    close(f);
    sprintf(f_start_a,"USERS/%s/HOSTED/%03d.txt", uid, a_count);
    f = open(f_start_a, O_WRONLY | O_TRUNC | O_CREAT, 0666);
    close(f);
    sprintf(response, "ROA OK %03d\n", a_count);
    write(fd, response, strlen(response));
    if(v) fprintf(stderr, "Successfully opened asset with aid %03d [HOSTED BY USER WITH UID : %s]\n", a_count, uid);
}

void sa(int fd){
    char aid_str[4], buffer[2048], aname[MAX_ANAME+1], fname[MAX_FNAME+1], fsize_str[8], start_as[35], asset_f_str[50];
    int n, aid, f_as, first = 1, x;
    FILE *f_get_size, *f_st;
    long f_size, wrote = 0;

    fd_set read_fds;
    struct timeval timeout;

    // Set the timeout to 5 seconds
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    // Initialize the file descriptor set
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    int ready = select(fd + 1, &read_fds, NULL, NULL, &timeout);

    if(v) fprintf(stderr, "Received a request to show asset ...\n");

    memset(aid_str, 0, sizeof(aid_str));
    n = read(fd, aid_str, 3);
    if (n != 3){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RSA ERR\n",4);
        return;
    }
    for(int i = 0; i<3; i++){
        if(aid_str[i] < '0' || aid_str[i] > '9'){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "RSA ERR\n",4);
            return;
        }
    }
    sscanf(aid_str, "%d", &aid);
    set_a_count();
    if (aid > a_count){
        if(v) fprintf(stderr, "Auction does not exist\n");
        write(fd,"RSA NOK\n", 8);
        return;
    }
    sprintf(start_as, "AUCTIONS/%03d/START_%03d.txt", aid, aid);

    f_st = fopen(start_as,"r");
    fscanf(f_st, "%*s %s %s", aname, fname);
    fclose(f_st);

    sprintf(asset_f_str, "AUCTIONS/%03d/%s",aid, fname);
    f_get_size = fopen(asset_f_str, "r");
    f_size = getFileSize(f_get_size);
    fclose(f_get_size);
    memset(buffer,0,sizeof(buffer));
    sprintf(buffer,"RSA OK ");
    write(fd, buffer, strlen(buffer));
    memset(buffer,0,sizeof(buffer));
    sprintf(buffer,"%s %ld ", fname, f_size);
    f_as = open(asset_f_str, O_RDONLY);
    while(wrote < f_size){
        if(first){
            x = strlen(buffer);
            n = read(f_as, buffer+x, sizeof(buffer)-x);
            wrote += n;
            if(wrote == f_size && n+x<sizeof(buffer)){
                buffer[n+x] = '\n';
                n = write(fd, buffer, n+x+1);
                if (n == -1){
                    if(v) fprintf(stderr, "Something went wrong\n");
                    close(f_as);
                    return;
                }
                wrote ++;
                close(f_as);
                read(fd, buffer, 1);
                if(v) fprintf(stderr, "Successfully showed asset with aid %03d\n", aid);
                return;
            }
        }
        else{
            n = read(f_as, buffer, sizeof(buffer));
            wrote += n;
        }
        if(wrote == f_size && n<sizeof(buffer)){
            buffer[n] = '\n';
            n = write(fd, buffer, n+1);
            if (n == -1){
                if(v) fprintf(stderr, "Something went wrong\n");
                close(f_as);
                return;
            }
            wrote++;
        }
        else{
            if(first){
                n = write(fd, buffer, n+x);
            }
            else
                n = write(fd, buffer, n);
            if (n == -1){
                if(v) fprintf(stderr, "Something went wrong\n");
                close(f_as);
                return;
            }
        }
        first = 0;
    }
    if(wrote == f_size){
        n = write(fd, "\n", 1);
        if (n == -1){
            if(v) fprintf(stderr, "Something went wrong\n");
            close(f_as);
            return;
        }
    }
    read(fd, buffer, 1);
    close(f_as);
    if(v) fprintf(stderr, "Successfully showed asset with aid %03d\n", aid);
}

int check_active(long end_time){
    time_t current_time;

    current_time = time(NULL);

    if(current_time > end_time){
        return 0;
    }
    return 1;
}

void end_auc(int aid, long time_ended){
    char end_f_str[40];
    long end_t;
    FILE *f;
    sprintf(end_f_str,"AUCTIONS/%03d/END_%03d.txt", aid, aid);
    if(!time_ended)
        end_t = (long)difftime(time(NULL),0);
    else
        end_t = time_ended;
    f = fopen(end_f_str,"w");
    fprintf(f,"%ld ", end_t);
    fclose(f);
}

void close_a(int fd){
    int n, f_asset, f, val, aid;
    char buffer[2048], uid[7], pass[9], fname[MAX_FNAME+1], aname[MAX_ANAME+1], value_str[MAX_VALUE+1], f_size_str[7], timeactive_str[MAX_TIME+1],
    f_asset_str[MAX_FNAME+15], dir_a_str[20], f_start_a[35], bids_dir[25], response[20], start_content[256], aid_str[4], uid_owner[7], end_f_str[40];
    long time_act, start_time;
    FILE *f_start;

    if(v) fprintf(stderr, "Received a request to close an auction ...\n");

    memset(uid,0,sizeof(uid));
    n = read(fd,uid,6);
    if(n != 6){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RCL ERR\n", 8);
        return;
    }
    if(!verify_uid(uid)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RCL ERR\n", 8);
        return;
    }

    if(next_not_space(fd)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RCL ERR\n", 8);
        return;
    }
    memset(pass, 0, sizeof(pass));
    n = read(fd,pass,8);
    if(n != 8){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RCL ERR\n", 8);
        return;
    }
    if(!verify_pass(pass)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RCL ERR\n", 8);
        return;
    }
    if(next_not_space(fd)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RCL ERR\n", 8);
        return;
    }
    if(!correct_password(uid,pass)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RCL ERR\n", 8);
        return;
    }
    if(!user_logged_in(uid)){
        if(v) fprintf(stderr, "User was not logged in\n");
        write(fd, "RCL NLG\n", 8);
        return;
    }
    
    n = read(fd,aid_str,3);

    for(int i=0; i<3;i++){
        if(aid_str[i]>'9' || aid_str[i]<'0'){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "RCL ERR\n", 8);
            return;
        }
    }

    sscanf(aid_str,"%d",&aid);
    set_a_count();
    if(aid>a_count){
        if(v) fprintf(stderr, "Auction does not exist\n");
        write(fd, "RCL EAU\n", 8);
        return;
    }

    sprintf(f_start_a,"AUCTIONS/%03d/START_%03d.txt",aid,aid);

    f_start = fopen(f_start_a,"r");
    fscanf(f_start, "%s", uid_owner);
    if(strcmp(uid_owner,uid)){
        if(v) fprintf(stderr, "Auction is not hosted by user that send request\n");
        write(fd, "RCL EOW\n", 8);
        return;
    }
    sprintf(end_f_str,"AUCTIONS/%03d/END_%03d.txt", aid, aid);
    f = open(end_f_str, O_RDONLY);
    if(f != -1){
        if(v) fprintf(stderr, "Auction has already ended\n");
        write(fd, "RCL END\n",8);
        return;
    }
    close(f);
    fscanf(f_start, "%*s %*s %*s %ld %ld", &time_act, &start_time);
    if(!check_active(time_act+start_time)){
        end_auc(aid, time_act+start_time);
        write(fd, "RCL END\n",8);
        if(v) fprintf(stderr, "Auction has already ended\n");
        return;
    }
    end_auc(aid,0);
    write(fd, "RCL OK\n",7);
    if(v) fprintf(stderr, "Auction has been successfully closed\n");
}

void check_a(int aid){
    char f_start_a[40];
    long time_act, start_time;
    FILE *f;
    sprintf(f_start_a,"AUCTIONS/%03d/START_%03d.txt",aid,aid);
    f = fopen(f_start_a,"r");
    if(!f) exit(1);
    fscanf(f, "%*s %*s %*s %*s %ld %ld", &time_act, &start_time);
    if(!check_active(start_time+time_act)){
        end_auc(aid, time_act+start_time);
    }
}

void bid(int fd){
    int n, f_asset, val, aid, start_val, n_entries, max_bid = 0, f;
    char buffer[2048], uid[7], pass[9],dirname[40], val_str[7],
    f_asset_str[MAX_FNAME+15], dir_a_str[20], f_start_a[35], bids_dir[25], response[20], start_content[256], aid_str[4], uid_owner[7], end_f_str[40];
    long time_act, start_time;
    FILE *f_start, *file;
    struct dirent **filelist;

    if(v) fprintf(stderr, "Received a request to place a bid ...\n");

    memset(uid,0,sizeof(uid));
    n = read(fd,uid,6);
    if(n != 6){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RBD ERR\n", 8);
        return;
    }
    if(!verify_uid(uid)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RBD ERR\n", 8);
        return;
    }

    if(next_not_space(fd)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RBD ERR\n", 8);
        return;
    }
    memset(pass, 0, sizeof(pass));
    n = read(fd,pass,8);
    if(n != 8){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RBD ERR\n", 8);
        return;
    }
    if(!verify_pass(pass)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RBD ERR\n", 8);
        return;
    }
    if(next_not_space(fd)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RBD ERR\n", 8);
        return;
    }
    if(!correct_password(uid,pass)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RBD ERR\n", 8);
        return;
    }
    if(!user_logged_in(uid)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RBD NLG\n", 8);
        return;
    }
    
    n = read(fd,aid_str,3);

    for(int i=0; i<3;i++){
        if(aid_str[i]>'9' || aid_str[i]<'0'){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "RBD ERR\n", 8);
            return;
        }
    }
    if(next_not_space(fd)){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RBD ERR\n", 8);
        return;
    }
    n = read(fd, buffer, sizeof(buffer));
    if(n>7 || n<2){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RBD ERR\n", 8);
        return;
    }
    if(buffer[n-1] != '\n'){
        if(v) fprintf(stderr, "Something went wrong\n");
        write(fd, "RBD ERR\n", 8);
        return;
    }
    buffer[n-1] = '\0';
    for(int i = 0; i<n-1; i++){
        if(buffer[i] > '9' || buffer[i] < '0'){
            if(v) fprintf(stderr, "Something went wrong\n");
            write(fd, "RBD ERR\n", 8);
            return;
        }
    }
    sscanf(buffer, "%d", &val);

    sscanf(aid_str,"%d",&aid);
    set_a_count();
    if(aid>a_count){
        if(v) fprintf(stderr, "Auction does not exist\n");
        write(fd, "RBD NOK\n", 8);
        return;
    }


    sprintf(f_start_a,"AUCTIONS/%03d/START_%03d.txt",aid,aid);

    f_start = fopen(f_start_a,"r");
    fscanf(f_start, "%s", uid_owner);
    if(!strcmp(uid_owner,uid)){
        if(v) fprintf(stderr, "User was not logged in\n");
        write(fd, "RBD ILG\n", 8);
        return;
    }
    check_a(aid);
    sprintf(end_f_str,"AUCTIONS/%03d/END_%03d.txt", aid, aid);
    f = open(end_f_str, O_RDONLY);
    if(f != -1){
        close(f);
        if(v) fprintf(stderr, "Auction has already been closed\n");
        write(fd, "RBD NOK\n",8);
        return;
    }
    fscanf(f_start, " %*s %*s %d", &start_val);
    fclose(f_start);
    if(val < start_val){
        if(v) fprintf(stderr, "Bid refused, amount is lower than start value\n");
        write(fd, "RBD REF\n",8);
        return;
    }

    sprintf(dirname ,"AUCTIONS/%03d/BIDS/",aid);
    n_entries = scandir(dirname, &filelist , 0, alphasort);
    while(n_entries--){
        if(strlen(filelist[n_entries]->d_name) == 10 && !max_bid){
            memset(val_str, 0, sizeof(val_str));
            memcpy(val_str, filelist[n_entries]->d_name, 6);
            sscanf(val_str, "%d", &max_bid);
        }
        free(filelist[n_entries]);
    }
    free(filelist);

    if(val <= max_bid){
        if(v) fprintf(stderr, "Bid refused, amount is lower than previous bid\n");
        write(fd, "RBD REF\n",8);
        return;
    }

    memset(buffer,0,sizeof(buffer));
    sprintf(buffer, "USERS/%s/BIDDED/%03d.txt", uid,aid);
    file = fopen(buffer, "w");
    fclose(file);

    memset(buffer,0,sizeof(buffer));
    sprintf(buffer, "AUCTIONS/%03d/BIDS/%06d.txt", aid, val);
    file = fopen(buffer, "w");
    fprintf(file, "%s %d %ld", uid, val, (long)time(NULL));
    fclose(file);
    n = write(fd, "RBD ACC\n", 8);
    if(n == 8){
        if(v) fprintf(stderr, "Bid by user with uid %s was accepted [AUCTION - %03d, value - %d]\n",uid,aid,val);
    }
    else{
        if(v) fprintf(stderr, "Something went wrong\n");
    }
}

void handle_tcp(char *PORT){
    int fd,errcode, newfd;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in addr;
    char command[4];
    pid_t pid;


    fd=socket(AF_INET,SOCK_STREAM,0); //TCP socket
    if (fd==-1) 
        exit(1); //error
    memset(&hints,0,sizeof hints);
    hints.ai_family=AF_INET; //IPv4
    hints.ai_socktype=SOCK_STREAM; //TCP socket
    hints.ai_flags=AI_PASSIVE;
    errcode=getaddrinfo(NULL,PORT,&hints,&res);
    if((errcode)!=0)/*error*/exit(1);
    n=bind(fd,res->ai_addr,res->ai_addrlen);
    if(n==-1)
        exit(1);
    if(listen(fd,5)==-1)
        exit(1);
    addrlen=sizeof(addr);

    while(1){
        if((newfd=accept(fd,(struct sockaddr*)&addr,&addrlen))==-1){
            if(errno == EINTR) continue;
            perror("accept");
            exit(1);
        }
        pid = fork();
        if(pid == 0){
            close(fd);
            n=read(newfd,command,sizeof(command));
            if(n==-1)
                exit(1);
            if(n == 4){
                if(!memcmp(command, "OPA ",4)){
                    open_a(newfd);
                }
                else if(!memcmp(command, "SAS ",4)){
                    sa(newfd);
                }
                else if(!memcmp(command, "CLS ",4)){
                    close_a(newfd);
                }
                else if(!memcmp(command, "BID ",4)){
                    bid(newfd);
                }
                else{
                    write(newfd, "ERR\n",4);
                }
            }
            else{
                write(newfd, "ERR\n",4);
            }
            close(newfd);
            exit(0);
        }
        else{
            close(newfd);
        }
    }
    freeaddrinfo(res);
    close(fd);
}

void my_auc(char *buffer, int fd, socklen_t addrlen, struct sockaddr_in addr){
    char message[7000], uid[7], aid_str[4], aid_info[10];
    int n, aid, f, count, active;
    char dirname[40];
    int n_entries, none = 1;
    struct dirent **filelist;

    if(v) fprintf(stderr, "Received a request to list auctions that user hosts ...\n");

    if(buffer[6] != '\n'){
        if(v) fprintf(stderr, "Something went wrong\n");
        memcpy(message,"RMA ERR\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    memset(uid,0,sizeof(uid));
    memcpy(uid,buffer,6);
    if(!verify_uid(uid)){
        if(v) fprintf(stderr, "Something went wrong\n");
        memcpy(message,"RMA ERR\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    if(!user_logged_in(uid)){
        if(v) fprintf(stderr, "User was not logged in\n");
        memcpy(message,"RMA NLG\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    sprintf(dirname ,"USERS/%s/HOSTED/",uid);
    n_entries = scandir(dirname, &filelist , 0, alphasort);
    n = 0;
    memset(message, 0, sizeof(message));
    for(int i = 0; i < n_entries; i++){
        if(strlen(filelist[i]->d_name) == 7){
            memset(aid_str,0,sizeof(aid_str));
            memcpy(aid_str, filelist[i]->d_name, 3);
            sscanf(aid_str, "%d", &aid);
            check_a(aid);
            sprintf(dirname, "AUCTIONS/%03d/END_%03d.txt", aid, aid);
            f = open(dirname, O_RDONLY);
            if(f == -1)
                active = 1;
            else{
                active = 0;
                close(f);
            }
            if(none){
                memcpy(message,"RMA OK ",7);
                count = 7;
                none = 0;
            }
            if(active){
                sprintf(aid_info,"%03d 1 ", aid);
            }
            else{
                sprintf(aid_info,"%03d 0 ", aid);
            }
            memcpy(message+count,aid_info,strlen(aid_info));
            count += strlen(aid_info);
        }
        free(filelist[i]);
    }
    free(filelist);
    if(none){
        if(v) fprintf(stderr, "User has not hosted any auctions\n");
        memcpy(message,"RMA NOK\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    message[count-1] = '\n';
    n=sendto(fd,message,count,0,
    (struct sockaddr*)&addr,addrlen);
    if(n == -1){
        if(v) fprintf(stderr, "Something went wrong\n");
    }
    else{
        if(v) fprintf(stderr, "List of auctions hosted by user with uid %s was sent\n", uid);
    }
}

void my_bids(char *buffer, int fd, socklen_t addrlen, struct sockaddr_in addr){
    char message[7000], uid[7], aid_str[4], aid_info[10];
    int n, aid, f, count, active;
    char dirname[40];
    int n_entries, none = 1;
    struct dirent **filelist;

    if(v) fprintf(stderr, "Received a request to list auctions where user has placed bids ...\n");

    if(buffer[6] != '\n'){
        if(v) fprintf(stderr, "Something went wrong\n");
        memcpy(message,"RMB ERR\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    memset(uid,0,sizeof(uid));
    memcpy(uid,buffer,6);
    if(!verify_uid(uid)){
        if(v) fprintf(stderr, "Something went wrong\n");
        memcpy(message,"RMB ERR\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    if(!user_logged_in(uid)){
        if(v) fprintf(stderr, "User was not logged in\n");
        memcpy(message,"RMB NLG\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    sprintf(dirname ,"USERS/%s/BIDDED/",uid);
    n_entries = scandir(dirname, &filelist , 0, alphasort);
    n = 0;
    memset(message, 0, sizeof(message));
    for(int i = 0; i < n_entries; i++){
        if(strlen(filelist[i]->d_name) == 7){
            memset(aid_str,0,sizeof(aid_str));
            memcpy(aid_str, filelist[i]->d_name, 3);
            sscanf(aid_str, "%d", &aid);
            check_a(aid);
            sprintf(dirname, "AUCTIONS/%03d/END_%03d.txt", aid, aid);
            f = open(dirname, O_RDONLY);
            if(f == -1)
                active = 1;
            else{
                active = 0;
                close(f);
            }
            if(none){
                memcpy(message,"RMB OK ",7);
                count = 7;
                none = 0;
            }
            if(active){
                sprintf(aid_info,"%03d 1 ", aid);
            }
            else{
                sprintf(aid_info,"%03d 0 ", aid);
            }
            memcpy(message+count,aid_info,strlen(aid_info));
            count += strlen(aid_info);
        }
        free(filelist[i]);
    }
    free(filelist);
    if(none){
        if(v) fprintf(stderr, "User has not placed any bids on auctions\n");
        memcpy(message,"RMB NOK\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    message[count-1] = '\n';
    n=sendto(fd,message,count,0,
    (struct sockaddr*)&addr,addrlen);
    if(n == -1){
        if(v) fprintf(stderr, "Something went wrong\n");
    }
    else{
        if(v) fprintf(stderr, "List of auctions sent to user with uid - %s\n", uid);
    }
}



void list(int fd, socklen_t addrlen, struct sockaddr_in addr){
    char message[7000], aid_info[15];
    int n, f, count, active;
    char dirname[40];
    int none = 1;

    if(v) fprintf(stderr, "Received a request to list the auctions ...\n");
    set_a_count();
    if(a_count == 0){
        if(v) fprintf(stderr, "There is no auctions yet\n");
        memcpy(message,"RLS NOK\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    memset(message, 0, sizeof(message));
    for(int i = 1; i <= a_count; i++){
        check_a(i);
        sprintf(dirname, "AUCTIONS/%03d/END_%03d.txt", i, i);
        f = open(dirname, O_RDONLY);
        if(f == -1)
            active = 1;
        else{
            active = 0;
            close(f);
        }
        if(none){
            memcpy(message,"RLS OK ",7);
            count = 7;
            none = 0;
        }
        if(active){
            sprintf(aid_info,"%03d 1 ", i);
        }
        else{
            sprintf(aid_info,"%03d 0 ", i);
        }
        memcpy(message+count,aid_info,strlen(aid_info));
        count += strlen(aid_info);
        
    }
    message[count-1] = '\n';
    n=sendto(fd,message,count,0,
    (struct sockaddr*)&addr,addrlen);
    if(n == -1){
        if(v) fprintf(stderr, "Something went wrong\n");
    }
    else{
        if(v) fprintf(stderr, "List of auctions sent\n");
    }
}

void trans_time(char *str, long timestamp){
    struct tm *tm_info = localtime(&timestamp);
    if (tm_info != NULL) {
        // Format and print the date and time
        str[19] = '\0';
        sprintf(str,"%04d-%02d-%02d %02d:%02d:%02d",
               tm_info->tm_year + 1900,  // Year since 1900
               tm_info->tm_mon + 1,      // Month (0-11, so add 1)
               tm_info->tm_mday,         // Day of the month
               tm_info->tm_hour,         // Hour
               tm_info->tm_min,          // Minutes
               tm_info->tm_sec);         // Seconds
    } else {
        // Handle the case where conversion failed
        printf("Error converting timestamp to date and time\n");
    }
}


void sr(char *buffer, int fd, socklen_t addrlen, struct sockaddr_in addr){
    char message[7000], uid[7], aid_str[4], bid_info[50], f_str[60], a_name[MAX_ANAME+1], a_f_name[MAX_FNAME+1], time_str[20];
    int n, aid, f, count, active, time_act, start_val, bids = 0;
    char dirname[40];
    int n_entries, none = 1, value;
    long start_time, bid_time;
    struct dirent **filelist;
    FILE *file;
    if(v) fprintf(stderr, "Received show record request ...\n");
    if(buffer[3] != '\n'){
        if(v) fprintf(stderr, "Something went wrong\n");
        memcpy(message,"RRC ERR\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    memset(aid_str,0,sizeof(aid_str));
    memcpy(aid_str,buffer,3);
    for(int i = 0; i<3;i++){
        if(aid_str[i] < '0' || aid_str[i] > '9'){
            if(v) fprintf(stderr, "Something went wrong\n");
            memcpy(message,"RRC ERR\n",8);
            n=sendto(fd,message,8,0,
            (struct sockaddr*)&addr,addrlen);
            return;
        }
    }
    sscanf(aid_str,"%d", &aid);
    set_a_count();
    if(aid > a_count){
        if(v) fprintf(stderr, "Requested auction does not exist\n");
        memcpy(message,"RRC NOK\n",8);
        n=sendto(fd,message,8,0,
        (struct sockaddr*)&addr,addrlen);
        return;
    }
    sprintf(f_str, "AUCTIONS/%03d/START_%03d.txt",aid, aid);
    file = fopen(f_str,"r");
    fscanf(file, "%s %s %s %d %d %ld", uid, a_name, a_f_name, &start_val, &time_act, &start_time);
    fclose(file);

    sprintf(dirname ,"AUCTIONS/%03d/BIDS/",aid);
    n_entries = scandir(dirname, &filelist , 0, alphasort);
    n = 0;
    memset(message, 0, sizeof(message));
    bids = 0;
    trans_time(time_str, start_time);
    sprintf(message, "RRC OK %s %s %s %d %s %d ", uid, a_name, a_f_name, start_val, time_str, time_act);
    count = strlen(message);
    check_a(aid);
    while(n_entries--){
        if(strlen(filelist[n_entries]->d_name) == 10 && bids <50){
            bids += 1;
            sprintf(f_str,"AUCTIONS/%03d/BIDS/%s",aid, filelist[n_entries]->d_name);
            file = fopen(f_str, "r");
            fscanf(file, "%s %d %ld", uid, &value, &bid_time);
            fclose(file);
            trans_time(time_str, bid_time);
            sprintf(bid_info, "B %s %d %s %ld ", uid, value, time_str, bid_time-start_time);
            memcpy(message+count,bid_info,strlen(bid_info));
            count += strlen(bid_info);
        }
        free(filelist[n_entries]);
    }
    free(filelist);
    sprintf(dirname, "AUCTIONS/%03d/END_%03d.txt", aid, aid);
    f = open(dirname, O_RDONLY);
    if(f == -1){
        message[count-1] = '\n';
        n=sendto(fd,message,count,0,
        (struct sockaddr*)&addr,addrlen);
        if(v) fprintf(stderr, "Sended the record of the auction %03d with success\n",aid);
        return;
    }
    close(f);
    file = fopen(dirname,"r");
    fscanf(file,"%ld",&bid_time);
    trans_time(time_str, bid_time);
    sprintf(bid_info,"E %s %ld\n",time_str, bid_time-start_time);
    memcpy(message+count,bid_info,strlen(bid_info));
    count += strlen(bid_info);
    n=sendto(fd,message,count,0,(struct sockaddr*)&addr,addrlen);
    if(n == -1){
        if(v) fprintf(stderr, "Something went wrong\n");
    }
    else{
        if(v) fprintf(stderr, "Sended the record of the auction %03d with success\n",aid);
    }
}


int main(int argc, char **argv){

    int fd,errcode;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints,*res;
    struct sockaddr_in addr;
    char buffer[256];
    pid_t pid;

    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigaction(SIGCHLD, &sa, NULL);

    char *PORT = NULL, c;

    for(size_t i = 1; i < argc; i ++){
        if(!strcmp(argv[i], "-p")){
            i++;
            PORT = malloc(strlen(argv[i])+1);
            strcpy(PORT, argv[i]);
        }
        else if(!strcmp(argv[i], "-v")){
            v = 1;
        }
    }
    if(!PORT){
        PORT = malloc(strlen("58013")+1);
        strcpy(PORT, "58013");
    }


    set_a_count();


    pid = fork();

    if(pid == 0){
        handle_tcp(PORT);
        return 0;
    }

    fd=socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(fd==-1)/*error*/
        exit(1);

    memset(&hints,0,sizeof hints);
    hints.ai_family=AF_INET; // IPv4
    hints.ai_socktype=SOCK_DGRAM; // UDP socket
    hints.ai_flags=AI_PASSIVE;
    errcode=getaddrinfo(NULL,PORT,&hints,&res);
    if(errcode!=0) /*error*/
        exit(1);

    n=bind(fd,res->ai_addr, res->ai_addrlen);
    if(n==-1) /*error*/
        exit(1);

    addrlen=sizeof(addr);

    while (1){
        memset(buffer, 0, sizeof(buffer));
        n=recvfrom(fd,buffer,sizeof(buffer),0,(struct sockaddr*)&addr,&addrlen);
        if(n==-1)
            exit(1);

        if(n == 20){
            if(!memcmp(buffer,"LIN ",4)){
                login(buffer+4,fd, addrlen, addr);
            }
            else if(!memcmp(buffer,"LOU ",4)){
                logout(buffer+4,fd, addrlen, addr);
            }
            else if(!memcmp(buffer,"UNR ",4)){
                unreg(buffer+4,fd, addrlen, addr);
            }
            else{
                memcpy(buffer,"ERR\n",4);
                n=sendto(fd,buffer,4,0,
                (struct sockaddr*)&addr,addrlen);
            }
        }
        else if(n == 11){
            if(!memcmp(buffer, "LMA ", 4)){
                my_auc(buffer+4, fd, addrlen, addr);
            }
            else if(!memcmp(buffer, "LMB ",4)){
                my_bids(buffer+4, fd, addrlen, addr);
            }
            else{
                memcpy(buffer,"ERR\n",4);
                n=sendto(fd,buffer,4,0,
                (struct sockaddr*)&addr,addrlen);
            }
        }
        else if(n == 8){
            if(!memcmp(buffer, "SRC ",4)){
                sr(buffer+4, fd, addrlen, addr);
            }
            else{
                memcpy(buffer,"ERR\n",4);
                n=sendto(fd,buffer,4,0,
                (struct sockaddr*)&addr,addrlen);
            }
        }
        else if(n == 4){
            if(!memcmp(buffer,"LST\n",4)){
                list(fd, addrlen,addr);
            }
            else{
                memcpy(buffer,"ERR\n",4);
                n=sendto(fd,buffer,4,0,
                (struct sockaddr*)&addr,addrlen);
            }
        }
        else{
            memcpy(buffer,"ERR\n",4);
            n=sendto(fd,buffer,4,0,
            (struct sockaddr*)&addr,addrlen);
        }
    }

    freeaddrinfo(res);
    close(fd);
}