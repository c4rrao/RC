#include "commands.hpp"

extern sys_var sv;


int start_udp() {
    // UDP SOCKET
    sv.UDP.fd=socket(AF_INET,SOCK_DGRAM,0); //UDP socket
    if(sv.UDP.fd == -1) {
        STATUS("Could not create socket [UDP]")
        return -1;
    }

    memset(&sv.UDP.hints, 0, sizeof sv.UDP.hints);
    sv.UDP.hints.ai_family=AF_INET; //IPv4
    sv.UDP.hints.ai_socktype=SOCK_DGRAM; //UDP socket

    sv.UDP.errcode=getaddrinfo( sv.ASIP.c_str(), sv.ASport.c_str() ,&sv.UDP.hints,&sv.UDP.res);
    if(sv.UDP.errcode!=0) {
        STATUS("Could not get address info [UDP]")
        return -1;
    }

    sv.UDP.active = 1;

    return 0;
}

int end_udp() {
    // Close UDP
    if (close(sv.UDP.fd) == -1) {
        MSG("Something went wrong.")
        STATUS("Could not close [UDP]")
        freeaddrinfo(sv.UDP.res);
        sv.UDP.active=0;
        return -1;
    }

    sv.UDP.active=0;

    freeaddrinfo(sv.UDP.res);
    return 0;

}

int start_tcp() {
    // TCP SOCKET
    sv.TCP.fd=socket(AF_INET,SOCK_STREAM,0); //TCP socket
    if(sv.TCP.fd == -1) {
        STATUS("Could not create socket [TCP]")
        return -1;
    }

    memset(&sv.TCP.hints, 0, sizeof sv.TCP.hints);
    sv.TCP.hints.ai_family=AF_INET; //IPv4
    sv.TCP.hints.ai_socktype=SOCK_STREAM; //TCP socket

    sv.TCP.errcode=getaddrinfo( sv.ASIP.c_str(), sv.ASport.c_str() ,&sv.TCP.hints,&sv.TCP.res);
    if(sv.TCP.errcode!=0) {
        STATUS("Could not get address info [TCP]")
        return -1;
    }

    sv.TCP.addrlen=sizeof(sv.TCP.addr);

    // Connect to TCP
    if (connect(sv.TCP.fd, sv.TCP.res->ai_addr, sv.TCP.res->ai_addrlen) == -1) {
        MSG("Something went wrong.")
        STATUS("Could not connect [TCP]")
        return -1;
    }

    sv.TCP.active=1;

    return 0;
}

int end_tcp() {
    // Close to TCP
    if (close(sv.TCP.fd) == -1) {
        MSG("Something went wrong.")
        STATUS("Could not close [TCP]")
        freeaddrinfo(sv.TCP.res);
        sv.TCP.active=0;
        return -1;
    }

    freeaddrinfo(sv.TCP.res);
    sv.TCP.active = 0;
    return 0;
}

void sig_handler(int signo) {
    if (signo == SIGINT || signo == SIGTERM) {
        if (sv.UDP.active){
            end_udp();
        }
        else if (sv.TCP.active){
            end_tcp();
        }
        sv.to_exit = true;
        STATUS("Exiting safely...")
        exit(EXIT_FAILURE);
    }
}

string get_unique_fname(string fname){
    if (!ifstream(fname)) return fname;
    string stem,extension;
    int n = 1;
    string fname_old = fname;
    int f=0;

    size_t lastDotPos = fname.find_last_of('.');
    if (lastDotPos != string::npos) {
        stem = fname.substr(0, lastDotPos);
        extension = fname.substr(lastDotPos);
        fname = stem + "(" + to_string(n) + ")" + extension;
    } else {
        //no extension
        f = 1;
        fname += " (" + to_string(n) + ")";
    }

    STATUS_WA("%s already exists. Trying %s", fname_old.c_str(),fname.c_str());

    while(ifstream(fname)){
        int n_pos;
        for (n_pos = fname.length() - 1; n_pos >= 0; n_pos--) {
            if (fname[n_pos] == '(') {
                n_pos++;
                break;
            }
        }

        fname_old = fname;
        if (f==1){
            fname = fname.substr(0, n_pos) + to_string(++n) + ")";
        }
        else {
            fname = fname.substr(0, n_pos) + to_string(++n) + ")" + extension;
        }

        STATUS_WA("%s already exists. Trying %s", fname_old.c_str(), fname.c_str());
    }

    return fname;
}

int read_timer(int fd) {
    /* Set up the file descriptor set for select */
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(fd, &readSet);

    /* Set up the timeout */
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SECONDS;
    timeout.tv_usec = 0;
    
    /* Use select to wait for data or timeout */
    int status = select(fd + 1, &readSet, NULL, NULL, &timeout);

    if (status == -1) {
        STATUS("Error in select.")
        return -1;
    } else if (status == 0) {
        STATUS("Timeout occurred. No data received.")
        return -1;
    }

    return 0;
}

int cmd_login(istringstream &cmdstream) {
    string UID, pass;

    if (sv.UID != NO_USER){
        MSG("You are already logged in.")
        return -1;
    }
    
    if ( !(cmdstream >> UID) ){
        MSG("UID not specified.")
        return -1;
    }

    if (!is_valid_UID(UID)) {
        MSG("UID is not correctly formatted.")
        return -1;
    }

    if (!(cmdstream >> pass)){
        MSG("Password is not specified.")
        return -1;
    }

    if (!is_valid_pass(pass)) {
        MSG("Password is not correctly formatted.")
        return -1;
    }

    if (!cmdstream.eof()) {
        MSG("Too many arguments.")
        return -1;
    }

    string sbuff = "LIN " + UID + " " + pass + "\n";

    if(sendto(sv.UDP.fd, sbuff.c_str(), sbuff.length(), 0, sv.UDP.res->ai_addr, 
                sv.UDP.res->ai_addrlen) == -1) {
        MSG("Something went wrong.")
        STATUS("Could not send login message")
        return -1;
    }
    STATUS_WA("Login message sent: %s", sbuff.c_str())

    // Reply

    //memset(sv.UDP.buffer,0,128);

    if (read_timer(sv.UDP.fd) == -1) {
        MSG("Something went wrong.")
        return -1;
    }

    // sv.UDP.addrlen=sizeof(sv.UDP.addr);

    size_t n = recvfrom(sv.UDP.fd,sv.UDP.buffer,BUFFER_SIZE,0,(struct sockaddr*) &sv.UDP.addr,&sv.UDP.addrlen);
    if(n <= 0) {
        MSG("Something went wrong.")
        if (n == -1) STATUS("Could not receive login reply.")
        else STATUS("Login reply is empty.")
        return -1;
    }
    
    // Retirar o \n no final e colocar \0
    if (sv.UDP.buffer[n-1] == '\n')
        sv.UDP.buffer[n-1] = '\0';
    else {
        MSG("Something went wrong.")
        STATUS("No newline at the end of the message.")
        return -1;
    }

    STATUS_WA("Login reply received: %s", sv.UDP.buffer);

    istringstream reply(string(sv.UDP.buffer));

    string opcode;
    if (!(reply >> opcode)) {
        MSG("Something went wrong.")
        STATUS("Can't comprehend server's reply: no opcode.")
        return -1;
    }
    
    if (opcode == "RLI") {
        string status;
        if (!(reply >> status)) {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply: no status.")
            return -1;
        }
        
        if (status == "OK"  || status == "REG") {
            sv.UID=UID;
            sv.pass=pass;
            if (status == "REG") MSG("Registration was successful. Logged in.")
            else MSG("Login was successful.")
        }
        else if (status == "NOK") MSG("The password is wrong. Try again.")
        else {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply.")
            return -1;
        }
    }
    else {
        MSG("Something went wrong.")
        if (opcode == "ERR") STATUS("Wrong syntax or parameters with invalid values.")
        else STATUS("Can't comprehend server's reply.")
        return -1;
    }

    return 0;
}

int cmd_logout() {
    if (sv.UID == NO_USER) {
        MSG("You are not logged in.")
        return -1;
    }
    STATUS("User is logged in.")

    string sbuff = "LOU " + sv.UID + " " + sv.pass + "\n";

    if(sendto(sv.UDP.fd, sbuff.c_str(), sbuff.length(), 0, sv.UDP.res->ai_addr, sv.UDP.res->ai_addrlen) == -1) {
        MSG("Something went wrong.")
        STATUS("Could not send logout message")
        return -1;
    }
    STATUS_WA("Logout message sent: %s", sbuff.c_str())

    //memset(sv.UDP.buffer,0,128);


    if (read_timer(sv.UDP.fd) == -1) {
        MSG("Something went wrong.")
        return -1;
    }

    // sv.UDP.addrlen=sizeof(sv.UDP.addr);
    size_t n = recvfrom(sv.UDP.fd,sv.UDP.buffer,BUFFER_SIZE,0,(struct sockaddr*) &sv.UDP.addr,&sv.UDP.addrlen);
    if(n <= 0) {
        MSG("Something went wrong.")
        if (n == -1) STATUS("Could not receive logout reply.")
        else STATUS("Logout reply is empty.")
        return -1;
    }

    // Retirar o \n no final e colocar \0
    if (sv.UDP.buffer[n-1] == '\n')
        sv.UDP.buffer[n-1] = '\0';
    else {
        MSG("Something went wrong.")
        STATUS("No newline at the end of the message.")
        return -1;
    }

    STATUS_WA("Logout reply received: %s", sv.UDP.buffer);

    istringstream reply(string(sv.UDP.buffer));

    string opcode;
    if (!(reply >> opcode)) {
        MSG("Something went wrong.")
        STATUS("Can't comprehend server's reply: no opcode.")
        return -1;
    }
    
    if (opcode == "RLO") {
        string status;

        if (!(reply >> status)) {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply: no status.")
            return -1;
        }
        
        if (status == "OK") {
            sv.UID = NO_USER;
            sv.pass = NO_PASS;
            MSG("Successful logout.")
        }
        else if (status == "NOK") MSG("User not logged in.")
        else if (status == "UNR") MSG("Unknown user.")
        else {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply: status not reconizable.")
            return -1;
        }
    }
    else {
        MSG("Something went wrong.")
        if (opcode == "ERR") STATUS("Wrong syntax or parameters with invalid values.")
        else STATUS("Can't comprehend server's reply.")
        return -1;
    }
 
    return 0;
}

int cmd_unregister() {

    if (sv.UID == NO_USER) {
        MSG("You are not logged in.")
        return -1;
    }

    string sbuff = "UNR " + sv.UID + " " + sv.pass + "\n";

    if(sendto(sv.UDP.fd, sbuff.c_str(), sbuff.length(), 0, sv.UDP.res->ai_addr, sv.UDP.res->ai_addrlen) == -1) {
        MSG("Something went wrong.")
        STATUS("Could not send unregister message.")
        return -1;
    }
    STATUS_WA("Unregister message sent: %s", sbuff.c_str())

    //memset(sv.UDP.buffer,0,128);
    
    if (read_timer(sv.UDP.fd) == -1) {
        MSG("Something went wrong.")
        return -1;
    }

    //sv.UDP.addrlen=sizeof(sv.UDP.addr);
    size_t n = recvfrom(sv.UDP.fd,sv.UDP.buffer,BUFFER_SIZE,0,(struct sockaddr*) &sv.UDP.addr,&sv.UDP.addrlen);
    if(n <= 0) {
        MSG("Something went wrong.")
        if (n == -1) STATUS("Could not receive unregister reply.")
        else STATUS("Unregister reply is empty.")
        return -1;
    }

    // Retirar o \n no final e colocar \0
    if (sv.UDP.buffer[n-1] == '\n')
        sv.UDP.buffer[n-1] = '\0';
    else {
        MSG("Something went wrong.")
        STATUS("No newline at the end of the message.")
        return -1;
    }

    STATUS_WA("Unregister reply received: %s", sv.UDP.buffer);

    istringstream reply(string(sv.UDP.buffer));

    string opcode;
    if (!(reply >> opcode)) {
        MSG("Something went wrong.")
        STATUS("Can't comprehend server's reply: no opcode.")
        return -1;
    }

    if (opcode == "RUR") {
        string status;

        if (!(reply >> status)) {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply: no status.")
            return -1;
        }
        
        if (status == "OK") {
            sv.UID = NO_USER;
            sv.pass = NO_PASS;
            MSG("Unregister was successful. You're now logged out.")
        }
        else if (status == "NOK") MSG("User not logged in.")
        else if (status == "UNR") {
            sv.UID = NO_USER;
            sv.pass = NO_PASS;
            MSG("Incorrect unregister attempt: your user is no longer registered. You will be logged out.")
        } 
        else {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply: status not reconizable.")
            return -1;
        }
    }
    else {
        MSG("Something went wrong.")
        if (opcode == "ERR") STATUS("Wrong syntax or parameters with invalid values.")
        else STATUS("Can't comprehend server's reply.")
        return -1;
    }
    
    return 0;
}

int cmd_exit() {
    if (sv.UID!=NO_USER){
        MSG("You need to logout before exiting the program.")
        return -1;
    }

    MSG("Exiting program...")
    sv.to_exit = 1;

    return 0;
}

int cmd_open(istringstream &cmdstream) {
    string name, asset_fname;
    int start_value, timeactive;

    if (sv.UID == NO_USER) {
        MSG("You are not logged in.")
        return -1;
    }

    if ( !(cmdstream >> name) ){
        MSG("Name is not specified.")
        return -1;
    }

    if (!is_valid_auction_name(name)) {
        MSG("Auction name is not correctly formatted")
        return -1;
    }

    if ( !(cmdstream >> asset_fname) ){
        MSG("Asset filename is not specified.")
        return -1;
    }

    if (!is_valid_fname(asset_fname)) {
        MSG("Asset filename is not valid.")
        return -1;
    }

    if ( !(cmdstream >> start_value) ){
        MSG("Start_value is not a valid integer.")
        return -1;
    }

    if (!is_valid_bid_value(start_value)){
        MSG("Start_value is not valid")
        return -1;
    }

    if ( !(cmdstream >> timeactive)){
        MSG("Timeactive is not a valid integer.")
        return -1;
    }

    if (!is_valid_timeactive(timeactive)){
        MSG_WA("Timeactive is not valid. (Max time is %d)", MAX_TIME_ACTIVE);
    }

    if (!cmdstream.eof()) {
        MSG("Too many arguments.")
        return -1;
    }

    // Request
    string sbuff = "OPA " + sv.UID + " " + sv.pass + " " + name + " " 
                    + to_string(start_value) + " " + to_string(timeactive) + " "
                    + asset_fname + " ";
    
    ifstream fasset(asset_fname, ios::in | ios::ate | ios::binary);

    if (fasset.is_open()) {
        size_t size = fasset.tellg();

        if (!is_valid_fsize(size)) {
            MSG_WA("Asset file is too big (> %d) bytes", FILE_MAX_SIZE)
            return -1;
        }
        
        STATUS_WA("Asset file size: %ld", size)

        sbuff += to_string(size) + " ";

        fasset.seekg(0, ios::beg);
        
        // read BUFFER_SIZE bytes of file to TCP.buffer and send it
        fasset.read(sv.TCP.buffer, BUFFER_SIZE - sbuff.length());
        if ((fasset.fail() || fasset.bad()) && !fasset.eof()) {
            MSG("Something went wrong.")
            STATUS("Could not read asset file")
            return -1;
        }

        size_t total_read = fasset.gcount();
        sv.TCP.buffer[fasset.gcount()] = '\0';
        sbuff += sv.TCP.buffer;

        STATUS_WA("Open message sent (if too big, 1st %d bytes): %s", 90,
                    sbuff.substr(0, min(90, static_cast<int>(sbuff.length()))).c_str())

        while(total_read < size) {
            size_t n = write(sv.TCP.fd, sbuff.c_str(), sbuff.length());
            if (n != sbuff.length()) {
                MSG("Something went wrong.")
                STATUS("Could not send open message")
                return -1;
            }

            fasset.read(sv.TCP.buffer, BUFFER_SIZE);
            if ((fasset.fail() || fasset.bad()) && !fasset.eof()) {
                MSG("Something went wrong.")
                STATUS("Could not read asset file")
                return -1;
            }

            sv.TCP.buffer[fasset.gcount()] = '\0';
            sbuff = string(sv.TCP.buffer);
            total_read += fasset.gcount();
        }

        if (sbuff.length() < BUFFER_SIZE) {
            sbuff += "\n";
        }

        size_t n = write(sv.TCP.fd, sbuff.c_str(), sbuff.length());
        if (n != sbuff.length()) {
            MSG("Something went wrong.")
            STATUS("Could not send open message")
            return -1;
        }

        if (sbuff.length() == BUFFER_SIZE) {
            sbuff = "\n";
            n = write(sv.TCP.fd, sbuff.c_str(), sbuff.length());
            if (n != sbuff.length()) {
                MSG("Something went wrong.")
                STATUS("Could not send open message")
                return -1;
            }
        }
    }
    else {
        MSG("Could not open asset file.")
        return -1;
    }

    // Reply
    // Read till AS closes socket
    sv.TCP.buffer[0] = '\0';
    size_t n, old_n = 0;

    memset(sv.TCP.buffer,0,BUFFER_SIZE + 1);
    if (read_timer(sv.TCP.fd) == -1) {
        MSG("Something went wrong.")
        return -1;
    }
    n = read(sv.TCP.fd,sv.TCP.buffer, BUFFER_SIZE);

    if (n==-1){
        MSG("Something went wrong.")
        STATUS("Could not receive open reply.")
        return -1;
    }

    if(n==0){
        MSG("Something went wrong.")
        STATUS("Open reply is empty.")
        return -1;
    }

    int len = strlen(sv.TCP.buffer);
    if (sv.TCP.buffer[len-1] == '\n')
        sv.TCP.buffer[len-1] = '\0';
    else {
        MSG("Something went wrong.")
        STATUS("No newline at the end of the message.")
        return -1;
    }

    STATUS_WA("Open reply received: %s", sv.TCP.buffer);

    istringstream reply(string(sv.TCP.buffer));
    
    string opcode;
    if (!(reply >> opcode)) {
        MSG("Something went wrong.")
        STATUS("Can't comprehend server's reply: no opcode.")
        return -1;
    }
    
    if (opcode == "ROA") {
        string status;

        if (!(reply >> status)) {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply: no status.")
            return -1;
        }

        if (status == "OK") {
            string AID;

            if (!(reply >> AID)) {
                MSG("Something went wrong.")
                STATUS("Can't comprehend server's reply: no AID.")
                return -1;
            }
            
            if (!is_valid_AID(AID)) {
                MSG("Something went wrong.")
                STATUS("Can't comprehend server's reply: AID not valid")
                return -1;
            }


            if (!cmdstream.eof()) {
                MSG("Too many arguments.")
                return -1;
            }

            MSG_WA("Auction %s was successfully started.", AID.c_str())
        }
        else if (status == "NOK") MSG("Auction can't be started.")
        else if (status == "NLG") {
            MSG("You are not logged in.")
            STATUS("NOT SUPPOSED TO HAPPEN!!!")
        }
        else {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply.")
            return -1;
        }
    }
    else {
        MSG("Something went wrong.")
        if (opcode == "ERR") STATUS("Wrong syntax or parameters with invalid values.")
        else STATUS("Can't comprehend server's reply.")
        return -1;
    }

    return 0;
}

int cmd_close(istringstream &cmdstream){

    string AID;

    if (sv.UID == NO_USER) {
        MSG("You are not logged in.")
        return -1;
    }


    if (!(cmdstream >> AID) ){
        MSG("AID not specified.")
        return -1;
    }

    if (!(is_valid_AID(AID))) {
        MSG("AID is not correctly formatted.")
        return -1;
    }

    if (!cmdstream.eof()) {
        MSG("Too many arguments.")
        return -1;
    }
    string sbuff = "CLS " + sv.UID + " " + sv.pass + " " + AID + "\n";
    size_t n = write(sv.TCP.fd, sbuff.c_str(), sbuff.length());

    if (n != sbuff.length()) {
        MSG("Something went wrong.")
        STATUS("Could not send close request.")
        return -1;
    }
    STATUS_WA("Close message sent: %s", sbuff.c_str())

    memset(sv.TCP.buffer,0,BUFFER_SIZE + 1);

    
    n = read(sv.TCP.fd, sv.TCP.buffer,BUFFER_SIZE);

    if (n==-1){
        MSG("Something went wrong.")
        STATUS("Could not receive close reply.")
        return -1;
    }

    if (n==0){
        MSG("Something went wrong.")
        STATUS("Close reply is empty.")
        return -1;
    }

    int len = strlen(sv.TCP.buffer);

    // Retirar o \n no final e colocar \0
    if (sv.TCP.buffer[len-1] == '\n')
        sv.TCP.buffer[len-1] = '\0';
    else {
        MSG("Something went wrong.")
        STATUS("No newline at the end of the message.")
        return -1;
    }

    STATUS_WA("Close reply received: %s", sv.TCP.buffer);

    istringstream reply(string(sv.TCP.buffer));

    string opcode;
    if (!(reply >> opcode)){
        MSG("Something went wrong.")
        STATUS("Can't comprehend server's reply: no opcode.")
        return -1;
    }

    if ( opcode == "RCL"){
        string status;

        if (!(reply >> status)) {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply: no status.")
            return -1;
        }

        if (status == "OK") MSG("Close was successful.")
        else if (status == "NLG") MSG("You are not logged in.")
        else if (status == "EAU") MSG_WA("Auction %s does not exist.", AID.c_str())
        else if (status == "EOW") MSG_WA("You are not the owner of %s auction.",AID.c_str())
        else if (status == "END") MSG_WA("Auction %s has already finished.", AID.c_str())
        else {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply.")
            return -1;
        }
    }
    else {
        MSG("Something went wrong.")
        if (opcode == "ERR") STATUS("Wrong syntax or parameters with invalid values.")
        else STATUS("Can't comprehend server's reply.")
        return -1;
    }

    return 0;

}

int cmd_myauctions(){
    if (sv.UID == NO_USER){
        MSG("You are not logged in.")
        return -1;
    }

    string sbuff = "LMA " + sv.UID + "\n";

    if(sendto(sv.UDP.fd, sbuff.c_str(), sbuff.length(), 0, sv.UDP.res->ai_addr, 
                sv.UDP.res->ai_addrlen) == -1) {
        MSG("Couldn't get your auctions.")
        STATUS("Could not send my auctions message")
        return -1;
    }
    STATUS_WA("Myauction message sent: %s", sbuff.c_str())

    if (read_timer(sv.UDP.fd) == -1) {
        MSG("Something went wrong.")
        return -1;
    }

    size_t n = recvfrom(sv.UDP.fd,sv.UDP.buffer,BUFFER_SIZE,0,(struct sockaddr*) &sv.UDP.addr,&sv.UDP.addrlen);
    if(n<=0) {
        MSG("Couldn't get your auctions.")
        if (n == -1) STATUS("Could not receive my auction reply")
        else STATUS("My auction reply is empty.") 
        return -1;
    }

    // Retirar o \n no final e colocar \0
    if (sv.UDP.buffer[n-1] == '\n')
        sv.UDP.buffer[n-1] = '\0';
    else {
        MSG("Something went wrong.")
        STATUS("No newline at the end of the message.")
        return -1;
    }

    STATUS_WA("My auctions reply received: %s", sv.UDP.buffer)
    istringstream reply(string(sv.UDP.buffer));


    string opcode;
    if (!(reply >> opcode)){
        MSG("Something went wrong.")
        STATUS("Myauctions reply is empty")
        return -1;
    }

    if (opcode == "RMA") {
        string status;
        if (!(reply >> status)){
            MSG("Something went wrong.")
            STATUS("Myauctions reply status is missing.")
            return -1; 
        }
        if (status == "OK"){
            string AID, state;
            while ((!(reply.eof()))){
                if (!(reply >> AID)){
                    MSG("Something went wrong.")
                    STATUS("Couldn't extract AID.")
                    return -1;
                }

                if (!is_valid_AID(AID)){
                    MSG("Something went wrong.")
                    STATUS("Cant' comprehend server's reply: AID is not valid")
                    return -1;
                }

                if (!(reply>>state)){
                    MSG("Something went wrong.")
                    STATUS("Auction doesn't have a state.")
                    return -1;
                }
                if (!is_valid_state(state)){
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: state is not valid")
                    return -1;
                }
                MSG_WA("Auction: %s | Active: %s", AID.c_str(), (state == "0") ? "No" : "Yes")
            }
        }
        else if (status == "NOK") MSG("You have no ongoing auctions.")
        else if (status == "NLG") MSG("You are not logged in.")
        else {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply.")
            return -1;
        }
    }
    else {
        MSG("Something went wrong.")
        if (opcode == "ERR") STATUS("Wrong syntax or parameters with invalid values.")
        else STATUS("Can't comprehend server's reply.")
        return -1;
    }

    return 0;

}

int cmd_mybids(){

    if (sv.UID == NO_USER){
        MSG("You are not logged in.")
        return -1;
    }

    string sbuff = "LMB " + sv.UID + "\n";

    if(sendto(sv.UDP.fd, sbuff.c_str(), sbuff.length(), 0, sv.UDP.res->ai_addr, 
                sv.UDP.res->ai_addrlen) == -1) {
        MSG("Couldn't get your bids.")
        STATUS("Could not send my bids message")
        return -1;
    }
    STATUS_WA("Mybids message sent: %s", sbuff.c_str())

    if (read_timer(sv.UDP.fd) == -1) {
        MSG("Something went wrong.")
        return -1;
    }

    size_t n = recvfrom(sv.UDP.fd,sv.UDP.buffer,BUFFER_SIZE,0,(struct sockaddr*) &sv.UDP.addr,&sv.UDP.addrlen);
    if(n<=0) {
        MSG("Couldn't get your bids.")
        if (n == -1) STATUS("Could not receive my bids reply")
        else STATUS("My bids reply is empty.")
        return -1;
    }

    // Retirar o \n no final e colocar \0
    if (sv.UDP.buffer[n-1] == '\n')
        sv.UDP.buffer[n-1] = '\0';
    else {
        MSG("Something went wrong.")
        STATUS("No newline at the end of the message.")
        return -1;
    }

    STATUS_WA("My bids reply received: %s", sv.UDP.buffer)

    istringstream reply(string(sv.UDP.buffer));

    string opcode;
    if (!(reply >> opcode)){
        MSG("Something went wrong.")
        STATUS("My bids reply is empty")
        return -1;
    }

    if (opcode == "RMB"){
        string status;
        if (!(reply >> status)){
            MSG("Something went wrong.")
            STATUS("Mybids reply status is missing.")
            return -1;
        }

        if (status == "OK"){
            string AID, state;
            while ((!(reply.eof()))){
                if (!(reply >> AID)){
                    MSG("Something went wrong.")
                    STATUS("Couldn't extract AID.")
                    return -1;
                }

                if (!is_valid_AID(AID)){
                    MSG("Something went wrong.")
                    STATUS("Cant' comprehend server's reply: AID is not valid")
                    return -1;
                }
                if (!(reply>>state)){
                    MSG("Something went wrong.")
                    STATUS("Auction doesn't have a state.")
                    return -1;
                }
                if (!is_valid_state(state)){
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: state is not valid")
                    return -1;
                }
                MSG_WA("Auction: %s | Active: %s", AID.c_str(), (state == "0") ? "No" : "Yes")
            }
        }
        else if (status == "NOK") MSG("You have no ongoing bids.")
        else if (status == "NLG") MSG("You are not logged in.")
        else {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply.")
            return -1;
        }
    }
    else {
        MSG("Something went wrong.")
        if (opcode == "ERR") STATUS("Wrong syntax or parameters with invalid values.")
        else STATUS("Can't comprehend server's reply.")
        return -1;
    }

    return 0;

}

int cmd_list(){
    // if (sv.UID == NO_USER){
    //     MSG("You are not logged in.")
    //     return -1;
    // }

    string sbuff = "LST\n";

    if(sendto(sv.UDP.fd, sbuff.c_str(), sbuff.length(), 0, sv.UDP.res->ai_addr, 
                sv.UDP.res->ai_addrlen) == -1) {
        MSG("Couldn't auction listing.")
        STATUS("Could not send list message")
        return -1;
    }
    STATUS_WA("List message sent: %s", sbuff.c_str())

    if (read_timer(sv.UDP.fd) == -1) {
        MSG("Something went wrong.")
        return -1;
    }

    size_t n = recvfrom(sv.UDP.fd,sv.UDP.buffer,BUFFER_SIZE,0,(struct sockaddr*) &sv.UDP.addr,&sv.UDP.addrlen);
    if(n<=0) {
        MSG("Couldn't get auction listing.")
        if (n == -1) STATUS("Could not receive list reply")
        else STATUS("List reply is empty.")
        return -1;
    }

    // Retirar o \n no final e colocar \0
    if (sv.UDP.buffer[n-1] == '\n')
        sv.UDP.buffer[n-1] = '\0';
    else {
        MSG("Something went wrong.")
        STATUS("No newline at the end of the message.")
        return -1;
    }

    STATUS_WA("List reply received: %s", sv.UDP.buffer)

    istringstream reply(string(sv.UDP.buffer));

    string opcode;
    if (!(reply >> opcode)){
        MSG("Something went wrong")
        STATUS("List reply is empty")
        return -1;
    }

    if (opcode == "RLS"){
        string status;
        if (!(reply >> status)){
            MSG("Something went wrong.")
            STATUS("Mybids reply status is missing.")
            return -1;
        }
        if (status == "OK"){
            string AID, state;
            while ((!(reply.eof()))){
                if (!(reply >> AID)){
                    MSG("Something went wrong.")
                    STATUS("Couldn't extract AID.")
                    return -1;
                }

                if (!is_valid_AID(AID)){
                    MSG("Something went wrong.")
                    STATUS("Cant' comprehend server's reply: AID is not valid")
                    return -1;
                }

                if (!(reply>>state)){
                    MSG("Something went wrong.")
                    STATUS("Auction doesn't have a state.")
                    return -1;
                }
                if (!is_valid_state(state)){
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: state is not valid")
                    return -1;
                }
                MSG_WA("Auction: %s | Active: %s", AID.c_str(), (state == "0") ? "No" : "Yes")
            }
        }
        else if (status == "NOK") MSG("There is no ongoing auctions.")
        else {
                MSG("Something went wrong.")
                STATUS("Can't comprehend server's reply.")
                return -1;
            }
    }
    else {
        MSG("Something went wrong.")
        if (opcode == "ERR") STATUS("Wrong syntax or parameters with invalid values.")
        else STATUS("Can't comprehend server's reply.")
        return -1;
    }

    return 0;

}

int cmd_show_asset(istringstream &cmdstream){
    string AID;

    if (!(cmdstream >> AID) ){
        MSG("AID not specified.")
        return -1;
    }

    if (!(is_valid_AID(AID))){
        MSG("AID is not correctly formatted.")
        return -1;
    }

    if (!cmdstream.eof()) {
        MSG("Too many arguments.")
        return -1;
    }

    string sbuff = "SAS " +  AID + "\n";
    size_t n = write(sv.TCP.fd, sbuff.c_str(), sbuff.length());

    if (n != sbuff.length()) {
        MSG("Something went wrong.")
        STATUS("Could not send show asset request.")
        return -1;
    }
    STATUS_WA("Show_asset message sent: %s", sbuff.substr(0, sbuff.length() - 1).c_str())

    memset(sv.TCP.buffer,0,BUFFER_SIZE+1);
    //le a primeira vez
    if (read_timer(sv.TCP.fd)==-1) {
        MSG("Something went wrong.")
        return -1;
    }
    n = read(sv.TCP.fd,sv.TCP.buffer,BUFFER_SIZE);
    //erro a ler
    if (n == -1) {
        MSG("Something went wrong.")
        STATUS("Could not receive show asset reply.")
        return -1;
    }
    //nao ha resposta
    if (n == 0) {
        MSG("Something went wrong.")
        STATUS("Empty reply.")
        return -1;
    }

    string buff = string(sv.TCP.buffer);
    istringstream reply(buff);
    int bytesToRemove=0;

    //analisar a primeira parte do pedido
    string opcode;
    if (!(reply >> opcode)){
        MSG("Something went wrong.")
        STATUS("Can't comprehend server's reply: no opcode.")
        return -1;
    }
    if (opcode == "RSA"){
        string status;

        bytesToRemove+=4;

        if (!(reply >> status)) {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply: no status.")
            return -1;
        }

        //continuar a ler a reply
        if (status=="OK"){
            string fname, fdata;
            int fsize;

            bytesToRemove+=3;

            if (!(reply >> fname)){
                MSG("Something went wrong.")
                STATUS("Can't comprehend server's reply: no fname.")
                return -1;
            }

            if (!is_valid_fname(fname)){
                MSG("Something went wrong.")
                STATUS("Not valid fname.")
                return -1;
            }

            bytesToRemove+= fname.length()+1;

            if (!(reply >> fsize)){
                MSG("Something went wrong.")
                STATUS("Can't comprehend server's reply: no fsize or fsize is not an int")
                return -1;
            }

            if (!(is_valid_fsize(fsize))){
                MSG("Something went wrong.")
                STATUS("Not valid fsize.")
                return -1;
            }

            bytesToRemove += to_string(fsize).length()+1;
            int bytes_written = 0;

            fname = get_unique_fname(ASSETS_DIR + fname);


            char tempBuf[BUFFER_SIZE+1];
            memset(tempBuf,0,BUFFER_SIZE+1);
            memcpy(tempBuf,sv.TCP.buffer+bytesToRemove,BUFFER_SIZE+1-bytesToRemove);
            tempBuf[n-bytesToRemove] = '\0';

            FILE *file = fopen(fname.c_str(), "wb");
            if (file == NULL) {
                MSG("Something went wrong.")
                STATUS("Could not open asset file.")
                return -1; // Return an error code
            }

            size_t old_n = n-bytesToRemove;
            while (1){
                memset(sv.TCP.buffer,0,BUFFER_SIZE+1);

                if (read_timer(sv.TCP.fd)==-1) {
                    MSG("Something went wrong.")
                    return -1;
                }
                n = read(sv.TCP.fd,sv.TCP.buffer,BUFFER_SIZE);
                if (n==0) break;
                if(n==-1){
                    MSG("Something went wrong.")
                    STATUS("Could not receive show asset reply.")
                    fclose(file);
                    return -1;
                }

                size_t elements_written = fwrite(tempBuf,1,old_n,file);
                bytes_written += elements_written;

                memset(tempBuf,0,BUFFER_SIZE+1);
                memcpy(tempBuf,sv.TCP.buffer,BUFFER_SIZE+1);
                old_n = n;
            }

            //write da ultima porçao do pedido


            if (tempBuf[old_n-1]=='\n'){
                tempBuf[old_n-1] = '\0';
            }
            else {
                MSG("Something went wrong.")
                STATUS("No newline at the end of the message.")
                fclose(file);
                return -1;
            }

            size_t elements_written = fwrite(tempBuf,1,old_n-1,file);
            bytes_written += elements_written;

            STATUS_WA("Bytes_written: %d\t\tfsize: %d", bytes_written,fsize);

            fclose(file);

            STATUS_WA("There were written %d bytes to asset file", bytes_written);

            if (bytes_written!=fsize){
                MSG("Something went wrong.")
                STATUS("Bytes written to asset file != fsize")
                return -1;
            }

            string short_fname;
            for (int i = fname.length() - 1; i >= 0; i--) {
                if (fname[i] == '/') {
                    short_fname = fname.substr(i + 1);
                    break;
                }
            }

            MSG_WA("Asset file was successfully saved as \"%s\" in the \"%s\" directory.", short_fname.c_str(), ASSETS_DIR)
        }
        else if (status == "NOK") MSG("There is no file or some other problems.")
        else {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply.")
            return -1;
        }
    }
    else {
        MSG("Something went wrong.")
        if (opcode == "ERR") STATUS("Wrong syntax or parameters with invalid values.")
        else STATUS("Can't comprehend server's reply.")
        return -1;
    }
    
    return 0;
}

int cmd_bid(istringstream &cmdstream){
    string AID;
    int value;


    if (sv.UID == NO_USER) {
        MSG("You are not logged in.")
        return -1;
    }

    if (!(cmdstream>>AID)){
        MSG("AID is not specified.")
        return -1;
    }

    if (!is_valid_AID(AID)){
        MSG("AID is not correctly formatted.")
        return -1;
    }

    if (!(cmdstream>>value)){
        MSG("Value is not a valid integer.")
        return -1;
    }

    if (!is_valid_bid_value(value)) {
        MSG("Value is too big (> 999999).")
        return -1;
    }

    if (!cmdstream.eof()) {
        MSG("Too many arguments.")
        return -1;
    }

    string sbuff = "BID " + sv.UID + " " + sv.pass + " " + AID + " " + 
                    to_string(value) + "\n";

    size_t n = write(sv.TCP.fd, sbuff.c_str(), sbuff.length());
    if (n != sbuff.length()) {
        MSG("Something went wrong.")
        STATUS("Could not send bid request")
        return -1;
    }

    STATUS_WA("Bid message sent: %s", sbuff.c_str())

    memset(sv.TCP.buffer,0,BUFFER_SIZE+1);

    

    n = read(sv.TCP.fd, sv.TCP.buffer, BUFFER_SIZE);

    if (n == 0) {
        MSG("Something went wrong.")
        STATUS("Bid reply is empty.")
        return -1;
    }

    if (n == -1) {
        MSG("Something went wrong.")
        STATUS("Could not receive show asset reply.")
        return -1;
    }

    int len = strlen(sv.TCP.buffer);

    STATUS_WA("Bid reply received: \"%s\"", sv.TCP.buffer)

    // Retirar o \n no final e colocar \0
    if (sv.TCP.buffer[len-1] == '\n')
        sv.TCP.buffer[len-1] = '\0';
    else {
        MSG("Something went wrong.")
        STATUS("No newline at the end of the message.")
        return -1;
    }

    STATUS_WA("Bid reply received: %s", sv.TCP.buffer);

    istringstream reply(string(sv.TCP.buffer));

    string opcode;
    if (!(reply >> opcode)){
        MSG("Something went wrong.")
        STATUS("Can't comprehend server's reply: no opcode.")
        return -1;
    }

    if ( opcode == "RBD"){
        string status;

        if (!(reply >> status)) {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply: no status.")
            return -1;
        }

        if (status == "OK") MSG("Bid was accepted.")
        else if (status == "NOK") MSG("Auction is not active or doesn't exist.")
        else if (status == "NLG") MSG("You are not logged in.")
        else if (status == "ACC") MSG("Your bid was accepted.")
        else if (status == "REF") MSG("Your bid is smaller than the current bid value.")
        else if (status == "ILG") MSG("You can't bid on your own auction.")
        else{
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply.")
            return -1;
        }

    }
    else {
        MSG("Something went wrong.")
        if (opcode == "ERR") STATUS("Wrong syntax or parameters with invalid values.")
        else STATUS("Can't comprehend server's reply.")
        return -1;
    }

    return 0;
    
}

int cmd_show_record(istringstream &cmdstream){
    string AID;

    if (!(cmdstream>>AID)){
        MSG("AID is not specified.")
        return -1;
    }

    if (!is_valid_AID(AID)){
        MSG("AID is not correctly formatted.")
        return -1;
    }

    if (!cmdstream.eof()) {
        MSG("Too many arguments.")
        return -1;
    }

    string sbuff = "SRC " + AID + "\n";

    if(sendto(sv.UDP.fd, sbuff.c_str(), sbuff.length(), 0, sv.UDP.res->ai_addr, 
                sv.UDP.res->ai_addrlen) == -1) {
        MSG("Something went wrong.")
        STATUS("Could not send show_record message")
        return -1;
    }
    STATUS_WA("Show_record message sent: %s", sbuff.c_str())

    if (read_timer(sv.UDP.fd) == -1) {
        MSG("Something went wrong.")
        return -1;
    }

    size_t n = recvfrom(sv.UDP.fd,sv.UDP.buffer,BUFFER_SIZE,0,(struct sockaddr*) &sv.UDP.addr,&sv.UDP.addrlen);
    if(n <= 0) {
        MSG("Something went wrong.")
        if (n == -1) STATUS("Could not receive show record reply.")
        else STATUS("Show record reply is empty.")
        return -1;
    }

    // Retirar o \n no final e colocar \0
    if (sv.UDP.buffer[n-1] == '\n')
        sv.UDP.buffer[n-1] = '\0';
    else {
        MSG("Something went wrong.")
        STATUS("No newline at the end of the message.")
        return -1;
    }

    STATUS_WA("Show_record reply received: %s", sv.UDP.buffer);

    istringstream reply(string(sv.UDP.buffer));

    string opcode;
    if (!(reply >> opcode)) {
        MSG("Something went wrong.")
        STATUS("Can't comprehend server's reply: no opcode.")
        return -1;
    }

    if (opcode == "RRC"){
        string status;
        if (!(reply >> status)) {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply: no status.")
            return -1;
        }
        if (status == "OK"){
            string host_UID,auction_name,asset_fname, start_date, start_time, start_date_time;
            int start_value, timeactive;

            if (!(reply >> host_UID)) {
                MSG("Something went wrong.")
                STATUS("Can't comprehend server's reply: no host UID.")
                return -1;
            }

            if (!is_valid_UID(host_UID)){
                MSG("Something went wrong.")
                STATUS("Host UID is not a valid UID.")
                return -1;
            }

            if (!(reply >> auction_name)) {
                MSG("Something went wrong.")
                STATUS("Can't comprehend server's reply: no auction name.")
                return -1;
            }

            if (!is_valid_auction_name(auction_name)){
                MSG("Something went wrong.")
                STATUS("Auction name is not valid.")
                return -1;
            }

            if (!(reply >> asset_fname)) {
                MSG("Something went wrong.")
                STATUS("Can't comprehend server's reply: no asset file name.")
                return -1;
            }

            if (!is_valid_fname(asset_fname)){
                MSG("Something went wrong.")
                STATUS("Auction name is not valid.")
                return -1;
            }

            if (!(reply >> start_value)) {
                MSG("Something went wrong.")
                STATUS("Can't comprehend server's reply: no start value or start value is not an int.")
                return -1;
            }

            if (!is_valid_bid_value(start_value)){
                MSG("Something went wrong.")
                STATUS("Auction name is not valid.")
                return -1;
            }
            
            if (!(reply >> start_date >> start_time)){
                MSG("Something went wrong.")
                STATUS("Can't comprehend server's reply: no start date and time")
                return -1;
            }

            start_date_time = start_date + " " + start_time;
            if (!is_valid_date_time(start_date_time)){
                MSG("Something went wrong.")
                STATUS("Start date_time is not valid.")
                return -1;
            }

            if (!(reply >> timeactive)) {
                MSG("Something went wrong.")
                STATUS("Can't comprehend server's reply: no start value or time active is not an int.")
                return -1;
            }

            if (!is_valid_timeactive(timeactive)){
                MSG("Something went wrong.")
                STATUS("Time active is not valid.")
                return -1;
            }

            bid bids[MAX_BIDS_SHOWN];

            bool ended = false;
            string end_date_time;
            int end_sec;
            int num_bids;
            for (num_bids = 0 ;; num_bids++) { 
                if (num_bids > MAX_BIDS_SHOWN){
                    MSG("Something went wrong.")
                    STATUS("The number of bids exceeds the max number of bids to show.")
                    return -1;
                }

                if (!(reply >> sbuff)) {
                    if (reply.eof()) break;
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: no info character.")
                    return -1;
                }

                if (sbuff == "E") {
                    ended = true;

                    string end_date, end_time;
                    if (!(reply >> end_date >> end_time)) {
                        MSG("Something went wrong.")
                        STATUS("Can't comprehend server's reply: no end date time.")
                        return -1;
                    }

                    end_date_time = end_date + " " + end_time;
                    if (!is_valid_date_time(end_date_time)){
                        MSG("Something went wrong.")
                        STATUS("End date_time is not valid.")
                        return -1;
                    }



                    if (!(reply >> end_sec)) {
                        MSG("Something went wrong.")
                        STATUS("Can't comprehend server's reply: no end time.")
                        return -1;
                    }

                    STATUS_WA("endtime: %d",end_sec);

                    if (!is_valid_time_seconds(end_sec, timeactive)){
                        MSG("Something went wrong.")
                        STATUS("End time is not valid.")
                        return -1;
                    }

                    if (!reply.eof()) {
                        MSG("Something went wrong.")
                        STATUS("Can't comprehend server's reply: too many arguments.")
                        return -1;
                    }

                    break;
                }
                
                if (sbuff != "B"){
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: ")
                    return -1;
                }
                
                if (!(reply >> bids[num_bids].UID)) {
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: no UID.")
                    return -1;
                }

                if (!is_valid_UID(bids[num_bids].UID)){
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: UID is not valid.")
                    return -1;
                }

                if (!(reply >> bids[num_bids].value)) {
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: no value.")
                    return -1;
                }

                if (!is_valid_bid_value(bids[num_bids].value)){
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: value is too big.")
                    return -1;
                }

                string date_time, clock_time;
                if (!(reply >> date_time >> clock_time)) {
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: no date_time.")
                    return -1;
                }

                bids[num_bids].date_time = date_time + " " + clock_time;
                if (!is_valid_date_time(bids[num_bids].date_time)){
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: date_time is not valid.")
                    return -1;
                }

                int bid_time;
                if (!(reply >> bid_time)) {
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: no end time.")
                    return -1;
                }

                if (!is_valid_time_seconds(bid_time,timeactive)){
                    MSG("Something went wrong.")
                    STATUS("Can't comprehend server's reply: date_time is not valid.")
                    return -1;
                }
                
                bids[num_bids].time = bid_time;
            }
            
            MSG_WA("Auction %s info -------------------------------------------------", AID.c_str())
            MSG_WA("Host: %s\nAuction name: %s\nAsset file name: %s\nStart value: %d\nStart date_time: %s\nTime active: %d sec\n",
                    host_UID.c_str(),auction_name.c_str(), asset_fname.c_str(), start_value, start_date_time.c_str(), timeactive)

            for (int i = 0; i < num_bids; i++) {
                MSG_WA("Biddder: %s | Value: %d | Date: %s | Time elapsed: %d sec", bids[i].UID.c_str(), bids[i].value, bids[i].date_time.c_str(), bids[i].time)
            }

            if (ended) {
                MSG_WA("Auction ended at %s, lasting %d second(s).", end_date_time.c_str(), end_sec)
            }
            else {
                MSG("\nAuction is still active.")
            }
            MSG("-------------------------------------------------------------")
        }
        else if (status == "NOK") MSG_WA("Auction %s does not exist.", AID.c_str())
        else {
            MSG("Something went wrong.")
            STATUS("Can't comprehend server's reply.")
            return -1;
        }
    }
    else {
        MSG("Something went wrong.")
        if (opcode == "ERR") STATUS("Wrong syntax or parameters with invalid values.")
        else STATUS("Can't comprehend server's reply.")
        return -1;
    }

    return 0;
    
}

int processCommand(string full_cmd) {
    
    istringstream cmdstream(full_cmd);
    string word, cmd;
    
    if (!(cmdstream >> cmd)){
        STATUS("invalid command")
        return -1;
    }

    if (cmd=="login") {
        start_udp();

        if (cmd_login(cmdstream) == -1){
            STATUS("invalid login.")
        }

        end_udp();
    }
    else if (cmd == "logout") {
        start_udp();

        if (!cmdstream.eof()) {
            MSG("Too many arguments.")
            return -1;
        }
        if (cmd_logout()==-1){
            STATUS("invalid logout")
        }

        end_udp();
    }

    else if (cmd == "unregister") {
        start_udp();
        
        if (!cmdstream.eof()) {
            MSG("Too many arguments.")
            return -1;
        }
        if (cmd_unregister()==-1){
            STATUS("invalid unregister")
        }

        end_udp();
    }

    else if (cmd == "exit") {
        if (!cmdstream.eof()) {
            MSG("Too many arguments.")
            return -1;
        }
        if (cmd_exit()==-1){
            STATUS("invalid exit")
        }
    }

    else if (cmd == "open") {
        start_tcp();
        
        if (cmd_open(cmdstream)==-1){
            STATUS("invalid open")
        }

        end_tcp();
    }

    else if (cmd == "close") {
        start_tcp();

        if (cmd_close(cmdstream)==-1){
            STATUS("invalid close")
        }

        end_tcp();
    }
    else if (cmd == "myauctions" || cmd == "ma") {
        start_udp();

        if (!cmdstream.eof()) {
            MSG("Too many arguments.")
            return -1;
        }
        
        if (cmd_myauctions()==-1){
            STATUS("invalid myauctions")
            return -1;
        }

        end_udp();
    }
    else if (cmd == "mybids" || cmd == "mb") {
        start_udp();

        if (!cmdstream.eof()) {
            MSG("Too many arguments.")
            return -1;
        }
        if (cmd_mybids()==-1){
            STATUS("invalid mybids")
            return -1;
        }

        end_udp();
    }
    else if (cmd == "list" || cmd == "l") {
        start_udp();

        if (!cmdstream.eof()) {
            MSG("Too many arguments.")
            return -1;
        }
        if (cmd_list()==-1){
            STATUS("invalid list")
            return -1;
        }

        end_udp();
    }
    else if (cmd == "show_asset" || cmd == "sa") {
        start_tcp();

        if (cmd_show_asset(cmdstream)==-1){
            STATUS("invalid show_asset")
        }

        end_tcp();
    }
    else if (cmd == "bid" || cmd == "b") {
        start_tcp();

        if (cmd_bid(cmdstream) == -1) {
            STATUS("invalid bid")
        }

        end_tcp();
    }
    else if (cmd == "show_record" || cmd == "sr") {
        start_udp();

        cmd_show_record(cmdstream);

        end_udp();
    }
    else {
        MSG("Invalid command.")
    }

    
    return 0;
}

