#include "requests.hpp"

extern sys_var sv;

//HOSTED E BIDDED CRIADO QUANDO REGISTAMOS

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

int f_rdlock(string path) {
    int lock_fd = open(path.c_str(), O_RDWR | O_CREAT, 0644);



    if (lock_fd == -1) {
        STATUS("Error opening lock file.");
        return -1;
    }

    if (flock(lock_fd, LOCK_SH) == -1) {
        STATUS("Error locking file.");
        return -1;
    }

    if (close(lock_fd) == -1) {
        STATUS("Error closing lock file.");
        return -1;
    }

    return 0;
}

int f_wrlock(string path) {
    int lock_fd = open(path.c_str(), O_RDWR | O_CREAT, 0644);

    if (lock_fd == -1) {
        STATUS("Error opening lock file.");
        return -1;
    }

    if (flock(lock_fd, LOCK_EX) == -1) {
        STATUS("Error locking file.");
        return -1;
    }

    if (close(lock_fd) == -1) {
        STATUS("Error closing lock file.");
        return -1;
    }

    STATUS("Lock created")

    return 0;
}

int f_unlock(string path) {
    int lock_fd = open(path.c_str(), O_RDWR | O_CREAT, 0644);

    if (lock_fd == -1) {
        STATUS("Error opening lock file.");
        return -1;
    }

    if (flock(lock_fd, LOCK_UN) == -1) {
        STATUS("Error unlocking file.");
        return -1;
    }

    if (close(lock_fd) == -1) {
        STATUS("Error closing lock file.");
        return -1;
    }

    return 0;

}

int update_auction(string AID) {
    std::filesystem::path auction_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID);
    std::filesystem::path auction_dir_lock = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID+".lock");

    if (!std::filesystem::exists(auction_dir)) {
        STATUS("Auction directory does not exist.")
        return -1;
    }

    std::filesystem::path end_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("END_" + AID + ".txt");
    if (std::filesystem::exists(end_auction_file)) {
        STATUS("Auction has already ended.")
        return 0;
    }

    std::filesystem::path start_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("START_" + AID + ".txt");
    if (!std::filesystem::exists(start_auction_file)) {
        STATUS("Start auction file does not exist.")
        return -1;
    }

    ifstream start_stream(start_auction_file);

    if (!(start_stream.is_open())){
        STATUS("Couldn't open start auction file")
        return -1;
    }

    string host_uid,name,asset_fname,start_date, start_time;

    int start_value, timeactive;
    long int start_date_secs;

    if (!(start_stream >> host_uid >> name >> asset_fname >> start_value >> timeactive >> start_date >> start_time >> start_date_secs)){
        STATUS("Something went wrong reading start auction file.")
        return -1;
    }




    //o ficheiro end é criado quando o leilao acaba
    time_t fulltime;
    time(&fulltime);


    if (start_date_secs + timeactive < fulltime) {
        struct tm *current_time;
        char timestr[20];
        current_time = gmtime(&fulltime);

        sprintf(timestr, "%4d-%02d-%02d %02d:%02d:%02d", current_time->tm_year+1900,
            current_time->tm_mon+1, current_time->tm_mday,current_time->tm_hour,
            current_time->tm_min,current_time->tm_sec);

        ofstream end_stream(end_auction_file);

        if (!(end_stream.is_open())){
            STATUS("Couldn't create end auction file")
            return -1;
        }

        end_stream << timestr << " " << timeactive;
    }

    return 0;
}

// UDP
string req_login(istringstream &reqstream){

    string UID, req_pass;
    
    if (!(reqstream >> UID)){
        STATUS("Login request doesn't have UID")
        return "RLI ERR\n";
    }

    if (!is_valid_UID(UID)){
        STATUS("UID is not correctly formatted.")
        return "RLI ERR\n";
    }

    if (!(reqstream >> req_pass)){
        STATUS("Login request doesn't have password.")
        return "RLI ERR\n";
    }

    if (!is_valid_pass(req_pass)) {
        STATUS("Password is not correctly formatted.")
        return "RLI ERR\n";
    }

    if (!reqstream.eof()){
        STATUS("Login request format is incorrect.")
        return "RLI ERR\n";
    }

    std::filesystem::path user_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID);
    std::filesystem::path pass_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_pass.txt");
    std::filesystem::path login_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_login.txt");

    //Registar user;
    //O registo e feito se nao existir a diretoria ou se existir mas nao tem password.
    if(!(std::filesystem::exists(pass_path))){

        if (!(std::filesystem::exists(user_dir))){
            
            std::filesystem::path user_hosted_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(HOSTED_DIR_PATH);
            std::filesystem::path user_bidded_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(BIDDED_DIR_PATH);

            if (!std::filesystem::create_directory(user_dir)){
                STATUS("Failed to create user directory.")
                return "BAD\n";
            }
            if (!std::filesystem::create_directory(user_hosted_dir)){
                STATUS("Failed to create user hosted directory.")
                return "BAD\n";
            }
            if (!std::filesystem::create_directory(user_bidded_dir)){
                STATUS("Failed to create bidded directory.")
                return "BAD\n";
            }
        }

        ofstream pass_stream(pass_path);
        ofstream login_stream(login_path);

        if (!login_stream.is_open()){
            STATUS("Couldn't create a login file.")
            return "BAD\n";
        }

        login_stream.close();

        if (!(pass_stream.is_open())){
            STATUS("Couldn't create password file.")
            return "BAD\n";
        }

        if (!(pass_stream << req_pass)){
            STATUS("Error writing to password file.")
            return "BAD\n";
        }

        pass_stream.close();

        return "RLI REG\n";
    }
    else {
        ifstream pass_stream(pass_path);

        if (!(pass_stream.is_open())){
            STATUS("Couldn't open password file.")
            return "BAD\n";
        }

        string password;
        getline(pass_stream,password); // reply como a pass é alfanumerica, podemos so apanhar a primeira linha?

        if (pass_stream.fail()){
            STATUS("Error reading password file.")
            return "BAD\n";
        }

        pass_stream.close();

        //se o user tiver registado. Checkar se existe um login file. Se não existir criar um e se existir cagar;

        if (req_pass == password){

            //o user nao ta logged in;
            if (!(std::filesystem::exists(login_path))){

                ofstream login_stream(login_path);

                if (!login_stream.is_open()){
                    STATUS("Couldn't create a login file.")
                    login_stream.close();
                    return "BAD\n";
                }

                login_stream.close();

            }

            return "RLI OK\n";
            
        }
        else return "RLI NOK\n";
    }
    
    return "BAD\n";
}

string req_logout(istringstream &reqstream){
    string UID, req_pass;

    if (!(reqstream >> UID)){
        STATUS("Logout request doesn't have UID")
        return "RLO ERR\n";
    }

    if (!is_valid_UID(UID)){
        STATUS("UID is not correctly formatted.")
        return "RLO ERR\n";
    }

    if (!(reqstream >> req_pass)){
        STATUS("Logout request doesn't have password.")
        return "RLO ERR\n";
    }

    if (!is_valid_pass(req_pass)) {
        STATUS("Password is not correctly formatted.")
        return "RLO ERR\n";
    }

    if (!reqstream.eof()){
        STATUS("Logout request format is incorrect.")
        return "RLO ERR\n";
    }
    std::filesystem::path user_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID);
    std::filesystem::path pass_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_pass.txt");
    std::filesystem::path login_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_login.txt");

    //O logout é feito se a diretoria existe,se o login existe, e se a password está correta;
    //Reply no ok, se a password nao existir damos print do que??
    //OK se a diretoria existe, se o login existe, a password existe e está correta;
    //NOK se a diretoria existe, (se o login não existe || login existe e a password está errada)
    //UNR se a diretoria não existe || se a password não existe;
    if(std::filesystem::exists(user_dir) || !(std::filesystem::exists(pass_path))){

        //OK ou NOK
        if (std::filesystem::exists(login_path)){

            ifstream pass_stream(pass_path);

            if (!(pass_stream.is_open())){
                STATUS("Couldn't open password file.")
                return "BAD\n";
            }

            string password;
            getline(pass_stream,password); // reply como a pass é alfanumerica, podemos so apanhar a primeira linha?

            if (pass_stream.fail()){
                STATUS("Error reading password file.")
                return "BAD\n";
            }

            pass_stream.close();

            //faz logout;
            if (req_pass == password){
                
                //apaga login;
                try {std::filesystem::remove(login_path);}
                catch (const std::filesystem::filesystem_error& e) {
                    STATUS("Error deleting login file.")
                    return "BAD\n";
                }

                return "RLO OK\n";

            }
            else return "RLO NOK\n";  //Login existe mas pass errada
        }
        else return "RLO NOK\n";
    }
    else return "RLO UNR\n";

    return "BAD\n";
}

string req_unregister(istringstream &reqstream){
    string UID, req_pass;

    if (!(reqstream >> UID)){
        STATUS("Unregister request doesn't have UID")
        return "RUR ERR\n";
    }

    if (!is_valid_UID(UID)){
        STATUS("UID is not correctly formatted.")
        return "RUR ERR\n";
    }

    if (!(reqstream >> req_pass)){
        STATUS("Unregister request doesn't have password.")
        return "RUR ERR\n";
    }

    if (!is_valid_pass(req_pass)) {
        STATUS("Password is not correctly formatted.")
        return "RUR ERR\n";
    }

    if (!reqstream.eof()){
        STATUS("Unregister request format is incorrect.")
        return "RUR ERR\n";
    }

    std::filesystem::path user_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID);
    std::filesystem::path pass_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_pass.txt");
    std::filesystem::path login_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_login.txt");

    //OK - user_dir existe, login existe e pass está correta
    //NOK - user_dir existe, (se o login não existe || login existe e password está errada) 
    //UNR - user_dir não existe ou password não existe.
    if(std::filesystem::exists(user_dir)){

        //Reply
        //Não estamos a tratar do caso em pass não existe e login existe (o que fazer?)
        //ou seja nao tou a checkar se a passe e o login existem em simultaneo
        //assumo que caso o login exista entao a passe tambem.

        //UNR
        if (!(std::filesystem::exists(pass_path))) return "RUR UNR\n"; 
        //OK ou NOK
        else if (std::filesystem::exists(login_path)){

            ifstream pass_stream(pass_path);

            if (!(pass_stream.is_open())){
                STATUS("Couldn't open password file.")
                pass_stream.close();
                return "BAD\n";
            }

            string password;
            getline(pass_stream,password); // reply como a pass é alfanumerica, podemos so apanhar a primeira linha?

            if (pass_stream.fail()){
                STATUS("Error reading password file.")
                pass_stream.close();
                return "BAD\n";
            }

            pass_stream.close();

            //faz logout;
            if (req_pass == password){

                try {
                    std::filesystem::remove(login_path);
                    std::filesystem::remove(pass_path);
                }
                catch (const std::filesystem::filesystem_error& e) {
                    STATUS("Error deleting file.")
                    return "BAD\n";
                }
                return "RUR OK\n";

            }
            else return "RUR NOK\n";  //Login existe mas pass errada
        }
        else return "RUR NOK\n";
    }
    else return "RUR UNR\n"; //o user não está registado 

    return "BAD\n";
}

string req_myauctions(istringstream &reqstream){

    string UID;

    string reply = "RMA ";
    if (!(reqstream >> UID)){
        STATUS("My auctions request doesn't have UID")
        return "RMA ERR\n";
    }

    if (!is_valid_UID(UID)){
        STATUS("UID is not correctly formatted.")
        return "RMA ERR\n";
    }

    if (!reqstream.eof()){
        STATUS("My auctions request format is incorrect.")
        return "RMA ERR\n";
    }

    std::filesystem::path user_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID);
    std::filesystem::path login_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append((UID + "_login.txt"));
    std::filesystem::path uid_hosted_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(HOSTED_DIR_PATH);

    if (std::filesystem::exists(user_dir)){
        //Checkar login primeiro
        if (!(std::filesystem::exists(login_path))) return "RMA NLG\n";
        else if (!(std::filesystem::exists(uid_hosted_dir)) || std::filesystem::is_empty(uid_hosted_dir)) {
            return "RMA NOK\n";
        }
        else {
            reply += "OK";
            try {
                for (const auto& entry : std::filesystem::directory_iterator(uid_hosted_dir)) {
                    if (std::filesystem::is_regular_file(entry.path())) { // Reply este if é preciso?
                        string AID;
                        AID = entry.path().stem().string();

                        if (!is_valid_AID(AID)){
                            STATUS("Auction file name is not a valid AID.")
                            return "BAD\n";
                        }

                        reply += " " + AID;

                        std::filesystem::path auction_dir_lock = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID+".lock");
                        std::filesystem::path curr_auction_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID);
                        std::filesystem::path end_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("END_" + AID + ".txt");

                        if (update_auction(AID) == -1) {
                            STATUS("Error updating auction.")
                            return "BAD\n";
                        }

                        if (!(std::filesystem::exists(end_auction_file))){
                            reply += " 1";
                        }
                        else reply += " 0";
                    }
                }
                reply += "\n";
            } catch (const filesystem::filesystem_error& e) {
                STATUS("Error accessing directory")
                return "BAD\n";
            }
        }
    }
    //Reply o que acontece quando não existe a pasta desse user?
    //consideramos como se não tivesse logged in? Pq so o proprio user pode pedir este
    else return "RMA NLG\n";

    return reply;
}

string req_mybids(istringstream &reqstream){
    string UID;

    string reply = "RMB ";
    if (!(reqstream >> UID)){
        STATUS("My auctions request doesn't have UID")
        return "RMB ERR\n";
    }

    if (!is_valid_UID(UID)){
        STATUS("UID is not correctly formatted.")
        return "RMB ERR\n";
    }

    if (!reqstream.eof()){
        STATUS("My auctions request format is incorrect.")
        return "RMB ERR\n";
    }

    std::filesystem::path user_dir_lock = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID+".lock");
    std::filesystem::path user_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID);
    std::filesystem::path login_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_login.txt");
    std::filesystem::path uid_bidded_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(BIDDED_DIR_PATH);

    if (std::filesystem::exists(user_dir)){
        //checkar login
        if (!(std::filesystem::exists(login_path))) return "RMB NLG\n";
        else if (!(std::filesystem::exists(uid_bidded_dir)) || std::filesystem::is_empty(uid_bidded_dir)){
            return "RMB NOK\n";
        }
        else{
            reply += "OK";
            try {
                for (const auto& entry : std::filesystem::directory_iterator(uid_bidded_dir)) {
                    if (std::filesystem::is_regular_file(entry.path())) { // Reply este if é preciso?
                        string AID;
                        AID = entry.path().stem().string();

                        if (!is_valid_AID(AID)){
                            STATUS("Auction file name is not a valid AID.")
                            return "BAD\n";
                        }

                        reply += " " + AID;

                        std::filesystem::path auction_dir_lock = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID+".lock");
                        std::filesystem::path curr_auction_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID);
                        std::filesystem::path end_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("END_" + AID + ".txt");
                        
                        if (!(std::filesystem::exists(end_auction_file))){
                            reply += " 1";
                        }
                        else reply += " 0";
                    }
                }
                reply += "\n";
            } catch (const filesystem::filesystem_error& e) {
                STATUS("Error accessing directory")
                return "BAD\n";
            }
        }
    }
    else return "RMB NLG\n";

    return reply;
}

string req_list(){
    string reply = "RLS ";


    std::filesystem::path auctions_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH);

    if (!std::filesystem::exists(auctions_dir)) {
        STATUS("AUCTIONS directory does not exist")
        return "BAD\n";
    } //a pasta auction assume se que ja está criada antes de correr
    else if (std::filesystem::is_empty(auctions_dir)) return "RLS NOK\n";
    else {
        reply += "OK";
            try {
                for (const auto& entry : std::filesystem::directory_iterator(auctions_dir)) {
                        string AID;
                        AID = entry.path().stem().string();
                        std::filesystem::path auction_dir_lock = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID+".lock");

                        if (!is_valid_AID(AID)){
                                STATUS("Auction file name is not a valid AID.")
                                return "BAD\n";
                        }

                        reply += " " + AID;


                        std::filesystem::path curr_auction_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID);
                        std::filesystem::path end_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("END_" + AID + ".txt");
                        
                        if (update_auction(AID) == -1) {
                            STATUS("Error updating auction.")
                            return "BAD\n";
                        }

                        if (!(std::filesystem::exists(end_auction_file))){
                            reply += " 1";
                        }
                        else reply += " 0";
                }
                reply += "\n";
            } catch (const filesystem::filesystem_error& e) {
                STATUS("Error accessing directory")
                return "BAD\n";
            }
    }

    return reply;
}

//falta atualizar o timeactive sempre que se usa isto;
string req_showrecord(istringstream &reqstream){
    string AID;


    string reply = "RRC ";
    if (!(reqstream >> AID)){
        STATUS("My auctions request doesn't have AID")
        return "RRC ERR\n";
    }

    if (!is_valid_AID(AID)){
        STATUS_WA("AID is not correctly formatted: \"%s\"", AID.c_str())
        return "RRC ERR\n";
    }

    if (!reqstream.eof()){
        STATUS("Show record request format is incorrect.")
        return "RRC ERR\n";
    }


    std::filesystem::path auction_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID);
    std::filesystem::path start_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("START_" + AID + ".txt");

    if (std::filesystem::exists(auction_dir)){
        if (std::filesystem::exists(start_auction_file)){

            if (update_auction(AID) == -1) {
                STATUS("Error updating auction.")
                return "BAD\n";
            }

            reply += "OK ";

            ifstream start_stream(start_auction_file);

            if (!(start_stream.is_open())){
                STATUS("Couldn't open start auction file.")
                start_stream.close();
                return "BAD\n";
            }

            string host_uid,name,asset_fname,start_date, start_time;
            int start_value, timeactive;
            long int start_date_secs;

            if (!(start_stream >> host_uid)){
                STATUS("Start file doesn't have Host_UID")
                return "BAD\n";
            }

            if (!is_valid_UID(host_uid)){
                STATUS("Start file has a incorrectly formatted host_uid")
                return "BAD\n";
            }

            if (!(start_stream >> name)){
                STATUS("Start file doesn't have auction name")
                return "BAD\n";
            }

            if (!is_valid_auction_name(name)){
                STATUS("Start file has a incorrectly formatted auction name")
                return "BAD\n";
            }

            if (!(start_stream >> asset_fname)){
                STATUS("Start file doesn't have asset name")
                return "BAD\n";
            }

            if (!is_valid_fname(asset_fname)){
                STATUS("Start file has a incorrectly formatted asset name")
                return "BAD\n";
            }

            if (!(start_stream >> start_value)){
                STATUS("Start file doesn't have start value")
                return "BAD\n";
            }

            if (!is_valid_bid_value(start_value)){
                STATUS("Start file has a incorrectly formatted start value")
                return "BAD\n";
            }

            if (!(start_stream >> timeactive)){
                STATUS("Start file doesn't have time active")
                return "BAD\n";
            }

            if (!is_valid_timeactive(timeactive)){
                STATUS("Start file has a incorrectly formatted time active")
                return "BAD\n";
            }

            if (!(start_stream >> start_date)){
                STATUS("Start file doesn't have start date")
                return "BAD\n";
            }

            if (!(start_stream >> start_time)){
                STATUS("Start file doesn't have start time")
                return "BAD\n";
            }

            string start_datetime = start_date + " " + start_time;

            if (!is_valid_date_time(start_datetime)){
                STATUS("Start file has a incorrectly formatted start date")
                return "BAD\n";
            }

            if (!(start_stream >> start_date_secs)){
                STATUS("Start file doesn't have a start date in seconds")
                return "BAD\n";
            }

            if (!is_valid_start_time(start_date_secs)){
                STATUS("Start file has a incorrectly formatted start date in seconds")
                return "BAD\n";
            }

            start_stream.close();

            reply += host_uid + " " + name + " " + asset_fname + " " + to_string(start_value) \
            + " " + start_datetime + " " + to_string(timeactive);



            //checkar se alguem biddou;
            std::filesystem::path bids_directory = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append(BIDS_DIR_PATH);

            if (std::filesystem::exists(bids_directory) && !(std::filesystem::is_empty(bids_directory))){
                vector<string> file_names;
                try {

                    for (const auto& entry : std::filesystem::directory_iterator(bids_directory)) {
                        file_names.push_back(entry.path().filename().string());
                    }

                    std::sort(file_names.begin(), file_names.end(), std::greater<std::string>());


                    int len = file_names.size();


                    for (int i=0; i<len; i++){
                        if (i >= MAX_BIDS_SHOWN) break;


                        std::filesystem::path curr_bid_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append(BIDS_DIR_PATH).append(file_names[i]);
                        
                        ifstream bid_stream(curr_bid_file);

                        string uid,bid_date, bid_time;
                        int bid_value;
                        long long int bid_date_secs;

                        if (!(bid_stream.is_open())){
                            STATUS("Couldn't open bid file.")
                            bid_stream.close();
                            return "BAD\n";
                        }

                        if (!(bid_stream >> uid)){
                            STATUS("Bid file doesn't have uid")
                            return "BAD\n";
                        }

                        if (!is_valid_UID(uid)){
                            STATUS("Bid file has a incorrectly formatted host_uid")
                            return "BAD\n";
                        }

                        if (!(bid_stream >> bid_value)){
                            STATUS("Bid file doesn't have start value")
                            return "BAD\n";
                        }

                        if (!is_valid_bid_value(bid_value)){
                            STATUS("Bid file has a incorrectly formatted start value")
                            return "BAD\n";
                        }

                        if (!(bid_stream >> bid_date)){
                            STATUS("Bid file doesn't have start date")
                            return "BAD\n";
                        }

                        if (!(bid_stream >> bid_time)){
                            STATUS("Bid file doesn't have start date")
                            return "BAD\n";
                        }

                        string bid_datetime = bid_date + " " + bid_time;

                        if (!is_valid_date_time(bid_datetime)){
                            STATUS("Bid file has a incorrectly formatted date")
                            return "BAD\n";
                        }
                        
                        string sbds;
                        if (!(bid_stream >> sbds)){
                            STATUS("Bid file doesn't have a date in seconds")
                            return "BAD\n";
                        }

                        STATUS_WA("sbds: %s", sbds.c_str())
                        bid_date_secs = stoll(sbds);

                        STATUS_WA("Parameters read: uid: %s | bid_value: %d | bid_datetime: %s | bid_date_secs: %lld",
                                    uid.c_str(), bid_value, bid_datetime.c_str(), bid_date_secs)
                        
                        if (!is_valid_time_seconds(bid_date_secs,timeactive)){
                            STATUS_WA("Bid file has a incorrectly formatted date in seconds: %s | %s",
                                         to_string(bid_date_secs).c_str(), to_string(timeactive).c_str())
                            return "BAD\n";
                        }


                        reply += " B " + uid + " " + to_string(bid_value) + " " + bid_datetime + " " + to_string(bid_date_secs);
                    }
                    
                }catch (const exception& e) {
                    STATUS("Error accessing directory");
                    return "BAD\n";
                }
                

            }
            //checkar se a auction ja acabou e se ja escrever o [E ...]
            std::filesystem::path end_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("END_" + AID + ".txt");
            if (std::filesystem::exists(end_auction_file)){
                ifstream end_stream(end_auction_file);

                if (!(end_stream.is_open())){
                    STATUS("Couldn't open end auction file.")
                    end_stream.close();
                    return "BAD\n";
                }

                string end_date, end_time, end_sec_time;

                if (!(end_stream >> end_date)){
                    STATUS("End file doesn't have a date")
                    return "BAD\n";
                }

                if (!(end_stream >> end_time)){
                    STATUS("End file doesn't have a date")
                    return "BAD\n";
                }

                string end_datetime = end_date + " " + end_time;

                if (!is_valid_date_time(end_datetime)){
                    STATUS("End file date is incorrectly formatted")
                    return "BAD\n";
                }

                if (!(end_stream >> end_sec_time)){
                    STATUS("End file doesn't have a end date in seconds")
                    return "BAD\n";
                }

                reply += " E " + end_datetime + " " + end_sec_time + "\n";
            }
            else reply += "\n";

        }
        else return "BAD\n"; //A auction existe mas nao tem start file
    }
    else{
        return "RRC NOK\n";
    }

    STATUS_WA("Reply: %s", reply.c_str());

    return reply;
}

// TCP
int req_open_rollback(string UID, string AID) {
    std::filesystem::path auction_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID);

    if (std::filesystem::exists(auction_dir)) {
        try {
            std::filesystem::remove_all(auction_dir);
        } catch (const std::filesystem::filesystem_error& e) {
            STATUS("Error deleting auction directory.")
            return -1;
        }
    }

    STATUS("Rollback successful.")

    return 0;
}

string req_open(istringstream &reqstream){
    string UID, req_pass;
    int n = reqstream.str().length();
    int bytesToRemove = 4;
    string AID_str;
    int AID=0;

    ifstream nextaidstream(sv.next_AID_file);

    if (!(nextaidstream.is_open())){
        STATUS("Couldn't open next AID file.")
        return "BAD\n";
    }

    getline(nextaidstream, AID_str);

    if (nextaidstream.fail()){
        STATUS("Error reading next AID file.")
        return "BAD\n";
    }

    nextaidstream.close();

    if (!is_valid_AID(AID_str)){
        STATUS("AID is not correctly formatted.")
        return "BAD\n";
    }

    AID = stoi(AID_str);

    if (AID > MAX_AID) {
        STATUS("Maximum number of auctions reached.")
        return "ROA NOK\n";
    }

    if (!(reqstream >> UID)) {
        STATUS("Unregister request doesn't have UID")
        return "ROA ERR\n";
    }

    if (!is_valid_UID(UID)) {
        STATUS("UID is not correctly formatted.")
        return "ROA ERR\n";
    }

    bytesToRemove += UID.length()+1;

    if (!(reqstream >> req_pass)) {
        STATUS("Unregister request doesn't have password.")
        return "ROA ERR\n";
    }

    if (!is_valid_pass(req_pass)) {
        STATUS("Password is not correctly formatted.")
        return "ROA ERR\n";
    }

    bytesToRemove += req_pass.length()+1;
    
    string name;
    if (!(reqstream >> name)) {
        STATUS("Open request doesn't have name.")
        return "ROA ERR\n";
    }

    if (!is_valid_auction_name(name)){
        STATUS("Auction name is not valid.")
        return "ROA ERR\n";
    }

    bytesToRemove += name.length()+1;
    
    int start_value;
    if (!(reqstream >> start_value)) {
        STATUS("Open request doesn't have value.")
        return "ROA ERR\n";
    }

    if (!is_valid_bid_value(start_value)) {
        STATUS("Start value is not valid.")
        return "ROA ERR\n";
    }

    bytesToRemove += to_string(start_value).length()+1;

    int timeactive;
    if ( !(reqstream >> timeactive)){
        STATUS("Timeactive is not a valid integer.")
        return "ROA ERR\n";
    }

    if (!is_valid_timeactive(timeactive)){
        STATUS_WA("Timeactive is not valid. (Max time is %d)", MAX_TIME_ACTIVE);
        return "ROA ERR\n";
    }

    bytesToRemove += to_string(timeactive).length()+1;

    string asset_fname;
    if (!(reqstream >> asset_fname)) {
        STATUS("Open request doesn't have asset filename.")
        return "ROA ERR\n";
    }

    if (!is_valid_fname(asset_fname)) {
        STATUS("Asset filename is not valid.")
        return "ROA ERR\n";
    }

    bytesToRemove += asset_fname.length()+1;

    int asset_fsize;
    if (!(reqstream >> asset_fsize)) {
        STATUS("Open request doesn't have asset filesize.")
        return "ROA ERR\n";
    }

    if (!is_valid_fsize(asset_fsize)) {
        STATUS("Asset filesize is not valid.")
        return "ROA ERR\n";
    }

    bytesToRemove += to_string(asset_fsize).length()+1;

    std::filesystem::path user_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID);
    std::filesystem::path pass_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_pass.txt");
    std::filesystem::path login_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_login.txt");

    if (std::filesystem::exists(pass_path) && std::filesystem::exists(login_path)){
        ifstream pass_stream(pass_path);

        if (!(pass_stream.is_open())){
            STATUS("Couldn't open password file.")
            return "BAD\n";
        }

        string password;
        getline(pass_stream,password); // reply como a pass é alfanumerica, podemos so apanhar a primeira linha?

        if (pass_stream.fail()){
            STATUS("Error reading password file.")
            return "BAD\n";
        }

        pass_stream.close();

        if (req_pass == password){

            std::filesystem::path hosted_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(HOSTED_DIR_PATH);
            std::filesystem::path auction_file_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(HOSTED_DIR_PATH).append(AID_str+".txt");

            if (!std::filesystem::exists(hosted_dir)){
                STATUS("Hosted directory does not exist.")
                return "BAD\n";
            }

            ofstream auction_file(auction_file_path);

            if (!(auction_file.is_open())){
                STATUS("Couldn't create auction file.")
                return "BAD\n";
            }

            std::filesystem::path auction_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID_str);
            std::filesystem::path start_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID_str).append("START_" + AID_str + ".txt");
            std::filesystem::path bids_auction_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID_str).append(BIDS_DIR_PATH);
            std::filesystem::path assets_auction_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID_str).append(ASSET_DIR_PATH);
            std::filesystem::path asset_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID_str).append(ASSET_DIR_PATH).append(asset_fname);

            // cria as diretorias a partir dos paths
            if (!std::filesystem::create_directory(auction_dir)) {
                STATUS("Error creating auction directory.")
                return "BAD\n";
            }

            if (!std::filesystem::create_directory(bids_auction_dir)) {
                STATUS("Error creating bids directory.")
                return "BAD\n";
            }

            if (!std::filesystem::create_directory(assets_auction_dir)) {
                STATUS("Error creating assets directory.")
                return "BAD\n";
            }

            STATUS("Directories created successfully.")

            ofstream start_stream(start_auction_file);

            if (!(start_stream.is_open())){
                STATUS("Couldn't create start auction file")
                return "BAD\n";
            }

            time_t fulltime;
            struct tm *current_time;
            char timestr[20];
            
            time(&fulltime);
            current_time = gmtime(&fulltime);
            
            
            sprintf(timestr, "%4d-%02d-%02d %02d:%02d:%02d", \
            current_time->tm_year+1900,current_time->tm_mon+1,\
            current_time->tm_mday,current_time->tm_hour,\
            current_time->tm_min,current_time->tm_sec);

            start_stream << UID << " " << name << " " << asset_fname << " " << start_value <<
                            " " << timeactive << " " << timestr << " " << fulltime << endl;


            start_stream.close();

            char tempBuf[BUFFER_SIZE+1];
            memset(tempBuf, 0, BUFFER_SIZE+1);
            memcpy(tempBuf, sv.TCP.buffer + bytesToRemove, BUFFER_SIZE+1-bytesToRemove);
            
            FILE *asset = fopen(asset_file.c_str(), "wb");
            if (asset == NULL){
                STATUS("Couldn't create asset file.")
                return "BAD\n";
            }

            int old_n = strlen(tempBuf);
            int written=0, total_written=0, total_read=0;
            
            written = fwrite(tempBuf,1,old_n,asset);
            total_written += written;
            total_read += written;

            while (total_written < asset_fsize){
                memset(sv.TCP.buffer,0,BUFFER_SIZE+1);
                if (read_timer(sv.TCP.fd) == -1) {
                    STATUS_WA("total_read: %d | total_written: %d | asset_fsize: %d", total_read, total_written, asset_fsize)
                    return "BAD\n";
                }
                n = read(sv.TCP.fd, sv.TCP.buffer, BUFFER_SIZE);

                total_read += n;

                if (n==-1){
                    STATUS("Could not receive show asset reply.")
                    req_open_rollback(UID,AID_str);
                    return "ROA ERR\n";
                }

                if (n == 0) {
                    if (total_written < asset_fsize) {
                        STATUS("Could not receive all asset.")
                        STATUS_WA("total_read: %d | total_written: %d | asset_fsize: %d | buffer size: %ld", total_read, total_written, asset_fsize, strlen(sv.TCP.buffer))
                        req_open_rollback(UID,AID_str);
                        return "ROA ERR\n";
                    }
                    else break;
                }

                written = fwrite(sv.TCP.buffer, 1, n, asset);

                if (written != n){
                    STATUS("Não escreveu tudo.")
                }

                total_written += written;
            }

            fclose(asset);

            asset = fopen(asset_file.c_str(), "rb");
            if (asset == NULL){
                STATUS("Couldn't open asset file for reading.")
                return "BAD\n";
            }

            // Determine the file size
            fseek(asset, 0, SEEK_END);
            long asset_fsize = ftell(asset);

            // Open the file in update mode
            asset = freopen(asset_file.c_str(), "r+", asset);
            if (asset == NULL){
                STATUS("Couldn't open asset file for modification.")
                return "BAD\n";
            }

            // Seek to the position one character before the end
            fseek(asset, -1, SEEK_END);

            // Truncate the file at that position
            int result = truncate(asset_file.c_str(), ftell(asset));
            if (result != 0) {
                STATUS("Error truncating the file.")
                // Handle the error, rollback, or return an appropriate value
            }

            fclose(asset);

            STATUS_WA("There were written %d bytes to asset file", total_written)

            STATUS_WA("total_read: %d | total_written: %d | asset_fsize: %ld", total_read, total_written, asset_fsize)

            if (total_written!=asset_fsize){
                STATUS("Bytes written to asset file != fsize")
                return "ROA ERR\n";
            }

            STATUS_WA("Asset file was successfully saved as \"%s\".", asset_fname.c_str())

            string reply = "ROA OK " + AID_str + "\n";

            ofstream next_aid(sv.next_AID_file);

            if (!(next_aid.is_open())){
                STATUS("Couldn't open next AID file.")
                return "BAD\n";
            }

            AID++;
            char nAID[4];
            sprintf(nAID, "%03d", AID);

            if (!(next_aid << nAID)){
                STATUS("Couldn't write to next AID file.")
                return "BAD\n";
            }

            next_aid.close();
            

            return reply;
        }
        else return "ROA NOK\n";
    }
    else return "ROA NLG\n";

    return "BAD\n";
}

string req_close(istringstream &reqstream){
    string UID, req_pass, AID;

    if (!(reqstream >> UID)){
        STATUS("Close request doesn't have UID")
        return "RCL ERR\n";
    }

    if (!is_valid_UID(UID)){
        STATUS("UID is not correctly formatted.")
        return "RCL ERR\n";
    }

    if (!(reqstream >> req_pass)){
        STATUS("Close request doesn't have password.")
        return "RCL ERR\n";
    }

    if (!is_valid_pass(req_pass)) {
        STATUS("Password is not correctly formatted.")
        return "RCL ERR\n";
    }

    if (!(reqstream >> AID)){
        STATUS("Close request doesn't have AID")
        return "RCL ERR\n";
    }

    if (!is_valid_AID(AID)){
        STATUS("AID is not correctly formatted.")
        return "RCL ERR\n";
    }

    if (!reqstream.eof()){
        STATUS("Close request format is incorrect.")
        return "RCL ERR\n";
    }

    std::filesystem::path user_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID);
    std::filesystem::path pass_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_pass.txt");
    std::filesystem::path login_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_login.txt");

    
    if(std::filesystem::exists(user_dir)){

        if (std::filesystem::exists(login_path)){

            ifstream pass_stream(pass_path);

            if (!(pass_stream.is_open())){
                STATUS("Couldn't open password file.")
                pass_stream.close();
                return "BAD\n";
            }

            string password;
            getline(pass_stream,password); 

            if (pass_stream.fail()){
                STATUS("Error reading password file.")
                pass_stream.close();
                return "BAD\n";
            }

            pass_stream.close();

            
            if (req_pass == password){
                
                std::filesystem::path curr_auction_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID);
                std::filesystem::path end_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("END_" + AID + ".txt");
                std::filesystem::path start_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("START_" + AID + ".txt");
                std::filesystem::path user_auction_hosted_file = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(HOSTED_DIR_PATH).append(AID+".txt");

                //checkar se o auction existe
                if (std::filesystem::exists(curr_auction_dir)){

                    if (update_auction(AID) == -1) {
                        STATUS("Error updating auction.")
                        return "BAD\n";
                    }

                    //checkar se o auction é do user
                    if (std::filesystem::exists(user_auction_hosted_file)){

                        //checkar se a auction está terminada
                        if (!std::filesystem::exists(end_auction_file)){

                            
                            ifstream start_stream(start_auction_file);

                            if (!(start_stream.is_open())){
                                STATUS("Couldn't open start auction file")
                                start_stream.close();
                                return "BAD\n";
                            }

                            string trash;

                            long int start_time_secs;
                            if (!(start_stream>>trash>>trash>>trash>>trash>>trash>>trash>>trash>>start_time_secs)){
                                STATUS("Error reading from START file")
                                start_stream.close();
                                return "BAD\n";
                            }

                            if (!is_valid_start_time(start_time_secs)){
                                STATUS("Start file has a incorrectly formatted start date in seconds")
                                start_stream.close();
                                return "BAD\n";
                            }

                            start_stream.close();

                            ofstream end_stream(end_auction_file);
                            time_t fulltime;
                            time(&fulltime);
                            struct tm *current_time;
                            char timestr[20];

                            if (!(end_stream.is_open())){
                                STATUS("Couldn't create end auction file")
                                end_stream.close();
                                return "BAD\n";
                            }
                            
                            current_time = gmtime(&fulltime);
                            sprintf(timestr, "%4d-%02d-%02d %02d:%02d:%02d", \
                            current_time->tm_year+1900,current_time->tm_mon+1,\
                            current_time->tm_mday,current_time->tm_hour,\
                            current_time->tm_min,current_time->tm_sec);   

                            end_stream << timestr << " " << fulltime-start_time_secs;  

                            end_stream.close();

                            return "RCL OK\n";

                        }
                        else return "RCL END\n";
                    }
                    else return "RCL EOW\n";
                }
                else return "RCL EAU\n";
            }
            else return "RCL NOK\n";  //Login existe mas pass está errada
        }
        else return "RCL NLG\n";
    }
    else return "RCL NOK\n";

    return "BAD\n";
}

void req_showasset(istringstream &reqstream){
    string AID;
    string reply = "RSA ";
    
    do {
        if (!(reqstream >> AID)){
            STATUS("Show asset request doesn't have AID")
            reply = "RSA ERR\n";
            break;
        }

        AID = AID.substr(0, 3);
        if (!is_valid_AID(AID)){
            STATUS_WA("AID provided is not valid: \"%s\"", AID.c_str())
            reply = "RSA ERR\n";
            break;
        }

        if (!reqstream.eof()){
            STATUS("Show asset request format is incorrect.")
            reply = "RSA ERR\n";
            break;
        }


        std::filesystem::path auction_dir = std::filesystem::path(DB_DIR_PATH)/AUCTIONS_DIR_PATH/AID;
        std::filesystem::path auction_asset_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append(ASSET_DIR_PATH);
        
        STATUS_WA("auction_dir: %s", auction_dir.c_str())
        STATUS_WA("auction_asset_dir: %s", auction_asset_dir.c_str())

        if(std::filesystem::exists(auction_dir) && (std::filesystem::exists(auction_asset_dir)) && (!std::filesystem::is_empty(auction_asset_dir))){
            int fileCount = 0;
            string filename;
            try {
                for (const auto& entry : std::filesystem::directory_iterator(auction_asset_dir)) {
                    //iterate for files that arent directories
                    STATUS_WA("<trash>filename: %s", entry.path().filename().c_str())
                    if (entry.is_directory()) continue;
                    filename = entry.path().filename();

                    STATUS_WA("filename: %s", filename.c_str())

                    break;
                }
            } catch (const exception& e) {
                STATUS("Error iterating through directory")
                reply = "BAD\n";
                break;
            }

            // if (fileCount != 1){
            //     STATUS_WA("There are more than 1 file in asset folder: %d", fileCount)
            //     reply = "BAD\n";
            //     break;
            // }
            
            reply += "OK " + filename;

            uintmax_t fileSize;
            std::filesystem::path filePath;
            try {
                filePath = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append(ASSET_DIR_PATH).append(filename);
                fileSize = std::filesystem::file_size(filePath);
            } catch (const exception& e) {
                STATUS("Error getting the size of the file")
                reply = "BAD\n";
                break;
            }

            reply += " " + to_string(fileSize) + " ";

            int l = write(sv.TCP.fd, reply.c_str(), reply.length());

            if (l!=reply.length()){
                STATUS("Could not send show asset message")
                reply = "BAD\n";
                break;
            }

            //ler e escrever o ficheiro


            FILE* file = fopen(filePath.c_str(), "rb");

            if (file == NULL){
                STATUS("Couldn't open asset file.")
                reply = "BAD\n";
                break;
            }

            fseek(file, 0, SEEK_END);
            long file_size = ftell(file);
            rewind(file);

            memset(sv.TCP.buffer, 0, BUFFER_SIZE+1);
            size_t bytesRead = 0;
            int flag = 0;
            int total_written = 0;
            int total_read = 0;

            while(total_written < fileSize){

                memset(sv.TCP.buffer,0,BUFFER_SIZE+1);
                bytesRead = fread(sv.TCP.buffer,1,BUFFER_SIZE,file);
                if (bytesRead == -1){
                    STATUS("Could not read asset file")
                    reply = "BAD\n";
                    flag = 1;
                    break;
                }
                total_read += bytesRead;

                size_t n = write(sv.TCP.fd, sv.TCP.buffer, strlen(sv.TCP.buffer));
                // while (n < bytesRead){
                //     n += write(sv.TCP.fd, sv.TCP.buffer+n, bytesRead-n);
                // }

                if( n==-1){
                    STATUS("Could not write asset file")
                    flag = 1;
                    break;
                }
                total_written += bytesRead;
                STATUS_WA("totalwritten: %d", total_written)
            }

            if (flag) break;

            if (total_written != file_size) {
                STATUS_WA("total_written: %d, file_size: %ld", total_written, file_size)
                STATUS("Failed to write all bytes")
                reply = "BAD\n";
                break;
            }

            l = write(sv.TCP.fd,"\n", 1);
            if (l!=1){
                STATUS("Could not write \\n on message")
                reply = "BAD\n";
                break;
            }

            return;

        }
        else {
            reply = "RSA NOK\n";
        }
    } while (0);


    STATUS_WA("Show asset message: %s",reply.c_str())
}

string req_bid(istringstream &reqstream){
    string UID, req_pass, AID;
    int value;

    STATUS_WA("Bid request: %s", reqstream.str().c_str())
    
    if (!(reqstream >> UID)){
        STATUS("Bid request doesn't have UID")
        return "RBD ERR\n";
    }

    if (!is_valid_UID(UID)){
        STATUS("UID is not correctly formatted.")
        return "RBD ERR\n";
    }

    if (!(reqstream >> req_pass)){
        STATUS("Bid request doesn't have password.")
        return "RBD ERR\n";
    }

    if (!is_valid_pass(req_pass)) {
        STATUS("Password is not correctly formatted.")
        return "RBD ERR\n";
    }

    if (!(reqstream >> AID)){
        STATUS("Bid request doesn't have AID")
        return "RBD ERR\n";
    }

    if (!is_valid_AID(AID)){
        STATUS("AID is not correctly formatted.")
        return "RBD ERR\n";
    }

    if (!(reqstream >> value)){
        STATUS("Bid request doesn't have a value")
        return "RBD ERR\n";
    }

    if (!is_valid_bid_value(value)){
        STATUS("AID is not correctly formatted.")
        return "RBD ERR\n";
    }

    string trash;
    if (!(reqstream >> trash)){
        STATUS("Bid request doesn't have a value")
        return "RBD ERR\n";
    }

    if (!reqstream.eof()){
        STATUS("Bid request format is incorrect.")
        return "RBD ERR\n";
    }

    std::filesystem::path user_dir = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID);
    std::filesystem::path pass_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_pass.txt");
    std::filesystem::path login_path = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(UID + "_login.txt");


    if(std::filesystem::exists(user_dir)){

        if (std::filesystem::exists(login_path)){

            ifstream pass_stream(pass_path);

            if (!(pass_stream.is_open())){
                STATUS("Couldn't open password file.")
                pass_stream.close();
                return "BAD\n";
            }

            string password;
            getline(pass_stream,password); 

            if (pass_stream.fail()){
                STATUS("Error reading password file.")
                pass_stream.close();
                return "BAD\n";
            }

            pass_stream.close();


            
            if (req_pass == password){
                
                std::filesystem::path curr_auction_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID);
                std::filesystem::path end_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("END_" + AID + ".txt");
                std::filesystem::path user_auction_hosted_file = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(HOSTED_DIR_PATH).append(AID+".txt");

                
                if (std::filesystem::exists(curr_auction_dir)){
                    
                    //checkar se o auction e do user
                    if (!std::filesystem::exists(user_auction_hosted_file)){

                        //checkar se a auction esta terminada
                        if (!std::filesystem::exists(end_auction_file)){

                            std::filesystem::path bids_dir = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append(BIDS_DIR_PATH);

                            if (!std::filesystem::exists(bids_dir) && !std::filesystem::is_empty(bids_dir)){
                                vector<string> file_names;
                                try {

                                    for (const auto& entry : std::filesystem::directory_iterator(bids_dir)) {
                                        if (std::filesystem::is_regular_file(entry.path())) {
                                            file_names.push_back(entry.path().stem().string());
                                        }
                                    }
                                    
                                    std::sort(file_names.begin(), file_names.end(), std::greater<std::string>());

                                } catch (const exception& ex) {
                                    STATUS("Error accessing directory")
                                    return "BAD\n";
                                }

                                int highest_bid;

                                highest_bid = stoi(file_names[0]);

                                
                                if (!is_valid_bid_value(highest_bid)){
                                    STATUS("Highest value is not correctly formatted")
                                    return "BAD\n";
                                }


                                if (value <= highest_bid){ //a bid é menor do que a maior
                                    return "RBD REF\n"; 
                                }
                            }
                            else{

                                std::filesystem::path start_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("START_" + AID + ".txt");

                                ifstream start_stream(start_auction_file);

                                if (!(start_stream.is_open())){
                                    STATUS("Couldn't open start auction file")
                                    start_stream.close();
                                    return "BAD\n";
                                }

                                int start_value;

                                if (!(start_stream>>trash>>trash>>trash>>start_value)){
                                    STATUS("Error reading from START file")
                                    start_stream.close();
                                    return "BAD\n";
                                }

                                start_stream.close();

                                STATUS_WA("start_value: %d | value: %d", start_value,value)

                                if (value <= start_value){ //a bid é menor do que a maior
                                    return "RBD REF\n"; 
                                }
                            }
                            
                            char fname[7];
                            sprintf(fname, "%06d", value);
                            std::filesystem::path user_bidded_file = std::filesystem::path(DB_DIR_PATH).append(USERS_DIR_PATH).append(UID).append(BIDDED_DIR_PATH).append(AID + ".txt");

                            ofstream bid_stream(user_bidded_file);
                            
                            if (!bid_stream.is_open()){
                                STATUS("Couldn't create bid file in user directory")
                                bid_stream.close();
                                return "BAD\n";
                            }

                            bid_stream.close();

                            std::filesystem::path start_auction_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append("START_" + AID + ".txt");
                            ifstream start_stream(start_auction_file);

                            if (!start_stream.is_open()){
                                STATUS("Could not open start auction file.");
                                start_stream.close();
                                return "BAD\n";
                            }


                            string trash;
                            long int start_time_secs;
                            if (!(start_stream>>trash>>trash>>trash>>trash>>trash>>trash>>trash>>start_time_secs)){
                                STATUS("Error reading from START file")
                                start_stream.close();
                                return "BAD\n";
                            }
                            
                            start_stream.close();

                            if (!is_valid_start_time(start_time_secs)){
                                STATUS("Start time is not valid")
                                return "BAD\n";
                            }

                            std::filesystem::path auctions_bidded_file = std::filesystem::path(DB_DIR_PATH).append(AUCTIONS_DIR_PATH).append(AID).append(BIDS_DIR_PATH).append(string(fname) + ".txt");
                            
                            bid_stream = ofstream(auctions_bidded_file);

                            if (!bid_stream.is_open()){
                                STATUS("Couldn't create bid file in auctions directory")
                                bid_stream.close();
                                return "BAD\n";
                            }

                            time_t fulltime;
                            time(&fulltime);
                            struct tm *current_time;
                            char timestr[20];

                            current_time = gmtime(&fulltime);
                            sprintf(timestr, "%4d-%02d-%02d %02d:%02d:%02d", \
                            current_time->tm_year+1900,current_time->tm_mon+1,\
                            current_time->tm_mday,current_time->tm_hour,\
                            current_time->tm_min,current_time->tm_sec);  


                            if (!(bid_stream<<UID<<" "<<value<<" "<<timestr<<" "<< (fulltime - start_time_secs))){
                                STATUS("Couldn't write to bid file")
                                bid_stream.close();
                                return "BAD\n";
                            }
                            return "RBD OK\n";
                        
                        }
                        else return "RBD AID\n"; //AID is not active
                    }
                    else return "RBD ILG\n"; //Auction is hosted my user
                }
                else return "RBD NOK\n";//checkar se o auction existe
            }
            else return "RBD NOK\n";  //Login existe mas pass esta errada
        }
        else return "RBD NLG\n"; //User not logged in
    }
    else return "RBD NOK\n"; //User doesnt exist


    return "BAD\n";
}


int count_spaces(string str){
    int count = 0;
    for (int i = 0; i < str.length(); i++){
        if (str[i] == ' ') count++;
    }
    return count;
}

int handle_TCP_req(){   

    bool err_with_st = false;
    string sbuff = "";
    size_t n = 0;

    // 76 is the max length of the reply without the last space and the Fdata of the open command
    for (int total_n = 0; total_n < 76;) {

        memset(sv.TCP.buffer, 0, BUFFER_SIZE+1);
        if (read_timer(sv.TCP.fd) == -1) {
            STATUS_WA("sbuff: %s", sbuff.c_str())

            if (total_n >= 3) err_with_st = true;
            break;
        }
        n = read(sv.TCP.fd, sv.TCP.buffer, BUFFER_SIZE);
        total_n += n;

        sbuff += string(sv.TCP.buffer);

        if (n < 0) {
            STATUS("Could not receive tcp reply.")
            return -1;
        }
        if (sbuff[total_n - 1] == '\n') {
            STATUS("No more bytes in tcp message.")
            sbuff[total_n - 1] = '\0';
            break;
        }
        else if (sbuff.substr(0, 3) == "OPA" && count_spaces(sbuff) >= 8) {
            STATUS("No more bytes in tcp message - open big file.")
            break;
        }
    }


    istringstream reqstream(sbuff);
    string opcode, reply;

    if (reqstream.str().length()>200) LOG_WA(sv.verbose,"Received request: %s...", reqstream.str().substr(0,200).c_str())
    else LOG_WA(sv.verbose,"Received request: %s", reqstream.str().c_str())
    
    string request_type;
    STATUS_WA("Received request: %s", reqstream.str().c_str())
    if (!(reqstream>>request_type)){
        STATUS("Invalid command")
        return -1;
    }

    if (request_type == "OPA"){
        if (err_with_st) reply = "RLI ERR\n";
        else {
            reply = req_open(reqstream);
        }
    }

        else if (request_type == "CLS"){
            if (err_with_st) reply = "RCL ERR\n";
            else {
                reply = req_close(reqstream);
            }
        }

    else if (request_type == "SAS"){
        if (err_with_st) reply = "RSA ERR\n";
        else {
            req_showasset(reqstream);
            return 0;
        }
    }
    
    else if (request_type == "BID"){
        if (err_with_st) reply = "RBD ERR\n";
        else {
            reply = req_bid(reqstream);
        }
    }
    else reply = "ERR\n";

    //send reply
    n = write(sv.TCP.fd, reply.c_str(), reply.length());
    if (n == -1) {
        STATUS("Could not send message")
        return -1;
    }

    STATUS_WA("Message sent: %s",reply.c_str())

    return 0;
}

int handle_UDP_req(string req){

    if (req[req.length() - 1] == '\n'){
        req = req.substr(0, req.length() - 1);
        STATUS_WA("Request: \"%s\"", req.c_str())
    }
    else {
        STATUS("No newline at the end of the message.")
        return -1;
    }

    istringstream reqstream(req);
    string request_type;
    string reply;
    int n;

    if (!(reqstream>>request_type)){
        STATUS("Invalid command")
        return -1;
    }


    f_wrlock("server/DB.lock");
    if (request_type == "LIN"){
        reply = req_login(reqstream);
        if (reply == ""){
            STATUS("Error during login.")
        }
    }

    else if (request_type == "LOU"){
        reply = req_logout(reqstream);
        if (reply == ""){
            STATUS("Error during logout.")
        }
    }

    else if (request_type == "UNR"){
        reply = req_unregister(reqstream);
        if (reply == ""){
            STATUS("Error during unregister.")
        }
    }

    else if (request_type == "LMA"){
        reply = req_myauctions(reqstream);
        if (reply == ""){
            STATUS("Error during my auctions.")
        }
    }

    else if (request_type == "LMB"){
        reply = req_mybids(reqstream);
        if (reply == ""){
            STATUS("Error during my auctions.")
        }
    }

    else if (request_type == "LST"){
        reply = req_list();
        if (reply == ""){
            STATUS("Error during list")
        }
    }

    else if (request_type == "SRC"){
        reply = req_showrecord(reqstream);

        if (reply == ""){
            STATUS("Error during show record.")
        }
    }

    else{
        reply = "ERR\n";
        STATUS("Invalid request.")
    }

    f_unlock("server/DB.lock");

    STATUS_WA("Message %s will be sent", reply.c_str())

    n = sendto(sv.UDP.fd,reply.c_str(),reply.length(),0,(struct sockaddr*) &sv.UDP.addr,sv.UDP.addrlen);
    if (n==-1){
        STATUS("Could not send message")
        exit(EXIT_FAILURE);
    }


    exit(EXIT_SUCCESS);
}