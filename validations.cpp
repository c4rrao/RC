#include "definitions.hpp"


bool is_valid_port (string port) {
    for (char c : port) {
        if (!isdigit(c)) {
            return false;
        }
    }
    int port_int = atoi(port.c_str());
    return port_int >= 0 && port_int <= 65535;
}

bool is_valid_ip (string ip) {
    struct sockaddr_in sa;
    if (ip == "localhost") return true;
    int result = inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
    return result != 0;
}

bool is_valid_AID(string AID){

    if (strlen(AID.c_str()) != AID_SIZE){
        STATUS("AID is not size 3")
        return false;
    }

    for (int i = 0; i < AID_SIZE; i++) {
        if (!isdigit(AID[i])) {
            STATUS("AID is not numeric")
            return false;  // If any character is not a digit, the string is not numeric
        }
    }
    return true;
}

bool is_valid_state(string state){
    if (state == "0" || state == "1") return true;
    STATUS("State is not either 0 or 1.")
    return false;
}

bool is_valid_fname(string fname){
    if (fname.length()>FILE_NAME_MAX_SIZE) {
        STATUS("Filename is too long >24 chars.")
        return false;
    }
    for (char c: fname){
        if (!isalnum(c) && c!='-' && c!='_' && c!='.') {
            STATUS_WA("Filename has invalid characters: %c", c)
            return false;
        }
    }
    return true;
}

bool is_valid_fsize(int fsize){
    if (fsize>FILE_MAX_SIZE){
        STATUS("File is larger than 10*10^6 Bytes")
        return false;
    }
    return true;
}

bool is_numeric(string input) {
    for (char c : input) {
        if (!isdigit(c)) {
            return false;
        }
    }
    return true;
}

bool is_valid_date_time(string input) {
    std::istringstream iss(input);
    int year, month, day, hour, minute, second;
    string syear, smonth, sday, shour, sminute, ssecond;  

    if (getline(iss, syear, '-') && syear.length() == 4 && is_numeric(syear) &&
        getline(iss, smonth, '-') && smonth.length() == 2 && is_numeric(smonth) &&
        getline(iss, sday, ' ') && sday.length() == 2 && is_numeric(sday) && 
        getline(iss, shour, ':') && shour.length() == 2 && is_numeric(shour) &&
        getline(iss, sminute, ':') && sminute.length() == 2 && is_numeric(sminute) &&
        getline(iss, ssecond) && ssecond.length() == 2 && is_numeric(ssecond)) {
            year = stoi(syear);
            month = stoi(smonth);
            day = stoi(sday);
            hour = stoi(shour);
            minute = stoi(sminute);
            second = stoi(ssecond);
    } else {
        STATUS_WA("Couldnt extract date in the correct form: Date: %d-%d-%d %d:%d:%d", year, month, day, hour, minute, second)
        return false;
        
    }

    if (year < 0){
        STATUS("Year is negative.")
        return false;
    }

    else if (month < 1 || month > 12){
        STATUS("Incorrect month")
        return false;
    }

    else if (day < 1 || day > 31){
        STATUS("Incorrect day")
        return false;
    }

    else if (hour < 0 || hour > 23){
        STATUS("Incorrect hour")
        return false;
    }

    else if (minute < 0 || minute > 59){
        STATUS("Incorrect minute")
        return false;
    }

    else if (second < 0 || second > 59){
        STATUS("Incorrect second")
        return false;
    }

    else if(!iss.eof()){
        STATUS("Date didnt reach eof.")
        return false;
    }

    // Check if the day is valid for the given month
    if ((month == 4 || month == 6 || month == 9 || month == 11) && day > 30) {
        STATUS("The month only has 30 days.")
        return false;
    } else if (month == 2) {
        // Check for leap year in February
        if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
            if (day > 29) {
                STATUS("Leap year.")
                return false;
            }
        } else {
            if (day > 28) {
                STATUS("February doesnt have more than 28 days in default year.")
                return false;
            }
        }
    }

    return true;  // Valid format and values
}

bool is_valid_UID(string UID){
    for (char c : UID) {
        if (!isdigit(c)) {
            STATUS("UID should be only numeric.")
            return false;
        }
    }
    if (UID.length() != UID_LEN){
        STATUS("UID should be 6 digits")
        return false;
    }

    return true;
}

bool is_valid_timeactive(int timeactive){

    if (timeactive>MAX_TIME_ACTIVE) {
        STATUS("timeactive is higher than max_time.")
        return false;
    }

    if (timeactive<0){
        STATUS("timeactive is negative.")
        return false;
    }
    return true;
}

bool is_valid_time_seconds(int time, int timeactive){
    return is_valid_timeactive(time) && time <= timeactive;
}

bool is_valid_start_time(long int start_time){
    return start_time>=0;
}

bool is_valid_pass(string pass){
    if (pass.length() != PASSWORD_LEN){
        STATUS("Password is not 8 characters long")
        return false;
    }
    
    for (char c : pass) {
        if (!isalnum(c)) {
            STATUS("Password should be alphanumeric.")
            return false;
        }
    }

    return true;
}

bool is_valid_auction_name(string name){
    if (name.length() > NAME_MAX_LEN) {
        STATUS("Auction name is too long.")
        return false;
    }

    for (char c : name) {
        if (!isalnum(c) && c!='-' && c!='_') {
            STATUS("Auction name should be alphanumeric.")
            return false;
        }
    }

    return true;

}

bool is_valid_bid_value(int value){
    if (value > MAX_START_VALUE) {
        STATUS("Start_value is too big (> 999999).")
        return false;
    }

    if (value < 0) {
        STATUS("Start_value can't be negative.")
        return false;
    }

    return true;
}

