/**
 * File: John_Gilbert_Assignment_Two_Decrypt.cpp
 * Name: John Gilbert
 * PID: P100945579
 * Description: Decrypts a DES Encryption with a 10 bit key
 * IMPORTANT: The key comes first then the cypher text
 */


#include <iostream>
#include <vector>
#include <string>
#include <bitset>


using namespace std;
typedef basic_string<unsigned char> ustring;

// takes full string and splits it into two strings 
void splitStrings(string& stringOne, string& stringTwo, string fullString) {
    for (size_t i = 0; i < fullString.length()/2; i++) {
        stringOne += fullString[i];
    }
    for (size_t i =fullString.length()/2; i < fullString.length(); i++){
        stringTwo += fullString[i];
    }
}

void read_string(istream &ins, ustring &cypher){
    unsigned char x;
    while(ins.read(reinterpret_cast<char *>(&x), 1)) {
        cypher+=x; 
    }
}

/**
 *
 * Key Gen Helper Functions below 
 * 
 *  
 */

// runs the p10 permutaiton on a key
string p_ten(string key) {
    vector<int> p_ten_order = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};
    string p_ten_key = "";
    for (size_t i = 0; i < p_ten_order.size(); i++) {
        p_ten_key += key[p_ten_order[i]];
    }
    return p_ten_key;
}

// runs the ls1 permutions on a key
string ls_one(string key) {
    vector<int> ls_one_order = {1, 2, 3, 4, 0};
    string ls_one_key = "";
    for (size_t i = 0; i < ls_one_order.size(); i++) {
        ls_one_key += key[ls_one_order[i]];
    }
    return ls_one_key;
}

// runs the p8 permutation on a key
string p_eight(string key) {
    vector<int> p_eight_order = {5, 2, 6, 3, 7, 4, 9, 8};
    string p_eight_key = "";
    for (size_t i = 0; i < p_eight_order.size(); i++) {
        p_eight_key += key[p_eight_order[i]];
    }
    return p_eight_key;
}

string ls_two(string key) {
    vector<int> ls_two_order = {2, 3, 4, 0, 1};
    string ls_two_key = "";
    for (size_t i = 0; i < ls_two_order.size(); i++) {
        ls_two_key += key[ls_two_order[i]];
    }
    return ls_two_key;
}

/**
 * 
 * End Key Gen Helper Functions
 * 
 */

/**
 *
 * Decryption helper functions below 
 *
 * 
 */

// swaps the the upper and lower nibbles on a cypher binary string
string sw(string cypher_binary) {
    vector<int> sw_order = {4, 5, 6, 7, 0, 1, 2, 3};
    string sw_cypher = "";
    for (size_t i = 0; i < sw_order.size(); i++) {
        sw_cypher += cypher_binary[sw_order[i]];
    }
    return sw_cypher;
}

// runs the ip permutation on a cypher binary string
string ip(string cypher_binary) {
    vector<int> ip_order = {1, 5, 2, 0, 3, 7, 4, 6};
    string ip_cypher = "";
    for (size_t i = 0; i < ip_order.size(); i++) {
        ip_cypher += cypher_binary[ip_order[i]];
    }
    return ip_cypher;
}

// runs the ip inverse permutation on a cypher binary string
string ip_inverse(string cypher_binary) {
    vector<int> ip_inverse_order = {3, 0, 2, 4, 6, 1, 7, 5};
    string ip_inverse_cypher = "";
    for (size_t i = 0; i < ip_inverse_order.size(); i++) {
        ip_inverse_cypher += cypher_binary[ip_inverse_order[i]];
    }
    return ip_inverse_cypher;
}

// runs an expansion permutation on a 4 bit cypher string
string ep(string cypher_binary) {
    vector<int> ep_order = {3, 0, 1, 2, 1, 2, 3, 0};
    string cypher_ep = "";
    for(size_t i = 0; i < ep_order.size(); i++) {
        cypher_ep += cypher_binary[ep_order[i]];
    }
    return cypher_ep;
}

// does the key matchcing step of the feistal function
string km(string binary_cypher, string key) {
    int ep_right_int = stoi(binary_cypher, 0, 2);
    int k_int = stoi(key, 0, 2);
    int xor_result = (ep_right_int ^ k_int);
    return bitset<8>(xor_result).to_string();
}

// finds the s0 values for the s boxes
string s_zero(string binary_cypher) {
    string s_matrix_one[4][4] = {{"01", "00", "11", "10"}, {"11", "10", "01", "00"}, {"00", "10", "01", "11"}, {"11", "01", "11", "10"}};
    string row_bin = "";
    row_bin += binary_cypher[0];
    row_bin += binary_cypher[3];
    string col_bin = "";
    col_bin += binary_cypher[1];
    col_bin += binary_cypher[2];
    int row_num = stoi(row_bin,0,2);
    int col_num = stoi(col_bin,0,2);
    return s_matrix_one[row_num][col_num];
}

// finds the s0 values for the s boxes
string s_one(string binary_cypher) {
    string s_matrix_one[4][4] = {{"00", "01", "10", "11"}, {"10", "00", "01", "11"}, {"11", "00", "01", "00"}, {"10", "01", "00", "11"}};
    string row_bin = "";
    row_bin += binary_cypher[0];
    row_bin += binary_cypher[3];
    string col_bin = "";
    col_bin += binary_cypher[1];
    col_bin += binary_cypher[2];
    int row_num = stoi(row_bin,0,2);
    int col_num = stoi(col_bin,0,2);
    return s_matrix_one[row_num][col_num];
}

// runs the p4 permutation on a nibble of the cypher text
string p_four(string binary_cypher) {
    vector<int> p_four_order = {1, 3, 2, 0};
    string cypher_p_four = "";
    for(size_t i = 0; i < p_four_order.size(); i++) {
        cypher_p_four += binary_cypher[p_four_order[i]];
    }
    return cypher_p_four;
}

// xor's the p4 result of the feistal function and xors it with the left half of the initial ip permutation
string xor_p4_four_ip_left(string p4, string ip_left) {
    int p4_num = stoi(p4, 0, 2);
    int ip_num = stoi(ip_left, 0, 2);
    int xor_result = (p4_num ^ ip_num);
    return bitset<4>(xor_result).to_string();
}


// main driver for the feistal function
string feistal(string cypher_ip_left, string cypher_ip_right, string key) {
    string cypher_ep = ep(cypher_ip_right);
    string cypher_km = km(cypher_ep, key);
    string cypher_km_left = "";
    string cypher_km_right = "";
    splitStrings(cypher_km_left, cypher_km_right, cypher_km);
    string cypher_s_zero = s_zero(cypher_km_left);
    string cypher_s_one = s_one(cypher_km_right);
    string cypher_s_combined = cypher_s_zero + cypher_s_one;
    string cypher_p4 = p_four(cypher_s_combined);
    string xor_p4_ip_left = xor_p4_four_ip_left(cypher_p4, cypher_ip_left);
    return xor_p4_ip_left + cypher_ip_right;
}

/**
 * 
 * End Decryption helper functions
 * 
 */

int main() {
    string cypher_key;
    ustring cyphertext;
    getline(cin, cypher_key);
    read_string(cin, cyphertext);
    string p_ten_cypher_key = p_ten(cypher_key);
    string p_ten_left_key, p_ten_right_key = "";
    splitStrings(p_ten_left_key, p_ten_right_key, p_ten_cypher_key);
    string ls_one_left_key = ls_one(p_ten_left_key);
    string ls_one_right_key = ls_one(p_ten_right_key);
    string ls_one_combined = ls_one_left_key + ls_one_right_key;
    string k1 = p_eight(ls_one_combined);
    string ls_two_left_key = ls_two(ls_one_left_key);
    string ls_two_right_key = ls_two(ls_one_right_key);
    string ls_two_combined = ls_two_left_key + ls_two_right_key;
    string k2 = p_eight(ls_two_combined);
    cout << cypher_key << endl;
    for(unsigned char c: cyphertext) {
        string cypher_binary = bitset<8>(int(c)).to_string();
        string cypher_ip = ip(cypher_binary);
        string cypher_ip_left, cypher_ip_right = "";
        splitStrings(cypher_ip_left, cypher_ip_right, cypher_ip);
        string feistal_result_one  = feistal(cypher_ip_left, cypher_ip_right, k2);
        string cypher_sw = sw(feistal_result_one);
        string cypher_sw_left, cypher_sw_right = "";
        splitStrings(cypher_sw_left, cypher_sw_right, cypher_sw);
        string feistal_result_two = feistal(cypher_sw_left, cypher_sw_right, k1);
        string cypher_ip_inverse = ip_inverse(feistal_result_two);
        cout << (unsigned char)stoi(cypher_ip_inverse, 0, 2);
    }
}
