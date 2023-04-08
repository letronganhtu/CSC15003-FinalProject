#include <iomanip>
#include <sstream>

#include <openssl/sha.h>

#include "sha256.h"
using namespace std;

string sha256(const string message) { // Sử dụng hàm băm SHA256 đưa message về chuỗi hexa có độ dài 256-bit
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message.c_str(), message.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}