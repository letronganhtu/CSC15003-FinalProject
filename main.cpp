#include <iostream>
#include <vector>
#include <fstream>
#include <algorithm>
#include <sstream>

#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "ring_sign.h"
#include "ring_verify.h"
using namespace std;

int main() {
    // Nhập vào tin nhắn cần kí
    string m = "abc";
    getline(cin, m);

    // Tạo khoá công khai và khoá bí mật để kí
    RSA *my_rsa = RSA_generate_key(1024, 65537, 0, 0);
    const BIGNUM *n_s = RSA_get0_n(my_rsa);
    const BIGNUM *d_s = RSA_get0_d(my_rsa);

    // Lấy tất cả khoá công khai trên kênh truyền
    vector<BIGNUM *> all_pk;
    ifstream fin("public_key.txt");
    string line = "";
    while (getline(fin, line)) {
        stringstream s(line);
        string temp = "";
        getline(s, temp, ' ');
        getline(s, temp);
        BIGNUM *pk_i = NULL;
        BN_dec2bn(&pk_i, temp.c_str());
        all_pk.push_back(pk_i);
    }

    // Lấy (r-1) khoá công khai
    vector<BIGNUM *> ring_pk;
    srand(time(NULL));
    vector<int> idx;
    for (size_t i = 0; i < ring_member - 1; i++) {
        uint8_t temp_idx = rand() % all_pk.size();
        while (find(idx.begin(), idx.end(), temp_idx) != idx.end())
            temp_idx = rand() % all_pk.size();
        idx.push_back(temp_idx);
        ring_pk.push_back(all_pk[temp_idx]);
    }

    // Tạo chữ kí vành
    vector<const BIGNUM *> sigma = ringSign(m, ring_pk, n_s, d_s);

    // Kiểm tra chữ kí vành
    bool ok_signature = ringVerify(m, sigma);
    if (ok_signature) cout << "Chữ kí vành hợp lệ\n";
    else cout << "Chữ kí vành không hợp lệ\n";
    
    return 0;
}