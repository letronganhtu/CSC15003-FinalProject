#include "ring_verify.h"
#include "sp_func.h"
#include "sha256.h"
using namespace std;

const int ring_member = 8;

bool ringVerify(string m, vector<const BIGNUM *> ring_signature) {
    vector<BIGNUM *> y_verify;
    for (size_t i = ring_member + 1; i <= 2 * ring_member; i++) {
        y_verify.push_back(g((BIGNUM *)ring_signature[i], (BIGNUM *)ring_signature[i - ring_member - 1], 1028));
    }
    
    // Tìm khoá k từ h(m)
    string temp_k = hex2bin(sha256(m));
    string k_bin = temp_k + temp_k + temp_k + temp_k + "0101";

    // Kiểm tra C_(k,v)(y) = v
    string v_bin = hex2bin((string)BN_bn2hex(ring_signature[ring_member]));
    while (v_bin.length() > 1028 && v_bin[0] == '0')
        v_bin.erase(0, 1);

    string temp_value = "";
    for (size_t i = 0; i < ring_member; i++) {
        // Đưa y_i thành chuỗi bit dài 1028-bit
        string yi_bin = hex2bin((string)BN_bn2hex(y_verify[i]));
        while (yi_bin.length() < 1028)
            yi_bin = '0' + yi_bin;
        while (yi_bin.length() > 1028 && yi_bin[0] == '0')
            yi_bin.erase(0, 1);

        if (i == 0) {
            for (size_t j = 0; j < yi_bin.length(); j++) {
                temp_value += (yi_bin[j] != v_bin[j]) ? '1' : '0';
            }
        }
        else {
            for (size_t j = 0; j < yi_bin.length(); j++) {
                temp_value[j] = (yi_bin[j] != temp_value[j]) ? '1' : '0';
            }
        }

        for (size_t j = 0; j < k_bin.length(); j++) {
            temp_value[j] = (k_bin[j] != temp_value[j]) ? '1' : '0';
        }
    }

    if (v_bin == temp_value) return 1;
    return 0;
}