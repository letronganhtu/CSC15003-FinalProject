#include <sstream>
#include <bitset>

#include "ring_sign.h"
#include "sha256.h"
#include "sp_func.h"
using namespace std;

vector<const BIGNUM *> ringSign(string m, vector<BIGNUM *> pk, const BIGNUM *pk_s, const BIGNUM *sk_s) {
    string k = sha256(m);

    BIGNUM *v = BN_new();
    BN_rand(v, 1028, 0, 0);

    vector<BIGNUM *> x;
    for (size_t i = 1; i < ring_member; i++) {
        BIGNUM *xi = BN_new();
        BN_rand(xi, 1028, 0, 0);
        x.push_back(xi);
    }

    vector<BIGNUM *> y;
    for (size_t i = 0; i < x.size(); i++) {
        y.push_back(g(x[i], pk[i], 1028));
    }

    // Expand key to 1028-bit
    string temp_k = hex2bin(k);
    string k_bin = temp_k + temp_k + temp_k + temp_k + "0101";

    string v_bin = hex2bin((string)BN_bn2hex(v));
    while (v_bin.length() > 1028 && v_bin[0] == '0')
        v_bin.erase(0, 1);
    string temp_value = "";
    for (size_t i = 0; i < ring_member - 1; i++) {
        // Đưa y_i thành chuỗi bit dài 1028-bit
        string yi_bin = hex2bin((string)BN_bn2hex(y[i]));
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

    for (size_t i = 0; i < k_bin.length(); i++) {
        temp_value[i] = (k_bin[i] != temp_value[i]) ? '1' : '0';
    }

    for (size_t i = 0; i < v_bin.length(); i++) {
        temp_value[i] = (v_bin[i] != temp_value[i]) ? '1' : '0';
    }

    // Convert temp_value (y_s string) to y_s in BIGNUM
    while (temp_value.length() % 4 != 0)
        temp_value = '0' + temp_value;

    stringstream ss;
    for (size_t i = 0; i < temp_value.length() / 4; i++) {
        string temp = temp_value.substr(4 * i, 4);
        ss << hex << bitset<4>(temp).to_ulong();
    }

    string temp_ys = ss.str();
    BIGNUM *y_s = NULL;
    BN_hex2bn(&y_s, temp_ys.c_str());

    // Tính giá trị x_s
    BIGNUM *quo = BN_new();
    BIGNUM *rem = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_div(quo, rem, y_s, pk_s, ctx);

    BIGNUM *a = NULL;
    BN_dec2bn(&a, "1");
    BN_add(a, quo, a); // a = q + 1
    BN_mul(a, a, pk_s, ctx); // a = (q + 1) * n

    BIGNUM *b = NULL;
    BN_dec2bn(&b, "2");
    BIGNUM *c = NULL;
    BN_dec2bn(&c, "1028");
    BN_exp(b, b, c, ctx); // b = 2^1028

    int cmp = BN_cmp(a, b);
    BIGNUM *x_s = BN_new();
    if (cmp == 1) {
        x_s = y_s;
    }
    else {
        BN_mod_exp(rem, rem, sk_s, pk_s, ctx);
        BN_mul(x_s, quo, pk_s, ctx);
        BN_add(x_s, x_s, rem);
    }

    vector<const BIGNUM *> ring_signature;
    for (size_t i = 0; i < pk.size(); i++) {
        ring_signature.push_back(pk[i]);
    }

    ring_signature.push_back(pk_s);

    ring_signature.push_back(v);

    for (size_t i = 0; i < x.size(); i++) {
        ring_signature.push_back(x[i]);
    }

    ring_signature.push_back(x_s);

    return ring_signature;
}