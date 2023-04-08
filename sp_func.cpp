#include <string>
#include <unordered_map>

#include "sp_func.h"
using namespace std;

BIGNUM *g(BIGNUM *x, BIGNUM *n, int bit) {
    BIGNUM *q = BN_new();
    BIGNUM *r = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_div(q, r, x, n, ctx);

    BIGNUM *a = NULL;
    BN_dec2bn(&a, "1");
    BN_add(a, q, a); // a = q + 1
    BN_mul(a, a, n, ctx); // a = a * n = (q + 1) * n

    BIGNUM *b = NULL;
    BN_dec2bn(&b, "2");
    BIGNUM *c = NULL;
    BN_dec2bn(&c, to_string(bit).c_str());
    BN_exp(b, b, c, ctx); // b = b^c = 2^1028

    int cmp = BN_cmp(a, b);
    if (cmp == 1) { // (q + 1) * n > 2^b
        return x;
    }
    else {
        BN_mul(q, q, n, ctx); // q = q * n

        BIGNUM *f = NULL;
        BN_dec2bn(&f, "65537");
        BN_mod_exp(f, r, f, n, ctx); // f = r^f (% n) = r^65537 (% n)

        BN_add(q, q, f);

        BN_free(f);

        return q;
    }
}

string hex2bin(string hex) {
    unordered_map<char, string> hex_to_bin_dict {
        {'0', "0000"}, {'1', "0001"}, {'2', "0010"}, {'3', "0011"},
        {'4', "0100"}, {'5', "0101"}, {'6', "0110"}, {'7', "0111"},
        {'8', "1000"}, {'9', "1001"}, {'A', "1010"}, {'B', "1011"},
        {'C', "1100"}, {'D', "1101"}, {'E', "1110"}, {'F', "1111"}
    };
    string res = "";

    for (char character : hex)
        res += hex_to_bin_dict[toupper(character)];

    return res;
}