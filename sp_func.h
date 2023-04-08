#ifndef SUPPORT_FUNCTION
#define SUPPORT_FUNCTION

#include <openssl/bn.h>
#include <iostream>

BIGNUM *g(BIGNUM *x, BIGNUM *n, int bit);
std::string hex2bin(std::string hex);

#endif