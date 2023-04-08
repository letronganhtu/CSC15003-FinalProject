#ifndef RINGSIGN
#define RINGSIGN

#include <iostream>
#include <vector>

#include <openssl/bn.h>

const uint8_t ring_member = 8;

std::vector<const BIGNUM *> ringSign(std::string m, std::vector<BIGNUM *> pk, const BIGNUM *pk_s, const BIGNUM *sk_s);

#endif