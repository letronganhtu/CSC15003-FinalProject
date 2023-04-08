#ifndef RINGVERIFY
#define RINGVERIFY

#include <iostream>
#include <vector>

#include <openssl/bn.h>

bool ringVerify(std::string m, std::vector<const BIGNUM *> ring_signature);

#endif