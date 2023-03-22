#pragma once
#include"BigInt.h"

BigInt CreateOddNum(int);
BigInt PowMod(BigInt, const BigInt& , const BigInt&);
bool isPrime(BigInt);
BigInt CreatePrime(int);
bool isEven(const BigInt&);
BigInt Encrypt(BigInt, BigInt, BigInt);
BigInt Decrypt(BigInt, BigInt, BigInt);
void ExtendEuclid(BigInt, BigInt, BigInt&, BigInt&, const BigInt&);