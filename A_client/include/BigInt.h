#ifndef B_H
#define B_H
#include <iostream>
using namespace std;

typedef unsigned long long uint64;

const int UINT_LENGTH = 4096;
const int UINT_DIGIT = UINT_LENGTH / 32;

class BigInt {

private:
    unsigned int digit[UINT_DIGIT];

public:
    BigInt();
    BigInt(int var);
    BigInt(const char * varHex);
    BigInt(const string varHex);
    BigInt(const BigInt & var);
    virtual ~BigInt();
    
public:
    //赋值运算
    BigInt& operator = (int var);
    BigInt & operator = (const char * varHex);
    BigInt& operator = (string varHex);
    BigInt & operator = (const BigInt & var);

    //比较运算
    bool operator == (const BigInt & var) const;
    bool operator < (const BigInt & var) const;
    bool operator <= (const BigInt & var) const;
    bool operator != (const BigInt & var) const;
    bool operator > (const BigInt & var) const;
    bool operator >= (const BigInt & var) const;

    //位运算
    BigInt operator ~ () const;
    BigInt operator >> (int var) const;
    BigInt operator << (int var) const;
    BigInt & operator <<= (int var);
    BigInt & operator >>= (int var);
    
    //逻辑运算
    BigInt operator | (const BigInt& var) const;
    BigInt operator & (const BigInt& var) const;
    BigInt operator ^ (const BigInt& var) const;
    BigInt & operator |= (const BigInt & var);
    BigInt & operator &= (const BigInt & var);
    BigInt & operator ^= (const BigInt & var);

    //代数运算
    BigInt operator + (const BigInt& var) const;
    BigInt operator - (const BigInt& var) const;
    BigInt operator * (const BigInt& var) const;
    BigInt operator / (const BigInt& var) const;
    BigInt operator % (const BigInt& var) const;
    BigInt & operator += (const BigInt & var);
    BigInt & operator -= (const BigInt & var);
    BigInt & operator *= (const BigInt & var);
    BigInt & operator /= (const BigInt & var);
    BigInt & operator %= (const BigInt & var);

    

public:
    //其他函数
    uint64 toUint64() const;
    int getLength() const;
    void setBit(int i, int v);
    int getBit(int i) const;
    friend ostream & operator << (ostream & out, const BigInt & var);
    void setDigit(int num,int loc);
    int getDigit(int loc);
};
#endif