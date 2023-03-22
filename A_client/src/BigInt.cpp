#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include "BigInt.h"

//构造函数
BigInt::BigInt() {
    * this = 0;
}
BigInt::BigInt(int var) {
    * this = var;
}
BigInt::BigInt(const char * varHex) {
    * this = varHex;
}
BigInt::BigInt(const string varHex)
{
    *this = varHex;
}
BigInt::BigInt(const BigInt & var) {
    * this = var;
}

BigInt::~BigInt() {
}

//赋值运算
BigInt& BigInt::operator = (int var) {
    memset(digit, 0, sizeof(digit));
    digit[0] = var;
    return *this;
}

static int hexCharToInt(char ch) {
    if ('0' <= ch && ch <= '9') {
        return (int) (ch - '0');
    } else if ('A' <= ch && ch <= 'F') {
        return (int) (ch - 'A' + 10);
    } else if ('a' <= ch && ch <= 'f') {
        return (int) (ch - 'a' + 10);
    } else if (ch == '_'){
        return 0x10;
    } else {
        return 0xff;
    }
}
BigInt & BigInt::operator = (const char * varHex) {
    memset(digit, 0, sizeof(digit));
    int varLen = 0, cnt = 0;
    while (varLen < (UINT_DIGIT << 1)) {
        int t = hexCharToInt(varHex[varLen]);
        if (t == 0xff) {
            break;
        } else {
            varLen ++;
            cnt += t != 0x10;
        }
    }
    for (int i = 0; i < varLen; i ++) {
        int t = hexCharToInt(varHex[i]);
        if (t != 0x10) {
            cnt --;
            digit[cnt >> 3] |= t << (cnt << 2);
        }
    }
    return * this;
}
BigInt& BigInt::operator=(string varHex)
{
    memset(digit, 0, sizeof(digit));
    int varLen = 0, cnt = 0;
    while (varLen < (UINT_DIGIT << 1)) {
        int t = hexCharToInt(varHex[varLen]);
        if (t == 0xff) {
            break;
        }
        else {
            varLen++;
            cnt += t != 0x10;
        }
    }
    for (int i = 0; i < varLen; i++) {
        int t = hexCharToInt(varHex[i]);
        if (t != 0x10) {
            cnt--;
            digit[cnt >> 3] |= t << (cnt << 2);
        }
    }
    return *this;
}
BigInt & BigInt::operator = (const BigInt & var) {
    memcpy(digit, var.digit, sizeof(digit));
    return * this;
}

//比较运算
bool BigInt::operator == (const BigInt & var) const {
    for (int i = UINT_DIGIT - 1; i >= 0; i --) {
        if (digit[i] != var.digit[i]) {
            return false;
        }
    }
    return true;
}
bool BigInt::operator < (const BigInt & var) const {
    for (int i = UINT_DIGIT - 1; i >= 0; i --) {
        if (digit[i] != var.digit[i]) {
            return digit[i] < var.digit[i];
        }
    }
    return false;
}
bool BigInt::operator <= (const BigInt & var) const {
    for (int i = UINT_DIGIT - 1; i >= 0; i --) {
        if (digit[i] != var.digit[i]) {
            return digit[i] <= var.digit[i];
        }
    }
    return true;
}
bool BigInt::operator != (const BigInt & var) const {
    return ! operator == (var);
}

bool BigInt::operator > (const BigInt & var) const {
    return ! operator <= (var);
}

bool BigInt::operator >= (const BigInt & var) const {
    return ! operator < (var);
}

//位运算
BigInt BigInt::operator ~ () const {
    BigInt res = 0;
    for (int i = 0; i < UINT_DIGIT; i ++)
        res.digit[i] = ~ digit[i];
    return res;
}
BigInt BigInt::operator << (int var) const {
    if (var == 0) {
        return *this;
    }
    else {
        int offset = var >> 5;
        int offsetA = var & 31;
        int offsetB = 32 - offsetA;
        int onesA = (1 << offsetA) - 1u;
        int onesB = (1 << offsetB) - 1u;
        BigInt res = 0;
        for (int i = UINT_DIGIT - 1; i >= 0; i--) {
            if (i - (int)(offset) >= 0) {
                res.digit[i] |= (digit[i - offset] & onesB) << offsetA;
            }
            if (i - (int)(offset) >= 1) {
                res.digit[i] |= digit[i - offset - 1] >> offsetB & onesA;
            }
        }
        return res;
    }
}
BigInt BigInt::operator >> (int var) const {
    int offset = var >> 5;
    int offsetA = var & 31;
    int offsetB = 32 - offsetA;
    int onesA = (1 << offsetA) - 1u;
    int onesB = (1 << offsetB) - 1u;
    BigInt res = 0;
    for (int i = 0; i < UINT_DIGIT; i++) {
        if (i + offset < UINT_DIGIT) {
            res.digit[i] |= digit[i + offset] >> offsetA & onesB;
        }
        if (i + offset + 1 < UINT_DIGIT) {
            res.digit[i] |= (digit[i + offset + 1] & onesA) << offsetB;
        }
    }
    return res;
}
BigInt & BigInt::operator <<= (int var) {
    * this = operator << (var);
    return * this;
}
BigInt & BigInt::operator >>= (int var) {
    * this = operator >> (var);
    return * this;
}
BigInt & BigInt::operator |= (const BigInt & var) {
    return * this = operator | (var);
}
BigInt & BigInt::operator &= (const BigInt & var) {
    return * this = operator & (var);
}
BigInt & BigInt::operator ^= (const BigInt & var) {
    return * this = operator ^ (var);
}

BigInt BigInt::operator | (const BigInt & var) const {
    BigInt res = 0;
    for (int i = 0; i < UINT_DIGIT; i ++) {
        res.digit[i] = digit[i] | var.digit[i];
    }
    return res;
}
BigInt BigInt::operator & (const BigInt & var) const {
    BigInt res = 0;
    for (int i = 0; i < UINT_DIGIT; i ++) {
        res.digit[i] = digit[i] & var.digit[i];
    }
    return res;
}
BigInt BigInt::operator ^ (const BigInt & var) const {
    BigInt res = 0;
    for (int i = 0; i < UINT_DIGIT; i ++) {
        res.digit[i] = digit[i] ^ var.digit[i];
    }
    return res;
}


//代数运算
BigInt BigInt::operator + (const BigInt& var) const {
    BigInt res = 0;
    int overflow_flag = 0;
    for (int i = 0; i < UINT_DIGIT; i++) {
        uint64 tmp = (uint64)(digit[i]) + (uint64)(var.digit[i]) + (uint64)(overflow_flag);
        res.digit[i] = tmp & 0xffffffff;
        overflow_flag = tmp >> 32 & 0x1;
    }
    return res;
}
BigInt BigInt::operator - (const BigInt& var) const {
    BigInt res = 0;
    int borrow_flag = 0;
    for (int i = 0; i < UINT_DIGIT; i++) {
        uint64 tmp = (uint64)(digit[i]) - (uint64)(var.digit[i]) - (uint64)(borrow_flag);
        res.digit[i] = tmp & 0xffffffff;
        borrow_flag = tmp >> 32 & 0x1;
    }
    return res;
}
BigInt BigInt::operator * (const BigInt& var) const {
    BigInt res = 0;
    for (int i = 0; i < UINT_DIGIT; i++) {
        if (digit[i]) {
            unsigned int overflow = 0;
            for (int j = 0; i + j < UINT_DIGIT; j++) {
                uint64 tmp = (uint64)(digit[i]) * (uint64)(var.digit[j]) + (uint64)(res.digit[i + j]) + (uint64)(overflow);
                res.digit[i + j] = tmp & 0xffffffff;
                overflow = tmp >> 32;
            }
        }
    }
    return res;
}
BigInt BigInt::operator / (const BigInt& var) const {
    int offset = (int)(getLength()) - (int)(var.getLength());
    if (offset < 0) {
        return BigInt("0");
    }
    BigInt res_div(0);
    BigInt res_mod(*this);
    BigInt varOffset = var << offset;
    for (; offset >= 0; varOffset >>= 1, offset--) {
        if (res_mod >= varOffset) {
            res_div.setBit(offset, 1u);
            res_mod -= varOffset;
        }
    }
    return res_div;
}
BigInt BigInt::operator % (const BigInt& var) const {
    int offset = (int)(getLength()) - (int)(var.getLength());
    if (offset < 0) {
        return *this;
    }
    BigInt res_mod(*this);
    BigInt varOffset = var << (int)(offset);
    for (; offset >= 0; varOffset >>= 1, offset--) {
        if (res_mod >= varOffset) {
            res_mod -= varOffset;
        }
    }
    return res_mod;
}
BigInt & BigInt::operator += (const BigInt & var) {
    return * this = operator + (var);
}
BigInt & BigInt::operator -= (const BigInt & var) {
    return * this = operator - (var);
}
BigInt & BigInt::operator *= (const BigInt & var) {
    return * this = operator * (var);
}
BigInt & BigInt::operator /= (const BigInt & var) {
    return * this = operator / (var);
}
BigInt & BigInt::operator %= (const BigInt & var) {
    return * this = operator % (var);
}


//其他函数
uint64 BigInt::toUint64() const {
    return (uint64) (digit[1]) << 32 | (uint64) (digit[0]);
}
int BigInt::getLength() const {
    int i, j;
    for (i = UINT_DIGIT - 1; i >= 0 && digit[i] == 0; i --);
    if (i == -1) {
        return 0u;
    }
    for (j = 31; j >= 0 && (digit[i] >> j & 1) == 0; j --);
    return (int)((i << 5 | j) + 1);
}
void BigInt::setBit(int i, int v) {
    if (i < UINT_LENGTH) {
        if (v == 0) {
            digit[i >> 5] &= ~ (1u << (i & 31));
        } else {
            digit[i >> 5] |= 1u << (i & 31);
        }
    }
}
int BigInt::getBit(int i) const {
    if (i < UINT_LENGTH) {
        return digit[i >> 5] >> (i & 31) & 1u;
    }
    return 0u;
}
std::ostream & operator << (std::ostream & out, const BigInt & var) {
    int i;
    for (i = UINT_DIGIT - 1; i >= 1 && var.digit[i] == 0u; i --);
    for (; i >= 0; i --) {
        out << std::setfill('0') << std::setw(8) <<hex << var.digit[i];
    }
    return out;
}
void BigInt::setDigit(int num,int loc) {
    digit[loc] = num;
}

int BigInt::getDigit(int loc) {
    return digit[loc];
}