#include"RSA_Cipher.h"

BigInt CreateOddNum(int len) {
    srand(time(0));
    len = len / 4 + ((len % 4 > 0) ? 1 : 0);//��Ϊstring��ʹ��ʮ�����Ʊ�ʾ������λ��Ӧ����4�ı��������ǽ�������Ϊ4�ı���
    char hex_table[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
    char hex_table_odd[] = { '1','3','5','7','9','B','D','F' };
    string str = "";
    str.push_back(hex_table[rand() % 8 + 8]);//���λ�̶�Ϊ1
    for (int i = 1;i < len - 1;i++) {
        str.push_back(hex_table[rand() % 16]);
    }
    str.push_back(hex_table_odd[rand() % 8]);//���һλȷ����Ϊ����

    return BigInt(str);
}

BigInt PowMod(BigInt x, const BigInt& m, const BigInt& n) {
    BigInt res = 1ull;
    int mLen = m.getLength();
    x %= n;
    clock_t begin = clock();
    for (int i = 0; i < mLen; i++) {
        if (m.getBit(i)) {
            res = res * x % n;
        }
        x = x * x % n;
    }
    return res;
}

bool isPrime(BigInt num) {

    //��n-1д��2��k�η�*t����ʽ
    BigInt m = num - 1;
    int k = 0;
    while (m.getBit(0) == 0)//���t������������ִ�С��൱��t%2
    {
        k++;
        m >>= 1;//t�����ƶ�һλ���൱��t/2
    }
    //����20�ֲ��ԣ����ӿɿ���
    for (int i = 0; i <= 20; i++)
    {
        BigInt a = CreateOddNum(3);//ѡȡ����a��1<=a<=n-1
        BigInt x = PowMod(a, m, num);
        BigInt y;
        for (int i = 0; i < k; i++)
        {
            y = x * x % num;
            if (y == 1 && x != 1 && x != (num - 1))
                return false;
            x = y;
        }
        if (y != 1)
            return false;
    }
    return true;
}

BigInt CreatePrime(int len) {
    BigInt result = CreateOddNum(len);
    BigInt temp = 2;
    int count = 0;
    clock_t begin = clock();
    while (!isPrime(result))
    {
        result = result + temp;
        count++;
        if (count > 10) {
            result = CreateOddNum(len);
            count = 0;
        }
    }
    return result;
}

bool isEven(const BigInt& b) {
    if (b.getBit(0) == 0)
        return true;
    return false;
}

BigInt Encrypt(BigInt m, BigInt e, BigInt n) {
    return PowMod(m, e, n);
}

BigInt Decrypt(BigInt c, BigInt d, BigInt n) {
    return PowMod(c, d, n);
}

void ExtendEuclid(BigInt a, BigInt b, BigInt& x, BigInt& y, const BigInt& m) {
    if (a == 0) {
        x = 0, y = 1;
        return;
    }
    BigInt c = b / a, d = b % a;
    ExtendEuclid(d, a, y, x, m);
    x = (x + m - (c * y) % m) % m;
}