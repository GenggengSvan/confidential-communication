#include <iostream>
#include <bitset>
#include "AES_KeyExtend.h"
using namespace std;

//将4个 Abyte 转换为一个word，因为word这个数组存储二进制是小端序，所以word的前8位实际对应的key4
word Get_word(Abyte k1, Abyte k2, Abyte k3, Abyte k4)
{
	word result;
	for (int i = 0;i < 8;i++) 
		result[24 + i] = k1[i];
	for (int i = 0;i < 8;i++) 
		result[16 + i] = k2[i];
	for (int i = 0;i < 8;i++) 
		result[8 + i] = k3[i];
	for (int i = 0;i < 8;i++) 
		result[i] = k4[i];
	return result;
}
//按字节循环左移一位,即把[a0, a1, a2, a3]变成[a1, a2, a3, a0]
word RotWord(word w)
{
	word w_high = w << 8;
	word w_low = w >> 24;
	word result = w_high | w_low;
	return result;
}

//对输入word中的每一个字节进行S-盒变换,注意输入的一个字即四个字节
word SubWord(word w)
{
	//因为S和是按字节变换，所以将word类型转换为4个Abyte
	Abyte result[4];
	for (int i = 3;i >= 0;i--) {
		for (int j = 0;j < 8;j++) {
			result[3 - i][j] = w[8 * i + j];
		}
	}
	for (int i = 0;i < 4;i++) {
		int a = 0;
		int k = 1;
		for (int t = 0;t < 8;t++) {
			a += result[i][t] * k;
			k *= 2;
		}
		result[i]= AESReplaceTable[a];
	}
	w = Get_word(result[0], result[1], result[2], result[3]);
	return w;
}
// 轮常数，密钥扩展中用到。（AES-128只需要10轮,但是可能会用到14轮）
word Rcon[14] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
				 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
                 0x6c000000, 0xd8000000,0x10000000,0x20000000};

//密钥扩展函数 - 对Nk<=6的密钥进行扩展得到 W[Nb*(Nr+1)]，适用于AES-128和AES-192
void KeyExpansion(const Abyte* Key, word* W)
{
	// W[]的前Nk个字是输入的key（在AES-128中是前4个字,在AES-192中是前6个字）
	for (int i = 0;i < Nk;i++)
		W[i] = Get_word(Key[4 * i], Key[4 * i + 1], Key[4 * i + 2], Key[4 * i + 3]);

	for (int i = Nk;i < Nb * (Nr + 1);i++) {
		word temp = W[i - 1]; // 记录前一个word
		if (i % Nk == 0) //如果i是Nk的倍数
			temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk - 1];
		else if (Nk ==8 && i % Nk == 4)
			temp = SubWord(temp);
		W[i] = W[i - Nk] ^ temp;
	}
}
