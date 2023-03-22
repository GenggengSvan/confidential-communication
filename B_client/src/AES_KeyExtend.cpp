#include <iostream>
#include <bitset>
#include "AES_KeyExtend.h"
using namespace std;

//��4�� Abyte ת��Ϊһ��word����Ϊword�������洢��������С��������word��ǰ8λʵ�ʶ�Ӧ��key4
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
//���ֽ�ѭ������һλ,����[a0, a1, a2, a3]���[a1, a2, a3, a0]
word RotWord(word w)
{
	word w_high = w << 8;
	word w_low = w >> 24;
	word result = w_high | w_low;
	return result;
}

//������word�е�ÿһ���ֽڽ���S-�б任,ע�������һ���ּ��ĸ��ֽ�
word SubWord(word w)
{
	//��ΪS���ǰ��ֽڱ任�����Խ�word����ת��Ϊ4��Abyte
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
// �ֳ�������Կ��չ���õ�����AES-128ֻ��Ҫ10��,���ǿ��ܻ��õ�14�֣�
word Rcon[14] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
				 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
                 0x6c000000, 0xd8000000,0x10000000,0x20000000};

//��Կ��չ���� - ��Nk<=6����Կ������չ�õ� W[Nb*(Nr+1)]��������AES-128��AES-192
void KeyExpansion(const Abyte* Key, word* W)
{
	// W[]��ǰNk�����������key����AES-128����ǰ4����,��AES-192����ǰ6���֣�
	for (int i = 0;i < Nk;i++)
		W[i] = Get_word(Key[4 * i], Key[4 * i + 1], Key[4 * i + 2], Key[4 * i + 3]);

	for (int i = Nk;i < Nb * (Nr + 1);i++) {
		word temp = W[i - 1]; // ��¼ǰһ��word
		if (i % Nk == 0) //���i��Nk�ı���
			temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk - 1];
		else if (Nk ==8 && i % Nk == 4)
			temp = SubWord(temp);
		W[i] = W[i - Nk] ^ temp;
	}
}
