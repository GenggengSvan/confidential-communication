#include <iostream>
#include <bitset>
#include "AES_Cipher.h"
using namespace std;



//1.�ֽڱ任
void ByteSub(Abyte **state) {
	for (int i = 0;i < 4;i++) {
		for (int j = 0;j < Nb;j++) {
			int a = 0;
			int k = 1;
			for (int t = 0;t < 8;t++) {
				a += state[i][j][t] * k;
				k *= 2;
			}
			state[i][j] = AESReplaceTable[a];
		}
	}
}
//2.�б任
void ShiftRow(Abyte** state) {
	for (int i = 0;i < 4;i++) {
		Abyte *temp=new Abyte[Nb];
		for (int j = 0;j < Nb;j++) {
			 temp[j]= state[i][j];
		}
		int Shiftnum = ShiftNum[(Nb - 4) / 2][i];
		for (int j = 0;j < Nb;j++) {
			state[i][j] = temp[(j+Shiftnum )%Nb];
		}
		
	}
}
//GF(2^8)�ϵĳ˷�
Abyte GFMUL(Abyte a, Abyte b) {
	Abyte p = 0,temp;
	for (int counter = 0; counter < 8; counter++) {
		if ((b & Abyte(1)) != 0) 
			p ^= a;
		temp = a >> 7;
		a <<= 1;
		if (temp != 0) 
			a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
		b >>= 1;
	}
	return p;
}
//3.�л��
void MixColumn(Abyte** state)
{
	Abyte temp[4];
	for (int i = 0; i < Nb; ++i)
	{
		for (int j = 0; j < 4; ++j)
			temp[j] =state[j][i];

		for (int j = 0;j < 4;j++) {
			state[j][i] = GFMUL(c_MixColumns[0][(4 - j) % 4], temp[0]);
			for (int t = 1;t < 4;t++)
				state[j][i] ^= GFMUL(c_MixColumns[0][(4 + t - j) % 4], temp[t]);
		}
	}
}
//4.����Կ�� - ��ÿһ������չ��Կ�������
void AddRoundKey(Abyte** state, word *w)
{
	for (int t = 0; t < Nb; t++)
	{
		//����ʹ�÷���
		Abyte temp[4];
		for (int i = 3;i >=0;i--) 
			for (int j = 0;j<8;j++) 
				temp[3-i][j] = w[t][8*i+j];
		for (int i = 0;i < 4;i++) 
			state[i][t] = temp[i] ^ state[i][t];
	}
}


void Test(Abyte** state) {
	for (int i = 0;i < 4;i++) {
		for (int j = 0;j < Nb;j++) {
			cout<<state[i][j]<<" ";
		}
		cout << endl;
	}
	cout << endl;
}
// 5 ���ܺ���
void Encryption(const Abyte *in, Abyte *out, word *w) {
	//��ʼ��state,��Ϊ����ľ���
	Abyte** state = new Abyte*[4];
	for (int i = 0;i < 4;i++) {
		state[i] = new Abyte[Nb];
	}
	for (int i = 0;i < Nb;i++) {
		for (int j = 0;j < 4;j++) {
			state[j][i] = in[4 * i + j];
		}
	}

	//��ʼ����ǰ�ֵ�����Կ,ע�������ȡ�ĳ��ȵ��ڷ��鳤��
	word *Roundkey=new word[Nb];
	for (int i = 0; i < Nb; ++i)
		Roundkey[i] = w[i];
	AddRoundKey(state, Roundkey);
	for (int round = 1; round < Nr; ++round)
	{
		ByteSub(state);
		ShiftRow(state);
		MixColumn(state);
		for (int i = 0; i < Nb; ++i)
			Roundkey[i] = w[4 * round + i];
		AddRoundKey(state, Roundkey);
	}
	ByteSub(state);
	ShiftRow(state);
	for (int i = 0; i < Nb; ++i)
		Roundkey[i] = w[4 * Nr + i];
	AddRoundKey(state, Roundkey);
	//������鸳ֵ
	for (int i = 0;i < Nb;i++) {
		for (int j = 0;j < 4;j++) {
			out[4 * i + j] = state[j][i];
		}
	}

	delete[]Roundkey;
	for (int i = 0;i < 4;i++) {
		delete[]state[i];
	}
	delete[]state;
}
//------------------------------------------------------------------------------//
//1.�����ֽڴ���
void InvByteSub(Abyte** state) {
	for (int i = 0;i < 4;i++) {
		for (int j = 0;j < Nb;j++) {
			int a = 0;
			int k = 1;
			for (int t = 0;t < 8;t++) {
				a += state[i][j][t] * k;
				k *= 2;
			}
			state[i][j] = InvAESReplaceTable[a];
		}
	}
}
//2.������λ�ơ�������ѭ���ƶ�
void InvShiftRow(Abyte** state) {
	for (int i = 0;i < 4;i++) {
		Abyte* temp = new Abyte[Nb];
		for (int j = 0;j < Nb;j++) {
			temp[j] = state[i][j];
		}
		int Shiftnum = ShiftNum[(Nb - 4) / 2][i];
		for (int j = Nb;j < 2*Nb;j++) {
			state[i][j-Nb] = temp[((j-Shiftnum) % Nb)];
		}

	}
}
//3.�����л��
void InvMixColumn(Abyte** state) {
	Abyte temp[4];
	for (int i = 0; i < Nb; ++i)
	{
		for (int j = 0; j < 4; ++j)
			temp[j] = state[j][i];

		for (int j = 0;j < 4;j++)
			state[j][i] = GFMUL(c_MixColumns[1][(4 - j) % 4], temp[0]) ^ GFMUL(c_MixColumns[1][(5 - j) % 4], temp[1]) ^ GFMUL(c_MixColumns[1][(6 - j) % 4], temp[2]) ^ GFMUL(c_MixColumns[1][(7 - j) % 4], temp[3]);
	}
}
//���ܺ���
void Decryptint(const Abyte* in, Abyte* out, word* w) {
	//��ʼ��state,��Ϊ����ľ���
	Abyte** state = new Abyte * [4];
	for (int i = 0;i < 4;i++) {
		state[i] = new Abyte[Nb];
	}
	for (int i = 0;i < Nb;i++) {
		for (int j = 0;j < 4;j++) {
			state[j][i] = in[4 * i + j];
		}
	}

	//��ʼ����ǰ�ֵ�����Կ,ע�������ȡ�ĳ��ȵ��ڷ��鳤��
	word* Roundkey = new word[Nb];
	for (int i = 0; i < Nb; ++i)
		Roundkey[i] = w[4*Nr+i];
	AddRoundKey(state, Roundkey);

	for (int round = Nr - 1; round > 0; round--)
	{
		InvShiftRow(state);
		InvByteSub(state);
		for (int i = 0; i < Nb; i++)
			Roundkey[i] = w[4 * round + i];
		AddRoundKey(state, Roundkey);
		InvMixColumn(state);
		
	}
	InvShiftRow(state);
	InvByteSub(state);
	for (int i = 0; i < Nb; i++)
		Roundkey[i] = w[i];
	AddRoundKey(state, Roundkey);
	//������鸳ֵ
	for (int i = 0;i < Nb;i++) {
		for (int j = 0;j < 4;j++) {
			out[4 * i + j] = state[j][i];
		}
	}
}
