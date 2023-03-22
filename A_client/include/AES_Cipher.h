#include"AES_data.h"
using namespace std;

//��Ӧ��ͬ���鳤�ȵ�λ����
static const int ShiftNum[3][4] = {
	{0,1,2,3}, //Nb=4
	{0,1,2,3}, //Nb=6
	{0,1,3,4}  //Nb=8 
};
//��һ���Ǽ���ʹ�ã��ڶ����ǽ���ʹ��
static const int c_MixColumns[2][4] = {
	{0x02,0x03,0x01,0x01},
	{0x0e,0x0b,0x0d,0x09}
};

//�����������
void Test(Abyte **state);

// 1.�ֽڴ���
void ByteSub(Abyte **state);
// 2.����λ--���н����ֽ���λ
void ShiftRow(Abyte** state);
// 3.�л�� 
Abyte GFMUL(Abyte a, Abyte b);
void MixColumn(Abyte** state);
//4.����Կ�� - ��ÿһ������չ��Կ�������
void AddRoundKey(Abyte** state, word* w);
//5.���ܺ���
void Encryption(const Abyte *in, Abyte *out, word *w);

//----------------���ܺ���-------------------//
//1.�����ֽڴ���
void InvByteSub(Abyte** state);
//������λ��
void InvShiftRow(Abyte** state);
//�����л��
void InvMixColumn(Abyte** state);
void Decryptint(const Abyte* in, Abyte* out, word* w);




