#include"AES_data.h"
using namespace std;

//对应不同分组长度的位移量
static const int ShiftNum[3][4] = {
	{0,1,2,3}, //Nb=4
	{0,1,2,3}, //Nb=6
	{0,1,3,4}  //Nb=8 
};
//第一行是加密使用；第二行是解密使用
static const int c_MixColumns[2][4] = {
	{0x02,0x03,0x01,0x01},
	{0x0e,0x0b,0x0d,0x09}
};

//测试输出函数
void Test(Abyte **state);

// 1.字节代换
void ByteSub(Abyte **state);
// 2.行移位--按行进行字节移位
void ShiftRow(Abyte** state);
// 3.列混合 
Abyte GFMUL(Abyte a, Abyte b);
void MixColumn(Abyte** state);
//4.轮密钥加 - 将每一列与扩展密钥进行异或
void AddRoundKey(Abyte** state, word* w);
//5.加密函数
void Encryption(const Abyte *in, Abyte *out, word *w);

//----------------解密函数-------------------//
//1.反向字节代换
void InvByteSub(Abyte** state);
//反向行位移
void InvShiftRow(Abyte** state);
//反向列混合
void InvMixColumn(Abyte** state);
void Decryptint(const Abyte* in, Abyte* out, word* w);




