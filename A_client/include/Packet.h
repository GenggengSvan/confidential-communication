#include"AES_data.h"
#include"BigInt.h"


class Packet {
private:
	int type;
	BigInt bigint1;
	BigInt bigint2;
	int len;
	Abyte Data[1024];//Êý¾Ý
	

public:
	enum { Null,RSA,AES,String, FileName, FileContent };
	Packet() {
		type = Packet::Null;
		len = 0;
		BigInt bigint1 = 0;
		BigInt bigint2 = 0;
		memset(Data, 0, 1024);
		
	};

	void clean() {
		type = Packet::Null;
		len = 0;
		BigInt bigint1 = 0;
		BigInt bigint2 = 0;
		memset(Data, 0, 1024);
	};

	void setType(int t) { type = t; };
	int getType() { return type; }

	void setRSAe(BigInt s) { bigint1 = s; };
	BigInt getRSAe() { return bigint1; };

	void setRSAn(BigInt s) { bigint2 = s; };
	BigInt getRSAn() { return bigint2; };

	void setAESKEY(BigInt key) { bigint1 = key; };
	BigInt getAESKEY() { return bigint1; };
	
	void setData(Abyte* data,int num) { 
		for (int i = len;i < len+num;i++) {
			Data[i] = data[i-len];
		}
		len +=num;
	};
	Abyte* getData() { return Data; };
	Abyte getDataNum(int a) { return Data[a]; };
	int getLen() { return len; };
	

};