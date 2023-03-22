#include"AES_Cipher.h"
#include"AES_KeyExtend.h"
#include"RSA_Cipher.h"
#include"Packet.h"
#include<iostream>
#include<fstream>
#include<string>
#include<time.h>
#include<WinSock2.h>
#include <WS2tcpip.h>
#include<iomanip>
#include <thread>
#pragma comment (lib,"ws2_32.lib")
using namespace std;
void init_WSA();
void Receive();
ifstream ReadFile();//读入文件函数
SOCKET ConnSocket;//客户端
SOCKET SendSocket;//目的客户端
SOCKADDR_IN servaddr;
SOCKADDR_IN addrClient;//保存客户端的IP地址信息
int len = sizeof(SOCKADDR);

unsigned short DestiontionPort = 4567;
unsigned short SourcePort = 1333;
const char* DestiontionIP = "127.0.0.1";
const char* SourceIP = "127.0.0.1";
Packet* pkt = new Packet();
Packet* pkt_rec = new Packet();

//AES密钥
Abyte* key_AES = new Abyte[4 * Nk];
Abyte* AES_IV = new Abyte[4 * Nk];
Abyte result[4 * Nb];
word w[4 * (Nr + 1)];

//RSA公钥
BigInt des_e = "10001";
BigInt des_n = "86F9AA341FDCF2168D23CEE753BAD4169C6BC3D2148ED6A5F04DF684343078C71B0E4610CAF747C5AA7725EBC9A7C9C2808D258E6F861FB7A89AC215A8CB7F3382F5308B7511E65CC7538A49B6A95D970C56394D9FB784C0E9607E4303B9DDE035B7F04C70345A09097F51269924F7D1F871A8849EBCE1A6EE8D5774015704E1";

BigInt this_e = "10001";
BigInt this_d = "6AEA02F6F9E139F255EA91A9D6F6A1C7F2004A4F07CE54A63E78A95E5D6A28D3AB47D55B0B13B84B0CA903C607E8B326E80DCDCEB857B91AC08C90DEFD13A7BDE96F962AEBAD8DD16417BF1A149516A50F3E16117ABF02B19D99B1A6CDF1A37213F63286856E17375D6FF4F9531A89C6A2920BC2187D4184AB84C386EABE9A2D";
BigInt this_n = "934141168AAAC5F93B2B6616CDDAD966AD71AD5E8329A90CE42C7B48D591F7D2451C17C09A82500F4354FB07705DE35274C31CEBB3A8BE35AB7430B833E0CCCD2CF56564F33D5FE219036C94F87255AB9D9826C65B84190BDE9F0C22120CBA9FD32B547EA56D8806294C6E5D365177A20CACEF3591EDB2C3E7B69AB8AE0546C1";

HANDLE handle_rec;
bool pro = true;

//文件相关属性
char filepath_get[32];
ofstream outfile;
string filepath;
ifstream infile;
int file_len = 0;
int original_file_len = 0;
int totalpacket = 0;
bool file_send = false;

int main()
{
    char model,c;
    cout << "是否使用默认端口号（Y/N）：";
    model = getchar();
    if (model == 'N') {
        cout << "请输入目的端口号：";
        cin >> DestiontionPort;

        cout << "请输入源端口号：";
        cin >> SourcePort;
    }
    while ((c = getchar()) != '\n');
    init_WSA();

    //开始监听，是否有客服端请求连接
    listen(ConnSocket, 100);
    cout << "Start,Waiting.........." << endl;
    SendSocket = accept(ConnSocket, (SOCKADDR*)&servaddr, &len);
    cout << "和用户A成功建立连接！"<<endl;

    //输出AES密钥
    string key = "AES_KEY AES_KEY ";
    for (int i = 0;i < (Nk * 4);i++)//初始化AES密钥
        key_AES[i] = key[i];
    KeyExpansion(key_AES, w); //密钥扩展
    cout << "默认16字节的AES密钥为:";
    for (int i = 0;i < (Nk * 4);i++) {  // 输入密钥
        cout << "0x" << hex << setw(2) << setfill('0') << key_AES[i].to_ulong() << " ";
    }
    cout << endl;

    for (int i = 0;i < (Nk * 4);i++)//初始化AES密钥
        AES_IV[i] = 0x0;

    handle_rec = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Receive, 0, 0, NULL);
    
    while (pro) {
        cout << "请选择进行的操作：" << endl;
        cout << "输入“1”，发送信息；输入“2”，发送文件；输入“3”,重置并发送AES密钥；输入“4”,重置并发送RSA公钥；" << endl;
        model=getchar();
        
        while ((c = getchar()) != '\n');//清空缓冲区
        if (model == '1') {
            pkt->clean();
            pkt->setType(Packet::String);
            string P;
            cout << "请输入任意长度明文：";
            getline(cin, P);
            int len_P = P.length();

            //AES加密信息
            int group = len_P / (Nb * 4) + 1;//明文分组
            int len_temp = 0;
            for (int t = 0;t < group;t++) {
                Abyte P_temp[(4 * Nb)];
                for (int i_temp = 0;len_temp < (t + 1) * Nb * 4;len_temp++) {
                    if (len_temp > len_P) {
                        P_temp[i_temp++] = 0x00;
                    }
                    else
                        P_temp[i_temp++] = P[len_temp];
                }

                if (t == 0) {
                    for (int i_temp = 0; i_temp < Nb * 4; i_temp++) {
                        P_temp[i_temp] = P_temp[i_temp].to_ulong() ^ AES_IV[i_temp].to_ulong();
                    }
                }
                else {
                    for (int i_temp = 0; i_temp < Nb * 4; i_temp++) {
                        P_temp[i_temp] = P_temp[i_temp].to_ulong() ^ pkt->getDataNum(16 * (t - 1) + i_temp).to_ulong();
                    }
                }

                Abyte result[4 * Nb];
                Encryption(P_temp, result, w);
                pkt->setData(result, 4 * Nb);//加密信息封入数据包中

                cout << "加密结果,第" << t + 1 << "组:";//输出加密结果
                for (int j = 0;j < 4 * Nb;j++)
                    cout << hex << result[j].to_ulong() << " ";
                cout << endl;
            }
            send(SendSocket, (char*)pkt, 5136, 0);//传输密文
            
        }
        else if (model == '2') {
            infile = ReadFile();
            if (file_send) {
                //文件名发送
                pkt->setType(Packet::FileName);
                int len_P = filepath.length();
                int group = len_P / (Nb * 4) + 1;//明文分组
                int len_temp = 0;
                for (int t = 0;t < group;t++) {
                    Abyte P_temp[(4 * Nb)];
                    for (int i_temp = 0;len_temp < (t + 1) * Nb * 4;len_temp++) {
                        if (len_temp > len_P) {
                            P_temp[i_temp++] = 0x00;
                        }
                        else
                            P_temp[i_temp++] = filepath[len_temp];
                    }
                    //CBC模式加密
                    if (t == 0) {
                        for (int i_temp = 0; i_temp < Nb * 4; i_temp++) {
                            P_temp[i_temp] = P_temp[i_temp].to_ulong() ^ AES_IV[i_temp].to_ulong();
                        }
                    }
                    else {
                        for (int i_temp = 0; i_temp < Nb * 4; i_temp++) {
                            P_temp[i_temp] = P_temp[i_temp].to_ulong() ^ pkt->getDataNum(16 * (t - 1) + i_temp).to_ulong();
                        }
                    }
                    Abyte result[4 * Nb];
                    Encryption(P_temp, result, w);
                    pkt->setData(result, 4 * Nb);//加密信息封入数据包中
                }
                send(SendSocket, (char*)pkt, 5136, 0);

                //文件内容发送
                for (int i = 0;i < totalpacket;i++) {
                    pkt->clean();
                    pkt->setType(Packet::FileContent);
                    char buf[1024];
                    int len_P;
                    if (file_len >= 1024) {
                        infile.read(buf, 1024);
                        file_len -= 1024;
                        len_P = 1024;
                    }
                    else {
                        infile.read(buf, file_len);
                        file_len = 0;
                        len_P = file_len;
                    }
                    int group = len_P / (Nb * 4) + 1;//明文分组
                    int len_temp = 0;
                    for (int t = 0;t < group;t++) {
                        Abyte P_temp[(4 * Nb)];
                        for (int i_temp = 0;len_temp < (t + 1) * Nb * 4;len_temp++) {
                            if (len_temp > len_P)
                                P_temp[i_temp++] = 0x00;
                            else
                                P_temp[i_temp++] = buf[len_temp];
                        }
                        //CBC模式加密
                        if (t == 0) {
                            for (int i_temp = 0; i_temp < Nb * 4; i_temp++) {
                                P_temp[i_temp] = P_temp[i_temp].to_ulong() ^ AES_IV[i_temp].to_ulong();
                            }
                        }
                        else {
                            for (int i_temp = 0; i_temp < Nb * 4; i_temp++) {
                                P_temp[i_temp] = P_temp[i_temp].to_ulong() ^ pkt->getDataNum(16 * (t - 1) + i_temp).to_ulong();
                            }
                        }
                        Abyte result[4 * Nb];
                        Encryption(P_temp, result, w);
                        pkt->setData(result, 4 * Nb);//加密信息封入数据包中

                        cout << "文件加密结果,第" << dec << t + 1 << "组:";//输出加密结果
                        for (int j = 0;j < 4 * Nb;j++)
                            cout << hex << result[j].to_ulong() << " ";
                        cout << endl;
                    }
                    send(SendSocket, (char*)pkt, 5600, 0);
                }
            }
            file_send = false;
            while ((c = getchar()) != '\n');
        }
        else if (model == '3') {
            string key = "";
            cout << "请输入重置的AES密钥（任意长度字符串）:";
            getline(cin, key);

            for (int i = 0;i < (Nk * 4);i++)
            {
                if (i < key.length())
                    key_AES[i] = key[i];
                else
                    key_AES[i] = 0x0;
            }

            cout << "16字节的AES密钥为:" << endl;
            for (int i = 0;i < (Nk * 4);i++) {
                cout << "0x" << hex << setw(2) << setfill('0') << key_AES[i].to_ulong() << " ";
            }
            cout << endl;
            KeyExpansion(key_AES, w); //密钥扩展
            //RSA加密
            BigInt AES_result;
            for (int i = 0;i < 16;i++) {
                AES_result.setDigit(key_AES[i].to_ulong(), i);
            }
            AES_result = Encrypt(AES_result, des_e, des_n);
            //传输AES密钥
            pkt->clean();
            pkt->setType(Packet::AES);
            pkt->setAESKEY(AES_result);
            cout << "RSA加密后AES密钥为：";
            cout << pkt->getAESKEY() << endl;
            send(SendSocket, (char*)pkt, 5136, 0);
        }
        else if (model == '4') {
            BigInt p, q;
            cout << "自己输入两个大素数/使用程序生成两个大素数(A/B)：";
            model = getchar();
            if (model == 'A') {
                while ((c = getchar()) != '\n');
                cout << "输入p:";
                string temp_p;
                getline(cin, temp_p);
                p = temp_p;
                cout << "输入q:";
                string temp_q;
                getline(cin, temp_q);
                q = temp_q;
            }
            else {
                cout << "生成第一个大素数p......" << endl;
                p = CreatePrime(512);
                cout << p << endl;

                cout << "生成第二个大素数q......" << endl;
                q = CreatePrime(512);
                cout << q << endl;
            }

            BigInt n = p * q;
            BigInt EulerN = (p - BigInt("1")) * (q - BigInt("1"));
            BigInt e = CreatePrime(16);
            while (EulerN % e == 0)
            {
                e = CreatePrime(16);
            }

            BigInt d, y;
            ExtendEuclid(e, EulerN, d, y, EulerN);
            cout << "公开钥：" << endl;
            cout << "e:" << e << endl;
            this_e = e;
            cout << "n:" << n << endl;
            this_n = n;
            cout << "秘密钥：" << endl;
            cout << "d:" << d << endl;
            this_d = d;
            cout << "n:" << n << endl;

            //传输RSA公钥
            pkt->clean();
            pkt->setType(Packet::RSA);
            pkt->setRSAe(e);
            pkt->setRSAn(n);
            send(SendSocket, (char*)pkt, 5136, 0);
        }
        cout << endl;
    }
    closesocket(SendSocket);
    WSACleanup();

        
        
}

void Receive() {
    while (pro) {
        recv(SendSocket, (char*)pkt_rec, 5600, 0);
        
        if (pkt_rec->getType() == Packet::String) {
            int len_P = pkt_rec->getLen();
            int group = len_P / 16;
            Abyte* D_in = pkt_rec->getData();
            cout << endl;
            for (int t = 0;t < group;t++) {
                cout << "接收到的密文,第" << dec << t + 1 << "组:";
                Abyte* D_in_temp = new Abyte[Nb * 4];
                for (int i = 0;i < Nb * 4;i++) {
                    D_in_temp[i] = D_in[t * Nb * 4 + i];
                    cout << hex << D_in_temp[i].to_ulong() << " ";
                }
                Abyte result[4 * Nb];
                Decryptint(D_in_temp, result, w);
                //CBC模式解密信息
                if (t == 0) {
                    for (int i_temp = 0; i_temp < Nb * 4; i_temp++)
                        result[i_temp] = result[i_temp].to_ulong() ^ AES_IV[i_temp].to_ulong();
                }
                else {
                    for (int i_temp = 0; i_temp < Nb * 4; i_temp++)
                        result[i_temp] = result[i_temp].to_ulong() ^ pkt_rec->getDataNum(16 * (t - 1) + i_temp).to_ulong();
                }
                cout << "    解密获得明文：";
                for (int j = 0;j < 4 * Nb;j++)
                    cout << (char)result[j].to_ulong();
                cout << endl;
            }
            cout << endl;
            cout << endl;
            cout << "请选择进行的操作：" << endl;
            cout << "输入“1”，发送信息；输入“2”，发送文件；输入“3”,重置并发送AES密钥；输入“4”,重置并发送RSA公钥；" << endl;
        }
        else if (pkt_rec->getType() == Packet::FileName) {
            int len_P = pkt_rec->getLen();
            int group = len_P / 16;
            Abyte* D_in = pkt_rec->getData();
            cout << endl;
            int filepath_len = 0;
            for (int t = 0;t < group;t++) {
                Abyte* D_in_temp = new Abyte[Nb * 4];
                for (int i = 0;i < Nb * 4;i++) {
                    D_in_temp[i] = D_in[t * Nb * 4 + i];
                }
                Abyte result[4 * Nb];
                Decryptint(D_in_temp, result, w);
                //CBC模式解密信息
                if (t == 0) {
                    for (int i_temp = 0; i_temp < Nb * 4; i_temp++) {
                        result[i_temp] = result[i_temp].to_ulong() ^ AES_IV[i_temp].to_ulong();
                        filepath_get[filepath_len++]= result[i_temp].to_ulong();
                    }
                }
                else {
                    for (int i_temp = 0; i_temp < Nb * 4; i_temp++) {
                        result[i_temp] = result[i_temp].to_ulong() ^ pkt_rec->getDataNum(16 * (t - 1) + i_temp).to_ulong();
                        filepath_get[filepath_len++] = result[i_temp].to_ulong();
                    }
                }
            }
            outfile.open(filepath_get, ios::out | ios::binary);
            if (outfile.is_open()) {
                cout << "成功创建文件" << filepath_get << endl;
            }
        }
        else if (pkt_rec->getType() == Packet::FileContent) {
            int len_P = pkt_rec->getLen();
            int group = len_P / 16;
            Abyte* D_in = pkt_rec->getData();
            
            char buf[1024];
            int buf_len = 0;
            
            for (int t = 0;t < group;t++) {
                Abyte* D_in_temp = new Abyte[Nb * 4];
                cout << "接收文件密文,第" <<dec<< t + 1 << "组:";
                for (int i = 0;i < Nb * 4;i++) {
                    D_in_temp[i] = D_in[(t * 16) + i];
                    cout << hex << D_in_temp[i].to_ulong() << " ";
                }
                cout << endl;
                Abyte result[4 * Nb];
                Decryptint(D_in_temp, result, w);
                //CBC模式解密信息
                if (t == 0) {
                    for (int i_temp = 0; i_temp < Nb * 4; i_temp++) {
                        result[i_temp] = result[i_temp].to_ulong() ^ AES_IV[i_temp].to_ulong();
                        buf[buf_len++] = result[i_temp].to_ulong();
                    }
                }
                else {
                    for (int i_temp = 0; i_temp < Nb * 4; i_temp++) {
                        result[i_temp] = result[i_temp].to_ulong() ^ pkt_rec->getDataNum(16 * (t - 1) + i_temp).to_ulong();
                        buf[buf_len++] = result[i_temp].to_ulong();
                    }
                }
            }
            outfile.write(buf, 1024);
            outfile.flush();
            cout << endl;
            cout << endl;
            cout << "请选择进行的操作：" << endl;
            cout << "输入“1”，发送信息；输入“2”，发送文件；输入“3”,重置并发送AES密钥；输入“4”,重置并发送RSA公钥；" << endl;
        }
        else if (pkt_rec->getType() == Packet::AES) {
            BigInt AESKEY = pkt_rec->getAESKEY();
            cout << endl;
            cout << "接收到的RSA加密的AES密钥为：";
            cout << AESKEY << endl;
            AESKEY = Decrypt(AESKEY, this_d, this_n);
            cout << "接收到的解密后的AES密钥为：";
            for (int i = 0;i < 16;i++) {
                key_AES[i] = AESKEY.getDigit(i);
                cout << "0x" << hex << setw(2) << setfill('0') << key_AES[i].to_ulong() << " ";
            }
            cout << endl;
            KeyExpansion(key_AES, w); //密钥扩展
            cout << endl;
            cout << endl;
            cout << "请选择进行的操作：" << endl;
            cout << "输入“1”，发送信息；输入“2”，发送文件；输入“3”,重置并发送AES密钥；输入“4”,重置并发送RSA公钥；" << endl;
        }
        else if (pkt_rec->getType() == Packet::RSA) {
            
            cout << endl;
            cout << "接收到的RSA公钥为：" << endl;
            des_e = pkt_rec->getRSAe();
            cout <<"e：" << des_e<< endl;
            des_n = pkt_rec->getRSAn();
            cout << "n：" << des_n << endl;

            cout << endl;
            cout << endl;
            cout << "请选择进行的操作：" << endl;
            cout << "输入“1”，发送信息；输入“2”，发送文件；输入“3”,重置并发送AES密钥；输入“4”,重置并发送RSA公钥；" << endl;
        }
        pkt_rec->clean();
        
    }
}

void init_WSA()
{
    WSADATA data;
    WORD version = MAKEWORD(2, 2);
    int info = WSAStartup(version, &data);
    if (info != 0) {
        //找不到 winsock.dll 
        cout << "WSAStartup failed with error: " << info << endl;
        return;
    }
    if (LOBYTE(data.wVersion) != 2 || HIBYTE(data.wVersion) != 2)
    {
        cout << "Could not find a usable version of Winsock.dll" << endl;
        WSACleanup();
    }

    ConnSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//AF_INET使用IPV4地址，使用数据包客户端


    servaddr.sin_port = htons(DestiontionPort);//端口要与服务器相同
    servaddr.sin_family = AF_INET;    //用IPV4地址
    servaddr.sin_addr.S_un.S_addr = inet_addr(DestiontionIP);

    addrClient.sin_family = AF_INET;//使用ipv4的地址
    addrClient.sin_port = htons(SourcePort);//设定应用占用的端口
    addrClient.sin_addr.S_un.S_addr = inet_addr(SourceIP);
    bind(ConnSocket, (SOCKADDR*)&addrClient, sizeof(SOCKADDR));//将套接字serverSocket与端口接收的ip绑定

}

ifstream ReadFile()
{
    cout << "请输入要发送的文件名：";
    cin >> filepath;
    ifstream infile(filepath, ios::in | ios::binary);//以二进制方式打开文件
    if (!infile.is_open()) {
        cout << "文件无法打开!" << endl;
        file_send = false;
    }
    else {
        file_send = true;
        infile.seekg(0, std::ios_base::end);  //将文件流指针定位到流的末尾
        file_len = infile.tellg();
        original_file_len = file_len;
        totalpacket = file_len / 1024 + 1;
        cout << "文件大小为" << file_len << "Bytes,总共有" << totalpacket << "个数据包" << endl;
        infile.seekg(0, std::ios_base::beg);  //将文件流指针重新定位到流的开始
    }
    return infile;
};