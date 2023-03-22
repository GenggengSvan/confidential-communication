#include <bitset>
#include"AES_data.h"
using namespace std;

word Get_word(Abyte k1, Abyte k2, Abyte k3, Abyte k4);
word RotWord(word w);
word SubWord(word tw);
void KeyExpansion(const Abyte *Key, word *W);

