#include <iostream>
#include "AES.h"

// Test function/Assignment 1 - Task 3

int main() {
    Block plain = {0x48,0x69,0x48,0x65,0x6C,0x6C,0x6F,0x48,0x65,0x79,0x48,0x69,0x69,0x69,0x69,0x69};
    Block key   = {0x54,0x61,0x6C,0x69,0x61,0x4A,0x6F,0x6C,0x79,0x6E,0x65,0x52,0x6F,0x73,0x73,0x2E};
    AES aes = AES(key, 1);

    std::cout<<"Talia Jolyne Ross Task 3 for Assignment 1!!!\n";

    Block cipher = aes.Encrypt(plain);
    std::cout<<"\nCipher Text: [";
    for(int i=0; i<16; i++) std::cout<<std::hex<<static_cast<int>(cipher[i]);
    std::cout<<"]\n";
    plain = aes.Decrypt(cipher);
    std::cout<<"\nDeciphered Plain Text: [";
    for(int i=0; i<16; i++) std::cout<<plain[i];
    std::cout<<"]\n";
}
