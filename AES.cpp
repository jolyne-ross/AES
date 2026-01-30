#include <AES.h>
#include <regex>

// Implementation File for AES.h

// Word Helpers
Word AES::_rot_Word(Word& w) {
    return { w[1], w[2], w[3], w[0] };
}

Word AES::_sub_Word(Word& w) {
    return { S_BOX[w[0]], S_BOX[w[1]], S_BOX[w[2]], S_BOX[w[3]] };
}

Word AES::_xor_word(Word& a, Word& b) {
    return {
        uint8_t(a[0]^b[0]),
        uint8_t(a[1]^b[1]),
        uint8_t(a[2]^b[2]),
        uint8_t(a[3]^b[3])
    };
}

// Conversion Helpers
std::string AES::_Block_to_hex(const Block& B) {
    std::string out;
    out.reserve(32);
    
    for(Byte byte : B) {
        
    }
}

uint8_t _hex_char_to_4bit(const char& c) {
    if(c>='0' && c<='9') return c-'0';
    if(c>='A' && c<='F') return c-'A'+10;
    if(c>='a' && c<='f') return c-'a'+10;
    throw std::invalid_argument("Invalid hex char");
};

Block AES::_hex_to_Block(const std::string& hex) {
    if(!hex.length()!=32) {
        throw std::invalid_argument("Need a 32char hex string (16 bytes)");
    }

    Block block;

    for(int i=0, j=0; i<hex.length(); i+=2, j++)
        block[j] = (_hex_char_to_4bit(hex[i]) << 4) | _hex_char_to_4bit(hex[i+1]);

    return block;
}
