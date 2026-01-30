#include <AES.h>
#include <regex>

// Implementation File for AES.h!! Talia Jolyne Ross

// Word Helpers
void AES::_rot_Word(Word& w, int len) {
    w = { w[(0+len) % 4], w[(1+len)%4], w[(2+len)%4], w[(3+len)%4] };
}

void AES::_sub_Word(Word& w) {
    w = { S_BOX[w[0]], S_BOX[w[1]], S_BOX[w[2]], S_BOX[w[3]] };
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

// Encryption Functions
void AES::AddRoundKey(const Block& round_key) {
    for(int i=0; i<state.size(); i++) 
        state[i] ^= round_key[i];
}

void AES::SubBytes() {
    for(int i=0; i<state.size(); i++)
        state[i] = S_BOX[state[i]];
}

void AES::ShiftRows() {
    for(int i=4; i<16; i+=4) {
        Word w = {state[i], state[i+1], state[i+2], state[i+3]};
        _rot_Word(w, i/4);
        state[i]=w[0]; state[i+1]=w[1]; state[i+2]=w[2]; state[i+3]=w[3];
    }
}

Byte xBy2(Byte x) { // see textbook 6.4 Mix columns 
    x = (x<<1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

Byte multiply(Byte x, Byte y) {
    if(y==1) return x;
    if(y==2) return xBy2(x);
    if(y==3) return xBy2(x) ^ x; // see 6.6
}

void _mix_column(Word& col) {
    uint8_t s0 = col[0], s1 = col[1], s2=col[2], s3=col[3];

    col[0] = multiply(s0,2) ^ multiply(s1, 3) ^ multiply(s2, 1) ^ multiply(s3, 1);
    col[1] = multiply(s0,1) ^ multiply(s1, 2) ^ multiply(s2, 3) ^ multiply(s3, 1);
    col[2] = multiply(s0,1) ^ multiply(s1, 1) ^ multiply(s2, 2) ^ multiply(s3, 3);
    col[3] = multiply(s0,3) ^ multiply(s1, 1) ^ multiply(s2, 1) ^ multiply(s3, 2);
}

void AES::MixColumns() {
    for(int c=0; c<4; c++) {
        Word col = {state[c], state[c+4], state[c+8], state[c+12]};

        _mix_column(col);
        state[c] = col[c]; state[c+4] = col[c+4]; state[c+8] = col[c+8]; state[c+12] = col[c+12]; 
    }
}
