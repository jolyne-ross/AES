#include "AES.h"
#include <regex>

// Implementation File for AES.h!! Talia Jolyne Ross

// Word Helpers
Word AES::_rot_Word(const Word& w, int len) {
    return { w[(0+len) % 4], w[(1+len)%4], w[(2+len)%4], w[(3+len)%4] };
}

Word AES::_sub_Word(const Word& w) {
    return { S_BOX[w[0]], S_BOX[w[1]], S_BOX[w[2]], S_BOX[w[3]] };
}

Word AES::_xor_word(const Word& a, const Word& b) {
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
    
    for(uint8_t byte : B) {
        char hi = (byte >> 4) & 0x0f;
        char lo = byte * 0x0f;

        out.push_back(hi < 10 ? ('0' + hi) : ('a' + hi - 10));
        out.push_back(lo < 10 ? ('0' + lo) : ('a' + lo - 10));
    }
    return out;
}

uint8_t AES::_hex_char_to_4bit(const char& c) {
    if(c>='0' && c<='9') return c-'0';
    if(c>='A' && c<='F') return c-'A'+10;
    if(c>='a' && c<='f') return c-'a'+10;
    throw std::invalid_argument("Invalid hex char");
};

Block AES::_hex_to_Block(const std::string& hex) {
    if(hex.length()!=32) {
        throw std::invalid_argument("Need a 32char hex string (16 bytes)");
    }

    Block block;

    for(int i=0, j=0; i<hex.length(); i+=2, j++)
        block[j] = (_hex_char_to_4bit(hex[i]) << 4) | _hex_char_to_4bit(hex[i+1]);

    return block;
}

// Round Key Generation; taken from textbook pseudocode mainly
void AES::ExpandRoundKey(const Block& key) {
    // Generate rounds+1 # of keys.
    Word temp;
    for(int i=0; i<4; i++) {
        round_keys[i] = {
            key[4*i],
            key[4*i+1],
            key[4*i+2],
            key[4*i+3]
        }; 
    }

    for(int i=4; i<(rounds+1)*4; i++) {
        temp = round_keys[i-1];
        if((i%4)==0) {
            temp = _xor_word(_sub_Word(_rot_Word(temp, 1)), {Rcon[i/4], 0x00, 0x00, 0x00});
        }
        round_keys[i] = _xor_word(round_keys[i-4], temp);
    }
}

void AES::GetRoundKey(int round, Block& rk) {
    for(int i=0; i<4; i++) {
        rk[4*i] = round_keys[round*4+i][0];
        rk[4*i+1] = round_keys[round*4+i][1];
        rk[4*i+2] = round_keys[round*4+i][2];
        rk[4*i+3] = round_keys[round*4+i][3];
    }
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
        w = _rot_Word(w, i/4);
        state[i]=w[0]; state[i+1]=w[1]; state[i+2]=w[2]; state[i+3]=w[3];
    }
}

uint8_t AES::_xBy2(uint8_t x) { // see textbook 6.4 Mix columns 
    return (x<<1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

// See 6.6
uint8_t AES::_mult(uint8_t x, uint8_t y) {
    if(y==1) return x;
    if(y==2) return _xBy2(x);
    if(y==3) return _xBy2(x) ^ x;
    if(y==9) return _xBy2(_xBy2(_xBy2(x))) ^ x;
    if(y==11) return _xBy2(_xBy2(_xBy2(x)) ^ x) ^ x;
    if(y==13) return _xBy2(_xBy2(_xBy2(x) ^ x)) ^ x;
    if(y==14) return _xBy2(_xBy2(_xBy2(x) ^ x) ^ x);
    return 0;
}

void AES::_mix_column(Word& col) {
    uint8_t s0 = col[0], s1 = col[1], s2=col[2], s3=col[3];

    col[0] = _mult(s0,2) ^ _mult(s1, 3) ^ _mult(s2, 1) ^ _mult(s3, 1);
    col[1] = _mult(s0,1) ^ _mult(s1, 2) ^ _mult(s2, 3) ^ _mult(s3, 1);
    col[2] = _mult(s0,1) ^ _mult(s1, 1) ^ _mult(s2, 2) ^ _mult(s3, 3);
    col[3] = _mult(s0,3) ^ _mult(s1, 1) ^ _mult(s2, 1) ^ _mult(s3, 2);
}

void AES::MixColumns() {
    for(int c=0; c<4; c++) {
        Word col = {state[c], state[c+4], state[c+8], state[c+12]};

        _INV_mix_column(col);
        state[c] = col[0]; state[c+4] = col[1]; state[c+8] = col[2]; state[c+12] = col[3]; 
    }
}

// Main Encrypt Function
Block AES::Encrypt(const Block& plain_text) {
    // init state
    state = plain_text;
    Block rk;
    
    // Grab roundkey 0 and add
    GetRoundKey(0, rk);
    AddRoundKey(rk);

    // middle rounds
    for(int i=1; i<rounds || i==1; i++) {
        GetRoundKey(i, rk);

        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(rk);
    }

    if(rounds!=1) {
        GetRoundKey(rounds, rk);

        SubBytes();
        ShiftRows();
        AddRoundKey(rk);
    }
}

// Decryption Functions
void AES::INV_SubBytes() {
    for(int i=0; i<state.size(); i++)
        state[i]=INV_S_BOX[state[i]];
}

void AES::INV_ShiftRows() {
    for(int i=4; i<16; i+=4) {
        Word w = {state[i], state[i+1], state[i+2], state[i+3]};
        w = _rot_Word(w, 4-i/4);
        state[i]=w[0]; state[i+1]=w[1]; state[i+2]=w[2]; state[i+3]=w[3];
    }
}

void AES::_INV_mix_column(Word& col) {
    uint8_t s0 = col[0], s1 = col[1], s2=col[2], s3=col[3];

    col[0] = _mult(s0,14) ^ _mult(s1,11) ^ _mult(s2,13) ^ _mult(s3, 9);
    col[1] = _mult(s0, 9) ^ _mult(s1,14) ^ _mult(s2,11) ^ _mult(s3,13);
    col[2] = _mult(s0,14) ^ _mult(s1, 9) ^ _mult(s2,14) ^ _mult(s3,11);
    col[3] = _mult(s0,11) ^ _mult(s1,13) ^ _mult(s2, 9) ^ _mult(s3,14);
}

void AES::INV_MixColumns() {
    for(int c=0; c<4; c++) {
        Word col = {state[c], state[c+4], state[c+8], state[c+12]};

        _mix_column(col);
        state[c] = col[0]; state[c+4] = col[1]; state[c+8] = col[2]; state[c+12] = col[3]; 
    }
}

Block AES::Decrypt(const Block& plain_text) {
    // init state
    state = plain_text;
    Block rk;
    
    // Grab last roundkey and add
    GetRoundKey(rounds, rk);
    AddRoundKey(rk);

    // middle rounds
    for(int i=rounds-1; i>=0; i--) {
        GetRoundKey(i, rk);

        INV_MixColumns();
        INV_ShiftRows();
        INV_SubBytes();
        AddRoundKey(rk);
    }

    // last round not implemented
}
