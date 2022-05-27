#include <stdio.h>
#include <string>
#include <iostream>
#include "odocrypt.h"
#include <algorithm>

using namespace std;

std::string byte_2_str(char* bytes, int size) {
    char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B','C','D','E','F' };
    std::string str;
    for (int i = 0; i < size; ++i) {
        const char ch = bytes[i];
        str.append(&hex[(ch & 0xF0) >> 4], 1);
        str.append(&hex[ch & 0xF], 1);
    }

    return str;
}

std::string byte2lestr(char* bytes, int size) {
    char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B','C','D','E','F' };
    std::string str;
    for (int i = 0; i < size; ++i) {
        const char ch = bytes[size - i - 1];
        str.append(&hex[(ch & 0xF0) >> 4], 1);
        str.append(&hex[ch & 0xF], 1);
    }
    return str;
}

inline int hexchar(char c) {
    if (c >= 'a') {
        c -= 0x20;
    }
    return c - (c >= 'A' ? ('A' - 10) : '0');
}

string reverseHex(string hexstr) {
    string r;
    r.resize(hexstr.length());
    for (int i = 0; i < hexstr.length(); i+=2) {
        r.at(i) = *(hexstr.data() + (hexstr.length() - i - 2));
        r.at(i + 1) = *(hexstr.data() + (hexstr.length() - i - 1));
    }
    return r;
}

void genparam(uint32_t key) {
    OdoCrypt cry = OdoCrypt(key);
    string mask1, mask2;
    string rotation1, rotation2;
    for (int i = 0; i < OdoCrypt::PBOX_SUBROUNDS; i++) {
        // 构建简化运算数据
        for (int j = 0; j < OdoCrypt::STATE_SIZE / 2; j++) {
            for (int p = 0; p < 2; p++) {
                int n = sizeof(uint64_t);
                string str = byte2lestr((char*)cry.Permutation[0].mask[i]+n*j, n);
                mask1.insert(0, str);
                string str2 = byte2lestr((char*)cry.Permutation[1].mask[i] + n * j, n);
                mask2.insert(0, str2);
            }
        }
    }
    unsigned char rot1[5];
    unsigned char rot2[5];
    for (int i = 0; i < OdoCrypt::PBOX_SUBROUNDS - 1; i++) {
        for (int j = 0; j < 5; j++) {
            rot1[j] = (unsigned char)cry.Permutation[0].rotation[i][j] & 0xff;
            rot2[j] = (unsigned char)cry.Permutation[1].rotation[i][j] & 0xff;
        }
        string str = byte2lestr((char*)rot1, sizeof(rot1));
        rotation1.insert(0, str);
        string str2 = byte2lestr((char*)rot2, sizeof(rot2));
        rotation2.insert(0, str2);
    }
    mask1.insert(0, std::to_string(mask1.length() * 4) + "'h");
    mask2.insert(0, std::to_string(mask2.length() * 4) + "'h");

    rotation1.insert(0, std::to_string(rotation1.length() * 4) + "'h");
    rotation2.insert(0, std::to_string(rotation2.length() * 4) + "'h");

    string rotation, roundKey;
    rotation = byte2lestr((char*)cry.Rotations, sizeof(cry.Rotations));
    rotation.insert(0, std::to_string(rotation.length() * 4) + "'h");
    roundKey = byte2lestr((char*)cry.RoundKey, sizeof(cry.RoundKey));
    roundKey.insert(0, std::to_string(roundKey.length() * 4) + "'h");

    string sbox1 = "'{", sbox2 = "'{";

    for (int i = 0; i < OdoCrypt::SMALL_SBOX_COUNT; i++) {
        string str = byte2lestr((char*)cry.Sbox1[i], sizeof(cry.Sbox1[i]));
        str.insert(0, std::to_string(str.length() * 4) + "'h");
        sbox1.append(str);
        sbox1.append(",");
    }
    sbox1.at(sbox1.length() - 1) = '}';
    sbox1.append(";");
    for (int i = 0; i < OdoCrypt::LARGE_SBOX_COUNT; i++) {
        string str = byte2lestr((char*)cry.Sbox2[i], sizeof(cry.Sbox2[i]));
        str.insert(0, std::to_string(str.length() * 4) + "'h");
        sbox2.append(str);
        sbox2.append(",");
    }
    sbox2.at(sbox1.length() - 1) = '}';
    sbox2.append(";");
    std::cout << mask1 << std::endl;
    std::cout << mask2 << std::endl;
    std::cout << rotation1 << std::endl;
    std::cout << rotation2 << std::endl;
    std::cout << roundKey << std::endl;
    std::cout << rotation << std::endl;
    std::cout << sbox1 << std::endl;
    std::cout << sbox2 << std::endl;
} 

int main() {
    char cipher[OdoCrypt::DIGEST_SIZE] = {};


    std::string str( "020e00209941a705b841378e7b8cbcebd1de2e57b80f97488fa4cb7b9dcb2118f50bb11ae64d39be36483e152f6e7c6bad7e4d878bc7eaa5ee5f41d68638109b5a07a62b83656762e30f191a00000000");
    uint32_t key = 1650240000;


    genparam(key);

    char plain[OdoCrypt::DIGEST_SIZE];
    for (int i = 0; i < OdoCrypt::DIGEST_SIZE; i++) {
        int n = hexchar(str.at(i * 2)) * 16 + hexchar(str.at(i * 2 + 1));
        plain[i] = n;
    }
    

    OdoCrypt cry = OdoCrypt(key);
    string result;

    
    uint64_t state[OdoCrypt::STATE_SIZE];
    cry.Unpack(state, plain);
    cry.PreMix(state);
    for (int round = 0; round < OdoCrypt::ROUNDS; round++)
    {
        cry.ApplyPbox(state, cry.Permutation[0]);
        string str = byte2lestr((char*)state, sizeof(state));
        cry.ApplySboxes(state, cry.Sbox1, cry.Sbox2);
        string str2 = byte2lestr((char*)state, sizeof(state));
        cry.ApplyPbox(state, cry.Permutation[1]);
        cry.ApplyRotations(state, cry.Rotations);
        cry.ApplyRoundKey(state, cry.RoundKey[round]);
        result = byte2lestr((char*)state, sizeof(state));
    }

    cry.Encrypt(cipher, plain);
    result = byte2lestr((char*)cipher, sizeof(state));
	return 0;
}