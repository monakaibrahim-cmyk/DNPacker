#include "crypto.h"
#include <cstring>
#include <stdexcept>
#include <algorithm>

#if defined(_WIN32) && !defined(DN_FORCE_PORTABLE_AES)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace DragonNest {

// Standard AES S-Box
static const uint8_t s_SBox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5e, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Standard AES Inverse S-Box
static const uint8_t s_InvSBox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Round constants
static const uint32_t s_Rcon[11] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

static inline uint32_t SubWord(uint32_t w) {
    return (static_cast<uint32_t>(s_SBox[(w >> 24) & 0xFF]) << 24) |
           (static_cast<uint32_t>(s_SBox[(w >> 16) & 0xFF]) << 16) |
           (static_cast<uint32_t>(s_SBox[(w >> 8)  & 0xFF]) << 8)  |
           (static_cast<uint32_t>(s_SBox[w & 0xFF]));
}

static inline uint32_t RotWord(uint32_t w) {
    return (w << 8) | (w >> 24);
}

static inline uint8_t XTime(uint8_t a) {
    return (a << 1) ^ ((a & 0x80) ? 0x1B : 0x00);
}

static inline uint8_t GfMul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        bool hi = (a & 0x80) != 0;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

void AES256ECB::ExpandKeys(const uint8_t key[32]) {
    for (int i = 0; i < 8; ++i) {
        m_roundKeys[i] = (static_cast<uint32_t>(key[4 * i])     << 24) |
                         (static_cast<uint32_t>(key[4 * i + 1]) << 16) |
                         (static_cast<uint32_t>(key[4 * i + 2]) << 8)  |
                         (static_cast<uint32_t>(key[4 * i + 3]));
    }
    for (int i = 8; i < 60; ++i) {
        uint32_t temp = m_roundKeys[i - 1];
        if (i % 8 == 0) {
            temp = SubWord(RotWord(temp)) ^ s_Rcon[i / 8];
        } else if (i % 8 == 4) {
            temp = SubWord(temp);
        }
        m_roundKeys[i] = m_roundKeys[i - 8] ^ temp;
    }

    // Inverse round keys
    std::memcpy(m_invRoundKeys, m_roundKeys, sizeof(m_roundKeys));
    for (int r = 1; r < 14; ++r) {
        for (int c = 0; c < 4; ++c) {
            uint32_t w = m_invRoundKeys[r * 4 + c];
            uint8_t a0 = (w >> 24) & 0xFF;
            uint8_t a1 = (w >> 16) & 0xFF;
            uint8_t a2 = (w >> 8)  & 0xFF;
            uint8_t a3 = w & 0xFF;

            uint8_t b0 = GfMul(a0, 0x0e) ^ GfMul(a1, 0x0b) ^ GfMul(a2, 0x0d) ^ GfMul(a3, 0x09);
            uint8_t b1 = GfMul(a0, 0x09) ^ GfMul(a1, 0x0e) ^ GfMul(a2, 0x0b) ^ GfMul(a3, 0x0d);
            uint8_t b2 = GfMul(a0, 0x0d) ^ GfMul(a1, 0x09) ^ GfMul(a2, 0x0e) ^ GfMul(a3, 0x0b);
            uint8_t b3 = GfMul(a0, 0x0b) ^ GfMul(a1, 0x0d) ^ GfMul(a2, 0x09) ^ GfMul(a3, 0x0e);

            m_invRoundKeys[r * 4 + c] = (static_cast<uint32_t>(b0) << 24) |
                                        (static_cast<uint32_t>(b1) << 16) |
                                        (static_cast<uint32_t>(b2) << 8)  |
                                        (static_cast<uint32_t>(b3));
        }
    }
}

AES256ECB::AES256ECB(const uint8_t key[32]) {
    ExpandKeys(key);

#if defined(_WIN32) && !defined(DN_FORCE_PORTABLE_AES)
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) {
        m_hAlg = nullptr;
        m_hKey = nullptr;
        return; // Fall back to portable engine
    }

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return;
    }

    DWORD cbKeyObj = 0;
    DWORD cbData = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return;
    }

    m_keyObj.resize(cbKeyObj);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, m_keyObj.data(), cbKeyObj, (PUCHAR)key, 32, 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return;
    }

    m_hAlg = hAlg;
    m_hKey = hKey;
#endif
}

AES256ECB::~AES256ECB() {
#if defined(_WIN32) && !defined(DN_FORCE_PORTABLE_AES)
    if (m_hKey) {
        BCryptDestroyKey((BCRYPT_KEY_HANDLE)m_hKey);
        m_hKey = nullptr;
    }
    if (m_hAlg) {
        BCryptCloseAlgorithmProvider((BCRYPT_ALG_HANDLE)m_hAlg, 0);
        m_hAlg = nullptr;
    }
#endif
}

AES256ECB::AES256ECB(AES256ECB&& other) noexcept {
    *this = std::move(other);
}

AES256ECB& AES256ECB::operator=(AES256ECB&& other) noexcept {
    if (this != &other) {
#if defined(_WIN32) && !defined(DN_FORCE_PORTABLE_AES)
        if (m_hKey) BCryptDestroyKey((BCRYPT_KEY_HANDLE)m_hKey);
        if (m_hAlg) BCryptCloseAlgorithmProvider((BCRYPT_ALG_HANDLE)m_hAlg, 0);
        m_hAlg = other.m_hAlg;
        m_hKey = other.m_hKey;
        m_keyObj = std::move(other.m_keyObj);
        other.m_hAlg = nullptr;
        other.m_hKey = nullptr;
#endif
        std::memcpy(m_roundKeys, other.m_roundKeys, sizeof(m_roundKeys));
        std::memcpy(m_invRoundKeys, other.m_invRoundKeys, sizeof(m_invRoundKeys));
    }
    return *this;
}

// Portable AES-256 block encryption
static void PortableEncryptBlock(const uint32_t rk[60], const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[4][4];
    for (int i = 0; i < 16; ++i) {
        state[i % 4][i / 4] = in[i];
    }

    // AddRoundKey 0
    for (int c = 0; c < 4; ++c) {
        uint32_t w = rk[c];
        state[0][c] ^= (w >> 24) & 0xFF;
        state[1][c] ^= (w >> 16) & 0xFF;
        state[2][c] ^= (w >> 8)  & 0xFF;
        state[3][c] ^= w & 0xFF;
    }

    // Rounds 1 to 13
    for (int round = 1; round < 14; ++round) {
        // SubBytes
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) {
                state[r][c] = s_SBox[state[r][c]];
            }
        }
        // ShiftRows
        uint8_t t;
        t = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t;
        t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
        t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;
        t = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = t;

        // MixColumns
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
            state[0][c] = XTime(a0 ^ a1) ^ a1 ^ a2 ^ a3;
            state[1][c] = XTime(a1 ^ a2) ^ a2 ^ a3 ^ a0;
            state[2][c] = XTime(a2 ^ a3) ^ a3 ^ a0 ^ a1;
            state[3][c] = XTime(a3 ^ a0) ^ a0 ^ a1 ^ a2;
        }

        // AddRoundKey
        for (int c = 0; c < 4; ++c) {
            uint32_t w = rk[round * 4 + c];
            state[0][c] ^= (w >> 24) & 0xFF;
            state[1][c] ^= (w >> 16) & 0xFF;
            state[2][c] ^= (w >> 8)  & 0xFF;
            state[3][c] ^= w & 0xFF;
        }
    }

    // Round 14: SubBytes + ShiftRows + AddRoundKey
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = s_SBox[state[r][c]];
        }
    }
    uint8_t t;
    t = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t;
    t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
    t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;
    t = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = t;

    for (int c = 0; c < 4; ++c) {
        uint32_t w = rk[14 * 4 + c];
        state[0][c] ^= (w >> 24) & 0xFF;
        state[1][c] ^= (w >> 16) & 0xFF;
        state[2][c] ^= (w >> 8)  & 0xFF;
        state[3][c] ^= w & 0xFF;
    }

    for (int i = 0; i < 16; ++i) {
        out[i] = state[i % 4][i / 4];
    }
}

// Portable AES-256 block decryption
static void PortableDecryptBlock(const uint32_t rk[60], const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[4][4];
    for (int i = 0; i < 16; ++i) {
        state[i % 4][i / 4] = in[i];
    }

    // AddRoundKey 14
    for (int c = 0; c < 4; ++c) {
        uint32_t w = rk[14 * 4 + c];
        state[0][c] ^= (w >> 24) & 0xFF;
        state[1][c] ^= (w >> 16) & 0xFF;
        state[2][c] ^= (w >> 8)  & 0xFF;
        state[3][c] ^= w & 0xFF;
    }

    // Rounds 13 down to 1
    for (int round = 13; round >= 1; --round) {
        // InvShiftRows
        uint8_t t;
        t = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = t;
        t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
        t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;
        t = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = t;

        // InvSubBytes
        for (int r = 0; r < 4; ++r) {
            for (int c = 0; c < 4; ++c) {
                state[r][c] = s_InvSBox[state[r][c]];
            }
        }

        // AddRoundKey (using InvMixColumns-transformed keys)
        for (int c = 0; c < 4; ++c) {
            uint32_t w = rk[round * 4 + c];
            state[0][c] ^= (w >> 24) & 0xFF;
            state[1][c] ^= (w >> 16) & 0xFF;
            state[2][c] ^= (w >> 8)  & 0xFF;
            state[3][c] ^= w & 0xFF;
        }

        // InvMixColumns
        for (int c = 0; c < 4; ++c) {
            uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
            state[0][c] = GfMul(a0, 0x0e) ^ GfMul(a1, 0x0b) ^ GfMul(a2, 0x0d) ^ GfMul(a3, 0x09);
            state[1][c] = GfMul(a0, 0x09) ^ GfMul(a1, 0x0e) ^ GfMul(a2, 0x0b) ^ GfMul(a3, 0x0d);
            state[2][c] = GfMul(a0, 0x0d) ^ GfMul(a1, 0x09) ^ GfMul(a2, 0x0e) ^ GfMul(a3, 0x0b);
            state[3][c] = GfMul(a0, 0x0b) ^ GfMul(a1, 0x0d) ^ GfMul(a2, 0x09) ^ GfMul(a3, 0x0e);
        }
    }

    // Round 0: InvShiftRows + InvSubBytes + AddRoundKey 0
    uint8_t t;
    t = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = t;
    t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
    t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;
    t = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = t;

    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = s_InvSBox[state[r][c]];
        }
    }

    for (int c = 0; c < 4; ++c) {
        uint32_t w = rk[c];
        state[0][c] ^= (w >> 24) & 0xFF;
        state[1][c] ^= (w >> 16) & 0xFF;
        state[2][c] ^= (w >> 8)  & 0xFF;
        state[3][c] ^= w & 0xFF;
    }

    for (int i = 0; i < 16; ++i) {
        out[i] = state[i % 4][i / 4];
    }
}

bool AES256ECB::EncryptBlock(const uint8_t inBlock[16], uint8_t outBlock[16]) const {
#if defined(_WIN32) && !defined(DN_FORCE_PORTABLE_AES)
    if (m_hKey) {
        ULONG cbResult = 0;
        NTSTATUS status = BCryptEncrypt(
            (BCRYPT_KEY_HANDLE)m_hKey,
            (PUCHAR)inBlock, 16,
            nullptr, nullptr, 0,
            (PUCHAR)outBlock, 16,
            &cbResult, 0
        );
        return NT_SUCCESS(status) && cbResult == 16;
    }
#endif
    PortableEncryptBlock(m_roundKeys, inBlock, outBlock);
    return true;
}

bool AES256ECB::DecryptBlock(const uint8_t inBlock[16], uint8_t outBlock[16]) const {
#if defined(_WIN32) && !defined(DN_FORCE_PORTABLE_AES)
    if (m_hKey) {
        ULONG cbResult = 0;
        NTSTATUS status = BCryptDecrypt(
            (BCRYPT_KEY_HANDLE)m_hKey,
            (PUCHAR)inBlock, 16,
            nullptr, nullptr, 0,
            (PUCHAR)outBlock, 16,
            &cbResult, 0
        );
        return NT_SUCCESS(status) && cbResult == 16;
    }
#endif
    PortableDecryptBlock(m_invRoundKeys, inBlock, outBlock);
    return true;
}

std::vector<uint8_t> AES256ECB::Encrypt(const uint8_t* data, size_t size) const {
    if (size % 16 != 0) {
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES-ECB");
    }

    std::vector<uint8_t> output(size);
#if defined(_WIN32) && !defined(DN_FORCE_PORTABLE_AES)
    if (m_hKey) {
        ULONG cbResult = 0;
        NTSTATUS status = BCryptEncrypt(
            (BCRYPT_KEY_HANDLE)m_hKey,
            (PUCHAR)data, static_cast<ULONG>(size),
            nullptr, nullptr, 0,
            output.data(), static_cast<ULONG>(size),
            &cbResult, 0
        );
        if (NT_SUCCESS(status)) {
            return output;
        }
    }
#endif
    for (size_t i = 0; i < size; i += 16) {
        PortableEncryptBlock(m_roundKeys, data + i, output.data() + i);
    }
    return output;
}

std::vector<uint8_t> AES256ECB::Decrypt(const uint8_t* data, size_t size) const {
    if (size % 16 != 0) {
        throw std::invalid_argument("Data size must be a multiple of 16 bytes for AES-ECB");
    }

    std::vector<uint8_t> output(size);
#if defined(_WIN32) && !defined(DN_FORCE_PORTABLE_AES)
    if (m_hKey) {
        ULONG cbResult = 0;
        NTSTATUS status = BCryptDecrypt(
            (BCRYPT_KEY_HANDLE)m_hKey,
            (PUCHAR)data, static_cast<ULONG>(size),
            nullptr, nullptr, 0,
            output.data(), static_cast<ULONG>(size),
            &cbResult, 0
        );
        if (NT_SUCCESS(status)) {
            return output;
        }
    }
#endif
    for (size_t i = 0; i < size; i += 16) {
        PortableDecryptBlock(m_invRoundKeys, data + i, output.data() + i);
    }
    return output;
}

std::vector<uint8_t> AES256ECB::AddPKCS7Padding(const uint8_t* data, size_t size) {
    size_t padLen = 16 - (size % 16);
    std::vector<uint8_t> padded(size + padLen);
    std::memcpy(padded.data(), data, size);
    std::memset(padded.data() + size, static_cast<uint8_t>(padLen), padLen);
    return padded;
}

bool AES256ECB::RemovePKCS7Padding(std::vector<uint8_t>& data) {
    if (data.empty() || data.size() % 16 != 0) {
        return false;
    }
    uint8_t padLen = data.back();
    if (padLen == 0 || padLen > 16 || padLen > data.size()) {
        return false;
    }
    for (size_t i = data.size() - padLen; i < data.size(); ++i) {
        if (data[i] != padLen) {
            return false;
        }
    }
    data.resize(data.size() - padLen);
    return true;
}

} // namespace DragonNest
