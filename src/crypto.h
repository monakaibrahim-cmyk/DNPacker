#pragma once

#include <vector>
#include <cstdint>
#include <cstddef>
#include <string>

namespace DragonNest {

/**
 * High-performance AES-256-ECB implementation.
 * - On Windows: Uses Windows CNG (bcrypt.lib) with hardware AES-NI instructions.
 * - On Linux / POSIX: Uses an optimized, self-contained portable AES-256 engine.
 */
class AES256ECB {
public:
    explicit AES256ECB(const uint8_t key[32]);
    ~AES256ECB();

    // Delete copy operations (owns crypto handle / state)
    AES256ECB(const AES256ECB&) = delete;
    AES256ECB& operator=(const AES256ECB&) = delete;

    AES256ECB(AES256ECB&& other) noexcept;
    AES256ECB& operator=(AES256ECB&& other) noexcept;

    // Core 16-byte block encryption/decryption
    bool EncryptBlock(const uint8_t inBlock[16], uint8_t outBlock[16]) const;
    bool DecryptBlock(const uint8_t inBlock[16], uint8_t outBlock[16]) const;

    // Buffer operations (must be multiple of 16 bytes)
    std::vector<uint8_t> Encrypt(const uint8_t* data, size_t size) const;
    std::vector<uint8_t> Decrypt(const uint8_t* data, size_t size) const;

    // PKCS#7 padding helpers
    static std::vector<uint8_t> AddPKCS7Padding(const uint8_t* data, size_t size);
    static bool RemovePKCS7Padding(std::vector<uint8_t>& data);

private:
#if defined(_WIN32) && !defined(DN_FORCE_PORTABLE_AES)
    void* m_hAlg = nullptr;
    void* m_hKey = nullptr;
    std::vector<uint8_t> m_keyObj;
#endif

    // Portable AES state (used on non-Windows or fallback)
    uint32_t m_roundKeys[60];
    uint32_t m_invRoundKeys[60];
    void ExpandKeys(const uint8_t key[32]);
};

} // namespace DragonNest
