#pragma once

#include <cstdint>
#include <string>
#include <cstring>
#include <map>

namespace DragonNest {

constexpr uint32_t HEADER_KEY_ID = 0x8992FD01;
constexpr const char* HEADER_KEY_STR = "fTD6kNYM6vECvYVc3pUutQJ9ZiPoKxQ";

constexpr uint32_t DEFAULT_DATA_KEY_ID = 0x9B6536B2;
constexpr const char* DEFAULT_DATA_KEY_STR = "IodFUGvntOcxu2AplnA8yTBCZWxfZBP";

constexpr const char* PAK_MAGIC = "EyedentityGames Packing File 01";
constexpr const char* PAK_MAGIC_V10 = "EyedentityGames Packing File 0.1";
constexpr const char* PAK_MAGIC_PREFIX = "EyedentityGames Packing File";
constexpr const char* ENCRYPTION_MAGIC = "EwAF256";

// Built-in known keys recovered from dragonnest_x64.exe (Eyedentity Games)
inline const std::map<uint32_t, std::string> DEFAULT_KEYS = {
    { 0x8992FD01, "fTD6kNYM6vECvYVc3pUutQJ9ZiPoKxQ" },
    { 0x89A1C9D7, "eliK3CK3t1QjpFiL1RU4jTi0TCBgVLV" },
    { 0x89B1CF90, "vMqD6ZWjOULFDrOQzFnBZIIuCoVXFrf" },
    { 0x89C09CA0, "i1hPdnApMOYCI93waNqDdEluFBhYM2A" },
    { 0x89CF9131, "M7KaljQDaJer1otikwySCfUs2u72sZQ" },
    { 0x8F1E34F7, "IfgVLjOTZvkd9zroi9mgwUX1A3xAgxb" },
    { 0x8F2D9E9E, "Z4meRI9rjmRdtFrnz5toG1kE2pKI0gH" },
    { 0x8F3C1D32, "65qERsA4nlcQtoVdbVNHGMSPVCpMz0h" },
    { 0x8F4AEA90, "YEr3RS6UBZbR1jgmLsNgibWHCqv2RUU" },
    { 0x8F5AF024, "MxhC1Fj7tbcRUSUbFPzCDkBbyteqVsD" },
    { 0x8F6ACE4A, "YyrSvMgNuxuAjvyYJXBoXJZSM47FjyQ" },
    { 0x8F7A5ED2, "rLhWzetEDtnOJs2HmMsV3xRB0LlWy7M" },
    { 0x8F888F84, "GphJQRG4nqmXMcvUAmuYY05uULSMcpz" },
    { 0x8F975C85, "Arsu8ktZi8q0d7SNps1aensHTqB1AXl" },
    { 0x8FA76271, "Zc25NGJQdFLT05N7A1sOBoNdMsXSWgH" },
    { 0x8FB62F87, "uQviKkz0LEUAJGkcp7IHCfnUB5xWgrB" },
    { 0x8FC523AF, "jx3gucIl7zQdHwMxcqVt07NDnM1lEjb" },
    { 0x9512B6D3, "DHHekf1zv6ZdMy4XlP7afqp97wllnS8" },
    { 0x95229535, "7gXlfTFbpJ16wckdBQjOus0FgN9PIYI" },
    { 0x953272F8, "WhbxG7iN2VEHcNK78lWG0BoxDpvZ4aJ" },
    { 0x9541B5B7, "pPqiPjNicnDgnzB83qtNKjyefuCEhco" },
    { 0x9550A9B5, "swC2b0RDecyT89RN2wFkxJo9zCYOSX3" },
    { 0x9560FDC7, "awY9IThbRleayyl4ftwXBSQVZPzOe5s" },
    { 0x956F7CB1, "yGaSsxMkTGRUshqKzySXczpJ87Wxih9" },
    { 0x957E49C9, "XC0ujEYZvGASfDQSjkmcxBtd6JHpPWE" },
    { 0x958D8C17, "M3ySoTyOYVe7YB4O7cU2WvQ9tER272K" },
    { 0x959E06D9, "qJUnbLLCzd1iNmbmhRUai35t98axErc" },
    { 0x95AC5F06, "GW6UhevfMY1WXVmO6rwRBcwb4dsLkG8" },
    { 0x95BB52CD, "NlwC9YfLnSLBnz0n3dKvDgu2qMDgZtP" },
    { 0x9B098214, "D5q0UVzMA78p5ywJq1Gowk0kbuiUHCj" },
    { 0x9B18C480, "VDeYSSLlz62xuHKbwIw7s6yv1hcEY0v" },
    { 0x9B291800, "mBMjJWkKZzSiZxOgTUbryx2Osk5xmFi" },
    { 0x9B38815B, "CBFXOKb7eul35nn9noemLbygmFeA9R0" },
    { 0x9B466401, "44U3TeUSbtZArXEGS7zPsga5mCOaHYK" },
    { 0x9B55A647, "RNA9i8onWim1AhfICmUV9OAAMqbox3A" },
    { 0x9B6536B2, "IodFUGvntOcxu2AplnA8yTBCZWxfZBP" }
};

// Runtime active keys table
inline std::map<uint32_t, std::string> g_ActiveKeyTable = DEFAULT_KEYS;

inline bool HasKey(uint32_t keyId) {
    return g_ActiveKeyTable.find(keyId) != g_ActiveKeyTable.end();
}

inline std::string GetKeyString(uint32_t keyId) {
    auto it = g_ActiveKeyTable.find(keyId);
    if (it != g_ActiveKeyTable.end()) {
        return it->second;
    }
    return DEFAULT_DATA_KEY_STR;
}

// Fills 32-byte AES key buffer (31 characters + '\0')
inline void GetAES256Key(const std::string& keyStr, uint8_t outKey[32]) {
    std::memset(outKey, 0, 32);
    size_t len = keyStr.size() < 31 ? keyStr.size() : 31;
    std::memcpy(outKey, keyStr.data(), len);
}

} // namespace DragonNest
