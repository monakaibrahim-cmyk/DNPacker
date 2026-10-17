#include "key_extractor.h"
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <cctype>
#include <cstring>

namespace DragonNest {

#pragma pack(push, 1)
struct PeDosHeader {
    uint16_t e_magic;    // 'MZ' = 0x5A4D
    uint8_t  e_reserved[58];
    uint32_t e_lfanew;   // Offset to NT headers
};

struct PeFileHeader {
    uint16_t machine;
    uint16_t numberOfSections;
    uint32_t timeDateStamp;
    uint32_t pointerToSymbolTable;
    uint32_t numberOfSymbols;
    uint16_t sizeOfOptionalHeader;
    uint16_t characteristics;
};

struct PeSectionHeader {
    char     name[8];
    uint32_t virtualSize;
    uint32_t virtualAddress;
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
    uint32_t pointerToRelocations;
    uint32_t pointerToLinenumbers;
    uint16_t numberOfRelocations;
    uint16_t numberOfLinenumbers;
    uint32_t characteristics;
};
#pragma pack(pop)

struct SectionInfo {
    char name[9];
    uint32_t virtualAddress;
    uint32_t virtualSize;
    uint32_t rawOffset;
    uint32_t rawSize;
};

static uint64_t RvaToOffset(uint32_t rva, const std::vector<SectionInfo>& sections) {
    for (const auto& sec : sections) {
        if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
            return sec.rawOffset + (rva - sec.virtualAddress);
        }
    }
    return 0;
}

static uint64_t VaToOffset(uint64_t va, uint64_t imageBase, const std::vector<SectionInfo>& sections) {
    if (va < imageBase) return 0;
    return RvaToOffset(static_cast<uint32_t>(va - imageBase), sections);
}

bool ExtractKeysFromExecutable(
    const std::filesystem::path& exePath,
    std::map<uint32_t, std::string>& outKeys,
    std::string& errMsg
) {
    std::ifstream file(exePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        errMsg = "Failed to open executable file.";
        return false;
    }

    std::streamsize fileSize = file.tellg();
    if (fileSize < 4096) {
        errMsg = "Executable file is too small.";
        return false;
    }

    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(static_cast<size_t>(fileSize));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        errMsg = "Failed to read executable file into memory.";
        return false;
    }

    // 1. Verify DOS Header
    if (buffer.size() < sizeof(PeDosHeader)) {
        errMsg = "File too small for DOS header.";
        return false;
    }
    auto dosHeader = reinterpret_cast<const PeDosHeader*>(buffer.data());
    if (dosHeader->e_magic != 0x5A4D) { // 'MZ'
        errMsg = "Invalid DOS signature (not a PE executable).";
        return false;
    }

    if (dosHeader->e_lfanew + 24 > buffer.size()) {
        errMsg = "NT headers pointer out of file bounds.";
        return false;
    }

    // 2. Verify NT Headers
    const uint8_t* ntPtr = buffer.data() + dosHeader->e_lfanew;
    uint32_t ntSig = *reinterpret_cast<const uint32_t*>(ntPtr);
    if (ntSig != 0x00004550) { // 'PE\0\0'
        errMsg = "Invalid NT signature.";
        return false;
    }

    auto fileHeader = reinterpret_cast<const PeFileHeader*>(ntPtr + 4);
    uint16_t numSections = fileHeader->numberOfSections;
    uint16_t optHdrSize = fileHeader->sizeOfOptionalHeader;

    if (dosHeader->e_lfanew + 24 + optHdrSize > buffer.size()) {
        errMsg = "Optional header out of bounds.";
        return false;
    }

    // Read ImageBase from OptionalHeader64 (offset 24 in OptionalHeader)
    const uint8_t* optHdrPtr = ntPtr + 24;
    uint64_t imageBase = 0x140000000ULL;
    if (optHdrSize >= 32) {
        imageBase = *reinterpret_cast<const uint64_t*>(optHdrPtr + 24);
    }

    // 3. Parse Sections
    const uint8_t* secTblPtr = optHdrPtr + optHdrSize;
    if (secTblPtr + numSections * sizeof(PeSectionHeader) > buffer.data() + buffer.size()) {
        errMsg = "Section table out of bounds.";
        return false;
    }

    auto secHeaders = reinterpret_cast<const PeSectionHeader*>(secTblPtr);
    std::vector<SectionInfo> sections;
    sections.reserve(numSections);

    for (uint16_t i = 0; i < numSections; ++i) {
        SectionInfo info{};
        std::memcpy(info.name, secHeaders[i].name, 8);
        info.name[8] = '\0';
        info.virtualAddress = secHeaders[i].virtualAddress;
        info.virtualSize = secHeaders[i].virtualSize;
        info.rawOffset = secHeaders[i].pointerToRawData;
        info.rawSize = secHeaders[i].sizeOfRawData;
        sections.push_back(info);
    }

    const SectionInfo* textSec = nullptr;
    for (const auto& sec : sections) {
        if (std::strcmp(sec.name, ".text") == 0) {
            textSec = &sec;
            break;
        }
    }

    if (!textSec || textSec->rawOffset + textSec->rawSize > buffer.size()) {
        errMsg = ".text section not found or invalid.";
        return false;
    }

    // 4. Scan .text section for Key Registration Opcode Patterns:
    // C7 45 F0 [KeyID: 4 bytes] 48 8D [ModRM: 05, 0D, etc.] [Disp32: 4 bytes]
    const uint8_t* textData = buffer.data() + textSec->rawOffset;
    size_t textLen = textSec->rawSize;

    size_t initialCount = outKeys.size();

    for (size_t i = 0; i + 14 < textLen; ++i) {
        // Match: C7 45 F0 [4-byte keyId]
        if (textData[i] == 0xC7 && textData[i + 1] == 0x45 && textData[i + 2] == 0xF0) {
            uint32_t keyId = *reinterpret_cast<const uint32_t*>(textData + i + 3);

            // Match following LEA instruction: 48 8D [ModRM] [Disp32]
            size_t leaOffset = i + 7;
            if (leaOffset + 7 <= textLen && textData[leaOffset] == 0x48 && textData[leaOffset + 1] == 0x8D) {
                uint8_t modRm = textData[leaOffset + 2];
                // Check if ModRM uses RIP-relative addressing (mod == 00, r/m == 101)
                if ((modRm & 0xC7) == 0x05) {
                    int32_t disp32 = *reinterpret_cast<const int32_t*>(textData + leaOffset + 3);

                    // Calculate destination VA: InsnVA + 7 + Disp32
                    uint64_t insnVa = imageBase + textSec->virtualAddress + leaOffset;
                    uint64_t targetVa = insnVa + 7 + disp32;

                    uint64_t strFileOffset = VaToOffset(targetVa, imageBase, sections);
                    if (strFileOffset > 0 && strFileOffset < buffer.size()) {
                        // Read ASCII string until null terminator
                        const char* strPtr = reinterpret_cast<const char*>(buffer.data() + strFileOffset);
                        size_t strLen = 0;
                        while (strFileOffset + strLen < buffer.size() && strPtr[strLen] != '\0' && strLen < 128) {
                            strLen++;
                        }

                        if (strLen >= 16 && strLen <= 64) {
                            bool isAlnum = true;
                            for (size_t s = 0; s < strLen; ++s) {
                                if (!std::isalnum(static_cast<unsigned char>(strPtr[s]))) {
                                    isAlnum = false;
                                    break;
                                }
                            }
                            if (isAlnum) {
                                outKeys[keyId] = std::string(strPtr, strLen);
                                i += 14; // Advance scanner
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }

    if (outKeys.size() == initialCount) {
        errMsg = "Scanner did not locate any valid key patterns in executable.";
        return false;
    }

    return true;
}

bool SaveKeysToFile(const std::filesystem::path& filePath, const std::map<uint32_t, std::string>& keys) {
    std::ofstream file(filePath);
    if (!file.is_open()) return false;

    file << "# Dragon Nest Encryption Keys Database\n";
    file << "# Format: KeyID=KeyString\n\n";
    for (const auto& [kid, kstr] : keys) {
        std::stringstream ss;
        ss << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << kid;
        file << ss.str() << "=" << kstr << "\n";
    }
    return true;
}

bool LoadKeysFromFile(const std::filesystem::path& filePath, std::map<uint32_t, std::string>& outKeys) {
    std::ifstream file(filePath);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        size_t eqPos = line.find('=');
        if (eqPos == std::string::npos) continue;

        std::string idStr = line.substr(0, eqPos);
        std::string valStr = line.substr(eqPos + 1);

        // Trim whitespace
        while (!idStr.empty() && std::isspace(static_cast<unsigned char>(idStr.front()))) idStr.erase(idStr.begin());
        while (!idStr.empty() && std::isspace(static_cast<unsigned char>(idStr.back()))) idStr.pop_back();
        while (!valStr.empty() && std::isspace(static_cast<unsigned char>(valStr.front()))) valStr.erase(valStr.begin());
        while (!valStr.empty() && std::isspace(static_cast<unsigned char>(valStr.back()))) valStr.pop_back();

        if (idStr.empty() || valStr.empty()) continue;

        try {
            uint32_t kid = static_cast<uint32_t>(std::stoul(idStr, nullptr, 0));
            outKeys[kid] = valStr;
        } catch (...) {}
    }

    return true;
}

} // namespace DragonNest
