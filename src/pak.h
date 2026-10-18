#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include "key_table.h"

namespace DragonNest {

#pragma pack(push, 1)
struct PakHeaderRaw {
    char magic[256];
    uint32_t version;
    uint32_t fileCount;
    uint32_t tableOffset;
    uint32_t reserved;
};
static_assert(sizeof(PakHeaderRaw) == 272, "PakHeaderRaw must be exactly 272 bytes (0x110)");

struct PakEntryRaw {
    char filename[256];
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint32_t reserved;
    uint32_t offset;
    uint8_t padding[44];
};
static_assert(sizeof(PakEntryRaw) == 316, "PakEntryRaw must be exactly 316 bytes (0x13C)");
#pragma pack(pop)

struct PakEntry {
    std::string filename;
    uint32_t compressedSize = 0;
    uint32_t uncompressedSize = 0;
    uint32_t offset = 0;
    bool isEncrypted = false;
    uint32_t keyId = 0;
};

class PakArchive {
public:
    PakArchive() = default;
    ~PakArchive();

    // Disable copy
    PakArchive(const PakArchive&) = delete;
    PakArchive& operator=(const PakArchive&) = delete;

    bool Open(const std::filesystem::path& pakPath);
    void Close();

    bool UnpackAll(const std::filesystem::path& outputDir, const std::string& filter = "");
    bool ExtractFile(const PakEntry& entry, std::vector<uint8_t>& outData);

    void PrintInfo() const;
    void List(const std::string& filter = "") const;

    static bool Pack(
        const std::filesystem::path& sourceDir,
        const std::filesystem::path& pakPath,
        bool encrypt = true,
        uint32_t keyId = DEFAULT_DATA_KEY_ID,
        bool oldFormat = false
    );

    const std::vector<PakEntry>& GetEntries() const { return m_entries; }
    uint32_t GetVersion() const { return m_header.version; }
    uint32_t GetFileCount() const { return m_header.fileCount; }
    uint32_t GetTableOffset() const { return m_header.tableOffset; }

private:
    std::filesystem::path m_path;
    FILE* m_pFile = nullptr;
    PakHeaderRaw m_header{};
    std::vector<PakEntry> m_entries;

    bool ReadBytes(uint64_t offset, void* buffer, size_t size) const;
};

} // namespace DragonNest
