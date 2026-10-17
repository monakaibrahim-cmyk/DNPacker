#include "pak.h"
#include "crypto.h"
#include "miniz.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>

namespace fs = std::filesystem;

namespace DragonNest {

// Cross-platform 64-bit file helpers
#if defined(_WIN32)
static FILE* PortableFileOpen(const fs::path& p, const char* mode) {
    std::wstring wmode(mode, mode + std::strlen(mode));
    return _wfopen(p.c_str(), wmode.c_str());
}
static int PortableFileSeek64(FILE* f, int64_t offset, int origin) {
    return _fseeki64(f, offset, origin);
}
static int64_t PortableFileTell64(FILE* f) {
    return _ftelli64(f);
}
#else
static FILE* PortableFileOpen(const fs::path& p, const char* mode) {
    return fopen(p.c_str(), mode);
}
static int PortableFileSeek64(FILE* f, int64_t offset, int origin) {
    return fseeko(f, offset, origin);
}
static int64_t PortableFileTell64(FILE* f) {
    return ftello(f);
}
#endif

static inline void SafeStrCopy(char* dest, size_t destSize, const char* src) {
    if (!dest || destSize == 0) return;
    std::strncpy(dest, src ? src : "", destSize - 1);
    dest[destSize - 1] = '\0';
}

PakArchive::~PakArchive() {
    Close();
}

void PakArchive::Close() {
    if (m_pFile) {
        std::fclose(m_pFile);
        m_pFile = nullptr;
    }
    m_entries.clear();
}

bool PakArchive::ReadBytes(uint64_t offset, void* buffer, size_t size) const {
    if (!m_pFile) return false;
    if (PortableFileSeek64(m_pFile, static_cast<int64_t>(offset), SEEK_SET) != 0) {
        return false;
    }
    return std::fread(buffer, 1, size, m_pFile) == size;
}

bool PakArchive::Open(const fs::path& pakPath) {
    Close();
    m_path = pakPath;

    m_pFile = PortableFileOpen(pakPath, "rb");
    if (!m_pFile) {
        return false;
    }

    // 1. Read archive header (272 bytes)
    if (!ReadBytes(0, &m_header, sizeof(m_header))) {
        Close();
        return false;
    }

    // Validate magic prefix "EyedentityGames Packing File 01"
    if (std::memcmp(m_header.magic, PAK_MAGIC, std::strlen(PAK_MAGIC)) != 0) {
        Close();
        return false;
    }

    // Validate version (Version 10 or 11 supported)
    if (m_header.version != 10 && m_header.version != 11) {
        Close();
        return false;
    }

    if (m_header.fileCount == 0) {
        return true; // Empty archive is technically valid
    }

    // 2. Read File Entry Table (316 bytes per entry)
    std::vector<PakEntryRaw> rawEntries(m_header.fileCount);
    size_t tableSize = static_cast<size_t>(m_header.fileCount) * sizeof(PakEntryRaw);

    if (!ReadBytes(m_header.tableOffset, rawEntries.data(), tableSize)) {
        Close();
        return false;
    }

    // 3. Populate high-level entries
    m_entries.reserve(m_header.fileCount);

    uint8_t headerKeyBytes[32];
    GetAES256Key(HEADER_KEY_STR, headerKeyBytes);
    AES256ECB headerCipher(headerKeyBytes);

    for (const auto& raw : rawEntries) {
        PakEntry entry;
        // Filename is null-terminated within 256 bytes
        char nameBuf[257]{};
        std::memcpy(nameBuf, raw.filename, 256);
        entry.filename = nameBuf;
        entry.compressedSize = raw.compressedSize;
        entry.uncompressedSize = raw.uncompressedSize;
        entry.offset = raw.offset;

        // Check if file is encrypted (first 16 bytes contain EwAF256 after decrypt)
        if (entry.compressedSize >= 16) {
            uint8_t first16[16];
            if (ReadBytes(entry.offset, first16, 16)) {
                uint8_t decHeader[16];
                if (headerCipher.DecryptBlock(first16, decHeader)) {
                    if (std::memcmp(decHeader, ENCRYPTION_MAGIC, 7) == 0) {
                        entry.isEncrypted = true;
                        std::string hexId(reinterpret_cast<char*>(decHeader + 7), 8);
                        try {
                            entry.keyId = static_cast<uint32_t>(std::stoul(hexId, nullptr, 16));
                        } catch (...) {
                            entry.keyId = DEFAULT_DATA_KEY_ID;
                        }
                    }
                }
            }
        }

        m_entries.push_back(std::move(entry));
    }

    return true;
}

bool PakArchive::ExtractFile(const PakEntry& entry, std::vector<uint8_t>& outData) {
    if (entry.compressedSize == 0) {
        outData.clear();
        return true;
    }

    std::vector<uint8_t> rawPayload(entry.compressedSize);
    if (!ReadBytes(entry.offset, rawPayload.data(), entry.compressedSize)) {
        return false;
    }

    uint8_t headerKeyBytes[32];
    GetAES256Key(HEADER_KEY_STR, headerKeyBytes);
    AES256ECB headerCipher(headerKeyBytes);

    const uint8_t* compressedStream = rawPayload.data();
    size_t compressedLen = rawPayload.size();
    std::vector<uint8_t> decryptedBody;

    // Check EwAF256 encryption
    if (rawPayload.size() >= 16) {
        uint8_t decHeader[16];
        if (headerCipher.DecryptBlock(rawPayload.data(), decHeader)) {
            if (std::memcmp(decHeader, ENCRYPTION_MAGIC, 7) == 0) {
                std::string hexId(reinterpret_cast<char*>(decHeader + 7), 8);
                uint32_t keyId = DEFAULT_DATA_KEY_ID;
                try {
                    keyId = static_cast<uint32_t>(std::stoul(hexId, nullptr, 16));
                } catch (...) {}

                std::string keyStr;
                if (!HasKey(keyId)) {
                    static bool s_warned = false;
                    if (!s_warned) {
                        std::cerr << "[!] Warning: File encrypted with unknown Key ID: 0x"
                                  << std::hex << std::uppercase << keyId << std::dec << "\n"
                                  << "    If the game was recently updated, drag dragonnest_x64.exe onto dnpak\n"
                                  << "    to extract the newest keys automatically into keys.txt!\n";
                        s_warned = true;
                    }
                    keyStr = DEFAULT_DATA_KEY_STR;
                } else {
                    keyStr = GetKeyString(keyId);
                }

                uint8_t dataKeyBytes[32];
                GetAES256Key(keyStr, dataKeyBytes);

                AES256ECB dataCipher(dataKeyBytes);
                const uint8_t* encBodyPtr = rawPayload.data() + 16;
                size_t encBodyLen = rawPayload.size() - 16;

                if (encBodyLen % 16 == 0 && encBodyLen > 0) {
                    decryptedBody = dataCipher.Decrypt(encBodyPtr, encBodyLen);
                    AES256ECB::RemovePKCS7Padding(decryptedBody);
                    compressedStream = decryptedBody.data();
                    compressedLen = decryptedBody.size();
                }
            }
        }
    }

    // Decompress via zlib (miniz)
    outData.resize(entry.uncompressedSize > 0 ? entry.uncompressedSize : compressedLen);
    mz_ulong destLen = static_cast<mz_ulong>(outData.size());
    int status = mz_uncompress(
        outData.data(),
        &destLen,
        compressedStream,
        static_cast<mz_ulong>(compressedLen)
    );

    if (status == MZ_OK) {
        outData.resize(destLen);
        return true;
    } else {
        // If not compressed, return stream directly
        outData.assign(compressedStream, compressedStream + compressedLen);
        return true;
    }
}

static bool MatchesFilter(const std::string& name, const std::string& filter) {
    if (filter.empty()) return true;

    // Simple wildcard support: *.ext or pattern*
    if (filter.front() == '*' && filter.size() > 1) {
        std::string suffix = filter.substr(1);
        if (name.size() >= suffix.size()) {
            return name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0;
        }
        return false;
    }
    return name.find(filter) != std::string::npos;
}

bool PakArchive::UnpackAll(const fs::path& outputDir, const std::string& filter) {
    fs::create_directories(outputDir);

    size_t count = 0;
    size_t total = m_entries.size();

    for (size_t i = 0; i < total; ++i) {
        const auto& entry = m_entries[i];
        if (!MatchesFilter(entry.filename, filter)) {
            continue;
        }

        std::vector<uint8_t> data;
        if (!ExtractFile(entry, data)) {
            std::cerr << "[-] Error extracting: " << entry.filename << "\n";
            continue;
        }

        // Sanitize path (convert backslashes to forward slashes for filesystem)
        std::string cleanName = entry.filename;
        for (char& c : cleanName) {
            if (c == '\\') c = '/';
        }

        fs::path outFilePath = outputDir / cleanName;
        fs::create_directories(outFilePath.parent_path());

        std::ofstream outFile(outFilePath, std::ios::binary);
        if (outFile.is_open()) {
            outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
            outFile.close();
            count++;

            std::cout << "[" << (i + 1) << "/" << total << "] Extracted: " << entry.filename;
            if (entry.isEncrypted) {
                std::cout << " [Enc: 0x" << std::hex << std::uppercase << entry.keyId << std::dec << "]";
            }
            std::cout << " (" << data.size() << " bytes)\n";
        } else {
            std::cerr << "[-] Failed to write: " << outFilePath.string() << "\n";
        }
    }

    std::cout << "\nUnpacking complete! Extracted " << count << " files.\n";
    return true;
}

void PakArchive::PrintInfo() const {
    std::cout << "Archive:      " << m_path.string() << "\n";
    std::cout << "Version:      " << m_header.version << "\n";
    std::cout << "File Count:   " << m_header.fileCount << "\n";
    std::cout << "Table Offset: 0x" << std::hex << std::uppercase << m_header.tableOffset
              << std::dec << " (" << m_header.tableOffset << " bytes)\n";
}

void PakArchive::List(const std::string& filter) const {
    PrintInfo();
    std::cout << "Offset      Comp Size     Orig Size     Status          Filename\n";
    std::cout << "--------------------------------------------------------------------------------\n";
    for (const auto& e : m_entries) {
        if (!MatchesFilter(e.filename, filter)) continue;

        std::string status = "Plain";
        if (e.isEncrypted) {
            std::stringstream ss;
            ss << "Enc(0x" << std::hex << e.keyId << ")";
            status = ss.str();
        }

        std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << e.offset << std::dec << "  "
                  << std::left << std::setw(14) << std::setfill(' ') << e.compressedSize
                  << std::setw(14) << e.uncompressedSize
                  << std::setw(16) << status
                  << e.filename << "\n";
    }
}

bool PakArchive::Pack(
    const fs::path& sourceDir,
    const fs::path& pakPath,
    bool encrypt,
    uint32_t keyId
) {
    if (!fs::exists(sourceDir) || !fs::is_directory(sourceDir)) {
        std::cerr << "[-] Source directory does not exist: " << sourceDir.string() << "\n";
        return false;
    }

    std::vector<fs::path> filePaths;
    for (const auto& entry : fs::recursive_directory_iterator(sourceDir)) {
        if (entry.is_regular_file()) {
            filePaths.push_back(entry.path());
        }
    }

    std::cout << "Packing " << filePaths.size() << " files into '" << pakPath.string() << "'...\n";

    FILE* pOut = PortableFileOpen(pakPath, "wb");
    if (!pOut) {
        std::cerr << "[-] Failed to create output file: " << pakPath.string() << "\n";
        return false;
    }

    // Reserve 272 bytes for header
    uint8_t zeroHeader[sizeof(PakHeaderRaw)]{};
    std::fwrite(zeroHeader, 1, sizeof(zeroHeader), pOut);

    // Initialize encryption ciphers if enabled
    uint8_t headerKeyBytes[32];
    GetAES256Key(HEADER_KEY_STR, headerKeyBytes);
    AES256ECB headerCipher(headerKeyBytes);

    std::string dataKeyStr = GetKeyString(keyId);
    uint8_t dataKeyBytes[32];
    GetAES256Key(dataKeyStr, dataKeyBytes);
    AES256ECB dataCipher(dataKeyBytes);

    std::vector<PakEntryRaw> rawTable;
    rawTable.reserve(filePaths.size());

    // 1. Write file payloads
    for (const auto& filePath : filePaths) {
        fs::path relPath = fs::relative(filePath, sourceDir);
        std::string relName = relPath.string();
        // Convert to Windows backslashes as expected by Dragon Nest engine
        for (char& c : relName) {
            if (c == '/') c = '\\';
        }

        std::ifstream inFile(filePath, std::ios::binary | std::ios::ate);
        if (!inFile.is_open()) {
            std::cerr << "[-] Warning: Failed to open " << filePath.string() << ", skipping.\n";
            continue;
        }

        std::streamsize uncompSize = inFile.tellg();
        inFile.seekg(0, std::ios::beg);

        std::vector<uint8_t> plainData(static_cast<size_t>(uncompSize));
        inFile.read(reinterpret_cast<char*>(plainData.data()), uncompSize);
        inFile.close();

        // Compress with zlib
        mz_ulong compBound = mz_compressBound(static_cast<mz_ulong>(uncompSize));
        std::vector<uint8_t> compBuffer(compBound);
        mz_ulong actualCompLen = compBound;

        int status = mz_compress(
            compBuffer.data(),
            &actualCompLen,
            plainData.data(),
            static_cast<mz_ulong>(uncompSize)
        );

        compBuffer.resize(actualCompLen);

        int64_t curPos = PortableFileTell64(pOut);
        uint32_t fileOffset = static_cast<uint32_t>(curPos);

        std::vector<uint8_t> finalPayload;
        if (encrypt) {
            // Build 16-byte header: EwAF256 + 8 hex chars + \0
            uint8_t headerPlain[16]{};
            std::memcpy(headerPlain, ENCRYPTION_MAGIC, 7);
            char hexBuf[9];
            std::snprintf(hexBuf, sizeof(hexBuf), "%08X", keyId);
            std::memcpy(headerPlain + 7, hexBuf, 8);
            headerPlain[15] = 0;

            uint8_t encHdr[16];
            headerCipher.EncryptBlock(headerPlain, encHdr);

            // Pad compressed data with PKCS#7 to 16-byte boundary
            std::vector<uint8_t> paddedData = AES256ECB::AddPKCS7Padding(compBuffer.data(), compBuffer.size());
            std::vector<uint8_t> encBody = dataCipher.Encrypt(paddedData.data(), paddedData.size());

            finalPayload.resize(16 + encBody.size());
            std::memcpy(finalPayload.data(), encHdr, 16);
            std::memcpy(finalPayload.data() + 16, encBody.data(), encBody.size());
        } else {
            finalPayload = std::move(compBuffer);
        }

        std::fwrite(finalPayload.data(), 1, finalPayload.size(), pOut);

        PakEntryRaw rawEntry{};
        SafeStrCopy(rawEntry.filename, sizeof(rawEntry.filename), relName.c_str());
        rawEntry.compressedSize = static_cast<uint32_t>(finalPayload.size());
        rawEntry.uncompressedSize = static_cast<uint32_t>(uncompSize);
        rawEntry.reserved = rawEntry.compressedSize;
        rawEntry.offset = fileOffset;

        rawTable.push_back(rawEntry);
    }

    // 2. Write File Entry Table
    int64_t tablePos = PortableFileTell64(pOut);
    uint32_t tableOffset = static_cast<uint32_t>(tablePos);

    std::fwrite(rawTable.data(), sizeof(PakEntryRaw), rawTable.size(), pOut);

    // 3. Write Actual Header (Version 11)
    PortableFileSeek64(pOut, 0, SEEK_SET);

    PakHeaderRaw finalHdr{};
    SafeStrCopy(finalHdr.magic, sizeof(finalHdr.magic), PAK_MAGIC);
    finalHdr.version = 11;
    finalHdr.fileCount = static_cast<uint32_t>(rawTable.size());
    finalHdr.tableOffset = tableOffset;

    std::fwrite(&finalHdr, 1, sizeof(finalHdr), pOut);
    std::fclose(pOut);

    std::cout << "Packing completed successfully! Output: " << pakPath.string() << "\n";
    return true;
}

} // namespace DragonNest
