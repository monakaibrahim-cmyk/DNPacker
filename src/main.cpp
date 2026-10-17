#include "pak.h"
#include "key_table.h"
#include "key_extractor.h"

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>

#if defined(_WIN32)
#include <windows.h>
#pragma comment(lib, "user32.lib")
#endif

namespace fs = std::filesystem;

namespace {

fs::path GetExeDirectory(const char* argv0) {
#if defined(_WIN32)
    wchar_t buf[MAX_PATH];
    if (GetModuleFileNameW(nullptr, buf, MAX_PATH)) {
        return fs::path(buf).parent_path();
    }
#endif
    try {
        if (argv0 && *argv0) {
            fs::path p(argv0);
            if (p.is_absolute()) {
                return p.parent_path();
            }
            return (fs::current_path() / p).parent_path();
        }
    } catch (...) {}
    return fs::current_path();
}

bool IsLaunchedFromExplorer() {
#if defined(_WIN32)
    HWND consoleWnd = GetConsoleWindow();
    if (!consoleWnd) return false;
    DWORD pid = 0;
    GetWindowThreadProcessId(consoleWnd, &pid);
    return (GetCurrentProcessId() == pid);
#else
    return false;
#endif
}

void WaitIfExplorer() {
    if (IsLaunchedFromExplorer()) {
        std::cout << "\nPress Enter to exit...";
        std::string dummy;
        std::getline(std::cin, dummy);
    }
}

std::string ToLower(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return str;
}

void PrintBanner() {
    std::cout << "===================================================================\n";
    std::cout << "  DNPacker - Dragon Nest PAK Archive Tool (Cross-Platform C++)\n";
    std::cout << "  High-Performance AES-256-ECB & zlib Deflate Compression\n";
    std::cout << "===================================================================\n\n";
}

void PrintKeyStatus(bool hasKeysTxt, const fs::path& keysPath) {
    if (hasKeysTxt) {
        std::cout << "[i] Keys Status: Loaded custom keys from " << keysPath.filename().string()
                  << " (" << DragonNest::g_ActiveKeyTable.size() << " keys active)\n\n";
    } else {
        std::cout << "[i] Keys Status: Using " << DragonNest::DEFAULT_KEYS.size() << " built-in archive keys.\n";
        std::cout << "    NOTE: If Dragon Nest received a new patch with new keys, simply drag\n";
        std::cout << "          dragonnest_x64.exe onto dnpak to generate keys.txt automatically!\n\n";
    }
}

void PrintUsage() {
    std::cout << "Usage:\n";
    std::cout << "  dnpacker unpack <archive.pak> [output_dir] [--filter <pattern>]\n";
    std::cout << "  dnpacker pack <folder> [output.pak] [--no-encrypt] [--key <hex_key_id>]\n";
    std::cout << "  dnpacker list <archive.pak> [--filter <pattern>]\n";
    std::cout << "  dnpacker info <archive.pak>\n";
    std::cout << "  dnpacker extract-keys <dragonnest_x64.exe> [output_keys.txt]\n\n";
    std::cout << "Drag & Drop:\n";
    std::cout << "  - Drag .pak file onto dnpacker   -> Automatically unpacks to folder\n";
    std::cout << "  - Drag folder onto dnpacker      -> Automatically packs to .pak (AES-256)\n";
    std::cout << "  - Drag .exe onto dnpacker         -> Extracts encryption keys to keys.txt\n\n";
}

bool HandleExtractKeys(const fs::path& exePath, fs::path outTxtPath, const fs::path& exeDir) {
    std::cout << "[*] Scanning executable for encryption keys: " << exePath.string() << "\n";
    std::map<uint32_t, std::string> extractedKeys;
    std::string errMsg;

    if (!DragonNest::ExtractKeysFromExecutable(exePath, extractedKeys, errMsg)) {
        std::cerr << "[-] Extraction failed: " << errMsg << "\n";
        return false;
    }

    std::cout << "[+] Successfully extracted " << extractedKeys.size() << " archive encryption keys!\n";
    std::cout << "-------------------------------------------------------------------\n";
    for (const auto& [id, str] : extractedKeys) {
        std::cout << "  Key ID: 0x" << std::hex << std::uppercase << id
                  << " -> \"" << str << "\"\n";
        DragonNest::g_ActiveKeyTable[id] = str;
    }
    std::cout << std::dec << "-------------------------------------------------------------------\n";

    if (outTxtPath.empty()) {
        outTxtPath = exeDir / "keys.txt";
    }

    if (DragonNest::SaveKeysToFile(outTxtPath, extractedKeys)) {
        std::cout << "[+] Saved " << extractedKeys.size() << " keys to: " << outTxtPath.string() << "\n";
        std::cout << "[+] Future unpack / pack operations will automatically use these keys.\n";
    }

    return true;
}

bool HandleUnpack(const fs::path& pakPath, fs::path outDir, const std::string& filter = "") {
    if (outDir.empty()) {
        outDir = pakPath.parent_path() / pakPath.stem();
    }

    DragonNest::PakArchive pak;
    if (!pak.Open(pakPath)) {
        std::cerr << "[-] Error: Failed to open PAK archive: " << pakPath.string() << "\n";
        return false;
    }

    std::cout << "[*] Unpacking " << pakPath.string() << " -> " << outDir.string() << "\n";
    return pak.UnpackAll(outDir, filter);
}

bool HandlePack(const fs::path& inDir, fs::path outPak, bool encrypt = true, uint32_t keyId = DragonNest::DEFAULT_DATA_KEY_ID) {
    if (outPak.empty()) {
        if (inDir.has_filename()) {
            outPak = (inDir.parent_path() / inDir.filename()).string() + ".pak";
        } else {
            outPak = inDir.string() + ".pak";
        }
    }

    std::cout << "[*] Packing folder " << inDir.string() << " -> " << outPak.string() << "\n";
    return DragonNest::PakArchive::Pack(inDir, outPak, encrypt, keyId);
}

void ProcessSinglePath(const fs::path& p, const fs::path& exeDir) {
    if (!fs::exists(p)) {
        std::cerr << "[-] Error: Path does not exist: " << p.string() << "\n";
        return;
    }

    if (fs::is_directory(p)) {
        // Dragged a folder -> Pack into PAK
        std::cout << "[+] Detected directory: " << p.string() << "\n";
        fs::path outPak = (p.parent_path() / p.filename()).string() + ".pak";
        HandlePack(p, outPak, true, DragonNest::DEFAULT_DATA_KEY_ID);
    } else if (fs::is_regular_file(p)) {
        std::string ext = ToLower(p.extension().string());
        if (ext == ".pak") {
            // Dragged a .pak file -> Unpack
            std::cout << "[+] Detected PAK archive: " << p.string() << "\n";
            fs::path outDir = p.parent_path() / p.stem();
            HandleUnpack(p, outDir);
        } else if (ext == ".exe") {
            // Dragged an executable -> Extract keys
            std::cout << "[+] Detected executable binary: " << p.string() << "\n";
            fs::path outKeys = exeDir / "keys.txt";
            HandleExtractKeys(p, outKeys, exeDir);
        } else {
            std::cerr << "[-] Unrecognized file type (" << ext << "). Please drag a .pak file, folder, or dragonnest_x64.exe\n";
        }
    }
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    fs::path exeDir = GetExeDirectory(argc > 0 ? argv[0] : nullptr);
    fs::path keysTxtPath = exeDir / "keys.txt";
    bool hasKeysTxt = fs::exists(keysTxtPath) && DragonNest::LoadKeysFromFile(keysTxtPath, DragonNest::g_ActiveKeyTable);
    if (!hasKeysTxt && fs::exists("keys.txt")) {
        keysTxtPath = fs::current_path() / "keys.txt";
        hasKeysTxt = DragonNest::LoadKeysFromFile(keysTxtPath, DragonNest::g_ActiveKeyTable);
    }

    if (argc < 2) {
        PrintBanner();
        PrintKeyStatus(hasKeysTxt, keysTxtPath);
        PrintUsage();

        std::cout << "Interactive Mode:\n";
        std::cout << "Enter path to a .pak file, folder, or executable (or drag and drop into this window):\n> ";
        std::string inputPath;
        if (std::getline(std::cin, inputPath)) {
            // Strip quotes if any
            if (inputPath.size() >= 2 && inputPath.front() == '"' && inputPath.back() == '"') {
                inputPath = inputPath.substr(1, inputPath.size() - 2);
            }
            if (!inputPath.empty()) {
                ProcessSinglePath(inputPath, exeDir);
            }
        }
        WaitIfExplorer();
        return 0;
    }

    std::string cmd = ToLower(argv[1]);

    if (cmd == "unpack") {
        if (argc < 3) {
            std::cerr << "Usage: dnpacker unpack <archive.pak> [output_dir] [--filter <pattern>]\n";
            return 1;
        }
        fs::path pakPath = argv[2];
        fs::path outDir = (argc >= 4 && argv[3][0] != '-') ? argv[3] : "";
        std::string filter = "";
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--filter" && i + 1 < argc) {
                filter = argv[i + 1];
                break;
            }
        }
        bool ok = HandleUnpack(pakPath, outDir, filter);
        return ok ? 0 : 1;
    } else if (cmd == "pack") {
        if (argc < 3) {
            std::cerr << "Usage: dnpacker pack <folder> [output.pak] [--no-encrypt] [--key <hex_key_id>]\n";
            return 1;
        }
        fs::path inDir = argv[2];
        fs::path outPak = (argc >= 4 && argv[3][0] != '-') ? argv[3] : "";
        bool encrypt = true;
        uint32_t keyId = DragonNest::DEFAULT_DATA_KEY_ID;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--no-encrypt") {
                encrypt = false;
            } else if (arg == "--key" && i + 1 < argc) {
                keyId = std::stoul(argv[i + 1], nullptr, 16);
            }
        }
        bool ok = HandlePack(inDir, outPak, encrypt, keyId);
        return ok ? 0 : 1;
    } else if (cmd == "list") {
        if (argc < 3) {
            std::cerr << "Usage: dnpacker list <archive.pak> [--filter <pattern>]\n";
            return 1;
        }
        fs::path pakPath = argv[2];
        std::string filter = "";
        if (argc >= 5 && std::string(argv[3]) == "--filter") {
            filter = argv[4];
        }
        DragonNest::PakArchive pak;
        if (!pak.Open(pakPath)) {
            std::cerr << "[-] Failed to open PAK: " << pakPath.string() << "\n";
            return 1;
        }
        pak.List(filter);
        return 0;
    } else if (cmd == "info") {
        if (argc < 3) {
            std::cerr << "Usage: dnpacker info <archive.pak>\n";
            return 1;
        }
        fs::path pakPath = argv[2];
        DragonNest::PakArchive pak;
        if (!pak.Open(pakPath)) {
            std::cerr << "[-] Failed to open PAK: " << pakPath.string() << "\n";
            return 1;
        }
        pak.PrintInfo();
        return 0;
    } else if (cmd == "extract-keys") {
        if (argc < 3) {
            std::cerr << "Usage: dnpacker extract-keys <dragonnest_x64.exe> [output_keys.txt]\n";
            return 1;
        }
        fs::path exePath = argv[2];
        fs::path outTxt = (argc >= 4) ? argv[3] : (exeDir / "keys.txt");
        bool ok = HandleExtractKeys(exePath, outTxt, exeDir);
        return ok ? 0 : 1;
    } else if (cmd == "-h" || cmd == "--help" || cmd == "/help" || cmd == "/?") {
        PrintBanner();
        PrintKeyStatus(hasKeysTxt, keysTxtPath);
        PrintUsage();
        return 0;
    }

    // Otherwise, treat arguments as Drag & Drop items (files or folders)
    PrintBanner();
    PrintKeyStatus(hasKeysTxt, keysTxtPath);
    for (int i = 1; i < argc; ++i) {
        ProcessSinglePath(argv[i], exeDir);
    }

    WaitIfExplorer();
    return 0;
}
