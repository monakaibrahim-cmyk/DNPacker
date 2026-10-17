# DNPacker

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B17)
[![CMake](https://img.shields.io/badge/CMake-3.15%2B-064F8C.svg?logo=cmake)](https://cmake.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)]()

High-performance, cross-platform C++ archive packer, unpacker, and key extractor for **Dragon Nest** `.pak` resource archives.

---

## Features

- **Cross-Platform**: Compiles natively on **Windows** and **Linux** with zero external dependencies (no OpenSSL or third-party crypto libraries required).
- **Static Compilation**: Configured to produce standalone, statically-linked binaries (`/MT` on MSVC, `-static` on GCC/Clang).
- **Two-Tier Hardware Cryptography**:
  - Windows: Hardware-accelerated AES-NI via Windows CNG (`bcrypt.dll`).
  - Linux / POSIX: Optimized, self-contained portable AES-256-ECB engine.
- **Drag & Drop (Windows Explorer)**:
  - Drag a `.pak` archive onto `dnpacker` $\rightarrow$ automatically unpacks to a folder.
  - Drag a folder onto `dnpacker` $\rightarrow$ automatically packs into a `.pak` file.
  - Drag `dragonnest_x64.exe` onto `dnpacker` $\rightarrow$ automatically scans and extracts all 36+ encryption keys into `keys.txt`.
- **Dynamic Key Extraction**: Includes a PE opcode scanner that recovers fresh archive encryption keys directly from updated `dragonnest_x64.exe` binaries.
- **Full Version 10 & 11 PAK Support**: Complete support for both modern and legacy Dragon Nest archive formats.

---

## Dragon Nest PAK File Architecture

### 1. Archive Header (272 bytes / `0x110`)
| Offset | Type | Description |
| :--- | :--- | :--- |
| `0x000` | `char[256]` | Magic string: `"EyedentityGames Packing File 01"` (null-padded) |
| `0x100` | `uint32` | Format version (`10` or `11`) |
| `0x104` | `uint32` | Number of files in archive |
| `0x108` | `uint32` | Absolute file offset to File Entry Table |
| `0x10C` | `uint32` | Reserved / padding |

### 2. File Entry Table (316 bytes / `0x13C` per file)
| Offset | Type | Description |
| :--- | :--- | :--- |
| `0x000` | `char[256]` | Relative file path (Windows backslash format) |
| `0x100` | `uint32` | Compressed payload size in bytes |
| `0x104` | `uint32` | Uncompressed original size in bytes |
| `0x108` | `uint32` | Reserved (typically matches compressed size) |
| `0x10C` | `uint32` | Absolute offset to file payload data |
| `0x110` | `uint8[44]` | Reserved / alignment padding |

### 3. Payload Encryption Scheme (`EwAF256`)
Dragon Nest employs a two-tier AES-256-ECB encryption mechanism:
1. **Header Block (16 bytes)**:
   - Decrypted using the **Master Header Key** (`0x8992FD01` $\rightarrow$ `"fTD6kNYM6vECvYVc3pUutQJ9ZiPoKxQ\0"`).
   - Validated against the magic string `"EwAF256"`.
   - Next 8 ASCII bytes represent the 32-bit hex **Data Key ID** (e.g. `"9B6536B2"`).
2. **Payload Body**:
   - Decrypted using the specific 32-byte AES-256 key corresponding to the Data Key ID.
   - Stripped of PKCS#7 padding.
   - Decompressed via zlib Deflate (`mz_uncompress`).

---

## Ghidra Reverse Engineering Reference

The following table maps functions identified in `dragonnest_x64.exe` for analysis in Ghidra:

| Address | Ghidra Symbol | Recommended Name | Purpose |
| :--- | :--- | :--- | :--- |
| `0x140bfa570` | `FUN_140bfa570` | `CEtPackingFile::Open` | Opens PAK, validates 272-byte header, reads table offset |
| `0x140bfa730` | `FUN_140bfa730` | `CEtPackingFile::ReadFileEntry` | Reads file payload and checks `EwAF256` header |
| `0x140bfba80` | `FUN_140bfba80` | `CEtPackingFile::WriteFileEntry` | Deflate-compresses and AES-encrypts entry |
| `0x140bfa250` | `FUN_140bfa250` | `CEtPackingFile::ReadArchiveHeader` | Parses 272-byte `PakHeaderRaw` |
| `0x140bfa3a0` | `FUN_140bfa3a0` | `CEtPackingFile::ReadFileTable` | Reads array of 316-byte `PakEntryRaw` structs |
| `0x140bfab60` | `FUN_140bfab60` | `CEtPackingFile::Close` | Closes file handle and releases buffers |
| `0x140bfc680` | `FUN_140bfc680` | `CEtPackingFile::SetEncryptionKey` | Configures 32-byte AES key for cipher |
| `0x140bfb1f0` | `FUN_140bfb1f0` | `CEtPackingFile::DecompressPayload` | Decompresses zlib stream (`uncompress`) |
| `0x140bfb2d0` | `FUN_140bfb2d0` | `CEtPackingFile::CompressPayload` | Compresses stream with zlib (`compress`) |
| `0x140c005b0` | `FUN_140c005b0` | `AES256ECB_DecryptBlock` | Core AES-256-ECB block decryption routine |
| `0x140c00620` | `FUN_140c00620` | `AES256ECB_EncryptBlock` | Core AES-256-ECB block encryption routine |
| `0x140c00490` | `FUN_140c00490` | `AES256_KeyExpansion` | Computes 14 round keys from 256-bit key |
| `0x140c05e70` | `FUN_140c05e70` | `InitArchiveKeyTable` | Registers all 36 Key IDs and string pointers |
| `0x140c05750` | `FUN_140c05750` | `GetArchiveKeyById` | Resolves key string given 4-byte Key ID |

---

## Building from Source

### Prerequisites
- CMake 3.15 or newer
- **Windows**: Visual Studio 2019/2022/2026 (MSVC) or MinGW
- **Linux**: GCC 8+ or Clang 9+ with C++17 support

### Windows Build
```cmd
git clone https://github.com/monakaibrahim-cmyk/DNPacker.git
cd DNPacker
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```
The compiled executable will be located at `build\bin\Release\dnpacker.exe`.

### Linux Build
```bash
git clone https://github.com/monakaibrahim-cmyk/DNPacker.git
cd DNPacker
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```
The compiled static executable will be located at `build/bin/dnpacker`.

---

## Usage

### 1. Drag & Drop (Windows)
- **Unpack**: Drag any `.pak` file onto `dnpacker.exe`.
- **Pack**: Drag any directory onto `dnpacker.exe`.
- **Extract Keys**: Drag `dragonnest_x64.exe` onto `dnpacker.exe`.

### 2. Command Line Interface (CLI)
```bash
# Unpack entire archive
dnpacker unpack Resource01.pak [output_directory]

# Unpack only specific files (glob filter)
dnpacker unpack Resource01.pak output_dir --filter "*.xml"

# Pack a directory into a PAK archive (AES-256 encrypted)
dnpacker pack my_modded_folder output.pak

# Pack without encryption
dnpacker pack my_modded_folder output.pak --no-encrypt

# Pack with a specific key ID (hex)
dnpacker pack my_modded_folder output.pak --key 0x9B6536B2

# List contents of an archive
dnpacker list Resource01.pak

# Show archive header metadata
dnpacker info Resource01.pak

# Scan executable and extract all encryption keys
dnpacker extract-keys dragonnest_x64.exe [output_keys.txt]
```

---

## Dynamic Key Extractor

When Dragon Nest releases client updates, new encryption keys can be added or existing keys updated.

`DNPacker` inspects the executable's machine instructions in the `.text` section:
```x86asm
C7 45 F0 [KeyID: 4 bytes]          ; mov dword ptr [rbp - 10h], <KeyID>
48 8D 05 [Disp32: 4 bytes]         ; lea rax, [rip + <offset_to_rdata_key_string>]
```
It computes the RIP-relative displacement:
$$\text{TargetVA} = \text{InsnVA} + 7 + \text{Disp32}$$
and extracts the null-terminated 31-character ASCII key from `.rdata`.

Running:
```bash
dnpacker extract-keys dragonnest_x64.exe
```
automatically generates `keys.txt`, which `dnpacker` reads on startup to support any new key without recompilation.

---

## License

This project is licensed under the [MIT License](LICENSE).
Code of conduct available at [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
