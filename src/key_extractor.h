#pragma once

#include <string>
#include <map>
#include <cstdint>
#include <filesystem>

namespace DragonNest {

/**
 * Dynamically scans and extracts Dragon Nest archive encryption keys
 * directly from an updated dragonnest_x64.exe executable.
 * Fully cross-platform: runs on Linux, macOS, and Windows.
 *
 * @param exePath  Path to dragonnest_x64.exe
 * @param outKeys  Map populated with extracted (KeyID -> KeyString) pairs
 * @param errMsg   Error string if extraction fails
 * @return True if one or more keys were successfully extracted.
 */
bool ExtractKeysFromExecutable(
    const std::filesystem::path& exePath,
    std::map<uint32_t, std::string>& outKeys,
    std::string& errMsg
);

/**
 * Saves extracted keys to a text file for caching / inspection.
 */
bool SaveKeysToFile(const std::filesystem::path& filePath, const std::map<uint32_t, std::string>& keys);

/**
 * Loads keys from a text file if available.
 */
bool LoadKeysFromFile(const std::filesystem::path& filePath, std::map<uint32_t, std::string>& outKeys);

} // namespace DragonNest
