#pragma once

#include <filesystem>
#include <vector>

namespace util {

template <typename T>
std::vector<uint8_t> VecToLittleEndianBytes(const std::vector<T>& vec);

// returns path to the current executable
std::filesystem::path getExePath();

}  // namespace util
