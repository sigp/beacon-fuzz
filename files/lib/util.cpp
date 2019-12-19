#include "util.h"

#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

namespace util {

template <typename T>
std::vector<uint8_t> VecToLittleEndianBytes(const std::vector<T>& vec) {
  size_t t_size = sizeof(T);
  std::vector<uint8_t> result(vec.size() * t_size);
  for (size_t i = 0; i < vec.size(); ++i) {
    T cur = vec[i];
    size_t j = 0;
    while (cur != 0 && j < t_size) {
      result[i * t_size + j] = cur & 0xFF;
      cur >>= 8;
      ++j;
    }
    /* Could use in c++17, but not too readable:
    for ( auto [cur, j] = std::tuple{vec[i], size_t{0}}; cur != 0 && j < t_size;
    ++j, cur >>= 8) {
    */
  }
  return result;
}

// based on https://stackoverflow.com/a/19535628
// returns path to the current executable
std::filesystem::path getExePath() {
  // TODO(gnattishness) might need to include <string_view>
  char result[PATH_MAX];
  ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
  if (count == -1) {
    std::string errMsg =
        std::string("Failed to get current executable path: ") +
        std::strerror(errno);
    throw std::system_error(errno, std::system_category(), errMsg);
  }
  std::string_view resultView(result, count);
  std::filesystem::path exePath(resultView);
  return std::filesystem::canonical(exePath);
}

}  // namespace util
