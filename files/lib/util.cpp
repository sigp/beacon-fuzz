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
