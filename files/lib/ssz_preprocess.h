#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "go.h"

namespace fuzzing {
extern "C" {
int SSZPreprocess(GoSlice);
void SSZPreprocessGetReturnData(GoSlice);
}

std::vector<uint8_t> SSZPreprocess(uint8_t* data, size_t size) {
  const int modifiedSize =
      SSZPreprocess({data, (long long)size, (long long)size});
  if (modifiedSize == 0) {
    return {};
  }

  std::vector<uint8_t> v(modifiedSize);
  SSZPreprocessGetReturnData(
      {v.data(), (long long)v.size(), (long long)v.size()});

  return v;
}
} /* namespace fuzzing */
