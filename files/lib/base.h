#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace fuzzing {

class Base {
 public:
  Base(void);
  virtual ~Base();
  virtual std::optional<std::vector<uint8_t>> Run(
      const std::vector<uint8_t>& data) = 0;
};

} /* namespace fuzzing */
