#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace fuzzing {

class Base {
 public:
  Base(void);
  virtual ~Base();
  virtual std::optional<std::vector<uint8_t>> Run(
      const std::vector<uint8_t>& data) = 0;
  virtual const std::string& name() = 0;
};

} /* namespace fuzzing */
