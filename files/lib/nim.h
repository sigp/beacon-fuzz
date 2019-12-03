#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "base.h"

namespace fuzzing {

class Nim : public Base {
 private:
  virtual std::optional<std::vector<uint8_t>> run(
      const std::vector<uint8_t>& data) = 0;

 public:
  Nim(void) : Base() {}

  std::optional<std::vector<uint8_t>> Run(
      const std::vector<uint8_t>& data) override {
    return run(data);
  };
};

} /* namespace fuzzing */
