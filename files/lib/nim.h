#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "base.h"
#include "libnfuzz.h"  // Ensure NIM_CPPFLAGS is passed to the preprocessor

namespace fuzzing {

class Nim : public Base {
 private:
  virtual std::optional<std::vector<uint8_t>> run(
      const std::vector<uint8_t>& data) = 0;

 public:
  Nim(void) : Base() { NimMain(); }

  std::optional<std::vector<uint8_t>> Run(
      const std::vector<uint8_t>& data) override {
    return run(data);
  };
};

} /* namespace fuzzing */
