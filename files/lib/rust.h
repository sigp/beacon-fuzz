#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "base.h"

namespace fuzzing {

class Rust : public Base {
 private:
  virtual std::optional<std::vector<uint8_t>> run(
      const std::vector<uint8_t>& data) = 0;

 public:
  Rust(void) : Base() { GO_LLVMFuzzerInitialize(nullptr, nullptr); }

  std::optional<std::vector<uint8_t>> Run(
      const std::vector<uint8_t>& data) override {
    return run(data);
  };
};

} /* namespace fuzzing */
