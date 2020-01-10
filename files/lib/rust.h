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
  std::string name_;

 public:
  explicit Rust(const std::string& name) : Base() { name_ = name; }

  std::optional<std::vector<uint8_t>> Run(
      const std::vector<uint8_t>& data) override {
    return run(data);
  };
  const std::string& name() override { return name_; }
};

} /* namespace fuzzing */
