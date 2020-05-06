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
  std::string name_;

 protected:
  bool bls_disabled;

 public:
  explicit Nim(const bool bls_disabled = true,
               const std::string& name = "nimbus")
      : Base() {
    this->bls_disabled = bls_disabled;
    name_ = name;
    NimMain();
  }

  std::optional<std::vector<uint8_t>> Run(
      const std::vector<uint8_t>& data) override {
    return run(data);
  };
  const std::string& name() override { return name_; }
};

}  // namespace fuzzing
