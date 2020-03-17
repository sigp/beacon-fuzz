#pragma once

#include <cstdint>
#include <experimental/propagate_const>  // NOLINT(build/include_order)
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base.h"

namespace fuzzing {

// TODO(gnattishness) pass path to java class files?
class Java : public Base {
 public:
  explicit Java(const std::string& name = "java",
                const bool bls_disabled = true);
  std::optional<std::vector<uint8_t>> Run(
      const std::vector<uint8_t>& data) override;
  const std::string& name() override;
  ~Java();

 private:
  // Uses "pImpl" technique as described here
  // https://en.cppreference.com/w/cpp/language/pimpl
  class Impl;
  std::experimental::propagate_const<std::unique_ptr<Impl>> pimpl_;
  std::string name_;
};

} /* namespace fuzzing */
