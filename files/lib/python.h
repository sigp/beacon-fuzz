#pragma once

#include <cstdint>
#include <experimental/propagate_const>  // NOLINT(build/include_order)
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base.h"

namespace fuzzing {

class Python : public Base {
 public:
  Python(const std::string& name, const std::string& argv0,
         const std::filesystem::path scriptPath,
         std::optional<const std::filesystem::path> libPath = std::nullopt,
         std::optional<const std::filesystem::path> venvPath = std::nullopt,
         const bool bls_disabled = true);
  std::optional<std::vector<uint8_t>> Run(
      const std::vector<uint8_t>& data) override;
  const std::string& name() override;
  ~Python();

 private:
  // Uses "pImpl" technique as described here to avoid including the whole
  // <Python.h>: https://en.cppreference.com/w/cpp/language/pimpl
  class Impl;
  std::experimental::propagate_const<std::unique_ptr<Impl>> pimpl_;
  std::string name_;
};

} /* namespace fuzzing */
