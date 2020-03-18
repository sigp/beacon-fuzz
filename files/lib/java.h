#pragma once

#include <cstdint>
#include <experimental/propagate_const>  // NOLINT(build/include_order)
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base.h"

namespace fuzzing {

class Java : public Base {
 public:
  /**
   * Constructor.
   *
   * @param fuzzClass fully-qualified class name
   * @param fuzzMethod name of fuzz harness method
   * @param classPath contains a java CLASSPATH setting, as defined in
   * https://docs.oracle.com/javase/tutorial/essential/environment/sysprop.html
   * e.g. : separated filesystem paths for Unix
   * @param string identifier for the fuzzing module
   * @param bls_disabled whether BLS verification is disabled
   */
  Java(const std::string& fuzzClass, const std::string& fuzzMethod,
       const std::string& classPath = ".", const std::string& name = "java",
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
