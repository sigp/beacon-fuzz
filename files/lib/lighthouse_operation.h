#pragma once

#ifndef LIGHTHOUSE_FUZZ_HANDLE
#error You must define LIGHTHOUSE_FUZZ_HANDLE
#endif

#include <cstdint>
#include <optional>
#include <vector>

#include "rust.h"

// LIGHTHOUSE_FUZZ_HANDLE should be a function that has the following interface:
// Params:
//  uint8_t* input_ptr: ptr to buffer containing input bytes
//  size_t input_size: size of input buffer
//  uint8_t* output_ptr: ptr to a pre-allocated buffer in which to store the
//  processed output size_t* output_size: size of the allocated output buffer
// Returns:
//  bool indicating success/failure
// Postconditions:
//  output_ptr contains the result of processing
//  output_size is set to the size of the processed result (should be <= to
//  initial value) abort if the result would overflow the output buffer

extern "C" bool LIGHTHOUSE_FUZZ_HANDLE(uint8_t* input_ptr, size_t input_size,
                                       uint8_t* output_ptr,
                                       size_t* output_size);

namespace fuzzing {

// Common implementation for Lighthouse fuzzing handlers targeting state
// operations
class LighthouseOp : public Rust {
  // inherit Rust's constructors
  using Rust::Rust;

  std::optional<std::vector<uint8_t>> run(
      const std::vector<uint8_t>& _data) override {
    /* Copy because attestation_c wants a non-const pointer */
    std::vector<uint8_t> data(_data);

    // give the return buffer surplus space
    size_t output_size = data.size() * 4;
    std::vector<uint8_t> output(output_size);

    if (LIGHTHOUSE_FUZZ_HANDLE(data.data(), data.size(), output.data(),
                               &output_size) == false) {
      return std::nullopt;
    }

    output.resize(output_size);
    return output;
  }
};

}  // namespace fuzzing
