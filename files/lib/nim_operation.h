#pragma once

#ifndef NIM_FUZZ_HANDLE
#error You must define NIM_FUZZ_HANDLE
#endif

#include <vector>

#include "nim.h"

namespace fuzzing {

extern "C" {
// TODO(gnattishness) any initialization needed?
bool NIM_FUZZ_HANDLE(uint8_t* input_ptr, size_t input_size, uint8_t* output_ptr,
                     size_t* output_size);
}

// Common implementation for Nim fuzzing handlers targeting state operations
class NimOp : public Nim {
  std::optional<std::vector<uint8_t>> run(
      const std::vector<uint8_t>& _data) override {
    // TODO(gnattishness) implement
  }
}

} /* namespace fuzzing */
