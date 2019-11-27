#pragma once

#if !defined(GO_FUZZ_PREFIX)
#error You must define GO_FUZZ_PREFIX
#endif

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "base.h"

#define CONCAT(A, B) CONCAT_(A, B)
#define CONCAT_(A, B) A##B

#define GO_LLVMFuzzerInitialize CONCAT(GO_FUZZ_PREFIX, LLVMFuzzerInitialize)
#define GO_LLVMFuzzerTestOneInput CONCAT(GO_FUZZ_PREFIX, LLVMFuzzerTestOneInput)
#define GO_get_return_size CONCAT(GO_FUZZ_PREFIX, get_return_size)
#define GO_get_return_data CONCAT(GO_FUZZ_PREFIX, get_return_data)

namespace fuzzing {

typedef struct {
  void *data;
  long long len;
  long long cap;
} GoSlice;

extern "C" {
int GO_LLVMFuzzerInitialize(int *argc, char ***argv);
int GO_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int GO_get_return_size(void);
void GO_get_return_data(GoSlice dest);
}

class Go : public Base {
 public:
  Go(void) : Base() { GO_LLVMFuzzerInitialize(nullptr, nullptr); }

  std::optional<std::vector<uint8_t>> Run(
      const std::vector<uint8_t> &data) override {
    GO_LLVMFuzzerTestOneInput(data.data(), data.size());

    const int retSize = GO_get_return_size();

    if (retSize == 0) {
      /* No point in retrieving data from go */
      // TODO(gnattishness) distinguish between returning empty and nullopt
      // would need to change go-fuzz-build interface to allow for this
      return std::nullopt;
    }

    auto ret = std::make_optional<std::vector<uint8_t>>(retSize);

    GoSlice slice{ret->data(), (long long)(ret->size()),
                  (long long)(ret->size())};

    GO_get_return_data(slice);

    return ret;
  };
};

} /* namespace fuzzing */
