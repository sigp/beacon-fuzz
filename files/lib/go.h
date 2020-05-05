#pragma once

#if !defined(GO_FUZZ_PREFIX)
#error You must define GO_FUZZ_PREFIX
#endif

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "base.h"

#define CONCAT(A, B) CONCAT_(A, B)
#define CONCAT_(A, B) A##B

#define GO_LLVMFuzzerTestOneInput \
  CONCAT(GO_FUZZ_PREFIX, BFUZZGolangTestOneInput)
#define GO_LLVMFuzzerResult \
  CONCAT(GO_FUZZ_PREFIX, BFUZZGolangTestOneInput_return)
// TODO(gnattishness) include generated bfuzz-go.h?

namespace fuzzing {

extern "C" {

/* Return type for BFUZZGolangTestOneInput */
struct GO_LLVMFuzzerResult {
  size_t r0; /* resultSize */
  int r1;    /* errnum */
};

typedef struct {
  void *data;
  long long len;
  long long cap;
} GoSlice;

// int GO_LLVMFuzzerInitialize(int *argc, char ***argv);
struct GO_LLVMFuzzerResult GO_LLVMFuzzerTestOneInput(unsigned char *data,
                                                     size_t size);
void BFUZZGolangGetReturnData(unsigned char *dest);
}

class Go : public Base {
  std::string name_;

 public:
  explicit Go(const std::string &name) : Base() {
    name_ = name;
    // GO_LLVMFuzzerInitialize(nullptr, nullptr);
  }

  std::optional<std::vector<uint8_t>> Run(
      const std::vector<uint8_t> &data) override {
    // TODO(gnattishness) any value in static casting to unsigned char?
    // TODO(gnattishness) copy instead of the dodgy const cast? Will linking
    // work if I say it is const?
    struct GO_LLVMFuzzerResult result = GO_LLVMFuzzerTestOneInput(
        const_cast<unsigned char *>(data.data()), data.size());

    if (result.r1) {
      /* An error occurred */
      return std::nullopt;
    } else if (!result.r0) {
      /* No error but empty data
       * No point in retrieving data from Go */
      return std::make_optional<std::vector<uint8_t>>();
    }

    auto ret = std::make_optional<std::vector<uint8_t>>(result.r0);

    BFUZZGolangGetReturnData(ret->data());

    return ret;
  };
  const std::string &name() override { return name_; }
};

} /* namespace fuzzing */
