#define GO_FUZZ_PREFIX shuffle_
#include <assert.h>
#include <lib/differential.h>
#include <lib/go.h>
#include <lib/python.h>
#include <lib/rust.h>

#include <cstring>

#ifndef PY_SPEC_HARNESS_PATH
#error PY_SPEC_HARNESS_PATH undefined
#endif
#ifndef PY_SPEC_VENV_PATH
// python venv containing dependencies
#error PY_SPEC_VENV_PATH undefined
#endif
#ifndef TRINITY_HARNESS_PATH
#error TRINITY_HARNESS_PATH undefined
#endif
#ifndef TRINITY_VENV_PATH
// python venv containing dependencies
#error TRINITY_VENV_PATH undefined
#endif

extern "C" bool shuffle_list_c(uint64_t *input_ptr, size_t input_size,
                               uint8_t *seed_ptr);

namespace fuzzing {
class Lighthouse : public Rust {
  std::optional<std::vector<uint8_t>> run(
      const std::vector<uint8_t> &data) override {
    std::vector<size_t> input;
    uint16_t count;
    // TODO(gnattishness) use c new instead of malloc?
    uint8_t *seed = reinterpret_cast<uint8_t *>(malloc(32));

    if (data.size() < sizeof(count) + 32) {
      return std::nullopt;
    }

    memcpy(&count, data.data(), sizeof(count));
    count %= 100;
    memcpy(seed, data.data() + sizeof(count), 32);

    input.resize(count);

    // TODO(gnattishness) N fix? - this uses size_t, where other impls use
    // uint_64_t sizeof(size_t) == sizeof(uint64_t) does not hold on all
    // architectures
    assert(sizeof(size_t) == sizeof(uint64_t));
    /* input[0..count] = 0..count */
    for (size_t i = 0; i < count; i++) {
      input[i] = i;
    }

    /* Call Lighthouse shuffle function */
    if (shuffle_list_c(input.data(), input.size(), seed) == false) {
      /* Lighthouse shuffle function failed */

      return std::nullopt;
    }

    /* std::vector<size_t> -> std::vector<uint8_t> */
    std::vector<uint8_t> ret(input.size() * sizeof(size_t));
    memcpy(ret.data(), input.data(), input.size() * sizeof(size_t));

    return ret;
  }
};
} /* namespace fuzzing */

std::shared_ptr<fuzzing::Python> pyspec = nullptr;
std::shared_ptr<fuzzing::Python> trinity = nullptr;
std::shared_ptr<fuzzing::Go> go = nullptr;
std::shared_ptr<fuzzing::Lighthouse> lighthouse = nullptr;

std::unique_ptr<fuzzing::Differential> differential = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  differential = std::make_unique<fuzzing::Differential>();

  differential->AddModule(go = std::make_shared<fuzzing::Go>());
  differential->AddModule(
      pyspec = std::make_shared<fuzzing::Python>(
          (*argv)[0], PY_SPEC_HARNESS_PATH, std::nullopt, PY_SPEC_VENV_PATH));
  differential->AddModule(
      trinity = std::make_shared<fuzzing::Python>(
          (*argv)[0], TRINITY_HARNESS_PATH, std::nullopt, TRINITY_VENV_PATH));
  differential->AddModule(lighthouse = std::make_shared<fuzzing::Lighthouse>());

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::vector<uint8_t> v(data, data + size);

  differential->Run(v);

  return 0;
}
