#define GO_FUZZ_PREFIX zrnt_shuffle_
#include <assert.h>
#include <lib/bfuzz_config.h>
#include <lib/differential.h>
#include <lib/go.h>
#include <lib/nim.h>
#include <lib/python.h>
#include <lib/rust.h>
#include <lib/util.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <numeric>

#ifndef PY_SPEC_HARNESS_PATH
#error PY_SPEC_HARNESS_PATH undefined
#endif
#ifndef PY_SPEC_VENV_PATH
// python venv containing dependencies
#error PY_SPEC_VENV_PATH undefined
#endif
// TODO(gnattishness) re-enable when TRINITY supports v0.10.1
// #ifndef TRINITY_HARNESS_PATH
// #error TRINITY_HARNESS_PATH undefined
// #endif
// #ifndef TRINITY_VENV_PATH
// // python venv containing dependencies
// #error TRINITY_VENV_PATH undefined
// #endif

extern "C" bool shuffle_list_c(uint64_t *input_ptr, size_t input_size,
                               const uint8_t *seed_ptr);

namespace fuzzing {
class Lighthouse : public Rust {
  std::optional<std::vector<uint8_t>> run(
      const std::vector<uint8_t> &data) override {
    uint16_t count;

    if (data.size() < sizeof(count) + 32) {
      // data is too small
      return std::nullopt;
    }

    // Don't need to copy because the rust shuffle takes a const uint8_t*
    const uint8_t *seed = data.data() + sizeof(count);

    // NOTE: this ensures a little-endian interpretation on all systems
    count = (data[0] | data[1] << 8) % 100;
    assert(sizeof(count) == 2);  // sanity check to protect against later bugs

    std::vector<size_t> input(count);
    std::iota(input.begin(), input.end(), 0);  // input = [0...count-1]

    // NOTE: this uses size_t, where other impls use uint_64_t.
    // `sizeof(size_t) == sizeof(uint64_t)` does not hold on all
    // architectures, but lighthouse only supports 64bit systems.
    assert(sizeof(size_t) == sizeof(uint64_t));

    /* Call Lighthouse shuffle function */
    if (shuffle_list_c(input.data(), input.size(), seed) == false) {
      /* Lighthouse shuffle function failed */
      return std::nullopt;
    }

    return util::VecToLittleEndianBytes(input);
  }

 public:
  Lighthouse() : Rust("lighthouse") {}
};

class Nimbus : public Nim {
  using Nim::Nim;
  // NOTE: Nim uses a "nimbus" name by default
  std::optional<std::vector<uint8_t>> run(
      const std::vector<uint8_t> &data) override {
    uint16_t count;
    if (data.size() < sizeof(count) + 32) {
      // data is too small
      return std::nullopt;
    }

    // NOTE: this ensures a little-endian interpretation on all systems
    count = (data[0] | data[1] << 8) % 100;
    assert(sizeof(count) == 2);  // sanity check to protect against later bugs

    // We copy because nfuzz_shuffle wants a non-const pointer
    std::vector<uint8_t> seed(data.begin() + sizeof(count),
                              data.begin() + sizeof(count) + 32);

    std::vector<uint64_t> output(count);

    // Call Nimbus shuffle function
    // NOTE: this doesn't shuffle an arbitrary array input, assumes output
    // buffer is initially zeroed but produces output assuming an initial input
    // of 0..N
    if (nfuzz_shuffle(seed.data(), output.data(), output.size()) == false) {
      // Nimbus shuffle function failed

      return std::nullopt;
    }

    return util::VecToLittleEndianBytes(output);
  }
};
} /* namespace fuzzing */

std::unique_ptr<fuzzing::Differential> differential = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  differential = std::make_unique<fuzzing::Differential>();

  differential->AddModule(std::make_shared<fuzzing::Go>("zrnt"));
  differential->AddModule(std::make_shared<fuzzing::Python>(
      "pyspec", (*argv)[0], PY_SPEC_HARNESS_PATH, std::nullopt,
      PY_SPEC_VENV_PATH, fuzzing::config::disable_bls));
  // differential->AddModule(std::make_shared<fuzzing::Python>(
  //    "trinity", (*argv)[0], TRINITY_HARNESS_PATH, std::nullopt,
  //    TRINITY_VENV_PATH, fuzzing::config::disable_bls));
  differential->AddModule(std::make_shared<fuzzing::Lighthouse>());
  differential->AddModule(
      std::make_shared<fuzzing::Nimbus>(fuzzing::config::disable_bls));

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::vector<uint8_t> v(data, data + size);

  differential->Run(v);

  return 0;
}
