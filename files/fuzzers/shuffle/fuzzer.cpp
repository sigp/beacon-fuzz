#define GO_FUZZ_PREFIX shuffle_
#include <assert.h>
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
    // TODO(gnattishness) use c new instead of malloc?
    // any reason not to have this point to the existing vector.data?
    // no need to malloc right?
    // this currently leaks
    uint8_t *seed = reinterpret_cast<uint8_t *>(malloc(32));
    uint16_t count;

    if (data.size() < sizeof(count) + 32) {
      // data is too small
      return std::nullopt;
    }

    // NOTE: this ensures a little-endian interpretation on all systems
    count = (data[0] | data[1] << 8) % 100;
    assert(sizeof(count) == 2);  // sanity check to protect against later bugs

    memcpy(seed, data.data() + sizeof(count), 32);

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
};

class Nimbus : public Nim {
  std::optional<std::vector<uint8_t>> run(
      const std::vector<uint8_t> &data) override {
    // TODO(gnattishness) use c new instead of malloc?
    // any reason not to have this point to the existing vector.data?
    // no need to malloc right?
    uint8_t *seed = reinterpret_cast<uint8_t *>(malloc(32));
    uint16_t count;

    if (data.size() < sizeof(count) + 32) {
      // data is too small
      return std::nullopt;
    }

    memcpy(seed, data.data() + sizeof(count), 32);

    // NOTE: this ensures a little-endian interpretation on all systems
    count = (data[0] | data[1] << 8) % 100;
    assert(sizeof(count) == 2);  // sanity check to protect against later bugs

    std::vector<uint64_t> output(count);

    // Call Nimbus shuffle function
    // NOTE: this doesn't shuffle an arbitrary array input, assumes output
    // buffer is initially zeroed but produces output assuming an initial input
    // of 0..N
    if (nfuzz_shuffle(seed, output.data(), output.size()) == false) {
      // Nimbus shuffle function failed

      return std::nullopt;
    }

    return util::VecToLittleEndianBytes(output);
  }
};
} /* namespace fuzzing */

std::shared_ptr<fuzzing::Python> pyspec = nullptr;
std::shared_ptr<fuzzing::Python> trinity = nullptr;
std::shared_ptr<fuzzing::Go> go = nullptr;
std::shared_ptr<fuzzing::Lighthouse> lighthouse = nullptr;
std::shared_ptr<fuzzing::Nimbus> nimbus = nullptr;

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
  differential->AddModule(nimbus = std::make_shared<fuzzing::Nimbus>());

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::vector<uint8_t> v(data, data + size);

  differential->Run(v);

  return 0;
}
