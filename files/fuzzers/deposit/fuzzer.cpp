#define GO_FUZZ_PREFIX zrnt_deposit_
#define NIM_FUZZ_HANDLE nfuzz_deposit
#define LIGHTHOUSE_FUZZ_HANDLE deposit_c

#include <lib/bfuzz_config.h>
#include <lib/differential.h>
#include <lib/go.h>
#include <lib/lighthouse_operation.h>
#include <lib/nim_operation.h>
#include <lib/python.h>
#include <lib/ssz_preprocess.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

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

std::unique_ptr<fuzzing::Differential> differential = nullptr;

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  differential = std::make_unique<fuzzing::Differential>();

  differential->AddModule(std::make_shared<fuzzing::Go>("zrnt"));
  differential->AddModule(std::make_shared<fuzzing::Python>(
      "pyspec", (*argv)[0], PY_SPEC_HARNESS_PATH, std::nullopt,
      PY_SPEC_VENV_PATH, fuzzing::config::disable_bls));
  // differential->AddModule(std::make_shared<fuzzing::Python>(
  //    "trinity", (*argv)[0], TRINITY_HARNESS_PATH, std::nullopt,
  //    TRINITY_VENV_PATH, fuzzing::config::disable_bls));
  differential->AddModule(std::make_shared<fuzzing::LighthouseOp>());
  differential->AddModule(
      std::make_shared<fuzzing::NimOp>(fuzzing::config::disable_bls));

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
  auto v = fuzzing::SSZPreprocess(data, size);
  if (v.empty()) {
    return 0;
  }
  differential->Run(v);

  return 0;
}
