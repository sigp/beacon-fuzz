#define GO_FUZZ_PREFIX block_
#include <lib/differential.h>
#include <lib/python.h>
#include <lib/go.h>
#include <lib/ssz-preprocess.h>
#include <cstring>

#ifndef PYTHON_HARNESS_PATH
#error PYTHON_HARNESS_PATH undefined
#endif

#ifndef PYTHON_HARNESS_BIN
// python binary to use as the name
#error PYTHON_HARNESS_BIN undefined
#endif

std::shared_ptr<fuzzing::Python> pyspec = nullptr;
std::shared_ptr<fuzzing::Go> zrnt = nullptr;

std::unique_ptr<fuzzing::Differential> differential = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    differential = std::make_unique<fuzzing::Differential>();

    differential->AddModule(
        pyspec = std::make_shared<fuzzing::Python>(PYTHON_HARNESS_BIN, PYTHON_HARNESS_PATH)
    );
    differential->AddModule(
        zrnt = std::make_shared<fuzzing::Go>()
    );

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    auto v = fuzzing::SSZPreprocess(data, size);
    if ( v.empty() ) {
        return 0;
    }

    differential->Run(v);

    return 0;
}
