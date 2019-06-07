#define GO_FUZZ_PREFIX proposer_slashing_
#include <lib/differential.h>
#include <lib/go.h>
#include <lib/ssz-preprocess.h>
#include <cstring>

std::shared_ptr<fuzzing::Go> go = nullptr;

std::unique_ptr<fuzzing::Differential> differential = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    differential = std::make_unique<fuzzing::Differential>();

    differential->AddModule(
            go = std::make_shared<fuzzing::Go>()
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
