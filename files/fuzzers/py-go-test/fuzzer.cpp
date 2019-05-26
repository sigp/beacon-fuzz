#define GO_FUZZ_PREFIX py_go_test_
#include <lib/python.h>
#include <lib/differential.h>
#include <lib/go.h>

#ifndef PYTHON_HARNESS_PATH
#error PYTHON_HARNESS_PATH undefined
#endif

std::shared_ptr<fuzzing::Python> python = nullptr;
std::shared_ptr<fuzzing::Go> go = nullptr;

std::unique_ptr<fuzzing::Differential> differential = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    differential = std::make_unique<fuzzing::Differential>();


    differential->AddModule(
        python = std::make_shared<fuzzing::Python>((*argv)[0], PYTHON_HARNESS_PATH)
    );

    differential->AddModule(
            go = std::make_shared<fuzzing::Go>()
    );

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::vector<uint8_t> v(data, data + size);

    differential->Run(v);

    return 0;
}
