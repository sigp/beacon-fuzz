#include <lib/python.h>
#include <lib/differential.h>

#ifndef PYTHON_HARNESS_PATH
#error PYTHON_HARNESS_PATH undefined
#endif

#ifndef PYTHON_LIB_PATH
#error PYTHON_LIB_PATH undefined
#endif

std::shared_ptr<fuzzing::Python> python = nullptr;

std::unique_ptr<fuzzing::Differential> differential = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    differential = std::make_unique<fuzzing::Differential>();

    differential->AddModule(
            python = std::make_shared<fuzzing::Python>((*argv)[0], PYTHON_HARNESS_PATH, PYTHON_LIB_PATH)
    );

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::vector<uint8_t> v(data, data + size);

    differential->Run(v);

    return 0;
}
