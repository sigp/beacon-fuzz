#define GO_FUZZ_PREFIX block_header_
#include <lib/differential.h>
#include <lib/go.h>
#include <lib/python.h>
#include <lib/rust.h>
#include <lib/ssz-preprocess.h>
#include <cstring>

#ifndef PYTHON_HARNESS_PATH
#error PYTHON_HARNESS_PATH undefined
#endif

#ifndef PYTHON_HARNESS_BIN
// python binary to use as the name
#error PYTHON_HARNESS_BIN undefined
#endif

extern "C" bool block_header_c(uint8_t* input_ptr, size_t input_size, uint8_t* output_ptr, size_t* output_size);

namespace fuzzing {
    class Lighthouse : public Rust {
        std::optional<std::vector<uint8_t>> run(const std::vector<uint8_t>& _data) override {
            /* Copy because block_header_c wants a non-const pointer */
            std::vector<uint8_t> data(_data.data(), _data.data() + _data.size());

            size_t output_size = data.size() * 4;
            std::vector<uint8_t> ret(output_size);

            if ( block_header_c(data.data(), data.size(), ret.data(), &output_size) == false ) {
                return std::nullopt;
            }

            ret.resize(output_size);

            return ret;
        }
    };
} /* namespace fuzzing */

std::shared_ptr<fuzzing::Go> go = nullptr;
std::shared_ptr<fuzzing::Lighthouse> lighthouse = nullptr;
std::shared_ptr<fuzzing::Python> pyspec = nullptr;

std::unique_ptr<fuzzing::Differential> differential = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    differential = std::make_unique<fuzzing::Differential>();

    differential->AddModule(
            go = std::make_shared<fuzzing::Go>()
    );

    differential->AddModule(
        pyspec = std::make_shared<fuzzing::Python>(PYTHON_HARNESS_BIN, PYTHON_HARNESS_PATH)
    );

    differential->AddModule(
            lighthouse = std::make_shared<fuzzing::Lighthouse>()
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
