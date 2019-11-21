#define GO_FUZZ_PREFIX shuffle_
#include <lib/python.h>
#include <lib/differential.h>
#include <lib/go.h>
#include <lib/rust.h>
#include <cstring>
#include <assert.h>

#ifndef PY_SPEC_HARNESS_PATH
#error PY_SPEC_HARNESS_PATH undefined
#endif
#ifndef PY_SPEC_HARNESS_BIN
// python binary to use as the name
#error PY_SPEC_HARNESS_BIN undefined
#endif
#ifndef TRINITY_HARNESS_PATH
#error TRINITY_HARNESS_PATH undefined
#endif
#ifndef TRINITY_HARNESS_BIN
// python binary to use as the name
#error TRINITY_HARNESS_BIN undefined
#endif

extern "C" bool shuffle_list_c(uint64_t* input_ptr, size_t input_size, uint8_t* seed_ptr);

namespace fuzzing {
    class Lighthouse_Shuffle : public Rust {
        std::optional<std::vector<uint8_t>> run(const std::vector<uint8_t>& data) override {
            std::vector<size_t> input;
            uint16_t count;
            uint8_t* seed = (uint8_t*)malloc(32);

            if ( data.size() < sizeof(count) + 32 ) {
                return std::nullopt;
            }

            memcpy(&count, data.data(), sizeof(count));
            count %= 100;
            memcpy(seed, data.data() + sizeof(count), 32);

            input.resize(count);

            // TODO N fix? - this uses size_t, where other impls use uint_64_t
            // sizeof(size_t) == sizeof(uint64_t) does not hold on all architectures
            assert(sizeof(size_t) == sizeof(uint64_t));
            /* input[0..count] = 0..count */
            for (size_t i = 0; i < count; i++) {
                input[i] = i;
            }

            /* Call Lighthouse shuffle function */
            if ( shuffle_list_c(input.data(), input.size(), seed) == false ) {
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
std::shared_ptr<fuzzing::Lighthouse_Shuffle> lighthouse = nullptr;

std::unique_ptr<fuzzing::Differential> differential = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    differential = std::make_unique<fuzzing::Differential>();

    differential->AddModule(
            pyspec = std::make_shared<fuzzing::Python>(PY_SPEC_HARNESS_BIN, PY_SPEC_HARNESS_PATH)
    );
    differential->AddModule(
            go = std::make_shared<fuzzing::Go>()
    );
    differential->AddModule(
            trinity = std::make_shared<fuzzing::Python>(TRINITY_HARNESS_BIN, TRINITY_HARNESS_PATH)
    );
    differential->AddModule(
            lighthouse = std::make_shared<fuzzing::Lighthouse_Shuffle>()
    );

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::vector<uint8_t> v(data, data + size);

    differential->Run(v);

    return 0;
}
