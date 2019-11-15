#pragma once

#ifndef PRYSM_FUZZ_PREFIX
#error You must define PRYSM_FUZZ_PREFIX
#endif

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#include "base.h"
#include "go.h" // if for some reason it's not already included, we need it for GoSlice

// NOTE: pretty much the same as go.h but with different macros,
// as we need to provide different compile-time function endpoints
// TODO could have these passed as function pointers in construction instead? but more pain for the harness func

// TODO move to common.h?
#define CONCAT(A, B) CONCAT_(A, B)
#define CONCAT_(A, B) A##B

#define PRYSM_LLVMFuzzerInitialize CONCAT(PRYSM_FUZZ_PREFIX, LLVMFuzzerInitialize)
#define PRYSM_LLVMFuzzerTestOneInput CONCAT(PRYSM_FUZZ_PREFIX, LLVMFuzzerTestOneInput)
#define PRYSM_get_return_size CONCAT(PRYSM_FUZZ_PREFIX, get_return_size)
#define PRYSM_get_return_data CONCAT(PRYSM_FUZZ_PREFIX, get_return_data)

namespace fuzzing {

extern "C" {
    int PRYSM_LLVMFuzzerInitialize(int *argc, char ***argv);
    int PRYSM_LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
    int PRYSM_get_return_size(void);
    void PRYSM_get_return_data(GoSlice dest);
}

class Prysm : public Base {
    public:
        Prysm(void) : Base() {
            PRYSM_LLVMFuzzerInitialize(nullptr, nullptr);
        }

        std::optional<std::vector<uint8_t>> Run(const std::vector<uint8_t>& data) override {
            PRYSM_LLVMFuzzerTestOneInput(data.data(), data.size());

            const int retSize = PRYSM_get_return_size();

            if ( retSize == 0 ) {
                /* No point in retrieving data from go */
                // TODO distinguish between returning empty and nullopt
                // would need to change go-fuzz-build interface to allow for this
                return std::nullopt;
            }

            auto ret = std::make_optional<std::vector<uint8_t>>(retSize);

            GoSlice slice {ret->data(), (long long)(ret->size()), (long long)(ret->size())};

            PRYSM_get_return_data(slice);

            return ret;
        };
};

} /* namespace fuzzing */
