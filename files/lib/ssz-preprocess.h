#pragma once

#include <lib/go.h>

#include <cstdint>
#include <cstddef>
#include <vector>
#include <optional>

namespace fuzzing {
    extern "C" {
        size_t SSZPreprocess(GoSlice);
        void SSZPreprocessGetReturnData(GoSlice);
    }

    std::vector<uint8_t> SSZPreprocess(uint8_t* data, size_t size) {
        const size_t modifiedSize = SSZPreprocess({data, (long long)size, (long long)size});
        if ( modifiedSize == 0 ) {
            return {};
        }

        std::vector<uint8_t> v(modifiedSize);
        SSZPreprocessGetReturnData({v.data(), (long long)v.size(), (long long)v.size()});

        return v;
    }
} /* namespace fuzzing */
