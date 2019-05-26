#pragma once

#include <vector>
#include <cstdint>
#include <optional>

namespace fuzzing {

class Base {
    public:
        Base(void);
        virtual ~Base();
        virtual std::optional<std::vector<uint8_t>> Run(const std::vector<uint8_t>& data) = 0;
};

} /* namespace fuzzing */
