#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

#include "base.h"

namespace fuzzing {

class Python : public Base {
    private:
        std::string code;
        std::string toPythonArrayString(const std::string variableName, const std::vector<uint8_t>& data);
        void* pFunc = nullptr;
    public:
        Python(const std::string argv0, const std::string scriptPath, std::optional<std::string> libPath = std::nullopt);
        std::optional<std::vector<uint8_t>> Run(const std::vector<uint8_t>& data) override;
};

} /* namespace fuzzing */
