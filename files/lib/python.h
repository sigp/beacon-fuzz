#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <filesystem>
#include <memory>
#include <experimental/propagate_const>

#include "base.h"

namespace fuzzing {

class Python : public Base {
    public:
        Python(const std::string argv0,
               const std::filesystem::path scriptPath,
               std::optional<std::filesystem::path> libPath = std::nullopt,
               std::optional<std::filesystem::path> venvPath = std::nullopt
               );
        std::optional<std::vector<uint8_t>> Run(const std::vector<uint8_t>& data) override;
        ~Python();
    private:
        // Uses "pImpl" technique as described here to avoid including the whole <Python.h>:
        // https://en.cppreference.com/w/cpp/language/pimpl
        class Impl;
        std::experimental::propagate_const<std::unique_ptr<Impl>> pimpl_;
};

} /* namespace fuzzing */
