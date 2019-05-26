#pragma once

#include <string>

#define COVERAGE_ARRAY_SIZE 65536

extern "C" {
    __attribute__((section("__libfuzzer_extra_counters")))
    uint8_t coverage_counter[COVERAGE_ARRAY_SIZE];
}

extern "C" void global_record_code_coverage(const char* filename, const char* function, const int line)
{
    static std::hash<std::string> hasher;
    coverage_counter[ hasher(std::string(filename) + std::string(function) + std::to_string(line)) % COVERAGE_ARRAY_SIZE ] = 1;
}

