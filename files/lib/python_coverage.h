#pragma once

#define COVERAGE_ARRAY_SIZE 65536

extern "C" {
    __attribute__((section("__libfuzzer_extra_counters")))
    uint8_t coverage_counter[COVERAGE_ARRAY_SIZE];
}

extern "C" void global_record_code_coverage(void* codeptr, int lasti)
{
    coverage_counter[ ((size_t)(codeptr) ^ (size_t)(lasti)) % COVERAGE_ARRAY_SIZE ] = 1;
}
