#include <stdio.h>
#include <cstdlib>
#include "differential.h"

namespace fuzzing {

Differential::Differential(void) { }
Differential::~Differential() { }

void Differential::AddModule(std::shared_ptr<Base> module) {
    modules.push_back(module);
}

void Differential::Run(const std::vector<uint8_t> data) const {
    std::optional<std::vector<uint8_t>> prev = std::nullopt;
    bool first = true;

    for (const auto& module : modules) {
        auto cur = module->Run(data);

        if ( cur == std::nullopt ) {
            // TODO N discuss - want to differentiate between an error response
            // a bug? this won't detect a difference when 1 impl gives no response and another gives some
            // depends what std:nullopt "means" wrt the diff fuzzer interface
            continue;
        }

        if ( first == false && cur != prev ) {
            printf("Difference detected\n");
            abort();
        }

        first = false;
        prev = cur;
    }
}

} /* namespace fuzzing */
