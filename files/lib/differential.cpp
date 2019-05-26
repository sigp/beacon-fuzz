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
    std::optional<std::vector<uint8_t>> prev;
    bool first = true;

    for (const auto& module : modules) {
        auto cur = module->Run(data);

        if ( first == false && cur != prev ) {
            printf("Difference detected\n");
            abort();
        }

        first = false;
        prev = cur;
    }
}

} /* namespace fuzzing */
