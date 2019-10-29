#include <stdio.h>
#include <cstdlib>
#include<utility>
#include "differential.h"

namespace {

void prettyPrintOptBytes(const std::optional<std::vector<uint8_t>>& data) {

    if (data) {
        printf("0x");
        for (const auto i: data.value()) {
            printf(" %02X", i);
        }
    } else {
        printf("nullopt");
    }
    printf("\n");
}

}

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
        std::optional<std::vector<uint8_t>> cur = module->Run(data);

        if (cur && cur.value().empty()) {
            // Workaround equating an empty vector and a nullopt
            // preferable to ignoring empty values
            // Necessary until go-fuzz targets can return a "None/nullopt" equivalent
            // TODO remove when go can return a nullopt equiv
            cur = std::nullopt;
        }

        if ( first == false && cur != prev ) {
            // NOTE: an empty list is different to a nullopt
            printf("Difference detected\n");
            printf("Prev:\n\t");
            prettyPrintOptBytes(prev);
            printf("Cur:\n\t");
            prettyPrintOptBytes(cur);
            abort();
        }

        first = false;
        prev = std::move(cur);
    }
}

} /* namespace fuzzing */
