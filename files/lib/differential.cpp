#include "differential.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <utility>

namespace {

void prettyPrintOptBytes(const std::optional<std::vector<uint8_t>>& data) {
  // NOTE: this is often pretty useless when you have large amounts of data
  // better to save the differences to a file and compare in a hex editor etc
  if (data) {
    printf("0x");
    for (const auto i : data.value()) {
      printf(" %02X", i);
    }
  } else {
    printf("nullopt");
  }
  printf("\n");
}

// Dumps a uint8_t bytes vector to a file
void dumpBytesVec(std::string filename, const std::vector<uint8_t>& buf) {
  std::ofstream outf(filename,
                     std::ios::out | std::ios::binary | std::ios::trunc);
  if (outf.is_open() && !buf.empty()) {
    outf.write(reinterpret_cast<const char*>(buf.data()), buf.size());
  } else {
    printf("Unable to open file: %s\n", filename.data());
  }
  outf.close();
}

}  // namespace

namespace fuzzing {

Differential::Differential(void) {}
Differential::~Differential() {}

void Differential::AddModule(std::shared_ptr<Base> module) {
  modules.push_back(module);
}

void Differential::Run(const std::vector<uint8_t>& data) {
  std::optional<std::vector<uint8_t>> prev = std::nullopt;
  bool first = true;
  std::shared_ptr<Base> prevmod = nullptr;

  for (const auto& module : modules) {
    std::optional<std::vector<uint8_t>> cur = module->Run(data);

    if (cur && cur.value().empty()) {
      // Workaround equating an empty vector and a nullopt
      // preferable to ignoring empty values
      // Necessary until go-fuzz targets can return a "None/nullopt" equivalent
      // TODO(gnattishness) remove when go can return a nullopt equiv
      cur = std::nullopt;
    }

    if (first == false && cur != prev) {
      // NOTE: an empty list is different to a nullopt
      // TODO(gnattishness) compile-time flag to change how differences are
      // displayed
      printf("Difference detected in %s\n", module->name().data());
      printf("Prev (%s): ", prevmod->name().data());
      if (prev) {
        printf("difference-prev.ssz\n");
        dumpBytesVec("difference-prev.ssz", *prev);
      } else {
        printf("nullopt\n");
      }
      printf("Cur (%s): ", module->name().data());
      if (cur) {
        printf("difference-cur.ssz\n");
        dumpBytesVec("difference-cur.ssz", *cur);
      } else {
        printf("nullopt\n");
      }
      abort();
    }

    first = false;
    prev = std::move(cur);
    prevmod = module;
  }
}

} /* namespace fuzzing */
