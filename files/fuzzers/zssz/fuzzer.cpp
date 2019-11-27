#define GO_FUZZ_PREFIX zssz_
#include <lib/go.h>

#include <memory>

std::shared_ptr<fuzzing::Go> zrnt_ssz = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  zrnt_ssz = std::make_shared<fuzzing::Go>();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  const std::vector<uint8_t> v(data, data + size);
  zrnt_ssz->Run(v);

  return 0;
}
