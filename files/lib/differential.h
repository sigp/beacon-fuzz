#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "base.h"

namespace fuzzing {

class Differential {
 private:
  std::vector<std::shared_ptr<Base>> modules;

 public:
  Differential(void);
  ~Differential();

  void AddModule(std::shared_ptr<Base> module);
  void Run(const std::vector<uint8_t>& data);
};

} /* namespace fuzzing */
