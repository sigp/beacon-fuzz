#pragma once

#include <memory>
#include <vector>

namespace util {

template <typename T>
std::vector<uint8_t> VecToLittleEndianBytes(const std::vector<T>& vec) {
  size_t t_size = sizeof(T);
  std::vector<uint8_t> result(vec.size() * t_size);
  for (size_t i = 0; i < vec.size(); ++i) {
    T cur = vec[i];
    size_t j = 0;
    while (cur != 0 && j < t_size) {
      result[i * t_size + j] = cur & 0xFF;
      cur >>= 8;
      ++j;
    }
    /* Could use in c++17, but not too readable:
    for ( auto [cur, j] = std::tuple{vec[i], size_t{0}}; cur != 0 && j < t_size;
    ++j, cur >>= 8) {
    */
  }
  return result;
}

} /* namespace util */
