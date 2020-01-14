#pragma once

// Handles compile-time configuration details and provides relevant macros
// Try to restrict all conditional compilation to here and use the provided
// variables/interface.

namespace fuzzing::config {
#ifdef BFUZZ_NO_DISABLE_BLS
inline bool const disable_bls = false;
#else
inline bool const disable_bls = true;
#endif

}  // namespace fuzzing::config
