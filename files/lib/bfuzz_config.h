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

// Client-specific flags
// TODO(gnattishness) can't abstract away the conditional includes this way
#ifdef BFUZZ_TRINITY_OFF
inline bool const enable_trinity = false;
#else
inline bool const enable_trinity = true;
#endif
#ifdef BFUZZ_PYSPEC_OFF
inline bool const enable_pyspec = false;
#else
inline bool const enable_pyspec = true;
#endif
inline bool const

// TODO(gnattishness) mapping of these flags to functions?
// enable_if to define as a noop if the flag is not defined?
//
// Then would also need individual types for trinity and pyspec etc

}  // namespace fuzzing::config

// TODO(gnattishness) maybe look into c++17 features to handle equivalent:
// https://coliru.stacked-crooked.com/a/c695575e4dcdecee
// https://stackoverflow.com/questions/52433953/using-constexpr-to-replace-define-and-ifdef-for-conditional-compilation/52441995#52441995
//
