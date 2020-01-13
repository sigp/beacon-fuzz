lighthouse_package_name := swap_or_not_shuffle_fuzzer

# bls is not relevant here, and isn't necessarily an available
# compile option e.g. no equivalent Rust feature
BFUZZ_NO_DISABLE_BLS := 1
