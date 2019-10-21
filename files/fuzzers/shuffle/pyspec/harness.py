import struct

from eth2spec.phase0 import spec

# TODO N why are we disabling hash caching here?
# monkey patch to revert hash caching
spec.hash = spec._hash


def FuzzerRunOne(fuzzer_input):
    if len(fuzzer_input) < 2 + 32:
        return None
    count = spec.bytes_to_int(fuzzer_input[:2]) % 100
    seed = fuzzer_input[2:34]
    res = [spec.compute_shuffled_index(i, count, seed) for i in range(count)]
    ret = bytes()
    for r in res:
        ret += struct.pack("<Q", r)
    return ret
