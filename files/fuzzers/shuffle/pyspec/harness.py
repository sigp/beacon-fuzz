import struct

from eth2spec.phase0 import spec

# monkey patch to revert hash caching
spec.hash = spec._hash

def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 2 + 32:
        return None
    count = spec.bytes_to_int(FuzzerInput[:2]) % 100
    seed = FuzzerInput[2:34]
    res = [spec.compute_shuffled_index(i, count, seed) for i in range(count)]
    ret = bytes()
    for r in res:
        ret += struct.pack('<Q', r)
    return ret
