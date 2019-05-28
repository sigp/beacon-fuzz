import struct
def FuzzerRunOne(FuzzerInput):
    if len(FuzzerInput) < 2 + 32:
        return None
    count = bytes_to_int(FuzzerInput[:2]) % 100
    seed = FuzzerInput[2:34]
    res = [get_shuffled_index(i, count, seed) for i in range(count)]
    ret = bytes()
    for r in res:
        ret += struct.pack('<Q', r)
    return ret
