import struct

import eth2._utils.bls as bls
from eth2.beacon.committee_helpers import compute_shuffled_index
from eth2.beacon.state_machines.forks.serenity.configs import SERENITY_CONFIG
from eth_utils import ValidationError

bls.Eth2BLS.use_noop_backend()


def FuzzerRunOne(fuzzer_input):
    if len(fuzzer_input) < 2 + 32:
        return None
    count = int.from_bytes(fuzzer_input[:2], "little") % 100
    seed = fuzzer_input[2:34]
    try:
        res = [
            compute_shuffled_index(i, count, seed, SERENITY_CONFIG.SHUFFLE_ROUND_COUNT)
            for i in range(count)
        ]
    except ValidationError:
        return None
    ret = bytes()
    # TODO join instead of +=?
    for r in res:
        ret += struct.pack("<Q", r)
    return ret
