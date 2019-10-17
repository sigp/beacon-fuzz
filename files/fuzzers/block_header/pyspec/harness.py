import os
import sys
from eth2spec.phase0 import spec

from preset_loader import loader
# TODO N fix config path difficult to do unless we assume the eth2spec
# module is at a fixed position relative to the configs
# (i.e. it is inside a cloned eth2.0-specs repo)
configs_path = '/eth2/eth2.0-specs/configs'
# TODO allow this to be adjusted?
presets = loader.load_presets(configs_path, 'mainnet')
spec.apply_constants_preset(presets)

import copy
from eth2spec.fuzzing.decoder import translate_typ, translate_value
from eth2spec.utils.ssz.ssz_impl import serialize

from eth2spec.utils import bls
bls.bls_active = False

class BlockHeaderTestCase(spec.Container):
    pre: spec.BeaconState
    block: spec.BeaconBlock

block_header_sedes = translate_typ(BlockHeaderTestCase)

def FuzzerRunOne(input_data):
    # looks like verify happens at the end of process
    test_case = translate_value(block_header_sedes.deserialize(input_data), BlockHeaderTestCase)

    # TODO N this returns None on failure - should it return bytes()?

    try:
        # modifies state in place
        spec.process_block_header(test_case.pre, test_case.block)
        # TODO N still need to verify block signature?
        # NOTE - signature verification should do nothing with bls disabled
        # The proposer signature is verified at the end of process_block_header
        return serialize(test_case.pre)
    except AssertionError as e:
        pass
    except IndexError:
        pass
