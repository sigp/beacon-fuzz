import os
import sys
from eth2spec.phase0 import spec

# Apply 'minimal' template
from preset_loader import loader
# TODO fix up so not hard-coded
configs_path = '/eth2/eth2.0-specs/configs'
presets = loader.load_presets(configs_path, 'minimal')
spec.apply_constants_preset(presets)

from eth2spec.fuzzing.decoder import translate_typ, translate_value
from eth2spec.utils.ssz.ssz_typing import uint32, uint8
from eth2spec.utils.ssz.ssz_impl import serialize

from eth2spec.utils import bls
bls.bls_active = False

class BlockTestCase(spec.Container):
    pre: spec.BeaconState
    block: spec.BeaconBlock

block_sedes = translate_typ(BlockTestCase)

def FuzzerRunOne(fuzzer_input):
    state_block = translate_value(state_block_sedes.deserialize(fuzzer_input), BlockTestCase)

    try:
        poststate = spec.state_transition(state_block.pre, state_block.block, False)
        return serialize(poststate)
    except AssertionError as e:
        pass
    except IndexError:
        pass
