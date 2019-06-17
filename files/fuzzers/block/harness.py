import os
import sys
from eth2spec.phase0 import spec as spec

# Apply 'minimal' template
from preset_loader import loader
configs_path = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'eth2.0-specs/configs')
presets = loader.load_presets(configs_path, 'minimal')
spec.apply_constants_preset(presets)

import copy
from eth2spec.fuzzing.decoder import translate_typ, translate_value
from eth2spec.utils.ssz.ssz_typing import uint32, uint8
from eth2spec.utils.ssz.ssz_impl import serialize

from eth2spec.utils import bls
bls.bls_active = False

class StateBlock(spec.Container):
    stateID: uint32
    block: spec.BeaconBlock

state_block_sedes = translate_typ(StateBlock)

def load_prestates():
    prestates = []
    assert 'ETH2_FUZZER_STATE_CORPUS_PATH' in os.environ, "ETH2_FUZZER_STATE_CORPUS_PATH not set"
        
    ETH2_FUZZER_STATE_CORPUS_PATH = os.environ['ETH2_FUZZER_STATE_CORPUS_PATH']
    i = 0
    while True:
        try:
            with open(os.path.join(ETH2_FUZZER_STATE_CORPUS_PATH, str(i)), 'rb') as fp:
                raw_value = translate_typ(spec.BeaconState).deserialize(fp.read())
                prestates += [translate_value(raw_value, spec.BeaconState)]
        except FileNotFoundError:
            break
        i += 1
    assert len(prestates) > 0, "Could not load any prestates"
    return prestates

prestates = load_prestates()

def FuzzerRunOne(FuzzerInput):
    state_block = translate_value(state_block_sedes.deserialize(FuzzerInput), StateBlock)
    prestate = copy.deepcopy(prestates[state_block.stateID])

    try:
        poststate = spec.state_transition(prestate, state_block.block, False)
        return serialize(poststate)
    except AssertionError as e:
        pass
    except IndexError:
        pass
