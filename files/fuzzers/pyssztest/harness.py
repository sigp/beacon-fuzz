from eth2spec.fuzzing.decoder import translate_typ, translate_value
from eth2spec.phase0 import spec as spec
from preset_loader import loader
from ssz.exceptions import DeserializationError

presets = loader.load_presets(
    "/home/jhg/eth-2019/x/eth2.0-fuzzing/files/fuzzers/block/eth2.0-specs/configs",
    "minimal",
)
spec.apply_constants_preset(presets)


block_sedes = translate_typ(spec.BeaconBlock)


def FuzzerRunOne(FuzzerInput):
    try:
        obj = block_sedes.deserialize(FuzzerInput)
        serialized = block_sedes.serialize(obj)
        if serialized != FuzzerInput:
            print("original: " + str([FuzzerInput]))
            print("serialized: " + str([serialized]))
            raise Exception("")
    except DeserializationError:
        pass
