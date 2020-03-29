import typing

from eth2spec.fuzzing.decoder import translate_typ, translate_value
from eth2spec.phase0 import spec
from eth2spec.utils import bls
from eth2spec.utils.ssz.ssz_impl import serialize
from preset_loader import loader

# TODO(gnattishness) fix config path difficult to do unless we assume the eth2spec
# module is at a fixed position relative to the configs
# (i.e. it is inside a cloned eth2.0-specs repo)
configs_path = "/eth2/eth2.0-specs/configs"
# TODO allow this to be adjusted?
presets = loader.load_presets(configs_path, "mainnet")
spec.apply_constants_preset(presets)


class VoluntaryExitTestCase(spec.Container):
    pre: spec.BeaconState
    exit: spec.SignedVoluntaryExit


voluntary_exit_sedes = translate_typ(VoluntaryExitTestCase)


def FuzzerInit(bls_disabled: bool) -> None:
    if bls_disabled:
        bls.bls_active = False


def FuzzerRunOne(input_data: bytes) -> typing.Optional[bytes]:
    test_case = translate_value(
        voluntary_exit_sedes.deserialize(input_data), VoluntaryExitTestCase
    )

    try:
        # modifies state in place
        spec.process_voluntary_exit(state=test_case.pre, exit=test_case.exit)
        return serialize(test_case.pre)
    except (AssertionError, IndexError):
        return None
