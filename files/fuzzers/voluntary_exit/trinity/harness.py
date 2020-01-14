import typing

import eth2._utils.bls as bls
import ssz
from eth2.beacon.state_machines.forks.serenity.configs import SERENITY_CONFIG
from eth2.beacon.state_machines.forks.serenity.operation_processing import (
    process_voluntary_exits,
)
from eth2.beacon.state_machines.forks.serenity.states import SerenityBeaconState
from eth2.beacon.tools.misc.ssz_vector import override_lengths
from eth2.beacon.types.voluntary_exits import VoluntaryExit
from eth_utils import ValidationError


class Dummy:
    pass


class VoluntaryExitTestCase(ssz.Serializable):

    fields = [("pre", SerenityBeaconState), ("voluntary_exit", VoluntaryExit)]

    def __init__(
        self, *, pre: SerenityBeaconState, voluntary_exit: VoluntaryExit
    ) -> None:
        super().__init__(pre=pre, voluntary_exit=voluntary_exit)

    def __str__(self) -> str:
        return f"pre={self.pre}, voluntary_exit={self.voluntary_exit}"


def FuzzerInit(bls_disabled: bool) -> None:
    if bls_disabled:
        bls.Eth2BLS.use_noop_backend()
    override_lengths(SERENITY_CONFIG)


def FuzzerRunOne(input_data: bytes) -> typing.Optional[bytes]:
    test_case = ssz.decode(input_data, sedes=VoluntaryExitTestCase)

    # NOTE Trinity doesn't implement a standalone process_attestation
    # So we make a dummy block to pass to process_voluntary_exits
    dummy_block = Dummy()
    dummy_block.body = Dummy()
    dummy_block.body.voluntary_exits = [test_case.voluntary_exit]

    # TODO(gnattishness) remove IndexError handling once we use a trinity version
    # where ethereum/trinity#1498 is accepted
    try:
        post = process_voluntary_exits(
            state=test_case.pre, block=dummy_block, config=SERENITY_CONFIG,
        )
    except (ValidationError, IndexError):
        return None
    return ssz.encode(post)
