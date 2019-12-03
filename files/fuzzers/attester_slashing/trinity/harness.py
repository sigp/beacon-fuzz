import typing

import eth2._utils.bls as bls
import ssz
from eth2.beacon.state_machines.forks.serenity.configs import SERENITY_CONFIG
from eth2.beacon.state_machines.forks.serenity.operation_processing import (
    process_attester_slashings,
)
from eth2.beacon.tools.misc.ssz_vector import override_lengths
from eth2.beacon.types.attester_slashings import AttesterSlashing
from eth2.beacon.types.states import BeaconState
from eth_utils import ValidationError

bls.Eth2BLS.use_noop_backend()
# TODO allow a runtime init instead of setting globally
override_lengths(SERENITY_CONFIG)


class Dummy:
    pass


class AttesterSlashingTestCase(ssz.Serializable):

    fields = [("pre", BeaconState), ("attester_slashing", AttesterSlashing)]

    def __init__(
        self, *, pre: BeaconState, attester_slashing: AttesterSlashing
    ) -> None:
        super().__init__(pre=pre, attester_slashing=attester_slashing)

    def __str__(self) -> str:
        return f"pre={self.pre}, attester_slashing={self.attester_slashing}"


def FuzzerRunOne(input_data: bytes) -> typing.Optional[bytes]:
    test_case = ssz.decode(input_data, AttesterSlashingTestCase)

    # NOTE Trinity doesn't implement a standalone process_attester_slashing
    # So we make a dummy block to pass to process_attester_slashings
    dummy_block = Dummy()
    dummy_block.body = Dummy()
    dummy_block.body.attester_slashings = [test_case.attester_slashing]

    try:
        post = process_attester_slashings(
            state=test_case.pre, block=dummy_block, config=SERENITY_CONFIG
        )
    except ValidationError as e:
        return None
    return ssz.encode(post)
