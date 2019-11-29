import typing

import eth2._utils.bls as bls
import ssz
from eth2.beacon.state_machines.forks.serenity.configs import SERENITY_CONFIG
from eth2.beacon.state_machines.forks.serenity.state_transitions import (
    SerenityStateTransition,
)
from eth2.beacon.types.blocks import BeaconBlock
from eth2.beacon.types.states import BeaconState
from eth_utils import ValidationError

# TODO(gnattishness) check that this works
bls.Eth2BLS.use_noop_backend()


class BlockTestCase(ssz.Serializable):

    fields = [("pre", BeaconState), ("block", BeaconBlock)]

    def __init__(self, *, pre: BeaconState, block: BeaconBlock) -> None:
        super().__init__(pre=pre, block=block)

    def __str__(self) -> str:
        return f"pre={self.pre}, block={self.block}"


def FuzzerRunOne(input_data: bytes) -> typing.Optional[bytes]:
    test_case = ssz.decode(input_data, BlockTestCase)

    # TODO(gnattishness) enable/disable validate state root?
    # See https://github.com/ethereum/trinity/issues/1340
    transition = SerenityStateTransition(SERENITY_CONFIG)
    try:
        post = transition.apply_state_transition(
            state=test_case.pre, block=test_case.block, check_proposer_signature=True,
        )
    except ValidationError as e:
        return None
    # NOTE - signature verification should do nothing with bls disabled
    return ssz.encode(post)
