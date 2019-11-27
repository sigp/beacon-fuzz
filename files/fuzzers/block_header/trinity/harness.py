import typing

import ssz
from eth2.beacon.state_machines.forks.serenity.block_processing import (
    process_block_header,
)
from eth2.beacon.state_machines.forks.serenity.configs import SERENITY_CONFIG
from eth2.beacon.types.blocks import BeaconBlock
from eth2.beacon.types.states import BeaconState
from eth_utils import ValidationError

# TODO disable bls?


class BlockHeaderTestCase(ssz.Serializable):

    fields = [("pre", BeaconState), ("block", BeaconBlock)]

    def __init__(self, *, pre: BeaconState, block: BeaconBlock) -> None:
        super().__init__(pre=pre, block=block)

    def __str__(self) -> str:
        return f"pre={self.pre}, block={self.block}"


def FuzzerRunOne(input_data: bytes) -> typing.Optional[bytes]:
    # TODO(gnattishness) ensure abort if deserialize fails
    test_case = ssz.decode(input_data, BlockHeaderTestCase)

    # TODO(gnattishness) any other relevant exceptions to catch?
    # TODO(gnattishness) do we validate signatures or not here?
    try:
        post = process_block_header(
            state=test_case.pre,
            block=test_case.block,
            config=SERENITY_CONFIG,
            check_proposer_signature=False,
        )
    except ValidationError as e:
        return None
    # TODO(gnattishness) is this right?
    return ssz.encode(post)
