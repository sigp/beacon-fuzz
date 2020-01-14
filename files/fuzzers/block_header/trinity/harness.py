import typing

import eth2._utils.bls as bls
import ssz
from eth2.beacon.state_machines.forks.serenity.block_processing import (
    process_block_header,
)
from eth2.beacon.state_machines.forks.serenity.blocks import SerenityBeaconBlock
from eth2.beacon.state_machines.forks.serenity.configs import SERENITY_CONFIG
from eth2.beacon.state_machines.forks.serenity.states import SerenityBeaconState
from eth2.beacon.tools.misc.ssz_vector import override_lengths
from eth_utils import ValidationError


class BlockHeaderTestCase(ssz.Serializable):

    fields = [("pre", SerenityBeaconState), ("block", SerenityBeaconBlock)]

    def __init__(self, *, pre: SerenityBeaconState, block: SerenityBeaconBlock) -> None:
        super().__init__(pre=pre, block=block)

    def __str__(self) -> str:
        return f"pre={self.pre}, block={self.block}"


def FuzzerInit(bls_disabled: bool) -> None:
    if bls_disabled:
        bls.Eth2BLS.use_noop_backend()
    override_lengths(SERENITY_CONFIG)


def FuzzerRunOne(input_data: bytes) -> typing.Optional[bytes]:
    test_case = ssz.decode(input_data, sedes=BlockHeaderTestCase)

    # TODO(gnattishness) any other relevant exceptions to catch?
    try:
        post = process_block_header(
            state=test_case.pre,
            block=test_case.block,
            config=SERENITY_CONFIG,
            check_proposer_signature=False,
        )
    except ValidationError as e:
        return None
    return ssz.encode(post)
