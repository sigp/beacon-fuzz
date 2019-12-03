import typing

import eth2._utils.bls as bls
import ssz
from eth2.beacon.state_machines.forks.serenity.blocks import SerenityBeaconBlock
from eth2.beacon.state_machines.forks.serenity.configs import SERENITY_CONFIG
from eth2.beacon.state_machines.forks.serenity.state_transitions import (
    SerenityStateTransition,
)
from eth2.beacon.state_machines.forks.serenity.states import SerenityBeaconState
from eth_utils import ValidationError

VALIDATE_STATE_ROOT = True

if VALIDATE_STATE_ROOT:
    from eth2._utils.ssz import validate_imported_block_unchanged

# TODO(gnattishness) check that this works
bls.Eth2BLS.use_noop_backend()

st_instance = SerenityStateTransition(SERENITY_CONFIG)


class BlockTestCase(ssz.Serializable):

    # TODO should be serenitybeaconstate&beaconblock?
    fields = [("pre", SerenityBeaconState), ("block", SerenityBeaconBlock)]

    def __init__(self, *, pre: SerenityBeaconState, block: SerenityBeaconBlock) -> None:
        super().__init__(pre=pre, block=block)

    def __str__(self) -> str:
        return f"pre={self.pre}, block={self.block}"


def FuzzerRunOne(input_data: bytes) -> typing.Optional[bytes]:
    test_case = ssz.decode(input_data, BlockTestCase)

    try:
        post = st_instance.apply_state_transition(
            state=test_case.pre, block=test_case.block, check_proposer_signature=True,
        )
        if VALIDATE_STATE_ROOT:
            # NOTE trinity performs state root validation at a higher level
            # so we perform it here if needed.
            # See https://github.com/ethereum/trinity/issues/1340
            # https://github.com/ethereum/trinity/blob/0d53ef2cf57458d11c5a5b0e5546b026f2fce3f9/eth2/beacon/chains/base.py#L413-L415

            # TODO when updating spec versions, ensure this matches the relevant
            # Trinity code
            post_block = test_case.block.copy(state_root=post.hash_tree_root)
            # Raises a ValidationError if state_roots are different
            validate_imported_block_unchanged(test_case.block, post_block)
    except ValidationError as e:
        return None
    # NOTE - signature verification should do nothing with bls disabled
    return ssz.encode(post)
