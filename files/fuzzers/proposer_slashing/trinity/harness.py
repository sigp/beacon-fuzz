import typing

import eth2._utils.bls as bls
import ssz
from eth2.beacon.state_machines.forks.serenity.configs import SERENITY_CONFIG
from eth2.beacon.state_machines.forks.serenity.operation_processing import (
    process_proposer_slashings,
)
from eth2.beacon.tools.misc.ssz_vector import override_lengths
from eth2.beacon.types.proposer_slashings import ProposerSlashing
from eth2.beacon.types.states import BeaconState
from eth_utils import ValidationError


class Dummy:
    pass


class ProposerSlashingTestCase(ssz.Serializable):

    fields = [("pre", BeaconState), ("proposer_slashing", ProposerSlashing)]

    def __init__(
        self, *, pre: BeaconState, proposer_slashing: ProposerSlashing
    ) -> None:
        super().__init__(pre=pre, proposer_slashing=proposer_slashing)

    def __str__(self) -> str:
        return f"pre={self.pre}, proposer_slashing={self.proposer_slashing}"


def FuzzerInit(bls_disabled: bool) -> None:
    if bls_disabled:
        bls.Eth2BLS.use_noop_backend()
    override_lengths(SERENITY_CONFIG)


def FuzzerRunOne(input_data: bytes) -> typing.Optional[bytes]:
    test_case = ssz.decode(input_data, ProposerSlashingTestCase)

    # NOTE Trinity doesn't implement a standalone process_proposer_slashing
    # So we make a dummy block to pass to process_proposer_slashings
    dummy_block = Dummy()
    dummy_block.body = Dummy()
    dummy_block.body.proposer_slashings = [test_case.proposer_slashing]

    # TODO(gnattishness) disable signature validation
    # TODO(gnattishness) remove IndexError handling once we use a trinity version
    # where ethereum/trinity#1498 is accepted
    try:
        post = process_proposer_slashings(
            state=test_case.pre, block=dummy_block, config=SERENITY_CONFIG
        )
    except (ValidationError, IndexError):
        return None
    return ssz.encode(post)
