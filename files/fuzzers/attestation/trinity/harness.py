import typing

import eth2._utils.bls as bls
import ssz
from eth2.beacon.state_machines.forks.serenity.configs import SERENITY_CONFIG
from eth2.beacon.state_machines.forks.serenity.operation_processing import (
    process_attestations,
)
from eth2.beacon.tools.misc.ssz_vector import override_lengths
from eth2.beacon.types.attestations import Attestation
from eth2.beacon.types.states import BeaconState
from eth_utils import ValidationError

# TODO do we have to override lengths for the AttestationTestCase?
# I don't think so - only when there are dynamic lengthed items


class Dummy:
    pass


class AttestationTestCase(ssz.Serializable):

    fields = [("pre", BeaconState), ("attestation", Attestation)]

    def __init__(self, *, pre: BeaconState, attestation: Attestation) -> None:
        super().__init__(pre=pre, attestation=attestation)

    def __str__(self) -> str:
        return f"pre={self.pre}, attestation={self.attestation}"


def FuzzerInit(bls_disabled: bool) -> None:
    if bls_disabled:
        bls.Eth2BLS.use_noop_backend()
    override_lengths(SERENITY_CONFIG)


def FuzzerRunOne(input_data: bytes) -> typing.Optional[bytes]:
    test_case = ssz.decode(input_data, AttestationTestCase)

    # NOTE Trinity doesn't implement a standalone process_attestation
    # So we make a dummy block to pass to process_attestations
    dummy_block = Dummy()
    dummy_block.body = Dummy()
    dummy_block.body.attestations = [test_case.attestation]

    # TODO(gnattishness) any other relevant exceptions to catch?
    try:
        post = process_attestations(
            state=test_case.pre, block=dummy_block, config=SERENITY_CONFIG
        )
    except ValidationError:
        return None
    return ssz.encode(post)
