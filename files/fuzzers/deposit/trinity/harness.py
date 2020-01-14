import typing

import eth2._utils.bls as bls
import ssz
from eth2.beacon.deposit_helpers import process_deposit
from eth2.beacon.state_machines.forks.serenity.configs import SERENITY_CONFIG
from eth2.beacon.state_machines.forks.serenity.states import SerenityBeaconState
from eth2.beacon.tools.misc.ssz_vector import override_lengths
from eth2.beacon.types.deposits import Deposit
from eth_utils import ValidationError


class DepositTestCase(ssz.Serializable):

    fields = [("pre", SerenityBeaconState), ("deposit", Deposit)]

    def __init__(self, *, pre: SerenityBeaconState, deposit: Deposit) -> None:
        super().__init__(pre=pre, deposit=deposit)

    def __str__(self) -> str:
        return f"pre={self.pre}, deposit={self.deposit}"


def FuzzerInit(bls_disabled: bool) -> None:
    if bls_disabled:
        bls.Eth2BLS.use_noop_backend()
    override_lengths(SERENITY_CONFIG)


def FuzzerRunOne(input_data: bytes) -> typing.Optional[bytes]:
    test_case = ssz.decode(input_data, sedes=DepositTestCase)

    # TODO(gnattishness) any other relevant exceptions to catch?
    try:
        post = process_deposit(
            state=test_case.pre, deposit=test_case.deposit, config=SERENITY_CONFIG,
        )
    except ValidationError:
        return None
    return ssz.encode(post)
