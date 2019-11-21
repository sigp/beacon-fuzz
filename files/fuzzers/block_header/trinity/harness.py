import ssz
from eth2.beacon.state_machines.forks.serenity.configs import SERENITY_CONFIG
from eth2.beacon.types.block_headers import BeaconBlockHeader
from eth2.beacon.types.states import BeaconState

# TODO confirm SERENITY_CONFIG is equiv to mainnet

# TODO disable bls?


class BlockHeaderTestCase(ssz.Serializable):
    pre: spec.BeaconState
    block: spec.BeaconBlock


block_header_sedes = translate_typ(BlockHeaderTestCase)


def FuzzerRunOne(input_data):
    # looks like verify happens at the end of process
    test_case = translate_value(
        block_header_sedes.deserialize(input_data), BlockHeaderTestCase
    )

    # TODO N this returns None on failure - should it return bytes()?

    try:
        # modifies state in place
        spec.process_block_header(test_case.pre, test_case.block)
        # TODO N still need to verify block signature?
        # NOTE - signature verification should do nothing with bls disabled
        # The proposer signature is verified at the end of process_block_header
        return serialize(test_case.pre)
    except AssertionError as e:
        pass
    except IndexError:
        pass
