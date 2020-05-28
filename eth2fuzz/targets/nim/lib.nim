# name: nim-beacon-chain
# github: https://github.com/status-im/nim-beacon-chain/

import
    chronicles,
    ../../nim-beacon-chain/beacon_chain/spec/crypto,
    ../../nim-beacon-chain/beacon_chain/spec/datatypes,
    ../../nim-beacon-chain/beacon_chain/spec/digest,
    ../../nim-beacon-chain/beacon_chain/spec/validator,
    ../../nim-beacon-chain/beacon_chain/spec/beaconstate,
    ../../nim-beacon-chain/beacon_chain/spec/state_transition_block,
    ../../nim-beacon-chain/beacon_chain/ssz,
    ../../nim-beacon-chain/beacon_chain/extras,
    ../../nim-beacon-chain/beacon_chain/state_transition,
    ../../nim-beacon-chain/beacon_chain/eth2_discovery

# state: BeaconState, 
proc fuzz_nimbus_attestation*(payload: openarray[byte]): bool = 
    try:
        discard SSZ.decode(payload, Attestation)

    except CatchableError:
        discard
    true

proc fuzz_nimbus_attester_slashing*(payload: openarray[byte]): bool = 
    try:
        discard SSZ.decode(payload, AttesterSlashing)
    except CatchableError:
        discard
    true

proc fuzz_nimbus_block*(payload: openarray[byte]): bool = 
    try:
        discard SSZ.decode(payload, BeaconBlock)
    except CatchableError:
        discard
    true

proc fuzz_nimbus_block_header*(payload: openarray[byte]): bool = 
    try:
        discard SSZ.decode(payload, BeaconBlockHeader)
    except CatchableError:
        discard
    true

proc fuzz_nimbus_deposit*(payload: openarray[byte]): bool = 
    try:
        discard SSZ.decode(payload, Deposit)
    except CatchableError:
        discard
    true

proc fuzz_nimbus_proposer_slashing*(payload: openarray[byte]): bool = 
    try:
        discard SSZ.decode(payload, ProposerSlashing)
    except CatchableError:
        discard
    true

proc fuzz_nimbus_voluntary_exit*(payload: openarray[byte]): bool = 
    try:
        discard SSZ.decode(payload, VoluntaryExit)
    except CatchableError:
        discard
    true

proc fuzz_nimbus_beaconstate*(payload: openarray[byte]): bool = 
    try:
        discard SSZ.decode(payload, BeaconState)
    except CatchableError:
        discard
    true

proc fuzz_nimbus_enr*(payload: openarray[byte]): bool = 
    try:
        discard parseBootstrapAddress($payload)
    except CatchableError:
        discard
    true
