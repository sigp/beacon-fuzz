# name: nimbus-eth2
# github: https://github.com/status-im/nimbus-eth2/

import
    chronicles,
    ../../../nimbus-eth2/beacon_chain/spec/crypto,
    ../../../nimbus-eth2/beacon_chain/spec/datatypes,
    ../../../nimbus-eth2/beacon_chain/spec/digest,
    ../../../nimbus-eth2/beacon_chain/spec/validator,
    ../../../nimbus-eth2/beacon_chain/spec/beaconstate,
    ../../../nimbus-eth2/beacon_chain/spec/state_transition_block,
    ../../../nimbus-eth2/beacon_chain/spec/presets,
    ../../../nimbus-eth2/beacon_chain/ssz,
    ../../../nimbus-eth2/beacon_chain/extras,
    ../../../nimbus-eth2/beacon_chain/spec/state_transition,
    ../../../nimbus-eth2/beacon_chain/eth2_discovery



# state: BeaconState,
proc fuzz_nimbus_attestation*(state: var BeaconState, payload: openarray[byte]): bool =
    try:
        var cache = StateCache()
        let attestation = SSZ.decode(payload, Attestation)
        discard process_attestation(state, attestation, {}, cache)
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_attester_slashing*(state: var BeaconState, payload: openarray[byte]): bool =
    try:
        var cache = StateCache()
        let attester =  SSZ.decode(payload, AttesterSlashing)
        discard process_attester_slashing(state, attester, {}, cache)
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_block*(state: var BeaconState, payload: openarray[byte]): bool =
    # There's not a perfect approach here, but it's not worth switching the rest
    # and requiring HashedBeaconState (yet). So to keep consistent, puts wrapper
    # only in one function.

    try:
        let blck = SSZ.decode(payload, SignedBeaconBlock)
        var hashedState =
            HashedBeaconState(data: state, root: hash_tree_root(state))
        discard state_transition(mainnetRuntimePreset, hashedState, blck, {}, noRollback)
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_block_header*(state: var BeaconState, payload: openarray[byte]): bool =
    try:
        var cache = StateCache()
        let blck = SSZ.decode(payload, BeaconBlock)
        discard process_block_header(state, blck, {}, cache)
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_deposit*(state: var BeaconState, payload: openarray[byte]): bool =
    try:
        let deposit = SSZ.decode(payload, Deposit)
        discard process_deposit(mainnetRuntimePreset, state, deposit, {})
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_proposer_slashing*(state: var BeaconState, payload: openarray[byte]): bool =
    try:
        var cache = StateCache()
        let proposer =  SSZ.decode(payload, ProposerSlashing)
        discard process_proposer_slashing(state, proposer, {}, cache)
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_voluntary_exit*(state: var BeaconState, payload: openarray[byte]): bool =
    try:
        var cache = StateCache()
        let exit = SSZ.decode(payload, SignedVoluntaryExit)
        discard process_voluntary_exit(state, exit, {}, cache)
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_beaconstate*(payload: openarray[byte]): bool =
    try:
        discard SSZ.decode(payload, BeaconState)
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_enr*(payload: openarray[byte]): bool =
    try:
        discard parseBootstrapAddress($payload)
    except SSZError: #CatchableError:
        discard
    true
