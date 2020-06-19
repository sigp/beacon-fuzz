# name: nim-beacon-chain
# github: https://github.com/status-im/nim-beacon-chain/

import
    #chronicles,
    ../../../nim-beacon-chain/beacon_chain/spec/crypto,
    ../../../nim-beacon-chain/beacon_chain/spec/datatypes,
    ../../../nim-beacon-chain/beacon_chain/spec/digest,
    ../../../nim-beacon-chain/beacon_chain/spec/validator,
    ../../../nim-beacon-chain/beacon_chain/spec/beaconstate,
    ../../../nim-beacon-chain/beacon_chain/spec/state_transition_block,
    ../../../nim-beacon-chain/beacon_chain/ssz,
    ../../../nim-beacon-chain/beacon_chain/extras,
    ../../../nim-beacon-chain/beacon_chain/state_transition,
    ../../../nim-beacon-chain/beacon_chain/eth2_discovery



# state: BeaconState, 
proc fuzz_nimbus_attestation*(state: var BeaconState, payload: openarray[byte]): bool = 
    try:
        var cache = get_empty_per_epoch_cache()
        let attestation = SSZ.decode(payload, Attestation)        
        discard process_attestation(state, attestation, {}, cache)
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_attester_slashing*(state: var BeaconState, payload: openarray[byte]): bool = 
    try:
        var cache = get_empty_per_epoch_cache()
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
        discard state_transition(hashedState, blck, {}, noRollback)
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_block_header*(state: var BeaconState, payload: openarray[byte]): bool = 
    try:
        var cache = get_empty_per_epoch_cache()
        let blck = SSZ.decode(payload, BeaconBlock)
        discard process_block_header(state, blck, {}, cache)
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_deposit*(state: var BeaconState, payload: openarray[byte]): bool = 
    try:
        let deposit = SSZ.decode(payload, Deposit)
        discard process_deposit(state, deposit, {})
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_proposer_slashing*(state: var BeaconState, payload: openarray[byte]): bool = 
    try:
        var cache = get_empty_per_epoch_cache()
        let proposer =  SSZ.decode(payload, ProposerSlashing)
        discard process_proposer_slashing(state, proposer, {}, cache)
    except SSZError: #CatchableError:
        discard
    true

proc fuzz_nimbus_voluntary_exit*(state: var BeaconState, payload: openarray[byte]): bool = 
    try:
        let exit = SSZ.decode(payload, SignedVoluntaryExit)
        discard process_voluntary_exit(state, exit, {})
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
