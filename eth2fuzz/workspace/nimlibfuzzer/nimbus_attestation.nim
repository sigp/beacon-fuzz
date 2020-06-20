import
    os,
    ../../../nim-testutils/testutils/fuzzing,
    random,
    ../targets/nim/lib,
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

# info fuzzing nim:
# https://github.com/status-im/nim-testutils/tree/master/testutils/fuzzing

var beacon {.global.} : BeaconState

# ETH2FUZZ_BEACONSTATE
init:

    echo "testing - ETH2FUZZ_BEACONSTATE"

    # Get beaconstate folder
    var dir: string
    dir = getEnv("ETH2FUZZ_BEACONSTATE").string

    # translate iterator to seq[string] list
    var states = newSeq[string]()
    for file in walkFiles(dir & "/*"):
        states.add(file)

    randomize()
    # shuffle state order in the list
    shuffle(states)
    block iter:
        for state in states:
            echo state

            # try to find a valid beaconstate
            try: 
                beacon = SSZ.loadFile(state, BeaconState)
                break iter
            except SSZError:
                continue
    echo "OK"
    echo sizeof(beacon)

test:
    discard lib.fuzz_nimbus_attestation(beacon, payload)
