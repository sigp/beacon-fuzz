import
    os,
    ../../../nim-testutils/testutils/fuzzing,
    random,
    ../targets/nim/lib,
    ../../../nimbus-eth2/beacon_chain/spec/crypto,
    ../../../nimbus-eth2/beacon_chain/spec/datatypes,
    ../../../nimbus-eth2/beacon_chain/spec/digest,
    ../../../nimbus-eth2/beacon_chain/spec/validator,
    ../../../nimbus-eth2/beacon_chain/spec/beaconstate,
    ../../../nimbus-eth2/beacon_chain/spec/state_transition_block,
    ../../../nimbus-eth2/beacon_chain/ssz,
    ../../../nimbus-eth2/beacon_chain/extras,
    ../../../nimbus-eth2/beacon_chain/spec/state_transition,
    ../../../nimbus-eth2/beacon_chain/eth2_discovery

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
    discard lib.fuzz_nimbus_attester_slashing(beacon, payload)
