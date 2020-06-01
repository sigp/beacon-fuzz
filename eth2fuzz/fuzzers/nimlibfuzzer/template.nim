import
    os,
    fuzztest,
    random,
    ../targets/nim/lib


# info fuzzing nim:
# https://github.com/status-im/nim-testutils/tree/master/testutils/fuzzing

# var beacon: BeaconState

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

    # shuffle state order in the list
    shuffle(states)
    for state in states:
        echo state

        # TODO - make ssz load state to work 
        # SSZ.loadFile(state, BeaconState)


    echo "OK"

test:
    discard lib.fuzz_###TARGET###(payload)
