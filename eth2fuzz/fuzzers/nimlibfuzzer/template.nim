import
    os, chronicles,
    nimlibfuzzer/fuzztest,
    ../targets/nim/lib


# info fuzzing nim:
# https://github.com/status-im/nim-testutils/tree/master/testutils/fuzzing

proc env(): string = 
    return string(getEnv("ETH2FUZZ_BEACONSTATE")) & "/"

# ETH2FUZZ_BEACONSTATE
init: 
    echo "TEST"
    #let dir = getEnv("ETH2FUZZ_BEACONSTATE").string
    #for file in walkFiles(env()):
    #    echo file

test:
    discard lib.fuzz_###TARGET###(payload)




