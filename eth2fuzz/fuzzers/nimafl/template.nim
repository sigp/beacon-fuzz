import
    os, chronicles,
    nimafl/fuzztest,
    ../targets/nim/lib


# info fuzzing nim:
# https://github.com/status-im/nim-testutils/tree/master/testutils/fuzzing

# ETH2FUZZ_BEACONSTATE
init: 
    echo "TEST"
    echo getEnv("ETH2FUZZ_BEACONSTATE")
    

test:
    discard lib.fuzz_###TARGET###(payload)




