import
    chronicles,
    ../../../nim-testutils/testutils/fuzzing,
    ../targets/nim/lib

test:
    discard lib.fuzz_nimbus_beaconstate(payload)
