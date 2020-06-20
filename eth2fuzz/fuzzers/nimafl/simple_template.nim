import
    chronicles,
    ../../nim-testutils/testutils/fuzzing,
    ../targets/nim/lib

test:
    discard lib.fuzz_###TARGET###(payload)

