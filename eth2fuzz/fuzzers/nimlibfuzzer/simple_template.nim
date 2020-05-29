import
    chronicles,
    nimlibfuzzer/fuzztest,
    ../targets/nim/lib

test:
    discard lib.fuzz_###TARGET###(payload)

