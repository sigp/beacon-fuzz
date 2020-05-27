import
  chronicles,
  ../fuzztest,
  lib

test:
    discard lib.fuzz_###TARGET###(payload)
