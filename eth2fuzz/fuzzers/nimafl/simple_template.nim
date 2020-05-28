import
  chronicles,
  nimafl/fuzztest,
  ../targets/nim/lib

test:
    discard lib.fuzz_###TARGET###(payload)

