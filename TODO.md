## TODO

- When differences are detected, print out which one had the differences
- Util that: given corpora identifies what beaconstate it uses (i.e. what the `state_id` is)
- Easier interface to build only selected fuzzers
- Enable/disable support for python impls
- Confirm/figure out Python coverage
- Python use virtualenvs fully instead of appending their PATH
  - Not isolated from system dependencies and editable installs
- Make flag/option to disable or enable bls verification
- Option to build so that errors are printed (not useful for fuzzing, but helpful when replaying a detected difference)?
- Multiple differential passes with the same input? e.g. with validate state root then not?
- bfuzz tool to extract corpora suitable for zcli/integrate with zcli?
- in runtimes (nim etc) catch panics and abort immediately rather than letting them unwind
  lets libfuzzer get the exact location of the crash and avoid unwinding stack frames
  (as described here) https://github.com/rust-fuzz/libfuzzer/blob/master/src/lib.rs
- preprocessing to update eth1 deposit count for `process_deposit`
  `assert len(body.deposits) == min(MAX_DEPOSITS, state.eth1_data.deposit_count - state.eth1_deposit_index)`
  main thing is that state.eth1_deposit_index should never be >= eth1_data.deposit_count if we want to pass it a deposit.
- disable merkle for `process_deposit` and state transition
- fuzz is_valid_merkle_branch on its own?
- bls fuzzing and ssz diff fuzzing?
- diff fuzzing of crypto primitives?
