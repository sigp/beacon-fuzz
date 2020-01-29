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
