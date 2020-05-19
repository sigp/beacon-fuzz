# beacon-fuzz

Open-source differential fuzzing of Ethereum 2.0 Phase 0 implementations.
Maintained by Sigma Prime for the Ethereum Foundation.

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## Overview

A differential fuzzer of Eth2.0 implementations using [libfuzzer](https://llvm.org/docs/LibFuzzer.html).
By default, fuzzing progresses indefinitely unless an implementation panics or differing output is identified.

This is a continuation of Guido Vranken's [eth2.0-fuzzing](https://github.com/guidovranken/eth2.0-fuzzing).

This project and its inner workings are subject to change.

**A note on terminology:** "client" and "implementation" are used interchangeably here to mean a specific Eth2 implementation.

## Current Status

Currently fuzzes against Eth2 `v0.9.1` python or Go executable specs
([pyspec](https://github.com/ethereum/eth2.0-specs/tree/v0.9.1/test_libs/pyspec) or [zrnt](https://github.com/protolambda/zrnt/tree/v0.9.1))


### Implementations

* [Lighthouse](https://github.com/sigp/lighthouse/) (rust)
* [Nimbus](https://github.com/status-im/nim-beacon-chain) (nim)
* [pyspec](https://github.com/ethereum/eth2.0-specs/tree/dev/test_libs/pyspec) (python)
* [Trinity](https://github.com/ethereum/trinity) (python)
* [zrnt](https://github.com/protolambda/zrnt/) (go)


### Operational Fuzz Targets:

(and their relevant spec function)

All currently use the "mainnet" config: https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/configs/mainnet.yaml

* `attestation` - [`process_attestation`](https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/specs/core/0_beacon-chain.md#attestations)
* `attester_slashing` - [`process_attester_slashing`](https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/specs/core/0_beacon-chain.md#attester-slashings)
* `block` - [`state_transition`](https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function)
* `block_header` - [`process_block_header`](https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/specs/core/0_beacon-chain.md#block-header)
* `deposit` - [`process_deposit`](https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/specs/core/0_beacon-chain.md#deposits)
* `proposer_slashing` - [`process_proposer_slashing`](https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/specs/core/0_beacon-chain.md#proposer-slashings)
* `shuffle` -  [`compute_shuffled_index`](https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/specs/core/0_beacon-chain.md#compute_shuffled_index)
* `voluntary_exit` - [`process_voluntary_exit`](https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/specs/core/0_beacon-chain.md#voluntary-exits)

See [corpora](https://github.com/sigp/beacon-fuzz-corpora) repository for explanation of input structure.

### Corpora

See [corpora](https://github.com/sigp/beacon-fuzz-corpora) for examples and explanation of structure.


## Usage

Quickstart:

```console
$ git clone --depth 1 --recurse-submodules https://github.com/sigp/beacon-fuzz.git
$ git clone --depth 1 https://github.com/sigp/beacon-fuzz-corpora.git
$ cd beacon-fuzz
$ sudo ./runfuzzer.sh block_header ../beacon-fuzz-corpora/0-9-1/mainnet/block_header/ ../beacon-fuzz-corpora/0-9-1/mainnet/beaconstate
```

Interactive usage:

```console
$ git clone --depth 1 --recurse-submodules https://github.com/sigp/beacon-fuzz.git
$ cd beacon-fuzz
$ sudo docker build . -t beacon_fuzz
$ sudo docker run -it beacon_fuzz bash
# git clone --depth 1 https://github.com/sigp/beacon-fuzz-corpora.git
# export ETH2_FUZZER_STATE_CORPUS_PATH="/eth2/beacon-fuzz-corpora/0-9-1/mainnet/beaconstate"
# /eth2/fuzzers/attestation/fuzzer /eth2/beacon-fuzz-corpora/0-9-1/mainnet/attestation
```

Use `jobs=N` to run N simultaneous jobs (by default in `num_cpu_cores/2` processes).

Use `help=1` for more arguments (see also [libfuzzer docs](https://llvm.org/docs/LibFuzzer.html))


## Roadmap

- Add more implementations
- Add more fuzz targets
- Improved onboarding, ease of adding new targets and implementations
- Improved coverage measurements and visibility
- Deploy on dedicated production fuzzing infrastructure
- Structure-aware fuzzing mutations
- Mutate input `BeaconState`s


### Implementation Roadmap

The following implementations will be added to the various fuzzing targets:

* [Prysm](https://github.com/prysmaticlabs/prysm)
* [Teku](https://github.com/PegaSysEng/artemis)
* [Lodestar](https://github.com/ChainSafe/lodestar)

## Contributing

Use [pre-commit](https://pre-commit.com/)

```console
$ pre-commit install
```
(see also [.pre-commit-config.yaml](./.pre-commit-config.yaml))

If build fails, comment the `RUN /eth2/build.sh` in `Dockerfile`, and run it manually from within the container.
Can adjust Makefiles as needed.

It is generally fine to run `build.sh` multiple times, and previously built components will be ignored.

### `make`ing fuzzers directly

This is quicker than re-running `./build.sh` and is useful when troubleshooting specific build issues.

After running `build.sh` once, a file `/eth2/exported_env.sh` will be created.
Sourcing this will ensure you have all the environment variables required by the Makefiles.

NOTE: the fuzzer's Makefiles do not currently identify changes to dependent file outside of the `fuzzers` directory.
So, for example, a change to a dependent file in `./files/lib` will require a `make clean` (or equivalent) for the modifications to be visible.

#### Compile-time options

The following make variable flags are exposed (and are enabled by setting them to anything other than ''):
e.g. `make BFUZZ_NO_DISABLE_BLS=1 all`

- `BFUZZ_NO_DISABLE_BLS` - don't disable bls verification


### Adding new implementations for a target

TODO

See pyspec `harness.py`s for a succinct, readable harness implementation example without much boilerplate.

For state transition functions, each client should expect to receive a correctly-encoded SSZ container containing a `BeaconState`,
and an input object relevant for the transition. (As described in https://github.com/sigp/beacon-fuzz-corpora/blob/master/0-8-3/README.md,
except `state_id` has been replaced with a corresponding `BeaconState`.)

Please panic/abort if SSZ decoding fails, as this indicates an error in preprocessing or the SSZ libraries.
e.g. even though a client implementing the Attestation fuzz target can expect to receive any arbitrary `Attestation` object,
it should be in the form of a validly-encoded SSZ blob.

Currently clients will only receive known, valid `BeaconState`s (from `ETH2_FUZZER_STATE_CORPUS_PATH`) so the actual fuzzing/mutation is performed with the other part of the input.
This is because clients generally maintain their own `BeaconState`s, so don't expect to receive arbitrary states from untrusted sources.
(It is also highly unlikely that current mutation will ever produce a valid `BeaconState`)

There are 3 types of results/outputs that a client is expected to return to the fuzzer:

1. A bytestring/bytearray/blob (usually a SSZ-encoding of the `BeaconState` post-transition).
2. An error result (usually a `nullptr`, `None` or `False` equivalent).
  - To be returned when the operation failed but the client is in a consistent state
    (e.g. supplied Attestation data does not refer to an appropriate epoch).
  - The c++ module returns this as a `std::nullopt`.
  - This is necessary to differentiate from the few cases where an empty bytestring is a valid and successful result
    e.g. shuffling an empty list.
3. Abort/panic.
  - To occur when a client is in an inconsistent state and indicates a bug is present.

### Client modifications

TODO disabling BLS verification?

### Adding a new fuzzing target

TODO

## Known bugs/limitations

- Python editable installs in Venvs aren't detected.

## Trophies

- [Nimbus: `process_attestation` missing index validation](https://github.com/status-im/nim-beacon-chain/issues/659) **fixed**
- [Nimbus: `process_deposit` not validating merkle proofs](https://github.com/status-im/nim-beacon-chain/issues/703) **fixed**
- [Nimbus: `ncli_pretty` `Deposit` SSZ parsing `AssertionError`](https://github.com/status-im/nim-beacon-chain/issues/895) **fixed**
- [Nimbus: `ncli_pretty` Bytes Reader `IndexError` decoding `BeaconState` with empty container](https://github.com/status-im/nim-beacon-chain/issues/896) **fixed**
- [Nimbus: `ncli_pretty` Bytes Reader `IndexError` decoding `BeaconState` with variable list reporting 0 length](https://github.com/status-im/nim-beacon-chain/issues/920) **fixed**
- [Nimbus: `ncli_transition` out of memory segfault during `process_final_updates`](https://github.com/status-im/nim-beacon-chain/issues/921) **fixed**
- [Nimbus: `ncli_transition` `AssertionError` due to inconsistent aggregation bits and committee length when passed *invalid* `BeaconState` and `BeaconBlock`](https://github.com/status-im/nim-beacon-chain/issues/922) (See [1](#invalidState)) **fixed**
- [Nimbus: `ncli` `IndexError` decoding 0-byte SSZ BitList](https://github.com/status-im/nim-beacon-chain/issues/931) **fixed**
- [Trinity: some block validation raising `IndexError`, not caught by `BeaconChainSyncer`](https://github.com/ethereum/trinity/issues/1497)
- [Teku: infinite loop when decoding SSZ `BitList` without "end-of-list" marker bit](https://github.com/PegaSysEng/teku/issues/1674) **fixed**
- [Teku: transition subcommand raising `IllegalArgumentException` instead of logging when passed invalid SSZ](https://github.com/PegaSysEng/teku/issues/1675) **fixed**
- [Teku: transition subcommand raising `IllegalArgumentException` instead of logging when passed invalid SSZ](https://github.com/PegaSysEng/teku/issues/1677) **fixed**
- [Teku: `IndexOutOfBoundsException` when SSZ decoding 0-byte `BitList`](https://github.com/PegaSysEng/teku/issues/1678) **fixed**
- [Teku: `IndexOutOfBoundsException` when passed *invalid* `BeaconState` and committee size is inconsistent with attestation aggregation bits](https://github.com/PegaSysEng/teku/issues/1685). (See [1](#invalidState)) **fixed**
- [Lighthouse: out-of-bounds offset in variable list SSZ decoding](https://github.com/sigp/lighthouse/pull/974) **fixed**
- [Lighthouse: multiplication overflow in `compute_proposer_index`](https://github.com/sigp/lighthouse/pull/1009) (See [1](#invalidState)) **fixed**
- [Lighthouse: ENR panic](https://github.com/AgeManning/enr/pull/12) **fixed**
- [Lighthouse: Underflow in Snappy (external dependency)](https://github.com/BurntSushi/rust-snappy/pull/30)
- [Lodestar: `TypeError` when SSZ decoding a `Block` with invalid `BigInt` parent scope](https://github.com/ChainSafe/ssz/issues/22)
- [Lodestar: `RangeError` when SSZ decoding an empty `Block` container](https://github.com/ChainSafe/ssz/issues/23)

<a name="invalidState">1</a>: **NOTE** `BeaconState` objects are consider as trusted input (for the moment), so client state transition functions are not expected to handle invalid `BeaconState` values.

## License

MIT - see [LICENSE](./LICENSE)
