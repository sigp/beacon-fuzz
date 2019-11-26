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

Currently fuzzes against Eth2 `v0.8.3` python or Go executable specs
([pyspec](https://github.com/ethereum/eth2.0-specs/tree/v0.8.3/test_libs/pyspec) or [zrnt](https://github.com/protolambda/zrnt/tree/v0.8.3))


### Implementations

* [Lighthouse](https://github.com/sigp/lighthouse/)/rust
* [pyspec](https://github.com/ethereum/eth2.0-specs/tree/dev/test_libs/pyspec)/python
* [zrnt](https://github.com/protolambda/zrnt/)/go

### Operational Fuzz Targets:

(and their relevant spec function)

All currently use the "mainnet" config: https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/configs/mainnet.yaml

* `attestation` - [`process_attestation`](https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#attestations)
* `attester_slashing` - [`process_attester_slashing`](https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#attester-slashings)
* `block` - [`state_transition`](https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function)
* `block_header` - [`process_block_header`](https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#block-header)
* `shuffle` -  [`compute_shuffled_index`](https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/core/0_beacon-chain.md#compute_shuffled_index)

See [corpora](https://github.com/sigp/beacon-fuzz-corpora) repository for explanation of input structure.

### Corpora

See [corpora](https://github.com/sigp/beacon-fuzz-corpora) for examples and explanation of structure.


## Usage

Quickstart:

```bash
$ git clone --depth 1 https://github.com/sigp/beacon-fuzz.git
$ git clone --depth 1 https://github.com/sigp/beacon-fuzz-corpora.git
$ cd beacon-fuzz
$ ./runfuzzer.sh block_header ../beacon-fuzz-corpora/0-8-3/mainnet/block_header/ ../beacon-fuzz-corpora/0-8-3/mainnet/beaconstate
```

Interactive usage:

```bash
$ git clone --depth 1 https://github.com/sigp/beacon-fuzz.git
$ cd beacon-fuzz
$ sudo docker build . -t beacon_fuzz
$ sudo docker run -it beacon_fuzz bash
$ git clone --depth 1 https://github.com/sigp/beacon-fuzz-corpora.git
$ export ETH2_FUZZER_STATE_CORPUS_PATH="/eth2/beacon-fuzz-corpora/0-8-3/mainnet/beaconstate"
$ /eth2/fuzzers/attestation/fuzzer /eth2/beacon-fuzz-corpora/0-8-3/mainnet/attestation
```

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

* [Nimbus](https://github.com/status-im/nim-beacon-chain)
* [Prysm](https://github.com/prysmaticlabs/prysm)
* [Artemis](https://github.com/PegaSysEng/artemis)
* [Harmony](https://github.com/harmony-dev/beacon-chain-java)
* [Lodestar](https://github.com/ChainSafe/lodestar)
* [Trinity](https://github.com/ethereum/trinity)

## Contributing

Use [pre-commit](https://pre-commit.com/)

```console
$ pre-commit install
```
If build fails, comment the `RUN /eth2/build.sh` in `Dockerfile`, and run it manually from within the container.
Can adjust Makefiles as needed.

It is generally fine to run `build.sh` multiple times, and previously built components will be ignored.

### `make`ing fuzzers directly

This is quicker than re-running `./build.sh` and is useful when troubleshooting specific build issues.

After running `build.sh` once, a file `/eth2/exported_env.sh` will be created.
Sourcing this will ensure you have all the environment variables required by the Makefiles.

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

## License

MIT - see [LICENSE](./LICENSE)
